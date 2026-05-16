//! Agent VM launcher.
//!
//! This module provides the low-level VM launching functionality.
//! All setup is done in the child process after fork, where
//! DYLD_LIBRARY_PATH is still available for dlopen.

use crate::data::consts::{
    ENV_SMOLVM_GPU, ENV_SMOLVM_KRUN_LOG_LEVEL, ENV_SMOLVM_LIB_DIR, ENV_VALUE_ON,
};
use crate::error::{Error, Result};
use crate::network::backend::{COMPAT_NET_FEATURES, TSI_FEATURE_HIJACK_INET};
use crate::network::{plan_launch_network, EffectiveNetworkBackend};
use crate::security::prepare::{PreparedLaunch, PreparedMount};
use crate::storage::{OverlayDisk, StorageDisk};
use crate::util::{libkrun_filename, libkrunfw_filename};

use smolvm_network::{
    guest_env, start_virtio_network, GuestNetworkConfig, PortMapping as VirtioPortMapping,
    VirtioNetworkRuntime,
};
use smolvm_protocol::ports;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::KrunFunctions;

/// Maximum number of CIDR entries held in the live egress allow-list.
/// Protects the muxer's per-packet O(n) scan from unbounded growth when
/// a host resolves to many IPs across many refresh cycles.
const EGRESS_CIDR_CAP: usize = 512;

/// The Arc type shared between the egress-refresh thread and libkrun's vsock muxer.
type EgressArc = std::sync::Arc<std::sync::RwLock<Vec<(std::net::IpAddr, u8)>>>;

/// Disks to attach to the agent VM.
pub struct VmDisks<'a> {
    /// Storage disk for OCI layers (/dev/vda in guest).
    pub storage: &'a StorageDisk,
    /// Optional overlay disk for persistent rootfs (/dev/vdb in guest).
    pub overlay: Option<&'a OverlayDisk>,
}

/// Find the directory containing libkrun/libkrunfw by checking explicit overrides and
/// paths relative to the current executable.
///
/// Checks:
/// - `$SMOLVM_LIB_DIR` (explicit override for embedded runtimes)
/// - `<exe_dir>/lib/` (distribution layout)
/// - `<exe_dir>/../lib/` (alternative layout)
/// - `<exe_dir>/../../lib/linux-<arch>/` (source tree dev builds)
pub fn find_lib_dir() -> Option<PathBuf> {
    let lib_names = [libkrun_filename(), libkrunfw_filename()];
    if let Ok(explicit_dir) = std::env::var(ENV_SMOLVM_LIB_DIR) {
        let path = PathBuf::from(explicit_dir);
        if lib_names.iter().all(|lib| path.join(lib).exists()) {
            return path.canonicalize().ok().or(Some(path));
        }

        tracing::warn!(
            path = %path.display(),
            "{} does not contain the expected libkrun/libkrunfw libraries", ENV_SMOLVM_LIB_DIR
        );
    }

    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;

    let candidates = [
        exe_dir.join("lib"),
        exe_dir.join("../lib"),
        exe_dir.join("../../lib"),
        exe_dir.join(format!("../../lib/linux-{}", std::env::consts::ARCH)),
    ];

    for dir in &candidates {
        if lib_names.iter().all(|lib| dir.join(lib).exists()) {
            return dir.canonicalize().ok();
        }
    }

    None
}

/// Launch the agent VM (call in the forked child process).
///
/// This function sets up and starts the VM in a single call.
/// It should be called in the child process after fork, where
/// DYLD_LIBRARY_PATH is still available for dlopen to find libkrunfw.
///
/// Optional features for VM launch (SSH agent, preloaded image data, etc.).
///
/// Groups optional capabilities that don't affect core VM operation.
/// New features should be added here rather than as additional parameters
/// on manager/launcher functions.
#[derive(Debug, Clone, Default)]
pub struct LaunchFeatures {
    /// Host SSH agent socket path for forwarding into the guest.
    pub ssh_agent_socket: Option<std::path::PathBuf>,
    /// Hostnames from `--allow-host` to periodically re-resolve for egress policy.
    pub egress_policy_hosts: Option<Vec<String>>,
    /// Host directory containing image data mounted for the guest agent.
    /// When set, the launcher mounts this directory via virtiofs so the agent
    /// can use local image data instead of pulling from a registry.
    pub preloaded_image_dir: Option<std::path::PathBuf>,
    /// Additional disk images to attach to the VM (path, read_only).
    /// Appear as /dev/vdc, /dev/vdd, ... after the storage and overlay disks.
    pub extra_disks: Vec<(std::path::PathBuf, bool)>,
}

/// Configuration for launching an agent VM.
pub struct LaunchConfig<'a> {
    /// Prepared launch policy and VMM-facing resources.
    pub prepared: &'a PreparedLaunch,
    /// Storage and overlay disk handles.
    pub disks: &'a VmDisks<'a>,
}

/// Launch the agent VM using libkrun.
///
/// This function never returns on success.
pub fn launch_agent_vm(config: &LaunchConfig<'_>) -> Result<()> {
    let prepared = config.prepared;
    let policy = &prepared.policy;
    let disks = config.disks;
    let rootfs_path = &policy.rootfs_path;
    let vsock_socket = &policy.vsock_socket;
    let console_log = policy.console_log.as_deref();
    let mounts = &prepared.mounts;
    let port_mappings = &policy.ports;
    let resources = &policy.resources;
    let gpu_requested = policy.devices.gpu;
    let ssh_agent_socket = policy.secrets.ssh_agent_socket.as_deref();
    let preloaded_image_mount = prepared.preloaded_image_mount.as_ref();
    let extra_disks = &prepared.extra_disks;
    let prepared_network = &prepared.network;

    crate::network::validate_requested_network_backend(prepared_network)?;

    // Raise file descriptor limits
    raise_fd_limits();

    let resource_guard = crate::security::hardening::apply_runner_resource_confinement(prepared)?;
    tracing::debug!(
        hardening = %resource_guard.report().render_text(),
        "applied runner resource confinement"
    );

    let lib_dir = find_lib_dir().ok_or_else(|| {
        Error::agent(
            "find libraries",
            "libkrun/libkrunfw not found. Install smolvm with bundled libraries or set SMOLVM_LIB_DIR.",
        )
    })?;
    let krun =
        unsafe { KrunFunctions::load(&lib_dir) }.map_err(|e| Error::agent("load libkrun", e))?;

    unsafe {
        let krun_set_log_level = krun.set_log_level;
        let krun_create_ctx = krun.create_ctx;
        let krun_free_ctx = krun.free_ctx;
        let krun_set_vm_config = krun.set_vm_config;
        let krun_set_root = krun.set_root;
        let krun_set_workdir = krun.set_workdir;
        let krun_set_exec = krun.set_exec;
        let krun_add_disk2 = krun.add_disk2;
        let krun_add_vsock_port2 = krun.add_vsock_port2;
        let krun_set_console_output = krun.set_console_output;
        let krun_set_port_map = krun.set_port_map;
        let krun_start_enter = krun.start_enter;
        let krun_disable_implicit_vsock = krun.disable_implicit_vsock;
        let krun_add_vsock = krun.add_vsock;

        // Set log level (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug)
        // Enable debug logging to trace vsock timing issues
        let log_level = std::env::var(ENV_SMOLVM_KRUN_LOG_LEVEL)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        krun_set_log_level(log_level);

        // Create VM context
        let ctx = krun_create_ctx();
        if ctx < 0 {
            return Err(Error::agent("create vm context", "krun_create_ctx failed"));
        }
        let ctx = ctx as u32;

        // Set VM config
        if krun_set_vm_config(ctx, resources.cpus, resources.memory_mib) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("configure vm", "krun_set_vm_config failed"));
        }

        // Enable GPU if requested (virgl for OpenGL + Venus for Vulkan via virtio-gpu).
        // Requires libkrun built with `gpu` feature and host virglrenderer.
        // On macOS, also requires MoltenVK (Vulkan → Metal translation).
        if gpu_requested {
            let virgl_flags = super::gpu_virgl_flags();
            // Size the GPU shared-memory region. Caller may override
            // via `--gpu-vram <MiB>` (CLI) or `gpu_vram = N` (Smolfile);
            // default is `DEFAULT_GPU_VRAM_MIB`.
            let vram_mib = resources.effective_gpu_vram_mib();
            let vram_bytes: u64 = (vram_mib as u64) * crate::data::consts::BYTES_PER_MIB;

            // Resolve krun_set_gpu_options2 dynamically — it may not exist
            // if libkrun was built without the `gpu` feature.
            let set_gpu = match krun.set_gpu_options2 {
                Some(f) => f,
                None => {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure gpu",
                        "libkrun was built without GPU support (krun_set_gpu_options2 not found). \
                         Rebuild libkrun with GPU=1 — see project README for details.",
                    ));
                }
            };

            let ret = set_gpu(ctx, virgl_flags, vram_bytes);
            if ret < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "configure gpu",
                    format!("krun_set_gpu_options2 failed (ret={}). Check that virglrenderer is installed.", ret),
                ));
            }
            tracing::info!("GPU enabled (Venus/Vulkan via virtio-gpu)");
        }

        // Helper: evaluate a fallible expression, freeing ctx if it fails.
        // Replaces bare `?` which would leak the libkrun context.
        macro_rules! try_or_free_ctx {
            ($expr:expr, $op:expr, $msg:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(_) => {
                        krun_free_ctx(ctx);
                        return Err(Error::agent($op, $msg));
                    }
                }
            };
        }

        let filesystem_report =
            match crate::security::hardening::apply_runner_filesystem_confinement(prepared) {
                Ok(report) => report,
                Err(e) => {
                    krun_free_ctx(ctx);
                    return Err(e);
                }
            };
        tracing::debug!(
            hardening = %filesystem_report.render_text(),
            "applied runner filesystem confinement"
        );

        // Set root filesystem
        let root = try_or_free_ctx!(
            path_to_cstring(rootfs_path),
            "set rootfs",
            "path contains null byte"
        );
        if krun_set_root(ctx, root.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set rootfs", "krun_set_root failed"));
        }

        let network_plan = plan_launch_network(prepared_network);
        if let Some(reason) = network_plan.fallback_reason {
            tracing::warn!(reason = %reason.user_message(), "network backend fell back to TSI");
        }

        let mut virtio_network_runtime: Option<VirtioNetworkRuntime> = None;
        let guest_network = match network_plan.backend {
            EffectiveNetworkBackend::None => {
                if krun_disable_implicit_vsock(ctx) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure vsock",
                        "krun_disable_implicit_vsock failed",
                    ));
                }
                if krun_add_vsock(ctx, 0) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent("configure vsock", "krun_add_vsock failed"));
                }

                tracing::debug!("configured vsock without guest networking");
                None
            }
            EffectiveNetworkBackend::Tsi => {
                if krun_disable_implicit_vsock(ctx) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure vsock",
                        "krun_disable_implicit_vsock failed",
                    ));
                }
                if krun_add_vsock(ctx, TSI_FEATURE_HIJACK_INET) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure vsock",
                        "krun_add_vsock with TSI failed",
                    ));
                }

                let port_cstrings: Vec<CString> = port_mappings
                    .iter()
                    .map(|p| {
                        CString::new(format!("{}:{}", p.host, p.guest))
                            .expect("port mapping format cannot contain null bytes")
                    })
                    .collect();
                let mut port_ptrs: Vec<*const libc::c_char> =
                    port_cstrings.iter().map(|s| s.as_ptr()).collect();
                port_ptrs.push(std::ptr::null());

                if krun_set_port_map(ctx, port_ptrs.as_ptr()) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent("set port mapping", "krun_set_port_map failed"));
                }

                if let Some(cidrs) = prepared_network.initial_cidrs() {
                    let Some(set_egress) = krun.set_egress_policy else {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "set egress policy",
                            "libkrun does not support egress policy (krun_set_egress_policy not found). \
                             Update libkrun or remove --allow-cidr flags.",
                        ));
                    };

                    let mut all_cidrs = cidrs.to_vec();
                    if prepared_network.should_allow_dns_for_egress_policy() {
                        crate::data::network::ensure_dns_in_cidrs(&mut all_cidrs);
                    }

                    let cidr_cstrings: Vec<CString> = all_cidrs
                        .iter()
                        .map(|c| CString::new(c.as_str()).expect("CIDR cannot contain null bytes"))
                        .collect();
                    let mut cidr_ptrs: Vec<*const libc::c_char> =
                        cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                    cidr_ptrs.push(std::ptr::null());

                    if set_egress(ctx, cidr_ptrs.as_ptr()) < 0 {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "set egress policy",
                            "krun_set_egress_policy failed",
                        ));
                    }
                }

                tracing::info!("network backend: tsi");
                None
            }
            EffectiveNetworkBackend::VirtioNet => {
                let add_net_unixstream = krun.add_net_unixstream.ok_or_else(|| {
                    Error::agent(
                        "configure virtio-net",
                        "libkrun does not expose krun_add_net_unixstream; update libkrun or use --net-backend tsi",
                    )
                })?;
                let guest_network = GuestNetworkConfig::default();
                let mut guest_mac = guest_network.guest_mac;
                let (host_fd, guest_fd) = create_unix_stream_pair().map_err(|e| {
                    Error::agent("configure virtio-net", format!("socketpair failed: {e}"))
                })?;

                let virtio_port_mappings: Vec<VirtioPortMapping> = port_mappings
                    .iter()
                    .map(|mapping| VirtioPortMapping::new(mapping.host, mapping.guest))
                    .collect();
                let runtime =
                    match start_virtio_network(host_fd, guest_network, &virtio_port_mappings) {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            libc::close(guest_fd);
                            krun_free_ctx(ctx);
                            return Err(Error::agent(
                                "configure virtio-net",
                                format!("failed to start virtio network runtime: {err}"),
                            ));
                        }
                    };

                if add_net_unixstream(
                    ctx,
                    std::ptr::null(),
                    guest_fd,
                    guest_mac.as_mut_ptr(),
                    COMPAT_NET_FEATURES,
                    0,
                ) < 0
                {
                    libc::close(guest_fd);
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure virtio-net",
                        "krun_add_net_unixstream failed",
                    ));
                }

                virtio_network_runtime = Some(runtime);

                tracing::info!("network backend: virtio-net");
                Some(guest_network)
            }
        };

        // Add storage disk (critical - VM needs storage to function)
        // This is the first disk → /dev/vda in guest
        let block_id = cstr("storage");
        let disk_path = try_or_free_ctx!(
            path_to_cstring(disks.storage.path()),
            "add storage disk",
            "path contains null byte"
        );
        if krun_add_disk2(ctx, block_id.as_ptr(), disk_path.as_ptr(), 0, false) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add storage disk",
                "krun_add_disk2 failed - VM cannot function without storage",
            ));
        }

        // Add overlay disk for persistent rootfs changes (optional)
        // This is the second disk → /dev/vdb in guest
        if let Some(overlay) = disks.overlay {
            let overlay_id = cstr("overlay");
            let overlay_path = try_or_free_ctx!(
                path_to_cstring(overlay.path()),
                "add overlay disk",
                "path contains null byte"
            );
            if krun_add_disk2(ctx, overlay_id.as_ptr(), overlay_path.as_ptr(), 0, false) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add overlay disk",
                    "krun_add_disk2 failed for rootfs overlay",
                ));
            }
        }

        // Add extra disks (e.g., source VM storage for --from-vm export)
        // These appear as /dev/vdc, /dev/vdd, ... after storage and overlay
        for (i, disk) in extra_disks.iter().enumerate() {
            let block_id_str = format!("extra{}", i);
            let block_id = try_or_free_ctx!(
                CString::new(block_id_str.as_str()),
                "add extra disk",
                "block id contains null byte"
            );
            let path = try_or_free_ctx!(
                path_to_cstring(&disk.path_for_vmm),
                "add extra disk",
                "path contains null byte"
            );
            if krun_add_disk2(ctx, block_id.as_ptr(), path.as_ptr(), 0, disk.read_only) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add extra disk",
                    format!("krun_add_disk2 failed for extra disk {}", i),
                ));
            }
            tracing::debug!(
                disk = i,
                path = %disk.path_for_vmm.display(),
                read_only = disk.read_only,
                "added extra disk"
            );
        }

        // Add vsock port for control channel (critical - host-guest communication)
        let socket_path = try_or_free_ctx!(
            path_to_cstring(vsock_socket),
            "add vsock port",
            "path contains null byte"
        );
        if krun_add_vsock_port2(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add vsock port",
                "krun_add_vsock_port2 failed - control channel required for host-guest communication",
            ));
        }

        // Add vsock port for SSH agent forwarding (optional)
        if let Some(ssh_socket) = ssh_agent_socket {
            let ssh_path = try_or_free_ctx!(
                path_to_cstring(ssh_socket),
                "add ssh agent vsock port",
                "path contains null byte"
            );
            // listen=false: guest connects out to this port, host receives via Unix socket
            if krun_add_vsock_port2(ctx, ports::SSH_AGENT, ssh_path.as_ptr(), false) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add ssh agent vsock port",
                    "krun_add_vsock_port2 failed for SSH agent forwarding",
                ));
            } else {
                tracing::info!(
                    "SSH agent forwarding enabled on vsock port {}",
                    ports::SSH_AGENT
                );
            }
        }

        // Set console output if specified
        if let Some(log_path) = console_log {
            let console_path = try_or_free_ctx!(
                path_to_cstring(log_path),
                "set console output",
                "path contains null byte"
            );
            if krun_set_console_output(ctx, console_path.as_ptr()) < 0 {
                tracing::warn!("failed to set console output");
            }
        }

        // Add prepared virtiofs mounts. Tags and VMM-facing paths are assigned
        // before the launcher so future jail-path rewriting stays out of this
        // libkrun setup code.
        for mount in mounts.iter() {
            tracing::debug!(
                tag = %mount.tag,
                host = %mount.host_source.display(),
                vmm_path = %mount.source_for_vmm.display(),
                guest = %mount.guest_target.display(),
                read_only = mount.access.is_read_only(),
                "adding virtiofs mount"
            );

            if let Err(e) = add_virtiofs_prepared(&krun, ctx, mount) {
                krun_free_ctx(ctx);
                return Err(e);
            }
        }

        if let Some(image_mount) = preloaded_image_mount {
            if image_mount.source_for_vmm.exists() {
                if let Err(e) = add_virtiofs_prepared(&krun, ctx, image_mount) {
                    krun_free_ctx(ctx);
                    return Err(e);
                }
            }
        }

        // Set working directory
        let workdir = cstr("/");
        krun_set_workdir(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            cstr("HOME=/root"),
            cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            cstr("TERM=xterm-256color"),
        ];

        // Pass mount info to the agent via environment
        // Format: SMOLVM_MOUNT_0=tag:guest_path:ro
        for (i, mount) in mounts.iter().enumerate() {
            let env_val = format!(
                "SMOLVM_MOUNT_{}={}:{}:{}",
                i,
                mount.tag,
                mount.guest_target.display(),
                mount.access.agent_flag()
            );
            if let Ok(cstr) = CString::new(env_val) {
                env_strings.push(cstr);
            }
        }

        // Pass mount count
        if !mounts.is_empty() {
            if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", mounts.len())) {
                env_strings.push(cstr);
            }
        }

        // Tell the agent to start SSH agent forwarding bridge
        if ssh_agent_socket.is_some() {
            env_strings.push(cstr("SMOLVM_SSH_AGENT=1"));
        }

        // Tell the agent GPU was requested so it can sanity-check the
        // virtio-gpu device actually appeared in the guest. libkrun
        // happily accepts `krun_set_gpu_options2` even if the embedded
        // kernel lacks the driver; without this check the user sees
        // "VM started" and discovers missing GPU only when their
        // workload hits a rendering call.
        if gpu_requested {
            let gpu_env = format!("{}={}", ENV_SMOLVM_GPU, ENV_VALUE_ON);
            if let Ok(cs) = CString::new(gpu_env) {
                env_strings.push(cs);
            }
        }

        if let Some(network) = guest_network {
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::BACKEND,
                guest_env::BACKEND_VIRTIO_NET
            )));
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::GUEST_IP,
                network.guest_ip
            )));
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::GATEWAY,
                network.gateway_ip
            )));
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::PREFIX_LEN,
                network.prefix_len
            )));
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::GUEST_MAC,
                format_mac(network.guest_mac)
            )));
            env_strings.push(cstr(&format!("{}={}", guest_env::DNS, network.dns_server)));
        }

        if preloaded_image_mount.is_some_and(|mount| mount.source_for_vmm.exists()) {
            env_strings.push(cstr("SMOLVM_PRELOADED_IMAGE=smolvm_image:/preloaded_image"));
        }

        let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // Set exec command (/sbin/init)
        let exec_path = cstr("/sbin/init");
        let argv_strings = [cstr("/sbin/init")];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set exec command", "krun_set_exec failed"));
        }

        // Egress CIDR live-refresh thread.
        //
        // Re-resolves hostname egress policy targets every SMOLVM_EGRESS_REFRESH_SECS
        // (default 5 min) and atomically replaces the Arc<RwLock<Vec<...>>>
        // that the vsock muxer reads on every packet. The Arc is borrowed from
        // libkrun via `krun_get_egress_handle` — see libkrun/src/libkrun/src/lib.rs.
        //
        // Each cycle: resolve all hosts → build fresh list → single write-lock
        // swap. If all hosts fail to resolve, the previous list is kept intact.
        if let Some(hosts) = prepared_network.refresh_hosts() {
            if let Some(krun_get_egress_handle) = krun.get_egress_handle {
                let raw_handle = krun_get_egress_handle(ctx);

                if !raw_handle.is_null() {
                    let arc: EgressArc = *Box::from_raw(raw_handle as *mut EgressArc);
                    let hosts_copy = hosts.to_vec();
                    if let Err(e) = std::thread::Builder::new()
                        .name("egress-refresh".into())
                        .spawn(move || {
                            let refresh_secs: u64 = std::env::var("SMOLVM_EGRESS_REFRESH_SECS")
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(5 * 60);
                            let refresh_interval = std::time::Duration::from_secs(refresh_secs);
                            loop {
                                std::thread::sleep(refresh_interval);
                                // Resolve all hosts into a fresh list, then swap
                                // the shared Vec in a single write-lock acquisition.
                                // This ensures old rotated-away IPs are removed.
                                let mut fresh: Vec<(std::net::IpAddr, u8)> = Vec::new();
                                'hosts: for host in &hosts_copy {
                                    match resolve_host_subprocess(host) {
                                        Ok(new_cidrs) => {
                                            for cidr_str in new_cidrs {
                                                if fresh.len() >= EGRESS_CIDR_CAP {
                                                    break 'hosts;
                                                }
                                                if let Some((ip_str, prefix_str)) =
                                                    cidr_str.split_once('/')
                                                {
                                                    if let (Ok(ip), Ok(prefix)) = (
                                                        ip_str.parse::<std::net::IpAddr>(),
                                                        prefix_str.parse::<u8>(),
                                                    ) {
                                                        if !fresh.contains(&(ip, prefix)) {
                                                            fresh.push((ip, prefix));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                host = %host,
                                                error = %e,
                                                "egress-refresh: resolve failed"
                                            );
                                        }
                                    }
                                }
                                // Only replace if at least one host resolved
                                // successfully; keeps the old list on total failure.
                                if !fresh.is_empty() {
                                    let mut guard = arc.write().unwrap_or_else(|e| e.into_inner());
                                    *guard = fresh;
                                }
                            }
                        })
                    {
                        tracing::warn!(error = %e, "egress-refresh spawn failed");
                    }
                }
            }
        }

        let syscall_policy =
            crate::security::hardening::RunnerSyscallPolicy::from_prepared(prepared);
        let syscall_report =
            match crate::security::hardening::apply_runner_syscall_confinement(syscall_policy) {
                Ok(report) => report,
                Err(e) => {
                    krun_free_ctx(ctx);
                    return Err(e);
                }
            };
        tracing::debug!(
            hardening = %syscall_report.render_text(),
            "applied runner syscall confinement"
        );

        // Start VM (this replaces the process on success). Keep resource
        // confinement alive until libkrun returns on failure or VM exit.
        let ret = krun_start_enter(ctx);

        // If we get here, something went wrong — free the context before returning
        krun_free_ctx(ctx);
        drop(virtio_network_runtime);
        drop(resource_guard);
        Err(Error::agent(
            "start vm",
            format!("krun_start_enter returned: {}", ret),
        ))
    }
}

fn add_virtiofs_prepared(krun: &KrunFunctions, ctx: u32, mount: &PreparedMount) -> Result<()> {
    unsafe {
        krun.add_virtiofs_path(
            ctx,
            &mount.tag,
            &mount.source_for_vmm,
            mount.access.is_read_only(),
        )
    }
    .map_err(|err| Error::agent("add virtiofs mount", err.to_string()))
}

/// Create a CString from a static string that is known not to contain NUL bytes.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("string literal must not contain NUL bytes")
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::agent("convert path", "path contains null byte"))
}

fn create_unix_stream_pair() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    // SAFETY: `socketpair` initializes both descriptors on success.
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Resolve a hostname to /32 CIDR strings for the egress-refresh thread.
///
/// ## Why not `getaddrinfo`?
///
/// The `egress-refresh` thread runs inside the `_boot-vm` subprocess. Before
/// `krun_start_enter` is called, `internal_boot.rs` closes every inherited FD
/// from 3 up to `max_fd`. Apple's Network framework maps shared memory at
/// process launch and accesses it via FD-derived handles. After the mass close,
/// those handles are invalid, so any call to `getaddrinfo` (which routes
/// through the Network framework on macOS) crashes with SIGBUS at
/// `_os_log_preferences_refresh` inside `nw_path_libinfo_path_check`.
///
/// Spawning an external `dig` process sidesteps this: `exec()` gives the child
/// a completely fresh address space, so it never touches the broken inherited
/// shared memory. On non-macOS platforms `getaddrinfo` via glibc is safe and
/// is used directly.
#[cfg(target_os = "macos")]
#[inline(never)]
fn resolve_host_subprocess(host: &str) -> std::result::Result<Vec<String>, String> {
    // `/usr/bin/dig` is always present on macOS (part of BIND-tools in the
    // base system). `+short` prints one result per line (IPs and CNAMEs);
    // `+timeout=5 +tries=2` keeps the refresh loop from stalling the VM on
    // a flaky network.
    let output = std::process::Command::new("/usr/bin/dig")
        .args(["+short", "+timeout=5", "+tries=2", host])
        .output()
        .map_err(|e| format!("dig subprocess failed for '{}': {}", host, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // `+short` emits CNAMEs (ending in '.') interleaved with IPs; parse::<IpAddr>
    // silently skips the CNAME lines, leaving only valid addresses.
    let cidrs: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            line.trim()
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| format!("{}/32", ip))
        })
        .collect();

    if cidrs.is_empty() {
        return Err(format!("dig resolved '{}' to no IP addresses", host));
    }
    Ok(cidrs)
}

/// On non-macOS (Linux), `getaddrinfo` is safe to call from background threads
/// in child processes — glibc does not use shared-memory handles that become
/// invalid after a mass FD close. Delegate directly to the standard resolver.
#[cfg(not(target_os = "macos"))]
#[inline(never)]
fn resolve_host_subprocess(host: &str) -> std::result::Result<Vec<String>, String> {
    crate::smolfile::resolve_host_to_cidrs(host)
}

/// Raise file descriptor limits (required by libkrun).
fn raise_fd_limits() {
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}
