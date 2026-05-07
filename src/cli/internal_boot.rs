//! Internal boot subprocess for the API server.
//!
//! This command is NOT for direct user invocation. It's spawned by the API
//! server to launch a VM in a fresh single-threaded process, avoiding the
//! macOS fork-in-multithreaded-process issue.
//!
//! Usage: smolvm _boot-vm <config-path>

use smolvm::agent::boot_config::BootConfig;
use smolvm::agent::{launch_agent_vm, LaunchConfig, VmDisks};
use std::path::PathBuf;

/// Run the boot subprocess.
///
/// Reads the boot config from the given path, sets up libkrun, and calls
/// `krun_start_enter` which blocks forever (or until the VM exits).
pub fn run(config_path: PathBuf) -> smolvm::Result<()> {
    // Become a session leader (detach from parent's terminal session)
    unsafe {
        libc::setsid();
    }

    // Read boot config
    let config_data = std::fs::read(&config_path)
        .map_err(|e| smolvm::Error::agent("read boot config", e.to_string()))?;
    let config: BootConfig = serde_json::from_slice(&config_data)
        .map_err(|e| smolvm::Error::agent("parse boot config", e.to_string()))?;

    // Clean up the config file — it's no longer needed
    let _ = std::fs::remove_file(&config_path);

    let policy = smolvm::security::policy::LaunchPolicy::from_boot_config(config)?;
    let prepared = smolvm::security::prepare::PreparedLaunch::prepare(policy)?;

    // Redirect stdio. When SMOLVM_GPU_DEBUG=1, keep stderr pointed at a
    // debug log file so virglrenderer/MoltenVK errors are captured.
    if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
        if let Some(ref log) = prepared.policy.console_log {
            let debug_path = log.with_file_name("gpu-debug.log");
            if let Ok(cpath) = std::ffi::CString::new(debug_path.to_string_lossy().as_bytes()) {
                unsafe {
                    let fd = libc::open(
                        cpath.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        0o644,
                    );
                    if fd >= 0 {
                        libc::dup2(fd, 2);
                        libc::close(fd);
                    }
                }
            }
        }
        // Detach stdin/stdout only — keep stderr for GPU debug output
        unsafe {
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::close(devnull);
            }
        }
    } else if let Err(e) =
        smolvm::process::detach_stdio_to_stderr_file(&prepared.policy.startup_error_log)
    {
        let _ = std::fs::write(
            &prepared.policy.startup_error_log,
            format!("failed to redirect stdio: {}", e),
        );
        smolvm::process::exit_child(1);
    }

    // Close ALL inherited file descriptors from the parent (server).
    // Without this, the subprocess holds database locks, network sockets, etc.
    // that can interfere with libkrun's operation. Keep stdin/stdout/stderr (0-2)
    // which now point to /dev/null.
    unsafe {
        let max_fd = libc::getdtablesize();
        for fd in 3..max_fd {
            libc::close(fd);
        }
    }

    // Open storage and overlay disks
    let storage_disk = match smolvm::storage::StorageDisk::open_or_create_at(
        &prepared.policy.storage_disk_path,
        prepared.policy.storage_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &prepared.policy.startup_error_log,
                format!("failed to open storage disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };

    let overlay_disk = match smolvm::storage::OverlayDisk::open_or_create_at(
        &prepared.policy.overlay_disk_path,
        prepared.policy.overlay_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &prepared.policy.startup_error_log,
                format!("failed to open overlay disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };

    // Launch the VM (never returns on success)
    let disks = VmDisks {
        storage: &storage_disk,
        overlay: Some(&overlay_disk),
    };

    let result = launch_agent_vm(&LaunchConfig {
        rootfs_path: &prepared.policy.rootfs_path,
        disks: &disks,
        vsock_socket: &prepared.policy.vsock_socket,
        console_log: prepared.policy.console_log.as_deref(),
        mounts: &prepared.mounts,
        port_mappings: &prepared.policy.ports,
        resources: prepared.policy.resources.clone(),
        ssh_agent_socket: prepared.policy.secrets.ssh_agent_socket.as_deref(),
        preloaded_image_mount: prepared.preloaded_image_mount.as_ref(),
        extra_disks: &prepared.extra_disks,
        egress_refresh_hosts: prepared.policy.egress_policy_hosts.clone(),
    });

    // If we get here, launch_agent_vm returned (should only happen on error)
    if let Err(ref e) = result {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&prepared.policy.startup_error_log)
            .and_then(|mut file| {
                use std::io::Write;
                writeln!(file, "{e}")
            });
    }

    smolvm::process::exit_child(1);
}
