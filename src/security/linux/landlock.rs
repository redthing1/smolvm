//! Linux Landlock filesystem confinement.

use crate::data::storage::MountAccess;
use crate::security::hardening::Enforcement;
use crate::security::prepare::PreparedLaunch;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;

const FS_READ: u64 = FS_READ_FILE | FS_READ_DIR;
const FS_READ_EXECUTE: u64 = FS_READ | FS_EXECUTE;
const FS_WRITE_TREE: u64 = FS_WRITE_FILE
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE;
const FS_READ_WRITE: u64 = FS_READ | FS_WRITE_TREE;
const FS_DEVICE: u64 = FS_READ_FILE | FS_WRITE_FILE | FS_IOCTL_DEV;

pub(super) fn apply(prepared: &PreparedLaunch) -> Result<Enforcement> {
    if prepared.policy.devices.gpu {
        return Ok(Enforcement::Skipped {
            reason: "GPU device and helper-process access is not modeled by Landlock yet"
                .to_string(),
        });
    }

    let abi = match landlock_abi_version()? {
        LandlockAvailability::Available(abi) => abi,
        LandlockAvailability::Unavailable(reason) => {
            return Ok(Enforcement::Unavailable { reason });
        }
    };

    let handled_access_fs = supported_fs_access_for_abi(abi);
    if handled_access_fs == 0 {
        return Ok(Enforcement::Unavailable {
            reason: format!("Landlock ABI {abi} exposes no supported filesystem rights"),
        });
    }

    let rules = build_rules(prepared);
    let ruleset_fd = create_ruleset(handled_access_fs)?;
    for rule in rules {
        add_path_rule(&ruleset_fd, &rule, handled_access_fs)?;
    }
    restrict_self(&ruleset_fd)?;

    Ok(Enforcement::Enforced)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathRule {
    path: PathBuf,
    access: u64,
}

fn build_rules(prepared: &PreparedLaunch) -> Vec<PathRule> {
    let mut rules = PathRules::default();

    rules.allow(&prepared.policy.rootfs_path, FS_READ_WRITE);
    rules.allow_existing_file_or_parent(&prepared.policy.storage_disk_path, FS_READ_WRITE);
    rules.allow_existing_file_or_parent(&prepared.policy.overlay_disk_path, FS_READ_WRITE);
    rules.allow_parent(&prepared.policy.vsock_socket, FS_READ_WRITE);
    rules.allow_existing_file_or_parent(&prepared.policy.startup_error_log, FS_READ_WRITE);

    if let Some(console_log) = &prepared.policy.console_log {
        rules.allow_existing_file_or_parent(console_log, FS_READ_WRITE);
    }

    for mount in &prepared.mounts {
        let access = match mount.access {
            MountAccess::ReadOnly => FS_READ,
            MountAccess::ReadWrite => FS_READ_WRITE,
        };
        rules.allow(&mount.source_for_vmm, access);
    }

    if let Some(image_mount) = &prepared.preloaded_image_mount {
        if image_mount.source_for_vmm.exists() {
            rules.allow(&image_mount.source_for_vmm, FS_READ);
        }
    }

    for disk in &prepared.extra_disks {
        let access = if disk.read_only {
            FS_READ
        } else {
            FS_READ_WRITE
        };
        rules.allow_existing_file_or_parent(&disk.path_for_vmm, access);
    }

    if let Some(ssh_agent_socket) = &prepared.policy.secrets.ssh_agent_socket {
        if ssh_agent_socket.exists() {
            rules.allow_parent(ssh_agent_socket, FS_READ);
        }
    }

    if prepared
        .policy
        .egress_policy_hosts
        .as_ref()
        .is_some_and(|hosts| !hosts.is_empty())
    {
        add_resolver_rules(&mut rules);
    }

    add_device_rule_if_present(&mut rules, "/dev/kvm");

    rules.into_vec()
}

#[derive(Default)]
struct PathRules {
    rules: BTreeMap<PathBuf, u64>,
}

impl PathRules {
    fn allow(&mut self, path: &Path, access: u64) {
        self.rules
            .entry(path.to_path_buf())
            .and_modify(|existing| *existing |= access)
            .or_insert(access);
    }

    fn allow_parent(&mut self, path: &Path, access: u64) {
        self.allow(parent_or_current(path), access);
    }

    fn allow_existing_file_or_parent(&mut self, path: &Path, access: u64) {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => self.allow(path, access),
            Ok(_) => self.allow(path, file_access(access)),
            Err(_) => self.allow_parent(path, access),
        }
    }

    fn into_vec(self) -> Vec<PathRule> {
        self.rules
            .into_iter()
            .map(|(path, access)| PathRule { path, access })
            .collect()
    }
}

fn file_access(access: u64) -> u64 {
    access & (FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE | FS_IOCTL_DEV)
}

fn parent_or_current(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn add_resolver_rules(rules: &mut PathRules) {
    for path in [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/gai.conf",
    ] {
        let path = Path::new(path);
        if path.exists() {
            rules.allow_existing_file_or_parent(path, FS_READ);
        }
    }

    for path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        let path = Path::new(path);
        if path.exists() {
            rules.allow(path, FS_READ_EXECUTE);
        }
    }
}

fn add_device_rule_if_present(rules: &mut PathRules, path: &str) {
    let path = Path::new(path);
    if path.exists() {
        rules.allow(path, FS_DEVICE);
    }
}

enum LandlockAvailability {
    Available(u32),
    Unavailable(String),
}

fn landlock_abi_version() -> Result<LandlockAvailability> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if ret >= 1 {
        return Ok(LandlockAvailability::Available(ret as u32));
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS) => Ok(LandlockAvailability::Unavailable(
            "kernel does not support Landlock".to_string(),
        )),
        Some(libc::EOPNOTSUPP) => Ok(LandlockAvailability::Unavailable(
            "Landlock is disabled by the running kernel".to_string(),
        )),
        _ => Err(Error::agent(
            "probe Landlock",
            format!("landlock_create_ruleset version probe failed: {error}"),
        )),
    }
}

fn supported_fs_access_for_abi(abi: u32) -> u64 {
    let mut access = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;

    if abi >= 2 {
        access |= FS_REFER;
    }
    if abi >= 3 {
        access |= FS_TRUNCATE;
    }
    if abi >= 5 {
        access |= FS_IOCTL_DEV;
    }

    access
}

fn create_ruleset(handled_access_fs: u64) -> Result<OwnedFd> {
    let attr = LandlockRulesetAttr { handled_access_fs };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if fd < 0 {
        return Err(last_os_error("create Landlock ruleset"));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn add_path_rule(ruleset_fd: &OwnedFd, rule: &PathRule, handled_access_fs: u64) -> Result<()> {
    let allowed_access = rule.access & handled_access_fs;
    if allowed_access == 0 {
        return Ok(());
    }

    let path_fd = open_path(&rule.path)?;
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: path_fd.as_raw_fd(),
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const LandlockPathBeneathAttr,
            0u32,
        )
    };

    if ret != 0 {
        return Err(last_os_error(format!(
            "add Landlock rule for {}",
            rule.path.display()
        )));
    }

    Ok(())
}

fn restrict_self(ruleset_fd: &OwnedFd) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd.as_raw_fd(),
            0u32,
        )
    };

    if ret != 0 {
        return Err(last_os_error("restrict process with Landlock"));
    }

    Ok(())
}

fn open_path(path: &Path) -> Result<OwnedFd> {
    let cpath = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
        Error::agent(
            "open Landlock rule path",
            format!("path contains null byte: {}", path.display()),
        )
    })?;

    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_os_error(format!(
            "open Landlock rule path {}",
            path.display()
        )));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn last_os_error(operation: impl Into<String>) -> Error {
    Error::agent(
        "apply Landlock",
        format!("{}: {}", operation.into(), std::io::Error::last_os_error()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::resources::VmResources;
    use crate::data::storage::HostMount;
    use crate::security::policy::LaunchPolicy;
    use crate::security::prepare::PreparedLaunch;
    use std::process::Command;

    const CHILD_ENV: &str = "SMOLVM_TEST_LANDLOCK_CHILD";

    #[test]
    fn supported_access_tracks_landlock_abi_versions() {
        let abi1 = supported_fs_access_for_abi(1);
        assert_eq!(abi1 & FS_REFER, 0);
        assert_eq!(abi1 & FS_TRUNCATE, 0);
        assert_eq!(abi1 & FS_IOCTL_DEV, 0);

        let abi3 = supported_fs_access_for_abi(3);
        assert_ne!(abi3 & FS_REFER, 0);
        assert_ne!(abi3 & FS_TRUNCATE, 0);
        assert_eq!(abi3 & FS_IOCTL_DEV, 0);

        let abi5 = supported_fs_access_for_abi(5);
        assert_ne!(abi5 & FS_IOCTL_DEV, 0);
    }

    #[test]
    fn rules_are_built_from_prepared_launch() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        let rw_mount = temp.path().join("rw");
        let ro_mount = temp.path().join("ro");
        let runtime = temp.path().join("runtime");
        let storage = runtime.join("storage.img");
        let overlay = runtime.join("overlay.img");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&rw_mount).unwrap();
        std::fs::create_dir_all(&ro_mount).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(&storage, b"storage").unwrap();
        std::fs::write(&overlay, b"overlay").unwrap();

        let prepared = prepared_launch_for_paths(
            &rootfs,
            &storage,
            &overlay,
            vec![
                HostMount {
                    source: rw_mount.clone(),
                    target: "/rw".into(),
                    read_only: false,
                },
                HostMount {
                    source: ro_mount.clone(),
                    target: "/ro".into(),
                    read_only: true,
                },
            ],
        );

        let rules = build_rules(&prepared);
        let rootfs_rule = find_rule(&rules, &rootfs);
        let rw_rule = find_rule(&rules, &rw_mount);
        let ro_rule = find_rule(&rules, &ro_mount);

        assert_ne!(rootfs_rule.access & FS_WRITE_FILE, 0);
        assert_ne!(rw_rule.access & FS_WRITE_FILE, 0);
        assert_eq!(ro_rule.access & FS_WRITE_FILE, 0);
        assert_ne!(ro_rule.access & FS_READ_FILE, 0);
    }

    #[test]
    fn landlock_uses_materialized_paths() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        let host_mount = temp.path().join("host");
        let jail_mount = temp.path().join("jail").join("mounts").join("smolvm0");
        let runtime = temp.path().join("runtime");
        let storage = runtime.join("storage.img");
        let overlay = runtime.join("overlay.img");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&host_mount).unwrap();
        std::fs::create_dir_all(&jail_mount).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(&storage, b"storage").unwrap();
        std::fs::write(&overlay, b"overlay").unwrap();

        let mut prepared = prepared_launch_for_paths(
            &rootfs,
            &storage,
            &overlay,
            vec![HostMount {
                source: host_mount.clone(),
                target: "/workspace".into(),
                read_only: false,
            }],
        );
        prepared.mounts[0].source_for_vmm = jail_mount.clone();

        let rules = build_rules(&prepared);

        find_rule(&rules, &jail_mount);
        assert!(
            rules.iter().all(|rule| rule.path != host_mount),
            "Landlock must not retain the original host path after materialization"
        );
    }

    #[test]
    fn landlock_skips_gpu_device_grant_until_device_model_is_explicit() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        let runtime = temp.path().join("runtime");
        let storage = runtime.join("storage.img");
        let overlay = runtime.join("overlay.img");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(&storage, b"storage").unwrap();
        std::fs::write(&overlay, b"overlay").unwrap();

        let mut prepared = prepared_launch_for_paths(&rootfs, &storage, &overlay, Vec::new());
        prepared.policy.devices.gpu = true;

        assert_eq!(
            apply(&prepared).unwrap(),
            Enforcement::Skipped {
                reason: "GPU device and helper-process access is not modeled by Landlock yet"
                    .to_string(),
            }
        );
    }

    #[test]
    fn landlock_confinement_blocks_unlisted_paths_when_available() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, "1")
            .args([
                "--exact",
                "security::linux::landlock::tests::landlock_child_probe",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn landlock_child_probe() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        let runtime = temp.path().join("runtime");
        let storage = runtime.join("storage.img");
        let overlay = runtime.join("overlay.img");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(&storage, b"storage").unwrap();
        std::fs::write(&overlay, b"overlay").unwrap();

        let prepared = prepared_launch_for_paths(&rootfs, &storage, &overlay, Vec::new());
        super::super::apply_runner_baseline().unwrap();
        match apply(&prepared).unwrap() {
            Enforcement::Enforced => {}
            Enforcement::Unavailable { reason } => {
                eprintln!("Landlock unavailable on this host: {reason}");
                return;
            }
            Enforcement::Skipped { reason } => panic!("unexpected Landlock skip: {reason}"),
        }

        std::fs::write(rootfs.join("allowed"), b"ok").unwrap();

        let denied = std::fs::read_to_string("/etc/passwd").unwrap_err();
        assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    }

    fn prepared_launch_for_paths(
        rootfs: &Path,
        storage: &Path,
        overlay: &Path,
        mounts: Vec<HostMount>,
    ) -> PreparedLaunch {
        let runtime = storage.parent().unwrap();
        let config = BootConfig {
            rootfs_path: rootfs.into(),
            storage_disk_path: storage.into(),
            overlay_disk_path: overlay.into(),
            vsock_socket: runtime.join("agent.sock"),
            console_log: Some(runtime.join("console.log")),
            startup_error_log: runtime.join("startup-error.log"),
            storage_size_gb: 1,
            overlay_size_gb: 1,
            mounts,
            ports: Vec::new(),
            resources: VmResources::default(),
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks: Vec::new(),
        };

        let policy = LaunchPolicy::from_boot_config(config).unwrap();
        PreparedLaunch::prepare(policy).unwrap()
    }

    fn find_rule<'a>(rules: &'a [PathRule], path: &Path) -> &'a PathRule {
        rules
            .iter()
            .find(|rule| rule.path == path)
            .unwrap_or_else(|| panic!("missing rule for {}", path.display()))
    }
}
