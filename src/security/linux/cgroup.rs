//! Linux cgroup v2 resource confinement.

use crate::security::hardening::{Enforcement, RunnerResourceReport};
use crate::security::prepare::PreparedLaunch;
use crate::Result;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CHILD_PREFIX: &str = "smolvm-";

pub(super) struct CgroupGuard {
    child: PathBuf,
    parent: PathBuf,
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let pid = std::process::id();
        let _ = write_cgroup_file(&self.parent.join("cgroup.procs"), &pid.to_string());
        let _ = fs::remove_dir(&self.child);
    }
}

pub(super) fn apply(
    prepared: &PreparedLaunch,
) -> Result<(RunnerResourceReport, super::LinuxResourceGuard)> {
    let memory = memory_skipped(prepared);

    let Some(current_rel) = current_cgroup_path()? else {
        return Ok(unavailable(
            "current process is not in a cgroup v2 hierarchy",
            memory,
        ));
    };

    let parent = cgroup_path_under(Path::new(CGROUP_ROOT), &current_rel);
    cleanup_empty_stale_children(&parent);

    let child = match create_child_cgroup(&parent) {
        Ok(child) => child,
        Err(err) if is_unavailable_error(&err) => {
            return Ok(unavailable(
                format!("cgroup v2 parent is not delegated: {err}"),
                memory,
            ));
        }
        Err(err) => {
            return Ok(unavailable(
                format!("failed to create child cgroup: {err}"),
                memory,
            ));
        }
    };

    if let Err(err) = configure_child_type(&parent, &child) {
        let _ = fs::remove_dir(&child);
        return Ok(unavailable(
            format!("failed to configure child cgroup type: {err}"),
            memory,
        ));
    }

    let pids = configure_pids_limit(&parent, &child, planned_pids_max(prepared));

    let pid = std::process::id();
    if let Err(err) = write_cgroup_file(&child.join("cgroup.procs"), &pid.to_string()) {
        let _ = fs::remove_dir(&child);
        return Ok(unavailable(
            format!("failed to move runner into cgroup: {err}"),
            memory,
        ));
    }

    Ok((
        RunnerResourceReport {
            cgroup: Enforcement::Enforced,
            pids,
            memory,
        },
        super::LinuxResourceGuard {
            _cgroup: Some(CgroupGuard { child, parent }),
        },
    ))
}

fn unavailable(
    reason: impl Into<String>,
    memory: Enforcement,
) -> (RunnerResourceReport, super::LinuxResourceGuard) {
    let reason = reason.into();
    (
        RunnerResourceReport {
            cgroup: Enforcement::Unavailable {
                reason: reason.clone(),
            },
            pids: Enforcement::Unavailable { reason },
            memory,
        },
        super::LinuxResourceGuard { _cgroup: None },
    )
}

fn memory_skipped(prepared: &PreparedLaunch) -> Enforcement {
    Enforcement::Skipped {
        reason: format!(
            "memory.max not set until libkrun overhead is measured (guest_memory_mib={})",
            prepared.policy.resources.memory_mib
        ),
    }
}

fn configure_pids_limit(parent: &Path, child: &Path, pids_max: u64) -> Enforcement {
    match enable_controller(parent, "pids") {
        Ok(()) => {}
        Err(err) => {
            return Enforcement::Unavailable {
                reason: format!("failed to enable pids controller: {err}"),
            };
        }
    }

    let pids_max_path = child.join("pids.max");
    if !pids_max_path.exists() {
        return Enforcement::Unavailable {
            reason: "pids.max is not available in child cgroup".to_string(),
        };
    }

    match write_cgroup_file(&pids_max_path, &pids_max.to_string()) {
        Ok(()) => Enforcement::Enforced,
        Err(err) => Enforcement::Unavailable {
            reason: format!("failed to set pids.max={pids_max}: {err}"),
        },
    }
}

fn current_cgroup_path() -> Result<Option<PathBuf>> {
    let content = match fs::read_to_string("/proc/self/cgroup") {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(crate::Error::agent(
                "probe cgroup",
                format!("read /proc/self/cgroup: {err}"),
            ));
        }
    };

    Ok(parse_unified_cgroup_path(&content))
}

fn parse_unified_cgroup_path(content: &str) -> Option<PathBuf> {
    content.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        (hierarchy == "0" && controllers.is_empty()).then(|| PathBuf::from(path))
    })
}

fn cgroup_path_under(root: &Path, cgroup_path: &Path) -> PathBuf {
    let rel = cgroup_path.strip_prefix("/").unwrap_or(cgroup_path);
    root.join(rel)
}

fn create_child_cgroup(parent: &Path) -> io::Result<PathBuf> {
    for attempt in 0..32 {
        let name = format!("{}{}-{}", CHILD_PREFIX, std::process::id(), attempt);
        let child = parent.join(name);
        match fs::create_dir(&child) {
            Ok(()) => return Ok(child),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique smolvm cgroup name",
    ))
}

fn configure_child_type(parent: &Path, child: &Path) -> io::Result<()> {
    let parent_type_path = parent.join("cgroup.type");
    let parent_type = match fs::read_to_string(parent_type_path) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    match parent_type.trim() {
        "domain threaded" | "threaded" => write_cgroup_file(&child.join("cgroup.type"), "threaded"),
        _ => Ok(()),
    }
}

fn cleanup_empty_stale_children(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(CHILD_PREFIX) {
            let _ = fs::remove_dir(entry.path());
        }
    }
}

fn enable_controller(parent: &Path, controller: &str) -> io::Result<()> {
    let controllers = fs::read_to_string(parent.join("cgroup.controllers"))?;
    if !controllers
        .split_whitespace()
        .any(|item| item == controller)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("controller {controller} is not available"),
        ));
    }

    let subtree = fs::read_to_string(parent.join("cgroup.subtree_control"))?;
    if subtree
        .split_whitespace()
        .any(|item| item.trim_start_matches('+') == controller)
    {
        return Ok(());
    }

    write_cgroup_file(
        &parent.join("cgroup.subtree_control"),
        &format!("+{controller}"),
    )
}

fn write_cgroup_file(path: &Path, value: &str) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())
}

fn is_unavailable_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::ReadOnlyFilesystem
            | io::ErrorKind::NotFound
    )
}

fn planned_pids_max(prepared: &PreparedLaunch) -> u64 {
    let resources = &prepared.policy.resources;
    let mut limit = 512u64;
    limit += u64::from(resources.cpus) * 16;
    limit += prepared.mounts.len() as u64 * 8;
    limit += prepared.policy.ports.len() as u64 * 8;
    limit += prepared.extra_disks.len() as u64 * 4;

    if resources.network {
        limit += 128;
    }
    if prepared.policy.devices.gpu {
        limit += 256;
    }
    if prepared.policy.secrets.ssh_agent_socket.is_some() {
        limit += 16;
    }

    limit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::network::PortMapping;
    use crate::data::resources::VmResources;
    use crate::data::storage::HostMount;
    use crate::security::policy::LaunchPolicy;
    use crate::security::prepare::PreparedLaunch;
    use std::process::Command;

    const CHILD_ENV: &str = "SMOLVM_TEST_CGROUP_CHILD";

    #[test]
    fn parses_unified_cgroup_path() {
        let path =
            parse_unified_cgroup_path("0::/user.slice/user-1000.slice/session.scope\n").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/user.slice/user-1000.slice/session.scope")
        );
    }

    #[test]
    fn rejects_non_unified_cgroup_path() {
        assert_eq!(parse_unified_cgroup_path("3:cpu:/legacy\n"), None);
    }

    #[test]
    fn resolves_cgroup_paths_under_root() {
        assert_eq!(
            cgroup_path_under(Path::new("/sys/fs/cgroup"), Path::new("/a/b")),
            PathBuf::from("/sys/fs/cgroup/a/b")
        );
        assert_eq!(
            cgroup_path_under(Path::new("/sys/fs/cgroup"), Path::new("/")),
            PathBuf::from("/sys/fs/cgroup/")
        );
    }

    #[test]
    fn pids_limit_scales_with_host_side_features() {
        let basic = prepared_launch(false, false, 0, 0, 0);
        let larger = prepared_launch(true, true, 2, 3, 1);

        assert_eq!(planned_pids_max(&basic), 512 + 4 * 16);
        assert!(planned_pids_max(&larger) > planned_pids_max(&basic));
    }

    #[test]
    fn cleanup_only_removes_empty_smolvm_children() {
        let temp = tempfile::tempdir().unwrap();
        let empty = temp.path().join("smolvm-empty");
        let nonempty = temp.path().join("smolvm-nonempty");
        let unrelated = temp.path().join("other-empty");
        fs::create_dir(&empty).unwrap();
        fs::create_dir(&nonempty).unwrap();
        fs::create_dir(&unrelated).unwrap();
        fs::write(nonempty.join("file"), b"busy").unwrap();

        cleanup_empty_stale_children(temp.path());

        assert!(!empty.exists());
        assert!(nonempty.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn marks_child_threaded_under_threaded_domain_parent() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(parent.join("cgroup.type"), b"domain threaded\n").unwrap();
        fs::write(child.join("cgroup.type"), b"").unwrap();

        configure_child_type(&parent, &child).unwrap();

        assert_eq!(
            fs::read_to_string(child.join("cgroup.type")).unwrap(),
            "threaded"
        );
    }

    #[test]
    fn leaves_child_domain_under_domain_parent() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        fs::write(parent.join("cgroup.type"), b"domain\n").unwrap();
        fs::write(child.join("cgroup.type"), b"domain\n").unwrap();

        configure_child_type(&parent, &child).unwrap();

        assert_eq!(
            fs::read_to_string(child.join("cgroup.type")).unwrap(),
            "domain\n"
        );
    }

    #[test]
    fn cgroup_confinement_moves_child_when_available() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, "1")
            .args([
                "--exact",
                "security::linux::cgroup::tests::cgroup_child_probe",
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
    fn cgroup_child_probe() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }

        let prepared = prepared_launch(false, false, 0, 0, 0);
        let (report, _guard) = apply(&prepared).unwrap();

        match report.cgroup {
            Enforcement::Enforced => {}
            Enforcement::Unavailable { reason } => {
                eprintln!("cgroup unavailable on this host: {reason}");
                return;
            }
            Enforcement::Skipped { reason } => panic!("unexpected cgroup skip: {reason}"),
        }

        let current = current_cgroup_path().unwrap().unwrap();
        assert!(
            current
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(CHILD_PREFIX)),
            "current cgroup should be a smolvm child, got {}",
            current.display()
        );
        assert_eq!(report.pids, Enforcement::Enforced);
    }

    fn prepared_launch(
        network: bool,
        gpu: bool,
        mount_count: usize,
        port_count: usize,
        extra_disk_count: usize,
    ) -> PreparedLaunch {
        let mounts = (0..mount_count)
            .map(|index| HostMount {
                source: format!("/host/mount-{index}").into(),
                target: format!("/guest/mount-{index}").into(),
                read_only: false,
            })
            .collect();
        let ports = (0..port_count)
            .map(|index| PortMapping::new(8000 + index as u16, 9000 + index as u16))
            .collect();
        let extra_disks = (0..extra_disk_count)
            .map(|index| (format!("/host/disk-{index}.raw").into(), true))
            .collect();

        let config = BootConfig {
            rootfs_path: "/smolvm/rootfs".into(),
            storage_disk_path: "/smolvm/storage.raw".into(),
            overlay_disk_path: "/smolvm/overlay.raw".into(),
            vsock_socket: "/smolvm/agent.sock".into(),
            console_log: None,
            startup_error_log: "/smolvm/startup.err".into(),
            storage_size_gb: 20,
            overlay_size_gb: 10,
            mounts,
            ports,
            resources: VmResources {
                network,
                gpu,
                ..VmResources::default()
            },
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks,
        };

        PreparedLaunch::prepare(LaunchPolicy::from_boot_config(config).unwrap()).unwrap()
    }
}
