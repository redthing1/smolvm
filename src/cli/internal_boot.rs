//! Internal boot subprocess for the API server.
//!
//! This command is NOT for direct user invocation. It's spawned by the API
//! server to launch a VM in a fresh single-threaded process, avoiding the
//! macOS fork-in-multithreaded-process issue.
//!
//! Usage: smolvm _boot-vm <config-path>

use smolvm::agent::boot_config::BootConfig;
use smolvm::agent::{launch_agent_vm, LaunchConfig, VmDisks};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Run the boot subprocess.
///
/// Reads the boot config from the given path, sets up libkrun, and calls
/// `krun_start_enter` which blocks forever (or until the VM exits).
pub fn run(config_path: PathBuf) -> smolvm::Result<()> {
    // Become a session leader (detach from parent's terminal session)
    unsafe {
        libc::setsid();
    }

    let config = read_boot_config(&config_path)?;

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
                        if fd > 2 {
                            libc::close(fd);
                        }
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
                if devnull > 2 {
                    libc::close(devnull);
                }
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
    if let Err(e) = smolvm::process::close_inherited_fds_from(3) {
        let _ = std::fs::write(
            &prepared.policy.startup_error_log,
            format!("failed to close inherited file descriptors: {}", e),
        );
        smolvm::process::exit_child(1);
    }

    let hardening_report = match smolvm::security::hardening::apply_runner_baseline() {
        Ok(report) => report,
        Err(e) => {
            let _ = std::fs::write(
                &prepared.policy.startup_error_log,
                format!("failed to apply runner hardening: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };
    tracing::debug!(
        hardening = %hardening_report.render_text(),
        "applied runner hardening baseline"
    );

    let startup_error_log = prepared.policy.startup_error_log.clone();
    let materialized = match smolvm::security::materialize::materialize_launch(prepared) {
        Ok(materialized) => materialized,
        Err(e) => {
            let _ = std::fs::write(
                &startup_error_log,
                format!("failed to materialize launch paths: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };
    tracing::debug!(
        materialization = %materialized.filesystem_report().render_text(),
        "materialized launch paths"
    );
    let prepared = materialized.prepared();

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
        prepared,
        disks: &disks,
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

fn read_boot_config(path: &Path) -> smolvm::Result<BootConfig> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|e| {
        smolvm::Error::agent("read boot config", format!("{}: {}", path.display(), e))
    })?;
    validate_boot_config_metadata(path, &path_metadata)?;

    let mut file = std::fs::File::open(path).map_err(|e| {
        smolvm::Error::agent("open boot config", format!("{}: {}", path.display(), e))
    })?;
    let file_metadata = file.metadata().map_err(|e| {
        smolvm::Error::agent("stat boot config", format!("{}: {}", path.display(), e))
    })?;
    validate_boot_config_metadata(path, &file_metadata)?;

    #[cfg(unix)]
    ensure_same_boot_config_file(path, &path_metadata, &file_metadata)?;

    let mut config_data = Vec::new();
    file.read_to_end(&mut config_data).map_err(|e| {
        smolvm::Error::agent("read boot config", format!("{}: {}", path.display(), e))
    })?;

    let config: BootConfig = serde_json::from_slice(&config_data)
        .map_err(|e| smolvm::Error::agent("parse boot config", e.to_string()))?;

    #[cfg(unix)]
    {
        let current_metadata = std::fs::symlink_metadata(path).map_err(|e| {
            smolvm::Error::agent("stat boot config", format!("{}: {}", path.display(), e))
        })?;
        ensure_same_boot_config_file(path, &current_metadata, &file_metadata)?;
    }

    drop(file);

    std::fs::remove_file(path).map_err(|e| {
        smolvm::Error::agent("remove boot config", format!("{}: {}", path.display(), e))
    })?;

    Ok(config)
}

fn validate_boot_config_metadata(path: &Path, metadata: &std::fs::Metadata) -> smolvm::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(smolvm::Error::agent(
            "validate boot config",
            format!("{} is not a regular file", path.display()),
        ));
    }

    #[cfg(unix)]
    validate_unix_boot_config_metadata(path, metadata)?;

    Ok(())
}

#[cfg(unix)]
fn validate_unix_boot_config_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> smolvm::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(smolvm::Error::agent(
            "validate boot config",
            format!(
                "{} must not grant group/other access (mode {:03o})",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    if mode & 0o400 == 0 {
        return Err(smolvm::Error::agent(
            "validate boot config",
            format!("{} must be owner-readable", path.display()),
        ));
    }

    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(smolvm::Error::agent(
            "validate boot config",
            format!(
                "{} is owned by uid {}, expected current euid {}",
                path.display(),
                metadata.uid(),
                euid
            ),
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn ensure_same_boot_config_file(
    path: &Path,
    expected: &std::fs::Metadata,
    actual: &std::fs::Metadata,
) -> smolvm::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(smolvm::Error::agent(
            "validate boot config",
            format!("{} changed while being opened", path.display()),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use smolvm::agent::VmResources;

    fn sample_boot_config(base: &Path) -> BootConfig {
        BootConfig {
            rootfs_path: base.join("rootfs"),
            storage_disk_path: base.join("storage.img"),
            overlay_disk_path: base.join("overlay.img"),
            vsock_socket: base.join("agent.sock"),
            console_log: Some(base.join("console.log")),
            startup_error_log: base.join("startup-error.log"),
            storage_size_gb: 1,
            overlay_size_gb: 1,
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: VmResources::default(),
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks: Vec::new(),
        }
    }

    fn write_config(path: &Path, config: &BootConfig, mode: u32) {
        let json = serde_json::to_vec(config).unwrap();
        std::fs::write(path, json).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn read_boot_config_accepts_owner_only_file_and_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boot-config.json");
        let config = sample_boot_config(tmp.path());
        write_config(&path, &config, 0o600);

        let parsed = read_boot_config(&path).unwrap();

        assert_eq!(parsed.rootfs_path, config.rootfs_path);
        assert_eq!(parsed.storage_disk_path, config.storage_disk_path);
        assert!(
            !path.exists(),
            "boot config should be removed after parsing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_boot_config_rejects_group_accessible_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("boot-config.json");
        let config = sample_boot_config(tmp.path());
        write_config(&path, &config, 0o640);

        let err = read_boot_config(&path).expect_err("group-readable config must fail");

        assert!(
            err.to_string().contains("group/other access"),
            "unexpected error: {err}"
        );
        assert!(path.exists(), "rejected config should not be removed");
    }

    #[cfg(unix)]
    #[test]
    fn read_boot_config_rejects_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.json");
        let link = tmp.path().join("boot-config.json");
        let config = sample_boot_config(tmp.path());
        write_config(&target, &config, 0o600);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_boot_config(&link).expect_err("symlink config must fail");

        assert!(
            err.to_string().contains("regular file"),
            "unexpected error: {err}"
        );
        assert!(target.exists());
        assert!(link.exists());
    }
}
