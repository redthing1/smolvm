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

    let config = read_boot_config_and_remove(&config_path)?;

    if let Err(e) = redirect_stdio(&config) {
        exit_with_startup_error(
            &config.startup_error_log,
            format_args!("failed to redirect stdio: {e}"),
        );
    }

    // Close ALL inherited file descriptors from the parent (server).
    // Without this, the subprocess holds database locks, network sockets, etc.
    // that can interfere with libkrun's operation. Keep stdin/stdout/stderr (0-2)
    // which now point to /dev/null.
    if let Err(e) = smolvm::process::close_inherited_fds_from(3) {
        exit_with_startup_error(
            &config.startup_error_log,
            format_args!("failed to close inherited file descriptors: {e}"),
        );
    }

    // Open storage and overlay disks
    let storage_disk = match smolvm::storage::StorageDisk::open_or_create_at(
        &config.storage_disk_path,
        config.storage_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            exit_with_startup_error(
                &config.startup_error_log,
                format_args!("failed to open storage disk: {e}"),
            );
        }
    };

    let overlay_disk = match smolvm::storage::OverlayDisk::open_or_create_at(
        &config.overlay_disk_path,
        config.overlay_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            exit_with_startup_error(
                &config.startup_error_log,
                format_args!("failed to open overlay disk: {e}"),
            );
        }
    };

    // Launch the VM (never returns on success)
    let disks = VmDisks {
        storage: &storage_disk,
        overlay: Some(&overlay_disk),
    };

    let result = launch_agent_vm(&LaunchConfig {
        rootfs_path: &config.rootfs_path,
        disks: &disks,
        vsock_socket: &config.vsock_socket,
        console_log: config.console_log.as_deref(),
        mounts: &config.mounts,
        port_mappings: &config.ports,
        resources: config.resources,
        ssh_agent_socket: config.ssh_agent_socket.as_deref(),
        preloaded_image_dir: config.preloaded_image_dir.as_deref(),
        extra_disks: &config.extra_disks,
        egress_refresh_hosts: config.egress_policy_hosts.clone(),
    });

    // If we get here, launch_agent_vm returned (should only happen on error)
    if let Err(ref e) = result {
        append_startup_error(&config.startup_error_log, e);
    }

    smolvm::process::exit_child(1);
}

fn exit_with_startup_error(path: &Path, message: impl std::fmt::Display) -> ! {
    write_startup_error(path, message);
    smolvm::process::exit_child(1);
}

fn write_startup_error(path: &Path, message: impl std::fmt::Display) {
    let _ = std::fs::write(path, message.to_string());
}

fn append_startup_error(path: &Path, message: impl std::fmt::Display) {
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{message}")
        });
}

fn redirect_stdio(config: &BootConfig) -> smolvm::Result<()> {
    // Redirect stdio. When SMOLVM_GPU_DEBUG=1, keep stderr pointed at a
    // debug log file so virglrenderer/MoltenVK errors are captured.
    if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
        if let Some(ref log) = config.console_log {
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
        Ok(())
    } else {
        smolvm::process::detach_stdio_to_stderr_file(&config.startup_error_log)
            .map_err(|e| smolvm::Error::agent("redirect stdio", e.to_string()))
    }
}

fn read_boot_config_and_remove(path: &Path) -> smolvm::Result<BootConfig> {
    let read = read_owner_only_file(path, "boot config")?;
    let config = serde_json::from_slice(&read.data)
        .map_err(|e| smolvm::Error::agent("parse boot config", e.to_string()))?;
    remove_owner_only_file(path, "boot config", &read.identity)?;
    Ok(config)
}

struct OwnerOnlyFileRead {
    data: Vec<u8>,
    identity: OwnerOnlyFileIdentity,
}

#[derive(Clone, Copy)]
struct OwnerOnlyFileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

fn read_owner_only_file(path: &Path, label: &'static str) -> smolvm::Result<OwnerOnlyFileRead> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|e| {
        smolvm::Error::agent(
            format!("read {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;
    validate_owner_only_file_metadata(path, label, &path_metadata)?;

    let mut file = std::fs::File::open(path).map_err(|e| {
        smolvm::Error::agent(
            format!("open {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;
    let file_metadata = file.metadata().map_err(|e| {
        smolvm::Error::agent(
            format!("stat {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;
    validate_owner_only_file_metadata(path, label, &file_metadata)?;

    let identity = OwnerOnlyFileIdentity::from_metadata(&file_metadata);

    #[cfg(unix)]
    ensure_same_file(path, label, &path_metadata, &file_metadata)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        smolvm::Error::agent(
            format!("read {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;

    #[cfg(unix)]
    {
        let current_metadata = std::fs::symlink_metadata(path).map_err(|e| {
            smolvm::Error::agent(
                format!("stat {label}"),
                format!("{}: {}", path.display(), e),
            )
        })?;
        ensure_same_file(path, label, &current_metadata, &file_metadata)?;
    }

    Ok(OwnerOnlyFileRead { data, identity })
}

fn remove_owner_only_file(
    path: &Path,
    label: &'static str,
    identity: &OwnerOnlyFileIdentity,
) -> smolvm::Result<()> {
    let current_metadata = std::fs::symlink_metadata(path).map_err(|e| {
        smolvm::Error::agent(
            format!("stat {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;
    validate_owner_only_file_metadata(path, label, &current_metadata)?;
    identity.ensure_matches(path, label, &current_metadata)?;

    std::fs::remove_file(path).map_err(|e| {
        smolvm::Error::agent(
            format!("remove {label}"),
            format!("{}: {}", path.display(), e),
        )
    })?;

    Ok(())
}

impl OwnerOnlyFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self {}
        }
    }

    fn ensure_matches(
        &self,
        path: &Path,
        label: &'static str,
        metadata: &std::fs::Metadata,
    ) -> smolvm::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if self.dev != metadata.dev() || self.ino != metadata.ino() {
                return Err(smolvm::Error::agent(
                    format!("validate {label}"),
                    format!("{} changed while being opened", path.display()),
                ));
            }
        }

        #[cfg(not(unix))]
        let _ = (path, label, metadata);

        Ok(())
    }
}

fn validate_owner_only_file_metadata(
    path: &Path,
    label: &'static str,
    metadata: &std::fs::Metadata,
) -> smolvm::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(smolvm::Error::agent(
            format!("validate {label}"),
            format!("{} is not a regular file", path.display()),
        ));
    }

    #[cfg(unix)]
    validate_unix_owner_only_file_metadata(path, label, metadata)?;

    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner_only_file_metadata(
    path: &Path,
    label: &'static str,
    metadata: &std::fs::Metadata,
) -> smolvm::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(smolvm::Error::agent(
            format!("validate {label}"),
            format!(
                "{} must not grant group/other access (mode {:03o})",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    if mode & 0o400 == 0 {
        return Err(smolvm::Error::agent(
            format!("validate {label}"),
            format!("{} must be owner-readable", path.display()),
        ));
    }

    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(smolvm::Error::agent(
            format!("validate {label}"),
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
fn ensure_same_file(
    path: &Path,
    label: &'static str,
    expected: &std::fs::Metadata,
    actual: &std::fs::Metadata,
) -> smolvm::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
        return Err(smolvm::Error::agent(
            format!("validate {label}"),
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

        let parsed = read_boot_config_and_remove(&path).unwrap();

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

        let err = read_boot_config_and_remove(&path).expect_err("group-readable config must fail");

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

        let err = read_boot_config_and_remove(&link).expect_err("symlink config must fail");

        assert!(
            err.to_string().contains("regular file"),
            "unexpected error: {err}"
        );
        assert!(target.exists());
        assert!(link.exists());
    }
}
