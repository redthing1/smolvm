//! Validation for secret-like host capabilities.
//!
//! Secret grants are explicit bridges from the guest back to host authority.
//! This module keeps their side-effectful validation out of pure policy and
//! out of the libkrun setup path.

use crate::security::prepare::PreparedLaunch;
use crate::{Error, Result};
use std::path::Path;

/// Validate host secret grants before exposing them to the VM.
pub fn validate_secret_grants(prepared: &PreparedLaunch) -> Result<()> {
    if let Some(socket) = &prepared.policy.secrets.ssh_agent_socket {
        validate_ssh_agent_socket(socket)?;
    }

    Ok(())
}

#[cfg(unix)]
fn validate_ssh_agent_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    if !path.is_absolute() {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!("socket path must be absolute: {}", path.display()),
        ));
    }

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::agent(
            "validate SSH agent socket",
            format!("{}: {error}", path.display()),
        )
    })?;

    if metadata.file_type().is_symlink() {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!("socket path must not be a symlink: {}", path.display()),
        ));
    }

    if !metadata.file_type().is_socket() {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!("path must be a Unix socket: {}", path.display()),
        ));
    }

    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!(
                "{} is owned by uid {}, expected current euid {}",
                path.display(),
                metadata.uid(),
                euid
            ),
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        Error::agent(
            "validate SSH agent socket",
            format!("{} has no parent directory", path.display()),
        )
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        Error::agent(
            "validate SSH agent socket",
            format!("{}: {error}", parent.display()),
        )
    })?;

    if parent_metadata.file_type().is_symlink() {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!("socket parent must not be a symlink: {}", parent.display()),
        ));
    }

    if !parent_metadata.is_dir() {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!("socket parent must be a directory: {}", parent.display()),
        ));
    }

    if parent_metadata.uid() != euid {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!(
                "{} is owned by uid {}, expected current euid {}",
                parent.display(),
                parent_metadata.uid(),
                euid
            ),
        ));
    }

    let mode = parent_metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(Error::agent(
            "validate SSH agent socket",
            format!(
                "{} must not be group/other writable (mode {:03o})",
                parent.display(),
                mode & 0o777
            ),
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_ssh_agent_socket(path: &Path) -> Result<()> {
    Err(Error::agent(
        "validate SSH agent socket",
        format!(
            "{} cannot be forwarded on this host: Unix sockets are required",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::resources::VmResources;
    use crate::security::policy::LaunchPolicy;
    use std::path::PathBuf;

    #[test]
    fn accepts_launch_without_secret_grants() {
        let prepared = prepared_launch(None);

        validate_secret_grants(&prepared).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn accepts_owned_unix_socket_in_private_parent() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let prepared = prepared_launch(Some(socket));

        validate_secret_grants(&prepared).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_missing_ssh_agent_socket() {
        let temp = tempfile::tempdir().unwrap();
        let prepared = prepared_launch(Some(temp.path().join("missing.sock")));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("missing.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_relative_ssh_agent_socket() {
        let prepared = prepared_launch(Some(PathBuf::from("agent.sock")));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("must be absolute"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_regular_file_as_ssh_agent_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("not-a-socket");
        std::fs::write(&path, b"not a socket").unwrap();
        let prepared = prepared_launch(Some(path));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("must be a Unix socket"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ssh_agent_socket() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("agent.sock");
        let link = temp.path().join("agent-link.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let prepared = prepared_launch(Some(link));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_ssh_agent_socket_parent() {
        let temp = tempfile::tempdir().unwrap();
        let real_parent = temp.path().join("real-agent-dir");
        let link_parent = temp.path().join("agent-dir-link");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
        let socket = link_parent.join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let prepared = prepared_launch(Some(socket));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("parent must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_socket_in_group_or_other_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("agent-dir");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let socket = parent.join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let prepared = prepared_launch(Some(socket));

        let err = validate_secret_grants(&prepared).unwrap_err();

        assert!(err.to_string().contains("must not be group/other writable"));
    }

    fn prepared_launch(ssh_agent_socket: Option<PathBuf>) -> PreparedLaunch {
        let config = BootConfig {
            rootfs_path: "/smolvm/rootfs".into(),
            storage_disk_path: "/smolvm/storage.raw".into(),
            overlay_disk_path: "/smolvm/overlay.raw".into(),
            vsock_socket: "/smolvm/agent.sock".into(),
            console_log: None,
            startup_error_log: "/smolvm/startup.err".into(),
            storage_size_gb: 20,
            overlay_size_gb: 10,
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: VmResources::default(),
            ssh_agent_socket,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks: Vec::new(),
        };

        let policy = LaunchPolicy::from_boot_config(config).unwrap();
        PreparedLaunch::prepare(policy).unwrap()
    }
}
