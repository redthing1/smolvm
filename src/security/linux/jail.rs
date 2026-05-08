//! Linux per-launch filesystem view materialization.
//!
//! This module is intentionally small and side-effectful. It validates and pins
//! granted host paths, creates a private mount namespace when the runner has
//! the required privilege, bind-mounts only those grants into a generated
//! runtime directory, and rewrites VMM-facing paths to that generated view.

use crate::security::hardening::Enforcement;
use crate::security::prepare::PreparedLaunch;
use crate::{Error, Result};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

const JAIL_ROOT_COMPONENT: &str = "jails";

pub(super) fn materialize(
    prepared: PreparedLaunch,
) -> Result<(PreparedLaunch, Enforcement, Option<JailGuard>)> {
    let specs = collect_binding_specs(&prepared)?;
    if specs.is_empty() {
        return Ok((
            prepared,
            Enforcement::Skipped {
                reason: "no filesystem grants require generated VMM paths".to_string(),
            },
            None,
        ));
    }

    if let Some(reason) = enter_private_mount_namespace()? {
        return Ok((prepared, Enforcement::Unavailable { reason }, None));
    }

    make_mounts_private()?;

    let mut guard = JailGuard::new(create_jail_root(&prepared)?);
    let plans = plan_bind_paths(&specs, guard.root())?;

    for plan in &plans {
        create_bind_target(plan)?;
        let source = open_source(&plan.spec)?;
        bind_mount(&source, &plan.destination, plan.spec.kind)?;
        guard.record_mount(plan.destination.clone());

        if plan.spec.read_only {
            remount_readonly(&plan.destination, plan.spec.kind)?;
        }
    }

    let prepared = apply_bind_paths(prepared, &plans);
    Ok((prepared, Enforcement::Enforced, Some(guard)))
}

pub(crate) struct JailGuard {
    root: PathBuf,
    mounts: Vec<PathBuf>,
}

impl Drop for JailGuard {
    fn drop(&mut self) {
        for path in self.mounts.iter().rev() {
            let Ok(cpath) = path_to_cstring(path) else {
                continue;
            };
            unsafe {
                libc::umount2(cpath.as_ptr(), libc::MNT_DETACH);
            }
        }

        let _ = fs::remove_dir_all(&self.root);
    }
}

impl JailGuard {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            mounts: Vec::new(),
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn record_mount(&mut self, path: PathBuf) {
        self.mounts.push(path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingSpec {
    target: BindingTarget,
    source: PathBuf,
    kind: BindKind,
    read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindPlan {
    spec: BindingSpec,
    destination: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingTarget {
    UserMount(usize),
    PreloadedImage,
    ExtraDisk(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindKind {
    Directory,
    File,
}

impl BindKind {
    fn label(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "regular file",
        }
    }
}

fn collect_binding_specs(prepared: &PreparedLaunch) -> Result<Vec<BindingSpec>> {
    let mut specs = Vec::new();

    for (index, mount) in prepared.mounts.iter().enumerate() {
        validate_source(
            &mount.host_source,
            BindKind::Directory,
            SourceRequirement::Required,
        )?;
        specs.push(BindingSpec {
            target: BindingTarget::UserMount(index),
            source: mount.host_source.clone(),
            kind: BindKind::Directory,
            read_only: mount.access.is_read_only(),
        });
    }

    if let Some(mount) = &prepared.preloaded_image_mount {
        if validate_source(
            &mount.host_source,
            BindKind::Directory,
            SourceRequirement::Optional,
        )? {
            specs.push(BindingSpec {
                target: BindingTarget::PreloadedImage,
                source: mount.host_source.clone(),
                kind: BindKind::Directory,
                read_only: true,
            });
        }
    }

    for (index, disk) in prepared.extra_disks.iter().enumerate() {
        validate_source(
            &disk.original_path,
            BindKind::File,
            SourceRequirement::Required,
        )?;
        specs.push(BindingSpec {
            target: BindingTarget::ExtraDisk(index),
            source: disk.original_path.clone(),
            kind: BindKind::File,
            read_only: disk.read_only,
        });
    }

    Ok(specs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceRequirement {
    Required,
    Optional,
}

fn validate_source(path: &Path, kind: BindKind, requirement: SourceRequirement) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if requirement == SourceRequirement::Optional
                && error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(false);
        }
        Err(error) => {
            return Err(Error::agent(
                "validate filesystem jail source",
                format!("{}: {error}", path.display()),
            ));
        }
    };

    if metadata.file_type().is_symlink() {
        return Err(Error::agent(
            "validate filesystem jail source",
            format!("source path must not be a symlink: {}", path.display()),
        ));
    }

    let valid_kind = match kind {
        BindKind::Directory => metadata.is_dir(),
        BindKind::File => metadata.is_file(),
    };
    if !valid_kind {
        return Err(Error::agent(
            "validate filesystem jail source",
            format!("source path must be a {}: {}", kind.label(), path.display()),
        ));
    }

    Ok(true)
}

fn plan_bind_paths(specs: &[BindingSpec], root: &Path) -> Result<Vec<BindPlan>> {
    specs
        .iter()
        .map(|spec| {
            let destination = match spec.target {
                BindingTarget::UserMount(index) => {
                    root.join("mounts").join(format!("smolvm{index}"))
                }
                BindingTarget::PreloadedImage => root.join("mounts").join("smolvm_image"),
                BindingTarget::ExtraDisk(index) => root.join("disks").join(format!("extra{index}")),
            };
            ensure_under_root(root, &destination)?;
            Ok(BindPlan {
                spec: spec.clone(),
                destination,
            })
        })
        .collect()
}

fn apply_bind_paths(mut prepared: PreparedLaunch, plans: &[BindPlan]) -> PreparedLaunch {
    for plan in plans {
        match plan.spec.target {
            BindingTarget::UserMount(index) => {
                prepared.mounts[index].source_for_vmm = plan.destination.clone();
            }
            BindingTarget::PreloadedImage => {
                if let Some(mount) = &mut prepared.preloaded_image_mount {
                    mount.source_for_vmm = plan.destination.clone();
                }
            }
            BindingTarget::ExtraDisk(index) => {
                prepared.extra_disks[index].path_for_vmm = plan.destination.clone();
            }
        }
    }
    prepared
}

fn enter_private_mount_namespace() -> Result<Option<String>> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if ret == 0 {
        return Ok(None);
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EPERM) => Ok(Some(
            "private mount namespace requires CAP_SYS_ADMIN; rootless helper not installed"
                .to_string(),
        )),
        Some(libc::EINVAL) | Some(libc::ENOSYS) => Ok(Some(format!(
            "private mount namespace is not supported by this kernel: {error}"
        ))),
        _ => Err(Error::agent(
            "create filesystem jail namespace",
            error.to_string(),
        )),
    }
}

fn make_mounts_private() -> Result<()> {
    let target = cstring_literal("/")?;
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_os_error("make mount namespace private"));
    }
    Ok(())
}

fn create_jail_root(prepared: &PreparedLaunch) -> Result<PathBuf> {
    create_jail_root_in(launch_runtime_dir(prepared)?)
}

fn launch_runtime_dir(prepared: &PreparedLaunch) -> Result<&Path> {
    prepared
        .policy
        .startup_error_log
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::agent(
                "create filesystem jail root",
                format!(
                    "startup error log has no runtime directory: {}",
                    prepared.policy.startup_error_log.display()
                ),
            )
        })
}

fn create_jail_root_in(base: &Path) -> Result<PathBuf> {
    validate_runtime_dir(base)?;
    let parent = base.join(JAIL_ROOT_COMPONENT);
    create_owner_only_dir(&parent, "create filesystem jail root")?;

    for _ in 0..16 {
        let root = parent.join(format!(
            "{}-{}",
            std::process::id(),
            crate::util::generate_short_id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&root) {
            Ok(()) => return Ok(root),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::agent(
                    "create filesystem jail root",
                    format!("{}: {error}", root.display()),
                ));
            }
        }
    }

    Err(Error::agent(
        "create filesystem jail root",
        "failed to allocate a unique jail directory",
    ))
}

fn create_owner_only_dir(path: &Path, operation: &'static str) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::agent(
                operation,
                format!("{}: {error}", path.display()),
            ));
        }
    }
    validate_generated_parent_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        Error::agent(
            operation,
            format!("set permissions on {}: {error}", path.display()),
        )
    })
}

fn validate_runtime_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::agent(
            "validate filesystem jail root",
            format!("{}: {error}", path.display()),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::agent(
            "validate filesystem jail root",
            format!("launch runtime path is not a directory: {}", path.display()),
        ));
    }

    Ok(())
}

fn validate_generated_parent_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::agent(
            "validate filesystem jail root",
            format!("{}: {error}", path.display()),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::agent(
            "validate filesystem jail root",
            format!(
                "generated jail parent is not a directory: {}",
                path.display()
            ),
        ));
    }

    Ok(())
}

fn create_bind_target(plan: &BindPlan) -> Result<()> {
    match plan.spec.kind {
        BindKind::Directory => fs::create_dir_all(&plan.destination).map_err(|error| {
            Error::agent(
                "create filesystem jail target",
                format!("{}: {error}", plan.destination.display()),
            )
        }),
        BindKind::File => {
            let parent = plan.destination.parent().ok_or_else(|| {
                Error::agent(
                    "create filesystem jail target",
                    format!("{} has no parent directory", plan.destination.display()),
                )
            })?;
            fs::create_dir_all(parent).map_err(|error| {
                Error::agent(
                    "create filesystem jail target",
                    format!("{}: {error}", parent.display()),
                )
            })?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&plan.destination)
                .map(|_| ())
                .map_err(|error| {
                    Error::agent(
                        "create filesystem jail target",
                        format!("{}: {error}", plan.destination.display()),
                    )
                })
        }
    }
}

fn open_source(spec: &BindingSpec) -> Result<OwnedFd> {
    let cpath = path_to_cstring(&spec.source)?;
    let mut flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if spec.kind == BindKind::Directory {
        flags |= libc::O_DIRECTORY;
    }

    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_os_error(format!(
            "open filesystem jail source {}",
            spec.source.display()
        )));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    verify_open_source(&fd, spec)?;
    Ok(fd)
}

fn verify_open_source(fd: &OwnedFd, spec: &BindingSpec) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let ret = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
    if ret != 0 {
        return Err(last_os_error(format!(
            "stat filesystem jail source {}",
            spec.source.display()
        )));
    }
    let stat = unsafe { stat.assume_init() };
    let mode = stat.st_mode & libc::S_IFMT;
    let expected = match spec.kind {
        BindKind::Directory => libc::S_IFDIR,
        BindKind::File => libc::S_IFREG,
    };

    if mode != expected {
        return Err(Error::agent(
            "validate filesystem jail source",
            format!(
                "source path changed or has wrong type before bind mount: {}",
                spec.source.display()
            ),
        ));
    }

    Ok(())
}

fn bind_mount(source: &OwnedFd, destination: &Path, kind: BindKind) -> Result<()> {
    let source_path = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
    let csource = path_to_cstring(&source_path)?;
    let cdestination = path_to_cstring(destination)?;
    let mut flags = libc::MS_BIND as libc::c_ulong;
    if kind == BindKind::Directory {
        flags |= libc::MS_REC as libc::c_ulong;
    }
    let ret = unsafe {
        libc::mount(
            csource.as_ptr(),
            cdestination.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_os_error(format!(
            "bind mount filesystem jail path {}",
            destination.display()
        )));
    }
    Ok(())
}

fn remount_readonly(destination: &Path, kind: BindKind) -> Result<()> {
    let cdestination = path_to_cstring(destination)?;
    let mut flags = (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong;
    if kind == BindKind::Directory {
        flags |= libc::MS_REC as libc::c_ulong;
    }
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            cdestination.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(last_os_error(format!(
            "remount filesystem jail path read-only {}",
            destination.display()
        )));
    }
    Ok(())
}

fn ensure_under_root(root: &Path, destination: &Path) -> Result<()> {
    if destination.starts_with(root) {
        return Ok(());
    }

    Err(Error::agent(
        "plan filesystem jail paths",
        format!(
            "generated path escaped jail root: {} outside {}",
            destination.display(),
            root.display()
        ),
    ))
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::agent(
            "convert filesystem jail path",
            format!("path contains null byte: {}", path.display()),
        )
    })
}

fn cstring_literal(value: &str) -> Result<CString> {
    CString::new(value)
        .map_err(|_| Error::agent("convert filesystem jail path", "literal contains null byte"))
}

fn last_os_error(operation: impl Into<String>) -> Error {
    Error::agent(
        "materialize filesystem jail",
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

    #[test]
    fn jail_paths_preserve_original_audit_paths() {
        let temp = tempfile::tempdir().unwrap();
        let host_mount = temp.path().join("host");
        let image = temp.path().join("image");
        let disk = temp.path().join("disk.raw");
        let jail_root = temp.path().join("jail");
        fs::create_dir_all(&host_mount).unwrap();
        fs::create_dir_all(&image).unwrap();
        fs::write(&disk, b"disk").unwrap();

        let prepared = prepared_launch(&host_mount, Some(&image), vec![(disk.clone(), true)]);
        let specs = collect_binding_specs(&prepared).unwrap();
        let plans = plan_bind_paths(&specs, &jail_root).unwrap();
        let materialized = apply_bind_paths(prepared, &plans);

        assert_eq!(materialized.mounts[0].host_source, host_mount);
        assert_ne!(
            materialized.mounts[0].host_source,
            materialized.mounts[0].source_for_vmm
        );
        assert!(materialized.mounts[0]
            .source_for_vmm
            .starts_with(&jail_root));

        let image_mount = materialized.preloaded_image_mount.as_ref().unwrap();
        assert_eq!(image_mount.host_source, image);
        assert!(image_mount.source_for_vmm.starts_with(&jail_root));

        assert_eq!(materialized.extra_disks[0].original_path, disk);
        assert!(materialized.extra_disks[0]
            .path_for_vmm
            .starts_with(&jail_root));
    }

    #[test]
    fn jail_paths_rewrite_vmm_paths_to_stable_generated_paths() {
        let temp = tempfile::tempdir().unwrap();
        let host_mount = temp.path().join("host");
        let jail_root = temp.path().join("jail");
        fs::create_dir_all(&host_mount).unwrap();

        let prepared = prepared_launch(&host_mount, None, Vec::new());
        let specs = collect_binding_specs(&prepared).unwrap();
        let plans = plan_bind_paths(&specs, &jail_root).unwrap();
        let materialized = apply_bind_paths(prepared, &plans);

        assert_eq!(
            materialized.mounts[0].source_for_vmm,
            jail_root.join("mounts").join("smolvm0")
        );
    }

    #[test]
    fn jail_paths_do_not_fake_success_with_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let prepared = prepared_launch(&link, None, Vec::new());
        let err = collect_binding_specs(&prepared).unwrap_err();

        assert!(err.to_string().contains("must not be a symlink"));
    }

    #[test]
    fn open_source_rejects_symlink_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("disk.raw");
        let replacement_target = temp.path().join("replacement.raw");
        fs::write(&original, b"disk").unwrap();
        fs::write(&replacement_target, b"replacement").unwrap();

        let spec = BindingSpec {
            target: BindingTarget::ExtraDisk(0),
            source: original.clone(),
            kind: BindKind::File,
            read_only: true,
        };
        validate_source(&spec.source, spec.kind, SourceRequirement::Required).unwrap();

        fs::remove_file(&original).unwrap();
        std::os::unix::fs::symlink(&replacement_target, &original).unwrap();

        let err = open_source(&spec).unwrap_err();

        assert!(err
            .to_string()
            .contains("changed or has wrong type before bind mount"));
    }

    #[test]
    fn jail_cleanup_removes_runtime_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("jail");
        fs::create_dir_all(&root).unwrap();

        drop(JailGuard::new(root.clone()));

        assert!(!root.exists());
    }

    #[test]
    fn stale_runtime_files_are_not_reused() {
        let temp = tempfile::tempdir().unwrap();
        let stale = temp.path().join(JAIL_ROOT_COMPONENT).join("stale");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("leftover"), b"old").unwrap();

        let root = create_jail_root_in(temp.path()).unwrap();
        let parent_mode = root
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_ne!(root, stale);
        assert_eq!(parent_mode, 0o700);
        assert!(root.read_dir().unwrap().next().is_none());
    }

    fn prepared_launch(
        mount: &Path,
        preloaded_image: Option<&Path>,
        extra_disks: Vec<(PathBuf, bool)>,
    ) -> PreparedLaunch {
        let config = BootConfig {
            rootfs_path: "/smolvm/rootfs".into(),
            storage_disk_path: "/smolvm/storage.raw".into(),
            overlay_disk_path: "/smolvm/overlay.raw".into(),
            vsock_socket: "/smolvm/agent.sock".into(),
            console_log: None,
            startup_error_log: "/smolvm/startup.err".into(),
            storage_size_gb: 20,
            overlay_size_gb: 10,
            mounts: vec![HostMount {
                source: mount.into(),
                target: "/workspace".into(),
                read_only: false,
            }],
            ports: Vec::new(),
            resources: VmResources::default(),
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: preloaded_image.map(PathBuf::from),
            extra_disks,
        };

        let policy = LaunchPolicy::from_boot_config(config).unwrap();
        PreparedLaunch::prepare(policy).unwrap()
    }
}
