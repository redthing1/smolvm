//! Planned host filesystem view for a launch.
//!
//! This module is pure data shaping. It decides which prepared launch paths
//! need generated VMM-facing paths and where those generated paths should be.
//! Linux-specific validation, namespaces, bind mounts, and cleanup stay in the
//! Linux materialization code.

use crate::data::storage::MountAccess;
use crate::security::prepare::PreparedLaunch;
use std::path::{Path, PathBuf};

/// Host paths that should appear in a generated launch filesystem view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemViewRequest {
    entries: Vec<FilesystemViewSource>,
}

impl FilesystemViewRequest {
    pub(crate) fn from_entries(entries: Vec<FilesystemViewSource>) -> Self {
        Self { entries }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn entries(&self) -> &[FilesystemViewSource] {
        &self.entries
    }

    /// Add deterministic generated destination paths under `root`.
    pub(crate) fn plan(self, root: PathBuf) -> FilesystemViewSpec {
        let entries = self
            .entries
            .into_iter()
            .map(|source| FilesystemViewEntry {
                destination: destination_for(&root, source.target),
                source,
            })
            .collect();

        FilesystemViewSpec { root, entries }
    }
}

/// Fully planned generated filesystem view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemViewSpec {
    root: PathBuf,
    entries: Vec<FilesystemViewEntry>,
}

impl FilesystemViewSpec {
    pub(crate) fn entries(&self) -> &[FilesystemViewEntry] {
        &self.entries
    }
}

/// One host source requested for the generated view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemViewSource {
    pub(crate) target: FilesystemViewTarget,
    pub(crate) source: PathBuf,
    pub(crate) kind: FilesystemViewKind,
    pub(crate) access: FilesystemViewAccess,
    pub(crate) requirement: FilesystemViewSourceRequirement,
}

/// One planned bind target in the generated view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemViewEntry {
    pub(crate) source: FilesystemViewSource,
    pub(crate) destination: PathBuf,
}

/// The prepared launch field that receives the generated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemViewTarget {
    UserMount(usize),
    PreloadedImage,
    ExtraDisk(usize),
}

/// Filesystem object type expected at the source path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemViewKind {
    Directory,
    RegularFile,
}

impl FilesystemViewKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular file",
        }
    }
}

/// Access requested for the generated view path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemViewAccess {
    ReadOnly,
    ReadWrite,
}

impl FilesystemViewAccess {
    fn from_mount_access(access: MountAccess) -> Self {
        match access {
            MountAccess::ReadOnly => Self::ReadOnly,
            MountAccess::ReadWrite => Self::ReadWrite,
        }
    }

    pub(crate) fn from_read_only(read_only: bool) -> Self {
        if read_only {
            Self::ReadOnly
        } else {
            Self::ReadWrite
        }
    }

    pub(crate) fn is_read_only(self) -> bool {
        self == Self::ReadOnly
    }
}

/// Whether a missing source should fail materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemViewSourceRequirement {
    Required,
    Optional,
}

/// Build the requested filesystem view from prepared launch data.
pub(crate) fn request_from_prepared(prepared: &PreparedLaunch) -> FilesystemViewRequest {
    let mut entries = Vec::new();

    for (index, mount) in prepared.mounts.iter().enumerate() {
        entries.push(FilesystemViewSource {
            target: FilesystemViewTarget::UserMount(index),
            source: mount.host_source.clone(),
            kind: FilesystemViewKind::Directory,
            access: FilesystemViewAccess::from_mount_access(mount.access),
            requirement: FilesystemViewSourceRequirement::Required,
        });
    }

    if let Some(mount) = &prepared.preloaded_image_mount {
        entries.push(FilesystemViewSource {
            target: FilesystemViewTarget::PreloadedImage,
            source: mount.host_source.clone(),
            kind: FilesystemViewKind::Directory,
            access: FilesystemViewAccess::ReadOnly,
            requirement: FilesystemViewSourceRequirement::Optional,
        });
    }

    for (index, disk) in prepared.extra_disks.iter().enumerate() {
        entries.push(FilesystemViewSource {
            target: FilesystemViewTarget::ExtraDisk(index),
            source: disk.original_path.clone(),
            kind: FilesystemViewKind::RegularFile,
            access: FilesystemViewAccess::from_read_only(disk.read_only),
            requirement: FilesystemViewSourceRequirement::Required,
        });
    }

    FilesystemViewRequest::from_entries(entries)
}

/// Rewrite only VMM-facing paths in the prepared launch.
pub(crate) fn apply_to_prepared(
    spec: &FilesystemViewSpec,
    mut prepared: PreparedLaunch,
) -> PreparedLaunch {
    for entry in spec.entries() {
        match entry.source.target {
            FilesystemViewTarget::UserMount(index) => {
                prepared.mounts[index].source_for_vmm = entry.destination.clone();
            }
            FilesystemViewTarget::PreloadedImage => {
                if let Some(mount) = &mut prepared.preloaded_image_mount {
                    mount.source_for_vmm = entry.destination.clone();
                }
            }
            FilesystemViewTarget::ExtraDisk(index) => {
                prepared.extra_disks[index].path_for_vmm = entry.destination.clone();
            }
        }
    }
    prepared
}

fn destination_for(root: &Path, target: FilesystemViewTarget) -> PathBuf {
    match target {
        FilesystemViewTarget::UserMount(index) => {
            root.join("mounts").join(format!("smolvm{index}"))
        }
        FilesystemViewTarget::PreloadedImage => root.join("mounts").join("smolvm_image"),
        FilesystemViewTarget::ExtraDisk(index) => root.join("disks").join(format!("extra{index}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::resources::VmResources;
    use crate::data::storage::HostMount;
    use crate::security::policy::LaunchPolicy;
    use std::path::PathBuf;

    #[test]
    fn view_spec_preserves_original_audit_paths() {
        let prepared = prepared_launch(
            "/host/project",
            Some("/host/image"),
            vec![("/host/disk.raw".into(), true)],
        );
        let root = PathBuf::from("/runtime/view");
        let request = request_from_prepared(&prepared);
        let spec = request.plan(root.clone());
        let prepared = apply_to_prepared(&spec, prepared);

        assert_eq!(
            prepared.mounts[0].host_source,
            PathBuf::from("/host/project")
        );
        assert_eq!(
            prepared.preloaded_image_mount.as_ref().unwrap().host_source,
            PathBuf::from("/host/image")
        );
        assert_eq!(
            prepared.extra_disks[0].original_path,
            PathBuf::from("/host/disk.raw")
        );
        assert!(prepared.mounts[0].source_for_vmm.starts_with(&root));
        assert!(prepared
            .preloaded_image_mount
            .as_ref()
            .unwrap()
            .source_for_vmm
            .starts_with(&root));
        assert!(prepared.extra_disks[0].path_for_vmm.starts_with(&root));
    }

    #[test]
    fn view_spec_uses_stable_generated_paths() {
        let prepared = prepared_launch("/host/project", None, Vec::new());
        let root = PathBuf::from("/runtime/view");
        let request = request_from_prepared(&prepared);
        let spec = request.plan(root.clone());
        let prepared = apply_to_prepared(&spec, prepared);

        assert_eq!(
            prepared.mounts[0].source_for_vmm,
            root.join("mounts").join("smolvm0")
        );
    }

    #[test]
    fn view_request_marks_preloaded_image_optional() {
        let prepared = prepared_launch("/host/project", Some("/host/image"), Vec::new());
        let request = request_from_prepared(&prepared);
        let image = request
            .entries()
            .iter()
            .find(|entry| entry.target == FilesystemViewTarget::PreloadedImage)
            .unwrap();

        assert_eq!(image.requirement, FilesystemViewSourceRequirement::Optional);
        assert_eq!(image.access, FilesystemViewAccess::ReadOnly);
    }

    fn prepared_launch(
        mount: &str,
        preloaded_image: Option<&str>,
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
