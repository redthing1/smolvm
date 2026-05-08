//! Concrete launch preparation.
//!
//! Preparation turns pure policy into the exact tags and paths consumed by the
//! launcher. Initially `source_for_vmm` equals the original host path. A later
//! Linux jail milestone can rewrite `source_for_vmm` to a synthetic bind path
//! without changing the libkrun launcher again.

use crate::data::storage::{HostMount, MountAccess};
use crate::network::PreparedNetwork;
use crate::security::audit::SecurityAudit;
use crate::security::policy::{DiskGrant, LaunchPolicy, MountGrant};
use crate::Result;
use std::path::PathBuf;

/// Launch-ready resources derived from a pure [`LaunchPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLaunch {
    /// Original pure policy used to prepare this launch.
    pub policy: LaunchPolicy,
    /// User directory mounts with stable virtio-fs tags and VMM-facing paths.
    pub mounts: Vec<PreparedMount>,
    /// Optional read-only mount containing preloaded image data.
    pub preloaded_image_mount: Option<PreparedMount>,
    /// Additional disk images with VMM-facing paths.
    pub extra_disks: Vec<PreparedDisk>,
    /// Launch-ready network intent and backend request.
    pub network: PreparedNetwork,
    /// Policy/preparation audit summary.
    pub audit: SecurityAudit,
}

impl PreparedLaunch {
    /// Prepare concrete launch resources from a pure launch policy.
    pub fn prepare(policy: LaunchPolicy) -> Result<Self> {
        let mounts = policy
            .mounts
            .iter()
            .enumerate()
            .map(|(index, grant)| PreparedMount::from_grant(index, grant))
            .collect();

        let preloaded_image_mount = policy
            .preloaded_image_dir
            .as_ref()
            .map(|path| PreparedMount {
                tag: "smolvm_image".to_string(),
                host_source: path.clone(),
                source_for_vmm: path.clone(),
                guest_target: PathBuf::from("/preloaded_image"),
                access: MountAccess::ReadOnly,
            });

        let extra_disks = policy
            .extra_disks
            .iter()
            .map(PreparedDisk::from_grant)
            .collect();
        let network = PreparedNetwork::from_policy(&policy);

        let mut prepared = Self {
            policy,
            mounts,
            preloaded_image_mount,
            extra_disks,
            network,
            audit: SecurityAudit {
                summary: Vec::new(),
            },
        };
        prepared.audit = SecurityAudit::from_prepared(&prepared);
        Ok(prepared)
    }
}

/// A host directory mount prepared for libkrun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMount {
    /// Virtio-fs tag exposed to the guest.
    pub tag: String,
    /// Original host source path requested by the user or internal feature.
    pub host_source: PathBuf,
    /// Path passed to the VMM. This equals `host_source` until jail paths exist.
    pub source_for_vmm: PathBuf,
    /// Guest path where the agent should mount this directory.
    pub guest_target: PathBuf,
    /// Requested access mode.
    pub access: MountAccess,
}

impl PreparedMount {
    fn from_grant(index: usize, grant: &MountGrant) -> Self {
        Self {
            tag: HostMount::mount_tag(index),
            host_source: grant.host_source.clone(),
            source_for_vmm: grant.host_source.clone(),
            guest_target: grant.guest_target.clone(),
            access: grant.access,
        }
    }
}

/// Additional block disk prepared for libkrun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDisk {
    /// Original host path from policy.
    pub original_path: PathBuf,
    /// Path passed to the VMM. This equals `original_path` until jail paths exist.
    pub path_for_vmm: PathBuf,
    /// Whether the disk is attached read-only.
    pub read_only: bool,
}

impl PreparedDisk {
    fn from_grant(grant: &DiskGrant) -> Self {
        Self {
            original_path: grant.path.clone(),
            path_for_vmm: grant.path.clone(),
            read_only: grant.read_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::resources::VmResources;
    use crate::data::storage::HostMount;
    use crate::security::policy::LaunchPolicy;

    fn prepared_launch() -> PreparedLaunch {
        prepared_launch_with_resources(VmResources::default())
    }

    fn prepared_launch_with_resources(resources: VmResources) -> PreparedLaunch {
        let config = BootConfig {
            rootfs_path: "/smolvm/rootfs".into(),
            storage_disk_path: "/smolvm/storage.raw".into(),
            overlay_disk_path: "/smolvm/overlay.raw".into(),
            vsock_socket: "/smolvm/agent.sock".into(),
            console_log: None,
            startup_error_log: "/smolvm/startup.err".into(),
            storage_size_gb: 20,
            overlay_size_gb: 10,
            mounts: vec![
                HostMount {
                    source: "/host/project".into(),
                    target: "/workspace".into(),
                    read_only: false,
                },
                HostMount {
                    source: "/host/config".into(),
                    target: "/config".into(),
                    read_only: true,
                },
            ],
            ports: Vec::new(),
            resources,
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: Some("/smolvm/image".into()),
            extra_disks: vec![("/smolvm/extra.raw".into(), true)],
        };

        let policy = LaunchPolicy::from_boot_config(config).unwrap();
        PreparedLaunch::prepare(policy).unwrap()
    }

    #[test]
    fn prepared_mounts_have_stable_tags_and_identity_paths() {
        let prepared = prepared_launch();

        assert_eq!(prepared.mounts.len(), 2);
        assert_eq!(prepared.mounts[0].tag, "smolvm0");
        assert_eq!(
            prepared.mounts[0].host_source,
            PathBuf::from("/host/project")
        );
        assert_eq!(
            prepared.mounts[0].source_for_vmm,
            PathBuf::from("/host/project")
        );
        assert_eq!(prepared.mounts[0].guest_target, PathBuf::from("/workspace"));
        assert_eq!(prepared.mounts[0].access, MountAccess::ReadWrite);

        assert_eq!(prepared.mounts[1].tag, "smolvm1");
        assert_eq!(prepared.mounts[1].access, MountAccess::ReadOnly);
    }

    #[test]
    fn preloaded_image_mount_is_prepared_read_only() {
        let prepared = prepared_launch();
        let mount = prepared.preloaded_image_mount.unwrap();

        assert_eq!(mount.tag, "smolvm_image");
        assert_eq!(mount.host_source, PathBuf::from("/smolvm/image"));
        assert_eq!(mount.source_for_vmm, PathBuf::from("/smolvm/image"));
        assert_eq!(mount.guest_target, PathBuf::from("/preloaded_image"));
        assert_eq!(mount.access, MountAccess::ReadOnly);
    }

    #[test]
    fn extra_disks_are_prepared_with_identity_paths() {
        let prepared = prepared_launch();

        assert_eq!(
            prepared.extra_disks,
            vec![PreparedDisk {
                original_path: "/smolvm/extra.raw".into(),
                path_for_vmm: "/smolvm/extra.raw".into(),
                read_only: true,
            }]
        );
    }

    #[test]
    fn network_is_prepared_from_policy() {
        let prepared = prepared_launch();
        assert!(!prepared.network.wants_network());

        let prepared = prepared_launch_with_resources(VmResources {
            network: true,
            ..VmResources::default()
        });
        assert!(prepared.network.wants_network());
        assert!(!prepared.network.has_constrained_egress());
    }
}
