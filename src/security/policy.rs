//! Pure launch policy types.
//!
//! Policy compilation normalizes the already-parsed boot configuration into
//! typed capabilities. This module must stay side-effect free: no filesystem
//! mutation, no libkrun calls, no process hardening, and no Linux-specific
//! syscalls belong here.

use crate::agent::boot_config::BootConfig;
use crate::data::network::PortMapping;
use crate::data::resources::VmResources;
use crate::data::storage::MountAccess;
use crate::Result;
use std::path::PathBuf;

/// Normalized host capabilities requested for one VM launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPolicy {
    /// Path to the agent root filesystem directory.
    pub rootfs_path: PathBuf,
    /// Path to the persistent storage disk image.
    pub storage_disk_path: PathBuf,
    /// Path to the persistent container overlay disk image.
    pub overlay_disk_path: PathBuf,
    /// Host Unix socket path used for the guest control vsock endpoint.
    pub vsock_socket: PathBuf,
    /// Optional host path where libkrun writes VM console output.
    pub console_log: Option<PathBuf>,
    /// Host path where `_boot-vm` writes startup errors.
    pub startup_error_log: PathBuf,
    /// Storage disk size in GiB.
    pub storage_size_gb: u64,
    /// Overlay disk size in GiB.
    pub overlay_size_gb: u64,
    /// User-requested host directory mount grants.
    pub mounts: Vec<MountGrant>,
    /// Host-to-guest TCP port mappings.
    pub ports: Vec<PortMapping>,
    /// VM CPU, memory, GPU, disk, and current network resource settings.
    pub resources: VmResources,
    /// Outbound network capability requested by this launch.
    pub network: NetworkGrant,
    /// Secret-like host capabilities exposed to the guest.
    pub secrets: SecretGrants,
    /// Device-like host capabilities exposed to the guest.
    pub devices: DeviceGrants,
    /// Optional host directory containing preloaded image data.
    pub preloaded_image_dir: Option<PathBuf>,
    /// Additional block disk grants.
    pub extra_disks: Vec<DiskGrant>,
    /// Hostnames that should be re-resolved for long-running egress policy refresh.
    pub egress_policy_hosts: Option<Vec<String>>,
}

impl LaunchPolicy {
    /// Build a pure launch policy from the serialized `_boot-vm` configuration.
    pub fn from_boot_config(config: BootConfig) -> Result<Self> {
        let BootConfig {
            rootfs_path,
            storage_disk_path,
            overlay_disk_path,
            vsock_socket,
            console_log,
            startup_error_log,
            storage_size_gb,
            overlay_size_gb,
            mounts,
            ports,
            resources,
            ssh_agent_socket,
            egress_policy_hosts,
            preloaded_image_dir,
            extra_disks,
        } = config;

        let mounts = mounts
            .into_iter()
            .map(|mount| {
                let access = mount.access();
                MountGrant {
                    host_source: mount.source,
                    guest_target: mount.target,
                    access,
                }
            })
            .collect();

        let network = NetworkGrant::from_resources(&resources, egress_policy_hosts.as_deref());
        let devices = DeviceGrants { gpu: resources.gpu };
        let secrets = SecretGrants { ssh_agent_socket };
        let extra_disks = extra_disks
            .into_iter()
            .map(|(path, read_only)| DiskGrant { path, read_only })
            .collect();

        Ok(Self {
            rootfs_path,
            storage_disk_path,
            overlay_disk_path,
            vsock_socket,
            console_log,
            startup_error_log,
            storage_size_gb,
            overlay_size_gb,
            mounts,
            ports,
            resources,
            network,
            secrets,
            devices,
            preloaded_image_dir,
            extra_disks,
            egress_policy_hosts,
        })
    }
}

/// Host directory access granted to the VM runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountGrant {
    /// Canonical or previously-validated host source path.
    pub host_source: PathBuf,
    /// Path where the guest agent should mount the directory.
    pub guest_target: PathBuf,
    /// Requested read/write access.
    pub access: MountAccess,
}

/// Outbound network capability requested by this launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkGrant {
    /// No broad outbound network capability was requested.
    Disabled,
    /// Broad outbound network was requested.
    Broad,
    /// Egress is constrained to these CIDR ranges. An empty list means deny all.
    AllowCidrs(Vec<String>),
    /// Egress is constrained by hostnames plus the CIDRs resolved at start.
    AllowHosts {
        /// Hostnames that should remain part of the egress policy.
        hosts: Vec<String>,
        /// CIDRs already resolved for this launch.
        initial_cidrs: Vec<String>,
    },
}

impl NetworkGrant {
    pub(crate) fn from_resources(resources: &VmResources, hosts: Option<&[String]>) -> Self {
        if let Some(hosts) = hosts.filter(|hosts| !hosts.is_empty()) {
            return Self::AllowHosts {
                hosts: hosts.to_vec(),
                initial_cidrs: resources.allowed_cidrs.clone().unwrap_or_default(),
            };
        }

        if let Some(cidrs) = resources.allowed_cidrs.clone() {
            return Self::AllowCidrs(cidrs);
        }

        if resources.network {
            Self::Broad
        } else {
            Self::Disabled
        }
    }

    /// Short stable label for audit output.
    pub fn audit_label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Broad => "broad",
            Self::AllowCidrs(_) => "allow-cidrs",
            Self::AllowHosts { .. } => "allow-hosts",
        }
    }
}

/// Secret-like host capabilities exposed to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretGrants {
    /// Host SSH agent socket forwarded into the VM, if requested.
    pub ssh_agent_socket: Option<PathBuf>,
}

/// Device-like host capabilities exposed to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGrants {
    /// Whether the host GPU is exposed through libkrun.
    pub gpu: bool,
}

/// Additional disk image exposed to the guest as a block device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskGrant {
    /// Host path to the disk image.
    pub path: PathBuf,
    /// Whether the block device should be attached read-only.
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::network::PortMapping;
    use crate::data::storage::HostMount;

    fn boot_config() -> BootConfig {
        BootConfig {
            rootfs_path: "/smolvm/rootfs".into(),
            storage_disk_path: "/smolvm/storage.raw".into(),
            overlay_disk_path: "/smolvm/overlay.raw".into(),
            vsock_socket: "/smolvm/agent.sock".into(),
            console_log: Some("/smolvm/console.log".into()),
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
            ports: vec![PortMapping::new(8080, 80)],
            resources: VmResources::default(),
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks: Vec::new(),
        }
    }

    #[test]
    fn policy_preserves_core_boot_config_fields() {
        let policy = LaunchPolicy::from_boot_config(boot_config()).unwrap();

        assert_eq!(policy.rootfs_path, PathBuf::from("/smolvm/rootfs"));
        assert_eq!(
            policy.storage_disk_path,
            PathBuf::from("/smolvm/storage.raw")
        );
        assert_eq!(
            policy.overlay_disk_path,
            PathBuf::from("/smolvm/overlay.raw")
        );
        assert_eq!(policy.vsock_socket, PathBuf::from("/smolvm/agent.sock"));
        assert_eq!(
            policy.console_log,
            Some(PathBuf::from("/smolvm/console.log"))
        );
        assert_eq!(
            policy.startup_error_log,
            PathBuf::from("/smolvm/startup.err")
        );
        assert_eq!(policy.storage_size_gb, 20);
        assert_eq!(policy.overlay_size_gb, 10);
        assert_eq!(policy.ports, vec![PortMapping::new(8080, 80)]);
    }

    #[test]
    fn policy_converts_mounts_to_typed_grants() {
        let policy = LaunchPolicy::from_boot_config(boot_config()).unwrap();

        assert_eq!(policy.mounts.len(), 2);
        assert_eq!(policy.mounts[0].host_source, PathBuf::from("/host/project"));
        assert_eq!(policy.mounts[0].guest_target, PathBuf::from("/workspace"));
        assert_eq!(policy.mounts[0].access, MountAccess::ReadWrite);
        assert_eq!(policy.mounts[1].host_source, PathBuf::from("/host/config"));
        assert_eq!(policy.mounts[1].guest_target, PathBuf::from("/config"));
        assert_eq!(policy.mounts[1].access, MountAccess::ReadOnly);
    }

    #[test]
    fn policy_detects_disabled_network() {
        let policy = LaunchPolicy::from_boot_config(boot_config()).unwrap();

        assert_eq!(policy.network, NetworkGrant::Disabled);
    }

    #[test]
    fn policy_detects_broad_network() {
        let mut config = boot_config();
        config.resources.network = true;

        let policy = LaunchPolicy::from_boot_config(config).unwrap();

        assert_eq!(policy.network, NetworkGrant::Broad);
    }

    #[test]
    fn policy_detects_cidr_network_even_when_empty() {
        let mut config = boot_config();
        config.resources.allowed_cidrs = Some(Vec::new());

        let policy = LaunchPolicy::from_boot_config(config).unwrap();

        assert_eq!(policy.network, NetworkGrant::AllowCidrs(Vec::new()));
    }

    #[test]
    fn policy_detects_hostname_network_with_initial_cidrs() {
        let mut config = boot_config();
        config.resources.allowed_cidrs = Some(vec!["203.0.113.10/32".into()]);
        config.egress_policy_hosts = Some(vec!["example.com".into()]);

        let policy = LaunchPolicy::from_boot_config(config).unwrap();

        assert_eq!(
            policy.network,
            NetworkGrant::AllowHosts {
                hosts: vec!["example.com".into()],
                initial_cidrs: vec!["203.0.113.10/32".into()],
            }
        );
        assert_eq!(
            policy.egress_policy_hosts,
            Some(vec!["example.com".to_string()])
        );
    }

    #[test]
    fn policy_records_secrets_devices_preloaded_images_and_disks() {
        let mut config = boot_config();
        config.ssh_agent_socket = Some("/tmp/ssh-agent.sock".into());
        config.resources.gpu = true;
        config.preloaded_image_dir = Some("/smolvm/image".into());
        config.extra_disks = vec![("/smolvm/extra.raw".into(), true)];

        let policy = LaunchPolicy::from_boot_config(config).unwrap();

        assert_eq!(
            policy.secrets.ssh_agent_socket,
            Some(PathBuf::from("/tmp/ssh-agent.sock"))
        );
        assert!(policy.devices.gpu);
        assert_eq!(
            policy.preloaded_image_dir,
            Some(PathBuf::from("/smolvm/image"))
        );
        assert_eq!(
            policy.extra_disks,
            vec![DiskGrant {
                path: "/smolvm/extra.raw".into(),
                read_only: true,
            }]
        );
    }
}
