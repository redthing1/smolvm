//! Human-readable summaries of launch policy and enforcement state.

use crate::security::policy::{LaunchPolicy, NetworkGrant};
use crate::security::prepare::PreparedLaunch;

/// Simple audit record for a launch policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAudit {
    /// One-line facts describing requested capabilities.
    pub summary: Vec<String>,
}

impl SecurityAudit {
    /// Build a policy-only audit summary.
    pub fn from_policy(policy: &LaunchPolicy) -> Self {
        let mut summary = Vec::new();
        summary.push(format!("mounts={}", policy.mounts.len()));
        summary.push(format!("ports={}", policy.ports.len()));
        summary.push(format!("network={}", policy.network.audit_label()));
        summary.push(format!(
            "ssh_agent={}",
            if policy.secrets.ssh_agent_socket.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        ));
        summary.push(format!(
            "gpu={}",
            if policy.devices.gpu {
                "enabled"
            } else {
                "disabled"
            }
        ));

        if let NetworkGrant::AllowHosts {
            hosts,
            initial_cidrs,
        } = &policy.network
        {
            summary.push(format!("allow_hosts={}", hosts.len()));
            summary.push(format!("initial_cidrs={}", initial_cidrs.len()));
        }

        Self { summary }
    }

    /// Build an audit summary from prepared launch resources.
    pub fn from_prepared(prepared: &PreparedLaunch) -> Self {
        let mut audit = Self::from_policy(&prepared.policy);
        audit
            .summary
            .push(format!("prepared_mounts={}", prepared.mounts.len()));
        audit.summary.push(format!(
            "preloaded_image={}",
            if prepared.preloaded_image_mount.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        ));
        audit
            .summary
            .push(format!("extra_disks={}", prepared.extra_disks.len()));
        audit
    }

    /// Render the audit as newline-delimited text.
    pub fn render_text(&self) -> String {
        self.summary.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::boot_config::BootConfig;
    use crate::data::resources::VmResources;

    fn policy_with_network(network: bool) -> LaunchPolicy {
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
            resources: VmResources {
                network,
                ..VmResources::default()
            },
            ssh_agent_socket: None,
            egress_policy_hosts: None,
            preloaded_image_dir: None,
            extra_disks: Vec::new(),
        };

        LaunchPolicy::from_boot_config(config).unwrap()
    }

    #[test]
    fn audit_renders_policy_summary() {
        let policy = policy_with_network(true);
        let audit = SecurityAudit::from_policy(&policy);
        let text = audit.render_text();

        assert!(text.contains("mounts=0"));
        assert!(text.contains("ports=0"));
        assert!(text.contains("network=broad"));
        assert!(text.contains("ssh_agent=disabled"));
        assert!(text.contains("gpu=disabled"));
    }

    #[test]
    fn audit_renders_prepared_summary() {
        let policy = policy_with_network(false);
        let prepared = PreparedLaunch::prepare(policy).unwrap();
        let audit = SecurityAudit::from_prepared(&prepared);
        let text = audit.render_text();

        assert!(text.contains("prepared_mounts=0"));
        assert!(text.contains("preloaded_image=disabled"));
        assert!(text.contains("extra_disks=0"));
    }
}
