use crate::network::backend::NetworkBackend;
use crate::security::policy::{LaunchPolicy, NetworkGrant};

/// Launch-ready network intent derived from pure policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedNetwork {
    /// Requested outbound network capability.
    pub grant: NetworkGrant,
    /// Number of host-to-guest port mappings.
    pub port_count: usize,
    /// User-requested network backend, if one was specified.
    pub backend_request: Option<NetworkBackend>,
}

impl PreparedNetwork {
    /// Build network preparation from a full launch policy.
    pub fn from_policy(policy: &LaunchPolicy) -> Self {
        Self {
            grant: policy.network.clone(),
            port_count: policy.ports.len(),
            backend_request: policy.resources.network_backend,
        }
    }

    /// Build network preparation from raw resources for launch paths that do
    /// not yet build a full [`LaunchPolicy`], such as packed dynamic launch.
    pub fn from_resources(
        resources: &crate::data::resources::VmResources,
        hostname_policy_hosts: Option<&[String]>,
        port_count: usize,
    ) -> Self {
        Self {
            grant: NetworkGrant::from_resources(resources, hostname_policy_hosts),
            port_count,
            backend_request: resources.network_backend,
        }
    }

    /// Whether any guest networking should be attached.
    pub fn wants_network(&self) -> bool {
        self.port_count > 0 || !matches!(self.grant, NetworkGrant::Disabled)
    }

    /// Whether this launch has constrained egress policy.
    pub fn has_constrained_egress(&self) -> bool {
        matches!(
            self.grant,
            NetworkGrant::AllowCidrs(_) | NetworkGrant::AllowHosts { .. }
        )
    }

    /// Initial CIDRs for libkrun egress policy. `Some([])` is meaningful: it
    /// means constrained egress with an empty allowlist.
    pub fn initial_cidrs(&self) -> Option<&[String]> {
        match &self.grant {
            NetworkGrant::AllowCidrs(cidrs) => Some(cidrs),
            NetworkGrant::AllowHosts { initial_cidrs, .. } => Some(initial_cidrs),
            NetworkGrant::Disabled | NetworkGrant::Broad => None,
        }
    }

    /// Hostnames that should be re-resolved for long-running allow-host policy.
    pub fn refresh_hosts(&self) -> Option<&[String]> {
        match &self.grant {
            NetworkGrant::AllowHosts { hosts, .. } if !hosts.is_empty() => Some(hosts),
            _ => None,
        }
    }

    /// Whether DNS should be added to libkrun's egress allowlist.
    pub fn should_allow_dns_for_egress_policy(&self) -> bool {
        match &self.grant {
            NetworkGrant::AllowHosts { .. } => true,
            NetworkGrant::AllowCidrs(cidrs) => !cidrs.is_empty(),
            NetworkGrant::Disabled | NetworkGrant::Broad => false,
        }
    }
}

/// Effective backend selected for a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveNetworkBackend {
    /// No network device.
    None,
    /// TSI networking.
    Tsi,
    /// Virtio-net networking.
    VirtioNet,
}

/// Reason a requested backend was downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFallbackReason {
    /// Current egress policies are only implemented on TSI.
    PolicyRequiresTsi,
}

impl NetworkFallbackReason {
    /// User-facing explanation for the fallback.
    pub const fn user_message(self) -> &'static str {
        match self {
            Self::PolicyRequiresTsi => {
                "allow-cidr/allow-host policies still use the TSI backend; falling back from virtio-net"
            }
        }
    }

    /// User-facing explanation when an explicit virtio-net request must be rejected.
    pub const fn unsupported_message(self) -> &'static str {
        match self {
            Self::PolicyRequiresTsi => {
                "allow-cidr/allow-host policies are not supported by the current virtio-net implementation"
            }
        }
    }
}

/// Network launch decision for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchNetworkPlan {
    /// Selected backend.
    pub backend: EffectiveNetworkBackend,
    /// Downgrade reason when a requested backend cannot be honored.
    pub fallback_reason: Option<NetworkFallbackReason>,
}

impl LaunchNetworkPlan {
    /// Whether the launch should attach any network backend at all.
    pub const fn has_network(self) -> bool {
        !matches!(self.backend, EffectiveNetworkBackend::None)
    }
}

/// Compute the effective launch backend from prepared network intent.
pub fn plan_launch_network(network: &PreparedNetwork) -> LaunchNetworkPlan {
    if !network.wants_network() {
        return LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::None,
            fallback_reason: None,
        };
    }

    match network.backend_request.unwrap_or(NetworkBackend::Tsi) {
        NetworkBackend::Tsi => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::Tsi,
            fallback_reason: None,
        },
        NetworkBackend::VirtioNet if network.has_constrained_egress() => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::Tsi,
            fallback_reason: Some(NetworkFallbackReason::PolicyRequiresTsi),
        },
        NetworkBackend::VirtioNet => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::VirtioNet,
            fallback_reason: None,
        },
    }
}

/// Reject explicit virtio-net requests that the current branch cannot honor.
pub fn validate_requested_network_backend(network: &PreparedNetwork) -> crate::Result<()> {
    if network.backend_request != Some(NetworkBackend::VirtioNet) {
        return Ok(());
    }

    if !network.wants_network() {
        return Err(crate::Error::config(
            "--net-backend",
            "--net-backend virtio-net requires --net",
        ));
    }

    let plan = plan_launch_network(network);
    if plan.backend != EffectiveNetworkBackend::VirtioNet {
        let reason = plan
            .fallback_reason
            .unwrap_or(NetworkFallbackReason::PolicyRequiresTsi);
        return Err(crate::Error::config(
            "--net-backend",
            reason.unsupported_message(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::resources::VmResources;

    fn resources() -> VmResources {
        VmResources::default()
    }

    fn prepared(
        resources: &VmResources,
        hosts: Option<&[String]>,
        port_count: usize,
    ) -> PreparedNetwork {
        PreparedNetwork::from_resources(resources, hosts, port_count)
    }

    #[test]
    fn test_no_network_plan() {
        let resources = resources();
        let plan = plan_launch_network(&prepared(&resources, None, 0));
        assert_eq!(plan.backend, EffectiveNetworkBackend::None);
    }

    #[test]
    fn test_default_network_uses_tsi() {
        let mut resources = resources();
        resources.network = true;
        let plan = plan_launch_network(&prepared(&resources, None, 0));
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
    }

    #[test]
    fn test_plain_virtio_selects_virtio_backend() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let plan = plan_launch_network(&prepared(&resources, None, 0));
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
        assert_eq!(plan.fallback_reason, None);
    }

    #[test]
    fn test_ports_work_with_virtio() {
        let mut resources = resources();
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let plan = plan_launch_network(&prepared(&resources, None, 1));
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
        assert_eq!(plan.fallback_reason, None);
    }

    #[test]
    fn test_policy_forces_tsi() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let plan = plan_launch_network(&prepared(&resources, None, 0));
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
        assert_eq!(
            plan.fallback_reason,
            Some(NetworkFallbackReason::PolicyRequiresTsi)
        );
    }

    #[test]
    fn test_empty_cidr_policy_is_still_constrained_network() {
        let mut resources = resources();
        resources.allowed_cidrs = Some(Vec::new());
        let network = prepared(&resources, None, 0);

        assert!(network.wants_network());
        assert!(network.has_constrained_egress());
        assert_eq!(network.initial_cidrs(), Some(&[][..]));

        let plan = plan_launch_network(&network);
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
        assert_eq!(plan.fallback_reason, None);
    }

    #[test]
    fn test_empty_cidr_policy_does_not_auto_allow_dns() {
        let mut resources = resources();
        resources.allowed_cidrs = Some(Vec::new());
        let network = prepared(&resources, None, 0);

        assert!(!network.should_allow_dns_for_egress_policy());
    }

    #[test]
    fn test_hostname_policy_forces_tsi() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let hosts = [String::from("example.com")];
        let network = prepared(&resources, Some(&hosts), 0);
        let plan = plan_launch_network(&network);
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
        assert_eq!(
            plan.fallback_reason,
            Some(NetworkFallbackReason::PolicyRequiresTsi)
        );
        assert_eq!(network.refresh_hosts(), Some(&hosts[..]));
        assert!(network.should_allow_dns_for_egress_policy());
    }

    #[test]
    fn test_validate_plain_virtio_allowed() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        validate_requested_network_backend(&prepared(&resources, None, 0)).unwrap();
    }

    #[test]
    fn test_validate_ports_allowed_for_virtio() {
        let mut resources = resources();
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        validate_requested_network_backend(&prepared(&resources, None, 1)).unwrap();
    }

    #[test]
    fn test_validate_policy_rejected_for_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let err = validate_requested_network_backend(&prepared(&resources, None, 0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("allow-cidr/allow-host policies are not supported"));
    }

    #[test]
    fn test_validate_empty_policy_rejected_for_virtio() {
        let mut resources = resources();
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(Vec::new());
        let err = validate_requested_network_backend(&prepared(&resources, None, 0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("allow-cidr/allow-host policies are not supported"));
    }

    #[test]
    fn test_validate_hostname_policy_rejected_for_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let hosts = [String::from("example.com")];
        let err =
            validate_requested_network_backend(&prepared(&resources, Some(&hosts), 0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("allow-cidr/allow-host policies are not supported"));
    }
}
