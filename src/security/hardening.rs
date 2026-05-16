//! Runner hardening facade.
//!
//! This module is the stable interface used by `_boot-vm`. Platform-specific
//! syscall details live behind it so launch orchestration stays readable and
//! pure policy/preparation modules stay side-effect free.

use crate::security::prepare::PreparedLaunch;
use crate::Result;

/// Enforcement state for one runner hardening control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The control was installed successfully.
    Enforced,
    /// The host or platform cannot provide this control.
    Unavailable {
        /// Human-readable reason the control is unavailable.
        reason: String,
    },
    /// The control was intentionally not installed.
    Skipped {
        /// Human-readable reason the control was skipped.
        reason: String,
    },
}

impl Enforcement {
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Enforced => "enforced".to_string(),
            Self::Unavailable { reason } => format!("unavailable ({reason})"),
            Self::Skipped { reason } => format!("skipped ({reason})"),
        }
    }
}

/// Hardening controls applied to the host-side VM runner process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerHardeningReport {
    /// Linux `PR_SET_NO_NEW_PRIVS`.
    pub no_new_privs: Enforcement,
    /// Core dump resource limit.
    pub core_dumps: Enforcement,
    /// File descriptor limit handling.
    pub nofile: Enforcement,
}

impl RunnerHardeningReport {
    /// Render this report as stable newline-delimited text.
    pub fn render_text(&self) -> String {
        [
            format!("no_new_privs={}", self.no_new_privs.render()),
            format!("core_dumps={}", self.core_dumps.render()),
            format!("nofile={}", self.nofile.render()),
        ]
        .join("\n")
    }

    #[cfg(not(target_os = "linux"))]
    fn skipped_for_platform() -> Self {
        Self {
            no_new_privs: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
            core_dumps: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
            nofile: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
        }
    }
}

/// Filesystem confinement applied to the host-side VM runner process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerFilesystemReport {
    /// Linux Landlock filesystem allowlist.
    pub landlock: Enforcement,
}

impl RunnerFilesystemReport {
    /// Render this report as stable newline-delimited text.
    pub fn render_text(&self) -> String {
        format!("landlock={}", self.landlock.render())
    }

    #[cfg(not(target_os = "linux"))]
    fn skipped_for_platform() -> Self {
        Self {
            landlock: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
        }
    }
}

/// Resource confinement applied to the host-side VM runner process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerResourceReport {
    /// Linux cgroup v2 membership.
    pub cgroup: Enforcement,
    /// Linux cgroup v2 process/thread count limit.
    pub pids: Enforcement,
    /// Linux cgroup v2 memory limit.
    pub memory: Enforcement,
}

impl RunnerResourceReport {
    /// Render this report as stable newline-delimited text.
    pub fn render_text(&self) -> String {
        [
            format!("cgroup={}", self.cgroup.render()),
            format!("pids={}", self.pids.render()),
            format!("memory={}", self.memory.render()),
        ]
        .join("\n")
    }

    #[cfg(not(target_os = "linux"))]
    fn skipped_for_platform() -> Self {
        Self {
            cgroup: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
            pids: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
            memory: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
        }
    }
}

/// Syscall confinement applied to the host-side VM runner process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSyscallReport {
    /// Linux seccomp-BPF syscall filter.
    pub seccomp: Enforcement,
}

/// Launch facts needed to build host-side syscall confinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerSyscallPolicy {
    wants_network: bool,
}

impl RunnerSyscallPolicy {
    /// Build syscall policy from a fully prepared launch.
    pub fn from_prepared(prepared: &PreparedLaunch) -> Self {
        Self::from_network(prepared.network.wants_network())
    }

    /// Build syscall policy from an already prepared network decision.
    pub const fn from_network(wants_network: bool) -> Self {
        Self { wants_network }
    }

    /// Whether this launch needs host-side networking after VMM entry.
    pub const fn wants_network(self) -> bool {
        self.wants_network
    }
}

impl RunnerSyscallReport {
    /// Render this report as stable newline-delimited text.
    pub fn render_text(&self) -> String {
        format!("seccomp={}", self.seccomp.render())
    }

    #[cfg(not(target_os = "linux"))]
    fn skipped_for_platform() -> Self {
        Self {
            seccomp: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
        }
    }
}

/// Keeps resource confinement alive for the duration of the VM runner.
pub struct RunnerResourceGuard {
    report: RunnerResourceReport,
    #[cfg(target_os = "linux")]
    _linux: crate::security::linux::LinuxResourceGuard,
}

impl RunnerResourceGuard {
    /// Report describing resource controls installed by this guard.
    pub fn report(&self) -> &RunnerResourceReport {
        &self.report
    }
}

/// Apply the baseline hardening controls for the current VM runner process.
///
/// On Linux this enforces `no_new_privs` and disables core dumps. It reports
/// `RLIMIT_NOFILE` but leaves it unchanged because libkrun launch paths already
/// raise that limit to the hard limit immediately before entering the VMM.
pub fn apply_runner_baseline() -> Result<RunnerHardeningReport> {
    #[cfg(target_os = "linux")]
    {
        crate::security::linux::apply_runner_baseline()
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(RunnerHardeningReport::skipped_for_platform())
    }
}

/// Apply filesystem confinement for the current VM runner process.
///
/// This runs after libkrun has been loaded, but before the prepared rootfs,
/// disk, socket, log, and virtio-fs paths are passed to libkrun. That ordering
/// keeps dynamic loader behavior out of the allowlist while still constraining
/// the filesystem authority used for launch resources and VM runtime I/O.
pub fn apply_runner_filesystem_confinement(
    prepared: &PreparedLaunch,
) -> Result<RunnerFilesystemReport> {
    #[cfg(target_os = "linux")]
    {
        crate::security::linux::apply_runner_filesystem_confinement(prepared)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = prepared;
        Ok(RunnerFilesystemReport::skipped_for_platform())
    }
}

/// Apply resource confinement for the current VM runner process.
///
/// On Linux this uses cgroup v2 when the current process is already in a
/// writable delegated cgroup. The returned guard must stay alive until libkrun
/// exits so cleanup can move the runner back to its parent cgroup and remove
/// the child cgroup on normal return.
pub fn apply_runner_resource_confinement(prepared: &PreparedLaunch) -> Result<RunnerResourceGuard> {
    #[cfg(target_os = "linux")]
    {
        let (report, linux) = crate::security::linux::apply_runner_resource_confinement(prepared)?;
        Ok(RunnerResourceGuard {
            report,
            _linux: linux,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = prepared;
        Ok(RunnerResourceGuard {
            report: RunnerResourceReport::skipped_for_platform(),
        })
    }
}

/// Apply syscall confinement for the current VM runner process.
///
/// This should run after launch setup has loaded and configured libkrun, but
/// immediately before entering the VMM. That keeps dynamic loader and setup
/// syscalls out of the filter while still constraining the long-lived VMM.
pub fn apply_runner_syscall_confinement(
    policy: RunnerSyscallPolicy,
) -> Result<RunnerSyscallReport> {
    #[cfg(target_os = "linux")]
    {
        crate::security::linux::apply_runner_syscall_confinement(policy)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        Ok(RunnerSyscallReport::skipped_for_platform())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_hardening_report_renders_enforcement_states() {
        let report = RunnerHardeningReport {
            no_new_privs: Enforcement::Enforced,
            core_dumps: Enforcement::Unavailable {
                reason: "kernel does not support control".to_string(),
            },
            nofile: Enforcement::Skipped {
                reason: "left unchanged".to_string(),
            },
        };

        let text = report.render_text();

        assert!(text.contains("no_new_privs=enforced"));
        assert!(text.contains("core_dumps=unavailable (kernel does not support control)"));
        assert!(text.contains("nofile=skipped (left unchanged)"));
    }

    #[test]
    fn runner_filesystem_report_renders_landlock_state() {
        let report = RunnerFilesystemReport {
            landlock: Enforcement::Enforced,
        };

        assert_eq!(report.render_text(), "landlock=enforced");
    }

    #[test]
    fn runner_resource_report_renders_cgroup_states() {
        let report = RunnerResourceReport {
            cgroup: Enforcement::Enforced,
            pids: Enforcement::Enforced,
            memory: Enforcement::Skipped {
                reason: "not measured yet".to_string(),
            },
        };

        let text = report.render_text();

        assert!(text.contains("cgroup=enforced"));
        assert!(text.contains("pids=enforced"));
        assert!(text.contains("memory=skipped (not measured yet)"));
    }

    #[test]
    fn runner_syscall_report_renders_seccomp_state() {
        let report = RunnerSyscallReport {
            seccomp: Enforcement::Enforced,
        };

        assert_eq!(report.render_text(), "seccomp=enforced");
    }
}
