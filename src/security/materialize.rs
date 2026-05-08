//! Side-effectful launch materialization.
//!
//! Policy and preparation stay pure. Materialization is the narrow boundary
//! where smolvm may create temporary host-side launch resources, such as a
//! generated per-launch filesystem view for libkrun.

use crate::security::hardening::Enforcement;
use crate::security::prepare::PreparedLaunch;
use crate::Result;

/// Filesystem materialization state for one launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemMaterializationReport {
    /// Whether VMM-facing paths were rewritten into a per-launch jail view.
    pub jail_paths: Enforcement,
}

impl FilesystemMaterializationReport {
    /// Render this report as stable newline-delimited text.
    pub fn render_text(&self) -> String {
        format!("jail_paths={}", self.jail_paths.render())
    }

    #[cfg(not(target_os = "linux"))]
    fn skipped_for_platform() -> Self {
        Self {
            jail_paths: Enforcement::Skipped {
                reason: "not a Linux host".to_string(),
            },
        }
    }
}

/// Launch data after side-effectful materialization has run.
#[derive(Debug, Clone)]
pub struct MaterializedLaunch {
    prepared: PreparedLaunch,
    filesystem: FilesystemMaterializationReport,
}

impl MaterializedLaunch {
    /// Prepared launch data with materialized VMM-facing paths.
    pub fn prepared(&self) -> &PreparedLaunch {
        &self.prepared
    }

    /// Filesystem materialization report.
    pub fn filesystem_report(&self) -> &FilesystemMaterializationReport {
        &self.filesystem
    }
}

/// Keeps temporary materialized launch resources alive until the VM launch ends.
pub struct MaterializedLaunchGuard {
    materialized: MaterializedLaunch,
    #[cfg(target_os = "linux")]
    _linux: crate::security::linux::LinuxJailGuard,
}

impl MaterializedLaunchGuard {
    /// Materialized launch data.
    pub fn launch(&self) -> &MaterializedLaunch {
        &self.materialized
    }

    /// Prepared launch data with materialized VMM-facing paths.
    pub fn prepared(&self) -> &PreparedLaunch {
        self.materialized.prepared()
    }

    /// Filesystem materialization report.
    pub fn filesystem_report(&self) -> &FilesystemMaterializationReport {
        self.materialized.filesystem_report()
    }
}

/// Materialize side-effectful launch resources.
pub fn materialize_launch(prepared: PreparedLaunch) -> Result<MaterializedLaunchGuard> {
    #[cfg(target_os = "linux")]
    {
        let (prepared, filesystem, linux) = crate::security::linux::materialize_launch(prepared)?;
        Ok(MaterializedLaunchGuard {
            materialized: MaterializedLaunch {
                prepared,
                filesystem,
            },
            _linux: linux,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(MaterializedLaunchGuard {
            materialized: MaterializedLaunch {
                prepared,
                filesystem: FilesystemMaterializationReport::skipped_for_platform(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::hardening::Enforcement;

    #[test]
    fn filesystem_materialization_report_renders_jail_state() {
        let report = FilesystemMaterializationReport {
            jail_paths: Enforcement::Unavailable {
                reason: "private mount namespace unavailable".to_string(),
            },
        };

        assert_eq!(
            report.render_text(),
            "jail_paths=unavailable (private mount namespace unavailable)"
        );
    }
}
