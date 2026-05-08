//! Linux runner hardening implementation.

mod cgroup;
mod landlock;

use crate::security::hardening::{
    Enforcement, RunnerFilesystemReport, RunnerHardeningReport, RunnerResourceReport,
};
use crate::security::prepare::PreparedLaunch;
use crate::{Error, Result};

pub(super) fn apply_runner_baseline() -> Result<RunnerHardeningReport> {
    set_no_new_privs()?;
    disable_core_dumps()?;

    Ok(RunnerHardeningReport {
        no_new_privs: Enforcement::Enforced,
        core_dumps: Enforcement::Enforced,
        nofile: report_nofile_unchanged(),
    })
}

pub(super) fn apply_runner_filesystem_confinement(
    prepared: &PreparedLaunch,
) -> Result<RunnerFilesystemReport> {
    Ok(RunnerFilesystemReport {
        landlock: landlock::apply(prepared)?,
    })
}

pub(crate) struct LinuxResourceGuard {
    _cgroup: Option<cgroup::CgroupGuard>,
}

pub(super) fn apply_runner_resource_confinement(
    prepared: &PreparedLaunch,
) -> Result<(RunnerResourceReport, LinuxResourceGuard)> {
    cgroup::apply(prepared)
}

fn set_no_new_privs() -> Result<()> {
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if ret != 0 {
        return Err(last_os_error("set no_new_privs"));
    }

    let current = unsafe {
        libc::prctl(
            libc::PR_GET_NO_NEW_PRIVS,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if current != 1 {
        return Err(Error::agent(
            "apply runner hardening",
            format!("set no_new_privs: verification returned {current}"),
        ));
    }

    Ok(())
}

fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if ret != 0 {
        return Err(last_os_error("disable core dumps"));
    }
    Ok(())
}

fn report_nofile_unchanged() -> Enforcement {
    match current_nofile_limit() {
        Some((soft, hard)) => Enforcement::Skipped {
            reason: format!("left unchanged for libkrun fd budget (soft={soft}, hard={hard})"),
        },
        None => Enforcement::Skipped {
            reason: "left unchanged for libkrun fd budget".to_string(),
        },
    }
}

fn current_nofile_limit() -> Option<(libc::rlim_t, libc::rlim_t)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if ret == 0 {
        Some((limit.rlim_cur, limit.rlim_max))
    } else {
        None
    }
}

fn last_os_error(operation: &'static str) -> Error {
    Error::agent(
        "apply runner hardening",
        format!("{operation}: {}", std::io::Error::last_os_error()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const CHILD_ENV: &str = "SMOLVM_TEST_RUNNER_BASELINE_CHILD";

    #[test]
    fn runner_baseline_sets_no_new_privs_in_child() {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, "1")
            .args([
                "--exact",
                "security::linux::tests::runner_baseline_child_probe",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn runner_baseline_child_probe() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }

        let report = apply_runner_baseline().unwrap();
        assert_eq!(report.no_new_privs, Enforcement::Enforced);
        assert_eq!(report.core_dumps, Enforcement::Enforced);

        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let no_new_privs = status
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key == "NoNewPrivs").then(|| value.trim().to_string())
            })
            .expect("NoNewPrivs line should exist in /proc/thread-self/status");

        assert_eq!(no_new_privs, "1");
    }
}
