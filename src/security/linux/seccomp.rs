//! Linux seccomp syscall confinement.
//!
//! This is a deliberately small default-denylist profile, not a claim of full
//! syscall least privilege. It blocks kernel features that the long-lived VMM
//! should not need after launch setup has finished, while preserving libkrun's
//! normal KVM, memory, event, file, and thread operations.

use crate::security::hardening::{Enforcement, RunnerSyscallPolicy};
use crate::{Error, Result};

/// Apply seccomp confinement to the runner process.
pub(super) fn apply(policy: RunnerSyscallPolicy) -> Result<Enforcement> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        supported::apply(policy)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = policy;
        Ok(Enforcement::Skipped {
            reason: format!(
                "unsupported seccomp audit architecture: {}",
                std::env::consts::ARCH
            ),
        })
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod supported {
    use super::*;

    const ERRNO_EPERM: u32 = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);
    const ERRNO_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);
    const NAMESPACE_FLAGS: u32 = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWTIME) as u32;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    const NR_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    const ARCH_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    const ARG0_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, args) as u32;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Rule {
        Syscall { syscall: libc::c_long, errno: u32 },
        CloneNamespaceFlags,
        SocketFamily { family: libc::c_int },
    }

    pub(super) fn apply(policy: RunnerSyscallPolicy) -> Result<Enforcement> {
        if !super::super::no_new_privs_is_set()? {
            return Err(Error::agent(
                "apply seccomp filter",
                "no_new_privs is not set before seccomp",
            ));
        }

        let mut filter = build_filter(policy);
        let mut program = libc::sock_fprog {
            len: filter
                .len()
                .try_into()
                .expect("seccomp filter length fits in u16"),
            filter: filter.as_mut_ptr(),
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &mut program,
            )
        };
        if ret == 0 {
            return Ok(Enforcement::Enforced);
        }

        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOSYS) => Ok(Enforcement::Unavailable {
                reason: "seccomp syscall is unavailable on this kernel".to_string(),
            }),
            Some(libc::EINVAL) => Ok(Enforcement::Unavailable {
                reason: format!("seccomp filter or TSYNC is unsupported by this kernel: {error}"),
            }),
            Some(libc::EACCES) | Some(libc::EPERM) => Ok(Enforcement::Unavailable {
                reason: format!("seccomp filter was rejected by the kernel: {error}"),
            }),
            _ => Err(Error::agent("apply seccomp filter", error.to_string())),
        }
    }

    fn build_filter(policy: RunnerSyscallPolicy) -> Vec<libc::sock_filter> {
        let rules = rules_for(policy);
        let mut filter = Vec::with_capacity(8 + rules.len() * 4);

        load_arch(&mut filter);
        jump_if_eq(&mut filter, AUDIT_ARCH, 1, 0);
        ret(&mut filter, libc::SECCOMP_RET_KILL_PROCESS);

        deny_unsupported_abi_syscalls(&mut filter);

        for rule in rules {
            match rule {
                Rule::Syscall { syscall, errno } => deny_syscall(&mut filter, syscall, errno),
                Rule::CloneNamespaceFlags => deny_clone_namespace_flags(&mut filter),
                Rule::SocketFamily { family } => deny_socket_family(&mut filter, family),
            }
        }

        ret(&mut filter, libc::SECCOMP_RET_ALLOW);
        filter
    }

    #[cfg(target_arch = "x86_64")]
    fn deny_unsupported_abi_syscalls(filter: &mut Vec<libc::sock_filter>) {
        load_syscall_nr(filter);
        jump_if_set(filter, X32_SYSCALL_BIT, 0, 1);
        ret(filter, ERRNO_ENOSYS);

        for syscall in 512..=547 {
            deny_syscall(filter, syscall, ERRNO_ENOSYS);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn deny_unsupported_abi_syscalls(_filter: &mut Vec<libc::sock_filter>) {}

    fn rules_for(policy: RunnerSyscallPolicy) -> Vec<Rule> {
        let mut rules = vec![
            Rule::CloneNamespaceFlags,
            unsupported(libc::SYS_clone3),
            deny(libc::SYS_unshare),
            deny(libc::SYS_setns),
            deny(libc::SYS_mount),
            deny(libc::SYS_umount2),
            deny(libc::SYS_pivot_root),
            deny(libc::SYS_chroot),
            deny(libc::SYS_open_tree),
            deny(libc::SYS_move_mount),
            deny(libc::SYS_fsopen),
            deny(libc::SYS_fsconfig),
            deny(libc::SYS_fsmount),
            deny(libc::SYS_fspick),
            deny(libc::SYS_mount_setattr),
            deny(libc::SYS_open_by_handle_at),
            deny(libc::SYS_name_to_handle_at),
            deny(libc::SYS_ptrace),
            deny(libc::SYS_process_vm_readv),
            deny(libc::SYS_process_vm_writev),
            deny(libc::SYS_pidfd_getfd),
            deny(libc::SYS_process_madvise),
            deny(libc::SYS_process_mrelease),
            deny(libc::SYS_kcmp),
            deny(libc::SYS_bpf),
            deny(libc::SYS_perf_event_open),
            deny(libc::SYS_userfaultfd),
            deny(libc::SYS_io_uring_setup),
            deny(libc::SYS_io_uring_enter),
            deny(libc::SYS_io_uring_register),
            deny(libc::SYS_keyctl),
            deny(libc::SYS_add_key),
            deny(libc::SYS_request_key),
            deny(libc::SYS_init_module),
            deny(libc::SYS_finit_module),
            deny(libc::SYS_delete_module),
            deny(libc::SYS_kexec_load),
            deny(libc::SYS_kexec_file_load),
            deny(libc::SYS_reboot),
            deny(libc::SYS_swapon),
            deny(libc::SYS_swapoff),
            deny(libc::SYS_acct),
            deny(libc::SYS_quotactl),
            deny(libc::SYS_settimeofday),
            deny(libc::SYS_clock_settime),
            deny(libc::SYS_clock_adjtime),
            deny(libc::SYS_adjtimex),
            deny(libc::SYS_fanotify_init),
            deny(libc::SYS_lookup_dcookie),
            deny(libc::SYS_memfd_secret),
        ];

        deny_arch_specific_syscalls(&mut rules);

        if !policy.wants_network() {
            rules.extend([
                Rule::SocketFamily {
                    family: libc::AF_INET,
                },
                Rule::SocketFamily {
                    family: libc::AF_INET6,
                },
                Rule::SocketFamily {
                    family: libc::AF_NETLINK,
                },
                Rule::SocketFamily {
                    family: libc::AF_PACKET,
                },
                Rule::SocketFamily {
                    family: libc::AF_ALG,
                },
            ]);
        }

        rules
    }

    fn deny(syscall: libc::c_long) -> Rule {
        Rule::Syscall {
            syscall,
            errno: ERRNO_EPERM,
        }
    }

    fn unsupported(syscall: libc::c_long) -> Rule {
        Rule::Syscall {
            syscall,
            errno: ERRNO_ENOSYS,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn deny_arch_specific_syscalls(rules: &mut Vec<Rule>) {
        rules.extend([deny(libc::SYS_ioperm), deny(libc::SYS_iopl)]);
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn deny_arch_specific_syscalls(_rules: &mut Vec<Rule>) {}

    fn deny_syscall(filter: &mut Vec<libc::sock_filter>, syscall: libc::c_long, errno: u32) {
        load_syscall_nr(filter);
        jump_if_eq(filter, syscall as u32, 0, 1);
        ret(filter, errno);
    }

    fn deny_clone_namespace_flags(filter: &mut Vec<libc::sock_filter>) {
        load_syscall_nr(filter);
        jump_if_eq(filter, libc::SYS_clone as u32, 0, 3);
        load_arg0(filter);
        jump_if_set(filter, NAMESPACE_FLAGS, 0, 1);
        ret(filter, ERRNO_EPERM);
    }

    fn deny_socket_family(filter: &mut Vec<libc::sock_filter>, family: libc::c_int) {
        load_syscall_nr(filter);
        jump_if_eq(filter, libc::SYS_socket as u32, 0, 3);
        load_arg0(filter);
        jump_if_eq(filter, family as u32, 0, 1);
        ret(filter, ERRNO_EPERM);
    }

    fn load_arch(filter: &mut Vec<libc::sock_filter>) {
        stmt(
            filter,
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            ARCH_OFFSET,
        );
    }

    fn load_syscall_nr(filter: &mut Vec<libc::sock_filter>) {
        stmt(
            filter,
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            NR_OFFSET,
        );
    }

    fn load_arg0(filter: &mut Vec<libc::sock_filter>) {
        stmt(
            filter,
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            ARG0_OFFSET,
        );
    }

    fn jump_if_eq(filter: &mut Vec<libc::sock_filter>, value: u32, jt: u8, jf: u8) {
        jump(
            filter,
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            value,
            jt,
            jf,
        );
    }

    fn jump_if_set(filter: &mut Vec<libc::sock_filter>, value: u32, jt: u8, jf: u8) {
        jump(
            filter,
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            value,
            jt,
            jf,
        );
    }

    fn ret(filter: &mut Vec<libc::sock_filter>, value: u32) {
        stmt(filter, libc::BPF_RET | libc::BPF_K, value);
    }

    fn stmt(filter: &mut Vec<libc::sock_filter>, code: u32, value: u32) {
        filter.push(unsafe { libc::BPF_STMT(code as u16, value) });
    }

    fn jump(filter: &mut Vec<libc::sock_filter>, code: u32, value: u32, jt: u8, jf: u8) {
        filter.push(unsafe { libc::BPF_JUMP(code as u16, value, jt, jf) });
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::process::Command;

        const CHILD_ENV: &str = "SMOLVM_TEST_SECCOMP_CHILD";

        #[test]
        fn rules_include_high_value_kernel_attack_surface() {
            let prepared = prepared_launch(false);
            let rules = rules_for(prepared);

            assert!(rules.contains(&Rule::Syscall {
                syscall: libc::SYS_bpf,
                errno: ERRNO_EPERM,
            }));
            assert!(rules.contains(&Rule::Syscall {
                syscall: libc::SYS_perf_event_open,
                errno: ERRNO_EPERM,
            }));
            assert!(rules.contains(&Rule::Syscall {
                syscall: libc::SYS_ptrace,
                errno: ERRNO_EPERM,
            }));
            assert!(rules.contains(&Rule::Syscall {
                syscall: libc::SYS_mount,
                errno: ERRNO_EPERM,
            }));
            assert!(rules.contains(&Rule::CloneNamespaceFlags));
        }

        #[test]
        fn no_network_launch_denies_host_inet_socket_families() {
            let prepared = prepared_launch(false);
            let rules = rules_for(prepared);

            assert!(rules.contains(&Rule::SocketFamily {
                family: libc::AF_INET,
            }));
            assert!(rules.contains(&Rule::SocketFamily {
                family: libc::AF_INET6,
            }));
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn filter_rejects_x32_syscall_numbering() {
            let prepared = prepared_launch(false);
            let filter = build_filter(prepared);

            assert!(filter.iter().any(|instruction| {
                instruction.k == X32_SYSCALL_BIT
                    && instruction.code == (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16
            }));
            assert!(filter.iter().any(|instruction| {
                instruction.k == 512
                    && instruction.code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16
            }));
            assert!(filter.iter().any(|instruction| {
                instruction.k == 547
                    && instruction.code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16
            }));
        }

        #[test]
        fn network_launch_keeps_host_inet_sockets_available_for_vmm_networking() {
            let prepared = prepared_launch(true);
            let rules = rules_for(prepared);

            assert!(!rules.contains(&Rule::SocketFamily {
                family: libc::AF_INET,
            }));
            assert!(!rules.contains(&Rule::SocketFamily {
                family: libc::AF_INET6,
            }));
        }

        #[test]
        fn seccomp_child_probe_blocks_dangerous_syscalls() {
            let output = Command::new(std::env::current_exe().unwrap())
                .env(CHILD_ENV, "1")
                .args([
                    "--exact",
                    "security::linux::seccomp::supported::tests::seccomp_child_probe",
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
        fn seccomp_child_probe() {
            if std::env::var_os(CHILD_ENV).is_none() {
                return;
            }

            super::super::super::set_no_new_privs().unwrap();
            let report = apply(prepared_launch(false)).unwrap();
            match report {
                Enforcement::Enforced => {}
                Enforcement::Unavailable { reason } => {
                    eprintln!("seccomp unavailable on this host: {reason}");
                    return;
                }
                Enforcement::Skipped { reason } => panic!("unexpected seccomp skip: {reason}"),
            }

            assert_eq!(unsafe { libc::syscall(libc::SYS_bpf, 0, 0, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWUSER) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            assert_eq!(
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );

            let unix_socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            assert!(unix_socket >= 0);
            unsafe {
                libc::close(unix_socket);
            }
        }

        fn prepared_launch(network: bool) -> RunnerSyscallPolicy {
            RunnerSyscallPolicy::from_network(network)
        }
    }
}
