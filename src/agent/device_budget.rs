use crate::network::EffectiveNetworkBackend;

/// Virtio-mmio devices consume one IRQ each in libkrun's MMIO transport.
///
/// These ranges mirror libkrun's architecture layouts. Keep them in sync with
/// `libkrun/src/arch/src/*/layout.rs`.
#[cfg(target_arch = "x86_64")]
const MMIO_IRQ_RANGE: Option<(u32, u32)> = Some((5, 23));
#[cfg(target_arch = "aarch64")]
const MMIO_IRQ_RANGE: Option<(u32, u32)> = Some((32, 159));
#[cfg(target_arch = "riscv64")]
const MMIO_IRQ_RANGE: Option<(u32, u32)> = Some((0, 1023));
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
const MMIO_IRQ_RANGE: Option<(u32, u32)> = None;

const FIXED_VIRTIO_MMIO_DEVICES: usize = 5;

#[derive(Debug, Clone, Copy)]
pub(crate) struct MmioDevicePlan {
    pub block_disks: usize,
    pub virtiofs_devices: usize,
    pub network_backend: EffectiveNetworkBackend,
    pub gpu: bool,
}

impl MmioDevicePlan {
    fn required_devices(self) -> usize {
        FIXED_VIRTIO_MMIO_DEVICES
            + self.block_disks
            + self.virtiofs_devices
            + usize::from(matches!(
                self.network_backend,
                EffectiveNetworkBackend::VirtioNet
            ))
            + usize::from(self.gpu)
    }
}

pub(crate) fn validate_mmio_device_budget(plan: MmioDevicePlan) -> Result<(), String> {
    let Some((irq_base, irq_max)) = MMIO_IRQ_RANGE else {
        return Ok(());
    };

    let capacity = (irq_max - irq_base + 1) as usize;
    let required = plan.required_devices();
    if required <= capacity {
        return Ok(());
    }

    Err(format!(
        "VM requests {required} virtio-mmio devices, but {} libkrun exposes {capacity} IRQ slots \
         ({irq_base}-{irq_max}). Device count: fixed={} (balloon, rng, console, rootfs, vsock), \
         block disks={}, virtiofs={}, virtio-net={}, gpu={}. Reduce mounts, packed/imported image \
         attachments, extra disks, virtio-net networking, published ports, or GPU usage for this VM.",
        std::env::consts::ARCH,
        FIXED_VIRTIO_MMIO_DEVICES,
        plan.block_disks,
        plan.virtiofs_devices,
        usize::from(matches!(
            plan.network_backend,
            EffectiveNetworkBackend::VirtioNet
        )),
        usize::from(plan.gpu)
    ))
}
