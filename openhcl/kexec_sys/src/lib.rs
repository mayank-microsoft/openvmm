// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thin wrapper around the Linux `kexec_load(2)` and `reboot(2)` syscalls.
//!
//! This crate provides safe Rust wrappers for loading kexec segments and
//! triggering a kexec reboot. It is intentionally minimal — all boot
//! parameter construction logic lives elsewhere.

#![cfg(target_os = "linux")]
// UNSAFETY: This crate wraps Linux kexec_load(2) and reboot(2) syscalls,
// which inherently require unsafe FFI calls.
#![expect(unsafe_code)]

use thiserror::Error;

/// Architecture constants for the `flags` argument to `kexec_load`.
#[cfg(target_arch = "x86_64")]
const KEXEC_ARCH: u64 = 62 << 16; // KEXEC_ARCH_X86_64

#[cfg(target_arch = "aarch64")]
const KEXEC_ARCH: u64 = 183 << 16; // KEXEC_ARCH_AARCH64

/// Maximum number of segments the kernel accepts per `kexec_load` call.
const KEXEC_SEGMENT_MAX: usize = 16;

/// A single segment to be loaded by `kexec_load(2)`.
///
/// This is the Rust equivalent of the kernel's `struct kexec_segment`.
#[repr(C)]
struct RawKexecSegment {
    /// Pointer to the userspace buffer containing segment data.
    buf: *const u8,
    /// Size of the data in `buf`.
    bufsz: usize,
    /// Target physical memory address where the kernel places this segment.
    mem: usize,
    /// Size of the target memory region (>= bufsz, remainder is zero-filled).
    memsz: usize,
}

/// A safe description of a kexec segment: a data buffer and its target
/// physical address.
pub struct KexecSegment {
    /// The data to load at the target address.
    pub data: Vec<u8>,
    /// The target physical address.
    pub phys_addr: u64,
    /// The size of the target memory region (page-aligned, >= data.len()).
    pub mem_size: usize,
}

/// Errors from kexec operations.
#[derive(Debug, Error)]
pub enum KexecError {
    /// Too many segments.
    #[error("too many kexec segments ({count}), maximum is {KEXEC_SEGMENT_MAX}")]
    TooManySegments {
        /// The number of segments that were provided.
        count: usize,
    },
    /// The kexec_load syscall failed.
    #[error("kexec_load syscall failed: {0}")]
    KexecLoadFailed(std::io::Error),
    /// The reboot syscall failed.
    #[error("kexec reboot failed: {0}")]
    RebootFailed(std::io::Error),
}

/// Load kexec segments into the kernel, preparing for a kexec reboot.
///
/// After a successful call, a subsequent [`kexec_reboot`] will boot into
/// the new kernel.
///
/// # Arguments
/// * `entry_point` — The kernel entry point physical address.
/// * `segments` — The segments to load (kernel, initrd, boot params, etc.).
pub fn kexec_load(entry_point: u64, segments: &[KexecSegment]) -> Result<(), KexecError> {
    if segments.len() > KEXEC_SEGMENT_MAX {
        return Err(KexecError::TooManySegments {
            count: segments.len(),
        });
    }

    // Build the raw segment array that the kernel expects.
    let raw_segments: Vec<RawKexecSegment> = segments
        .iter()
        .map(|seg| RawKexecSegment {
            buf: seg.data.as_ptr(),
            bufsz: seg.data.len(),
            mem: seg.phys_addr as usize,
            memsz: seg.mem_size,
        })
        .collect();

    tracing::info!(
        entry_point = %format_args!("{:#x}", entry_point),
        num_segments = segments.len(),
        "invoking kexec_load syscall"
    );

    for (i, seg) in segments.iter().enumerate() {
        tracing::info!(
            segment = i,
            data_len = seg.data.len(),
            phys_addr = %format_args!("{:#x}", seg.phys_addr),
            mem_size = seg.mem_size,
            "kexec segment"
        );
    }

    // SAFETY: We are calling the kexec_load syscall with properly constructed
    // segments. The data buffers referenced by raw_segments are owned by the
    // caller's KexecSegment Vec and remain valid for the duration of the
    // syscall. The kernel copies the data into its own internal buffers before
    // returning.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_kexec_load,
            entry_point as libc::c_ulong,
            raw_segments.len() as libc::c_ulong,
            raw_segments.as_ptr(),
            KEXEC_ARCH as libc::c_ulong,
        )
    };

    if ret != 0 {
        return Err(KexecError::KexecLoadFailed(std::io::Error::last_os_error()));
    }

    tracing::info!("kexec_load succeeded, ready for kexec reboot");
    Ok(())
}

/// Trigger a kexec reboot into the previously loaded kernel.
///
/// This calls `reboot(LINUX_REBOOT_CMD_KEXEC)`. On success, this function
/// does not return — the system reboots into the new kernel.
pub fn kexec_reboot() -> Result<(), KexecError> {
    tracing::info!("triggering kexec reboot");

    // Sync filesystems first.
    // SAFETY: sync() is always safe to call.
    unsafe { libc::sync() };

    const LINUX_REBOOT_MAGIC1: libc::c_int = 0xfee1dead_u32 as libc::c_int;
    const LINUX_REBOOT_MAGIC2: libc::c_int = 672274793; // 0x28121969
    const LINUX_REBOOT_CMD_KEXEC: libc::c_int = 0x45584543;

    // SAFETY: We are calling the reboot syscall with KEXEC command. The caller
    // must have previously called kexec_load successfully.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_reboot,
            LINUX_REBOOT_MAGIC1,
            LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_KEXEC,
            std::ptr::null::<libc::c_void>(),
        )
    };

    // If we get here, the reboot failed.
    let _ = ret;
    Err(KexecError::RebootFailed(std::io::Error::last_os_error()))
}
