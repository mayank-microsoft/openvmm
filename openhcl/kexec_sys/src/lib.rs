// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thin wrapper around the Linux `kexec_file_load(2)` and `reboot(2)` syscalls.
//!
//! Provides safe Rust wrappers for loading a bzImage kernel via
//! `kexec_file_load` and triggering a kexec reboot.

#![cfg(target_os = "linux")]
// UNSAFETY: This crate wraps Linux kexec_file_load(2) and reboot(2) syscalls,
// which inherently require unsafe FFI calls.
#![expect(unsafe_code)]

use thiserror::Error;

/// Flag: carry over the current boot's FDT to the new kernel via setup_data.
pub const KEXEC_FILE_FORCE_DTB: u64 = 0x20;

/// Flag: enable verbose kexec_dprintk() output in the kernel.
pub const KEXEC_FILE_DEBUG: u64 = 0x08;

/// Flag: skip initrd (pass initrd_fd = -1).
pub const KEXEC_FILE_NO_INITRAMFS: u64 = 0x04;

/// Errors from kexec operations.
#[derive(Debug, Error)]
pub enum KexecError {
    /// The kexec_file_load syscall failed.
    #[error("kexec_file_load syscall failed: {0}")]
    KexecFileLoadFailed(std::io::Error),
    /// The reboot syscall failed.
    #[error("kexec reboot failed: {0}")]
    RebootFailed(std::io::Error),
}

/// Load a kernel via `kexec_file_load(2)`.
///
/// The kernel handles bzImage parsing, segment layout, boot_params
/// construction, purgatory, and page tables internally.
///
/// # Arguments
/// * `kernel_fd` - File descriptor of the kernel image (bzImage/vmlinuz).
/// * `initrd_fd` - File descriptor of the initrd image (-1 if none).
/// * `cmdline`   - Kernel command line string.
/// * `flags`     - Combination of KEXEC_FILE_* flags.
pub fn kexec_file_load(
    kernel_fd: i32,
    initrd_fd: i32,
    cmdline: &str,
    flags: u64,
) -> Result<(), KexecError> {
    // The kernel expects cmdline to be null-terminated, with cmdline_len
    // including the null terminator byte.
    let mut cmdline_buf = cmdline.as_bytes().to_vec();
    cmdline_buf.push(0); // null terminator

    // SAFETY: kexec_file_load is a Linux syscall that reads from the
    // provided fds and cmdline pointer. The cmdline_buf and its length
    // are valid for the duration of the syscall.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_kexec_file_load,
            kernel_fd as libc::c_long,
            initrd_fd as libc::c_long,
            cmdline_buf.len() as libc::c_ulong,
            cmdline_buf.as_ptr() as libc::c_ulong,
            flags as libc::c_ulong,
        )
    };
    if ret < 0 {
        Err(KexecError::KexecFileLoadFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

/// Trigger a kexec reboot into the previously loaded kernel.
///
/// On success, this function does not return. The current kernel
/// is replaced by the kernel loaded via [`kexec_file_load`].
pub fn kexec_reboot() -> Result<(), KexecError> {
    // SAFETY: reboot(LINUX_REBOOT_CMD_KEXEC) is a well-defined Linux
    // syscall. On success it does not return.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_reboot,
            0xfee1dead_u32 as libc::c_int,  // LINUX_REBOOT_MAGIC1
            672274793 as libc::c_int,         // LINUX_REBOOT_MAGIC2
            0x45584543u32 as libc::c_int,     // LINUX_REBOOT_CMD_KEXEC
            std::ptr::null::<u8>() as libc::c_ulong,
        )
    };
    if ret < 0 {
        Err(KexecError::RebootFailed(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_constants_match_kernel() {
        assert_eq!(KEXEC_FILE_NO_INITRAMFS, 0x04);
        assert_eq!(KEXEC_FILE_DEBUG, 0x08);
        assert_eq!(KEXEC_FILE_FORCE_DTB, 0x20);
    }
}