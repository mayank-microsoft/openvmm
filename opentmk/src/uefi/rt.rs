// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime support for the UEFI application environment.

#![cfg(target_os = "uefi")]
// UNSAFETY: Raw assembly needed for panic handling to abort.
#![expect(unsafe_code)]

use minimal_rt::arch::{Serial, InstrIoAccess};
use core::fmt::Write;


#[panic_handler]
fn panic_handler(panic: &core::panic::PanicInfo<'_>) -> ! {

    let io = InstrIoAccess {};
    let mut ser = Serial::new(io);
    ser.write_str(format!("{}\n", panic).as_str());

    // If the system table is available, use UEFI's standard shutdown mechanism
    if uefi::table::system_table_raw().is_none() {
        use uefi::table::runtime::ResetType;
        uefi::runtime::reset(ResetType::SHUTDOWN, uefi::Status::ABORTED, None);
    }

    ser.write_str("Could not shut down... falling back to invoking an undefined instruction");

    // SAFETY: the undefined instruction trap handler in `guest_test_uefi` will not return
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2");
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("brk #0");
        core::hint::unreachable_unchecked();
    }
}
