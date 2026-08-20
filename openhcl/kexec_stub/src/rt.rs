// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime support for the kexec stub.

pub(crate) const STACK_SIZE: usize = 32768;
pub(crate) const STACK_COOKIE: u32 = 0x30405060;

#[repr(C, align(16))]
pub struct Stack([u8; STACK_SIZE]);

pub static mut STACK: Stack = Stack([0; STACK_SIZE]);

/// Validate the stack cookie is still present. Panics if overwritten.
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub fn verify_stack_cookie() {
    // SAFETY: Checking the stack cookie value. The pointer is valid since
    // STACK is a static. If the cookie was overwritten, we've likely
    // already corrupted memory, but we try to catch it here.
    unsafe {
        let stack_ptr = core::ptr::addr_of!(STACK).cast::<u32>();
        if core::ptr::read(stack_ptr) != STACK_COOKIE {
            panic!("Stack was overrun");
        }
    }
}

/// Entry point called from assembly after BSS is zeroed and stack is set up.
///
/// # Safety
///
/// The caller must pass a valid physical pointer to a `boot_params` struct
/// (as provided by the kexec purgatory via RSI).
#[cfg_attr(not(minimal_rt), expect(dead_code))]
pub unsafe extern "C" fn start(boot_params_ptr: usize) -> ! {
    crate::stub_main(boot_params_ptr)
}

#[cfg(minimal_rt)]
mod panic_impl {
    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
        use core::fmt::Write;
        let mut serial = minimal_rt::arch::Serial::init(minimal_rt::arch::InstrIoAccess);
        let _ = writeln!(serial, "KEXEC STUB PANIC: {}", info);
        minimal_rt::arch::fault();
    }
}
