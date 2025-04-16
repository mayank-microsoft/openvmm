// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod alloc;
pub mod hypercall;
pub mod init;
mod rt;
mod hypvctx;
mod context;
mod single_threaded;

use crate::arch::interrupt::{read_idtr, set_int_handler};
use crate::slog::{AssertOption, AssertResult};
use crate::sync::{Channel, Receiver, Sender};
use crate::uefi::alloc::ALLOCATOR;
use crate::{infolog, tmk_assert};
use ::alloc::boxed::Box;
use ::alloc::vec::Vec;
use alloc::SIZE_1MB;
use context::{TestCtxTrait, VpExecutor};
use hypvctx::HvTestCtx;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::RefCell;
use core::ops::Range;
use core::sync::atomic::{AtomicI32, Ordering};
use hvdef::hypercall::HvInputVtl;
use hvdef::Vtl;
use uefi::entry;
use uefi::Status;
use init::init;

static mut HEAPX: RefCell<*mut u8> = RefCell::new(0 as *mut u8);
static mut CON: AtomicI32 = AtomicI32::new(0);

#[entry]
fn uefi_main() -> Status {
    init().expect_assert("Failed to initialize environment");

    let mut ctx = HvTestCtx::new();
    ctx.init();

    ctx.setup_interrupt_handler();
    infolog!("set intercept handler successfully!");

    ctx.setup_partition_vtl(Vtl::Vtl1);

    ctx.start_on_vp(
        VpExecutor::new(0, Vtl::Vtl1).command(move |ctx: &mut dyn TestCtxTrait| {
            infolog!("successfully started running VTL1 on vp0.");
            ctx.setup_secure_intercept(0x30);

            let layout =
                Layout::from_size_align(SIZE_1MB, 4096).expect("msg: failed to create layout");
            let ptr = unsafe { ALLOCATOR.alloc(layout) };
            infolog!("allocated some memory in the heap from vtl1");
            unsafe {
                let mut z = HEAPX.borrow_mut();
                *z = ptr;
                *ptr.add(10) = 0xAA;
            }

            let size = layout.size();
            ctx.setup_vtl_protection();

            infolog!("enabled vtl protections for the partition.");

            let range = Range {
                start: ptr as u64,
                end: ptr as u64 + size as u64,
            };

            ctx.apply_vtl_protection_for_memory(range, Vtl::Vtl1);

            infolog!("moving to vtl0 to attempt to read the heap memory");

            ctx.switch_to_low_vtl();
        }),
    );

    ctx.queue_command_vp(VpExecutor::new(0, Vtl::Vtl1).command(move |ctx| {
        infolog!("successfully started running VTL1 on vp0.");
        ctx.switch_to_low_vtl();
    }));

    unsafe {
        infolog!("Attempting to read heap memory from vtl0");
        let heapx = *HEAPX.borrow();
        if !heapx.is_null() {
            let val = *(heapx.add(10));
            infolog!(
                "reading mutated heap memory from vtl0(it should not be 0xAA): 0x{:x}",
                val
            );
            tmk_assert!(
                val != 0xAA,
                "heap memory should not be accessible from vtl0"
            );
        } else {
            infolog!("heapx pointer is null, cannot dereference.");
        }
    }

    let (mut tx, mut rx) = Channel::new(1);
    {
        let mut tx = tx.clone();
        ctx.start_on_vp(VpExecutor::new(2, Vtl::Vtl0).command(
            move |ctx: &mut dyn TestCtxTrait| {
                infolog!("Hello form vtl0 on vp2!");
                tx.send(());
                ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl0).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl0!");
                        unsafe { CON.fetch_add(1, Ordering::Release) };
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(7, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp7 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl0).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp6 is running in vtl0!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};


                        ctx.start_on_vp(VpExecutor::new(3, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp3 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};

                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(2, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("Hello form vtl1 on vp2!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};

                        ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp1 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};
                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(7, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp7 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl0).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp6 is running in vtl0!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};


                        ctx.start_on_vp(VpExecutor::new(3, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp3 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};
                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(2, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("Hello form vtl1 on vp2!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};

                        ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp1 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};
                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(7, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp7 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl0).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp6 is running in vtl0!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};

                        ctx.start_on_vp(VpExecutor::new(3, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp3 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};

                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(2, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("Hello form vtl1 on vp2!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};

                        ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl0).command(
                            move |ctx: &mut dyn TestCtxTrait| {
                                infolog!("vp1 is running in vtl0!");
                                unsafe {CON.fetch_add(1, Ordering::Release)};

                            },
                        ));
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(1, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                    },
                ));
                ctx.start_on_vp(VpExecutor::new(7, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp7 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};

                    },
                ));
                ctx.start_on_vp(VpExecutor::new(6, Vtl::Vtl1).command(
                    move |ctx: &mut dyn TestCtxTrait| {
                        infolog!("vp1 is running in vtl1!");
                        unsafe {CON.fetch_add(1, Ordering::Release)};
                        tx.send(());
                    },
                ));
            },
        ));
    }

    rx.recv();
    rx.recv();

    infolog!("we are in vtl0 now!");


    infolog!("con: {}", unsafe { CON.load(Ordering::Acquire) });
    infolog!("we reached the end of the test");

    Status::SUCCESS
}
