// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod alloc;
pub mod hypercall;
pub mod init;
mod rt;
mod single_threaded;

use crate::arch::interrupt::{read_idtr, set_int_handler};
use crate::sync::{Channel, Mutex, Receiver, Sender};
use crate::uefi::alloc::ALLOCATOR;
use crate::{infolog, logt, tmk_assert};
use ::alloc::boxed::Box;
use ::alloc::sync::Arc;
use ::alloc::vec::Vec;
use alloc::SIZE_1MB;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, naked_asm};
use core::cell::{RefCell, UnsafeCell};
use core::fmt::{Error, Write};
use core::ops::{DerefMut, Range};
use core::sync::atomic::AtomicBool;
use core::{isize, ptr};
use hvdef::hypercall::{HvInputVtl, InitialVpContextX64};
use hvdef::{
    HvRegisterName, HvRegisterValue, HvRegisterVsmPartitionStatus, HvX64RegisterName, Vtl,
};
use hypercall::HvCall;
use init::{init, interrupt_rsp_ptr};
use memory_range::MemoryRange;
use minimal_rt::arch::msr::{read_msr, write_msr};
use single_threaded::SingleThreaded;
use uefi::boot::exit_boot_services;
use uefi::boot::MemoryType;
use uefi::entry;
use uefi::println;
use uefi::proto::console::text;
use uefi::system;
use uefi::Status;
use uefi::{guid, CStr16};

static mut HEAPX: RefCell<*mut u8> = RefCell::new(0 as *mut u8);
static mut COMMAND_TABLE: Vec<(
    u64,
    (
        Receiver<(Box<dyn FnOnce(&mut TestCtx)>, Vtl)>,
        Sender<(Box<dyn FnOnce(&mut TestCtx)>, Vtl)>,
    ),
)> = Vec::new();

fn register_command_queue(vp_index: u32) {
    unsafe {
        let (send, rcsv) = Channel::new(10);
        COMMAND_TABLE.push((vp_index as u64, (rcsv, send.clone())));
        HOLDER.push((vp_index, Mutex::new(None)));
    }
}

fn get_vp_sender(vp_index: u32) -> Sender<(Box<dyn FnOnce(&mut TestCtx)>, Vtl)> {
    let mut cmd = unsafe {
        COMMAND_TABLE
            .iter_mut()
            .find(|cmd| cmd.0 == vp_index as u64)
            .expect("error: failed to find command queue")
    };
    cmd.1 .1.clone()
}

fn get_vp_recv(vp_index: u32) -> Receiver<(Box<dyn FnOnce(&mut TestCtx)>, Vtl)> {
    let mut cmd = unsafe {
        COMMAND_TABLE
            .iter_mut()
            .find(|cmd| cmd.0 == vp_index as u64)
            .expect("error: failed to find command queue")
    };
    cmd.1 .0.clone()
}
static mut HOLDER: Vec<(u32, Mutex<Option<(Box<dyn FnOnce(&mut TestCtx)>, Vtl)>>)> = Vec::new();

fn exec_handler() {
    let mut ctx = TestCtx::new();
    ctx.init();
    let reg = ctx
        .hvcall
        .get_register(hvdef::HvAllArchRegisterName::VpIndex.into(), None)
        .expect("error: failed to get vp index");
    let reg = reg.as_u64();
    ctx.my_vp_idx = reg as u32;

    let mut _cmd = unsafe {
        COMMAND_TABLE
            .iter_mut()
            .find(|cmd| cmd.0 == ctx.my_vp_idx as u64)
            .expect("error: failed to find command queue")
    };

    loop {
        let (cmd, vtl) = _cmd.1 .0.recv();
        if (vtl != ctx.hvcall.vtl) {
            // NOT USE PRIORITY ELSEWHERE
            _cmd.1.1.send_priority((cmd, vtl));
            if (vtl == Vtl::Vtl0) {
                HvCall::low_vtl();
            } else {
                HvCall::high_vtl();
            }
        } else {
            cmd(&mut ctx);
        }
    }
}

fn run_fn_with_current_context(
    func: fn(),
    hvcall: &mut HvCall,
) -> Result<InitialVpContextX64, bool> {
    let mut vp_context: InitialVpContextX64 = hvcall
        .get_current_vtl_vp_context()
        .expect("Failed to get VTL1 context");
    let stack_layout = Layout::from_size_align(SIZE_1MB, 16)
        .expect("Failed to create layout for stack allocation");
    let x = unsafe { ALLOCATOR.alloc(stack_layout) };
    if x.is_null() {
        return Err(false);
    }
    let sz = stack_layout.size();
    let stack_top = x as u64 + sz as u64;
    let fn_ptr = func as fn();
    let fn_address = fn_ptr as u64;
    vp_context.rip = fn_address;
    vp_context.rsp = stack_top;
    // print stack range
    let stack_range = Range {
        start: x as u64,
        end: x as u64 + sz as u64,
    };
    Ok(vp_context)
}

fn get_default_context(hvcall: &mut HvCall) -> Result<InitialVpContextX64, bool> {
    return run_fn_with_current_context(exec_handler, hvcall);
}

struct TestCtx {
    pub hvcall: HvCall,
    pub vp_runing: Vec<(u32, (bool, bool))>,
    pub my_vp_idx: u32,
    senders: Vec<(u64, Sender<(Box<dyn FnOnce(&mut HvCall)>, Vtl)>)>,
}

impl TestCtx {
    pub const fn new() -> Self {
        TestCtx {
            hvcall: HvCall::new(),
            vp_runing: Vec::new(),
            my_vp_idx: 0,
            senders: Vec::new(),
        }
    }

    pub fn init(&mut self) {
        self.hvcall.initialize();
    }

    fn start_on_vp<T>(&mut self, vp_index: u32, vtl: Vtl, cmd: T)
    where
        T: FnOnce(&mut TestCtx) + 'static,
    {
        if vtl >= Vtl::Vtl2 {
            panic!("error: can't run on vtl2");
        }
        let is_vp_running = self.vp_runing.iter_mut().find(|x| x.0 == vp_index);

        if let Some(running_vtl) = is_vp_running {
            infolog!("both vtl0 and vtl1 are running for VP: {:?}", vp_index);
        } else {
            if vp_index == 0 {
                // infolog!("INFO: starting VTL1 for VP: {:?}", vp_index);
                let vp_context = get_default_context(&mut self.hvcall)
                    .expect("error: failed to get default context");
                register_command_queue(vp_index);
                self.hvcall
                    .enable_vp_vtl(0, Vtl::Vtl1, Some(vp_context))
                    .expect("error: failed to enable vtl1");

                let mut sender = get_vp_sender(vp_index);

                sender.send((
                    Box::new(move |hvcall| {
                        HvCall::low_vtl();
                    }),
                    Vtl::Vtl1,
                ));
                HvCall::high_vtl();
                self.vp_runing.push((vp_index, (true, true)));
            } else {
                let vp_context = get_default_context(&mut self.hvcall)
                    .expect("error: failed to get default context");
                let mut priv_vtl_sender = get_vp_sender(self.my_vp_idx);
                register_command_queue(vp_index);
                priv_vtl_sender.send((
                    Box::new(move |ctx| {
                        let vp_ctx = get_default_context(&mut ctx.hvcall)
                            .expect("error: failed to get default context");
                        ctx.hvcall
                            .enable_vp_vtl(vp_index, Vtl::Vtl1, Some(vp_ctx))
                            .expect("errror: failed to enable vtl1");
                        ctx.hvcall
                            .start_virtual_processor(vp_index, Vtl::Vtl1, Some(vp_ctx))
                            .expect("error: failed to start vp");
                        let mut vp_sender = get_vp_sender(vp_index);
                        vp_sender.send((
                            Box::new(move |ctx| {
                                infolog!(
                                    "INFO: starting VTL1 for VP (inside vp2 vtl1): {:?}",
                                    vp_index
                                );
                                let vp_context = get_default_context(&mut ctx.hvcall)
                                    .expect("error: failed to get default context");
                                ctx.hvcall.set_vp_registers(
                                    vp_index,
                                    Some(
                                        HvInputVtl::new()
                                            .with_target_vtl_value(0)
                                            .with_use_target_vtl(true),
                                    ),
                                    Some(vp_context),
                                );
                            }),
                            Vtl::Vtl1,
                        ));
                        HvCall::low_vtl();
                    }),
                    Vtl::Vtl1,
                ));

                HvCall::high_vtl();
                self.vp_runing.push((vp_index, (true, true)));
            }
        }
        let mut sender = get_vp_sender(vp_index);
        let cmd = Box::new(cmd);
        sender.send((cmd, vtl));
        if vp_index == self.my_vp_idx && self.hvcall.vtl != vtl {
            if vtl == Vtl::Vtl0 {
                HvCall::low_vtl();
            } else {
                HvCall::high_vtl();
            }
        }
    }

    fn queue_command_vp<T>(&mut self, vp_index: u32, vtl: Vtl, cmd: T)
    where
        T: FnOnce(&mut TestCtx) + 'static,
    {
        let mut sender = get_vp_sender(vp_index);
        let cmd = Box::new(cmd);
        sender.send((cmd, vtl));
    }
}

#[entry]
fn uefi_main() -> Status {
    init().expect("Failed to initialize environment");

    let mut ctx = TestCtx::new();
    ctx.init();

    let h = read_idtr(&mut ctx.hvcall);
    set_int_handler(h, 0x30);
    let result = ctx
        .hvcall
        .enable_partition_vtl(hvdef::HV_PARTITION_ID_SELF, Vtl::Vtl1);

    if let Ok(_) = result {
        infolog!("VTL1 enabled successfully for the partition!");
    } else {
        infolog!("Failed to enable VTL!");
        infolog!("Error: {:?}", result.err());
    }

    let register_value = ctx
        .hvcall
        .get_register(HvX64RegisterName::VsmPartitionStatus.into(), None);

    if register_value.is_err() {
        infolog!("Failed to get register value!");
        infolog!("Error: {:?}", register_value.err());
    }

    let register_value: HvRegisterVsmPartitionStatus = register_value.unwrap().as_u64().into();
    infolog!("Register value: {:?}", register_value);

    ctx.start_on_vp(0, Vtl::Vtl1, move |ctx| {
        let hvcall = &mut ctx.hvcall;
        infolog!("Hello from VTL1!");
        let layout = Layout::from_size_align(4096, 4096).expect("msg: failed to create layout");
        let ptr = unsafe { ALLOCATOR.alloc(layout) };
        let gpn = (ptr as u64) >> 12;
        let reg = (gpn << 12) | 0x1;
        unsafe { write_msr(hvdef::HV_X64_MSR_SIMP, reg.into()) };
        // if let Ok(_) = hvcall.call_interrupt() {
        //     infolog!("Interrupt called successfully!");
        // } else {
        //     infolog!("Failed to call interrupt!");
        // }
        let reg = unsafe { read_msr(hvdef::HV_X64_MSR_SINT0) };
        let mut reg: hvdef::HvSynicSint = reg.into();
        infolog!("Register value: {:?}", reg);
        reg.set_vector(0x30);
        reg.set_masked(false);
        reg.set_auto_eoi(true);

        unsafe { write_msr(hvdef::HV_X64_MSR_SINT0, reg.into()) };

        let reg = unsafe { read_msr(hvdef::HV_X64_MSR_SINT0) };
        let mut reg: hvdef::HvSynicSint = reg.into();

        let reg = hvcall
            .get_register(HvX64RegisterName::Sint0.into(), None)
            .unwrap()
            .as_table();
        let layout = Layout::from_size_align(SIZE_1MB, 4096).expect("msg: failed to create layout");
        let ptr = unsafe { ALLOCATOR.alloc(layout) };
        unsafe {
            let mut z = HEAPX.borrow_mut();
            *z = ptr;
            *ptr.add(10) = 0xAA;
        }
        let size = layout.size();
        infolog!("Hello from VTL1!");
        let reg = hvcall
            .enable_vtl_protection(0, HvInputVtl::CURRENT_VTL)
            .expect("Failed to enable VTL protection, vtl1");
        let range = Range {
            start: ptr as u64,
            end: ptr as u64 + size as u64,
        };
        infolog!("Range: {:?}", range);
        let r = hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl1);
        if let Ok(_) = r {
            infolog!("APPLY SUCCESS!");
        } else {
            infolog!("APPLY FAILED!");
            infolog!("Error: {:?}", r.err());
        }
        infolog!("moving to VTL0");
        HvCall::low_vtl();
    });

    ctx.queue_command_vp(0, Vtl::Vtl1, move |ctx| {
        infolog!("called after interrupt!");
        HvCall::low_vtl();
    });

    unsafe {
        let heapx = *HEAPX.borrow();
        let val = *(heapx.add(10));
        tmk_assert!(val != 0xAA);
    }

    let (mut tx, mut rx) = Channel::new(1);
    {
        let mut tx = tx.clone();
        ctx.start_on_vp(2, Vtl::Vtl0, move |ctx: &mut TestCtx| {
            infolog!("Hello form vtl0 on vp2!");
            ctx.start_on_vp(1, Vtl::Vtl0, move |ctx: &mut TestCtx| {
                infolog!("vp1 is running in vtl0!");
            });

            ctx.start_on_vp(1, Vtl::Vtl1, move |ctx: &mut TestCtx| {
                infolog!("vp1 is running in vtl1!");
            });

            ctx.start_on_vp(7, Vtl::Vtl1, move |ctx: &mut TestCtx| {
                infolog!("vp7 is running in vtl1!");
            });

            
            ctx.start_on_vp(6, Vtl::Vtl1, move |ctx: &mut TestCtx| {
                infolog!("vp1 is running in vtl1!");
            });

            
            ctx.start_on_vp(6, Vtl::Vtl0, move |ctx: &mut TestCtx| {
                infolog!("vp6 is running in vtl0!");

                ctx.start_on_vp(3, Vtl::Vtl0, move |ctx: &mut TestCtx| {
                    infolog!("vp3 is running in vtl0!");
                });
            });
            tx.send(());
        });
    }

    {
        let mut tx = tx.clone();
        ctx.start_on_vp(2, Vtl::Vtl1, move |ctx| {
            infolog!("Hello form vtl1 on vp2!");
            infolog!("Hello from {:?} on vp2!", ctx.hvcall.vtl);
            tx.send(());
        });
    }

    rx.recv();
    rx.recv();

    infolog!("Hello from VTL0!");

    Status::SUCCESS
}
