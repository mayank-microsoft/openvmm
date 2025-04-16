use alloc::{boxed::Box, vec::Vec};
use memory_range::MemoryRange;
use core::alloc::{GlobalAlloc, Layout};
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};
use hvdef::{Vtl};
use hvdef::hypercall::{HvInputVtl, InitialVpContextX64};
use minimal_rt::arch::msr::{read_msr, write_msr};
use crate::slog::AssertResult;
use crate::uefi::alloc::ALLOCATOR;
use crate::{infolog, slog::AssertOption, sync::{Channel, Receiver, Sender}};
use crate::arch::interrupt::{read_idtr, set_int_handler};
use super::{context::{TestCtxTrait, VpExecutor}, hypercall::HvCall};

const ALIGNMENT: usize = 4096;

static mut COMMAND_TABLE: Vec<(
    u64,
    (
        Receiver<(Box<dyn FnOnce(&mut dyn TestCtxTrait) + 'static>, Vtl)>,
        Sender<(Box<dyn FnOnce(&mut dyn TestCtxTrait) + 'static>, Vtl)>,
    ),
)> = Vec::new();


struct VpContext {
    #[cfg(target_arch = "x86_64")]
    ctx: InitialVpContextX64,
    #[cfg(target_arch = "aarch64")]
    ctx: InitialVpContextAarch64,
}


fn register_command_queue(vp_index: u32) {
    unsafe {
        let (send, rcsv) = Channel::new(10);
        COMMAND_TABLE.push((vp_index as u64, (rcsv, send.clone())));
    }
}

fn get_vp_sender(vp_index: u32) -> Sender<(Box<dyn FnOnce(&mut dyn TestCtxTrait) + 'static>, Vtl)> {
    let mut cmd = unsafe {
        COMMAND_TABLE
            .iter_mut()
            .find(|cmd| cmd.0 == vp_index as u64)
            .expect("error: failed to find command queue")
    };
    cmd.1 .1.clone()
}
pub struct HvTestCtx {
    pub hvcall: HvCall,
    pub vp_runing: Vec<(u32, (bool, bool))>,
    pub my_vp_idx: u32,
    senders: Vec<(u64, Sender<(Box<dyn FnOnce(&mut HvCall)>, Vtl)>)>,
}



impl TestCtxTrait for HvTestCtx {
    fn start_on_vp(&mut self, cmd: VpExecutor) {
        let (vp_index, vtl, cmd) = cmd.get();
        let cmd = cmd.expect_assert("error: failed to get command as cmd is none");
        if vtl >= Vtl::Vtl2 {
            panic!("error: can't run on vtl2");
        }
        let is_vp_running = self.vp_runing.iter_mut().find(|x| x.0 == vp_index);

        if let Some(running_vtl) = is_vp_running {
            infolog!("both vtl0 and vtl1 are running for VP: {:?}", vp_index);
        } else {
            if vp_index == 0 {
                // infolog!("INFO: starting VTL1 for VP: {:?}", vp_index);
                let vp_context = self
                    .get_default_context()
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
                let mut priv_vtl_sender = get_vp_sender(self.my_vp_idx);
                register_command_queue(vp_index);
                let my_idx = self.my_vp_idx;
                priv_vtl_sender.send((
                    Box::new(move |ctx| {
                        ctx.enable_vp_vtl_with_default_context(vp_index, Vtl::Vtl1);
                        ctx.start_running_vp_with_default_context(VpExecutor::new(
                            vp_index,
                            Vtl::Vtl1,
                        ));
                        let mut vp_sender = get_vp_sender(vp_index);
                        vp_sender.send((
                            Box::new(move |ctx| {
                                infolog!(
                                    "INFO: starting VTL1 for VP: {:?} from idx: {}",
                                    vp_index,
                                    my_idx
                                );
                                ctx.set_default_ctx_to_vp(vp_index, Vtl::Vtl0);
                                infolog!("end for vp: {}", vp_index);
                            }),
                            Vtl::Vtl1,
                        ));
                        ctx.switch_to_low_vtl();
                    }),
                    Vtl::Vtl1,
                ));

                self.switch_to_high_vtl();
                self.vp_runing.push((vp_index, (true, true)));
            }
        }
        let mut sender = get_vp_sender(vp_index);
        sender.send((cmd, vtl));
        if vp_index == self.my_vp_idx && self.hvcall.vtl != vtl {
            if vtl == Vtl::Vtl0 {
                self.switch_to_low_vtl();
            } else {
                self.switch_to_high_vtl();
            }
        }
    }

    fn queue_command_vp(&mut self, cmd: VpExecutor) {
        let (vp_index, vtl, cmd) = cmd.get();
        let cmd =
            cmd.expect_assert("error: failed to get command as cmd is none with queue command vp");
        let mut sender = get_vp_sender(vp_index);
        sender.send((cmd, vtl));
    }

    fn switch_to_high_vtl(&mut self) {
        HvCall::high_vtl();
    }

    fn switch_to_low_vtl(&mut self) {
        HvCall::low_vtl();
    }

    fn setup_partition_vtl(&mut self, vtl: Vtl) {
        self.hvcall
            .enable_partition_vtl(hvdef::HV_PARTITION_ID_SELF, vtl)
            .expect_assert("Failed to enable VTL1 for the partition");
        infolog!("enabled vtl protections for the partition.");
    }
    fn setup_interrupt_handler(&mut self) {
        let idt = read_idtr(&mut self.hvcall);
        set_int_handler(idt, 0x30);
    }

    fn setup_vtl_protection(&mut self) {
        self.hvcall
            .enable_vtl_protection(0, HvInputVtl::CURRENT_VTL)
            .expect_assert("Failed to enable VTL protection, vtl1");

        infolog!("enabled vtl protections for the partition.");
    }

    fn setup_secure_intercept(&mut self, interrupt_idx: u8) {
        let layout = Layout::from_size_align(4096, ALIGNMENT)
            .expect_assert("error: failed to create layout for SIMP page");

        let ptr = unsafe { ALLOCATOR.alloc(layout) };
        let gpn = (ptr as u64) >> 12;
        let reg = (gpn << 12) | 0x1;

        unsafe { write_msr(hvdef::HV_X64_MSR_SIMP, reg.into()) };
        infolog!("Successfuly set the SIMP register.");

        let reg = unsafe { read_msr(hvdef::HV_X64_MSR_SINT0) };
        let mut reg: hvdef::HvSynicSint = reg.into();
        reg.set_vector(interrupt_idx);
        reg.set_masked(false);
        reg.set_auto_eoi(true);

        self.write_msr(hvdef::HV_X64_MSR_SINT0, reg.into());
        infolog!("Successfuly set the SINT0 register.");
    }

    fn apply_vtl_protection_for_memory(&mut self, range: Range<u64>, vtl: Vtl) {
        self.hvcall
            .apply_vtl_protections(MemoryRange::new(range), vtl)
            .expect_assert("Failed to apply VTL protections");
    }

    fn write_msr(&mut self, msr: u32, value: u64) {
        unsafe { write_msr(msr, value) };
    }

    fn read_msr(&mut self, msr: u32) -> u64 {
        unsafe { read_msr(msr) }
    }

    fn start_running_vp_with_default_context(&mut self, cmd: VpExecutor) {
        let (vp_index, vtl, cmd) = cmd.get();
        let vp_ctx = self
            .get_default_context()
            .expect_assert("error: failed to get default context");
        self.hvcall
            .start_virtual_processor(vp_index, vtl, Some(vp_ctx))
            .expect_assert("error: failed to start vp");
    }

    fn set_default_ctx_to_vp(&mut self, vp_index: u32, vtl: Vtl) {
        let i: u8 = match vtl {
            Vtl::Vtl0 => 0,
            Vtl::Vtl1 => 1,
            Vtl::Vtl2 => 2,
            _ => panic!("error: invalid vtl"),
        };
        let vp_context = self
            .get_default_context()
            .expect_assert("error: failed to get default context");
        self.hvcall
            .set_vp_registers(
                vp_index,
                Some(
                    HvInputVtl::new()
                        .with_target_vtl_value(i)
                        .with_use_target_vtl(true),
                ),
                Some(vp_context),
            )
            .expect_assert("error: failed to set vp registers");
    }

    fn enable_vp_vtl_with_default_context(&mut self, vp_index: u32, vtl: Vtl) {
        let vp_ctx = self
            .get_default_context()
            .expect_assert("error: failed to get default context");
        self.hvcall
            .enable_vp_vtl(vp_index, vtl, Some(vp_ctx))
            .expect_assert("error: failed to enable vp vtl");
    }
}



impl HvTestCtx {
    pub const fn new() -> Self {
        HvTestCtx {
            hvcall: HvCall::new(),
            vp_runing: Vec::new(),
            my_vp_idx: 0,
            senders: Vec::new(),
        }
    }

    pub fn init(&mut self) {
        self.hvcall.initialize();
    }

    fn exec_handler() {
        let mut ctx = HvTestCtx::new();
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
                _cmd.1 .1.send_priority((cmd, vtl));
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

    #[cfg(target_arch = "x86_64")]
    fn get_default_context(&mut self) -> Result<InitialVpContextX64, bool> {
        return self.run_fn_with_current_context(HvTestCtx::exec_handler);
    }

    #[cfg(target_arch = "x86_64")]
    fn run_fn_with_current_context(&mut self, func: fn()) -> Result<InitialVpContextX64, bool> {
        use super::alloc::SIZE_1MB;

        let mut vp_context: InitialVpContextX64 = self
            .hvcall
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
}
