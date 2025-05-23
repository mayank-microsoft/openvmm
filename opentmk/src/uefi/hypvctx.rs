use super::{
    context::{TestCtxTrait, VpExecutor},
    hypercall::HvCall,
};
use crate::{debuglog, slog::AssertResult};
use crate::uefi::alloc::ALLOCATOR;
use crate::{
    infolog,
    slog::AssertOption,
    sync::{Channel, Receiver, Sender},
};
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::linked_list::LinkedList;
use alloc::{boxed::Box, vec::Vec};
use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};
use hvdef::hypercall::{HvInputVtl, InitialVpContextX64};
use hvdef::{HvAllArchRegisterName, HvRegisterName, Vtl};
use memory_range::MemoryRange;
use minimal_rt::arch::msr::{read_msr, write_msr};
use spin::Mutex;

const ALIGNMENT: usize = 4096;

type ComandTable =
    BTreeMap<u32, LinkedList<(Box<dyn FnOnce(&mut dyn TestCtxTrait) + 'static>, Vtl)>>;
static mut CMD: Mutex<ComandTable> = Mutex::new(BTreeMap::new());

fn cmdt() -> &'static Mutex<ComandTable> {
    unsafe { &CMD }
}

struct VpContext {
    #[cfg(target_arch = "x86_64")]
    ctx: InitialVpContextX64,
    #[cfg(target_arch = "aarch64")]
    ctx: InitialVpContextAarch64,
}

fn register_command_queue(vp_index: u32) {
    unsafe {
        debuglog!("registering command queue for vp: {}", vp_index);
        if CMD.lock().get(&vp_index).is_none() {
            CMD.lock().insert(vp_index, LinkedList::new());
            debuglog!("registered command queue for vp: {}", vp_index);
        } else {
            debuglog!(
                "command queue already registered for vp: {}",
                vp_index
            );
        }
    }
}

pub struct HvTestCtx {
    pub hvcall: HvCall,
    pub vp_runing: Vec<(u32, (bool, bool))>,
    pub my_vp_idx: u32,
    senders: Vec<(u64, Sender<(Box<dyn FnOnce(&mut HvCall)>, Vtl)>)>,
}

impl Drop for HvTestCtx {
    fn drop(&mut self) {
        self.hvcall.uninitialize();
    }
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
            debuglog!("both vtl0 and vtl1 are running for VP: {:?}", vp_index);
        } else {
            if vp_index == 0 {
                let vp_context = self
                    .get_default_context()
                    .expect("error: failed to get default context");
                self.hvcall
                    .enable_vp_vtl(0, Vtl::Vtl1, Some(vp_context))
                    .expect("error: failed to enable vtl1");

                cmdt().lock().get_mut(&vp_index).unwrap().push_back((
                    Box::new(move |ctx| {
                        ctx.switch_to_low_vtl();
                    }),
                    Vtl::Vtl1,
                ));
                self.switch_to_high_vtl();
                self.vp_runing.push((vp_index, (true, true)));
            } else {
                let my_idx = self.my_vp_idx;
                cmdt().lock().get_mut(&self.my_vp_idx).unwrap().push_back((
                    Box::new(move |ctx| {
                        ctx.enable_vp_vtl_with_default_context(vp_index, Vtl::Vtl1);
                        ctx.start_running_vp_with_default_context(VpExecutor::new(
                            vp_index,
                            Vtl::Vtl1,
                        ));
                        cmdt().lock().get_mut(&vp_index).unwrap().push_back((
                            Box::new(move |ctx| {
                                ctx.set_default_ctx_to_vp(vp_index, Vtl::Vtl0);
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
        cmdt()
            .lock()
            .get_mut(&vp_index)
            .unwrap()
            .push_back((cmd, vtl));
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
        cmdt()
            .lock()
            .get_mut(&vp_index)
            .unwrap()
            .push_back((cmd, vtl));
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
        crate::arch::interrupt::init();
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

    #[cfg(target_arch = "x86_64")]
    fn set_interupt_idx(&mut self, interrupt_idx: u8, handler: fn()) {
        crate::arch::interrupt::set_handler(interrupt_idx, handler);
    }

    fn get_vp_count(&self) -> u32 {
        let mut result: u32 = 0;

        unsafe {
            // Call CPUID with EAX=1, but work around the rbx constraint
            asm!(
                "push rbx",                      // Save rbx
                "cpuid",                         // Execute CPUID
                "mov {result}, rbx",                // Store ebx to our result variable
                "pop rbx",                       // Restore rbx
                in("eax") 1u32,                 // Input: CPUID leaf 1
                out("ecx") _,                   // Output registers (not used)
                out("edx") _,                   // Output registers (not used)
                result = out(reg) result,                // Output: result from ebx
                options(nomem, nostack)
            );
        }

        // Extract logical processor count from bits [23:16]
        (result >> 16) & 0xFF
    }

    #[cfg(target_arch = "x86_64")]
    fn get_register(&mut self, reg: u32) -> u128 {
        use hvdef::HvX64RegisterName;

        let reg = HvX64RegisterName(reg);
        self.hvcall
            .get_register(reg.into(), None)
            .expect_assert("error: failed to get register")
            .as_u128()
    }

    #[cfg(target_arch = "aarch64")]
    fn get_register(&mut self, reg: u32) -> u128 {
        use hvdef::HvAarch64RegisterName;

        let reg = HvAarch64RegisterName(reg);
        self.hvcall
            .get_register(reg.into(), None)
            .expect_assert("error: failed to get register")
            .as_u128()
    }

    fn get_current_vp(&self) -> u32 {
        self.my_vp_idx
    }

    fn get_current_vtl(&self) -> Vtl {
        self.hvcall.vtl
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
        let vp_count = self.get_vp_count();
        for i in 0..vp_count {
            register_command_queue(i);
        }
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

        loop {
            let mut vtl: Option<Vtl> = None;
            let mut cmd: Option<Box<dyn FnOnce(&mut dyn TestCtxTrait) + 'static>> = None;

            {
                let mut d = unsafe { CMD.lock() };
                let mut d = d.get_mut(&ctx.my_vp_idx);
                if d.is_some() {
                    let mut d = d.unwrap();
                    if !d.is_empty() {
                        let (c, v) = d.front().unwrap();
                        if *v == ctx.hvcall.vtl {
                            let (c, v) = d.pop_front().unwrap();
                            cmd = Some(c);
                        } else {
                            vtl = Some(*v);
                        }
                    }
                }
            }

            if let Some(vtl) = vtl {
                if (vtl == Vtl::Vtl0) {
                    ctx.switch_to_low_vtl();
                } else {
                    ctx.switch_to_high_vtl();
                }
            }

            if let Some(cmd) = cmd {
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
