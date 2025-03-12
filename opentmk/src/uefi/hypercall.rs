// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hypercall infrastructure.

use crate::uefi::single_threaded::SingleThreaded;
use arrayvec::ArrayVec;
use hvdef::hypercall::EnablePartitionVtlFlags;
use hvdef::hypercall::InitialVpContextX64;
use minimal_rt::arch::hypercall::{invoke_hypercall_vtl, invoke_hypercall_high};
use core::arch;
use core::cell::RefCell;
use core::cell::UnsafeCell;
use core::mem::size_of;
use hvdef::hypercall::HvInputVtl;
use hvdef::Vtl;
use hvdef::HV_PAGE_SIZE;
use memory_range::MemoryRange;
use minimal_rt::arch::hypercall::invoke_hypercall;
use zerocopy::IntoBytes;
use zerocopy::FromBytes;

/// Page-aligned, page-sized buffer for use with hypercalls
#[repr(C, align(4096))]
struct HvcallPage {
    buffer: [u8; HV_PAGE_SIZE as usize],
}

impl HvcallPage {
    pub const fn new() -> Self {
        HvcallPage {
            buffer: [0; HV_PAGE_SIZE as usize],
        }
    }

    /// Address of the hypercall page.
    fn address(&self) -> u64 {
        let addr = self.buffer.as_ptr() as u64;

        // These should be page-aligned
        assert!(addr % HV_PAGE_SIZE == 0);

        addr
    }
}

/// Static, reusable page for hypercall input
static HVCALL_INPUT: SingleThreaded<UnsafeCell<HvcallPage>> =
    SingleThreaded(UnsafeCell::new(HvcallPage::new()));

/// Static, reusable page for hypercall output
static HVCALL_OUTPUT: SingleThreaded<UnsafeCell<HvcallPage>> =
    SingleThreaded(UnsafeCell::new(HvcallPage::new()));

static HVCALL: SingleThreaded<RefCell<HvCall>> = SingleThreaded(RefCell::new(HvCall {
    initialized: false,
    vtl: Vtl::Vtl0,
}));

/// Provides mechanisms to invoke hypercalls within the boot shim.
/// Internally uses static buffers for the hypercall page, the input
/// page, and the output page, so this should not be used in any
/// multi-threaded capacity (which the boot shim currently is not).
pub struct HvCall {
    initialized: bool,
    vtl: Vtl,
}

/// Returns an [`HvCall`] instance.
///
/// Panics if another instance is already in use.
#[track_caller]
pub fn hvcall() -> core::cell::RefMut<'static, HvCall> {
    HVCALL.borrow_mut()
}

#[expect(unsafe_code)]
impl HvCall {
    fn input_page() -> &'static mut HvcallPage {
        // SAFETY: `HVCALL` owns the input page.
        unsafe { &mut *HVCALL_INPUT.get() }
    }

    fn output_page() -> &'static mut HvcallPage {
        // SAFETY: `HVCALL` owns the output page.
        unsafe { &mut *HVCALL_OUTPUT.get() }
    }

    /// Returns the address of the hypercall page, mapping it first if
    /// necessary.
    #[cfg(target_arch = "x86_64")]
    pub fn hypercall_page(&mut self) -> u64 {
        self.init_if_needed();
        core::ptr::addr_of!(minimal_rt::arch::hypercall::HYPERCALL_PAGE) as u64
    }

    fn init_if_needed(&mut self) {
        if !self.initialized {
            self.initialize();
        }
    }

    pub fn initialize(&mut self) {
        assert!(!self.initialized);

        // TODO: revisit os id value. For now, use 1 (which is what UEFI does)
        let guest_os_id = hvdef::hypercall::HvGuestOsMicrosoft::new().with_os_id(1);
        crate::arch::hypercall::initialize(guest_os_id.into());
        self.initialized = true;

        self.vtl = self
            .get_register(hvdef::HvAllArchRegisterName::VsmVpStatus.into())
            .map_or(Vtl::Vtl0, |status| {
                hvdef::HvRegisterVsmVpStatus::from(status.as_u64())
                    .active_vtl()
                    .try_into()
                    .unwrap()
            });
    }

    /// Call before jumping to kernel.
    pub fn uninitialize(&mut self) {
        if self.initialized {
            crate::arch::hypercall::uninitialize();
            self.initialized = false;
        }
    }

    /// Returns the environment's VTL.
    pub fn vtl(&self) -> Vtl {
        assert!(self.initialized);
        self.vtl
    }

    /// Makes a hypercall.
    /// rep_count is Some for rep hypercalls
    fn dispatch_hvcall(
        &mut self,
        code: hvdef::HypercallCode,
        rep_count: Option<usize>,
    ) -> hvdef::hypercall::HypercallOutput {
        self.init_if_needed();

        let control: hvdef::hypercall::Control = hvdef::hypercall::Control::new()
            .with_code(code.0)
            .with_rep_count(rep_count.unwrap_or_default());

        // SAFETY: Invoking hypercall per TLFS spec
        unsafe {
            invoke_hypercall(
                control,
                Self::input_page().address(),
                Self::output_page().address(),
            )
        }
    }

    /// Hypercall for setting a register to a value.
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    pub fn set_register(
        &mut self,
        name: hvdef::HvRegisterName,
        value: hvdef::HvRegisterValue,
    ) -> Result<(), hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: hvdef::HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };

        header.write_to_prefix(Self::input_page().buffer.as_mut_slice());

        let reg = hvdef::hypercall::HvRegisterAssoc {
            name,
            pad: Default::default(),
            value,
        };

        reg.write_to_prefix(&mut Self::input_page().buffer[HEADER_SIZE..]);

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallSetVpRegisters, Some(1));

        output.result()
    }

    /// Hypercall for setting a register to a value.
    pub fn get_register(
        &mut self,
        name: hvdef::HvRegisterName,
    ) -> Result<hvdef::HvRegisterValue, hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: hvdef::HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };

        header.write_to_prefix(Self::input_page().buffer.as_mut_slice());
        name.write_to_prefix(&mut Self::input_page().buffer[HEADER_SIZE..]);

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallGetVpRegisters, Some(1));
        output.result()?;
        let value = hvdef::HvRegisterValue::read_from_prefix(&Self::output_page().buffer).unwrap();

        Ok(value.0)
    }

    /// Hypercall to apply vtl protections to the pages from address start to end
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    pub fn apply_vtl2_protections(&mut self, range: MemoryRange) -> Result<(), hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::ModifyVtlProtectionMask>();
        const MAX_INPUT_ELEMENTS: usize = (HV_PAGE_SIZE as usize - HEADER_SIZE) / size_of::<u64>();

        let header = hvdef::hypercall::ModifyVtlProtectionMask {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            map_flags: hvdef::HV_MAP_GPA_PERMISSIONS_NONE,
            target_vtl: HvInputVtl::CURRENT_VTL,
            reserved: [0; 3],
        };

        let mut current_page = range.start_4k_gpn();
        while current_page < range.end_4k_gpn() {
            let remaining_pages = range.end_4k_gpn() - current_page;
            let count = remaining_pages.min(MAX_INPUT_ELEMENTS as u64);

            header.write_to_prefix(Self::input_page().buffer.as_mut_slice());

            let mut input_offset = HEADER_SIZE;
            for i in 0..count {
                let page_num = current_page + i;
                page_num.write_to_prefix(&mut Self::input_page().buffer[input_offset..]);
                input_offset += size_of::<u64>();
            }

            let output = self.dispatch_hvcall(
                hvdef::HypercallCode::HvCallModifyVtlProtectionMask,
                Some(count as usize),
            );

            output.result()?;

            current_page += count;
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    /// Hypercall to get the current VTL VP context
    pub fn get_current_vtl_vp_context(&mut self) -> Result<InitialVpContextX64, hvdef::HvError> {
        use hvdef::HvX64RegisterName;
        use zerocopy::FromZeros;
        let mut context :InitialVpContextX64 = FromZeros::new_zeroed();
        context.cr0 = self.get_register(HvX64RegisterName::Cr0.into())?.as_u64();
        context.cr3 = self.get_register(HvX64RegisterName::Cr3.into())?.as_u64();
        context.cr4 = self.get_register(HvX64RegisterName::Cr4.into())?.as_u64();
        context.rip = self.get_register(HvX64RegisterName::Rip.into())?.as_u64();
        context.rsp = self.get_register(HvX64RegisterName::Rsp.into())?.as_u64();
        context.rflags = self.get_register(HvX64RegisterName::Rflags.into())?.as_u64();
        context.cs = self.get_register(HvX64RegisterName::Cs.into())?.as_segment();
        context.ss = self.get_register(HvX64RegisterName::Ss.into())?.as_segment();
        context.ds = self.get_register(HvX64RegisterName::Ds.into())?.as_segment();
        context.es = self.get_register(HvX64RegisterName::Es.into())?.as_segment();
        context.fs = self.get_register(HvX64RegisterName::Fs.into())?.as_segment();
        context.gs = self.get_register(HvX64RegisterName::Gs.into())?.as_segment();
        context.gdtr = self.get_register(HvX64RegisterName::Gdtr.into())?.as_table();
        context.idtr = self.get_register(HvX64RegisterName::Idtr.into())?.as_table();
        context.tr = self.get_register(HvX64RegisterName::Tr.into())?.as_segment();
        context.efer = self.get_register(HvX64RegisterName::Efer.into())?.as_u64();
        Ok(context)
    }

    pub fn high_vtl() {
        let control: hvdef::hypercall::Control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallVtlCall.0)
            .with_rep_count(0);

        // SAFETY: Invoking hypercall per TLFS spec
        unsafe {
            invoke_hypercall_vtl(
                control,
            );
        }
    }

    pub fn low_vtl() {
        Self::input_page().buffer.fill(0u8);
        let control: hvdef::hypercall::Control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallVtlReturn.0)
            .with_rep_count(0);
        Self::input_page().buffer.fill(0u8);
        // SAFETY: Invoking hypercall per TLFS spec
        unsafe {
            invoke_hypercall_high(
                control,
                Self::input_page().address(),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn enable_vp_vtl(&mut self, vp_index: u32, target_vtl : Vtl, vp_context : Option<InitialVpContextX64>) -> Result<(), hvdef::HvError> {
        let header = hvdef::hypercall::EnableVpVtlX64 {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index,
            target_vtl: target_vtl.into(),
            reserved: [0; 3],
            vp_vtl_context: vp_context.unwrap_or( zerocopy::FromZeros::new_zeroed()),
        };

        header.write_to_prefix(Self::input_page().buffer.as_mut_slice()).expect("size of enable_vp_vtl header is not correct");

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallEnableVpVtl, None);
        match output.result() {
            Ok(()) | Err(hvdef::HvError::VtlAlreadyEnabled) => Ok(()),
            err => err,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn start_virtual_processor(&mut self, vp_index: u32, target_vtl : Vtl, vp_context : Option<InitialVpContextX64>) -> Result<(), hvdef::HvError> {
        let header = hvdef::hypercall::StartVirtualProcessorX64 {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: vp_index,
            target_vtl: target_vtl.into(),
            vp_context: vp_context.unwrap_or(zerocopy::FromZeros::new_zeroed()),
            rsvd0: 0u8,
            rsvd1: 0u16,
        };

        header.write_to_prefix(Self::input_page().buffer.as_mut_slice()).expect("size of start_virtual_processor header is not correct");

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallStartVirtualProcessor, None);
        match output.result() {
            Ok(()) => Ok(()),
            err => panic!("Failed to start virtual processor: {:?}", err),
        }
    }

    pub fn enable_partition_vtl(&mut self, partition_id: u64, target_vtl : Vtl) -> Result<(), hvdef::HvError> {
        let flags: EnablePartitionVtlFlags =
             EnablePartitionVtlFlags::new()
                .with_enable_mbec(false)
                .with_enable_supervisor_shadow_stack(false);

        let header = hvdef::hypercall::EnablePartitionVtl {
            partition_id,
            target_vtl: target_vtl.into(),
            flags,
            reserved_z0: 0,
            reserved_z1: 0,
        };

        let _ = header.write_to_prefix(Self::input_page().buffer.as_mut_slice());

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallEnablePartitionVtl, None);
        match output.result() {
            Ok(()) | Err(hvdef::HvError::VtlAlreadyEnabled) => Ok(()),
            err => err,
        }
    }

    /// Hypercall to enable VP VTL
    #[cfg(target_arch = "aarch64")]
    pub fn enable_vp_vtl(&mut self, vp_index: u32) -> Result<(), hvdef::HvError> {
        let header = hvdef::hypercall::EnableVpVtlArm64 {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index,
            // The VTL value here is just a u8 and not the otherwise usual
            // HvInputVtl value.
            target_vtl: Vtl::Vtl2.into(),
            reserved: [0; 3],
            vp_vtl_context: zerocopy::FromZeroes::new_zeroed(),
        };

        header.write_to_prefix(Self::input_page().buffer.as_mut_slice());

        let output = self.dispatch_hvcall(hvdef::HypercallCode::HvCallEnableVpVtl, None);
        match output.result() {
            Ok(()) | Err(hvdef::HvError::VtlAlreadyEnabled) => Ok(()),
            err => err,
        }
    }

    /// Hypercall to accept vtl2 pages from address start to end with VTL 2
    /// protections and no host visibility
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    pub fn accept_vtl2_pages(
        &mut self,
        range: MemoryRange,
        memory_type: hvdef::hypercall::AcceptMemoryType,
    ) -> Result<(), hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::AcceptGpaPages>();
        const MAX_INPUT_ELEMENTS: usize = (HV_PAGE_SIZE as usize - HEADER_SIZE) / size_of::<u64>();

        let mut current_page = range.start_4k_gpn();
        while current_page < range.end_4k_gpn() {
            let header = hvdef::hypercall::AcceptGpaPages {
                partition_id: hvdef::HV_PARTITION_ID_SELF,
                page_attributes: hvdef::hypercall::AcceptPagesAttributes::new()
                    .with_memory_type(memory_type.0)
                    .with_host_visibility(hvdef::hypercall::HostVisibilityType::PRIVATE) // no host visibility
                    .with_vtl_set(1 << 2), // applies vtl permissions for vtl 2
                vtl_permission_set: hvdef::hypercall::VtlPermissionSet {
                    vtl_permission_from_1: [0; hvdef::hypercall::HV_VTL_PERMISSION_SET_SIZE],
                },
                gpa_page_base: current_page,
            };

            let remaining_pages = range.end_4k_gpn() - current_page;
            let count = remaining_pages.min(MAX_INPUT_ELEMENTS as u64);

            header.write_to_prefix(Self::input_page().buffer.as_mut_slice());

            let output = self.dispatch_hvcall(
                hvdef::HypercallCode::HvCallAcceptGpaPages,
                Some(count as usize),
            );

            output.result()?;

            current_page += count;
        }

        Ok(())
    }

    /// Get the corresponding VP indices from a list of VP hardware IDs (APIC
    /// IDs on x64, MPIDR on ARM64).
    ///
    /// This always queries VTL0, since the hardware IDs are the same across the
    /// VTLs in practice, and the hypercall only succeeds for VTL2 once VTL2 has
    /// been enabled (which it might not be at this point).
    pub fn get_vp_index_from_hw_id<const N: usize>(
        &mut self,
        hw_ids: &[HwId],
        output: &mut ArrayVec<u32, N>,
    ) -> Result<(), hvdef::HvError> {
        let header = hvdef::hypercall::GetVpIndexFromApicId {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            target_vtl: 0,
            reserved: [0; 7],
        };

        // Split the call up to avoid exceeding the hypercall input/output size limits.
        const MAX_PER_CALL: usize = 512;

        for hw_ids in hw_ids.chunks(MAX_PER_CALL) {
            header.write_to_prefix(Self::input_page().buffer.as_mut_slice());
            hw_ids.write_to_prefix(&mut Self::input_page().buffer[header.as_bytes().len()..]);

            // SAFETY: The input header and rep slice are the correct types for this hypercall.
            //         The hypercall output is validated right after the hypercall is issued.
            let r = self.dispatch_hvcall(
                hvdef::HypercallCode::HvCallGetVpIndexFromApicId,
                Some(hw_ids.len()),
            );

            let n = r.elements_processed() as usize;

            output.extend(
                <[u32]>::ref_from_bytes(&Self::output_page().buffer[..n * 4])
                    .unwrap()
                    .iter()
                    .copied(),
            );
            r.result()?;
            assert_eq!(n, hw_ids.len());
        }

        Ok(())
    }
}

/// The "hardware ID" used for [`HvCall::get_vp_index_from_hw_id`]. This is the
/// APIC ID on x64.
#[cfg(target_arch = "x86_64")]
pub type HwId = u32;

/// The "hardware ID" used for [`HvCall::get_vp_index_from_hw_id`]. This is the
/// MPIDR on ARM64.
#[cfg(target_arch = "aarch64")]
pub type HwId = u64;