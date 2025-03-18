// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod alloc;
mod hypercall;
mod rt;
mod single_threaded;

use crate::arch::hypercall::write_hypercall_msr;
use crate::arch::serial::{InstrIoAccess, Serial};
use crate::slog;
use crate::sync::Mutex;
use crate::uefi::alloc::ALLOCATOR;
use ::alloc::vec::Vec;
use alloc::SIZE_1MB;
use minimal_rt::arch::msr::read_msr;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, naked_asm};
use core::cell::RefCell;
use core::fmt::Write;
use core::ops::Range;
use core::sync::atomic::AtomicBool;
use hvdef::hypercall::{HvInputVtl, InitialVpContextX64};
use hvdef::{HvRegisterValue, HvRegisterVsmPartitionStatus, HvX64RegisterName, Vtl};
use hypercall::{HvCall};
use memory_range::MemoryRange;
use single_threaded::SingleThreaded;
use uefi::boot::exit_boot_services;
use uefi::boot::MemoryType;
use uefi::entry;
use uefi::println;
use uefi::system;
use uefi::Status;
use uefi::{guid, CStr16};

static mut MUTEX_1: Mutex<()> = Mutex::new(());

static DATA_CONTAINER: SingleThreaded<RefCell<bool>> = SingleThreaded(RefCell::new(false));
static mut HEAPX: RefCell<*mut u8> = RefCell::new(0 as *mut u8);


#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct InterruptDescriptor64 {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}


fn call_action() {
  let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
  slog!(serial, "Interrupt handler called!");
}

#[naked]
fn interrupt_handler() {
    unsafe { naked_asm!(r#"
        call {fnc}
        iretq
    "#, fnc = sym call_action) };
}


fn read_idtr(hvcall: &mut HvCall) -> Vec<*mut InterruptDescriptor64> {
  let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));

  let idtr = hvcall.get_register(hvdef::HvX64RegisterName::Idtr.into(), None).expect("Failed to get IDTR");
  let idtr = hvdef::HvX64TableRegister::from(idtr);
  slog!(serial, "IDTR: {:?}", idtr);

  let idtr_base = idtr.base;
  let idtr_limit = idtr.limit;
  let idtr_end = idtr_base + idtr_limit as u64;

  slog!(serial, "IDTR Base: {:?}", idtr_base);
  slog!(serial, "IDTR End: {:?}", idtr_end);

  let mut result = Vec::new();
  let mut idtr_seek = idtr_base;
  let mut count = 0;
  loop {
      if idtr_seek >= idtr_end {
          break;
      }
      
      let idt_entry: InterruptDescriptor64 = unsafe { core::ptr::read(idtr_seek as *const _) };
      result.push(idtr_seek as *mut InterruptDescriptor64);
      //slog!(serial, "IDT Entry: {:?}", idt_entry);
      idtr_seek += core::mem::size_of::<InterruptDescriptor64>() as u64;
      count += 1;
  }



  slog!(serial, "IDTR Limit: {:?}", idtr_limit);
  slog!(serial, "IDTR Count: {:?}", count);
  result
}


#[no_mangle]
fn call_interrupt_handler() {
    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
    slog!(serial, "Calling interrupt handler! {}", 0x25);
    unsafe { asm!("int 25H") };
}


fn set_int_handler(idt : Vec<*mut InterruptDescriptor64>, interrupt_idx: u8) {
    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
    slog!(serial, "Setting interrupt handler!");
    let idt_entry = idt[interrupt_idx as usize];
    let idt_entry = unsafe { &mut *idt_entry };
    let handler = interrupt_handler as u64;
    idt_entry.offset_high = (handler >> 32) as u32;
    idt_entry.offset_mid = ((handler >> 16) & 0b1111111111111111) as u16;
    idt_entry.offset_low = (handler & 0b1111111111111111) as u16;
}


fn vtl1_hello_world() {
    let mut hvcall = HvCall::new();
    hvcall.initialize();
    
    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));

    let reg = hvcall.get_register(HvX64RegisterName::Sint0.into(), None);
    if reg.is_err() {
        slog!(serial, "Failed to get register value!");
        slog!(serial, "Error: {:?}", reg.err());
    }
    let mut reg: hvdef::HvSynicSint = reg.unwrap().as_u64().into();
    slog!(serial, "Register value: {:?}", reg);

    reg.set_vector(0x25);
    reg.set_masked(false);
    reg.set_auto_eoi(true);

    hvcall.set_register(HvX64RegisterName::Sint0.into(), HvRegisterValue::from(reg.into_bits()), None).expect("Failed to set register value");
    call_interrupt_handler();

    let reg = hvcall.get_register(HvX64RegisterName::Sint0.into(), None);
    if reg.is_err() {
        slog!(serial, "Failed to get register value!");
        slog!(serial, "Error: {:?}", reg.err());
    }
    let mut reg: hvdef::HvSynicSint = reg.unwrap().as_u64().into();
    slog!(serial, "[NEW]Register value: {:?}", reg);


    let layout = Layout::from_size_align(SIZE_1MB, 4096).expect("msg: failed to create layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    unsafe {
        let mut z = HEAPX.borrow_mut();
        *z = ptr;
    }
    let size = layout.size();
    slog!(serial, "Hello from VTL1!");
    let reg = hvcall.enable_vtl_protection(0, HvInputVtl::CURRENT_VTL).expect("Failed to enable VTL protection, vtl1");
    let range = Range {
        start: ptr as u64,
        end: ptr as u64 + size as u64,
    };
    slog!(serial, "Range: {:?}", range);
    let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl1);
    if let Ok(_) = r {
        slog!(serial, "APPLY SUCCESS!");
    } else {
        slog!(serial, "APPLY FAILED!");
        slog!(serial, "Error: {:?}", r.err());
    }

    let vp_ctx_vtl1: InitialVpContextX64 = unsafe { run_fn_with_current_context(ap2_hello_world_vtl1, &mut hvcall) }
        .expect("Failed to run function with current context");

    hvcall
        .enable_vp_vtl(2, Vtl::Vtl1, Some(vp_ctx_vtl1))
        .expect("Failed to enable VTL1 on VP2");

    // let r = hvcall.start_virtual_processor(2, Vtl::Vtl1, Some(vp_ctx_vtl1));
    // if let Ok(_) = r {
    //     slog!(serial, "VTL2 AP1 enabled successfully!");
    // } else {
    //     slog!(serial, "Failed to enable VTL1!");
    //     slog!(serial, "Error: {:?}", r.err());
    // }
    slog!(serial, "Trying to move to VTL0!");
    HvCall::low_vtl();
    slog!(serial, "failed to move to VTL0!");
    loop {
        slog!(serial, "VTL1 loop!");
        slog!(serial, "BUSY.....");
    }
}

fn ap_write() {
    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
    slog!(serial, "Hello from AP!");
    loop {}
    // slog!(serial, "Trying to move to VTL0!");
    // let range = Range {
    //     start: HEAPX.as_ptr() as u64,
    //     end: HEAPX.as_ptr() as u64 + HEAPX.len() as u64,
    // };

    // let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl0);
    // if let Ok(_) = r {
    //     slog!(serial, "APPLY SUCCESS!");
    // } else {
    //     slog!(serial, "APPLY FAILED!");
    //     slog!(serial, "Error: {:?}", r.err());
    // }
}

fn ap_write_vtl1() {
    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
    slog!(serial, "Hello from AP1 VTL1!");
    loop {}
    // slog!(serial, "Trying to move to VTL0!");
    // let range = Range {
    //     start: HEAPX.as_ptr() as u64,
    //     end: HEAPX.as_ptr() as u64 + HEAPX.len() as u64,
    // };

    // let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl0);
    // if let Ok(_) = r {
    //     slog!(serial, "APPLY SUCCESS!");
    // } else {
    //     slog!(serial, "APPLY FAILED!");
    //     slog!(serial, "Error: {:?}", r.err());
    // }
}

fn ap2_hello_world() {
    let guest_os_id: hvdef::hypercall::HvGuestOsMicrosoft =
        hvdef::hypercall::HvGuestOsMicrosoft::new().with_os_id(1);
    crate::arch::hypercall::initialize(guest_os_id.into());

    let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
    slog!(serial, "Hello from AP2 VTL0!");
    loop {}
}

fn ap2_hello_world_vtl1() {
    let mut hvcall = HvCall::new();
    hvcall.initialize();
    let guest_os_id: hvdef::hypercall::HvGuestOsMicrosoft =
        hvdef::hypercall::HvGuestOsMicrosoft::new().with_os_id(1);
    crate::arch::hypercall::initialize(guest_os_id.into());
    let mut serial: Mutex<Serial<InstrIoAccess>> = Mutex::new(Serial::new(InstrIoAccess {}));
    let vp_ctx_vtl0: InitialVpContextX64 = unsafe { run_fn_with_current_context(ap2_hello_world, &mut hvcall) }
        .expect("Failed to run function with current context");
    let r = hvcall.set_vp_registers(
        2,
        Some(
            HvInputVtl::new()
                .with_target_vtl_value(0)
                .with_use_target_vtl(true),
        ),
        Some(vp_ctx_vtl0),
    );
    if let Ok(r) = r {
        slog!(serial, "VTL0 enabled successfully for AP2!");
    } else {
        slog!(serial, "Failed to enable VTL0 for AP2!");
        slog!(serial, "Error: {:?}", r.err());
    }
    HvCall::low_vtl();
}

fn run_on_vp() {
    let f = || {
        let mut serial = Mutex::new(Serial::new(InstrIoAccess {}));
        slog!(serial, "Hello from Closure!");
    };
    let f = &f as *const _ as u64;
}

fn run_fn_with_current_context(func: fn(), hvcall: &mut HvCall) -> Result<InitialVpContextX64, bool> {
    
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

    Ok(vp_context)
}

#[entry]
fn uefi_main() -> Status {
    let r: bool = unsafe { ALLOCATOR.init(1024) };
    let io = InstrIoAccess {};
    let mut serial = Mutex::new(Serial::new(io));
    if r == false {
        slog!(serial, "Failed to initialize allocator!");
        println!("Failed to initialize allocator!");
        return Status::ABORTED;
    }
    let mut buf = vec![0u8; 1024];
    let mut str_buff = vec![0u16; 1024];
    let os_loader_indications_key =
        CStr16::from_str_with_buf(&"OsLoaderIndications", str_buff.as_mut_slice()).unwrap();
    slog!(
        serial,
        "OsLoaderIndications key: {:?}",
        os_loader_indications_key
    );
    let os_loader_indications_result = uefi::runtime::get_variable(
        os_loader_indications_key,
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")),
        buf.as_mut(),
    )
    .expect("Failed to get OsLoaderIndications");

    slog!(
        serial,
        "OsLoaderIndications: {:?}",
        os_loader_indications_result.0
    );
    slog!(
        serial,
        "OsLoaderIndications size: {:?}",
        os_loader_indications_result.1
    );

    let mut os_loader_indications = u32::from_le_bytes(
        os_loader_indications_result.0[0..4]
            .try_into()
            .expect("error in output"),
    );
    os_loader_indications |= 0x1u32;

    let os_loader_indications = os_loader_indications.to_le_bytes();

    slog!(serial, "OsLoaderIndications: {:?}", os_loader_indications);

    let _ = uefi::runtime::set_variable(
        os_loader_indications_key,
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")),
        os_loader_indications_result.1,
        &os_loader_indications,
    )
    .expect("Failed to set OsLoaderIndications");

    let os_loader_indications_result = uefi::runtime::get_variable(
        os_loader_indications_key,
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")),
        buf.as_mut(),
    )
    .expect("Failed to get OsLoaderIndications");

    slog!(
        serial,
        "[SET] OsLoaderIndications: {:?}",
        os_loader_indications_result.0
    );

    let _ = unsafe { exit_boot_services(MemoryType::BOOT_SERVICES_DATA) };

    let ptr = DATA_CONTAINER.as_ptr();
    slog!(serial, "shared data: {:x}", ptr as u64);
    let mut hvcall = HvCall::new();
    hvcall.initialize();



    let h = read_idtr(&mut hvcall);
    set_int_handler(h, 0x25);

    call_interrupt_handler();


    println!("UEFI vendor = {}", system::firmware_vendor());
    println!("UEFI revision = {:x}", system::firmware_revision());

    slog!(serial, "Hypercall test");

    slog!(serial, "enabling VTL1..");
    let result = hvcall.enable_partition_vtl(hvdef::HV_PARTITION_ID_SELF, Vtl::Vtl1);

    if let Ok(_) = result {
        slog!(serial, "VTL1 enabled successfully for the partition!");
    } else {
        slog!(serial, "Failed to enable VTL!");
        slog!(serial, "Error: {:?}", result.err());
    }

    let register_value = hvcall.get_register(HvX64RegisterName::VsmPartitionStatus.into(), None);

    if register_value.is_err() {
        slog!(serial, "Failed to get register value!");
        slog!(serial, "Error: {:?}", register_value.err());
    }

    let register_value: HvRegisterVsmPartitionStatus = register_value.unwrap().as_u64().into();
    slog!(serial, "Register value: {:?}", register_value);

    // AP Bringup

    // let vp_ctx = unsafe {run_fn_with_current_context(ap_write)}.expect("Failed to run function with current context");
    // let r = hvcall.start_virtual_processor(1, Vtl::Vtl0, Some(vp_ctx));
    // if let Ok(_) = r {
    //       slog!(serial, "VTL0 AP1 enabled successfully!");
    // } else {
    //       slog!(serial, "Failed to enable VTL0!");
    //       slog!(serial, "Error: {:?}", r.err());
    // }

    // get vp context

    let mut vp_context: InitialVpContextX64 =
        run_fn_with_current_context(vtl1_hello_world,&mut hvcall)
        .expect("Failed to get VTL0 context");

    slog!(serial, "VP Context: {:?}", vp_context);
    let r = hvcall.enable_vp_vtl(0, Vtl::Vtl1, Some(vp_context));

    if let Ok(_) = r {
        slog!(serial, "VTL1 enabled successfully!");
    } else {
        slog!(serial, "Failed to enable VTL1!");
        slog!(serial, "Error: {:?}", r.err());
    }

    // unsafe {
    // slog!(serial, "HEAPX: {:?}", HEAPX.borrow()[0]);
    // }

    unsafe {
        let m = MUTEX_1.lock();
        HvCall::high_vtl();
    }
    unsafe  {
        slog!(serial, "Reached VTL0!");
        let heapx = *HEAPX.borrow();
        let val = *(heapx.add(10));
        slog!(serial, "HEAPX: {:?}", val);
    }

    slog!(serial, "VTL1 started!");

    Status::SUCCESS
}
