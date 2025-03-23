// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod alloc;
mod hypercall;
mod rt;
mod single_threaded;

use ::alloc::boxed::Box;
use ::alloc::sync::Arc;
use minimal_rt::arch::msr::{read_msr, write_msr};
use crate::{infolog, logt, tmk_assert};
use crate::sync::{Channel, Mutex, Receiver, Sender};
use crate::uefi::alloc::ALLOCATOR;
use ::alloc::vec::Vec;
use alloc::SIZE_1MB;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, naked_asm};
use core::cell::RefCell;
use core::fmt::Write;
use core::ops::Range;
use core::ptr;
use core::sync::atomic::AtomicBool;
use hvdef::hypercall::{HvInputVtl, InitialVpContextX64};
use hvdef::{HvRegisterName, HvRegisterValue, HvRegisterVsmPartitionStatus, HvX64RegisterName, Vtl};
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

#[repr(align(4096))]
struct Blank {
    data: [u8; 4096],
}

#[allow(non_upper_case_globals)]
static mut interrupt_rsp_ptr: *mut u8 = 0 as *mut u8;
#[allow(non_upper_case_globals)]
static mut interrupt_rsp_start : *mut u8 = 0 as *mut u8;

static mut MUTEX_1: Mutex<()> = Mutex::new(());

static DATA_CONTAINER: SingleThreaded<RefCell<bool>> = SingleThreaded(RefCell::new(false));
static mut HEAPX: RefCell<*mut u8> = RefCell::new(0 as *mut u8);

#[link_section = ".bss"]
static mut BUFFER: [u8; 1024] = [0; 1024];


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
    logt!("Interrupt called!\n");
    let mut out = 90u64;
    unsafe { asm!("mov {}, rsp", out(reg) out) };
    logt!("Interrupt called! rsp: 0x{:x}", out);
    unsafe {
        logt!("Interrupt called! rsp: 0x{:x}", interrupt_rsp_ptr as u64);
    }
}


fn dispatch() {
    unsafe { 
        asm!(r#"
        mov rsp, {rsp}
        "#, rsp = in(reg) interrupt_rsp_ptr);
    }
    call_action();
}

#[naked]
fn interrupt_handler() {
    unsafe { naked_asm!(r#"
        push rsp
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        call {fnc}
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        pop rsp
        iretq
    "#,fnc = sym dispatch) };
}


fn read_idtr(hvcall: &mut HvCall) -> Vec<*mut InterruptDescriptor64> {

  let idtr = hvcall.get_register(hvdef::HvX64RegisterName::Idtr.into(), None).expect("Failed to get IDTR");
  let idtr = hvdef::HvX64TableRegister::from(idtr);
  logt!("IDTR: {:?}", idtr);

  let idtr_base = idtr.base;
  let idtr_limit = idtr.limit;
  let idtr_end = idtr_base + idtr_limit as u64;

  logt!("IDTR Base: {:?}", idtr_base);
  logt!("IDTR End: {:?}", idtr_end);

  let mut result = Vec::new();
  let mut idtr_seek = idtr_base;
  let mut count = 0;
  loop {
      if idtr_seek >= idtr_end {
          break;
      }
      
      let idt_entry: InterruptDescriptor64 = unsafe { core::ptr::read(idtr_seek as *const _) };
      result.push(idtr_seek as *mut InterruptDescriptor64);
      //logt!("IDT Entry: {:?}", idt_entry);
      idtr_seek += core::mem::size_of::<InterruptDescriptor64>() as u64;
      count += 1;
  }



  logt!("IDTR Limit: {:?}", idtr_limit);
  logt!("IDTR Count: {:?}", count);
  result
}


#[no_mangle]
fn call_interrupt_handler() {
    unsafe { asm!("int 30H") };
}

fn allocate_interrupt_stack() -> *mut u8 {
    let layout: Layout = Layout::from_size_align(4096, 4096).expect("msg: failed to create layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    unsafe { interrupt_rsp_start = ptr };
    let ptr = unsafe { ptr.add(4096) };
    unsafe { interrupt_rsp_ptr = ptr };
    ptr
}


fn unallocate_interrupt_stack() {
    let layout = Layout::from_size_align(4096, 4096).expect("msg: failed to create layout");
    unsafe { ALLOCATOR.dealloc(interrupt_rsp_start, layout) };
    unsafe { interrupt_rsp_ptr = 0 as *mut u8 };
}
fn set_int_handler(idt : Vec<*mut InterruptDescriptor64>, interrupt_idx: u8) {
    infolog!("Setting interrupt handler!");
    let idt_entry = idt[interrupt_idx as usize];
    let idt_entry = unsafe { &mut *idt_entry };
    let handler = interrupt_handler as u64;
    idt_entry.offset_high = (handler >> 32) as u32;
    idt_entry.offset_mid = ((handler >> 16) & 0b1111111111111111) as u16;
    idt_entry.offset_low = (handler & 0b1111111111111111) as u16;
    idt_entry.type_attr |= 0b1110;

    // let inti: *mut InterruptDescriptor64 = idt[0];
    unsafe  {
        // asm!("lidt", in(reg) inti);
        asm!("sti");
    }
    infolog!("IDT Entry: {:?}", idt_entry);
}


static mut COMMAND_TABLE: Vec<(u64, Receiver<'static, Box<dyn FnOnce()>>)> = Vec::new();

fn register_command_queue(vp_index: u64, vtl: Vtl) -> (Channel<Box<dyn FnOnce()>>, Sender<'static, Box<dyn FnOnce()>>) {
    unsafe {
        let vtl: u64 = match vtl {
            Vtl::Vtl0 => 0,
            Vtl::Vtl1 => 1,
            Vtl::Vtl2 => 2,
        };
        let idx = (vp_index << 3) | vtl as u64;
        let mut queue: Channel<Box<dyn FnOnce()>> = Channel::new(1);
        let mut recv = Receiver::new(&mut queue);
        COMMAND_TABLE.push((idx, recv));
        return queue;
    }
}
fn exec_handler() {
    let mut hvcall = HvCall::new();
    hvcall.initialize();
    let reg = hvcall.get_register(hvdef::HvAllArchRegisterName::VpIndex.into(), None).expect("error: failed to get vp index");
    let reg = reg.as_u64();
    let vtl = match hvcall.vtl {
        Vtl::Vtl0 => 0,
        Vtl::Vtl1 => 1,
        Vtl::Vtl2 => 2,
    };
    let reg = (reg << 3) | vtl;
    logt!("chk1");
    let cmd = unsafe { COMMAND_TABLE.iter().find(|cmd| cmd.0 == reg).expect("error: failed to find command queue") };
    logt!("chk2");
    let cmd = unsafe {&mut *cmd.1};
    logt!("chk3");
    loop {
        let mut cmd = cmd.recv();
        logt!("chk4");
        cmd();
    }
    logt!("Register value: {:?}", reg);
}


fn vtl1_hello_world() {

    let mut hvcall = HvCall::new();
    hvcall.initialize();
    
    let h: Vec<*mut InterruptDescriptor64> = read_idtr(&mut hvcall);
    set_int_handler(h, 0x30);

    let layout = Layout::from_size_align(4096, 4096).expect("msg: failed to create layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    let gpn = (ptr as u64) >> 12;
    let reg = (gpn << 12) | 0x1;
    unsafe { write_msr(hvdef::HV_X64_MSR_SIMP, reg.into()) };


    // if let Ok(_) = hvcall.call_interrupt() {
    //     logt!("Interrupt called successfully!");
    // } else {
    //     logt!("Failed to call interrupt!");
    // }
    
    let reg = unsafe{ read_msr(hvdef::HV_X64_MSR_SINT0)};

    let mut reg: hvdef::HvSynicSint = reg.into();
    logt!("Register value: {:?}", reg);

    reg.set_vector(0x30);
    reg.set_masked(false);
    reg.set_auto_eoi(true);
    
    unsafe { write_msr(hvdef::HV_X64_MSR_SINT0, reg.into()) };

    let reg = unsafe { read_msr(hvdef::HV_X64_MSR_SINT0) };
    let mut reg: hvdef::HvSynicSint = reg.into();
    logt!("[NEW]Register value: {:?}", reg);


    let reg = hvcall.get_register(HvX64RegisterName::Sint0.into(), None).unwrap().as_table();
    logt!("[AAAAAA]Register value: {:?}", reg);
    

    let layout = Layout::from_size_align(SIZE_1MB, 4096).expect("msg: failed to create layout");
    let ptr = unsafe { ALLOCATOR.alloc(layout) };
    unsafe {
        let mut z = HEAPX.borrow_mut();
        *z = ptr;
        *ptr.add(10) = 0xAA;
    }
    let size = layout.size();
    logt!("Hello from VTL1!");
    let reg = hvcall.enable_vtl_protection(0, HvInputVtl::CURRENT_VTL).expect("Failed to enable VTL protection, vtl1");
    let range = Range {
        start: ptr as u64,
        end: ptr as u64 + size as u64,
    };
    logt!("Range: {:?}", range);
    let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl1);
    if let Ok(_) = r {
        logt!("APPLY SUCCESS!");
    } else {
        logt!("APPLY FAILED!");
        logt!("Error: {:?}", r.err());
    }

    let vp_ctx_vtl1: InitialVpContextX64 = unsafe { run_fn_with_current_context(ap2_hello_world_vtl1, &mut hvcall) }
        .expect("Failed to run function with current context");

    hvcall
        .enable_vp_vtl(2, Vtl::Vtl1, Some(vp_ctx_vtl1))
        .expect("Failed to enable VTL1 on VP2");

    // let r = hvcall.start_virtual_processor(2, Vtl::Vtl1, Some(vp_ctx_vtl1));
    // if let Ok(_) = r {
    //     logt!("VTL2 AP1 enabled successfully!");
    // } else {
    //     logt!("Failed to enable VTL1!");
    //     logt!("Error: {:?}", r.err());
    // }
    logt!("Trying to move to VTL0!");
    HvCall::low_vtl();
    loop {
        logt!("VTL1 loop!");
        logt!("BUSY.....");
        break;
    }
    HvCall::low_vtl();
}

fn ap_write() {
    logt!("Hello from AP!");
    loop {}
    // logt!("Trying to move to VTL0!");
    // let range = Range {
    //     start: HEAPX.as_ptr() as u64,
    //     end: HEAPX.as_ptr() as u64 + HEAPX.len() as u64,
    // };

    // let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl0);
    // if let Ok(_) = r {
    //     logt!("APPLY SUCCESS!");
    // } else {
    //     logt!("APPLY FAILED!");
    //     logt!("Error: {:?}", r.err());
    // }
}

fn ap_write_vtl1() {
    logt!("Hello from AP1 VTL1!");
    loop {}
    // logt!("Trying to move to VTL0!");
    // let range = Range {
    //     start: HEAPX.as_ptr() as u64,
    //     end: HEAPX.as_ptr() as u64 + HEAPX.len() as u64,
    // };

    // let r= hvcall.apply_vtl_protections(MemoryRange::new(range), Vtl::Vtl0);
    // if let Ok(_) = r {
    //     logt!("APPLY SUCCESS!");
    // } else {
    //     logt!("APPLY FAILED!");
    //     logt!("Error: {:?}", r.err());
    // }
}

fn ap2_hello_world() {
    let guest_os_id: hvdef::hypercall::HvGuestOsMicrosoft =
        hvdef::hypercall::HvGuestOsMicrosoft::new().with_os_id(1);
    crate::arch::hypercall::initialize(guest_os_id.into());

    logt!("Hello from AP2 VTL0!");
    loop {}
}

fn ap2_hello_world_vtl1() {
    let mut hvcall = HvCall::new();
    hvcall.initialize();
    let guest_os_id: hvdef::hypercall::HvGuestOsMicrosoft =
        hvdef::hypercall::HvGuestOsMicrosoft::new().with_os_id(1);
    crate::arch::hypercall::initialize(guest_os_id.into());
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
        logt!("VTL0 enabled successfully for AP2!");
    } else {
        logt!("Failed to enable VTL0 for AP2!");
        logt!("Error: {:?}", r.err());
    }
    HvCall::low_vtl();
}

fn run_on_vp() {
    let f = || {
        logt!("Hello from Closure!");
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
    // print stack range
    let stack_range = Range {
        start: x as u64,
        end: x as u64 + sz as u64,
    };
    logt!("Stack range: {:x}-{:x}", stack_range.start, stack_range.end);
    Ok(vp_context)
}

#[entry]
fn uefi_main() -> Status {
    let r: bool = unsafe { ALLOCATOR.init(1024) };
    if r == false {
        logt!("Failed to initialize allocator!");
        println!("Failed to initialize allocator!");
        return Status::ABORTED;
    }
    allocate_interrupt_stack();
    let mut buf = vec![0u8; 1024];
    let mut str_buff = vec![0u16; 1024];
    let os_loader_indications_key =
        CStr16::from_str_with_buf(&"OsLoaderIndications", str_buff.as_mut_slice()).unwrap();
    logt!(
        "OsLoaderIndications key: {:?}",
        os_loader_indications_key
    );
    let os_loader_indications_result = uefi::runtime::get_variable(
        os_loader_indications_key,
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")),
        buf.as_mut(),
    )
    .expect("Failed to get OsLoaderIndications");

    logt!(
    "OsLoaderIndications: {:?}",
        os_loader_indications_result.0
    );
    logt!( "OsLoaderIndications size: {:?}",
        os_loader_indications_result.1
    );

    let mut os_loader_indications = u32::from_le_bytes(
        os_loader_indications_result.0[0..4]
            .try_into()
            .expect("error in output"),
    );
    os_loader_indications |= 0x1u32;

    let os_loader_indications = os_loader_indications.to_le_bytes();

    logt!("OsLoaderIndications: {:?}", os_loader_indications);

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

    logt!(
        "[SET] OsLoaderIndications: {:?}",
        os_loader_indications_result.0
    );

    let _ = unsafe { exit_boot_services(MemoryType::BOOT_SERVICES_DATA) };

    let ptr = DATA_CONTAINER.as_ptr();
    logt!("shared data: {:x}", ptr as u64);
    let mut hvcall = HvCall::new();
    hvcall.initialize();



    // let h = read_idtr(&mut hvcall);
    // set_int_handler(h, 0x30);
    // call_interrupt_handler();


    println!("UEFI vendor = {}", system::firmware_vendor());
    println!("UEFI revision = {:x}", system::firmware_revision());

    logt!("Hypercall test");

    logt!("enabling VTL1..");
    let result = hvcall.enable_partition_vtl(hvdef::HV_PARTITION_ID_SELF, Vtl::Vtl1);

    if let Ok(_) = result {
        logt!("VTL1 enabled successfully for the partition!");
    } else {
        logt!("Failed to enable VTL!");
        logt!("Error: {:?}", result.err());
    }

    let register_value = hvcall.get_register(HvX64RegisterName::VsmPartitionStatus.into(), None);

    if register_value.is_err() {
        logt!("Failed to get register value!");
        logt!("Error: {:?}", register_value.err());
    }

    let register_value: HvRegisterVsmPartitionStatus = register_value.unwrap().as_u64().into();
    logt!("Register value: {:?}", register_value);

    // AP Bringup

    // let vp_ctx = unsafe {run_fn_with_current_context(ap_write)}.expect("Failed to run function with current context");
    // let r = hvcall.start_virtual_processor(1, Vtl::Vtl0, Some(vp_ctx));
    // if let Ok(_) = r {
    //       logt!("VTL0 AP1 enabled successfully!");
    // } else {
    //       logt!("Failed to enable VTL0!");
    //       logt!("Error: {:?}", r.err());
    // }

    // get vp context

    let mut chn = register_command_queue(0, Vtl::Vtl1);
    
    // .send(Box::new(|| {
    //     logt!("Hello from VTL1!");
    // }));
    let mut vp_context: InitialVpContextX64 =
        run_fn_with_current_context(exec_handler,&mut hvcall)
        .expect("Failed to get VTL0 context");

    logt!("VP Context: {:?}", vp_context);
    let r = hvcall.enable_vp_vtl(0, Vtl::Vtl1, Some(vp_context));

    if let Ok(_) = r {
        logt!("VTL1 enabled successfully!");
    } else {
        logt!("Failed to enable VTL1!");
        logt!("Error: {:?}", r.err());
    }

    unsafe {
        let m = MUTEX_1.lock();
        HvCall::high_vtl();
    }
    unsafe  {
        logt!("Reached VTL0!");
        let heapx = *HEAPX.borrow();
        let val = *(heapx.add(10));
        logt!("HEAPX: {:?}", val);
        tmk_assert!(val != 0xAA);
    }

    logt!("VTL1 started!");
    // unallocate_interrupt_stack();
    Status::SUCCESS
}
