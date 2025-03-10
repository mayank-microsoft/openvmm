// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#[no_std]
mod slog;
mod hypercall;
mod single_threaded;
mod alloc;
mod rt;

use crate::slog;
use crate::uefi::alloc::{ALLOCATOR};
use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;
use alloc::SIZE_1MB;
use hvdef::hypercall::InitialVpContextX64;
use hvdef::{HvRegisterVsmPartitionStatus, HvX64RegisterName, HvX64SegmentRegister, Vtl};
use hypercall::hvcall;
use minimal_rt::arch::InstrIoAccess;
use minimal_rt::arch::Serial;
use single_threaded::SingleThreaded;
use uefi::allocator::Allocator;
use uefi::{boot, guid, CStr16};
use uefi::boot::exit_boot_services;
use uefi::boot::AllocateType;
use uefi::boot::MemoryType;
use uefi::entry;
use uefi::println;
use uefi::system;
use uefi::Status;
use zerocopy::FromZeros;

#[allow(unsafe_code)]
#[no_mangle]
fn vtl1_hello_world() {
    let mut serial: Serial<InstrIoAccess> = Serial::new(InstrIoAccess {});
    slog!(serial, "Hello from VTL1!");
}



#[allow(unsafe_code)]
#[entry]
fn uefi_main() -> Status {
    let r: bool = unsafe { ALLOCATOR.init(1024) };
    let io = InstrIoAccess {};
    let mut serial = Serial::new(io);
    if r == false {
        slog!(serial, "Failed to initialize allocator!");
        println!("Failed to initialize allocator!");
        return Status::ABORTED;
    }
    let mut buf = vec![0u8; 1024];
    let mut str_buff = vec![0u16; 1024];
    let os_loader_indications_key = CStr16::from_str_with_buf(&"OsLoaderIndications", str_buff.as_mut_slice()).unwrap();
    slog!(serial, "OsLoaderIndications key: {:?}", os_loader_indications_key);
    let os_loader_indications_result = 
        uefi::runtime::get_variable(
            os_loader_indications_key, 
            &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")), buf.as_mut())
            .expect("Failed to get OsLoaderIndications");

    slog!(serial, "OsLoaderIndications: {:?}", os_loader_indications_result.0);
    slog!(serial, "OsLoaderIndications size: {:?}", os_loader_indications_result.1);


    let mut os_loader_indications = u32::from_le_bytes(os_loader_indications_result.0[0..4].try_into().expect("error in output"));
    os_loader_indications |= 0x1u32;


    let mut os_loader_indications = os_loader_indications.to_le_bytes();

    slog!(serial, "OsLoaderIndications: {:?}", os_loader_indications);

    let _ = uefi::runtime::set_variable(
        os_loader_indications_key, 
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")), 
        os_loader_indications_result.1, 
        &os_loader_indications
    ).expect("Failed to set OsLoaderIndications");
    
    let os_loader_indications_result = 
    uefi::runtime::get_variable(
        os_loader_indications_key, 
        &uefi::runtime::VariableVendor(guid!("610b9e98-c6f6-47f8-8b47-2d2da0d52a91")), buf.as_mut())
        .expect("Failed to get OsLoaderIndications");

    
    slog!(serial, "[SET] OsLoaderIndications: {:?}", os_loader_indications_result.0);

    
    let _ = unsafe { exit_boot_services(MemoryType::BOOT_SERVICES_DATA) };

    hvcall().initialize();
    

    println!("UEFI vendor = {}", system::firmware_vendor());
    println!("UEFI revision = {:x}", system::firmware_revision());

    slog!(serial, "Hypercall test");


    slog!(serial, "enabling VTL1..");
    let result = 
        hvcall()
            .enable_partition_vtl(hvdef::HV_PARTITION_ID_SELF, Vtl::Vtl1);

    if let Ok(_) = result {
        slog!(serial, "VTL1 enabled successfully for the partition!");
    } else {
        slog!(serial, "Failed to enable VTL!");
        slog!(serial, "Error: {:?}", result.err());
    }

    
    let register_value = hvcall().get_register(HvX64RegisterName::VsmPartitionStatus.into());

    if register_value.is_err() {
        slog!(serial,"Failed to get register value!");
        slog!(serial,"Error: {:?}", register_value.err());
    }

    let register_value : HvRegisterVsmPartitionStatus = register_value.unwrap().as_u64().into();
    slog!(serial, "Register value: {:?}", register_value);


    // get vp context 

    let mut vp_context: InitialVpContextX64 = hvcall().get_current_vtl_vp_context().expect("Failed to get VTL1 context");

    // let cs = hvcall().get_register(HvX64RegisterName::Cs.into()).expect("Failed to get CS");
    // slog!(serial, "VP CS as int {:?}", cs);
    let stack_layout = Layout::from_size_align(SIZE_1MB, 16).expect("Failed to create layout for stack allocation");
    let x = unsafe { ALLOCATOR.alloc(stack_layout) };
    if x.is_null() {
        slog!(serial, "Failed to allocate stack!");
        return Status::ABORTED;
    }

    let sz = stack_layout.size();

    let stack_top = x as u64 + sz as u64;



    let fn_ptr = vtl1_hello_world as fn();
    let fn_address = fn_ptr as u64;
    // vp_context.msr_cr_pat = 0x277u64;
    vp_context.rip = fn_address;
    vp_context.rsp = stack_top;


    slog!(serial, "VP Context: {:?}", vp_context);

    let r = hvcall().enable_vp_vtl(0, Vtl::Vtl1, Some(vp_context));

    if let Ok(_) = r {
        slog!(serial, "VTL1 enabled successfully!");
    } else {
        slog!(serial, "Failed to enable VTL1!");
        slog!(serial, "Error: {:?}", r.err());
    }

    slog!(serial, "[NEW] VTL1 context: {:?}", vp_context);

    let r = hvcall().high_vtl();
    if let Ok(_) = r {
        slog!(serial, "VTL1 started successfully!");
    } else {
        slog!(serial, "Failed to start VTL1!");
        slog!(serial, "Error: {:?}", r.err());
    }

    slog!(serial, "VTL1 started!");
    hvcall().uninitialize();

    Status::SUCCESS
}
