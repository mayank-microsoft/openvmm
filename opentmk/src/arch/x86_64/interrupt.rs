use core::{
    arch::{asm, global_asm, naked_asm},
    cell::RefCell,
};

use crate::{
    infolog,
    uefi::{hypercall::HvCall, init::interrupt_rsp_ptr},
};
use alloc::vec::Vec;
use bitfield_struct::bitfield;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptDescriptor64 {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

fn call_action() {
    infolog!("Interrupt called!\n");
}

// global_asm!(r#"
//     section .data
//     .global gpr_values
//     gpr_values: 
//         times 16 dq 0 
//     .global xmm_values
//     xmm_values: 
//         times 32 dq 0
// "#);

#[no_mangle]
static mut gpr_values: [u64; 16] = [0; 16];

#[no_mangle]
static mut xmm_values: [u128; 16] = [0; 16];


#[naked]
fn interrupt_handler() {
    unsafe {
        naked_asm!(r#"
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push rsp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    sub rsp, 256  
    movups [rsp + 16 * 0], xmm0
    movups [rsp + 16 * 1], xmm1
    movups [rsp + 16 * 2], xmm2
    movups [rsp + 16 * 3], xmm3
    movups [rsp + 16 * 4], xmm4
    movups [rsp + 16 * 5], xmm5
    movups [rsp + 16 * 6], xmm6
    movups [rsp + 16 * 7], xmm7
    movups [rsp + 16 * 8], xmm8
    movups [rsp + 16 * 9], xmm9
    movups [rsp + 16 * 10], xmm10
    movups [rsp + 16 * 11], xmm11
    movups [rsp + 16 * 12], xmm12
    movups [rsp + 16 * 13], xmm13
    movups [rsp + 16 * 14], xmm14
    movups [rsp + 16 * 15], xmm15
    
    call {fnc}

    movups xmm0, [rsp + 16 * 0]
    movups xmm1, [rsp + 16 * 1]
    movups xmm2, [rsp + 16 * 2]
    movups xmm3, [rsp + 16 * 3]
    movups xmm4, [rsp + 16 * 4]
    movups xmm5, [rsp + 16 * 5]
    movups xmm6, [rsp + 16 * 6]
    movups xmm7, [rsp + 16 * 7]
    movups xmm8, [rsp + 16 * 8]
    movups xmm9, [rsp + 16 * 9]
    movups xmm10, [rsp + 16 * 10]
    movups xmm11, [rsp + 16 * 11]
    movups xmm12, [rsp + 16 * 12]
    movups xmm13, [rsp + 16 * 13]
    movups xmm14, [rsp + 16 * 14]
    movups xmm15, [rsp + 16 * 15]
    add rsp, 16 * 16  

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsp
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

        iretq
    "#,fnc = sym call_action);
    };
}

// Segment Sector Register
#[bitfield(u16)]
pub struct SegmentSelector {
    #[bits(2)]
    pub rpl: u8,
    #[bits(1)]
    pub ti: u8,
    #[bits(13)]
    pub index: u16,
}

pub fn read_idtr(hvcall: &mut HvCall) -> Vec<*mut InterruptDescriptor64> {
    // // set up TSS for IST1

    // let tss = hvcall.get_register(hvdef::HvX64RegisterName::Tr.into(), None).expect("Failed to get TSS");
    // let tss = tss.as_u16();
    // // let tr = SegmentSelector::from_bits(tss);
    // infolog!("TSS: {:?}", tss);

    let rss = hvcall.get_register(hvdef::HvX64RegisterName::Gdtr.into(), None);

    let idtr: hvdef::HvRegisterValue = hvcall
        .get_register(hvdef::HvX64RegisterName::Idtr.into(), None)
        .expect("Failed to get IDTR");
    let idtr = hvdef::HvX64TableRegister::from(idtr);

    let idtr_base = idtr.base;
    let idtr_limit = idtr.limit;
    let idtr_end = idtr_base + idtr_limit as u64;

    let mut result = Vec::new();
    let mut idtr_seek = idtr_base;
    let mut count = 0;
    loop {
        if idtr_seek >= idtr_end {
            break;
        }

        let idt_entry: InterruptDescriptor64 = unsafe { core::ptr::read(idtr_seek as *const _) };
        result.push(idtr_seek as *mut InterruptDescriptor64);
        idtr_seek += core::mem::size_of::<InterruptDescriptor64>() as u64;
        count += 1;
    }
    result
}

#[no_mangle]
fn call_interrupt_handler() {
    unsafe { asm!("int 30H") };
}

pub fn set_int_handler(idt: Vec<*mut InterruptDescriptor64>, interrupt_idx: u8) {
    let idt_entry = idt[interrupt_idx as usize];
    let idt_entry = unsafe { &mut *idt_entry };
    let handler = interrupt_handler as u64;
    idt_entry.offset_high = (handler >> 32) as u32;
    idt_entry.offset_mid = ((handler >> 16) & 0b1111111111111111) as u16;
    idt_entry.offset_low = (handler & 0b1111111111111111) as u16;
    idt_entry.type_attr |= 0b1110;
    // idt_entry.ist = 1;
    unsafe {
        asm!("sti");
    }
}
