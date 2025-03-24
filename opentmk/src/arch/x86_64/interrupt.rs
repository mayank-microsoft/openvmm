use core::{arch::{asm, naked_asm}, cell::RefCell};

use alloc::vec::Vec;
use bitfield_struct::bitfield;
use crate::{infolog, uefi::{hypercall::HvCall, init::interrupt_rsp_ptr}};


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

#[allow(non_upper_case_globals)]
static mut copy_srp : [u8; 4096] = [0; 4096];

fn call_action() {
    infolog!("Interrupt called!\n");
}

fn dispatch() {
    unsafe { 
        asm!(r#"
        mov rsp, {rsp}
        "#, rsp = in(reg) interrupt_rsp_ptr)
    };
    
    call_action();
}

#[allow(non_upper_case_globals)]
static mut copy_rsp : u64 = 0;

// #[naked]
// fn dispatch() {
//     unsafe { 
//         naked_asm!(r#"
//         mov qword ptr [{cpy}], rsp
//         mov rsp, [{rsp}]
//         call {fnx}
//         mov rsp, qword ptr [{cpy}]
//         "#, rsp = sym interrupt_rsp_ptr, fnx = sym call_action, cpy = sym copy_rsp);
//     }
// }

#[naked]
fn interrupt_handler() {
    unsafe { naked_asm!(r#"
        // mov qword ptr [{cpy}], rsp
        call {fnc}
        // mov rsp, qword ptr [{cpy}]
        iretq
    "#,fnc = sym call_action, cpy = sym copy_rsp) };
}

// Segment Sector Register
#[bitfield(u16)]
pub struct SegmentSelector {
    #[bits(2)]
    pub rpl: u8,
    #[bits(1)]
    pub ti: u8,
    #[bits(13)]
    pub index: u16
}

pub fn read_idtr(hvcall: &mut HvCall) -> Vec<*mut InterruptDescriptor64> {

    // // set up TSS for IST1

    // let tss = hvcall.get_register(hvdef::HvX64RegisterName::Tr.into(), None).expect("Failed to get TSS");
    // let tss = tss.as_u16();
    // // let tr = SegmentSelector::from_bits(tss);
    // infolog!("TSS: {:?}", tss);

    let rss = hvcall.get_register(hvdef::HvX64RegisterName::Gdtr.into(), None);
    

    let idtr: hvdef::HvRegisterValue = hvcall.get_register(hvdef::HvX64RegisterName::Idtr.into(), None).expect("Failed to get IDTR");
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


pub fn set_int_handler(idt : Vec<*mut InterruptDescriptor64>, interrupt_idx: u8) {
    let idt_entry = idt[interrupt_idx as usize];
    let idt_entry = unsafe { &mut *idt_entry };
    let handler = interrupt_handler as u64;
    idt_entry.offset_high = (handler >> 32) as u32;
    idt_entry.offset_mid = ((handler >> 16) & 0b1111111111111111) as u16;
    idt_entry.offset_low = (handler & 0b1111111111111111) as u16;
    idt_entry.type_attr |= 0b1110;
    // idt_entry.ist = 1;
    unsafe  {
        asm!("sti");
    }
}

