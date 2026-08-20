// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kexec stub: a minimal bare-metal program that receives control via kexec,
//! unpacks a vmlinux kernel from a packed blob embedded in the bzImage kernel
//! file, copies its PT_LOAD segments to their target physical addresses, builds
//! new boot_params, and jumps to the kernel entry point.
//!
//! This stub is wrapped in a bzImage header by `kexec_prepare.rs` so that the
//! kernel's `kexec_file_load` bzImage64 handler can load it. The handler sets
//! up boot_params (with e820, cmdline, and DTB setup_data preserved from the
//! current kernel) and arranges for the purgatory to jump to offset 0x200
//! within the protected-mode kernel section, with RSI = boot_params pointer.
//!
//! The packed blob is embedded directly in the PM kernel file (after the stub
//! binary + BSS padding) so that it resides in VTL2 memory alongside the stub
//! code. The bzImage header's `payload_offset` and `payload_length` fields
//! tell the stub where to find it.
//!
//! ## Pack format (embedded in PM kernel)
//!
//! ```text
//! Offset  Size  Field
//! 0       8     Magic: "KXSTUB\x01\x00"
//! 8       8     vmlinux_size (u64 LE)
//! 16      8     initrd_size (u64 LE)
//! 24      V     vmlinux ELF data
//! 24+V    I     real initrd data (compressed cpio)
//! ```

#![cfg_attr(minimal_rt, no_std, no_main)]
// UNSAFETY: Bare-metal code interacting with physical memory and hardware.
#![expect(unsafe_code)]

#[cfg(target_arch = "x86_64")]
mod arch;
mod boot_params;
mod elf;
mod rt;

use boot_params::BootParams;

/// Magic bytes at the start of the packed blob.
const PACK_MAGIC: &[u8; 8] = b"KXSTUB\x01\x00";

/// Size of the pack header (magic + vmlinux_size + initrd_size).
const PACK_HEADER_SIZE: usize = 24;

/// Storage for the new boot_params. Must be static because the kernel reads
/// it during early boot, long after the stub's stack frame is gone.
#[cfg(minimal_rt)]
static mut NEW_BOOT_PARAMS: BootParams =
    // SAFETY: BootParams is all-zero-valid (it's a C struct of integers and
    // arrays). Zero-initialization produces a valid instance.
    unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

#[cfg(not(minimal_rt))]
fn main() {}

/// Main entry point for the kexec stub.
///
/// Called from `rt::start()` with the physical address of boot_params
/// (passed in RSI by the kexec purgatory).
#[cfg_attr(not(minimal_rt), expect(unused_variables))]
fn stub_main(boot_params_ptr: usize) -> ! {
    #[cfg(minimal_rt)]
    {

        // 1. Parse inherited boot_params (set up by kexec bzImage64 handler).
        // Contains e820, cmdline, and DTB in setup_data chain.
        // SAFETY: boot_params_ptr is a valid physical address provided by the
        // kexec purgatory. Identity mapping is active.
        let boot_params = unsafe {
            &*(boot_params_ptr as *const BootParams)
        };

        // 2. Find the packed blob (embedded in the PM kernel by kexec_prepare.rs).
        // The pack offset and size are patched into the stub binary header
        // by kexec_prepare.rs at fixed offsets: _start+8 and _start+16.
        unsafe extern "C" {
            static _start: u8;
            static pack_offset: u64;
            static pack_size: u64;
        }
        // _start is defined in entry.S and its address is fixed up by
        // self-relocation. It gives us the runtime base of the stub code.
        let start_addr = core::ptr::addr_of!(_start) as usize;
        // _start is at kernel_load_addr + 0x200 (after the startup_32 padding).
        let kernel_load_addr = start_addr - 0x200;

        // SAFETY: pack_offset and pack_size are in .text.entry, not in BSS,
        // so they survive the BSS zeroing. They were patched by kexec_prepare.rs
        // into the flat binary before it was wrapped in the bzImage.
        let payload_offset = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(pack_offset)) } as usize;
        let payload_length = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(pack_size)) } as usize;

        assert!(
            payload_length >= PACK_HEADER_SIZE,
            "packed blob too small for header"
        );

        let pack_addr = kernel_load_addr + payload_offset;

        // SAFETY: pack_addr is within the PM kernel memory region loaded by
        // kexec into VTL2 memory. Identity mapping makes it accessible.
        let pack = unsafe {
            core::slice::from_raw_parts(pack_addr as *const u8, payload_length)
        };

        // 3. Validate and parse the pack header.
        assert!(
            &pack[0..8] == PACK_MAGIC,
            "invalid pack magic"
        );

        let vmlinux_size = u64::from_le_bytes(pack[8..16].try_into().unwrap()) as usize;
        let initrd_size = u64::from_le_bytes(pack[16..24].try_into().unwrap()) as usize;

        assert!(
            PACK_HEADER_SIZE + vmlinux_size + initrd_size <= pack.len(),
            "pack header sizes exceed blob"
        );

        let vmlinux_data = &pack[PACK_HEADER_SIZE..PACK_HEADER_SIZE + vmlinux_size];
        // Page-align the initrd address. The kernel's free_initrd_mem expects
        // page-aligned addresses. Padding between vmlinux and initrd was added
        // by kexec_prepare.rs.
        let initrd_offset = (PACK_HEADER_SIZE + vmlinux_size + 0xFFF) & !0xFFF;
        let initrd_phys = pack_addr as u64 + initrd_offset as u64;

        // 4. Parse vmlinux ELF — extract PT_LOAD segments and entry point.
        let elf_info = elf::parse_elf64(vmlinux_data);

        // 5. Copy PT_LOAD segments to their target physical addresses.
        // After kexec, the old kernel is gone — all physical memory is available
        // (except persisted state and the regions containing the stub, packed
        // blob, and boot_params).
        for i in 0..elf_info.num_segments {
            let seg = &elf_info.segments[i];

            // SAFETY: The segment source is within the vmlinux ELF data (in the
            // packed blob). The target physical address is from the ELF's p_paddr.
            // After kexec, this memory is free. Identity mapping makes both
            // source and destination accessible.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vmlinux_data.as_ptr().add(seg.file_offset),
                    seg.phys_addr as *mut u8,
                    seg.file_size,
                );

                // Zero the BSS portion (mem_size > file_size).
                if seg.mem_size > seg.file_size {
                    core::ptr::write_bytes(
                        (seg.phys_addr + seg.file_size as u64) as *mut u8,
                        0,
                        seg.mem_size - seg.file_size,
                    );
                }
            }
        }

        // 6. Build new boot_params for the target kernel.
        // Start with a copy of the inherited boot_params — this preserves:
        //   - e820 memory map
        //   - command line pointer
        //   - setup_data chain (including DTB, preserved by OHCL kexec handler)
        // SAFETY: Writing to a static. No other code runs concurrently.
        let new_bp = unsafe {
            let ptr = &raw mut NEW_BOOT_PARAMS;
            core::ptr::copy_nonoverlapping(
                boot_params as *const BootParams,
                ptr,
                1,
            );
            &mut *ptr
        };

        // Update ramdisk pointer to the real initrd (within the packed blob,
        // after the vmlinux data).
        new_bp.set_ramdisk_addr(initrd_phys);
        new_bp.set_ramdisk_size(initrd_size as u64);

        // Set hardware_subarch = 1 (LGUEST hack from openhcl_boot) to disable
        // probe_roms and reserve_bios_regions, preventing the kernel from
        // reading VTL0 memory during boot.
        new_bp.set_hardware_subarch(1);

        // Set loader type (unknown).
        new_bp.set_type_of_loader(0xff);

        // Add the vmlinux physical range as an e820 RAM entry. The kernel's
        // .text/.data/.bss must be in e820 RAM for free_initmem() to work
        // correctly. Without this, the kernel warns ".text .data .bss are not
        // marked as E820_TYPE_RAM!" and free_initmem() hangs trying to free
        // __init pages that aren't tracked by memblock.
        let kernel_phys_start = elf_info.segments[0].phys_addr;
        let mut kernel_phys_end = kernel_phys_start;
        for i in 0..elf_info.num_segments {
            let seg = &elf_info.segments[i];
            let seg_end = seg.phys_addr + seg.mem_size as u64;
            if seg_end > kernel_phys_end {
                kernel_phys_end = seg_end;
            }
        }
        let kernel_range_size = kernel_phys_end - kernel_phys_start;
        new_bp.add_e820_entry(
            kernel_phys_start,
            kernel_range_size,
            boot_params::E820_TYPE_RAM,
        );

        // Verify stack cookie before jumping.
        rt::verify_stack_cookie();

        // 7. Jump to the vmlinux entry point.
        // Standard x86_64 Linux 64-bit boot protocol:
        //   RDI = 0
        //   RSI = pointer to boot_params
        // SAFETY: entry point is from the vmlinux ELF header.
        // boot_params is valid and identity-mapped.
        let kernel_entry: extern "C" fn(u64, &BootParams) -> ! =
            unsafe { core::mem::transmute(elf_info.entry) };
        kernel_entry(0, new_bp)
    }

    #[cfg(not(minimal_rt))]
    loop {}
}
