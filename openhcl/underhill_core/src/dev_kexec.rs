// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kexec segment preparation for the dev servicing flow.
//!
//! This module constructs the memory segments required by the Linux
//! `kexec_load` syscall to boot a new kernel from the currently running
//! OpenHCL instance. It mirrors the boot parameter setup performed by
//! `openhcl_boot` so that the newly kexec'd kernel receives the same
//! environment the original boot shim would have provided.
//!
//! # Segment layout
//!
//! ## x86_64
//! 1. **Trampoline** — small machine-code stub that loads RSI with the
//!    boot_params physical address, clears RDI, and jumps to the real
//!    kernel entry point. This is the kexec entry point.
//! 2. **Kernel ELF segments** — individual PT_LOAD segments from the vmlinux
//!    ELF binary, each loaded at its `p_paddr` (physical address). BSS
//!    regions (where `p_memsz > p_filesz`) are zero-filled.
//! 3. **boot_params** — 4096-byte Linux zero page with e820 map, initrd
//!    pointer, command line pointer, and `setup_data` chain head.
//! 4. **Initrd** — compressed initramfs image.
//! 5. **Device tree** — FDT blob wrapped in a `setup_data` header (type
//!    `SETUP_DTB`), chained from `boot_params.hdr.setup_data`.
//! 6. **Command line** — null-terminated kernel command line string.
//!
//! ## aarch64
//! 1. **Trampoline** — small machine-code stub that loads x0 with the FDT
//!    physical address, clears x1–x3, and branches to the real kernel
//!    entry point. This is the kexec entry point.
//! 2. **Kernel** — raw kernel Image bytes.
//! 3. **Initrd** — compressed initramfs image.
//! 4. **Device tree** — FDT blob containing `/chosen` node with `bootargs`,
//!    `linux,initrd-start`, and `linux,initrd-end`.

use crate::vmlinux_parser::VmlinuxInfo;
use anyhow::Context;
use bootloader_fdt_parser::ParsedBootDtInfo;
use diag_server::DevServicingData;
use kexec_sys::KexecSegment;

/// Size of the device tree buffer. The Linux kernel requires the FDT to fit
/// within a single 256KB mapping during early boot.
const FDT_SIZE: usize = 256 * 1024;

const PAGE_SIZE: u64 = 4096;

/// FDT buffer with a `setup_data` header prepended, matching the layout
/// used by `openhcl_boot`. On x86_64 the FDT is chained via the
/// `boot_params.hdr.setup_data` pointer as a `SETUP_DTB` node.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
struct Fdt {
    header: loader_defs::linux::setup_data,
    data: [u8; FDT_SIZE - size_of::<loader_defs::linux::setup_data>()],
}

/// Align `addr` up to the given power-of-two `alignment`.
fn align_up(addr: u64, alignment: u64) -> u64 {
    (addr + alignment - 1) & !(alignment - 1)
}

/// Build an x86_64 trampoline code stub.
///
/// After kexec's `relocate_kernel` runs, the CPU is in 64-bit long mode
/// with identity-mapped paging, but many control/debug/segment registers
/// may still carry stale state from the old kernel. This trampoline
/// provides the new kernel with a clean environment matching what
/// `startup_64` expects.
///
/// The generated machine code performs the following:
/// ```text
///   ; --- Phase 1: Diagnostic output ---
///   ;   Emit "KEXEC\r\n" to COM3 (I/O 0x3E8) so we can confirm entry
///   ;   even if later phases crash. (see emit_serial_char)
///
///   ; --- Phase 2: CPU state cleanup ---
///   cli                        ; disable maskable interrupts
///   cld                        ; clear direction flag
///   mov  al, 0x80
///   out  0x70, al              ; disable NMI via CMOS port
///
///   mov  eax, 0x20             ; CR4 = PAE only (bit 5)
///   mov  cr4, rax              ; clears SMEP/SMAP/UMIP/PCIDE/…
///   mov  eax, 0x80010033       ; CR0 = PG|WP|NE|ET|MP|PE
///   mov  cr0, rax              ; clears CD/NW
///   mov  rax, cr3
///   mov  cr3, rax              ; flush TLB
///
///   xor  eax, eax              ; zero for debug + segment regs
///   mov  dr0, rax              ; clear hardware breakpoints
///   mov  dr1, rax
///   mov  dr2, rax
///   mov  dr3, rax
///   mov  dr6, rax              ; clear debug status
///   mov  dr7, rax              ; disable all hw breakpoints
///
///   mov  ds, ax                ; null-out data segments
///   mov  es, ax
///   mov  ss, ax
///   mov  fs, ax
///   mov  gs, ax
///
///   ; --- Phase 3: Clear general-purpose registers ---
///   xor  ecx/edx/ebx/ebp/esp, ...   ; zero all GPRs
///   xor  r8d..r15d, ...
///
///   ; --- Phase 4: Boot protocol setup + jump ---
///   xor  edi, edi              ; RDI = 0
///   mov  rsi, <boot_params>    ; RSI = boot_params phys addr
///   mov  rax, <entry_point>    ; kernel entry point
///   jmp  rax
/// ```
///
/// The COM3 output provides early evidence that the trampoline executed,
/// visible via `ohcldiag-dev` serial or the Hyper-V COM3 pipe.
///
/// The Linux 64-bit boot protocol expects:
/// - RSI → pointer to the `boot_params` (zero page)
/// - RDI → 0
///
/// Returns the raw machine code bytes.
#[cfg(target_arch = "x86_64")]
fn build_x86_64_trampoline(boot_params_phys: u64, kernel_entry: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(256);

    // Helper: emit instructions to write one character to COM3 with
    // busy-wait on the transmit holding register.
    //
    // For each character the sequence is:
    //   mov dx, 0x3ED        ; LSR (COM3 + 5)
    //   .wait:
    //   in  al, dx           ; read LSR
    //   test al, 0x20        ; THRE bit set?
    //   jz  .wait            ; no → spin
    //   mov dx, 0x3E8        ; COM3 data register
    //   mov al, <char>
    //   out dx, al
    fn emit_serial_char(code: &mut Vec<u8>, ch: u8) {
        // mov dx, 0x3ED  =>  66 BA ED 03
        code.extend_from_slice(&[0x66, 0xBA, 0xED, 0x03]);

        // .wait:  (offset of 'in al, dx')
        // in al, dx  =>  EC
        code.push(0xEC);

        // test al, 0x20  =>  A8 20
        code.extend_from_slice(&[0xA8, 0x20]);

        // jz .wait  (jump back 4 bytes: offset = -4 = 0xFC)
        //   jz rel8  =>  74 FC
        code.extend_from_slice(&[0x74, 0xFC]);

        // mov dx, 0x3E8  =>  66 BA E8 03
        code.extend_from_slice(&[0x66, 0xBA, 0xE8, 0x03]);

        // mov al, <ch>  =>  B0 <ch>
        code.extend_from_slice(&[0xB0, ch]);

        // out dx, al  =>  EE
        code.push(0xEE);
    }

    // ---- Phase 1: Diagnostic output ----------------------------------------
    //
    // Emit "KEXEC\r\n" to COM3 so we can confirm the trampoline ran, even
    // if the CPU state cleanup below triggers a fault.
    for &ch in b"KEXEC\r\n" {
        emit_serial_char(&mut code, ch);
    }

    // ---- Phase 2: CPU state cleanup ----------------------------------------
    //
    // The old kernel's machine_kexec copied our segments to their final
    // physical addresses and jumped here with identity-mapped paging, but
    // the control registers, debug registers, and segment selectors may
    // still carry the old kernel's configuration. We reset everything to
    // the minimal state that Linux startup_64 expects.

    // cli — disable maskable interrupts
    code.push(0xFA);

    // cld — clear direction flag
    code.push(0xFC);

    // Disable NMI by setting bit 7 of CMOS address port.
    //   mov al, 0x80  =>  B0 80
    //   out 0x70, al  =>  E6 70
    code.extend_from_slice(&[0xB0, 0x80, 0xE6, 0x70]);

    // Set CR4 = PAE only (bit 5 = 0x20).
    // This clears SMEP, SMAP, UMIP, PCIDE, OSXSAVE, OSFXSR, etc.
    // The kernel will re-enable features it needs.
    //   mov eax, 0x20      =>  B8 20 00 00 00
    //   mov cr4, rax       =>  0F 22 E0
    code.extend_from_slice(&[0xB8, 0x20, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0x0F, 0x22, 0xE0]);

    // Set CR0 = PG | WP | NE | ET | MP | PE.
    //   PG  = bit 31 = 0x80000000
    //   WP  = bit 16 = 0x00010000
    //   NE  = bit  5 = 0x00000020
    //   ET  = bit  4 = 0x00000010
    //   MP  = bit  1 = 0x00000002
    //   PE  = bit  0 = 0x00000001
    //   Total        = 0x80010033
    // This clears CD (cache disable) and NW (not write-through).
    //   mov eax, 0x80010033  =>  B8 33 00 01 80
    //   mov cr0, rax         =>  0F 22 C0
    code.extend_from_slice(&[0xB8, 0x33, 0x00, 0x01, 0x80]);
    code.extend_from_slice(&[0x0F, 0x22, 0xC0]);

    // Flush TLB by reloading CR3 (the identity-map page table base set
    // up by kexec's relocate_kernel).
    //   mov rax, cr3   =>  0F 20 D8
    //   mov cr3, rax   =>  0F 22 D8
    code.extend_from_slice(&[0x0F, 0x20, 0xD8]);
    code.extend_from_slice(&[0x0F, 0x22, 0xD8]);

    // Clear all debug registers to remove stale hardware breakpoints and
    // watchpoints from the old kernel.
    //   xor eax, eax  =>  31 C0
    code.extend_from_slice(&[0x31, 0xC0]);
    //   mov dr0, rax  =>  0F 23 C0
    code.extend_from_slice(&[0x0F, 0x23, 0xC0]);
    //   mov dr1, rax  =>  0F 23 C8
    code.extend_from_slice(&[0x0F, 0x23, 0xC8]);
    //   mov dr2, rax  =>  0F 23 D0
    code.extend_from_slice(&[0x0F, 0x23, 0xD0]);
    //   mov dr3, rax  =>  0F 23 D8
    code.extend_from_slice(&[0x0F, 0x23, 0xD8]);
    //   mov dr6, rax  =>  0F 23 F0   (clear debug status)
    code.extend_from_slice(&[0x0F, 0x23, 0xF0]);
    //   mov dr7, rax  =>  0F 23 F8   (disable all breakpoints)
    code.extend_from_slice(&[0x0F, 0x23, 0xF8]);

    // Null out data segment selectors. In 64-bit long mode null selectors
    // are valid for DS/ES/SS/FS/GS. The kernel will load its own GDT and
    // selectors during early init.
    //   xor eax, eax  =>  31 C0
    code.extend_from_slice(&[0x31, 0xC0]);
    //   mov ds, ax    =>  8E D8
    code.extend_from_slice(&[0x8E, 0xD8]);
    //   mov es, ax    =>  8E C0
    code.extend_from_slice(&[0x8E, 0xC0]);
    //   mov ss, ax    =>  8E D0
    code.extend_from_slice(&[0x8E, 0xD0]);
    //   mov fs, ax    =>  8E E0
    code.extend_from_slice(&[0x8E, 0xE0]);
    //   mov gs, ax    =>  8E E8
    code.extend_from_slice(&[0x8E, 0xE8]);

    // ---- Phase 3: Clear general-purpose registers --------------------------
    //
    // Zero all GPRs so the kernel doesn't see stale values from the old
    // kernel's context. RSI and RDI are set in phase 4.

    //   xor ecx, ecx  =>  31 C9
    code.extend_from_slice(&[0x31, 0xC9]);
    //   xor edx, edx  =>  31 D2
    code.extend_from_slice(&[0x31, 0xD2]);
    //   xor ebx, ebx  =>  31 DB
    code.extend_from_slice(&[0x31, 0xDB]);
    //   xor ebp, ebp  =>  31 ED
    code.extend_from_slice(&[0x31, 0xED]);
    //   xor esp, esp  =>  31 E4   (kernel sets up its own stack)
    code.extend_from_slice(&[0x31, 0xE4]);

    //   xor r8d,  r8d   =>  45 31 C0
    code.extend_from_slice(&[0x45, 0x31, 0xC0]);
    //   xor r9d,  r9d   =>  45 31 C9
    code.extend_from_slice(&[0x45, 0x31, 0xC9]);
    //   xor r10d, r10d  =>  45 31 D2
    code.extend_from_slice(&[0x45, 0x31, 0xD2]);
    //   xor r11d, r11d  =>  45 31 DB
    code.extend_from_slice(&[0x45, 0x31, 0xDB]);
    //   xor r12d, r12d  =>  45 31 E4
    code.extend_from_slice(&[0x45, 0x31, 0xE4]);
    //   xor r13d, r13d  =>  45 31 ED
    code.extend_from_slice(&[0x45, 0x31, 0xED]);
    //   xor r14d, r14d  =>  45 31 F6
    code.extend_from_slice(&[0x45, 0x31, 0xF6]);
    //   xor r15d, r15d  =>  45 31 FF
    code.extend_from_slice(&[0x45, 0x31, 0xFF]);

    emit_serial_char(&mut code, 'x' as u8); // emit 'x' to indicate CPU state cleanup is done
    emit_serial_char(&mut code, '\n' as u8);
    // ---- Phase 4: Set up boot protocol registers and jump ------------------

    // xor edi, edi  =>  31 FF
    code.extend_from_slice(&[0x31, 0xFF]);

    // movabs rsi, imm64  =>  48 BE <imm64 little-endian>
    code.push(0x48);
    code.push(0xBE);
    code.extend_from_slice(&boot_params_phys.to_le_bytes());

    // movabs rax, imm64  =>  48 B8 <imm64 little-endian>
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&kernel_entry.to_le_bytes());

    // jmp rax  =>  FF E0
    code.extend_from_slice(&[0xFF, 0xE0]);

    code
}

/// Build an aarch64 trampoline code stub.
///
/// The generated machine code performs the following:
/// ```text
///   ldr  x0, =<fdt_phys>    ; x0 = FDT physical address
///   mov  x1, #0             ; x1 = 0
///   mov  x2, #0             ; x2 = 0
///   mov  x3, #0             ; x3 = 0
///   ldr  x4, =<entry_point> ; x4 = kernel entry point
///   br   x4                 ; branch to kernel
/// ```
///
/// The Linux ARM64 boot protocol expects:
/// - x0 → pointer to the device tree blob
/// - x1, x2, x3 → 0
///
/// The 64-bit literal values are stored after the instruction stream and
/// loaded via PC-relative `ldr` instructions.
///
/// Returns the raw machine code bytes.
#[cfg(target_arch = "aarch64")]
fn build_aarch64_trampoline(fdt_phys: u64, kernel_entry: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(48);

    // The layout is:
    //   offset 0x00: ldr x0, [pc, #20]   ; load fdt_phys from offset 0x18
    //   offset 0x04: mov x1, #0
    //   offset 0x08: mov x2, #0
    //   offset 0x0C: mov x3, #0
    //   offset 0x10: ldr x4, [pc, #16]   ; load kernel_entry from offset 0x20
    //   offset 0x14: br  x4
    //   offset 0x18: <fdt_phys>           (8 bytes)
    //   offset 0x20: <kernel_entry>       (8 bytes)

    // ldr x0, [pc, #20]  =>  pc + 20 = 0x00 + 20 = 0x14... wait, let me recalculate.
    // At offset 0x00, PC = 0x00.  We want to load from offset 0x18.
    // imm19 offset = (0x18 - 0x00) / 4 = 6.  LDR Xt, label => 0x58000000 | (imm19 << 5) | Rt
    // ldr x0, #6  =>  0x58000000 | (6 << 5) | 0 = 0x580000C0
    code.extend_from_slice(&0x580000C0u32.to_le_bytes());

    // mov x1, #0  =>  0xD2800001
    code.extend_from_slice(&0xD2800001u32.to_le_bytes());

    // mov x2, #0  =>  0xD2800002
    code.extend_from_slice(&0xD2800002u32.to_le_bytes());

    // mov x3, #0  =>  0xD2800003
    code.extend_from_slice(&0xD2800003u32.to_le_bytes());

    // ldr x4, [pc, #16]  At offset 0x10, load from offset 0x20.
    // imm19 offset = (0x20 - 0x10) / 4 = 4.
    // ldr x4, #4  =>  0x58000000 | (4 << 5) | 4 = 0x58000084
    code.extend_from_slice(&0x58000084u32.to_le_bytes());

    // br x4  =>  0xD61F0080
    code.extend_from_slice(&0xD61F0080u32.to_le_bytes());

    // Data literals at offset 0x18
    code.extend_from_slice(&fdt_phys.to_le_bytes());

    // Data literal at offset 0x20
    code.extend_from_slice(&kernel_entry.to_le_bytes());

    code
}

/// Prepare kexec segments from dev servicing data and the currently running
/// system's parsed boot device tree info.
///
/// This constructs all the memory buffers and segment descriptors needed for
/// a `kexec_load(2)` syscall to boot the provided kernel and initrd with the
/// appropriate boot parameters.
///
/// # Arguments
/// * `data` — The dev servicing upload containing kernel, initrd, and
///   command line.
/// * `vmlinux_info` — Parsed information about the kernel image (entry
///   point, architecture, format).
/// * `boot_dt_info` — The parsed device tree from the current boot,
///   providing CPU topology, memory map, isolation type, etc.
///
/// # Returns
/// A tuple of `(entry_point, segments)` suitable for passing to
/// [`kexec_sys::kexec_load`].
pub fn prepare_kexec_segments(
    mut data: DevServicingData,
    vmlinux_info: &VmlinuxInfo,
    boot_dt_info: &ParsedBootDtInfo,
) -> anyhow::Result<(u64, Vec<KexecSegment>)> {
    // Append a marker so the next boot knows it came from dev servicing.
    if !data.command_line.is_empty() {
        data.command_line.push(' ');
    }
    data.command_line
        .push_str(" OPENHCL_SERVICING_COMPLETED=1");

    // Enable early console output on COM3 (I/O 0x3E8 = ttyS2) so that
    // kernel boot messages are visible via the Hyper-V COM3 pipe /
    // ohcldiag-dev serial as soon as the new kernel starts executing.
    data.command_line
        .push_str(" earlycon=uart8250,io,0x3e8,115200n8 console=ttyS2,115200n8");

    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            prepare_x86_64(data, vmlinux_info, boot_dt_info)
        } else if #[cfg(target_arch = "aarch64")] {
            prepare_aarch64(data, vmlinux_info, boot_dt_info)
        } else {
            compile_error!("unsupported architecture for kexec");
        }
    }
}

// ---- x86_64 implementation ------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn prepare_x86_64(
    data: DevServicingData,
    vmlinux_info: &VmlinuxInfo,
    boot_dt_info: &ParsedBootDtInfo,
) -> anyhow::Result<(u64, Vec<KexecSegment>)> {
    use loader_defs::linux::SETUP_DTB;
    use loader_defs::linux::setup_data;
    use zerocopy::IntoBytes;

    anyhow::ensure!(
        !vmlinux_info.segments.is_empty(),
        "ELF vmlinux has no PT_LOAD segments"
    );

    // OpenHCL runs identity-mapped (vaddr == paddr), so e_entry is already
    // the physical entry point.
    let kernel_entry_phys = vmlinux_info.entry_point;

    for seg in &vmlinux_info.segments {
        tracing::info!(
            vaddr = %format_args!("{:#x}", seg.vaddr),
            paddr = %format_args!("{:#x}", seg.paddr),
            file_offset = %format_args!("{:#x}", seg.file_offset),
            file_size = %format_args!("{:#x}", seg.file_size),
            mem_size = %format_args!("{:#x}", seg.mem_size),
            "ELF PT_LOAD segment"
        );
    }

    // -- 1. Determine physical addresses for each segment --------------------
    //
    // During kexec, the kernel copies segments to the specified physical
    // addresses. ELF LOAD segments go to their p_paddr. Other segments
    // (trampoline, initrd, FDT, boot_params, cmdline) are placed after
    // the highest ELF segment in the largest VTL2 RAM range.

    let largest_ram = boot_dt_info
        .vtl2_memory
        .iter()
        .max_by_key(|r| r.range.len())
        .context("no VTL2 memory ranges available")?;

    tracing::info!(
        range_start = %format_args!("{:#x}", largest_ram.range.start()),
        range_len = %format_args!("{:#x}", largest_ram.range.len()),
        "using VTL2 RAM range for kexec segment placement"
    );

    // Build kexec segments for each ELF PT_LOAD, loading at p_paddr.
    let mut kernel_segments = Vec::new();
    let mut highest_seg_end: u64 = 0;
    for seg in &vmlinux_info.segments {
        let seg_memsz = align_up(seg.mem_size, PAGE_SIZE) as usize;

        // Extract the segment data from the raw ELF file.
        let file_start = seg.file_offset as usize;
        let file_end = file_start + seg.file_size as usize;
        anyhow::ensure!(
            file_end <= data.vmlinux.len(),
            "ELF segment at offset {:#x} extends past end of file (file_size={:#x}, elf_size={:#x})",
            seg.file_offset,
            seg.file_size,
            data.vmlinux.len()
        );

        // Build the segment data: file contents + zero-fill for BSS.
        let mut seg_data = data.vmlinux[file_start..file_end].to_vec();
        if seg.mem_size > seg.file_size {
            seg_data.resize(seg.mem_size as usize, 0);
        }

        let seg_end = seg.paddr + seg_memsz as u64;
        if seg_end > highest_seg_end {
            highest_seg_end = seg_end;
        }

        kernel_segments.push(KexecSegment {
            data: seg_data,
            phys_addr: seg.paddr,
            mem_size: seg_memsz,
        });
    }

    // Place auxiliary segments after the kernel's highest segment.
    let mut next_addr = align_up(highest_seg_end, PAGE_SIZE);

    // Trampoline
    let trampoline_phys = next_addr;
    let trampoline_memsz = PAGE_SIZE as usize;
    next_addr += trampoline_memsz as u64;

    // Initrd
    let initrd_phys = align_up(next_addr, PAGE_SIZE);
    let initrd_size = data.initrd.len() as u64;
    let initrd_memsz = align_up(initrd_size, PAGE_SIZE) as usize;
    next_addr = initrd_phys + initrd_memsz as u64;

    // Command line (null-terminated)
    let cmdline_phys = next_addr;
    let mut cmdline_buf = data.command_line.as_bytes().to_vec();
    cmdline_buf.push(0); // null-terminate
    let cmdline_memsz = align_up(cmdline_buf.len() as u64, PAGE_SIZE) as usize;
    next_addr += cmdline_memsz as u64;

    // FDT (with setup_data header prepended)
    let fdt_phys = next_addr;
    let fdt_memsz = align_up(FDT_SIZE as u64, PAGE_SIZE) as usize;
    next_addr += fdt_memsz as u64;

    // boot_params (one page)
    let boot_params_phys = next_addr;
    let boot_params_memsz = PAGE_SIZE as usize;
    next_addr += boot_params_memsz as u64;

    // Verify everything fits in the RAM range.
    anyhow::ensure!(
        next_addr <= largest_ram.range.end(),
        "kexec segments ({:#x} bytes) exceed VTL2 RAM range (ends at {:#x})",
        next_addr - largest_ram.range.start(),
        largest_ram.range.end()
    );

    // -- 2. Build the device tree --------------------------------------------
    let mut fdt = Fdt {
        header: setup_data {
            next: 0, // no further setup_data nodes
            ty: SETUP_DTB,
            len: (FDT_SIZE - size_of::<setup_data>()) as u32,
        },
        data: [0u8; FDT_SIZE - size_of::<setup_data>()],
    };

    // Build the FDT into the data portion (after the setup_data header).
    build_device_tree(
        &mut fdt.data,
        boot_dt_info,
        initrd_phys..initrd_phys + initrd_size,
        &data.command_line,
    )
    .context("failed to build device tree for kexec")?;

    let fdt_buf = fdt.as_bytes().to_vec();

    // -- 3. Build boot_params (zero page) ------------------------------------
    let bp = build_boot_params(
        initrd_phys..initrd_phys + initrd_size,
        cmdline_phys,
        fdt_phys,
    )
    .context("failed to build boot_params")?;

    tracing::info!(boot_params = ?bp, "built boot_params with e820 map entries:");

    let boot_params_buf = bp.as_bytes().to_vec();

    // -- 4. Build the trampoline ---------------------------------------------
    //
    // The trampoline sets up the register state that the Linux 64-bit boot
    // protocol requires (RSI = &boot_params, RDI = 0) and then jumps to the
    // real kernel entry point.
    let trampoline_buf = build_x86_64_trampoline(boot_params_phys, kernel_entry_phys);

    tracing::info!(
        trampoline_phys = %format_args!("{:#x}", trampoline_phys),
        kernel_entry_phys = %format_args!("{:#x}", kernel_entry_phys),
        boot_params_phys = %format_args!("{:#x}", boot_params_phys),
        "built x86_64 trampoline"
    );

    // -- 5. Assemble segments ------------------------------------------------
    //
    // The trampoline is the first segment and its physical address is the
    // kexec entry point. Kernel ELF segments follow.
    let mut segments = vec![KexecSegment {
        data: trampoline_buf,
        phys_addr: trampoline_phys,
        mem_size: trampoline_memsz,
    }];

    // Add all kernel ELF PT_LOAD segments.
    segments.extend(kernel_segments);

    // Add initrd, cmdline, FDT, and boot_params.
    segments.push(KexecSegment {
        data: data.initrd,
        phys_addr: initrd_phys,
        mem_size: initrd_memsz,
    });
    segments.push(KexecSegment {
        data: cmdline_buf,
        phys_addr: cmdline_phys,
        mem_size: cmdline_memsz,
    });
    segments.push(KexecSegment {
        data: fdt_buf,
        phys_addr: fdt_phys,
        mem_size: fdt_memsz,
    });
    segments.push(KexecSegment {
        data: boot_params_buf,
        phys_addr: boot_params_phys,
        mem_size: boot_params_memsz,
    });

    Ok((trampoline_phys, segments))
}

/// Construct `boot_params` (zero page) mimicking `openhcl_boot`.
#[cfg(target_arch = "x86_64")]
fn build_boot_params(
    initrd: std::ops::Range<u64>,
    cmdline_phys: u64,
    setup_data_phys: u64,
) -> anyhow::Result<loader_defs::linux::boot_params> {
    use loader_defs::linux::boot_params;
    use zerocopy::FromZeros;

    let mut bp = boot_params::new_zeroed();

    // Loader type: unknown
    bp.hdr.type_of_loader = 0xff;

    // HACK: Disable probe_roms and reserve_bios_regions (same as openhcl_boot)
    // by setting subarch to X86_SUBARCH_LGUEST.
    bp.hdr.hardware_subarch = 1.into();

    bp.hdr.ramdisk_image = (initrd.start as u32).into();
    bp.ext_ramdisk_image = (initrd.start >> 32) as u32;
    let initrd_len = initrd.end - initrd.start;
    bp.hdr.ramdisk_size = (initrd_len as u32).into();
    bp.ext_ramdisk_size = (initrd_len >> 32) as u32;

    bp.hdr.cmd_line_ptr = (cmdline_phys as u32).into();
    bp.ext_cmd_line_ptr = (cmdline_phys >> 32) as u32;

    bp.hdr.setup_data = setup_data_phys.into();

    build_e820_map(&mut bp)?;

    Ok(bp)
}

/// Build the e820 memory map by parsing `/proc/iomem`.
///
/// `/proc/iomem` is always available and reflects the kernel's view of the
/// physical address space. Only top-level (non-indented) entries are used,
/// as they correspond to the original e820 regions. Nested entries (e.g.
/// "Kernel code", "Kernel data") are sub-regions and are skipped.
///
/// Each line has the format:
/// ```text
/// <start>-<end> : <description>
/// ```
/// where `<start>` and `<end>` are inclusive hex addresses.
#[cfg(target_arch = "x86_64")]
fn build_e820_map(bp: &mut loader_defs::linux::boot_params) -> anyhow::Result<()> {
    use loader_defs::linux::E820_ACPI;
    use loader_defs::linux::E820_NVS;
    use loader_defs::linux::E820_RAM;
    use loader_defs::linux::E820_RESERVED;
    use loader_defs::linux::E820_UNUSABLE;
    use loader_defs::linux::e820entry;

    let iomem = std::fs::read_to_string("/proc/iomem")
        .context("failed to read /proc/iomem")?;

    let max_inline = bp.e820_map.len(); // 128
    let mut n = 0usize;

    for line in iomem.lines() {
        // Only consider top-level entries (lines that don't start with
        // whitespace). Indented lines are sub-regions of a parent entry.
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        // Format: "<start>-<end> : <description>"
        let Some((range_part, desc_part)) = line.split_once(" : ") else {
            tracing::warn!(line = line, "skipping malformed /proc/iomem line");
            continue;
        };

        let Some((start_hex, end_hex)) = range_part.trim().split_once('-') else {
            tracing::warn!(line = line, "skipping malformed range in /proc/iomem");
            continue;
        };

        let start = u64::from_str_radix(start_hex.trim(), 16)
            .with_context(|| format!("bad start address {:?}", start_hex))?;
        let end = u64::from_str_radix(end_hex.trim(), 16)
            .with_context(|| format!("bad end address {:?}", end_hex))?;

        // /proc/iomem uses inclusive end addresses, so size = end - start + 1.
        let size = end.saturating_sub(start).saturating_add(1);
        if size == 0 {
            continue;
        }

        let desc = desc_part.trim();
        let typ = match desc {
            "System RAM" => E820_RAM,
            "Reserved" | "reserved" => E820_RESERVED,
            "ACPI Tables" => E820_ACPI,
            "ACPI Non-volatile Storage" => E820_NVS,
            "Unusable" | "unusable" => E820_UNUSABLE,
            other => {
                tracing::warn!(
                    desc = other,
                    start = %format_args!("{:#x}", start),
                    "unknown /proc/iomem type, treating as reserved"
                );
                E820_RESERVED
            }
        };

        anyhow::ensure!(
            n < max_inline,
            "e820 map has more than {max_inline} entries; \
             E820_EXT chaining not yet implemented"
        );

        tracing::info!(
            index = n,
            start = %format_args!("{:#x}", start),
            size = %format_args!("{:#x}", size),
            typ = desc,
            "e820 entry from /proc/iomem"
        );

        bp.e820_map[n] = e820entry {
            addr: start.into(),
            size: size.into(),
            typ: typ.into(),
        };
        n += 1;
    }

    bp.e820_entries = n as u8;
    tracing::info!(e820_entries = n, "built e820 map from /proc/iomem");
    Ok(())
}

// ---- aarch64 implementation ------------------------------------------------

#[cfg(target_arch = "aarch64")]
fn prepare_aarch64(
    data: DevServicingData,
    vmlinux_info: &VmlinuxInfo,
    boot_dt_info: &ParsedBootDtInfo,
) -> anyhow::Result<(u64, Vec<KexecSegment>)> {
    let entry_point = vmlinux_info.entry_point;

    let largest_ram = boot_dt_info
        .vtl2_memory
        .iter()
        .max_by_key(|r| r.range.len())
        .context("no VTL2 memory ranges available")?;

    tracing::info!(
        range_start = %format_args!("{:#x}", largest_ram.range.start()),
        range_len = %format_args!("{:#x}", largest_ram.range.len()),
        "using VTL2 RAM range for kexec segment placement"
    );

    let mut next_addr = align_up(largest_ram.range.start() + 2 * 1024 * 1024, PAGE_SIZE);

    // Trampoline (placed first; its address becomes the kexec entry point)
    let trampoline_phys = next_addr;
    let trampoline_memsz = PAGE_SIZE as usize;
    next_addr += trampoline_memsz as u64;

    // For ARM64 Image format, the kernel must be loaded at a 2MB-aligned
    // address + text_offset.
    let kernel_phys = match vmlinux_info.format {
        crate::vmlinux_parser::VmlinuxFormat::Arm64Image { text_offset, .. } => {
            let base_2mb = align_up(next_addr, 2 * 1024 * 1024);
            base_2mb + text_offset
        }
        _ => next_addr,
    };
    let kernel_memsz = align_up(data.vmlinux.len() as u64, PAGE_SIZE) as usize;
    next_addr = align_up(kernel_phys + kernel_memsz as u64, PAGE_SIZE);

    // Initrd
    let initrd_phys = next_addr;
    let initrd_size = data.initrd.len() as u64;
    let initrd_memsz = align_up(initrd_size, PAGE_SIZE) as usize;
    next_addr += initrd_memsz as u64;

    // FDT (no setup_data header on aarch64)
    let fdt_phys = next_addr;
    let fdt_memsz = align_up(FDT_SIZE as u64, PAGE_SIZE) as usize;
    next_addr += fdt_memsz as u64;

    // Verify everything fits.
    anyhow::ensure!(
        next_addr <= largest_ram.range.end(),
        "kexec segments ({:#x} bytes) exceed VTL2 RAM range (ends at {:#x})",
        next_addr - largest_ram.range.start(),
        largest_ram.range.end()
    );

    // Build the device tree.
    let mut fdt_buf = vec![0u8; FDT_SIZE];
    build_device_tree(
        &mut fdt_buf,
        boot_dt_info,
        initrd_phys..initrd_phys + initrd_size,
        &data.command_line,
    )
    .context("failed to build device tree for kexec")?;

    // Build the trampoline.
    //
    // The trampoline sets up the register state that the Linux ARM64 boot
    // protocol requires (x0 = FDT pointer, x1-x3 = 0) and then branches
    // to the real kernel entry point.
    let trampoline_buf = build_aarch64_trampoline(fdt_phys, entry_point);

    tracing::info!(
        trampoline_phys = %format_args!("{:#x}", trampoline_phys),
        kernel_entry = %format_args!("{:#x}", entry_point),
        fdt_phys = %format_args!("{:#x}", fdt_phys),
        "built aarch64 trampoline"
    );

    // Assemble segments.
    //
    // The trampoline is the first segment and its physical address is the
    // kexec entry point.
    let segments = vec![
        KexecSegment {
            data: trampoline_buf,
            phys_addr: trampoline_phys,
            mem_size: trampoline_memsz,
        },
        KexecSegment {
            data: data.vmlinux,
            phys_addr: kernel_phys,
            mem_size: kernel_memsz,
        },
        KexecSegment {
            data: data.initrd,
            phys_addr: initrd_phys,
            mem_size: initrd_memsz,
        },
        KexecSegment {
            data: fdt_buf,
            phys_addr: fdt_phys,
            mem_size: fdt_memsz,
        },
    ];

    Ok((trampoline_phys, segments))
}

// ---- Device tree construction ----------------------------------------------

/// Build a device tree blob suitable for the kexec'd kernel.
///
/// This reconstructs the device tree that `openhcl_boot::dt::write_dt` would
/// produce, using information parsed from the current boot's device tree.
///
/// The FDT includes:
/// - `/hypervisor` with `compatible = "microsoft,hyperv"`
/// - `/cpus` with per-vCPU nodes containing reg and NUMA info
/// - `/memory@` nodes for VTL2 RAM ranges
/// - `/bus/vmbus` VMBus device nodes with MMIO ranges
/// - `/openhcl` node with isolation type, memory allocation mode, partition
///   memory map, MMIO ranges, and accepted memory ranges
/// - `/chosen` node (aarch64) with bootargs and initrd info
/// - GIC, timer, PMU, PSCI nodes (aarch64)
fn build_device_tree(
    buffer: &mut [u8],
    boot_dt_info: &ParsedBootDtInfo,
    initrd: std::ops::Range<u64>,
    cmdline: &str,
) -> anyhow::Result<()> {
    use bootloader_fdt_parser::AddressRange;
    use fdt::builder::Builder;
    use fdt::builder::BuilderConfig;

    // Build memory reservation entries from reserved ranges.
    let mut memory_reservations = Vec::new();
    for range in boot_dt_info
        .config_ranges
        .iter()
        .chain(std::iter::once(&boot_dt_info.vtl2_reserved_range))
        .chain(std::iter::once(&boot_dt_info.vtl2_persisted_header))
        .chain(std::iter::once(
            &boot_dt_info.vtl2_persisted_protobuf_region,
        ))
        .chain(boot_dt_info.private_pool_ranges.iter().map(|r| &r.range))
    {
        if !range.is_empty() {
            memory_reservations.push(fdt::ReserveEntry {
                address: range.start().into(),
                size: range.len().into(),
            });
        }
    }

    let builder_config = BuilderConfig {
        blob_buffer: buffer,
        string_table_cap: 1024,
        memory_reservations: &memory_reservations,
    };
    let mut builder =
        Builder::new(builder_config).map_err(|e| anyhow::anyhow!("fdt builder init: {e}"))?;

    // Common string IDs.
    let p_address_cells = builder.add_string("#address-cells").map_err(fdt_err)?;
    let p_size_cells = builder.add_string("#size-cells").map_err(fdt_err)?;
    let p_reg = builder.add_string("reg").map_err(fdt_err)?;
    let p_device_type = builder.add_string("device_type").map_err(fdt_err)?;
    let p_status = builder.add_string("status").map_err(fdt_err)?;
    let p_compatible = builder.add_string("compatible").map_err(fdt_err)?;
    let p_ranges = builder.add_string("ranges").map_err(fdt_err)?;
    let p_numa_node_id = builder.add_string("numa-node-id").map_err(fdt_err)?;
    let p_vtl = builder
        .add_string(igvm_defs::dt::IGVM_DT_VTL_PROPERTY)
        .map_err(fdt_err)?;
    let p_vmbus_connection_id = builder
        .add_string("microsoft,message-connection-id")
        .map_err(fdt_err)?;
    let p_dma_coherent = builder.add_string("dma-coherent").map_err(fdt_err)?;
    let p_igvm_type = builder
        .add_string(igvm_defs::dt::IGVM_DT_IGVM_TYPE_PROPERTY)
        .map_err(fdt_err)?;
    let p_openhcl_memory = builder
        .add_string("openhcl,memory-type")
        .map_err(fdt_err)?;

    #[cfg(target_arch = "aarch64")]
    let p_interrupt_parent = builder.add_string("interrupt-parent").map_err(fdt_err)?;
    #[cfg(target_arch = "aarch64")]
    let p_interrupts = builder.add_string("interrupts").map_err(fdt_err)?;
    #[cfg(target_arch = "aarch64")]
    let p_enable_method = builder.add_string("enable-method").map_err(fdt_err)?;

    let _num_cpus = boot_dt_info.cpus.len();
    #[cfg(target_arch = "aarch64")]
    let num_cpus = _num_cpus;
    let bsp_reg = boot_dt_info
        .cpus
        .first()
        .map(|c| c.reg as u32)
        .unwrap_or(0);

    // -- Root node --
    let mut root_builder = builder
        .start_node("")
        .map_err(fdt_err)?
        .add_u32(p_address_cells, 2)
        .map_err(fdt_err)?
        .add_u32(p_size_cells, 2)
        .map_err(fdt_err)?
        .add_str(p_compatible, "microsoft,openvmm")
        .map_err(fdt_err)?;

    // -- /hypervisor --
    root_builder = root_builder
        .start_node("hypervisor")
        .map_err(fdt_err)?
        .add_str(p_compatible, "microsoft,hyperv")
        .map_err(fdt_err)?
        .end_node()
        .map_err(fdt_err)?;

    // -- /cpus --
    let address_cells = if cfg!(target_arch = "aarch64") { 2 } else { 1 };
    let mut cpu_builder = root_builder
        .start_node("cpus")
        .map_err(fdt_err)?
        .add_u32(p_address_cells, address_cells)
        .map_err(fdt_err)?
        .add_u32(p_size_cells, 0)
        .map_err(fdt_err)?;

    for (vp_index, cpu_entry) in boot_dt_info.cpus.iter().enumerate() {
        let name = format!("cpu@{}", vp_index + 1);

        let mut cpu = cpu_builder
            .start_node(&name)
            .map_err(fdt_err)?
            .add_str(p_device_type, "cpu")
            .map_err(fdt_err)?
            .add_u32(p_numa_node_id, cpu_entry.vnode)
            .map_err(fdt_err)?;

        if cfg!(target_arch = "aarch64") {
            #[cfg(target_arch = "aarch64")]
            {
                cpu = cpu
                    .add_u64(p_reg, cpu_entry.reg)
                    .map_err(fdt_err)?
                    .add_str(p_compatible, "arm,arm-v8")
                    .map_err(fdt_err)?;

                if num_cpus > 1 {
                    cpu = cpu.add_str(p_enable_method, "psci").map_err(fdt_err)?;
                }

                if vp_index == 0 {
                    cpu = cpu.add_str(p_status, "okay").map_err(fdt_err)?;
                } else {
                    cpu = cpu.add_str(p_status, "disabled").map_err(fdt_err)?;
                }
            }
        } else {
            cpu = cpu
                .add_u32(p_reg, cpu_entry.reg as u32)
                .map_err(fdt_err)?
                .add_str(p_status, "okay")
                .map_err(fdt_err)?;
        }

        cpu_builder = cpu.end_node().map_err(fdt_err)?;
    }
    root_builder = cpu_builder.end_node().map_err(fdt_err)?;

    // -- /psci (aarch64 only) --
    #[cfg(target_arch = "aarch64")]
    if num_cpus > 1 {
        let p_method = root_builder.add_string("method").map_err(fdt_err)?;
        let p_cpu_off = root_builder.add_string("cpu_off").map_err(fdt_err)?;
        let p_cpu_on = root_builder.add_string("cpu_on").map_err(fdt_err)?;
        root_builder = root_builder
            .start_node("psci")
            .map_err(fdt_err)?
            .add_str(p_compatible, "arm,psci-0.2")
            .map_err(fdt_err)?
            .add_str(p_method, "hvc")
            .map_err(fdt_err)?
            .add_u32(p_cpu_off, 1)
            .map_err(fdt_err)?
            .add_u32(p_cpu_on, 2)
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;
    }

    // -- /memory@ nodes for VTL2 RAM --
    for mem_entry in &boot_dt_info.vtl2_memory {
        let name = format!("memory@{:x}", mem_entry.range.start());
        root_builder = root_builder
            .start_node(&name)
            .map_err(fdt_err)?
            .add_str(p_device_type, "memory")
            .map_err(fdt_err)?
            .add_u64_array(p_reg, &[mem_entry.range.start(), mem_entry.range.len()])
            .map_err(fdt_err)?
            .add_u32(p_numa_node_id, mem_entry.vnode)
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;
    }

    // -- GIC, timer, PMU (aarch64 only) --
    #[cfg(target_arch = "aarch64")]
    {
        use vm_topology::processor::aarch64::GicInfo;

        const DEFAULT_GIC_DISTRIBUTOR_BASE: u64 = 0xFFFF_0000;
        const DEFAULT_GIC_REDISTRIBUTORS_BASE: u64 = 0xEFFE_E000;
        const GIC_PHANDLE: u32 = 1;
        const GIC_PPI: u32 = 1;
        const IRQ_TYPE_LEVEL_LOW: u32 = 8;
        const IRQ_TYPE_LEVEL_HIGH: u32 = 4;
        const TIMER_INTID: u32 = 4;
        const PMU_GSIV: u32 = 0x17;
        const PMU_GSIV_INT_INDEX: u32 = PMU_GSIV - 16;

        let default_gic = GicInfo {
            gic_distributor_base: DEFAULT_GIC_DISTRIBUTOR_BASE,
            gic_distributor_size: aarch64defs::GIC_DISTRIBUTOR_SIZE,
            gic_redistributors_base: DEFAULT_GIC_REDISTRIBUTORS_BASE,
            gic_redistributors_size: aarch64defs::GIC_REDISTRIBUTOR_SIZE * num_cpus as u64,
            gic_redistributor_stride: aarch64defs::GIC_REDISTRIBUTOR_SIZE,
        };
        let gic = boot_dt_info.gic.as_ref().unwrap_or(&default_gic);

        let p_interrupt_cells = root_builder
            .add_string("#interrupt-cells")
            .map_err(fdt_err)?;
        let p_redist_regions = root_builder
            .add_string("#redistributor-regions")
            .map_err(fdt_err)?;
        let p_redist_stride = root_builder
            .add_string("redistributor-stride")
            .map_err(fdt_err)?;
        let p_interrupt_controller = root_builder
            .add_string("interrupt-controller")
            .map_err(fdt_err)?;
        let p_phandle = root_builder.add_string("phandle").map_err(fdt_err)?;
        let p_interrupt_names = root_builder
            .add_string("interrupt-names")
            .map_err(fdt_err)?;
        let p_always_on = root_builder.add_string("always-on").map_err(fdt_err)?;

        let name = format!("intc@{}", gic.gic_distributor_base);
        root_builder = root_builder
            .start_node(&name)
            .map_err(fdt_err)?
            .add_str(p_compatible, "arm,gic-v3")
            .map_err(fdt_err)?
            .add_u32(p_redist_regions, 1)
            .map_err(fdt_err)?
            .add_u64(p_redist_stride, gic.gic_redistributor_stride)
            .map_err(fdt_err)?
            .add_u64_array(
                p_reg,
                &[
                    gic.gic_distributor_base,
                    gic.gic_distributor_size,
                    gic.gic_redistributors_base,
                    gic.gic_redistributors_size,
                ],
            )
            .map_err(fdt_err)?
            .add_u32(p_address_cells, 2)
            .map_err(fdt_err)?
            .add_u32(p_size_cells, 2)
            .map_err(fdt_err)?
            .add_u32(p_interrupt_cells, 3)
            .map_err(fdt_err)?
            .add_null(p_interrupt_controller)
            .map_err(fdt_err)?
            .add_u32(p_phandle, GIC_PHANDLE)
            .map_err(fdt_err)?
            .add_null(p_ranges)
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;

        // Timer
        root_builder = root_builder
            .start_node("timer")
            .map_err(fdt_err)?
            .add_str(p_compatible, "arm,armv8-timer")
            .map_err(fdt_err)?
            .add_u32(p_interrupt_parent, GIC_PHANDLE)
            .map_err(fdt_err)?
            .add_str(p_interrupt_names, "virt")
            .map_err(fdt_err)?
            .add_u32_array(p_interrupts, &[GIC_PPI, TIMER_INTID, IRQ_TYPE_LEVEL_LOW])
            .map_err(fdt_err)?
            .add_null(p_always_on)
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;

        // PMU
        let pmu_gsiv_index = boot_dt_info
            .pmu_gsiv
            .map(|gsiv| {
                assert!(
                    (16..32).contains(&gsiv),
                    "PMU GSIV must be a PPI in [16, 32) range"
                );
                gsiv - 16
            })
            .unwrap_or(PMU_GSIV_INT_INDEX);
        root_builder = root_builder
            .start_node("pmu")
            .map_err(fdt_err)?
            .add_str(p_compatible, "arm,armv8-pmuv3")
            .map_err(fdt_err)?
            .add_u32_array(
                p_interrupts,
                &[GIC_PPI, pmu_gsiv_index, IRQ_TYPE_LEVEL_HIGH],
            )
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;
    }

    // -- /bus (simple-bus with VMBus) --
    let vtl2_mmio_ranges: Vec<memory_range::MemoryRange> = boot_dt_info
        .partition_memory_map
        .iter()
        .filter_map(|entry| match entry {
            AddressRange::Mmio(mmio) if mmio.vtl == bootloader_fdt_parser::Vtl::Vtl2 => {
                Some(mmio.range)
            }
            _ => None,
        })
        .collect();

    let mut simple_bus_builder = root_builder
        .start_node("bus")
        .map_err(fdt_err)?
        .add_str(p_compatible, "simple-bus")
        .map_err(fdt_err)?
        .add_u32(p_address_cells, 2)
        .map_err(fdt_err)?
        .add_u32(p_size_cells, 2)
        .map_err(fdt_err)?
        .add_prop_array(p_ranges, &[])
        .map_err(fdt_err)?;

    // VMBus node
    {
        let mut vmbus_builder = simple_bus_builder
            .start_node("vmbus")
            .map_err(fdt_err)?
            .add_u32(p_address_cells, 2)
            .map_err(fdt_err)?
            .add_u32(p_size_cells, 2)
            .map_err(fdt_err)?
            .add_null(p_dma_coherent)
            .map_err(fdt_err)?
            .add_str(p_compatible, "microsoft,vmbus")
            .map_err(fdt_err)?
            .add_u32(p_vtl, 2)
            .map_err(fdt_err)?
            .add_u32(p_vmbus_connection_id, 4)
            .map_err(fdt_err)?;

        let mut mmio_values = Vec::new();
        for entry in &vtl2_mmio_ranges {
            mmio_values.push(entry.start());
            mmio_values.push(entry.start());
            mmio_values.push(entry.len());
        }
        vmbus_builder = vmbus_builder
            .add_u64_array(p_ranges, &mmio_values)
            .map_err(fdt_err)?;

        #[cfg(target_arch = "aarch64")]
        {
            const VMBUS_INTID: u32 = 2;
            const IRQ_TYPE_EDGE_FALLING: u32 = 2;
            const GIC_PHANDLE: u32 = 1;
            const GIC_PPI: u32 = 1;
            vmbus_builder = vmbus_builder
                .add_u32(p_interrupt_parent, GIC_PHANDLE)
                .map_err(fdt_err)?
                .add_u32_array(
                    p_interrupts,
                    &[GIC_PPI, VMBUS_INTID, IRQ_TYPE_EDGE_FALLING],
                )
                .map_err(fdt_err)?;
        }

        simple_bus_builder = vmbus_builder.end_node().map_err(fdt_err)?;
    }

    root_builder = simple_bus_builder.end_node().map_err(fdt_err)?;

    // -- /chosen (aarch64: bootargs + initrd) --
    #[cfg(target_arch = "aarch64")]
    {
        let p_bootargs = root_builder.add_string("bootargs").map_err(fdt_err)?;
        let p_initrd_start = root_builder
            .add_string("linux,initrd-start")
            .map_err(fdt_err)?;
        let p_initrd_end = root_builder
            .add_string("linux,initrd-end")
            .map_err(fdt_err)?;

        root_builder = root_builder
            .start_node("chosen")
            .map_err(fdt_err)?
            .add_str(p_bootargs, cmdline)
            .map_err(fdt_err)?
            .add_u64(p_initrd_start, initrd.start)
            .map_err(fdt_err)?
            .add_u64(p_initrd_end, initrd.end)
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;
    }

    // Suppress unused variable warnings on x86_64.
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (&initrd, cmdline);

    // -- /openhcl (usermode information) --
    let mut openhcl_builder = root_builder.start_node("openhcl").map_err(fdt_err)?;

    // Isolation type
    let p_isolation_type = openhcl_builder
        .add_string("isolation-type")
        .map_err(fdt_err)?;
    let isolation_str = match boot_dt_info.isolation {
        bootloader_fdt_parser::IsolationType::None => "none",
        bootloader_fdt_parser::IsolationType::Vbs => "vbs",
        bootloader_fdt_parser::IsolationType::Snp => "snp",
        bootloader_fdt_parser::IsolationType::Tdx => "tdx",
    };
    openhcl_builder = openhcl_builder
        .add_str(p_isolation_type, isolation_str)
        .map_err(fdt_err)?;

    // Memory allocation mode
    let p_memory_allocation_mode = openhcl_builder
        .add_string("memory-allocation-mode")
        .map_err(fdt_err)?;
    match boot_dt_info.memory_allocation_mode {
        bootloader_fdt_parser::MemoryAllocationMode::Host => {
            openhcl_builder = openhcl_builder
                .add_str(p_memory_allocation_mode, "host")
                .map_err(fdt_err)?;
        }
        bootloader_fdt_parser::MemoryAllocationMode::Vtl2 {
            memory_size,
            mmio_size,
        } => {
            let p_memory_size = openhcl_builder.add_string("memory-size").map_err(fdt_err)?;
            let p_mmio_size = openhcl_builder.add_string("mmio-size").map_err(fdt_err)?;
            openhcl_builder = openhcl_builder
                .add_str(p_memory_allocation_mode, "vtl2")
                .map_err(fdt_err)?;
            if let Some(memory_size) = memory_size {
                openhcl_builder = openhcl_builder
                    .add_u64(p_memory_size, memory_size)
                    .map_err(fdt_err)?;
            }
            if let Some(mmio_size) = mmio_size {
                openhcl_builder = openhcl_builder
                    .add_u64(p_mmio_size, mmio_size)
                    .map_err(fdt_err)?;
            }
        }
    }

    // VTL0 alias map
    if let Some(alias_map) = boot_dt_info.vtl0_alias_map {
        let p_vtl0_alias_map = openhcl_builder
            .add_string("vtl0-alias-map")
            .map_err(fdt_err)?;
        openhcl_builder = openhcl_builder
            .add_u64(p_vtl0_alias_map, alias_map)
            .map_err(fdt_err)?;
    }

    // Unified partition memory map.
    let memory_openhcl_type = "memory-openhcl";
    for entry in &boot_dt_info.partition_memory_map {
        match entry {
            AddressRange::Memory(mem) => {
                let name = format!("memory@{:x}", mem.range.range.start());
                openhcl_builder = openhcl_builder
                    .start_node(&name)
                    .map_err(fdt_err)?
                    .add_str(p_device_type, memory_openhcl_type)
                    .map_err(fdt_err)?
                    .add_u64_array(
                        p_reg,
                        &[mem.range.range.start(), mem.range.range.len()],
                    )
                    .map_err(fdt_err)?
                    .add_u32(p_numa_node_id, mem.range.vnode)
                    .map_err(fdt_err)?
                    .add_u32(p_igvm_type, mem.igvm_type.0.into())
                    .map_err(fdt_err)?
                    .add_u32(p_openhcl_memory, mem.vtl_usage.0)
                    .map_err(fdt_err)?
                    .end_node()
                    .map_err(fdt_err)?;
            }
            AddressRange::Mmio(mmio) => {
                let name = format!("memory@{:x}", mmio.range.start());
                let vtl_type = match mmio.vtl {
                    bootloader_fdt_parser::Vtl::Vtl0 => {
                        loader_defs::shim::MemoryVtlType::VTL0_MMIO
                    }
                    bootloader_fdt_parser::Vtl::Vtl2 => {
                        loader_defs::shim::MemoryVtlType::VTL2_MMIO
                    }
                };
                openhcl_builder = openhcl_builder
                    .start_node(&name)
                    .map_err(fdt_err)?
                    .add_str(p_device_type, memory_openhcl_type)
                    .map_err(fdt_err)?
                    .add_u64_array(p_reg, &[mmio.range.start(), mmio.range.len()])
                    .map_err(fdt_err)?
                    .add_u32(p_openhcl_memory, vtl_type.0)
                    .map_err(fdt_err)?
                    .end_node()
                    .map_err(fdt_err)?;
            }
        }
    }

    // Accepted memory ranges
    for range in &boot_dt_info.accepted_ranges {
        let name = format!("accepted-memory@{:x}", range.start());
        openhcl_builder = openhcl_builder
            .start_node(&name)
            .map_err(fdt_err)?
            .add_u64_array(p_reg, &[range.start(), range.len()])
            .map_err(fdt_err)?
            .end_node()
            .map_err(fdt_err)?;
    }

    root_builder = openhcl_builder.end_node().map_err(fdt_err)?;

    root_builder
        .end_node()
        .map_err(fdt_err)?
        .build(bsp_reg)
        .map_err(fdt_err)?;

    Ok(())
}

/// Helper to convert FDT builder errors into anyhow errors.
fn fdt_err(e: fdt::builder::Error) -> anyhow::Error {
    anyhow::anyhow!("fdt builder error: {e}")
}
