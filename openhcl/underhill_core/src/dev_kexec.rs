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
//! The device tree is handled by cloning the raw FDT from `/sys/firmware/fdt`
//! (the exact blob the current kernel booted with) and patching only the
//! initrd location and command line. This avoids manually reconstructing
//! the entire tree and ensures perfect fidelity with the original boot.
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

/// Well-known path where the serialized servicing state is placed inside
/// the initramfs CPIO overlay. The next boot reads this file to restore
/// device state after a dev-servicing kexec.
pub const DEV_SERVICING_STATE_PATH: &str = "/openhcl/dev_servicing_state.bin";

/// Kernel command-line marker appended during dev servicing kexec.
/// The next boot checks `/proc/cmdline` for this token to distinguish
/// a dev-servicing restart from a fresh boot.
pub const DEV_SERVICING_CMDLINE_MARKER: &str = "OPENHCL_SERVICING_COMPLETED=1";

/// Build a minimal CPIO "newc" archive containing a single file at the
///
/// The returned bytes form a complete CPIO archive (including the
/// `TRAILER!!!` sentinel) that can be concatenated onto an existing
/// initramfs/initrd image. The Linux kernel will overlay the contents
/// when it unpacks the initramfs.
///
/// The format follows the SVR4 "newc" (non-CRC) format — magic `070701`,
/// 110-byte ASCII header, 4-byte aligned name and data fields.
pub fn build_cpio_archive(path: &str, contents: &[u8]) -> Vec<u8> {
    fn align4(pos: usize) -> usize {
        (4 - (pos % 4)) % 4
    }

    fn write_cpio_entry(
        buf: &mut Vec<u8>,
        inode: u32,
        mode: u32,
        name: &str,
        data: &[u8],
    ) {
        let namesize = name.len() + 1; // includes NUL
        let filesize = data.len();

        // 110-byte ASCII header (magic "070701", no CRC).
        let header = format!(
            "070701\
             {inode:08X}\
             {mode:08X}\
             00000000\
             00000000\
             00000001\
             00000000\
             {filesize:08X}\
             00000000\
             00000000\
             00000000\
             00000000\
             {namesize:08X}\
             00000000"
        );
        debug_assert_eq!(header.len(), 110);

        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0); // NUL terminator
        // Pad name+header to 4-byte boundary.
        let pad = align4(110 + namesize);
        buf.extend(std::iter::repeat(0u8).take(pad));
        // File data.
        buf.extend_from_slice(data);
        // Pad data to 4-byte boundary.
        let pad = align4(filesize);
        buf.extend(std::iter::repeat(0u8).take(pad));
    }

    let mut archive = Vec::new();

    // Ensure parent directories exist. Walk the path and emit a
    // directory entry for every intermediate component.
    // Strip leading '/' so the CPIO paths are relative.
    let rel_path = path.strip_prefix('/').unwrap_or(path);
    let mut inode: u32 = 1;

    // Collect ancestor directories.
    let parent = std::path::Path::new(rel_path).parent();
    if let Some(parent) = parent {
        let mut cumulative = String::new();
        for component in parent.components() {
            if !cumulative.is_empty() {
                cumulative.push('/');
            }
            cumulative.push_str(&component.as_os_str().to_string_lossy());
            // directory: mode 0755 (octal) = 0o040755 (S_IFDIR | 0755)
            write_cpio_entry(&mut archive, inode, 0o040755, &cumulative, &[]);
            inode += 1;
        }
    }

    // The file entry: mode 0644 (octal) = 0o100644 (S_IFREG | 0644)
    write_cpio_entry(&mut archive, inode, 0o100644, rel_path, contents);

    // TRAILER!!!
    write_cpio_entry(&mut archive, 0, 0, "TRAILER!!!", &[]);

    archive
}

/// Top-level entry point for the dev servicing kexec flow.
///
/// Parses the kernel image, computes hashes for diagnostics, reads the
/// boot device tree, builds the kexec segments, loads them, and triggers
/// the reboot. On success this function does not return.
pub fn perform_kexec(mut data: DevServicingData) -> anyhow::Result<()> {
    // If no command line was provided, use the currently running
    // kernel's command line.
    if data.command_line.is_empty() {
        data.command_line = std::fs::read_to_string("/proc/cmdline")
            .context("failed to read /proc/cmdline")?
            .trim_end()
            .to_string();
        tracing::debug!(
            command_line = %data.command_line,
            "no command line provided, using current kernel cmdline"
        );
    }

    // Parse the vmlinux/kernel image header to find the entry point.
    let vmlinux_info =
        crate::vmlinux_parser::parse_vmlinux(&data.vmlinux).context("failed to parse kernel image")?;

    tracing::debug!(
        initrd_size = data.initrd.len(),
        vmlinux_size = data.vmlinux.len(),
        entry_point = %format_args!("{:#x}", vmlinux_info.entry_point),
        arch = %vmlinux_info.arch,
        format = %vmlinux_info.format,
        command_line = %data.command_line,
        "dev servicing: preparing kexec"
    );

    // Parse the boot device tree to obtain the current system's
    // memory map, CPU topology, isolation type, and other parameters
    // needed to reconstruct the boot environment.
    let boot_dt_info =
        ParsedBootDtInfo::new().context("failed to parse boot device tree")?;

    // Build the kexec segments (kernel, initrd, boot_params, FDT,
    // command line).
    let (entry_point, segments) = prepare_kexec_segments(data, &vmlinux_info, &boot_dt_info)
        .context("failed to prepare kexec segments")?;

    // Load the segments into the kernel.
    kexec_sys::kexec_load(entry_point, &segments).context("kexec_load failed")?;

    tracing::debug!("kexec loaded, triggering reboot");

    // Reboot into the new kernel. On success this does not return.
    kexec_sys::kexec_reboot().context("kexec reboot failed")?;

    Ok(())
}

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
    data.command_line.push(' ');
    data.command_line
        .push_str(DEV_SERVICING_CMDLINE_MARKER);

    // Enable early console output on COM3 (I/O 0x3E8 = ttyS2) so that
    // kernel boot messages are visible via the Hyper-V COM3 pipe /
    // ohcldiag-dev serial as soon as the new kernel starts executing.
    // data.command_line
    //     .push_str(" earlycon=uart8250,io,0x3e8,115200n8 console=ttyS2,115200n8");

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
    let mut kernel_entry_phys = vmlinux_info.entry_point;

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
    // addresses. For relocatable kernels (CONFIG_RELOCATABLE=y), the ELF
    // p_paddr values may point outside the VTL2 RAM range (e.g. at
    // 0x0800_0000 which is inside VTL0 guest RAM). Loading there would
    // corrupt guest memory. Detect this case and rebase all segments
    // into the VTL2 RAM range, aligned to PHYSICAL_ALIGN (2 MB).

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

    // Compute relocation delta if kernel segments fall outside VTL2 RAM.
    //
    // When the lowest ELF p_paddr is below the VTL2 range start, we
    // relocate the entire kernel so its lowest segment begins at a
    // 2 MB-aligned address within VTL2 RAM. The kernel must be built
    // with CONFIG_RELOCATABLE=y for this to work correctly.
    const PHYSICAL_ALIGN: u64 = 2 * 1024 * 1024; // 2 MB

    let lowest_seg_paddr = vmlinux_info
        .segments
        .iter()
        .map(|s| s.paddr)
        .min()
        .unwrap(); // safe: ensured non-empty above

    let reloc_delta: i64 = if lowest_seg_paddr < largest_ram.range.start()
        || vmlinux_info.segments.iter().any(|s| {
            s.paddr + align_up(s.mem_size, PAGE_SIZE) > largest_ram.range.end()
        })
    {
        // Segments fall outside VTL2 RAM — relocate into the range.
        let new_base = align_up(largest_ram.range.start(), PHYSICAL_ALIGN);
        let delta = new_base as i64 - lowest_seg_paddr as i64;
        tracing::warn!(
            lowest_seg_paddr = %format_args!("{:#x}", lowest_seg_paddr),
            vtl2_range_start = %format_args!("{:#x}", largest_ram.range.start()),
            new_base = %format_args!("{:#x}", new_base),
            delta = %format_args!("{:#x}", delta),
            "kernel segments outside VTL2 RAM, relocating"
        );
        delta
    } else {
        0
    };

    // Apply relocation to the entry point.
    if reloc_delta != 0 {
        let old_entry = kernel_entry_phys;
        kernel_entry_phys = (kernel_entry_phys as i64 + reloc_delta) as u64;
        tracing::info!(
            old_entry = %format_args!("{:#x}", old_entry),
            new_entry = %format_args!("{:#x}", kernel_entry_phys),
            "relocated kernel entry point"
        );
    }

    // Build kexec segments for each ELF PT_LOAD, applying relocation.
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

        let relocated_paddr = (seg.paddr as i64 + reloc_delta) as u64;
        let seg_end = relocated_paddr + seg_memsz as u64;
        if seg_end > highest_seg_end {
            highest_seg_end = seg_end;
        }

        if reloc_delta != 0 {
            tracing::info!(
                original = %format_args!("{:#x}", seg.paddr),
                relocated = %format_args!("{:#x}", relocated_paddr),
                "relocated ELF segment"
            );
        }

        kernel_segments.push(KexecSegment {
            data: seg_data,
            phys_addr: relocated_paddr,
            mem_size: seg_memsz,
        });
    }

    // Verify all relocated segments are within VTL2 RAM.
    for kseg in &kernel_segments {
        let seg_end = kseg.phys_addr + kseg.mem_size as u64;
        anyhow::ensure!(
            kseg.phys_addr >= largest_ram.range.start() && seg_end <= largest_ram.range.end(),
            "relocated kernel segment [{:#x}..{:#x}) outside VTL2 RAM [{:#x}..{:#x})",
            kseg.phys_addr,
            seg_end,
            largest_ram.range.start(),
            largest_ram.range.end()
        );
    }

    // Compute the kernel physical load base (lowest relocated segment address).
    // This is needed for boot_params.hdr.pref_address and init_size so the
    // new kernel reserves this memory and does not overwrite its own code.
    let kernel_load_phys = kernel_segments
        .iter()
        .map(|s| s.phys_addr)
        .min()
        .unwrap();

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

    // Clone the boot FDT into the data portion (after the setup_data
    // header). On x86_64, initrd and cmdline are passed via boot_params,
    // not via the FDT, so the tree is cloned verbatim.
    clone_and_patch_device_tree(
        &mut fdt.data,
        initrd_phys..initrd_phys + initrd_size,
        &data.command_line,
    )
    .context("failed to clone device tree for kexec")?;

    let fdt_buf = fdt.as_bytes().to_vec();

    // -- 3. Build boot_params (zero page) ------------------------------------
    let bp = build_boot_params(
        kernel_load_phys,
        next_addr,
        initrd_phys..initrd_phys + initrd_size,
        cmdline_phys,
        fdt_phys,
    )
    .context("failed to build boot_params")?;

    tracing::debug!(boot_params = ?bp, "built boot_params with e820 map entries:");

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
    kernel_load_phys: u64,
    segments_end_phys: u64,
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

    // Tell the kernel where it is loaded and how much memory to reserve.
    // init_size covers all kexec segments (kernel text, initrd, FDT, etc.)
    // from the kernel load address to the end. Without this, the kernel's
    // early memory allocator may overwrite its own code pages.
    bp.hdr.pref_address = kernel_load_phys.into();
    let init_size = (segments_end_phys - kernel_load_phys) as u32;
    bp.hdr.init_size = init_size.into();
    bp.hdr.relocatable_kernel = 1;
    bp.hdr.kernel_alignment = (2 * 1024 * 1024_u32).into(); // 2 MB
    tracing::info!(
        pref_address = %format_args!("{:#x}", kernel_load_phys),
        init_size = %format_args!("{:#x}", init_size),
        "boot_params: kernel load reservation"
    );
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

    // Clone the boot device tree, patching the /chosen node with the
    // new initrd location and command line.
    let mut fdt_buf = vec![0u8; FDT_SIZE];
    clone_and_patch_device_tree(
        &mut fdt_buf,
        initrd_phys..initrd_phys + initrd_size,
        &data.command_line,
    )
    .context("failed to clone device tree for kexec")?;

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

/// Property patches to apply when cloning the boot device tree.
///
/// During dev servicing kexec, the device tree should be identical to the
/// one the current kernel booted with, except for a small set of properties
/// that reflect the new initrd location and command line.
struct DtPatches<'a> {
    /// New initrd physical address range.
    initrd: std::ops::Range<u64>,
    /// New kernel command line string.
    cmdline: &'a str,
}

/// Clone the current boot device tree, patching only the initrd location
/// and command line.
///
/// Instead of manually reconstructing the entire device tree from parsed
/// fields (which is fragile and can drift from what `openhcl_boot` produces),
/// this function reads the raw FDT blob from `/sys/firmware/fdt` — the exact
/// device tree the current kernel booted with — and clones it into `buffer`.
/// On aarch64, the `/chosen` node's `bootargs`, `linux,initrd-start`, and
/// `linux,initrd-end` properties are patched with the new values. On x86_64,
/// these values live in `boot_params` (the zero page), not in the FDT, so
/// the tree is cloned verbatim.
///
/// The tree is walked iteratively using an explicit stack (no recursion).
/// The parsed tree is first flattened into a linear event list, then the
/// events are written directly as raw FDT binary tokens into the output
/// buffer. This avoids fighting the FDT builder's type-state pattern
/// which prevents dynamic nesting in a flat loop.
///
/// This ensures the kexec'd kernel sees exactly the same device tree as the
/// original boot, preserving all nodes (cpus, memory, GIC, openhcl, etc.)
/// without risk of omitting or misordering properties.
fn clone_and_patch_device_tree(
    buffer: &mut [u8],
    initrd: std::ops::Range<u64>,
    cmdline: &str,
) -> anyhow::Result<()> {
    let patches = DtPatches { initrd, cmdline };

    // Read the raw FDT that the current kernel was booted with.
    let raw_fdt =
        std::fs::read("/sys/firmware/fdt").context("failed to read /sys/firmware/fdt")?;

    // The FDT parser requires 4-byte aligned input. Use a u32-aligned
    // Vec to guarantee this, then copy the raw bytes into it.
    let fdt_len = raw_fdt.len();
    let num_u32 = (fdt_len + 3) / 4;
    let mut aligned_fdt: Vec<u32> = vec![0u32; num_u32];
    zerocopy::IntoBytes::as_mut_bytes(aligned_fdt.as_mut_slice())[..fdt_len]
        .copy_from_slice(&raw_fdt);
    let fdt_slice = &zerocopy::IntoBytes::as_bytes(aligned_fdt.as_slice())[..fdt_len];

    let parser = fdt::parser::Parser::new(fdt_slice)
        .map_err(|e| anyhow::anyhow!("failed to parse boot FDT: {e}"))?;

    // Collect memory reservations from the source FDT.
    let memory_reservations: Vec<fdt::ReserveEntry> =
        parser.memory_reservations().map(|r| r.unwrap()).collect();

    let boot_cpuid_phys = parser.boot_cpuid_phys;
    let root = parser
        .root()
        .map_err(|e| anyhow::anyhow!("failed to get FDT root: {e}"))?;

    // Phase 1: Flatten the tree iteratively into events.
    let events = flatten_fdt_tree(&root, &patches)?;

    // Phase 2: Write the FDT blob directly into the output buffer.
    //
    // The FDT builder crate uses a type-state pattern (Nest<T>) that
    // changes the Builder's Rust type with each start_node / end_node
    // call. This makes a flat iterative loop over dynamically-nested
    // events impossible through the builder's public API. Instead, we
    // write the FDT binary format directly. The format is simple:
    //
    //   [Header (40 bytes)]
    //   [Memory reservation entries + sentinel (0,0)]
    //   [String table]
    //   [Struct table: sequence of tokens]
    //   - BEGIN_NODE (1) + name (null-terminated, 4-byte aligned)
    //   - PROP (3) + PropHeader { len, nameoff } + data (4-byte aligned)
    //   - END_NODE (2)
    //   - END (9)
    //
    // All multi-byte values are big-endian.

    // FDT format constants.
    const FDT_MAGIC: u32 = 0xd00dfeed;
    const FDT_VERSION: u32 = 17;
    const FDT_COMPAT_VERSION: u32 = 16;
    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;
    const HEADER_SIZE: usize = 40;
    const RESERVE_ENTRY_SIZE: usize = 16; // sizeof(ReserveEntry) = 8+8

    // --- Build the string table ---
    // Collect unique property names and assign offsets.
    let mut string_table = Vec::<u8>::new();
    let mut string_offsets: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for event in &events {
        if let FdtEvent::Property { name, .. } = event {
            if !string_offsets.contains_key(name.as_str()) {
                let offset = string_table.len() as u32;
                string_table.extend_from_slice(name.as_bytes());
                string_table.push(0); // null terminator
                string_offsets.insert(name.clone(), offset);
            }
        }
    }

    // --- Build the struct table ---
    let mut struct_table = Vec::<u8>::new();
    for event in &events {
        match event {
            FdtEvent::BeginNode(name) => {
                struct_table.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
                struct_table.extend_from_slice(name.as_bytes());
                struct_table.push(0); // null terminator
                // Align to 4 bytes.
                while struct_table.len() % 4 != 0 {
                    struct_table.push(0);
                }
            }
            FdtEvent::Property { name, data } => {
                let nameoff = *string_offsets.get(name.as_str()).unwrap();
                struct_table.extend_from_slice(&FDT_PROP.to_be_bytes());
                // PropHeader: len (u32be) + nameoff (u32be)
                struct_table.extend_from_slice(&(data.len() as u32).to_be_bytes());
                struct_table.extend_from_slice(&nameoff.to_be_bytes());
                struct_table.extend_from_slice(data);
                // Align to 4 bytes.
                while struct_table.len() % 4 != 0 {
                    struct_table.push(0);
                }
            }
            FdtEvent::EndNode => {
                struct_table.extend_from_slice(&FDT_END_NODE.to_be_bytes());
            }
        }
    }
    // Final END token.
    struct_table.extend_from_slice(&FDT_END.to_be_bytes());

    // --- Compute layout offsets ---
    // Use the standard FDT layout order: header, memory reservations,
    // struct table, string table. Placing the struct table before the
    // string table guarantees its offset is 4-byte aligned (the header
    // is 40 bytes and each reservation entry is 16 bytes, both multiples
    // of 4, and the struct table itself only contains 4-byte-aligned
    // tokens). The string table has no alignment requirement.
    let mem_rsv_off = HEADER_SIZE;
    // Each reservation entry is 16 bytes, plus the sentinel (0,0).
    let mem_rsv_size = (memory_reservations.len() + 1) * RESERVE_ENTRY_SIZE;
    let struct_table_off = mem_rsv_off + mem_rsv_size;
    let string_table_off = struct_table_off + struct_table.len();
    let total_size = string_table_off + string_table.len();

    anyhow::ensure!(
        total_size <= buffer.len(),
        "FDT output buffer too small: need {total_size} bytes, have {}",
        buffer.len()
    );

    // --- Write everything into the output buffer ---

    // Memory reservation entries.
    for (i, entry) in memory_reservations.iter().enumerate() {
        let off = mem_rsv_off + i * RESERVE_ENTRY_SIZE;
        zerocopy::IntoBytes::write_to_prefix(entry, &mut buffer[off..off + RESERVE_ENTRY_SIZE])
            .map_err(|_| anyhow::anyhow!("failed to write memory reservation entry"))?;
    }
    // Sentinel entry (0, 0).
    let sentinel_off = mem_rsv_off + memory_reservations.len() * RESERVE_ENTRY_SIZE;
    buffer[sentinel_off..sentinel_off + RESERVE_ENTRY_SIZE].fill(0);

    // Struct table.
    buffer[struct_table_off..struct_table_off + struct_table.len()]
        .copy_from_slice(&struct_table);

    // String table.
    buffer[string_table_off..string_table_off + string_table.len()]
        .copy_from_slice(&string_table);

    // Header (written last so we know all sizes).
    // Fields are all u32 big-endian, 10 fields = 40 bytes.
    let header_fields: [u32; 10] = [
        FDT_MAGIC,
        total_size as u32,
        struct_table_off as u32, // off_dt_struct
        string_table_off as u32, // off_dt_strings
        mem_rsv_off as u32,      // off_mem_rsvmap
        FDT_VERSION,
        FDT_COMPAT_VERSION,
        boot_cpuid_phys,
        string_table.len() as u32, // size_dt_strings
        struct_table.len() as u32, // size_dt_struct
    ];
    for (i, &field) in header_fields.iter().enumerate() {
        let off = i * 4;
        buffer[off..off + 4].copy_from_slice(&field.to_be_bytes());
    }

    tracing::debug!("cloned boot FDT with patched initrd/cmdline ({total_size} bytes)");

    Ok(())
}

/// Events produced by flattening the FDT tree.
enum FdtEvent {
    /// A node begins (with its name).
    BeginNode(String),
    /// A property with its name and data (already patched if needed).
    Property { name: String, data: Vec<u8> },
    /// A node ends.
    EndNode,
}

/// Flatten an FDT tree into a linear sequence of events using an explicit
/// stack (iterative DFS), applying property patches along the way.
fn flatten_fdt_tree(
    root: &fdt::parser::Node<'_>,
    patches: &DtPatches<'_>,
) -> anyhow::Result<Vec<FdtEvent>> {
    let mut events = Vec::new();

    // Each stack frame tracks a node whose BeginNode + properties have
    // already been emitted, plus its remaining children to process.
    struct Frame<'a> {
        path: String,
        children: Vec<fdt::parser::Node<'a>>,
        child_index: usize,
    }

    // Emit root's BeginNode and properties.
    events.push(FdtEvent::BeginNode(root.name.to_string()));
    emit_node_properties(&mut events, root, "", patches)?;

    let root_children: Vec<_> = root
        .children()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse FDT child node: {e}"))?;

    let mut stack = vec![Frame {
        path: String::new(),
        children: root_children,
        child_index: 0,
    }];

    while let Some(frame) = stack.last_mut() {
        if frame.child_index < frame.children.len() {
            let child = &frame.children[frame.child_index];
            frame.child_index += 1;

            let child_path = if frame.path.is_empty() {
                child.name.to_string()
            } else {
                format!("{}/{}", frame.path, child.name)
            };

            // Emit this child's BeginNode and properties.
            events.push(FdtEvent::BeginNode(child.name.to_string()));
            emit_node_properties(&mut events, child, &child_path, patches)?;

            let grandchildren: Vec<_> = child
                .children()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("failed to parse FDT child node: {e}"))?;

            stack.push(Frame {
                path: child_path,
                children: grandchildren,
                child_index: 0,
            });
        } else {
            // All children processed; emit EndNode and pop.
            events.push(FdtEvent::EndNode);
            stack.pop();
        }
    }

    Ok(events)
}

/// Emit property events for a single node, applying patches for `/chosen`
/// on aarch64.
fn emit_node_properties(
    events: &mut Vec<FdtEvent>,
    node: &fdt::parser::Node<'_>,
    node_path: &str,
    patches: &DtPatches<'_>,
) -> anyhow::Result<()> {
    let is_chosen = node_path == "chosen";

    for prop in node.properties() {
        let prop = prop.map_err(|e| anyhow::anyhow!("failed to parse FDT property: {e}"))?;

        // On aarch64, patch the /chosen node's initrd and bootargs properties.
        if cfg!(target_arch = "aarch64") && is_chosen {
            match prop.name {
                "bootargs" => {
                    let mut data = Vec::from(patches.cmdline.as_bytes());
                    data.push(0);
                    events.push(FdtEvent::Property {
                        name: prop.name.to_string(),
                        data,
                    });
                    continue;
                }
                "linux,initrd-start" => {
                    events.push(FdtEvent::Property {
                        name: prop.name.to_string(),
                        data: patches.initrd.start.to_be_bytes().to_vec(),
                    });
                    continue;
                }
                "linux,initrd-end" => {
                    events.push(FdtEvent::Property {
                        name: prop.name.to_string(),
                        data: patches.initrd.end.to_be_bytes().to_vec(),
                    });
                    continue;
                }
                _ => {}
            }
        }

        // Default: copy property data verbatim.
        events.push(FdtEvent::Property {
            name: prop.name.to_string(),
            data: prop.data.to_vec(),
        });
    }

    Ok(())
}
