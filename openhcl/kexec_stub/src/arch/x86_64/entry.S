// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Entry point for the kexec stub. The kexec bzImage64 handler jumps here
// at offset 0x200 within the protected-mode kernel section.
//
// Register state on entry (set by kexec purgatory via entry64_regs):
//   RSI = physical address of boot_params
//   RIP = kernel_load_addr + 0x200 (this code)
//   All other registers = 0
//   Identity mapping is active (set up by kexec purgatory)
//   64-bit long mode, paging enabled
//
// Self-relocation: the binary is linked at base 0 but loaded at an arbitrary
// kexec address. GOT entries, vtable pointers, and other absolute addresses
// are wrong. We process the embedded .rela.dyn (Elf64_Rela entries, kept in
// the flat binary by link.x) to fix them up BEFORE touching any Rust code.
//
// BSS must be zeroed because after kexec there may be stale data in memory.
// The stack is in BSS, so BSS must be zeroed before the stack is used.

.section .text.entry, "ax"
.globl _start
.globl pack_offset
.globl pack_size
_start:
    jmp     0f                                      // Skip over embedded pack info header
    .balign 8, 0x90                                 // Pad to 8-byte alignment (nop)
pack_offset:
    .quad   0                                       // Patched by kexec_prepare.rs: offset to packed blob in PM kernel
pack_size:
    .quad   0                                       // Patched by kexec_prepare.rs: size of packed blob
0:
    mov     rbx, rsi                                // Save boot_params pointer (RSI from purgatory)

    // === Self-relocation ===
    // Calculate load base. _start is linked at address 0, so the actual
    // runtime address of _start equals the load delta (base).
    lea     r8, _start[rip]                         // r8 = load_base (= load_delta)
    test    r8, r8
    jz      2f                                      // Skip if loaded at 0 (no fixup needed)

    // Process .rela.dyn entries (Elf64_Rela: 24 bytes each = r_offset + r_info + r_addend)
    lea     rdi, __rela_start[rip]                  // Start of relocation table
    lea     rcx, __rela_end[rip]                    // End of relocation table
1:
    cmp     rdi, rcx
    jae     2f                                      // Done
    mov     rsi, [rdi]                              // r_offset
    movzx   edx, byte ptr [rdi + 8]                 // r_info low byte = reloc type
    cmp     dl, 8                                   // R_X86_64_RELATIVE == 8
    jne     3f                                      // Skip non-RELATIVE entries
    // Apply: *(base + r_offset) = base + r_addend
    mov     rax, [rdi + 16]                         // r_addend
    add     rax, r8                                 // base + r_addend
    mov     [r8 + rsi], rax                         // *(base + r_offset) = result
3:
    add     rdi, 24                                 // sizeof(Elf64_Rela)
    jmp     1b
2:
    // === Zero BSS ===
    lea     rdi, __bss_start[rip]                   // BSS start
    lea     rcx, _end[rip]                          // BSS end
    sub     rcx, rdi                                // BSS length
    xor     eax, eax                                // Zero
    cld
    rep     stosb                                   // Zero BSS

    // === Set up identity-mapped page tables ===
    // The purgatory's page tables may only cover the kernel load area.
    // The initrd/ramdisk can be at a low physical address (e.g. 0x15678000)
    // that is NOT mapped. Build fresh identity-mapped page tables using
    // 1GB pages (PDPT entries with PS bit) covering 0-512GB.
    //
    // Page tables must be at page-aligned physical addresses. The stub binary
    // starts at kernel_load_addr + 0x200, so BSS symbols are offset by 0x200
    // and NOT page-aligned. Allocate from page-aligned memory past _end.
    // init_size has 64KB headroom past BSS for this purpose.
    //
    // Layout: PML4 at page_align(_end), PDPT at PML4 + 0x1000
    lea     rdi, _end[rip]
    add     rdi, 0xFFF
    and     rdi, 0xFFFFFFFFFFFFF000                 // rdi = PML4 (page-aligned)
    lea     rsi, [rdi + 0x1000]                     // rsi = PDPT

    // Zero PML4 and PDPT (2 pages = 8192 bytes)
    push    rdi                                     // Save PML4 address
    push    rsi                                     // Save PDPT address
    mov     rcx, 1024                               // 1024 qwords = 8192 bytes
    xor     eax, eax
    rep     stosq
    pop     rsi                                     // Restore PDPT
    pop     rdi                                     // Restore PML4

    // PML4[0] = physical address of PDPT | Present | Writable
    mov     rax, rsi
    or      rax, 0x3                                // Present + Writable
    mov     [rdi], rax                              // PML4[0] = &PDPT | flags

    // Fill PDPT[0..511] with 512 x 1GB identity-mapped pages (0-512GB)
    xor     ecx, ecx                                // index = 0
    mov     rax, 0x83                               // Present + Writable + PS (1GB page)
5:
    mov     [rsi + rcx*8], rax                      // PDPT[i] = phys | flags
    add     rax, 0x40000000                         // next 1GB
    inc     ecx
    cmp     ecx, 512
    jb      5b

    // Switch to new page tables
    mov     cr3, rdi                                // Load PML4 into CR3

    // === Set up stack and SSE ===
    lea     rsp, {STACK_SIZE} + {stack}[rip]        // Set stack pointer
    mov     dword ptr {stack}[rip], {STACK_COOKIE}  // Set stack cookie
    mov     rax, cr4                                // Read CR4
    or      rax, 0x600                              // Set OSFXSR and OSXMMEXCPT for SSE
    mov     cr4, rax                                // Write CR4

    // === Jump to Rust ===
    mov     rdi, rbx                                // boot_params_ptr as arg 0
    jmp     {start}                                 // Jump to Rust start()
