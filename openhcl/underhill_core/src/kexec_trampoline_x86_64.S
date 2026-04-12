// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Kexec trampoline for x86_64
//
// This code is copied to a dedicated physical page at kexec time.
// The preceding page contains the trampoline parameters with all
// runtime-dependent values. This code is fully static and
// position-independent -- identical binary every time.
//
// Memory layout (two contiguous physical pages):
//   [param_page]:          Parameter page (read-only data)
//   [param_page + 0x1000]: This code (execute-only)
//
// Param page layout (offsets from param page base):
//   0x000: boot_params_phys (u64)
//   0x008: kernel_entry (u64)
//   0x010: page_table_phys (u64)
//   0x018: cr4_value (u64)
//   0x020: cr0_value (u64)
//   0x100: GDT descriptor (2-byte limit + 8-byte base)
//   0x110: GDT entries (4 x 8 bytes)
//
// After execution:
//   RDI = 0
//   RSI = boot_params physical address
//   CS = __BOOT_CS (0x10), DS/ES/SS = __BOOT_DS (0x18)
//   CR3 = identity-mapped page tables
//   Jumps to kernel entry point

// Named constants for parameter page offsets
.set PARAM_BOOT_PARAMS, 0x00
.set PARAM_KERNEL_ENTRY, 0x08
.set PARAM_PAGE_TABLE, 0x10
.set PARAM_CR4, 0x18
.set PARAM_CR0, 0x20
.set PARAM_GDT_DESC, 0x100

.set BOOT_CS, 0x10
.set BOOT_DS, 0x18

.globl kexec_trampoline_x86_64_start
.globl kexec_trampoline_x86_64_end

kexec_trampoline_x86_64_start:

    // ---- Disable interrupts ------------------------------------------------
    cli
    cld
    mov     al, 0x80                                // Disable NMI via CMOS port
    out     0x70, al

    // ---- Locate the parameter page -----------------------------------------
    // This code sits at the start of a page-aligned code page.
    // The parameter page is the page immediately before it.
    lea     rbx, [rip + kexec_trampoline_x86_64_start]
    and     rbx, -0x1000                            // Align down to code page base
    sub     rbx, 0x1000                             // Step back to param page

    // ---- Configure control registers ---------------------------------------
    mov     rax, [rbx + PARAM_CR4]                  // CR4 (PAE only by default)
    mov     cr4, rax

    mov     rax, [rbx + PARAM_CR0]                  // CR0 (PG|WP|NE|ET|MP|PE)
    mov     cr0, rax

    mov     rax, [rbx + PARAM_PAGE_TABLE]           // CR3 = identity page tables
    mov     cr3, rax

    // ---- Clear debug registers ---------------------------------------------
    xor     eax, eax
    mov     dr0, rax
    mov     dr1, rax
    mov     dr2, rax
    mov     dr3, rax
    mov     dr6, rax
    mov     dr7, rax

    // ---- Load GDT and segment selectors ------------------------------------
    lgdt    [rbx + PARAM_GDT_DESC]

    mov     ax, BOOT_DS
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    xor     ax, ax
    mov     fs, ax
    mov     gs, ax

    // Reload CS via far return
    push    BOOT_CS
    lea     rax, [rip + .Lcs_reloaded]
    push    rax
    retfq
.Lcs_reloaded:

    // ---- Set up boot protocol registers and jump ---------------------------
    xor     edi, edi                                // RDI = 0
    mov     rsi, [rbx + PARAM_BOOT_PARAMS]          // RSI = boot_params address
    mov     rax, [rbx + PARAM_KERNEL_ENTRY]         // RAX = kernel entry point

    // Zero all remaining GPRs
    xor     ecx, ecx
    xor     edx, edx
    xor     ebx, ebx
    xor     ebp, ebp
    xor     esp, esp
    xor     r8d, r8d
    xor     r9d, r9d
    xor     r10d, r10d
    xor     r11d, r11d
    xor     r12d, r12d
    xor     r13d, r13d
    xor     r14d, r14d
    xor     r15d, r15d

    jmp     rax                                     // Jump to kernel

kexec_trampoline_x86_64_end:
