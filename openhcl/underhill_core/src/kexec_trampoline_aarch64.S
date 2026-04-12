// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Kexec trampoline for aarch64
//
// This code is copied to a dedicated physical page at kexec time.
// The preceding page contains the trampoline parameters with all
// runtime-dependent values.
//
// Memory layout (two contiguous physical pages):
//   [param_page]:          Parameter page (read-only data)
//   [param_page + 0x1000]: This code (execute-only)
//
// Param page layout (offsets from param page base):
//   0x000: fdt_phys (u64)
//   0x008: kernel_entry (u64)
//
// Linux ARM64 boot protocol:
//   x0 = FDT physical address
//   x1 = x2 = x3 = 0

.set PARAM_FDT_PHYS, 0x00
.set PARAM_KERNEL_ENTRY, 0x08

.globl kexec_trampoline_aarch64_start
.globl kexec_trampoline_aarch64_end

kexec_trampoline_aarch64_start:
    // Locate the parameter page (one page before this code page)
    adr     x5, kexec_trampoline_aarch64_start
    and     x5, x5, #-0x1000                       // Align down to code page base
    sub     x5, x5, #0x1000                         // Step back to param page

    // Load parameters
    ldr     x0, [x5, #PARAM_FDT_PHYS]              // x0 = FDT address
    ldr     x4, [x5, #PARAM_KERNEL_ENTRY]           // x4 = kernel entry

    // Zero x1-x3 per boot protocol
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0

    br      x4                                      // Branch to kernel

kexec_trampoline_aarch64_end:
