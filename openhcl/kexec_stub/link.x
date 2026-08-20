/* Linker script for kexec_stub: ensure _start is at the very beginning
 * of the flat binary so that kexec's purgatory can jump directly to
 * offset 0x200 of the PM kernel (= byte 0 of the flat binary).
 */

ENTRY(_start)

SECTIONS
{
    . = 0;

    /* Force _start to be the very first thing in the binary */
    .text.entry : {
        *(.text._start)
        *(.text.entry)
    }

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Keep relro sections contiguous: .dynamic, .got, .data */
    .dynamic : {
        *(.dynamic)
    }

    .got : {
        *(.got .got.*)
    }

    /* Keep .rela.dyn in a LOAD segment so objcopy -O binary preserves it.
     * entry.S processes these Elf64_Rela entries at runtime to self-relocate
     * (fix up GOT entries, vtable pointers, etc.) when loaded at an arbitrary
     * kexec address. */
    .rela.dyn : {
        __rela_start = .;
        *(.rela.dyn .rela.dyn.*)
        __rela_end = .;
    }

    .data : {
        *(.data .data.*)
    }

    /* BSS must be last — zeroed by entry.S */
    __bss_start = .;
    .bss : {
        *(.bss .bss.*)
    }
    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
