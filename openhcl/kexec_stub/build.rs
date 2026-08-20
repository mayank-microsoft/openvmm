// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");

    if minimal_rt_build::init() {
        // Use a custom linker script to ensure _start is at offset 0
        // in the flat binary output.
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg=-T{manifest_dir}/link.x");
        println!("cargo:rerun-if-changed=link.x");

        // Keep the default PIE build. The binary contains R_X86_64_RELATIVE
        // relocations (for GOT entries, vtable pointers, etc.) which entry.S
        // processes at runtime to self-relocate when loaded at an arbitrary
        // kexec physical address. The .rela.dyn section is kept in a LOAD
        // segment by link.x so objcopy -O binary preserves it.
    }
}
