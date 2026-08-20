// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

use std::path::PathBuf;

fn main() {
    build_rs_guest_arch::emit_guest_arch();

    // Embed the `kexec_stub` flat binary so guest-driven kexec servicing can
    // wrap an uncompressed vmlinux into a synthetic bzImage at runtime.
    //
    // Flowey sets `OPENVMM_KEXEC_STUB_BIN` to the objcopy'd flat binary when
    // building `openvmm_hcl`. When unset (e.g. plain `cargo build` or unit
    // tests), an empty placeholder is emitted so the crate still compiles; the
    // runtime vmlinux path then reports that the stub is unavailable.
    println!("cargo:rerun-if-env-changed=OPENVMM_KEXEC_STUB_BIN");
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dest = out_dir.join("kexec_stub.bin");
    match std::env::var_os("OPENVMM_KEXEC_STUB_BIN") {
        Some(src) => {
            let src = PathBuf::from(src);
            println!("cargo:rerun-if-changed={}", src.display());
            std::fs::copy(&src, &dest).unwrap_or_else(|e| {
                panic!(
                    "failed to copy kexec_stub binary from {}: {e}",
                    src.display()
                )
            });
        }
        None => {
            std::fs::write(&dest, []).expect("failed to write empty kexec_stub placeholder");
        }
    }
}
