// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Embedded `kexec_stub` flat binary used by guest-driven kexec servicing when
//! the IGVM-supplied custom binary is an uncompressed vmlinux ELF.
//!
//! The bytes are produced by the `kexec_stub` crate (built as an x86_64
//! `minimal_rt` flat binary and objcopy'd to a raw binary) and wired in by
//! `build.rs` via the `OPENVMM_KEXEC_STUB_BIN` environment variable. When the
//! binary is not provided at build time, the slice is empty.

/// The embedded `kexec_stub` flat binary. Empty if not provided at build time.
pub const KEXEC_STUB_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kexec_stub.bin"));

/// Returns the embedded `kexec_stub` flat binary, or `None` if this build did
/// not embed one.
pub fn kexec_stub_bin() -> Option<&'static [u8]> {
    if KEXEC_STUB_BIN.is_empty() {
        None
    } else {
        Some(KEXEC_STUB_BIN)
    }
}
