// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal ELF64 parser for extracting PT_LOAD segments and the entry point.
//! Only handles little-endian x86_64 ELF executables.

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // Little-endian
const PT_LOAD: u32 = 1;

/// A loadable segment from the ELF.
pub struct LoadSegment {
    /// File offset of the segment data within the ELF.
    pub file_offset: usize,
    /// Target physical address to copy to.
    pub phys_addr: u64,
    /// Size of data in the file.
    pub file_size: usize,
    /// Size in memory (file_size + BSS zeroed portion).
    pub mem_size: usize,
}

/// Maximum number of PT_LOAD segments we support.
const MAX_SEGMENTS: usize = 16;

/// Result of parsing an ELF file.
pub struct ElfInfo {
    /// Entry point physical address.
    pub entry: u64,
    /// Loadable segments.
    pub segments: [LoadSegment; MAX_SEGMENTS],
    /// Number of valid entries in `segments`.
    pub num_segments: usize,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Parse an ELF64 binary and extract PT_LOAD segments and entry point.
///
/// # Panics
///
/// Panics if the ELF is malformed or not a valid x86_64 ELF64 executable.
pub fn parse_elf64(data: &[u8]) -> ElfInfo {
    // Validate ELF magic
    assert!(
        data.len() >= 64,
        "ELF file too small for header"
    );
    assert!(
        data[0..4] == ELF_MAGIC,
        "not an ELF file"
    );
    assert!(data[4] == ELFCLASS64, "not a 64-bit ELF");
    assert!(data[5] == ELFDATA2LSB, "not little-endian");

    let entry = read_u64(data, 0x18);
    let ph_off = read_u64(data, 0x20) as usize;
    let ph_entsize = read_u16(data, 0x36) as usize;
    let ph_num = read_u16(data, 0x38) as usize;

    assert!(
        ph_entsize >= 56,
        "program header entry too small"
    );

    let mut info = ElfInfo {
        entry,
        segments: core::array::from_fn(|_| LoadSegment {
            file_offset: 0,
            phys_addr: 0,
            file_size: 0,
            mem_size: 0,
        }),
        num_segments: 0,
    };

    for i in 0..ph_num {
        let off = ph_off + i * ph_entsize;
        let p_type = read_u32(data, off);

        if p_type != PT_LOAD {
            continue;
        }

        assert!(
            info.num_segments < MAX_SEGMENTS,
            "too many PT_LOAD segments"
        );

        let p_offset = read_u64(data, off + 0x08) as usize;
        let p_paddr = read_u64(data, off + 0x18);
        let p_filesz = read_u64(data, off + 0x20) as usize;
        let p_memsz = read_u64(data, off + 0x28) as usize;

        info.segments[info.num_segments] = LoadSegment {
            file_offset: p_offset,
            phys_addr: p_paddr,
            file_size: p_filesz,
            mem_size: p_memsz,
        };
        info.num_segments += 1;
    }

    assert!(info.num_segments > 0, "no PT_LOAD segments found");

    info
}
