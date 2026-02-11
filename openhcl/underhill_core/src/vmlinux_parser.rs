// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal parser for vmlinux / Linux kernel images.
//!
//! Supports two formats:
//! - **ELF64**: The standard vmlinux binary format for both x86_64 and aarch64.
//! - **ARM64 flat `Image`**: The flat binary format produced by `make Image` for
//!   aarch64, identified by the `ARM\x64` magic at offset 56.
//!
//! Extracts key information (entry point, architecture) from a kernel image
//! provided as a byte slice, without requiring `std::io::Read + Seek`. This is
//! useful for the dev servicing path where the image arrives as an in-memory
//! `Vec<u8>`.

use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::KnownLayout;

/// Errors that can occur while parsing a vmlinux / kernel image.
#[derive(Debug, Error)]
pub enum VmlinuxParserError {
    /// The image is too small to contain any recognized header.
    #[error("image too small (got {size} bytes, need at least {minimum})")]
    ImageTooSmall { size: usize, minimum: usize },
    /// The image does not start with a recognized magic number.
    #[error("unrecognized image format (not ELF64 and not ARM64 Image)")]
    UnrecognizedFormat,
    /// The ELF file is not a 64-bit image.
    #[error("not a 64-bit ELF (EI_CLASS = {0}, expected 2)")]
    Not64Bit(u8),
    /// The image uses big-endian byte order, which is not supported.
    #[error("big-endian image is not supported")]
    BigEndian,
    /// The ELF file is not an executable (ET_EXEC or ET_DYN).
    #[error("unexpected ELF type {0:#x} (expected ET_EXEC=2 or ET_DYN=3)")]
    UnexpectedElfType(u16),
    /// The machine type is not x86_64 or aarch64.
    #[error("unsupported ELF machine type {0:#x} (expected EM_X86_64=0x3e or EM_AARCH64=0xb7)")]
    UnsupportedMachine(u16),
    /// The entry point address is zero, which is unexpected for a kernel.
    #[error("entry point is zero")]
    ZeroEntryPoint,
    /// The ARM64 Image requires a page size other than 4K.
    #[error("ARM64 Image requires non-4K page size (flags page_size field = {0})")]
    Arm64UnsupportedPageSize(u8),
}

// ---------------------------------------------------------------------------
// ELF constants
// ---------------------------------------------------------------------------

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1; // Little-endian

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

const PT_LOAD: u32 = 1;

/// ELF64 file header, laid out exactly as it appears on disk (little-endian).
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct Elf64Header {
    /// ELF identification bytes.
    e_ident: [u8; 16],
    /// Object file type.
    e_type: u16,
    /// Architecture.
    e_machine: u16,
    /// Object file version.
    e_version: u32,
    /// Entry point virtual address.
    e_entry: u64,
    /// Program header table file offset.
    e_phoff: u64,
    /// Section header table file offset.
    e_shoff: u64,
    /// Processor-specific flags.
    e_flags: u32,
    /// ELF header size in bytes.
    e_ehsize: u16,
    /// Program header table entry size.
    e_phentsize: u16,
    /// Program header table entry count.
    e_phnum: u16,
    /// Section header table entry size.
    e_shentsize: u16,
    /// Section header table entry count.
    e_shnum: u16,
    /// Section header string table index.
    e_shstrndx: u16,
}

/// ELF64 program header, laid out exactly as it appears on disk (little-endian).
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct Elf64Phdr {
    /// Segment type.
    p_type: u32,
    /// Segment flags.
    p_flags: u32,
    /// Segment file offset.
    p_offset: u64,
    /// Segment virtual address.
    p_vaddr: u64,
    /// Segment physical address.
    p_paddr: u64,
    /// Segment size in file.
    p_filesz: u64,
    /// Segment size in memory (>= p_filesz; excess is BSS).
    p_memsz: u64,
    /// Segment alignment.
    p_align: u64,
}

// ---------------------------------------------------------------------------
// ARM64 flat Image constants & header
// ---------------------------------------------------------------------------

/// Magic bytes at offset 56 in an ARM64 `Image`: `"ARM\x64"`.
const ARM64_IMAGE_MAGIC: [u8; 4] = *b"ARM\x64";

/// ARM64 flat kernel `Image` header.
///
/// As specified by the Linux ARM64 boot protocol
/// (Documentation/arm64/booting.rst).
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct Arm64ImageHeader {
    /// Executable code (branch instruction).
    _code0: u32,
    /// Executable code.
    _code1: u32,
    /// Image load offset from start of 2MB-aligned RAM, little-endian.
    text_offset: u64,
    /// Effective image size, little-endian (0 means unknown).
    image_size: u64,
    /// Kernel flags, little-endian.
    ///   Bit 0: endianness (0 = LE, 1 = BE)
    ///   Bits 1-2: page size (0 = unspecified, 1 = 4K, 2 = 16K, 3 = 64K)
    ///   Bit 3: placement (0 = near DRAM base, 1 = anywhere)
    flags: u64,
    _res2: u64,
    _res3: u64,
    _res4: u64,
    /// Magic number: `ARM\x64`.
    magic: [u8; 4],
    /// Reserved (used for PE COFF offset).
    _res5: u32,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The target architecture of the kernel image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmlinuxArch {
    /// x86_64 / AMD64
    X86_64,
    /// AArch64 / ARM64
    Aarch64,
}

impl std::fmt::Display for VmlinuxArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmlinuxArch::X86_64 => write!(f, "x86_64"),
            VmlinuxArch::Aarch64 => write!(f, "aarch64"),
        }
    }
}

/// The format of the kernel image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmlinuxFormat {
    /// ELF64 executable (ET_EXEC) or shared object (ET_DYN / PIC).
    Elf64 {
        /// The ELF type field value (`ET_EXEC` = 2, `ET_DYN` = 3).
        e_type: u16,
    },
    /// ARM64 flat `Image` binary (with `ARM\x64` magic).
    Arm64Image {
        /// The `text_offset` field from the image header.
        text_offset: u64,
        /// The `image_size` field (0 means the actual file size should be used).
        image_size: u64,
    },
}

impl std::fmt::Display for VmlinuxFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmlinuxFormat::Elf64 { e_type } => match *e_type {
                ET_EXEC => write!(f, "ELF64 (ET_EXEC)"),
                ET_DYN => write!(f, "ELF64 (ET_DYN)"),
                other => write!(f, "ELF64 (type={other:#x})"),
            },
            VmlinuxFormat::Arm64Image { .. } => write!(f, "ARM64 Image"),
        }
    }
}

/// A single ELF PT_LOAD segment extracted from a vmlinux ELF binary.
#[derive(Debug, Clone)]
pub struct ElfSegment {
    /// File offset of the segment data.
    pub file_offset: u64,
    /// Virtual address the segment is linked at.
    pub vaddr: u64,
    /// Physical address the segment should be loaded at.
    pub paddr: u64,
    /// Size of the segment data in the file.
    pub file_size: u64,
    /// Size of the segment in memory (may be larger than `file_size`
    /// due to BSS).
    pub mem_size: u64,
}

/// Information extracted from a vmlinux / kernel image.
#[derive(Debug, Clone)]
pub struct VmlinuxInfo {
    /// The kernel entry point virtual address.
    ///
    /// For ELF images, this is `e_entry` from the ELF header.
    /// For ARM64 flat images, this is `text_offset` (the entry point is at
    /// the start of the image, loaded at a 2MB-aligned base + text_offset).
    pub entry_point: u64,
    /// The target architecture.
    pub arch: VmlinuxArch,
    /// The image format.
    pub format: VmlinuxFormat,
    /// PT_LOAD segments from an ELF binary. Empty for ARM64 Image format.
    pub segments: Vec<ElfSegment>,
}
 
/// Parses a vmlinux / kernel image from raw bytes and extracts key information
/// including the kernel entry point.
///
/// The parser auto-detects the format by checking magic bytes:
/// - If the first 4 bytes are `\x7fELF`, it is parsed as an ELF64 binary.
/// - If the 4 bytes at offset 56 are `ARM\x64`, it is parsed as an ARM64
///   flat `Image`.
///
/// # Arguments
///
/// * `data` - The raw bytes of the kernel image.
///
/// # Returns
///
/// A [`VmlinuxInfo`] containing the entry point address, architecture,
/// and detected format.
///
/// # Errors
///
/// Returns a [`VmlinuxParserError`] if the image cannot be recognized or
/// has invalid/unsupported properties.
pub fn parse_vmlinux(data: &[u8]) -> Result<VmlinuxInfo, VmlinuxParserError> {
    // Check ELF magic first (at offset 0).
    if data.len() >= 4 && data[..4] == ELF_MAGIC {
        return parse_elf64(data);
    }

    // Check ARM64 Image magic (at offset 56).
    if data.len() >= size_of::<Arm64ImageHeader>() {
        let header = Arm64ImageHeader::ref_from_prefix(data)
            .map(|(h, _)| h)
            .ok();
        if let Some(header) = header {
            if header.magic == ARM64_IMAGE_MAGIC {
                return parse_arm64_image(header, data);
            }
        }
    }

    // Neither format matched.
    if data.len() < size_of::<Elf64Header>().min(size_of::<Arm64ImageHeader>()) {
        return Err(VmlinuxParserError::ImageTooSmall {
            size: data.len(),
            minimum: size_of::<Elf64Header>().min(size_of::<Arm64ImageHeader>()),
        });
    }
    Err(VmlinuxParserError::UnrecognizedFormat)
}

/// Parse the image as an ELF64 binary.
fn parse_elf64(data: &[u8]) -> Result<VmlinuxInfo, VmlinuxParserError> {
    let header = Elf64Header::ref_from_prefix(data)
        .map(|(header, _rest)| header)
        .map_err(|_| VmlinuxParserError::ImageTooSmall {
            size: data.len(),
            minimum: size_of::<Elf64Header>(),
        })?;

    // Must be 64-bit.
    if header.e_ident[4] != ELFCLASS64 {
        return Err(VmlinuxParserError::Not64Bit(header.e_ident[4]));
    }

    // Must be little-endian.
    if header.e_ident[5] != ELFDATA2LSB {
        return Err(VmlinuxParserError::BigEndian);
    }

    // Must be an executable or shared object (for PIC kernels).
    let e_type = header.e_type;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(VmlinuxParserError::UnexpectedElfType(e_type));
    }

    // Determine architecture.
    let arch = match header.e_machine {
        EM_X86_64 => VmlinuxArch::X86_64,
        EM_AARCH64 => VmlinuxArch::Aarch64,
        other => return Err(VmlinuxParserError::UnsupportedMachine(other)),
    };

    let entry_point = header.e_entry;
    if entry_point == 0 {
        return Err(VmlinuxParserError::ZeroEntryPoint);
    }

    // Extract PT_LOAD segments from program headers.
    let mut segments = Vec::new();
    let ph_offset = header.e_phoff as usize;
    let ph_entsize = header.e_phentsize as usize;
    let ph_num = header.e_phnum as usize;

    for i in 0..ph_num {
        let off = ph_offset + i * ph_entsize;
        if let Some((phdr, _)) = Elf64Phdr::ref_from_prefix(&data[off..]).ok() {
            if phdr.p_type == PT_LOAD {
                segments.push(ElfSegment {
                    file_offset: phdr.p_offset,
                    vaddr: phdr.p_vaddr,
                    paddr: phdr.p_paddr,
                    file_size: phdr.p_filesz,
                    mem_size: phdr.p_memsz,
                });
            }
        }
    }

    Ok(VmlinuxInfo {
        entry_point,
        arch,
        format: VmlinuxFormat::Elf64 { e_type },
        segments,
    })
}

/// Parse the image as an ARM64 flat `Image` binary.
fn parse_arm64_image(
    header: &Arm64ImageHeader,
    _data: &[u8],
) -> Result<VmlinuxInfo, VmlinuxParserError> {
    // Bit 0 of flags: endianness (0 = LE, 1 = BE).
    if header.flags & 1 != 0 {
        return Err(VmlinuxParserError::BigEndian);
    }

    // Bits 1-2 of flags: page size.
    // 0 = unspecified (acceptable), 1 = 4K (acceptable), 2 = 16K, 3 = 64K.
    let page_size_field = ((header.flags >> 1) & 0x3) as u8;
    if page_size_field > 1 {
        return Err(VmlinuxParserError::Arm64UnsupportedPageSize(
            page_size_field,
        ));
    }

    // For ARM64 Image, the entry point is at the base load address + text_offset.
    // The actual absolute address depends on where the image is loaded in RAM,
    // so we report text_offset as the entry point (relative to the 2MB-aligned
    // load base).
    let entry_point = header.text_offset;

    Ok(VmlinuxInfo {
        entry_point,
        arch: VmlinuxArch::Aarch64,
        format: VmlinuxFormat::Arm64Image {
            text_offset: header.text_offset,
            image_size: header.image_size,
        },
        segments: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ELF64 header for testing.
    fn make_elf64_header(machine: u16, entry: u64, elf_type: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 64];

        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS64; // EI_CLASS
        buf[5] = ELFDATA2LSB; // EI_DATA
        buf[6] = 1; // EI_VERSION = EV_CURRENT

        // e_type
        buf[16..18].copy_from_slice(&elf_type.to_le_bytes());
        // e_machine
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        // e_version
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        buf[24..32].copy_from_slice(&entry.to_le_bytes());

        buf
    }

    /// Build a minimal valid ARM64 flat Image header for testing.
    fn make_arm64_image(text_offset: u64, image_size: u64, flags: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 64];

        // _code0, _code1: branch instructions (don't matter for parsing)
        // text_offset at offset 8
        buf[8..16].copy_from_slice(&text_offset.to_le_bytes());
        // image_size at offset 16
        buf[16..24].copy_from_slice(&image_size.to_le_bytes());
        // flags at offset 24
        buf[24..32].copy_from_slice(&flags.to_le_bytes());
        // magic "ARM\x64" at offset 56
        buf[56..60].copy_from_slice(&ARM64_IMAGE_MAGIC);

        buf
    }

    // -----------------------------------------------------------------------
    // ELF64 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_x86_64_kernel() {
        let data = make_elf64_header(EM_X86_64, 0x100_0000, ET_EXEC);
        let info = parse_vmlinux(&data).unwrap();
        assert_eq!(info.entry_point, 0x100_0000);
        assert_eq!(info.arch, VmlinuxArch::X86_64);
        assert!(matches!(info.format, VmlinuxFormat::Elf64 { e_type: ET_EXEC }));
    }

    #[test]
    fn test_valid_aarch64_elf_kernel() {
        let data = make_elf64_header(EM_AARCH64, 0xffff_8000_0008_0000, ET_EXEC);
        let info = parse_vmlinux(&data).unwrap();
        assert_eq!(info.entry_point, 0xffff_8000_0008_0000);
        assert_eq!(info.arch, VmlinuxArch::Aarch64);
        assert!(matches!(info.format, VmlinuxFormat::Elf64 { e_type: ET_EXEC }));
    }

    #[test]
    fn test_pic_kernel_dyn() {
        let data = make_elf64_header(EM_X86_64, 0x100_0000, ET_DYN);
        let info = parse_vmlinux(&data).unwrap();
        assert!(matches!(info.format, VmlinuxFormat::Elf64 { e_type: ET_DYN }));
    }

    #[test]
    fn test_too_small() {
        let data = vec![0u8; 32];
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::ImageTooSmall { .. }));
    }

    #[test]
    fn test_unrecognized_format() {
        // 64 bytes of zeros — no ELF magic, no ARM64 magic.
        let data = vec![0u8; 64];
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::UnrecognizedFormat));
    }

    #[test]
    fn test_32bit_elf_rejected() {
        let mut data = make_elf64_header(EM_X86_64, 0x100_0000, ET_EXEC);
        data[4] = 1; // ELFCLASS32
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::Not64Bit(1)));
    }

    #[test]
    fn test_big_endian_elf_rejected() {
        let mut data = make_elf64_header(EM_X86_64, 0x100_0000, ET_EXEC);
        data[5] = 2; // ELFDATA2MSB
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::BigEndian));
    }

    #[test]
    fn test_unsupported_machine() {
        let data = make_elf64_header(0x03 /* EM_386 */, 0x100_0000, ET_EXEC);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::UnsupportedMachine(0x03)));
    }

    #[test]
    fn test_zero_entry_point() {
        let data = make_elf64_header(EM_X86_64, 0, ET_EXEC);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::ZeroEntryPoint));
    }

    #[test]
    fn test_unexpected_elf_type() {
        let data = make_elf64_header(EM_X86_64, 0x100_0000, 1 /* ET_REL */);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::UnexpectedElfType(1)));
    }

    // -----------------------------------------------------------------------
    // ARM64 flat Image tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_arm64_image() {
        // flags: LE (bit0=0), 4K pages (bits1-2=1), any placement (bit3=1) = 0b1010 = 0xA
        let data = make_arm64_image(0x0, 0x100_0000, 0xA);
        let info = parse_vmlinux(&data).unwrap();
        assert_eq!(info.arch, VmlinuxArch::Aarch64);
        assert_eq!(info.entry_point, 0x0);
        assert!(matches!(
            info.format,
            VmlinuxFormat::Arm64Image {
                text_offset: 0x0,
                image_size: 0x100_0000,
            }
        ));
    }

    #[test]
    fn test_arm64_image_with_text_offset() {
        // flags: LE, unspecified page size (0), any placement = 0b1000 = 0x8
        let data = make_arm64_image(0x8_0000, 0x200_0000, 0x8);
        let info = parse_vmlinux(&data).unwrap();
        assert_eq!(info.entry_point, 0x8_0000);
        assert!(matches!(
            info.format,
            VmlinuxFormat::Arm64Image {
                text_offset: 0x8_0000,
                image_size: 0x200_0000,
            }
        ));
    }

    #[test]
    fn test_arm64_image_big_endian_rejected() {
        // flags bit 0 = 1 means BE
        let data = make_arm64_image(0x0, 0x100_0000, 0x1);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(err, VmlinuxParserError::BigEndian));
    }

    #[test]
    fn test_arm64_image_16k_page_rejected() {
        // flags: LE, 16K pages (bits1-2=2), any placement = 0b1100 = 0xC
        let data = make_arm64_image(0x0, 0x100_0000, 0xC);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(
            err,
            VmlinuxParserError::Arm64UnsupportedPageSize(2)
        ));
    }

    #[test]
    fn test_arm64_image_64k_page_rejected() {
        // flags: LE, 64K pages (bits1-2=3), any placement = 0b1110 = 0xE
        let data = make_arm64_image(0x0, 0x100_0000, 0xE);
        let err = parse_vmlinux(&data).unwrap_err();
        assert!(matches!(
            err,
            VmlinuxParserError::Arm64UnsupportedPageSize(3)
        ));
    }

    #[test]
    fn test_arm64_image_unspecified_page_ok() {
        // flags: LE, unspecified page size (bits1-2=0), any placement = 0b1000 = 0x8
        let data = make_arm64_image(0x0, 0x100_0000, 0x8);
        let info = parse_vmlinux(&data).unwrap();
        assert_eq!(info.arch, VmlinuxArch::Aarch64);
    }

    #[test]
    fn test_arm64_image_zero_image_size() {
        // image_size=0 is valid (means use actual file length).
        let data = make_arm64_image(0x0, 0, 0xA);
        let info = parse_vmlinux(&data).unwrap();
        assert!(matches!(
            info.format,
            VmlinuxFormat::Arm64Image {
                image_size: 0,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Format display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_display() {
        assert_eq!(
            format!("{}", VmlinuxFormat::Elf64 { e_type: ET_EXEC }),
            "ELF64 (ET_EXEC)"
        );
        assert_eq!(
            format!("{}", VmlinuxFormat::Elf64 { e_type: ET_DYN }),
            "ELF64 (ET_DYN)"
        );
        assert_eq!(
            format!(
                "{}",
                VmlinuxFormat::Arm64Image {
                    text_offset: 0,
                    image_size: 0
                }
            ),
            "ARM64 Image"
        );
    }
}
