// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal x86_64 Linux boot_params accessors for the kexec stub.
//!
//! Instead of reproducing the full 4096-byte boot_params struct with all
//! padding, we use a flat byte array with accessor methods for the fields
//! the stub reads and writes. Field offsets match the Linux kernel's
//! arch/x86/include/uapi/asm/bootparam.h.

/// The e820 memory map entry (20 bytes).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub typ: u32,
}

/// A 4096-byte boot_params, accessed by raw offsets.
#[repr(C, align(4096))]
#[derive(Copy, Clone)]
pub struct BootParams {
    pub data: [u8; 4096],
}

// Field offsets within boot_params.
const OFF_EXT_RAMDISK_IMAGE: usize = 0x0C0;
const OFF_EXT_RAMDISK_SIZE: usize = 0x0C4;
const OFF_E820_ENTRIES: usize = 0x1E8;
// setup_header fields (within hdr at 0x1F1).
const OFF_TYPE_OF_LOADER: usize = 0x210;
const OFF_RAMDISK_IMAGE: usize = 0x218;
const OFF_RAMDISK_SIZE: usize = 0x21C;
const OFF_CMD_LINE_PTR: usize = 0x228;
const OFF_HARDWARE_SUBARCH: usize = 0x23C;
const OFF_PAYLOAD_OFFSET: usize = 0x248;
const OFF_PAYLOAD_LENGTH: usize = 0x24C;
const OFF_SETUP_DATA: usize = 0x250;
// e820 map starts at 0x2D0 (after edd_mbr_sig_buffer at 0x290).
const OFF_E820_MAP: usize = 0x2D0;

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn write_u32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_ne_bytes());
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes([
        data[off], data[off + 1], data[off + 2], data[off + 3],
        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
    ])
}

/// E820 type: usable RAM.
pub const E820_TYPE_RAM: u32 = 1;

/// Maximum number of e820 entries in boot_params.
const MAX_E820_ENTRIES: usize = 128;

impl BootParams {
    /// Ramdisk physical address (combining ramdisk_image + ext_ramdisk_image).
    pub fn ramdisk_addr(&self) -> u64 {
        read_u32(&self.data, OFF_RAMDISK_IMAGE) as u64
            | ((read_u32(&self.data, OFF_EXT_RAMDISK_IMAGE) as u64) << 32)
    }

    /// Ramdisk size (combining ramdisk_size + ext_ramdisk_size).
    pub fn ramdisk_size(&self) -> u64 {
        read_u32(&self.data, OFF_RAMDISK_SIZE) as u64
            | ((read_u32(&self.data, OFF_EXT_RAMDISK_SIZE) as u64) << 32)
    }

    /// Set the ramdisk address.
    pub fn set_ramdisk_addr(&mut self, addr: u64) {
        write_u32(&mut self.data, OFF_RAMDISK_IMAGE, addr as u32);
        write_u32(&mut self.data, OFF_EXT_RAMDISK_IMAGE, (addr >> 32) as u32);
    }

    /// Set the ramdisk size.
    pub fn set_ramdisk_size(&mut self, size: u64) {
        write_u32(&mut self.data, OFF_RAMDISK_SIZE, size as u32);
        write_u32(&mut self.data, OFF_EXT_RAMDISK_SIZE, (size >> 32) as u32);
    }

    /// Set hardware_subarch.
    pub fn set_hardware_subarch(&mut self, val: u32) {
        write_u32(&mut self.data, OFF_HARDWARE_SUBARCH, val);
    }

    /// Set type_of_loader.
    pub fn set_type_of_loader(&mut self, val: u8) {
        self.data[OFF_TYPE_OF_LOADER] = val;
    }

    /// Payload offset within the PM kernel (set by construct_bzimage_header).
    pub fn payload_offset(&self) -> u32 {
        read_u32(&self.data, OFF_PAYLOAD_OFFSET)
    }

    /// Payload length (packed blob size).
    pub fn payload_length(&self) -> u32 {
        read_u32(&self.data, OFF_PAYLOAD_LENGTH)
    }

    /// Number of e820 entries.
    pub fn e820_entries(&self) -> u8 {
        self.data[OFF_E820_ENTRIES]
    }

    /// Add an e820 entry. Panics if the table is full.
    pub fn add_e820_entry(&mut self, addr: u64, size: u64, typ: u32) {
        let idx = self.data[OFF_E820_ENTRIES] as usize;
        assert!(idx < MAX_E820_ENTRIES, "e820 table full");
        let off = OFF_E820_MAP + idx * 20;
        self.data[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        self.data[off + 8..off + 16].copy_from_slice(&size.to_le_bytes());
        self.data[off + 16..off + 20].copy_from_slice(&typ.to_le_bytes());
        self.data[OFF_E820_ENTRIES] = (idx + 1) as u8;
    }
}
