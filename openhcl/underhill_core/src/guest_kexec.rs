// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest-driven servicing via `kexec_file_load`.
//!
//! This module handles extracting the vmlinuz and initrd from the received
//! IGVM, building a CPIO overlay with serialized device state, and invoking
//! `kexec_file_load` to boot into the new kernel.


#![allow(unsafe_code)]

use anyhow::Context;

/// Path in the initramfs where the serialized device state is stored.
pub const DEV_SERVICING_STATE_PATH: &str = "/openhcl/dev_servicing_state.bin";

/// Kernel command line marker indicating this is a servicing boot.
pub const DEV_SERVICING_CMDLINE_MARKER: &str = "OPENHCL_SERVICING_COMPLETED=1";

/// Extract a contiguous byte region from IGVM PageData directives.
///
/// Collects all PageData entries whose GPA falls in `[region_base, region_base + region_size)`,
/// sorts by GPA, concatenates, and truncates to exactly `region_size` bytes.
pub fn extract_region_from_igvm(
    directives: &[igvm::IgvmDirectiveHeader],
    region_base: u64,
    region_size: u64,
) -> Vec<u8> {
    let mut pages: Vec<(u64, &[u8])> = Vec::new();
    for d in directives {
        if let igvm::IgvmDirectiveHeader::PageData { gpa, data, .. } = d {
            if *gpa >= region_base && *gpa < region_base + region_size {
                pages.push((*gpa, data));
            }
        }
    }
    pages.sort_by_key(|(gpa, _)| *gpa);

    let mut result = Vec::with_capacity(region_size as usize);
    for (_, data) in pages {
        result.extend_from_slice(data);
    }
    result.truncate(region_size as usize);
    result
}

/// Build a minimal CPIO "newc" archive containing a single file.
///
/// The archive follows the SVR4 "newc" format (magic "070701") and includes
/// a proper CPIO trailer. This is compatible with the Linux kernel's
/// `unpack_to_rootfs()` which supports concatenated initramfs archives.
pub fn build_cpio_archive(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut archive = Vec::new();

    // File entry
    write_cpio_entry(&mut archive, path, contents);

    // Trailer entry
    write_cpio_entry(&mut archive, "TRAILER!!!", &[]);

    archive
}

fn write_cpio_entry(archive: &mut Vec<u8>, name: &str, data: &[u8]) {
    let name_with_nul = format!("{}\0", name);
    let namesize = name_with_nul.len();

    let header = format!(
        "070701\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}",
        0u32,           // ino
        0o100644u32,    // mode (regular file)
        0u32,           // uid
        0u32,           // gid
        1u32,           // nlink
        0u32,           // mtime
        data.len(),     // filesize
        0u32,           // devmajor
        0u32,           // devminor
        0u32,           // rdevmajor
        0u32,           // rdevminor
        namesize,       // namesize
        0u32,           // checksum
    );
    assert_eq!(header.len(), 110, "CPIO header must be 110 bytes");

    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(name_with_nul.as_bytes());

    // Pad name to 4-byte boundary (header + name must be 4-byte aligned)
    let header_plus_name = 110 + namesize;
    let name_pad = (4 - (header_plus_name % 4)) % 4;
    archive.extend(std::iter::repeat(0u8).take(name_pad));

    // File data
    archive.extend_from_slice(data);

    // Pad data to 4-byte boundary
    let data_pad = (4 - (data.len() % 4)) % 4;
    archive.extend(std::iter::repeat(0u8).take(data_pad));
}

/// Build the augmented command line for the kexec'd kernel.
///
/// Takes the current kernel's cmdline and appends the servicing marker.
pub fn build_servicing_cmdline(current_cmdline: &str) -> String {
    let mut cmdline = current_cmdline.trim().to_string();
    if !cmdline.is_empty() {
        cmdline.push(' ');
    }
    cmdline.push_str(DEV_SERVICING_CMDLINE_MARKER);
    cmdline
}

/// Check if the current boot is a servicing boot (post-kexec).
pub fn is_servicing_boot(cmdline: &str) -> bool {
    cmdline.contains(DEV_SERVICING_CMDLINE_MARKER)
}

/// Create a memfd, write data to it, and return the raw fd.
pub fn create_memfd_with_data(name: &str, data: &[u8]) -> anyhow::Result<i32> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::FromRawFd;

    let c_name = CString::new(name).context("invalid memfd name")?;

    // SAFETY: memfd_create is a well-defined Linux syscall.
    let fd = unsafe { libc::memfd_create(c_name.as_ptr(), libc::MFD_CLOEXEC) };
    anyhow::ensure!(fd >= 0, "memfd_create failed: {}", std::io::Error::last_os_error());

    // SAFETY: fd is a valid file descriptor from memfd_create.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(data).context("failed to write to memfd")?;

    // Seek back to start so kexec_file_load reads from the beginning.
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(0))?;

    // Leak the File so the fd stays open (kexec_file_load needs it).
    let fd = std::os::fd::IntoRawFd::into_raw_fd(file);
    Ok(fd)
}
/// Abstraction over VM operations needed during the kexec blackout phase.
///
/// This trait allows the kexec orchestration to call stop/save/shutdown
/// without depending on `LoadedVm` directly, making the flow unit-testable.
#[async_trait::async_trait]
pub trait ServicingContext {
    /// Stop all VPs. Returns true if the VM was running.
    async fn stop_vps(&mut self) -> bool;

    /// Save all device state.
    async fn save_state(&mut self) -> anyhow::Result<Vec<u8>>;

    /// Write persisted info (NVMe interrupt state, etc.) for boot shim.
    fn write_persisted_info(&self, saved_state_bytes: &[u8]) -> anyhow::Result<()>;

    /// Shutdown all devices (MANA, NVMe, PCI).
    async fn shutdown_devices(&mut self);

    /// Read the current kernel command line.
    fn read_current_cmdline(&self) -> anyhow::Result<String>;
}

/// Result of parsing the IGVM for kexec servicing.
pub struct ParsedIgvmForKexec {
    /// The vmlinuz (bzImage) bytes extracted from the IGVM.
    pub vmlinuz: Vec<u8>,
    /// The initrd bytes extracted from the IGVM.
    pub initrd: Vec<u8>,
}

/// Parse the received IGVM and extract the vmlinuz and initrd.
///
/// Scans PageData directives for the ParavisorMeasuredVtl2Config (magic
/// `0x4F48434C56544C32`), then reassembles the vmlinuz and initrd from
/// page data in the corresponding GPA ranges.
pub fn parse_igvm_for_kexec(igvm_data: &[u8]) -> anyhow::Result<ParsedIgvmForKexec> {
    let igvm_file = igvm::IgvmFile::new_from_binary(igvm_data, None)
        .map_err(|e| anyhow::anyhow!("failed to parse IGVM: {}", e))?;

    let directives = igvm_file.directives();

    // Find ParavisorMeasuredVtl2Config by scanning for magic.
    let mut initrd_base: u64 = 0;
    let mut initrd_size: u64 = 0;
    let mut custom_binary_base: u64 = 0;
    let mut custom_binary_size: u64 = 0;
    let mut found_config = false;

    for directive in directives {
        if let igvm::IgvmDirectiveHeader::PageData { data, .. } = directive {
            if data.len() >= 48 {
                let magic = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
                if magic == 0x4F48434C56544C32 {
                    initrd_base = u64::from_le_bytes(data[16..24].try_into().unwrap_or([0; 8]));
                    initrd_size = u64::from_le_bytes(data[24..32].try_into().unwrap_or([0; 8]));
                    custom_binary_base =
                        u64::from_le_bytes(data[32..40].try_into().unwrap_or([0; 8]));
                    custom_binary_size =
                        u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
                    found_config = true;

                    tracing::info!(
                        initrd_base = format!("{:#x}", initrd_base),
                        initrd_size,
                        custom_binary_base = format!("{:#x}", custom_binary_base),
                        custom_binary_size,
                        "found ParavisorMeasuredVtl2Config in IGVM"
                    );
                    break;
                }
            }
        }
    }

    anyhow::ensure!(found_config, "ParavisorMeasuredVtl2Config not found in IGVM");
    anyhow::ensure!(custom_binary_size > 0, "no vmlinuz (custom_binary) in IGVM");
    anyhow::ensure!(initrd_size > 0, "no initrd in IGVM");

    let vmlinuz = extract_region_from_igvm(directives, custom_binary_base, custom_binary_size);
    let initrd = extract_region_from_igvm(directives, initrd_base, initrd_size);

    tracing::info!(
        vmlinuz_size = vmlinuz.len(),
        initrd_size = initrd.len(),
        "extracted vmlinuz and initrd from IGVM"
    );

    Ok(ParsedIgvmForKexec { vmlinuz, initrd })
}

/// Execute the full guest-driven kexec servicing flow.
///
/// This is the main orchestration function:
/// 1. Parse IGVM  extract vmlinuz + initrd
/// 2. Blackout: stop VPs  save state  shutdown devices
/// 3. Serialize state  CPIO  append to initrd
/// 4. Build cmdline with servicing marker
/// 5. Write to memfds  kexec_file_load  kexec_reboot
///
/// On success, this function does not return.
pub async fn execute_guest_driven_servicing(
    ctx: &mut dyn ServicingContext,
    igvm_data: &[u8],
) -> anyhow::Result<()> {
    // --- PRE-BLACKOUT: Parse IGVM ---
    let parsed = parse_igvm_for_kexec(igvm_data)?;
    let vmlinuz = parsed.vmlinuz;
    let mut initrd = parsed.initrd;

    // --- BLACKOUT PHASE ---
    let was_running = ctx.stop_vps().await;
    tracing::info!(was_running, "blackout: VPs stopped");

    let saved_state_bytes = ctx.save_state().await?;
    tracing::info!(state_size = saved_state_bytes.len(), "blackout: state saved");

    ctx.write_persisted_info(&saved_state_bytes)?;

    ctx.shutdown_devices().await;
    tracing::info!("blackout: devices shut down");

    // Serialize state  CPIO  append to initrd
    let cpio = build_cpio_archive(DEV_SERVICING_STATE_PATH, &saved_state_bytes);
    let pad = (4 - (initrd.len() % 4)) % 4;
    initrd.extend(std::iter::repeat(0u8).take(pad));
    initrd.extend_from_slice(&cpio);

    tracing::info!(
        cpio_size = cpio.len(),
        initrd_final_size = initrd.len(),
        "blackout: state serialized into initrd"
    );

    // Build cmdline
    let current_cmdline = ctx.read_current_cmdline()?;
    let cmdline = build_servicing_cmdline(&current_cmdline);

    // Write to memfds using libc
    let kernel_fd = create_memfd_with_data("vmlinuz", &vmlinuz)?;
    let initrd_fd = create_memfd_with_data("initrd", &initrd)?;

    tracing::info!("blackout: invoking kexec_file_load");

    kexec_sys::kexec_file_load(
        kernel_fd,
        initrd_fd,
        &cmdline,
        kexec_sys::KEXEC_FILE_FORCE_DTB | kexec_sys::KEXEC_FILE_DEBUG,
    )?;

    tracing::info!("blackout: kexec loaded, triggering reboot");
    kexec_sys::kexec_reboot()?;

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_region_basic() {
        use igvm::IgvmDirectiveHeader;
        let directives = vec![
            IgvmDirectiveHeader::PageData {
                gpa: 0x1000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xAA; 4096],
            },
            IgvmDirectiveHeader::PageData {
                gpa: 0x2000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xBB; 4096],
            },
        ];

        let result = extract_region_from_igvm(&directives, 0x1000, 8192);
        assert_eq!(result.len(), 8192);
        assert!(result[..4096].iter().all(|&b| b == 0xAA));
        assert!(result[4096..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_extract_region_sorted() {
        use igvm::IgvmDirectiveHeader;
        // Pages in reverse GPA order
        let directives = vec![
            IgvmDirectiveHeader::PageData {
                gpa: 0x2000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xBB; 4096],
            },
            IgvmDirectiveHeader::PageData {
                gpa: 0x1000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xAA; 4096],
            },
        ];

        let result = extract_region_from_igvm(&directives, 0x1000, 8192);
        assert_eq!(result.len(), 8192);
        assert!(result[..4096].iter().all(|&b| b == 0xAA), "first page should be 0xAA");
        assert!(result[4096..].iter().all(|&b| b == 0xBB), "second page should be 0xBB");
    }

    #[test]
    fn test_extract_region_truncated() {
        use igvm::IgvmDirectiveHeader;
        let directives = vec![
            IgvmDirectiveHeader::PageData {
                gpa: 0x1000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xCC; 4096],
            },
        ];

        // Request only 100 bytes from a 4096-byte page
        let result = extract_region_from_igvm(&directives, 0x1000, 100);
        assert_eq!(result.len(), 100);
        assert!(result.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn test_extract_region_empty() {
        use igvm::IgvmDirectiveHeader;
        let directives = vec![
            IgvmDirectiveHeader::PageData {
                gpa: 0x5000,
                compatibility_mask: 1,
                flags: igvm_defs::IgvmPageDataFlags::new(),
                data_type: igvm_defs::IgvmPageDataType::NORMAL,
                data: vec![0xFF; 4096],
            },
        ];

        // Request a region that doesn't overlap any pages
        let result = extract_region_from_igvm(&directives, 0x1000, 4096);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_build_cpio_archive_basic() {
        let archive = build_cpio_archive("/test/file.bin", b"hello world");
        let archive_str = String::from_utf8_lossy(&archive);
        assert!(archive_str.contains("070701"), "must have CPIO newc magic");
        assert!(archive_str.contains("TRAILER!!!"), "must have trailer");
        // Verify the file content is in the archive
        assert!(archive.windows(11).any(|w| w == b"hello world"));
    }

    #[test]
    fn test_build_cpio_archive_alignment() {
        let archive = build_cpio_archive("/a", b"x");
        // Total size must be 4-byte aligned
        assert_eq!(archive.len() % 4, 0, "archive must be 4-byte aligned");
    }

    #[test]
    fn test_build_servicing_cmdline() {
        let cmdline = build_servicing_cmdline("console=ttyS0 loglevel=8");
        assert!(cmdline.contains("console=ttyS0"));
        assert!(cmdline.contains(DEV_SERVICING_CMDLINE_MARKER));
    }

    #[test]
    fn test_build_servicing_cmdline_empty() {
        let cmdline = build_servicing_cmdline("");
        assert_eq!(cmdline, DEV_SERVICING_CMDLINE_MARKER);
    }

    #[test]
    fn test_is_servicing_boot_true() {
        assert!(is_servicing_boot("console=ttyS0 OPENHCL_SERVICING_COMPLETED=1 loglevel=8"));
    }

    #[test]
    fn test_is_servicing_boot_false() {
        assert!(!is_servicing_boot("console=ttyS0 loglevel=8"));
    }
}