//! Load crabefi-mm into the SMRAM area coreboot reserves for the payload
//! (coreboot `drivers/payload_mm_interface`, `PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE`).
//!
//! coreboot accepts exactly one load per boot. This runs before any third-party
//! code, so nothing else can claim the payload MM area first.

use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::tables::{BootMediaInfo, PayloadMmInfo};

static MM_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload_mm.img"));

const PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE: u32 = 1;
const PLD_MM_LOAD_CONTEXT_REVISION: u8 = 1;

/// coreboot `struct payload_mm_load_context`.
#[repr(C, packed)]
struct LoadContext {
    header_size: u16,
    header_revision: u8,
    reserved: u8,
    mm_core_source_address: u64,
    mm_core_destination_address: u32,
    mm_core_size: u32,
    mm_entrypoint_offset: u32,
    mm_entrypoint_arg1: u64,
    mm_entrypoint_arg2: u64,
    mm_entrypoint_arg3: u64,
    implementation_private_data: u64,
}

/// crabefi-mm `InitConfig` (passed as `arg1`, copied by MM at init).
#[repr(C)]
struct InitConfig {
    magic: u64,
    version: u32,
    size: u32,
    mm_area_base: u64,
    mm_area_size: u64,
    comm_base: u64,
    comm_size: u64,
    flash_base: u64,
    flash_size: u64,
    store_offset: u64,
    store_size: u64,
}

const INIT_MAGIC: u64 = 0x4749_4643_4d4d_4243; // "CBMMCFIG"

const STAGING_SIZE: usize = 512 * 1024;
const COMM_SIZE: usize = 64 * 1024 + 4096;

#[repr(C, align(4096))]
struct Staging([u8; STAGING_SIZE]);
#[repr(C, align(4096))]
struct Comm([u8; COMM_SIZE]);

// Payload .bss lies below 4 GiB, where coreboot's SMM can reach it.
static mut STAGING: Staging = Staging([0; STAGING_SIZE]);
static mut COMM: Comm = Comm([0; COMM_SIZE]);
static mut LOAD_CONTEXT: LoadContext = LoadContext {
    header_size: 0,
    header_revision: 0,
    reserved: 0,
    mm_core_source_address: 0,
    mm_core_destination_address: 0,
    mm_core_size: 0,
    mm_entrypoint_offset: 0,
    mm_entrypoint_arg1: 0,
    mm_entrypoint_arg2: 0,
    mm_entrypoint_arg3: 0,
    implementation_private_data: 0,
};
static mut INIT_CONFIG: InitConfig = InitConfig {
    magic: 0,
    version: 0,
    size: 0,
    mm_area_base: 0,
    mm_area_size: 0,
    comm_base: 0,
    comm_size: 0,
    flash_base: 0,
    flash_size: 0,
    store_offset: 0,
    store_size: 0,
};

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Find an FMAP area (offset, size) in the memory-mapped flash.
fn fmap_area(flash_base: u64, fmap_offset: u64, name: &[u8]) -> Option<(u64, u64)> {
    let fmap = (flash_base + fmap_offset) as *const u8;
    let read = |offset: usize, buf: &mut [u8]| {
        for (i, byte) in buf.iter_mut().enumerate() {
            // SAFETY: the FMAP lies in the memory-mapped flash coreboot described.
            *byte = unsafe { read_volatile(fmap.add(offset + i)) };
        }
    };
    let mut header = [0u8; 56];
    read(0, &mut header);
    if &header[..8] != b"__FMAP__" {
        return None;
    }
    let areas = u16::from_le_bytes([header[54], header[55]]) as usize;
    for i in 0..areas.min(64) {
        let mut area = [0u8; 42];
        read(56 + i * 42, &mut area);
        let area_name = &area[8..40];
        let len = area_name.iter().position(|&b| b == 0).unwrap_or(32);
        if &area_name[..len] == name {
            return Some((read_u32(&area, 0)? as u64, read_u32(&area, 4)? as u64));
        }
    }
    None
}

/// Load the MM image and route flash writes through it. Returns an error string
/// when payload MM is not available or the load fails; flash access then stays
/// as before (direct, and read-only if the platform locked writes to SMM).
pub fn load(mm: &PayloadMmInfo, boot_media: Option<BootMediaInfo>) -> Result<(), &'static str> {
    let (Some(apm_cmd), Some((smram_base, smram_size)), Some((shared_base, _))) =
        (mm.apm_cmd, mm.smram, mm.shared_mem)
    else {
        return Err("coreboot does not offer payload MM");
    };
    if !mm.smm_is_64bit {
        return Err("32-bit coreboot SMM is not supported yet");
    }
    let boot_media = boot_media.ok_or("no boot media parameters")?;
    let flash_size = boot_media.boot_media_size;
    if flash_size == 0 || flash_size > 16 * 1024 * 1024 {
        return Err("flash is not fully mapped below 4 GiB");
    }
    let flash_base = (1u64 << 32) - flash_size;
    let (store_offset, store_size) = fmap_area(flash_base, boot_media.fmap_offset, b"SMMSTORE")
        .ok_or("no SMMSTORE FMAP area")?;

    // Blob: "CRABMMI\0", file size, memory size, entry, relocation count, relocations, image.
    let image = MM_IMAGE;
    if image.get(..8) != Some(b"CRABMMI\0") {
        return Err("bad payload MM blob");
    }
    let file_size = read_u32(image, 8).ok_or("bad blob")? as usize;
    let mem_size = read_u32(image, 12).ok_or("bad blob")? as usize;
    let entry = read_u32(image, 16).ok_or("bad blob")?;
    let relocations = read_u32(image, 20).ok_or("bad blob")? as usize;
    let data_start = 24 + relocations * 4;
    let bytes = image
        .get(data_start..data_start + file_size)
        .ok_or("bad blob")?;
    if mem_size > STAGING_SIZE || mem_size as u64 > smram_size || smram_base + smram_size > 1 << 32
    {
        return Err("payload MM image does not fit");
    }

    // SAFETY: boot-time, single-threaded; these statics are only used here and by MM.
    unsafe {
        let staging = &mut (*addr_of_mut!(STAGING)).0;
        staging[..mem_size].fill(0);
        staging[..file_size].copy_from_slice(bytes);
        for i in 0..relocations {
            let offset = read_u32(image, 24 + i * 4).ok_or("bad blob")? as usize;
            let slot = staging
                .get_mut(offset..offset + 8)
                .ok_or("bad relocation")?;
            let addend = u64::from_le_bytes(slot.try_into().unwrap());
            slot.copy_from_slice(&(addend + smram_base).to_le_bytes());
        }

        let comm = addr_of_mut!(COMM) as u64;
        (*addr_of_mut!(COMM)).0.fill(0);
        *addr_of_mut!(INIT_CONFIG) = InitConfig {
            magic: INIT_MAGIC,
            version: 1,
            size: core::mem::size_of::<InitConfig>() as u32,
            mm_area_base: shared_base,
            mm_area_size: smram_base + smram_size - shared_base,
            comm_base: comm,
            comm_size: COMM_SIZE as u64,
            flash_base,
            flash_size,
            store_offset,
            store_size,
        };
        *addr_of_mut!(LOAD_CONTEXT) = LoadContext {
            header_size: core::mem::size_of::<LoadContext>() as u16,
            header_revision: PLD_MM_LOAD_CONTEXT_REVISION,
            reserved: 0,
            mm_core_source_address: staging.as_ptr() as u64,
            mm_core_destination_address: smram_base as u32,
            mm_core_size: mem_size as u32,
            mm_entrypoint_offset: entry,
            mm_entrypoint_arg1: addr_of!(INIT_CONFIG) as u64,
            mm_entrypoint_arg2: 0,
            mm_entrypoint_arg3: 0,
            implementation_private_data: 0,
        };

        let mut eax = (PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE << 8) | apm_cmd as u32;
        // coreboot reads the sub-command from AH and the load context from RBX, and
        // returns its status in RAX. RBX is reserved by LLVM, so swap it in and out.
        core::arch::asm!(
            "xchg {context}, rbx",
            "out 0xb2, al",
            "xchg {context}, rbx",
            context = inout(reg) addr_of!(LOAD_CONTEXT) as u64 => _,
            inout("eax") eax,
            options(nostack),
        );
        if eax & 0xff != 0 {
            log::error!("payload MM load failed: coreboot returned {:#x}", eax);
            return Err("coreboot rejected the payload MM image");
        }

        crabefi::drivers::spi::mm::register(crabefi::drivers::spi::mm::MmFlashConfig {
            comm_base: comm,
            comm_size: COMM_SIZE as u64,
            apm_cmd: 0, // any software SMI enters payload MM; 0 is coreboot's no-op command
            flash_base,
            flash_size: flash_size as u32,
        });
    }
    let controller = crabefi::drivers::spi::mm::controller().ok_or("MM flash not registered")?;
    controller
        .ping()
        .map_err(|_| "payload MM does not answer")?;
    log::info!(
        "payload MM loaded at {:#x} ({} KiB); flash writes go through SMM (store {:#x}+{:#x})",
        smram_base,
        mem_size / 1024,
        store_offset,
        store_size
    );
    Ok(())
}
