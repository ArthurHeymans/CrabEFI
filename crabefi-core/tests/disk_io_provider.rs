//! Exercise DiskIO through the installed EFI ABI on a mock revision-1 BlockIO provider.
#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use core::ffi::c_void;
use core::ptr;

use crabefi::efi::{allocator, boot_services, protocols::disk_io, tables};
use crabefi::{MemoryRegion, MemoryType};
use r_efi::{
    efi::{Boolean, Status},
    protocols::block_io,
};

// The x86 boot allocator caps identity-mapped firmware RAM at 64 GiB. Use
// Linux MAP_32BIT to provide a host mapping it can allocate EFI pool pages in.
unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        off: isize,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

#[repr(C)]
struct Revision1Media {
    media_id: u32,
    removable_media: bool,
    media_present: bool,
    logical_partition: bool,
    read_only: bool,
    write_caching: bool,
    block_size: u32,
    io_align: u32,
    last_block: u64,
}

const BLOCK: usize = 512;
const BLOCKS: u64 = 200;

/// Byte a mock block is filled with.
fn pattern(lba: u64) -> u8 {
    0x40u8.wrapping_add(lba as u8)
}

#[repr(C)]
struct Provider {
    protocol: block_io::Protocol,
    response: Status,
    /// (lba, size, buffer address) of every ReadBlocks call.
    reads: Vec<(u64, usize, usize)>,
}

unsafe extern "efiapi" fn read(
    this: *mut block_io::Protocol,
    _: u32,
    lba: u64,
    size: usize,
    buffer: *mut c_void,
) -> Status {
    // SAFETY: protocol is the first field of the live test provider.
    let provider = unsafe { &mut *this.cast::<Provider>() };
    provider.reads.push((lba, size, buffer.addr()));
    if !buffer.addr().is_multiple_of(BLOCK) || size == 0 || !size.is_multiple_of(BLOCK) {
        return Status::INVALID_PARAMETER;
    }
    // A driver may change its transfer buffer even if it reports an error.
    for (index, block) in (lba..).zip(0..size / BLOCK) {
        unsafe {
            buffer
                .cast::<u8>()
                .add(block * BLOCK)
                .write_bytes(pattern(index), BLOCK)
        };
    }
    provider.response
}

unsafe extern "efiapi" fn unused_reset(_: *mut block_io::Protocol, _: Boolean) -> Status {
    Status::UNSUPPORTED
}
unsafe extern "efiapi" fn unused_flush(_: *mut block_io::Protocol) -> Status {
    Status::UNSUPPORTED
}

/// Expected disk contents for the byte range `offset..offset + len`.
fn expected(offset: u64, len: usize) -> Vec<u8> {
    (offset..offset + len as u64)
        .map(|byte| pattern(byte / BLOCK as u64))
        .collect()
}

#[test]
fn routes_reads_and_propagates_live_media_status() {
    const SIZE: usize = 1024 * 1024;
    // Read/write, private, anonymous, below 2 GiB.
    let ram = unsafe { mmap(ptr::null_mut(), SIZE, 3, 0x62, -1, 0) };
    assert_ne!(ram as isize, -1);
    allocator::init_from_platform(&[MemoryRegion {
        base: ram as u64,
        size: SIZE as u64,
        region_type: MemoryType::Ram,
    }]);
    tables::init_caches().unwrap();

    let mut media = Revision1Media {
        media_id: 1,
        removable_media: false,
        media_present: true,
        logical_partition: false,
        read_only: true,
        write_caching: false,
        block_size: BLOCK as u32,
        io_align: BLOCK as u32,
        last_block: BLOCKS - 1,
    };
    let mut provider = Provider {
        protocol: block_io::Protocol {
            revision: block_io::REVISION,
            media: (&raw const media).cast(),
            reset: unused_reset,
            read_blocks: read,
            write_blocks: read,
            flush_blocks: unused_flush,
        },
        response: Status::SUCCESS,
        reads: Vec::new(),
    };
    let handle = boot_services::create_handle().unwrap();
    assert_eq!(
        boot_services::install_protocol(
            handle,
            &block_io::PROTOCOL_GUID,
            (&raw mut provider.protocol).cast()
        ),
        Status::SUCCESS
    );
    disk_io::install_disk_io_on_handle(handle);
    let disk = boot_services::get_protocol_on_handle(handle, &disk_io::DISK_IO_PROTOCOL_GUID)
        .cast::<disk_io::DiskIoProtocol>();
    assert!(!disk.is_null());
    let read_disk_as = |media_id, offset, len, dest: *mut u8| unsafe {
        ((*disk).read_disk)(disk, media_id, offset, len, dest.cast())
    };
    let read_disk = |offset, len, dest| read_disk_as(1, offset, len, dest);
    // The callback mutates the provider through the protocol pointer; read
    // its log through the same raw provenance.
    let provider = &raw mut provider;
    let take_reads = move || core::mem::take(unsafe { &mut (*provider).reads });
    let lba_sizes = |reads: Vec<(u64, usize, usize)>| {
        reads
            .into_iter()
            .map(|(lba, size, _)| (lba, size))
            .collect::<Vec<_>>()
    };

    #[repr(align(512))]
    struct Aligned([u8; 8 * BLOCK]);
    let mut out = Aligned([0; 8 * BLOCK]);
    let base = out.0.as_mut_ptr();

    // Aligned whole blocks go straight into the caller's buffer.
    assert_eq!(read_disk(0, BLOCK, base), Status::SUCCESS);
    assert_eq!(take_reads(), [(0, BLOCK, base.addr())]);
    assert_eq!(&out.0[..BLOCK], &expected(0, BLOCK)[..]);

    // A misaligned destination bounces through an IoAlign-aligned buffer.
    let unaligned = unsafe { base.add(1) };
    assert_eq!(read_disk(512, BLOCK, unaligned), Status::SUCCESS);
    let reads = take_reads();
    assert_ne!(reads[0].2, unaligned.addr());
    assert_eq!(lba_sizes(reads), [(1, BLOCK)]);
    assert_eq!(&out.0[1..1 + BLOCK], &expected(512, BLOCK)[..]);

    // Head and tail bounce one block each; the aligned middle is direct.
    let dest = unsafe { base.add(100) };
    assert_eq!(read_disk(100, 2000, dest), Status::SUCCESS);
    let reads = take_reads();
    assert_eq!(reads[1].2, base.addr() + BLOCK);
    assert_eq!(lba_sizes(reads), [(0, BLOCK), (1, 3 * BLOCK), (4, BLOCK)]);
    assert_eq!(&out.0[100..2100], &expected(100, 2000)[..]);

    // A large misaligned middle bounces in bounded chunks.
    let mut large = vec![0u8; 130 * BLOCK + 1];
    assert_eq!(
        read_disk(512, 130 * BLOCK, large[1..].as_mut_ptr()),
        Status::SUCCESS
    );
    assert_eq!(&large[1..], &expected(512, 130 * BLOCK)[..]);
    assert_eq!(
        lba_sizes(take_reads()),
        [(1, 128 * BLOCK), (129, 2 * BLOCK)]
    );

    // Known out-of-range requests and stale media IDs do no I/O; an empty
    // read succeeds without touching the device.
    let end = BLOCKS * BLOCK as u64;
    assert_eq!(read_disk(end - 1, 1, base), Status::SUCCESS);
    assert_eq!(out.0[0], pattern(BLOCKS - 1));
    assert_eq!(lba_sizes(take_reads()), [(BLOCKS - 1, BLOCK)]);
    assert_eq!(read_disk(end - 1, 2, base), Status::INVALID_PARAMETER);
    assert_eq!(read_disk(end, 1, base), Status::INVALID_PARAMETER);
    assert_eq!(read_disk_as(2, 0, 1, base), Status::MEDIA_CHANGED);
    assert_eq!(read_disk(0, 0, ptr::null_mut()), Status::SUCCESS);
    assert!(take_reads().is_empty());

    // With removable media, the driver's current status wins over cached LastBlock.
    unsafe { ptr::write_volatile(&raw mut media.removable_media, true) };
    out.0[0] = 0x5a;
    for status in [
        Status::NO_MEDIA,
        Status::MEDIA_CHANGED,
        Status::DEVICE_ERROR,
    ] {
        unsafe { (*provider).response = status };
        assert_eq!(read_disk(end, 1, base), status);
        assert_eq!(out.0[0], 0x5a, "error must not copy from bounce buffer");
    }
    assert_eq!(lba_sizes(take_reads()), [(BLOCKS, BLOCK); 3]);
    // No further EFI calls use the process-local globals in this test binary.
    assert_eq!(unsafe { munmap(ram, SIZE) }, 0);
}
