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

/// Byte stored at a disk offset; varies within a block so offset mistakes show.
fn pattern(byte: u64) -> u8 {
    (byte as u8).wrapping_mul(31) ^ (byte >> 9) as u8
}

/// Expected disk contents for the byte range `offset..offset + len`.
fn expected(offset: u64, len: usize) -> Vec<u8> {
    (offset..offset + len as u64).map(pattern).collect()
}

#[repr(C)]
struct Provider {
    protocol: block_io::Protocol,
    response: Status,
    /// Transfers starting at or after this LBA fail with DEVICE_ERROR.
    fail_from: u64,
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
    // SAFETY: `this` was derived from a pointer to the whole live provider,
    // whose first field is the protocol.
    let provider = unsafe { &mut *this.cast::<Provider>() };
    provider.reads.push((lba, size, buffer.addr()));
    if !buffer.addr().is_multiple_of(BLOCK) || size == 0 || !size.is_multiple_of(BLOCK) {
        return Status::INVALID_PARAMETER;
    }
    // A driver may change its transfer buffer even if it reports an error.
    let start = lba * BLOCK as u64;
    for (index, byte) in (start..start + size as u64).enumerate() {
        unsafe { buffer.cast::<u8>().add(index).write(pattern(byte)) };
    }
    if lba >= provider.fail_from {
        return Status::DEVICE_ERROR;
    }
    provider.response
}

unsafe extern "efiapi" fn unused_reset(_: *mut block_io::Protocol, _: Boolean) -> Status {
    Status::UNSUPPORTED
}
unsafe extern "efiapi" fn unused_flush(_: *mut block_io::Protocol) -> Status {
    Status::UNSUPPORTED
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

    // Both objects are reached only through these raw roots once installed,
    // so test-side updates and provider callbacks share one provenance.
    let media = Box::into_raw(Box::new(Revision1Media {
        media_id: 1,
        removable_media: false,
        media_present: true,
        logical_partition: false,
        read_only: true,
        write_caching: false,
        block_size: BLOCK as u32,
        io_align: BLOCK as u32,
        last_block: BLOCKS - 1,
    }));
    let provider = Box::into_raw(Box::new(Provider {
        protocol: block_io::Protocol {
            revision: block_io::REVISION,
            media: media.cast_const().cast(),
            reset: unused_reset,
            read_blocks: read,
            write_blocks: read,
            flush_blocks: unused_flush,
        },
        response: Status::SUCCESS,
        fail_from: u64::MAX,
        reads: Vec::new(),
    }));
    let handle = boot_services::create_handle().unwrap();
    assert_eq!(
        boot_services::install_protocol(handle, &block_io::PROTOCOL_GUID, provider.cast()),
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
    let out_bytes = move |range: core::ops::Range<usize>| unsafe {
        core::slice::from_raw_parts(base.add(range.start), range.len()).to_vec()
    };

    // Aligned whole blocks go straight into the caller's buffer.
    assert_eq!(read_disk(0, BLOCK, base), Status::SUCCESS);
    assert_eq!(take_reads(), [(0, BLOCK, base.addr())]);
    assert_eq!(out_bytes(0..BLOCK), expected(0, BLOCK));

    // A misaligned destination bounces through an IoAlign-aligned buffer.
    let unaligned = unsafe { base.add(1) };
    assert_eq!(read_disk(512, BLOCK, unaligned), Status::SUCCESS);
    let reads = take_reads();
    assert_ne!(reads[0].2, unaligned.addr());
    assert_eq!(lba_sizes(reads), [(1, BLOCK)]);
    assert_eq!(out_bytes(1..1 + BLOCK), expected(512, BLOCK));

    // Head and tail bounce one block each; the aligned middle is direct.
    let dest = unsafe { base.add(100) };
    assert_eq!(read_disk(100, 2000, dest), Status::SUCCESS);
    let reads = take_reads();
    assert_eq!(reads[1].2, base.addr() + BLOCK);
    assert_eq!(lba_sizes(reads), [(0, BLOCK), (1, 3 * BLOCK), (4, BLOCK)]);
    assert_eq!(out_bytes(100..2100), expected(100, 2000));

    // A large misaligned middle bounces in bounded chunks.
    let mut large = vec![0u8; 130 * BLOCK + 1];
    let large_dest = unsafe { large.as_mut_ptr().add(1) };
    assert_eq!(read_disk(512, 130 * BLOCK, large_dest), Status::SUCCESS);
    assert_eq!(&large[1..], &expected(512, 130 * BLOCK)[..]);
    assert_eq!(
        lba_sizes(take_reads()),
        [(1, 128 * BLOCK), (129, 2 * BLOCK)]
    );

    // A failing later chunk stops the read after the completed prefix.
    large.fill(0);
    // Writing through the Vec retires the earlier raw pointer; derive a new one.
    let large_dest = unsafe { large.as_mut_ptr().add(1) };
    unsafe { (*provider).fail_from = 129 };
    assert_eq!(
        read_disk(512, 130 * BLOCK, large_dest),
        Status::DEVICE_ERROR
    );
    assert_eq!(&large[1..1 + 128 * BLOCK], &expected(512, 128 * BLOCK)[..]);
    assert!(large[1 + 128 * BLOCK..].iter().all(|&byte| byte == 0));
    assert_eq!(
        lba_sizes(take_reads()),
        [(1, 128 * BLOCK), (129, 2 * BLOCK)]
    );
    // A failing middle skips the tail.
    unsafe { (*provider).fail_from = 1 };
    assert_eq!(read_disk(100, 2000, dest), Status::DEVICE_ERROR);
    assert_eq!(lba_sizes(take_reads()), [(0, BLOCK), (1, 3 * BLOCK)]);
    unsafe { (*provider).fail_from = u64::MAX };

    // Known out-of-range requests and stale media IDs do no I/O; an empty
    // read succeeds without touching the device.
    let end = BLOCKS * BLOCK as u64;
    assert_eq!(read_disk(end - 1, 1, base), Status::SUCCESS);
    assert_eq!(out_bytes(0..1), expected(end - 1, 1));
    assert_eq!(lba_sizes(take_reads()), [(BLOCKS - 1, BLOCK)]);
    assert_eq!(read_disk(end - 1, 2, base), Status::INVALID_PARAMETER);
    assert_eq!(read_disk(end, 1, base), Status::INVALID_PARAMETER);
    assert_eq!(read_disk_as(2, 0, 1, base), Status::MEDIA_CHANGED);
    assert_eq!(read_disk(0, 0, ptr::null_mut()), Status::SUCCESS);
    assert!(take_reads().is_empty());

    // With removable media, the driver's current status wins over cached LastBlock.
    unsafe { (*media).removable_media = true };
    unsafe { *base = 0x5a };
    for status in [
        Status::NO_MEDIA,
        Status::MEDIA_CHANGED,
        Status::DEVICE_ERROR,
    ] {
        unsafe { (*provider).response = status };
        assert_eq!(read_disk(end, 1, base), status);
        assert_eq!(
            out_bytes(0..1),
            [0x5a],
            "error must not copy from bounce buffer"
        );
    }
    assert_eq!(lba_sizes(take_reads()), [(BLOCKS, BLOCK); 3]);

    // An empty read reports media the provider already knows is absent.
    unsafe { (*media).media_present = false };
    assert_eq!(read_disk(0, 0, ptr::null_mut()), Status::NO_MEDIA);
    assert!(take_reads().is_empty());

    // No further EFI calls use the process-local globals in this test binary.
    assert_eq!(unsafe { munmap(ram, SIZE) }, 0);
}
