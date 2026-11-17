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

#[repr(C)]
struct Provider {
    protocol: block_io::Protocol,
    calls: usize,
    response: Status,
    last_buffer: usize,
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
    provider.calls += 1;
    provider.last_buffer = buffer.addr();
    if !buffer.addr().is_multiple_of(512) || size != 512 {
        return Status::INVALID_PARAMETER;
    }
    // A driver may change its transfer buffer even if it reports an error.
    unsafe { buffer.cast::<u8>().write_bytes(0x40 | lba as u8, size) };
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

    let mut media = Revision1Media {
        media_id: 1,
        removable_media: false,
        media_present: true,
        logical_partition: false,
        read_only: true,
        write_caching: false,
        block_size: 512,
        io_align: 512,
        last_block: 1,
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
        calls: 0,
        response: Status::SUCCESS,
        last_buffer: 0,
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
    let read_disk = |offset, len, dest: *mut u8| unsafe {
        ((*disk).read_disk)(disk, 1, offset, len, dest.cast())
    };

    #[repr(align(512))]
    struct Aligned([u8; 1024]);
    let mut out = Aligned([0; 1024]);
    assert_eq!(read_disk(0, 512, out.0.as_mut_ptr()), Status::SUCCESS);
    assert_eq!(provider.last_buffer, out.0.as_ptr().addr());
    assert_eq!(&out.0[..512], &[0x40; 512]);

    let unaligned = unsafe { out.0.as_mut_ptr().add(1) };
    assert_eq!(read_disk(512, 512, unaligned), Status::SUCCESS);
    assert_ne!(provider.last_buffer, unaligned.addr());
    assert_eq!(&out.0[1..513], &[0x41; 512]);
    assert_eq!(read_disk(1023, 1, out.0.as_mut_ptr()), Status::SUCCESS);
    assert_eq!(out.0[0], 0x41);
    assert_eq!(
        read_disk(1024, 1, out.0.as_mut_ptr()),
        Status::INVALID_PARAMETER
    );
    assert_eq!(provider.calls, 3);

    // With removable media, the driver's current status wins over cached LastBlock.
    unsafe { ptr::write_volatile(&raw mut media.removable_media, true) };
    out.0[0] = 0x5a;
    for status in [
        Status::NO_MEDIA,
        Status::MEDIA_CHANGED,
        Status::DEVICE_ERROR,
    ] {
        provider.response = status;
        assert_eq!(read_disk(1024, 1, out.0.as_mut_ptr()), status);
        assert_eq!(out.0[0], 0x5a, "error must not copy from bounce buffer");
    }
    assert_eq!(provider.calls, 6);
    // No further EFI calls use the process-local globals in this test binary.
    assert_eq!(unsafe { munmap(ram, SIZE) }, 0);
}
