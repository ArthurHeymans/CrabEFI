use super::*;
use crate::drivers::storage::{self, StorageId};
use crate::efi::protocols::simple_file_system;
use r_efi::efi::Status;
use r_efi::protocols::file as ef;

fn mount() -> *mut ef::Protocol {
    mount_disk(format(LAYOUTS[0]))
}
fn mount_disk(disk: impl BlockDevice + 'static) -> *mut ef::Protocol {
    let disk = alloc::boxed::Box::leak(alloc::boxed::Box::new(disk));
    unsafe {
        storage::register_platform_block_devices(&mut [disk]);
    }
    let sfs = simple_file_system::init(StorageId::Platform { index: 0 }, PARTITION_START);
    assert!(!sfs.is_null());
    let mut root = core::ptr::null_mut();
    assert_eq!(
        unsafe { ((*sfs).open_volume)(sfs, &mut root) },
        Status::SUCCESS
    );
    root
}
fn open(root: *mut ef::Protocol, name: &str, create: bool) -> *mut ef::Protocol {
    open_with_attributes(root, name, create, 0)
}
fn open_with_attributes(
    root: *mut ef::Protocol,
    name: &str,
    create: bool,
    attributes: u64,
) -> *mut ef::Protocol {
    let mut name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut handle = core::ptr::null_mut();
    let mode = ef::MODE_READ | ef::MODE_WRITE | if create { ef::MODE_CREATE } else { 0 };
    assert_eq!(
        unsafe { ((*root).open)(root, &mut handle, name.as_mut_ptr(), mode, attributes) },
        Status::SUCCESS
    );
    handle
}
fn write(handle: *mut ef::Protocol, input: &[u8]) {
    let mut len = input.len();
    assert_eq!(
        unsafe { ((*handle).write)(handle, &mut len, input.as_ptr().cast_mut().cast()) },
        Status::SUCCESS
    );
}
fn seek(handle: *mut ef::Protocol, offset: u64) {
    assert_eq!(
        unsafe { ((*handle).set_position)(handle, offset) },
        Status::SUCCESS
    );
}
fn read_byte(handle: *mut ef::Protocol) -> (usize, u8) {
    let mut out = [0];
    let mut len = 1;
    assert_eq!(
        unsafe { ((*handle).read)(handle, &mut len, out.as_mut_ptr().cast()) },
        Status::SUCCESS
    );
    (len, out[0])
}
fn truncate(handle: *mut ef::Protocol, size: u64) {
    let mut info: ef::Info = unsafe { core::mem::zeroed() };
    info.file_size = size;
    let mut guid = ef::INFO_ID;
    assert_eq!(
        unsafe {
            ((*handle).set_info)(
                handle,
                &mut guid,
                core::mem::size_of::<ef::Info>(),
                (&mut info as *mut ef::Info).cast(),
            )
        },
        Status::SUCCESS
    );
}
// These scenarios share the firmware's single-volume globals. Run them in one
// host test rather than racing registrations on parallel harness threads.
#[test]
fn efi_file_identity_metadata_and_durability() {
    truncate_regrow_invalidates_read_hint();
    two_handles_observe_the_same_file_size_and_cluster();
    deleted_handle_does_not_write_to_a_replacement_at_the_same_path();
    close_after_a_write_flushes_the_device_cache();
    existing_read_only_file_cannot_be_overwritten();
    creation_preserves_attributes_and_utf16_names();
    filesystem_info_uses_the_flexible_label_offset();
    opens_are_relative_to_the_source_location_not_its_access_mode();
}

fn truncate_regrow_invalidates_read_hint() {
    let root = mount();
    let a = open(root, "A.BIN", true);
    write(a, &[0xaa; 1500]);
    seek(a, 512);
    assert_eq!(read_byte(a), (1, 0xaa));
    truncate(a, 100);
    let mut byte = [0u8];
    let mut count = 1;
    assert_eq!(
        unsafe { ((*a).read)(a, &mut count, byte.as_mut_ptr().cast()) },
        Status::DEVICE_ERROR
    );
    assert_eq!(count, 0);
    let b = open(root, "B.BIN", true);
    write(b, &[0xbb; 512]);
    seek(a, 512);
    write(a, &[0xcc]);
    seek(a, 512);
    assert_eq!(read_byte(a), (1, 0xcc));
}
fn opens_are_relative_to_the_source_location_not_its_access_mode() {
    let root = mount();
    let directory = open_with_attributes(root, "DIR", true, ef::DIRECTORY);
    let mut info: ef::Info = unsafe { core::mem::zeroed() };
    info.attribute = ef::DIRECTORY | ef::READ_ONLY;
    let mut guid = ef::INFO_ID;
    assert_eq!(
        unsafe {
            ((*directory).set_info)(
                directory,
                &mut guid,
                core::mem::size_of::<ef::Info>(),
                (&mut info as *mut ef::Info).cast(),
            )
        },
        Status::SUCCESS
    );
    assert_eq!(unsafe { ((*directory).close)(directory) }, Status::SUCCESS);
    let mut name: Vec<_> = "DIR".encode_utf16().chain([0]).collect();
    let mut directory = core::ptr::null_mut();
    assert_eq!(
        unsafe { ((*root).open)(root, &mut directory, name.as_mut_ptr(), ef::MODE_READ, 0) },
        Status::SUCCESS
    );
    let file = open(directory, "A.BIN", true);
    // A regular-file source names its parent directory, not "DIR/A.BIN/B.BIN".
    let sibling = open(file, "B.BIN", true);
    write(sibling, &[0xaa]);
    let alias = open(root, "DIR/B.BIN", false);
    assert_eq!(read_byte(alias), (1, 0xaa));
}

fn two_handles_observe_the_same_file_size_and_cluster() {
    let root = mount();
    let a = open(root, "Long Name.bin", true);
    let b = open(root, "LONGNA~1.BIN", false);
    write(a, &[0xaa]);
    assert_eq!(read_byte(b), (1, 0xaa));
}
fn deleted_handle_does_not_write_to_a_replacement_at_the_same_path() {
    let root = mount();
    let a = open(root, "A.BIN", true);
    let b = open(root, "A.BIN", false);
    assert_eq!(unsafe { ((*a).delete)(a) }, Status::SUCCESS);
    let replacement = open(root, "A.BIN", true);
    write(replacement, &[0xbb]);
    let mut len = 1;
    let mut data = [0xcc];
    let status = unsafe { ((*b).write)(b, &mut len, data.as_mut_ptr().cast()) };
    assert_ne!(status, Status::SUCCESS);
    seek(replacement, 0);
    assert_eq!(read_byte(replacement), (1, 0xbb));
}

struct FlushDisk {
    disk: RamDisk,
    flushes: alloc::rc::Rc<core::cell::Cell<usize>>,
}
impl BlockDevice for FlushDisk {
    fn info(&self) -> BlockDeviceInfo {
        self.disk.info()
    }
    fn read_blocks(&mut self, lba: u64, count: u32, out: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(lba, count, out)
    }
    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        self.disk.write_blocks(lba, count, input)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.flushes.set(self.flushes.get() + 1);
        Ok(())
    }
}
fn close_after_a_write_flushes_the_device_cache() {
    let flushes = alloc::rc::Rc::new(core::cell::Cell::new(0));
    let root = mount_disk(FlushDisk {
        disk: format(LAYOUTS[0]),
        flushes: flushes.clone(),
    });
    let a = open(root, "A.BIN", true);
    write(a, &[0xaa]);
    flushes.set(0);
    assert_eq!(unsafe { ((*a).close)(a) }, Status::SUCCESS);
    assert!(flushes.get() > 0);
}

fn creation_preserves_attributes_and_utf16_names() {
    let root = mount();
    let mut invalid_name: Vec<_> = "readonly.bin".encode_utf16().chain([0]).collect();
    let mut invalid_handle = core::ptr::null_mut();
    assert_eq!(
        unsafe {
            ((*root).open)(
                root,
                &mut invalid_handle,
                invalid_name.as_mut_ptr(),
                ef::MODE_READ | ef::MODE_WRITE | ef::MODE_CREATE,
                ef::READ_ONLY,
            )
        },
        Status::INVALID_PARAMETER
    );
    assert!(invalid_handle.is_null());
    let name = "界".repeat(255);
    let attributes = ef::HIDDEN | ef::SYSTEM;
    let file = open_with_attributes(root, &name, true, attributes);
    let mut guid = ef::INFO_ID;
    let mut size = 0;
    assert_eq!(
        unsafe { ((*file).get_info)(file, &mut guid, &mut size, core::ptr::null_mut()) },
        Status::BUFFER_TOO_SMALL
    );
    let mut buffer = alloc::vec![0u8; size + 1];
    let ptr = unsafe { buffer.as_mut_ptr().add(1) };
    assert_eq!(
        unsafe { ((*file).get_info)(file, &mut guid, &mut size, ptr.cast()) },
        Status::SUCCESS
    );
    let mut info = unsafe { ptr.cast::<ef::Info>().read_unaligned() };
    assert_eq!(info.attribute, attributes);
    assert_eq!(size, core::mem::size_of::<ef::Info>() + 512);
    let name_ptr = unsafe {
        ptr.add(core::mem::offset_of!(ef::Info, file_name))
            .cast::<u16>()
    };
    let returned: Vec<_> = (0..256)
        .map(|i| unsafe { name_ptr.add(i).read_unaligned() })
        .collect();
    assert_eq!(returned, name.encode_utf16().chain([0]).collect::<Vec<_>>());
    // READ_ONLY is applied through SetInfo, not a read-write creation request.
    info.attribute |= ef::READ_ONLY;
    unsafe {
        ptr.cast::<ef::Info>().write_unaligned(info);
    }
    assert_eq!(
        unsafe { ((*file).set_info)(file, &mut guid, size, ptr.cast()) },
        Status::SUCCESS
    );
    let mut count = 1;
    assert_eq!(
        unsafe { ((*file).write)(file, &mut count, [0xaa].as_mut_ptr().cast()) },
        Status::WRITE_PROTECTED
    );
    assert_eq!(count, 0);
    assert_eq!(unsafe { ((*file).close)(file) }, Status::SUCCESS);
}

fn filesystem_info_uses_the_flexible_label_offset() {
    let root = mount();
    let mut guid = ef::SYSTEM_INFO_ID;
    let mut size = 0;
    assert_eq!(
        unsafe { ((*root).get_info)(root, &mut guid, &mut size, core::ptr::null_mut()) },
        Status::BUFFER_TOO_SMALL
    );
    let offset = core::mem::offset_of!(ef::SystemInfo, volume_label);
    assert_eq!(size, offset + 8);
    let mut buffer = alloc::vec![0xffu8; size + 1];
    let ptr = unsafe { buffer.as_mut_ptr().add(1) };
    assert_eq!(
        unsafe { ((*root).get_info)(root, &mut guid, &mut size, ptr.cast()) },
        Status::SUCCESS
    );
    let label = unsafe { ptr.add(offset).cast::<u16>() };
    let returned: Vec<_> = (0..4)
        .map(|i| unsafe { label.add(i).read_unaligned() })
        .collect();
    assert_eq!(
        returned,
        "EFI".encode_utf16().chain([0]).collect::<Vec<_>>()
    );
    assert_eq!(unsafe { ((*root).close)(root) }, Status::SUCCESS);
}

fn existing_read_only_file_cannot_be_overwritten() {
    let mut disk = format(LAYOUTS[0]);
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        fat.write_path("A.BIN", 0, &[0xaa]).unwrap();
        fat.flush().unwrap();
    }
    let spf = (DATA_CLUSTERS + 2).div_ceil(128);
    let root = PARTITION_START * 512 + (32 + 2 * spf as u64) * 512;
    disk.poke(root + 11, &[ATTR_READ_ONLY]);
    let root = mount_disk(disk);
    let mut name16: Vec<u16> = "A.BIN".encode_utf16().chain([0]).collect();
    let mut handle = core::ptr::null_mut();
    let status = unsafe {
        ((*root).open)(
            root,
            &mut handle,
            name16.as_mut_ptr(),
            ef::MODE_READ | ef::MODE_WRITE,
            0,
        )
    };
    if status == Status::SUCCESS {
        let mut len = 1;
        let mut data = [0xcc];
        assert_eq!(
            unsafe { ((*handle).write)(handle, &mut len, data.as_mut_ptr().cast()) },
            Status::WRITE_PROTECTED
        );
    } else {
        assert!(status == Status::WRITE_PROTECTED || status == Status::ACCESS_DENIED);
    }
}
