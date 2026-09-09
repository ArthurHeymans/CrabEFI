//! Execute the real normalized x86 runtime through the core loader and EFI ABI.
//! Host identity mappings exercise relocation/SVAM without privileged hardware.
#![cfg(all(
    target_arch = "x86_64",
    target_os = "linux",
    feature = "bundled-runtime-image",
    feature = "variable-store"
))]

use crabefi::efi::{allocator, runtime_image, varstore};
use crabefi::{
    DeferredBufferConfig, MemoryRegion, MemoryType, RuntimePlatformConfig, StorageBackend,
    StorageError, VariableStorage,
};
use r_efi::efi;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

unsafe extern "C" {
    fn mmap(
        address: *mut core::ffi::c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut core::ffi::c_void;
    fn munmap(address: *mut core::ffi::c_void, length: usize) -> i32;
}
struct Ram(*mut u8, usize);
impl Ram {
    fn new() -> Self {
        // SAFETY: private anonymous mapping, no external memory or file aliases.
        // Executable permission calls our checked-in firmware image; MAP_32BIT
        // stays inside the core allocator's firmware identity-mapped address cap.
        let pointer = unsafe { mmap(core::ptr::null_mut(), 4 * 1024 * 1024, 7, 0x62, -1, 0) };
        assert_ne!(pointer as isize, -1);
        Self(pointer.cast(), 4 * 1024 * 1024)
    }
}
impl Drop for Ram {
    fn drop(&mut self) {
        // SAFETY: the one test runs each image to completion before releasing RAM.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
    }
}
struct Region {
    bytes: Vec<u8>,
    writes: Arc<AtomicUsize>,
}
impl StorageBackend for Region {
    fn name(&self) -> &str {
        "test variable region"
    }
    fn size(&self) -> u32 {
        self.bytes.len() as u32
    }
    fn program_granularity(&self) -> u32 {
        1
    }
    fn erase_granularity(&self) -> u32 {
        4096
    }
    fn is_write_protected(&self) -> bool {
        false
    }
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), StorageError> {
        let data = self
            .bytes
            .get(offset as usize..offset as usize + bytes.len())
            .ok_or(StorageError::InvalidArgument)?;
        bytes.copy_from_slice(data);
        Ok(())
    }
    fn program(&mut self, offset: u32, bytes: &[u8]) -> Result<(), StorageError> {
        let target = self
            .bytes
            .get_mut(offset as usize..offset as usize + bytes.len())
            .ok_or(StorageError::InvalidArgument)?;
        for (old, new) in target.iter_mut().zip(bytes) {
            if *old & *new != *new {
                return Err(StorageError::IoError);
            }
            *old = *new;
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn erase(&mut self, offset: u32, size: u32) -> Result<(), StorageError> {
        if !offset.is_multiple_of(4096) || !size.is_multiple_of(4096) {
            return Err(StorageError::InvalidArgument);
        }
        self.bytes
            .get_mut(offset as usize..offset as usize + size as usize)
            .ok_or(StorageError::InvalidArgument)?
            .fill(0xff);
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn actual_loader_seal_svam_and_runtime_services_with_and_without_retained_staging() {
    let ram = Ram::new();
    allocator::init_from_platform(&[MemoryRegion {
        base: ram.0 as u64,
        size: ram.1 as u64,
        region_type: MemoryType::Ram,
    }]);
    for retained in [false, true] {
        let deferred_buffer = if retained {
            DeferredBufferConfig {
                base: ram.0 as u64,
                size: 64 * 1024,
            }
        } else {
            DeferredBufferConfig::disabled()
        };
        let config = RuntimePlatformConfig {
            time: crabefi::RuntimeTimeConfig {
                mechanism: crabefi::time_mechanism::UNSUPPORTED,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            reset: crabefi::RuntimeResetConfig {
                mechanism: crabefi::reset_mechanism::X86_LEGACY,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            external_ranges: &[],
            deferred_buffer,
        };
        let client = runtime_image::load(crabefi::BUNDLED_RUNTIME_IMAGE, config)
            .expect("actual core image loader");
        runtime_image::install(client);
        let writes = Arc::new(AtomicUsize::new(0));
        varstore::init_persistence(VariableStorage::Platform(Box::leak(Box::new(Region {
            bytes: vec![0xff; 32 * 1024],
            writes: writes.clone(),
        }))))
        .unwrap();
        if retained {
            client.prepare_retained_staging().unwrap();
        }
        client.finish_import().unwrap();
        // SAFETY: loader validated and initialized this image-owned EFI table.
        let runtime = unsafe { &mut *client.runtime_services() };
        let guid = efi::Guid::from_bytes(&[0x42; 16]);
        let mut nv_name = [b'N' as u16, 0];
        let mut volatile_name = [b'V' as u16, 0];
        let attributes = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
        let data = [1u8];
        let boot_writes_before = writes.load(Ordering::Relaxed);
        assert_eq!(
            (runtime.set_variable)(
                nv_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                attributes | efi::VARIABLE_NON_VOLATILE,
                data.len(),
                data.as_ptr().cast_mut().cast()
            ),
            efi::Status::SUCCESS
        );
        assert!(writes.load(Ordering::Relaxed) > boot_writes_before);
        let before = writes.load(Ordering::Relaxed);
        let mut descriptors = [allocator::MemoryDescriptor::new(0, 0, 0, 0); 32];
        let count = allocator::copy_runtime_descriptors(&mut descriptors).unwrap();
        client.prepare_ebs(&descriptors[..count]).unwrap();
        client.seal().unwrap();
        // SAFETY: system table shares the validated live image allocation.
        assert!(unsafe { (*client.system_table()).boot_services.is_null() });
        if !retained {
            let rejected = [3u8];
            assert_eq!(
                (runtime.set_variable)(
                    nv_name.as_mut_ptr(),
                    &guid as *const _ as *mut _,
                    attributes | efi::VARIABLE_NON_VOLATILE,
                    1,
                    rejected.as_ptr().cast_mut().cast()
                ),
                efi::Status::UNSUPPORTED
            );
        }
        for descriptor in &mut descriptors[..count] {
            descriptor.virtual_start = descriptor.physical_start;
        }
        assert_eq!(
            (runtime.set_virtual_address_map)(
                count * core::mem::size_of::<allocator::MemoryDescriptor>(),
                core::mem::size_of::<allocator::MemoryDescriptor>(),
                efi::MEMORY_DESCRIPTOR_VERSION,
                descriptors.as_mut_ptr().cast()
            ),
            efi::Status::SUCCESS
        );
        let new_data = [2u8];
        assert_eq!(
            (runtime.set_variable)(
                volatile_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                attributes,
                1,
                new_data.as_ptr().cast_mut().cast()
            ),
            efi::Status::SUCCESS
        );
        assert_eq!(
            (runtime.set_variable)(
                nv_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                attributes | efi::VARIABLE_NON_VOLATILE,
                1,
                new_data.as_ptr().cast_mut().cast()
            ),
            if retained {
                efi::Status::SUCCESS
            } else {
                efi::Status::UNSUPPORTED
            }
        );
        assert_eq!(
            writes.load(Ordering::Relaxed),
            before,
            "sealed runtime must never call the boot backend"
        );
        let mut value = [0u8];
        let mut size = value.len();
        let mut returned_attributes = 0;
        assert_eq!(
            (runtime.get_variable)(
                nv_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                &mut returned_attributes,
                &mut size,
                value.as_mut_ptr().cast()
            ),
            efi::Status::SUCCESS
        );
        assert_eq!(value, if retained { [2] } else { [1] });
        if !retained {
            assert_eq!(
                (runtime.set_variable)(
                    nv_name.as_mut_ptr(),
                    &guid as *const _ as *mut _,
                    0,
                    0,
                    core::ptr::null_mut()
                ),
                efi::Status::UNSUPPORTED
            );
            let mut header = efi::CapsuleHeader {
                capsule_guid: guid,
                header_size: core::mem::size_of::<efi::CapsuleHeader>() as u32,
                flags: 0x0001_0000,
                capsule_image_size: core::mem::size_of::<efi::CapsuleHeader>() as u32,
            };
            let mut header_pointer = &mut header as *mut _;
            let mut maximum = 0;
            let mut reset = efi::RESET_COLD;
            assert_eq!(
                (runtime.query_capsule_capabilities)(
                    &mut header_pointer,
                    1,
                    &mut maximum,
                    &mut reset
                ),
                efi::Status::UNSUPPORTED
            );
            assert_eq!(maximum, 0);
            assert_eq!(
                (runtime.update_capsule)(&mut header_pointer, 1, 0x1000),
                efi::Status::UNSUPPORTED
            );
        }
        let mut time = core::mem::MaybeUninit::<efi::Time>::uninit();
        assert_eq!(
            (runtime.get_time)(time.as_mut_ptr(), core::ptr::null_mut()),
            efi::Status::UNSUPPORTED
        );
    }
}
