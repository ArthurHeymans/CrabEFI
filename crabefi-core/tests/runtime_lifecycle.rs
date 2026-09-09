//! Execute the real normalized x86 runtime through the core loader and EFI ABI.
//! Shared memfd aliases exercise real non-identity SVAM without privileged hardware.
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
    Arc, Mutex,
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
    fn memfd_create(name: *const core::ffi::c_char, flags: u32) -> i32;
    fn ftruncate(fd: i32, length: isize) -> i32;
    fn close(fd: i32) -> i32;
}
struct Ram(*mut u8, usize, *mut u8);
impl Ram {
    fn new() -> Self {
        let size = 4 * 1024 * 1024;
        // SAFETY: process-private memfd, deliberately shared between two mappings
        // of our firmware image. MAP_32BIT keeps physical RAM inside the core cap.
        unsafe {
            let fd = memfd_create(c"crabefi-lifecycle".as_ptr(), 1);
            assert!(fd >= 0);
            assert_eq!(ftruncate(fd, size as isize), 0);
            let physical = mmap(core::ptr::null_mut(), size, 7, 0x41, fd, 0);
            let virtual_address = mmap(core::ptr::null_mut(), size, 7, 0x01, fd, 0);
            assert_eq!(close(fd), 0);
            assert_ne!(physical as isize, -1);
            assert_ne!(virtual_address as isize, -1);
            assert_ne!(physical, virtual_address);
            Self(physical.cast(), size, virtual_address.cast())
        }
    }
}
impl Drop for Ram {
    fn drop(&mut self) {
        // SAFETY: the one test runs each image to completion before releasing RAM.
        assert_eq!(unsafe { munmap(self.0.cast(), self.1) }, 0);
        assert_eq!(unsafe { munmap(self.2.cast(), self.1) }, 0);
    }
}
struct Region {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
    failure: Arc<AtomicUsize>,
}
impl StorageBackend for Region {
    fn name(&self) -> &str {
        "test variable region"
    }
    fn size(&self) -> u32 {
        self.bytes.lock().unwrap().len() as u32
    }
    fn program_granularity(&self) -> u32 {
        1
    }
    fn erase_granularity(&self) -> u32 {
        4096
    }
    fn is_write_protected(&self) -> bool {
        self.failure.load(Ordering::Relaxed) == 1
    }
    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), StorageError> {
        let mode = self.failure.load(Ordering::Relaxed);
        if mode == 5 || (mode == 4 && offset >= 256) {
            return Err(StorageError::IoError);
        }
        let media = self.bytes.lock().unwrap();
        let data = media
            .get(offset as usize..offset as usize + bytes.len())
            .ok_or(StorageError::InvalidArgument)?;
        bytes.copy_from_slice(data);
        Ok(())
    }
    fn program(&mut self, offset: u32, bytes: &[u8]) -> Result<(), StorageError> {
        match self.failure.load(Ordering::Relaxed) {
            2 => return Err(StorageError::IoError),
            3 => return Err(StorageError::WriteProtected),
            _ => {}
        }
        let mut media = self.bytes.lock().unwrap();
        let target = media
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
            .lock()
            .unwrap()
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
        let failure = Arc::new(AtomicUsize::new(0));
        let media = Arc::new(Mutex::new(vec![0xff; 32 * 1024]));
        let headers = varstore::edk2::build_fv_headers(32 * 1024);
        let mut corrupt_checksum = vec![0xff; 32 * 1024];
        corrupt_checksum[..headers.len()].copy_from_slice(&headers);
        corrupt_checksum[50] ^= 1;
        let mut partial_format = vec![0xff; 32 * 1024];
        partial_format[..16].copy_from_slice(&headers[..16]);
        let mut nonblank_tail = vec![0xff; 32 * 1024];
        nonblank_tail[32 * 1024 - 1] = 0xa5;
        for contents in [
            nonblank_tail,
            corrupt_checksum,
            partial_format,
            vec![0; 32 * 1024],
        ] {
            *media.lock().unwrap() = contents.clone();
            assert_eq!(
                varstore::init_persistence(VariableStorage::Platform(Box::leak(Box::new(
                    Region {
                        bytes: media.clone(),
                        writes: writes.clone(),
                        failure: failure.clone(),
                    }
                )))),
                Err(varstore::VarStoreError::InvalidHeader)
            );
            assert_eq!(writes.load(Ordering::Relaxed), 0);
            assert_eq!(*media.lock().unwrap(), contents);
        }
        media.lock().unwrap().fill(0xff);
        for (mode, error) in [
            (1, varstore::VarStoreError::WriteProtected),
            (4, varstore::VarStoreError::StorageFailure),
            (5, varstore::VarStoreError::StorageFailure),
        ] {
            failure.store(mode, Ordering::Relaxed);
            assert_eq!(
                varstore::init_persistence(VariableStorage::Platform(Box::leak(Box::new(
                    Region {
                        bytes: media.clone(),
                        writes: writes.clone(),
                        failure: failure.clone(),
                    }
                )))),
                Err(error)
            );
            assert_eq!(writes.load(Ordering::Relaxed), 0);
            assert!(media.lock().unwrap().iter().all(|byte| *byte == 0xff));
        }
        failure.store(0, Ordering::Relaxed);
        varstore::init_persistence(VariableStorage::Platform(Box::leak(Box::new(Region {
            bytes: media.clone(),
            writes: writes.clone(),
            failure: failure.clone(),
        }))))
        .unwrap();
        if retained {
            client.prepare_retained_staging().unwrap();
        }
        client.finish_import().unwrap();
        // SAFETY: loader validated and initialized this image-owned EFI table.
        let mut runtime = client.runtime_services();
        let guid = efi::Guid::from_bytes(&[0x42; 16]);
        let mut nv_name = [b'N' as u16, 0];
        let mut volatile_name = [b'V' as u16, 0];
        let attributes = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;
        let data = [1u8];
        let boot_writes_before = writes.load(Ordering::Relaxed);
        assert_eq!(
            (unsafe { (*runtime).set_variable })(
                nv_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                attributes | efi::VARIABLE_NON_VOLATILE,
                data.len(),
                data.as_ptr().cast_mut().cast()
            ),
            efi::Status::SUCCESS
        );
        assert!(writes.load(Ordering::Relaxed) > boot_writes_before);
        for (mode, status) in [
            (1, efi::Status::WRITE_PROTECTED),
            (2, efi::Status::DEVICE_ERROR),
            (3, efi::Status::WRITE_PROTECTED),
        ] {
            failure.store(mode, Ordering::Relaxed);
            let rejected = [3u8];
            assert_eq!(
                (unsafe { (*runtime).set_variable })(
                    nv_name.as_mut_ptr(),
                    &guid as *const _ as *mut _,
                    attributes | efi::VARIABLE_NON_VOLATILE,
                    1,
                    rejected.as_ptr().cast_mut().cast()
                ),
                status
            );
        }
        failure.store(0, Ordering::Relaxed);
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
                (unsafe { (*runtime).set_variable })(
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
            descriptor.virtual_start = ram.2 as u64 + (descriptor.physical_start - ram.0 as u64);
        }
        assert_eq!(
            (unsafe { (*runtime).set_virtual_address_map })(
                count * core::mem::size_of::<allocator::MemoryDescriptor>(),
                core::mem::size_of::<allocator::MemoryDescriptor>(),
                efi::MEMORY_DESCRIPTOR_VERSION,
                descriptors.as_mut_ptr().cast()
            ),
            efi::Status::SUCCESS
        );
        // The table itself and its function pointers now reside in the second alias.
        runtime = (ram.2 as usize + (client.runtime_services() as usize - ram.0 as usize))
            as *mut efi::RuntimeServices;
        let new_data = [2u8];
        assert_eq!(
            (unsafe { (*runtime).set_variable })(
                volatile_name.as_mut_ptr(),
                &guid as *const _ as *mut _,
                attributes,
                1,
                new_data.as_ptr().cast_mut().cast()
            ),
            efi::Status::SUCCESS
        );
        assert_eq!(
            (unsafe { (*runtime).set_variable })(
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
            (unsafe { (*runtime).get_variable })(
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
                (unsafe { (*runtime).set_variable })(
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
                (unsafe { (*runtime).query_capsule_capabilities })(
                    &mut header_pointer,
                    1,
                    &mut maximum,
                    &mut reset
                ),
                efi::Status::UNSUPPORTED
            );
            assert_eq!(maximum, 0);
            assert_eq!(
                (unsafe { (*runtime).update_capsule })(&mut header_pointer, 1, 0x1000),
                efi::Status::UNSUPPORTED
            );
        }
        let mut time = core::mem::MaybeUninit::<efi::Time>::uninit();
        assert_eq!(
            (unsafe { (*runtime).get_time })(time.as_mut_ptr(), core::ptr::null_mut()),
            efi::Status::UNSUPPORTED
        );
        if retained {
            // A fresh image and backend handle model warm reset: only media and
            // retained pages survive, not the previous runtime's live variable RAM.
            let warm = runtime_image::load(crabefi::BUNDLED_RUNTIME_IMAGE, config).unwrap();
            runtime_image::install(warm);
            varstore::init_persistence(VariableStorage::Platform(Box::leak(Box::new(Region {
                bytes: media.clone(),
                writes: writes.clone(),
                failure: failure.clone(),
            }))))
            .unwrap();
            warm.prepare_retained_staging().unwrap();
            let before_replay = writes.load(Ordering::Relaxed);
            warm.replay_deferred().unwrap();
            assert!(writes.load(Ordering::Relaxed) > before_replay);
            let after_replay = writes.load(Ordering::Relaxed);
            warm.replay_deferred().unwrap();
            assert_eq!(writes.load(Ordering::Relaxed), after_replay);
            warm.finish_import().unwrap();
            let mut restored = [0u8];
            let mut size = restored.len();
            let mut flags = 0;
            assert_eq!(
                (unsafe { (*warm.runtime_services()).get_variable })(
                    nv_name.as_mut_ptr(),
                    &guid as *const _ as *mut _,
                    &mut flags,
                    &mut size,
                    restored.as_mut_ptr().cast()
                ),
                efi::Status::SUCCESS
            );
            assert_eq!(restored, [2]);
        }
    }
}
