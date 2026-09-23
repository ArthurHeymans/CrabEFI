//! Boot-only typed client for validated runtime image exports.

use alloc::vec::Vec;
use core::ffi::c_void;

use crabefi_runtime_abi::{
    ConfigurationRegistration, ConsoleRegistration, EsrtRegistration, ExportOffsets,
    MemoryDescriptor, RelocationImport, RuntimeHandoff, VariableImport,
};
use r_efi::efi::{self, Guid, Status};

macro_rules! define_runtime_exports {
    ($($field:ident: $symbol:ident => $signature:ty;)*) => {
        /// Typed entry points of a loaded runtime image.
        #[derive(Clone, Copy)]
        struct RuntimeExports {
            $($field: $signature,)*
        }

        impl RuntimeExports {
            /// # Safety
            ///
            /// `offsets` must come from a validated image loaded at `base`.
            unsafe fn resolve(base: u64, offsets: ExportOffsets) -> Self {
                Self {
                    // SAFETY: forwarded from the caller.
                    $($field: unsafe { entry_point(base, offsets.$field) },)*
                }
            }
        }
    };
}
crabefi_runtime_abi::runtime_exports!(define_runtime_exports);

/// Convert an image-relative export offset into its typed entry point.
///
/// # Safety
///
/// `F` must be the function pointer type of the export at `base + offset`.
unsafe fn entry_point<F: Copy>(base: u64, offset: u32) -> F {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    let address = base.wrapping_add(u64::from(offset)) as usize;
    // SAFETY: `F` is a pointer-sized function pointer type naming this address.
    unsafe { core::mem::transmute_copy(&address) }
}

#[derive(Clone, Copy)]
pub struct RuntimeImageClient {
    exports: RuntimeExports,
    runtime_services: *mut efi::RuntimeServices,
    system_table: *mut efi::SystemTable,
}

// SAFETY: this boot-only value contains validated image addresses. Firmware is
// single-threaded and no client address is copied into post-seal image state.
unsafe impl Send for RuntimeImageClient {}
unsafe impl Sync for RuntimeImageClient {}

impl RuntimeImageClient {
    /// # Safety
    ///
    /// `offsets` must come from the validated image loaded and relocated at `base`.
    pub(crate) unsafe fn new(base: u64, offsets: ExportOffsets) -> Self {
        Self {
            // SAFETY: forwarded from the caller.
            exports: unsafe { RuntimeExports::resolve(base, offsets) },
            runtime_services: core::ptr::null_mut(),
            system_table: core::ptr::null_mut(),
        }
    }

    pub(crate) fn initialize(&self, handoff: &RuntimeHandoff) -> Result<(), Status> {
        // SAFETY: the handoff is a live reference for this immediate call.
        status_result(unsafe { (self.exports.init)(handoff) })
    }

    pub(crate) fn import_relocation(&self, relocation: &RelocationImport) -> Result<(), Status> {
        // SAFETY: the record is a live reference for this immediate call.
        status_result(unsafe { (self.exports.import_relocation)(relocation) })
    }

    pub fn import_variable(&self, import: &VariableImport) -> Result<(), Status> {
        // SAFETY: the record and the buffers it names are live for this call.
        status_result(unsafe { (self.exports.import_variable)(import) })
    }

    pub fn prepare_retained_staging(&self) -> Result<(), Status> {
        status_result((self.exports.prepare_retained_staging)())
    }

    pub fn replay_deferred(&self) -> Result<(), Status> {
        status_result((self.exports.replay_deferred)())
    }

    pub fn enable_capsule_delivery(&self) -> Result<(), Status> {
        status_result((self.exports.enable_capsule_delivery)())
    }

    pub fn complete_import(&self) -> Result<(), Status> {
        status_result((self.exports.complete_import)())
    }

    pub(crate) fn activate(&mut self, boot_services: *mut efi::BootServices) -> Result<(), Status> {
        status_result((self.exports.activate)(boot_services as u64))?;
        self.runtime_services = (self.exports.runtime_services)() as *mut efi::RuntimeServices;
        self.system_table = (self.exports.system_table)() as *mut efi::SystemTable;
        if self.runtime_services.is_null() || self.system_table.is_null() {
            return Err(Status::LOAD_ERROR);
        }
        Ok(())
    }

    pub fn register_configuration(
        &self,
        registration: &ConfigurationRegistration,
    ) -> Result<(), Status> {
        // SAFETY: the record is a live reference for this immediate call.
        status_result(unsafe { (self.exports.register_configuration)(registration) })
    }

    pub fn set_console(&self, registration: &ConsoleRegistration) -> Result<(), Status> {
        // SAFETY: the record is a live reference for this immediate call.
        status_result(unsafe { (self.exports.set_console)(registration) })
    }

    pub fn install_esrt(&self, registration: &EsrtRegistration) -> Result<(), Status> {
        // SAFETY: the record is a live reference for this immediate call.
        status_result(unsafe { (self.exports.install_esrt)(registration) })
    }

    pub fn prepare_ebs(&self, descriptors: &[MemoryDescriptor]) -> Result<(), Status> {
        // SAFETY: the descriptor slice is live for this immediate call.
        status_result(unsafe {
            (self.exports.prepare_ebs)(descriptors.as_ptr(), descriptors.len())
        })
    }

    pub fn seal(&self) -> Result<(), Status> {
        status_result((self.exports.seal)())
    }

    pub const fn runtime_services(&self) -> *mut efi::RuntimeServices {
        self.runtime_services
    }

    pub const fn system_table(&self) -> *mut efi::SystemTable {
        self.system_table
    }
}

fn status_result(status: usize) -> Result<(), Status> {
    let status = Status::from_usize(status);
    if status == Status::SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// Validated boot-side client for the separately allocated runtime image.
static CLIENT: crate::cell::LocalCell<Option<RuntimeImageClient>> =
    crate::cell::LocalCell::new(None);

/// The runtime image client, once the runtime image has been loaded.
pub fn installed() -> Option<RuntimeImageClient> {
    CLIENT.get()
}

/// Publish the runtime image client.
pub fn install(client: RuntimeImageClient) {
    CLIENT.set(Some(client));
}

fn client() -> Option<RuntimeImageClient> {
    installed()
}

pub fn get_system_table() -> *mut efi::SystemTable {
    client().map_or(core::ptr::null_mut(), |client| client.system_table())
}

pub fn get_runtime_services() -> *mut efi::RuntimeServices {
    client().map_or(core::ptr::null_mut(), |client| client.runtime_services())
}

pub mod variables {
    use super::*;

    pub fn get(guid: &Guid, name: &[u16]) -> Option<(u32, Vec<u8>)> {
        let client = client()?;
        let runtime = client.runtime_services();
        if runtime.is_null() {
            return None;
        }
        let mut name = nul_terminated(name)?;
        let mut guid = *guid;
        let mut attributes = 0u32;
        let mut size = 0usize;
        // SAFETY: runtime points to the validated image table and all inputs
        // are immediate boot-owned buffers.
        let first = crate::efi::boot_services::with_image_callback(|| unsafe {
            ((*runtime).get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                core::ptr::null_mut(),
            )
        });
        if first == Status::NOT_FOUND {
            return None;
        }
        if first != Status::BUFFER_TOO_SMALL || size > crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE {
            return None;
        }
        let mut data = Vec::new();
        if data.try_reserve_exact(size).is_err() {
            return None;
        }
        data.resize(size, 0);
        let status = crate::efi::boot_services::with_image_callback(|| unsafe {
            ((*runtime).get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                data.as_mut_ptr().cast::<c_void>(),
            )
        });
        (status == Status::SUCCESS).then_some((attributes, data))
    }

    pub fn set(guid: &Guid, name: &[u16], attributes: u32, data: &[u8]) -> Status {
        let Some(client) = client() else {
            return Status::NOT_READY;
        };
        let runtime = client.runtime_services();
        let Some(mut name) = nul_terminated(name) else {
            return Status::INVALID_PARAMETER;
        };
        let mut guid = *guid;
        if runtime.is_null() {
            return Status::NOT_READY;
        }
        // SAFETY: runtime points to the validated image table and all immediate
        // caller buffers remain live for the duration of this call.
        crate::efi::boot_services::with_image_callback(|| unsafe {
            ((*runtime).set_variable)(
                name.as_mut_ptr(),
                &mut guid,
                attributes,
                data.len(),
                data.as_ptr() as *mut c_void,
            )
        })
    }

    pub fn delete(guid: &Guid, name: &[u16]) -> Status {
        set(guid, name, 0, &[])
    }

    fn nul_terminated(name: &[u16]) -> Option<Vec<u16>> {
        let len = name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(name.len());
        if len == 0 || len > crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN {
            return None;
        }
        let mut output = Vec::new();
        output.try_reserve_exact(len + 1).ok()?;
        output.extend_from_slice(&name[..len]);
        output.push(0);
        Some(output)
    }
}
