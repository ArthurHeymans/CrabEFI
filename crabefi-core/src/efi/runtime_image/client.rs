//! Boot-only typed client for validated runtime image exports.

use alloc::vec::Vec;
use core::ffi::c_void;

use crabefi_runtime_abi::{
    ConfigurationRegistration, ConsoleRegistration, EsrtRegistration, MemoryDescriptor,
    RelocationImport, RuntimeExportsV1, RuntimeHandoff, VariableImport,
};
use r_efi::efi::{self, Guid, Status};

type Init = extern "C" fn(*const RuntimeHandoff) -> usize;
type ImportRelocation = extern "C" fn(*const RelocationImport) -> usize;
type ImportVariable = extern "C" fn(*const VariableImport) -> usize;
type FinishImport = extern "C" fn(u32) -> usize;
type Activate = extern "C" fn(u64) -> usize;
type RegisterConfiguration = extern "C" fn(*const ConfigurationRegistration) -> usize;
type SetConsole = extern "C" fn(*const ConsoleRegistration) -> usize;
type InstallEsrt = extern "C" fn(*const EsrtRegistration) -> usize;
type PrepareEbs = extern "C" fn(*const efi::MemoryDescriptor, usize) -> usize;
type Seal = extern "C" fn() -> usize;
type GetTable = extern "C" fn() -> u64;

// The runtime ABI owns the descriptor storage, while the image consumes it as
// r-efi descriptors. Keep the cast in `prepare_ebs` layout-checked.
const _: () = assert!(
    core::mem::size_of::<MemoryDescriptor>() == core::mem::size_of::<efi::MemoryDescriptor>()
        && core::mem::align_of::<MemoryDescriptor>()
            == core::mem::align_of::<efi::MemoryDescriptor>()
        && core::mem::offset_of!(MemoryDescriptor, memory_type)
            == core::mem::offset_of!(efi::MemoryDescriptor, r#type)
        && core::mem::offset_of!(MemoryDescriptor, physical_start)
            == core::mem::offset_of!(efi::MemoryDescriptor, physical_start)
        && core::mem::offset_of!(MemoryDescriptor, virtual_start)
            == core::mem::offset_of!(efi::MemoryDescriptor, virtual_start)
        && core::mem::offset_of!(MemoryDescriptor, number_of_pages)
            == core::mem::offset_of!(efi::MemoryDescriptor, number_of_pages)
        && core::mem::offset_of!(MemoryDescriptor, attribute)
            == core::mem::offset_of!(efi::MemoryDescriptor, attribute)
);

/// All export offsets are validated by `ValidatedImage` before this one audited
/// conversion from image-relative addresses to typed function pointers.
#[derive(Clone, Copy)]
struct RuntimeExports {
    init: Init,
    import_relocation: ImportRelocation,
    import_variable: ImportVariable,
    finish_import: FinishImport,
    activate: Activate,
    register_configuration: RegisterConfiguration,
    set_console: SetConsole,
    install_esrt: InstallEsrt,
    prepare_ebs: PrepareEbs,
    seal: Seal,
    runtime_services: GetTable,
    system_table: GetTable,
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
    pub(crate) fn new(base: u64, exports: RuntimeExportsV1) -> Self {
        let address = |offset: u32| base.wrapping_add(u64::from(offset)) as usize;
        // SAFETY: the checked normalized image proves each export offset lies
        // within the independently allocated image and names the fixed C ABI.
        let exports = unsafe {
            RuntimeExports {
                init: core::mem::transmute::<usize, Init>(address(exports.init)),
                import_relocation: core::mem::transmute::<usize, ImportRelocation>(address(
                    exports.import_relocation,
                )),
                import_variable: core::mem::transmute::<usize, ImportVariable>(address(
                    exports.import_variable,
                )),
                finish_import: core::mem::transmute::<usize, FinishImport>(address(
                    exports.finish_import,
                )),
                activate: core::mem::transmute::<usize, Activate>(address(exports.activate)),
                register_configuration: core::mem::transmute::<usize, RegisterConfiguration>(
                    address(exports.register_configuration),
                ),
                set_console: core::mem::transmute::<usize, SetConsole>(address(
                    exports.set_console,
                )),
                install_esrt: core::mem::transmute::<usize, InstallEsrt>(address(
                    exports.install_esrt,
                )),
                prepare_ebs: core::mem::transmute::<usize, PrepareEbs>(address(
                    exports.prepare_ebs,
                )),
                seal: core::mem::transmute::<usize, Seal>(address(exports.seal)),
                runtime_services: core::mem::transmute::<usize, GetTable>(address(
                    exports.runtime_services,
                )),
                system_table: core::mem::transmute::<usize, GetTable>(address(
                    exports.system_table,
                )),
            }
        };
        Self {
            exports,
            runtime_services: core::ptr::null_mut(),
            system_table: core::ptr::null_mut(),
        }
    }

    pub(crate) fn initialize(&self, handoff: &RuntimeHandoff) -> Result<(), Status> {
        status_result((self.exports.init)(handoff))
    }

    pub(crate) fn import_relocation(&self, relocation: &RelocationImport) -> Result<(), Status> {
        status_result((self.exports.import_relocation)(relocation))
    }

    pub fn import_variable(&self, import: &VariableImport) -> Result<(), Status> {
        status_result((self.exports.import_variable)(import))
    }

    pub fn prepare_retained_staging(&self) -> Result<(), Status> {
        status_result((self.exports.finish_import)(
            crabefi_runtime_abi::finish_import_operation::PREPARE_RETAINED_STAGING,
        ))
    }

    pub fn replay_deferred(&self) -> Result<(), Status> {
        status_result((self.exports.finish_import)(
            crabefi_runtime_abi::finish_import_operation::REPLAY_DEFERRED,
        ))
    }

    pub fn finish_import(&self) -> Result<(), Status> {
        status_result((self.exports.finish_import)(
            crabefi_runtime_abi::finish_import_operation::COMPLETE_IMPORT,
        ))
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
        status_result((self.exports.register_configuration)(registration))
    }

    pub fn set_console(&self, registration: &ConsoleRegistration) -> Result<(), Status> {
        status_result((self.exports.set_console)(registration))
    }

    pub fn install_esrt(&self, registration: &EsrtRegistration) -> Result<(), Status> {
        status_result((self.exports.install_esrt)(registration))
    }

    pub fn prepare_ebs(&self, descriptors: &[MemoryDescriptor]) -> Result<(), Status> {
        status_result((self.exports.prepare_ebs)(
            descriptors.as_ptr().cast::<efi::MemoryDescriptor>(),
            descriptors.len(),
        ))
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

fn client() -> Option<RuntimeImageClient> {
    if !crate::state::is_initialized() {
        return None;
    }
    unsafe { (*crate::state::efi_ptr()).runtime_image }
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
        let first = unsafe {
            ((*runtime).get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                core::ptr::null_mut(),
            )
        };
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
        let status = unsafe {
            ((*runtime).get_variable)(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                data.as_mut_ptr().cast::<c_void>(),
            )
        };
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
        unsafe {
            ((*runtime).set_variable)(
                name.as_mut_ptr(),
                &mut guid,
                attributes,
                data.len(),
                data.as_ptr() as *mut c_void,
            )
        }
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
