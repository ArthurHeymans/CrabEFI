//! Image-owned Runtime Services, System Table, and configuration survivors.

use core::ffi::c_void;

use crabefi_runtime_abi::{
    ConfigurationRegistration, ConsoleRegistration, EsrtRegistration, MAX_CONFIGURATION_TABLES,
    configuration_policy, section_flags,
};

use crate::{
    crc32, efi, services,
    state::{RangeRecord, SectionRecord},
};

const UEFI_REVISION: u32 = (2 << 16) | 100;
const FIRMWARE_REVISION: u32 = 0x0001_0000;
const ESRT_GUID: [u8; 16] = [
    0x63, 0xa2, 0x22, 0xb1, 0x61, 0x36, 0x68, 0x4f, 0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80,
];

#[repr(C)]
pub struct EsrtHeader {
    pub resource_count: u32,
    pub resource_count_max: u32,
    pub resource_version: u64,
}

#[repr(C)]
pub struct EsrtEntry {
    pub firmware_class: efi::Guid,
    pub firmware_type: u32,
    pub firmware_version: u32,
    pub lowest_supported_version: u32,
    pub capsule_flags: u32,
    pub last_attempt_version: u32,
    pub last_attempt_status: u32,
}

#[repr(C)]
pub struct EsrtTable {
    pub header: EsrtHeader,
    pub entry: EsrtEntry,
}

#[derive(Clone, Copy)]
pub struct ConfigurationMetadata {
    pub policy: u32,
    pub physical_address: u64,
}

impl ConfigurationMetadata {
    const fn empty() -> Self {
        Self {
            policy: 0,
            physical_address: 0,
        }
    }
}

#[repr(C)]
pub struct ImageTables {
    pub runtime: efi::RuntimeServices,
    pub system: efi::SystemTable,
    pub vendor: [u16; 8],
    pub configuration: [efi::ConfigurationTable; MAX_CONFIGURATION_TABLES],
    pub configuration_metadata: [ConfigurationMetadata; MAX_CONFIGURATION_TABLES],
    pub configuration_count: usize,
    pub properties: efi::RtPropertiesTable,
    pub memory_attributes: efi::MemoryAttributesTable<32>,
    pub esrt: EsrtTable,
}

impl ImageTables {
    pub const fn new() -> Self {
        const EMPTY_GUID: efi::Guid = efi::Guid::from_bytes(&[0; 16]);
        const EMPTY_CONFIGURATION_ENTRY: efi::ConfigurationTable = efi::ConfigurationTable {
            vendor_guid: EMPTY_GUID,
            vendor_table: core::ptr::null_mut(),
        };
        const EMPTY_DESCRIPTOR: efi::MemoryDescriptor = efi::MemoryDescriptor {
            r#type: 0,
            physical_start: 0,
            virtual_start: 0,
            number_of_pages: 0,
            attribute: 0,
        };
        Self {
            runtime: efi::RuntimeServices {
                hdr: efi::TableHeader {
                    signature: efi::RUNTIME_SERVICES_SIGNATURE,
                    revision: UEFI_REVISION,
                    header_size: core::mem::size_of::<efi::RuntimeServices>() as u32,
                    crc32: 0,
                    reserved: 0,
                },
                get_time: services::get_time,
                set_time: services::set_time,
                get_wakeup_time: services::get_wakeup_time,
                set_wakeup_time: services::set_wakeup_time,
                set_virtual_address_map: services::set_virtual_address_map,
                convert_pointer: services::convert_pointer,
                get_variable: services::get_variable,
                get_next_variable_name: services::get_next_variable_name,
                set_variable: services::set_variable,
                get_next_high_mono_count: services::get_next_high_mono_count,
                reset_system: services::reset_system,
                update_capsule: services::update_capsule,
                query_capsule_capabilities: services::query_capsule_capabilities,
                query_variable_info: services::query_variable_info,
            },
            system: efi::SystemTable {
                hdr: efi::TableHeader {
                    signature: efi::SYSTEM_TABLE_SIGNATURE,
                    revision: UEFI_REVISION,
                    header_size: core::mem::size_of::<efi::SystemTable>() as u32,
                    crc32: 0,
                    reserved: 0,
                },
                firmware_vendor: core::ptr::null_mut(),
                firmware_revision: FIRMWARE_REVISION,
                console_in_handle: core::ptr::null_mut(),
                con_in: core::ptr::null_mut(),
                console_out_handle: core::ptr::null_mut(),
                con_out: core::ptr::null_mut(),
                standard_error_handle: core::ptr::null_mut(),
                std_err: core::ptr::null_mut(),
                runtime_services: core::ptr::null_mut(),
                boot_services: core::ptr::null_mut(),
                number_of_table_entries: 0,
                configuration_table: core::ptr::null_mut(),
            },
            vendor: [
                b'C' as u16,
                b'r' as u16,
                b'a' as u16,
                b'b' as u16,
                b'E' as u16,
                b'F' as u16,
                b'I' as u16,
                0,
            ],
            configuration: [EMPTY_CONFIGURATION_ENTRY; MAX_CONFIGURATION_TABLES],
            configuration_metadata: [ConfigurationMetadata::empty(); MAX_CONFIGURATION_TABLES],
            configuration_count: 0,
            properties: efi::RtPropertiesTable {
                version: efi::RT_PROPERTIES_TABLE_VERSION,
                length: core::mem::size_of::<efi::RtPropertiesTable>() as u16,
                runtime_services_supported: efi::RT_SUPPORTED_GET_VARIABLE
                    | efi::RT_SUPPORTED_GET_NEXT_VARIABLE_NAME
                    | efi::RT_SUPPORTED_SET_VARIABLE
                    | efi::RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP
                    | efi::RT_SUPPORTED_CONVERT_POINTER
                    | efi::RT_SUPPORTED_RESET_SYSTEM
                    | efi::RT_SUPPORTED_UPDATE_CAPSULE
                    | efi::RT_SUPPORTED_QUERY_CAPSULE_CAPABILITIES
                    | efi::RT_SUPPORTED_QUERY_VARIABLE_INFO,
            },
            memory_attributes: efi::MemoryAttributesTable {
                version: efi::MEMORY_ATTRIBUTES_TABLE_VERSION,
                number_of_entries: 0,
                descriptor_size: core::mem::size_of::<efi::MemoryDescriptor>() as u32,
                reserved: 0,
                entry: [EMPTY_DESCRIPTOR; 32],
            },
            esrt: EsrtTable {
                header: EsrtHeader {
                    resource_count: 0,
                    resource_count_max: 1,
                    resource_version: 1,
                },
                entry: EsrtEntry {
                    firmware_class: EMPTY_GUID,
                    firmware_type: 1,
                    firmware_version: 0,
                    lowest_supported_version: 0,
                    capsule_flags: 0,
                    last_attempt_version: 0,
                    last_attempt_status: 0,
                },
            },
        }
    }

    pub fn initialize(
        &mut self,
        boot_services: u64,
        time_supported: bool,
    ) -> Result<(), efi::Status> {
        self.system.firmware_vendor = self.vendor.as_mut_ptr();
        self.system.runtime_services = &mut self.runtime;
        self.system.boot_services = boot_services as *mut efi::BootServices;
        self.system.configuration_table = self.configuration.as_mut_ptr();
        if time_supported {
            self.properties.runtime_services_supported |= efi::RT_SUPPORTED_GET_TIME;
        }
        let properties = core::ptr::addr_of_mut!(self.properties).cast();
        let memory_attributes = core::ptr::addr_of_mut!(self.memory_attributes).cast();
        self.install_image_table(*efi::RT_PROPERTIES_TABLE_GUID.as_bytes(), properties)?;
        self.install_image_table(
            *efi::MEMORY_ATTRIBUTES_TABLE_GUID.as_bytes(),
            memory_attributes,
        )?;
        self.recompute_crcs();
        Ok(())
    }

    fn install_image_table(
        &mut self,
        guid: [u8; 16],
        address: *mut c_void,
    ) -> Result<(), efi::Status> {
        self.install(ConfigurationRegistration {
            guid,
            table_address: address as u64,
            policy: configuration_policy::IMAGE_RUNTIME,
            reserved: 0,
        })
    }

    pub fn install(&mut self, registration: ConfigurationRegistration) -> Result<(), efi::Status> {
        if let Some(index) = self.configuration[..self.configuration_count]
            .iter()
            .position(|entry| *entry.vendor_guid.as_bytes() == registration.guid)
        {
            if registration.table_address == 0 {
                self.configuration
                    .copy_within(index + 1..self.configuration_count, index);
                self.configuration_metadata
                    .copy_within(index + 1..self.configuration_count, index);
                self.configuration_count -= 1;
                self.configuration[self.configuration_count] = efi::ConfigurationTable {
                    vendor_guid: efi::Guid::from_bytes(&[0; 16]),
                    vendor_table: core::ptr::null_mut(),
                };
                self.configuration_metadata[self.configuration_count] =
                    ConfigurationMetadata::empty();
            } else {
                self.configuration[index].vendor_table = registration.table_address as *mut c_void;
                self.configuration_metadata[index] = ConfigurationMetadata {
                    policy: registration.policy,
                    physical_address: registration.table_address,
                };
            }
            self.publish_configuration_count();
            return Ok(());
        }
        if registration.table_address == 0 {
            return Err(efi::Status::NOT_FOUND);
        }
        if !matches!(
            registration.policy,
            configuration_policy::PLATFORM_PHYSICAL
                | configuration_policy::IMAGE_RUNTIME
                | configuration_policy::EXTERNAL_PHYSICAL
        ) {
            return Err(efi::Status::UNSUPPORTED);
        }
        let index = self.configuration_count;
        if index >= MAX_CONFIGURATION_TABLES {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        self.configuration[index] = efi::ConfigurationTable {
            vendor_guid: efi::Guid::from_bytes(&registration.guid),
            vendor_table: registration.table_address as *mut c_void,
        };
        self.configuration_metadata[index] = ConfigurationMetadata {
            policy: registration.policy,
            physical_address: registration.table_address,
        };
        self.configuration_count += 1;
        self.publish_configuration_count();
        Ok(())
    }

    pub fn set_console(&mut self, registration: ConsoleRegistration) -> Result<(), efi::Status> {
        match registration.kind {
            0 => {
                self.system.console_in_handle = registration.handle as efi::Handle;
                self.system.con_in =
                    registration.protocol as *mut efi::protocols::simple_text_input::Protocol;
            }
            1 => {
                self.system.console_out_handle = registration.handle as efi::Handle;
                self.system.con_out =
                    registration.protocol as *mut efi::protocols::simple_text_output::Protocol;
            }
            2 => {
                self.system.standard_error_handle = registration.handle as efi::Handle;
                self.system.std_err =
                    registration.protocol as *mut efi::protocols::simple_text_output::Protocol;
            }
            _ => return Err(efi::Status::INVALID_PARAMETER),
        }
        self.recompute_crcs();
        Ok(())
    }

    pub fn install_esrt(&mut self, registration: EsrtRegistration) -> Result<(), efi::Status> {
        self.esrt.header.resource_count = 1;
        self.esrt.entry = EsrtEntry {
            firmware_class: efi::Guid::from_bytes(&registration.firmware_guid),
            firmware_type: 1,
            firmware_version: registration.firmware_version,
            lowest_supported_version: registration.lowest_supported_version,
            capsule_flags: registration.capsule_flags,
            last_attempt_version: registration.last_attempt_version,
            last_attempt_status: registration.last_attempt_status,
        };
        let esrt = core::ptr::addr_of_mut!(self.esrt).cast();
        self.install_image_table(ESRT_GUID, esrt)
    }

    pub fn prepare_memory_attributes(
        &mut self,
        descriptors: &[efi::MemoryDescriptor],
        sections: &[SectionRecord],
        _ranges: &[RangeRecord],
    ) -> Result<(), efi::Status> {
        let mut count = 0usize;
        for section in sections {
            let memory_type = if section.flags & section_flags::EXECUTE != 0 {
                efi::RUNTIME_SERVICES_CODE
            } else {
                efi::RUNTIME_SERVICES_DATA
            };
            let mut descriptor = exact_runtime_descriptor(
                descriptors,
                section.physical_base,
                u64::from(section.byte_len),
                memory_type,
            )?;
            if section.flags & section_flags::EXECUTE != 0 {
                descriptor.attribute = (descriptor.attribute | efi::MEMORY_RO) & !efi::MEMORY_XP;
            } else if section.flags & section_flags::WRITE != 0 {
                descriptor.attribute = (descriptor.attribute | efi::MEMORY_XP) & !efi::MEMORY_RO;
            } else {
                descriptor.attribute |= efi::MEMORY_RO | efi::MEMORY_XP;
            }
            let slot = self
                .memory_attributes
                .entry
                .get_mut(count)
                .ok_or(efi::Status::OUT_OF_RESOURCES)?;
            *slot = descriptor;
            count += 1;
        }
        self.memory_attributes.number_of_entries = count as u32;
        Ok(())
    }

    pub fn seal(&mut self) {
        self.system.console_in_handle = core::ptr::null_mut();
        self.system.con_in = core::ptr::null_mut();
        self.system.console_out_handle = core::ptr::null_mut();
        self.system.con_out = core::ptr::null_mut();
        self.system.standard_error_handle = core::ptr::null_mut();
        self.system.std_err = core::ptr::null_mut();
        self.system.boot_services = core::ptr::null_mut();
        self.recompute_crcs();
    }

    pub fn convert_internal_pointers(&mut self, mut convert: impl FnMut(u64) -> Option<u64>) {
        self.system.firmware_vendor = convert(self.system.firmware_vendor as u64)
            .unwrap_or(self.system.firmware_vendor as u64)
            as *mut efi::Char16;
        self.system.runtime_services = convert(self.system.runtime_services as u64)
            .unwrap_or(self.system.runtime_services as u64)
            as *mut efi::RuntimeServices;
        self.system.configuration_table = convert(self.system.configuration_table as u64)
            .unwrap_or(self.system.configuration_table as u64)
            as *mut efi::ConfigurationTable;
        for index in 0..self.configuration_count {
            if self.configuration_metadata[index].policy == configuration_policy::IMAGE_RUNTIME {
                let physical = self.configuration_metadata[index].physical_address;
                if let Some(virtual_address) = convert(physical) {
                    self.configuration[index].vendor_table = virtual_address as *mut c_void;
                }
            }
        }
    }

    pub fn recompute_crcs(&mut self) {
        self.recompute_runtime_crc_with(|_, byte| byte);
        self.recompute_system_crc();
    }

    /// Calculate the Runtime Services CRC as if deferred relocation slots had
    /// their final virtual values, without changing those slots while physical
    /// execution is still in progress.
    pub fn recompute_runtime_crc_with(&mut self, mut transform: impl FnMut(u64, u8) -> u8) {
        self.runtime.hdr.crc32 = 0;
        let runtime = core::ptr::addr_of!(self.runtime).cast::<u8>();
        let runtime_size = self.runtime.hdr.header_size as usize;
        self.runtime.hdr.crc32 = crc32::calculate_with(runtime_size, |index| {
            // SAFETY: `runtime` is the initialized, image-owned table and
            // index is bounded by its fixed header size.
            let byte = unsafe { runtime.add(index).read() };
            transform(runtime as u64 + index as u64, byte)
        });
    }

    fn recompute_system_crc(&mut self) {
        self.system.hdr.crc32 = 0;
        let system = core::ptr::addr_of!(self.system).cast::<u8>();
        let system_size = self.system.hdr.header_size as usize;
        // SAFETY: the table is initialized image-owned storage and header_size
        // is fixed to its exact Rust layout in `new`.
        let system_bytes = unsafe { core::slice::from_raw_parts(system, system_size) };
        self.system.hdr.crc32 = crc32::calculate(system_bytes);
    }

    fn publish_configuration_count(&mut self) {
        self.system.number_of_table_entries = self.configuration_count;
        self.recompute_crcs();
    }
}

fn exact_runtime_descriptor(
    descriptors: &[efi::MemoryDescriptor],
    physical_start: u64,
    byte_len: u64,
    memory_type: u32,
) -> Result<efi::MemoryDescriptor, efi::Status> {
    if byte_len == 0 || !physical_start.is_multiple_of(4096) || !byte_len.is_multiple_of(4096) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let physical_end = physical_start
        .checked_add(byte_len)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    descriptors
        .iter()
        .try_fold(None, |found, descriptor| {
            let descriptor_end = descriptor
                .number_of_pages
                .checked_mul(4096)
                .and_then(|length| descriptor.physical_start.checked_add(length))
                .ok_or(efi::Status::INVALID_PARAMETER)?;
            if descriptor.r#type != memory_type
                || descriptor.attribute & efi::MEMORY_RUNTIME == 0
                || descriptor.physical_start > physical_start
                || descriptor_end < physical_end
            {
                return Ok(found);
            }
            if found.is_some() {
                return Err(efi::Status::INVALID_PARAMETER);
            }
            let virtual_start = if descriptor.virtual_start == 0 {
                0
            } else {
                descriptor
                    .virtual_start
                    .checked_add(physical_start - descriptor.physical_start)
                    .ok_or(efi::Status::INVALID_PARAMETER)?
            };
            Ok(Some(efi::MemoryDescriptor {
                r#type: memory_type,
                physical_start,
                virtual_start,
                number_of_pages: byte_len / 4096,
                // EFI_MEMORY_ATTRIBUTES_TABLE entries may carry only the
                // permission bits, never cacheability or EFI_MEMORY_RUNTIME.
                attribute: 0,
            }))
        })?
        .ok_or(efi::Status::NOT_FOUND)
}
