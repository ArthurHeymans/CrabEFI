//! EFI Runtime Services
//!
//! This module implements the EFI Runtime Services table, which provides
//! time, variable, and system reset services that persist after ExitBootServices.

#[cfg(all(feature = "rt-debug", target_arch = "x86_64"))]
use crate::arch::x86_64::io;
use crate::efi::auth;
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES};
use zerocopy::FromBytes;

// ============================================================================
// Runtime Serial Logging (post-SetVirtualAddressMap)
// ============================================================================
//
// After SetVirtualAddressMap, the `log` crate is disabled because its stored
// `&dyn Log` vtable pointer becomes a stale physical address. These functions
// write directly to the serial port (COM1, 0x3F8) using x86 port I/O, which
// is completely independent of the virtual memory address space.
//
// Gated behind the `rt-debug` feature flag (default off) to avoid overhead.

#[cfg(all(feature = "rt-debug", target_arch = "x86_64"))]
mod rt_serial {
    use super::*;

    /// COM1 base I/O port
    const COM1: u16 = 0x3F8;

    /// Write a single byte to the serial port (blocking, waits for TX ready).
    #[inline]
    pub fn byte(b: u8) {
        unsafe {
            // Wait for Transmitter Holding Register Empty (bit 5 of LSR)
            while io::inb(COM1 + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            io::outb(COM1, b);
        }
    }

    /// Write a string to the serial port (with \n -> \r\n conversion).
    pub fn str(s: &str) {
        for &b in s.as_bytes() {
            if b == b'\n' {
                byte(b'\r');
            }
            byte(b);
        }
    }

    /// Write a u64 as hex to the serial port.
    pub fn hex(val: u64) {
        str("0x");
        if val == 0 {
            byte(b'0');
            return;
        }
        let mut started = false;
        for i in (0..16).rev() {
            let nibble = ((val >> (i * 4)) & 0xF) as u8;
            if nibble != 0 || started {
                started = true;
                byte(if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                });
            }
        }
    }
}

/// Runtime serial print -- tagged with "[RT] " prefix.
/// No-op when the `rt-debug` feature is disabled.
macro_rules! rt_serial_print {
    ($msg:expr) => {
        #[cfg(feature = "rt-debug")]
        {
            rt_serial::str("[RT] ");
            rt_serial::str($msg);
            rt_serial::str("\n");
        }
    };
    ($msg:expr, $hex:expr) => {
        #[cfg(feature = "rt-debug")]
        {
            rt_serial::str("[RT] ");
            rt_serial::str($msg);
            rt_serial::hex($hex as u64);
            rt_serial::str("\n");
        }
    };
}

// ============================================================================
// Runtime Access Control
// ============================================================================

/// Check if a variable is accessible at runtime based on its attributes.
///
/// Per UEFI Specification Section 8.2:
/// - Variables with EFI_VARIABLE_BOOTSERVICE_ACCESS but without EFI_VARIABLE_RUNTIME_ACCESS
///   are only accessible before ExitBootServices() is called.
/// - After ExitBootServices(), these boot-services-only variables should return NOT_FOUND.
///
/// Returns true if the variable is accessible, false if it should be hidden at runtime.
#[inline]
fn is_variable_accessible_at_runtime(attributes: u32) -> bool {
    // If ExitBootServices hasn't been called, all variables are accessible
    if !state::is_exit_boot_services_called() {
        return true;
    }

    // At runtime, only variables with RUNTIME_ACCESS are accessible
    (attributes & auth::attributes::RUNTIME_ACCESS) != 0
}
use alloc::vec::Vec as AllocVec;
use core::ffi::c_void;
use r_efi::efi::{
    self, CapsuleHeader, Guid, ResetType, Status, TableHeader, Time, TimeCapabilities,
};

fn runtime_auth_status(error: auth::AuthError) -> Status {
    if error == auth::AuthError::BufferTooSmall {
        Status::OUT_OF_RESOURCES
    } else {
        error.into()
    }
}

/// Runtime Services signature "RUNTSERV"
const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552;

/// Runtime Services revision
const EFI_RUNTIME_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Static runtime services table
static mut RUNTIME_SERVICES: efi::RuntimeServices = efi::RuntimeServices {
    hdr: TableHeader {
        signature: EFI_RUNTIME_SERVICES_SIGNATURE,
        revision: EFI_RUNTIME_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::RuntimeServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    get_time,
    set_time,
    get_wakeup_time,
    set_wakeup_time,
    set_virtual_address_map,
    convert_pointer,
    get_variable,
    get_next_variable_name,
    set_variable,
    get_next_high_mono_count,
    reset_system,
    update_capsule,
    query_capsule_capabilities,
    query_variable_info,
};

/// Get a pointer to the runtime services table
pub fn get_runtime_services() -> *mut efi::RuntimeServices {
    &raw mut RUNTIME_SERVICES
}

/// Get the address of runtime services code (for memory map reservation)
///
/// Returns the address of the set_virtual_address_map function, which is used
/// to determine where the runtime services code section is located.
pub fn get_runtime_code_address() -> u64 {
    set_virtual_address_map as *const () as u64
}

// ============================================================================
// Time Services
// ============================================================================

extern "efiapi" fn get_time(time: *mut Time, capabilities: *mut TimeCapabilities) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("GetTime");
    }
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Read time from CMOS RTC (shared implementation in auth::time)
    let (year, month, day, hour, minute, second) = crate::efi::auth::time::read_rtc_time();

    unsafe {
        (*time).year = year;
        (*time).month = month;
        (*time).day = day;
        (*time).hour = hour;
        (*time).minute = minute;
        (*time).second = second;
        (*time).nanosecond = 0;
        (*time).timezone = efi::UNSPECIFIED_TIMEZONE;
        (*time).daylight = 0;
        (*time).pad1 = 0;
        (*time).pad2 = 0;
    }

    if !capabilities.is_null() {
        unsafe {
            (*capabilities).resolution = 1; // 1 second resolution
            (*capabilities).accuracy = 50_000_000; // 50ms accuracy
            (*capabilities).sets_to_zero = efi::Boolean::from(false);
        }
    }

    Status::SUCCESS
}

extern "efiapi" fn set_time(_time: *mut Time) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("SetTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn get_wakeup_time(
    _enabled: *mut efi::Boolean,
    _pending: *mut efi::Boolean,
    _time: *mut Time,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("GetWakeupTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn set_wakeup_time(_enable: efi::Boolean, _time: *mut Time) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("SetWakeupTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

// ============================================================================
// Virtual Memory Services
// ============================================================================

/// EFI_OPTIONAL_PTR: if set, a NULL pointer is acceptable
const EFI_OPTIONAL_PTR: usize = 0x00000001;
/// EFI_MEMORY_RUNTIME attribute bit (bit 63)
const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;
/// Page size constant
const EFI_PAGE_SIZE: u64 = 4096;

/// Global state for ConvertPointer -- only valid during SetVirtualAddressMap.
static mut VIRTUAL_MAP_PTR: *const u8 = core::ptr::null();
static mut VIRTUAL_MAP_DESCRIPTOR_SIZE: usize = 0;
static mut VIRTUAL_MAP_ENTRY_COUNT: usize = 0;
/// Whether SetVirtualAddressMap has been called (one-shot operation).
///
/// Uses `AtomicBool` instead of `static mut` because this flag is read from
/// runtime service calls after ExitBootServices, potentially from OS context.
/// The actual write is a one-shot during SetVirtualAddressMap.
static VIRTUAL_MODE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn virtual_address_for_range(
    virtual_map: *const u8,
    descriptor_size: usize,
    num_entries: usize,
    start: u64,
    end: u64,
) -> Option<u64> {
    if start >= end {
        return None;
    }
    (0..num_entries).find_map(|index| {
        // SAFETY: SVAM validated the complete descriptor array before calling
        // this helper, and descriptor_size is at least the descriptor ABI size.
        let descriptor = unsafe {
            &*(virtual_map.add(index.checked_mul(descriptor_size)?) as *const efi::MemoryDescriptor)
        };
        if descriptor.attribute & EFI_MEMORY_RUNTIME == 0 {
            return None;
        }
        let descriptor_end = descriptor
            .number_of_pages
            .checked_mul(EFI_PAGE_SIZE)?
            .checked_add(descriptor.physical_start)?;
        (start >= descriptor.physical_start && end <= descriptor_end).then(|| {
            descriptor
                .virtual_start
                .wrapping_add(start - descriptor.physical_start)
        })
    })
}

extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> Status {
    log::info!(
        "RT.SetVirtualAddressMap(size={}, desc_size={}, version={}, map={:?})",
        memory_map_size,
        descriptor_size,
        descriptor_version,
        virtual_map
    );

    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        return Status::UNSUPPORTED;
    }

    if virtual_map.is_null() || descriptor_size == 0 {
        return Status::INVALID_PARAMETER;
    }

    if descriptor_size < core::mem::size_of::<efi::MemoryDescriptor>() {
        return Status::INVALID_PARAMETER;
    }

    if memory_map_size == 0 || !memory_map_size.is_multiple_of(descriptor_size) {
        return Status::INVALID_PARAMETER;
    }
    let num_entries = memory_map_size / descriptor_size;

    // Sanity check: a realistic memory map has at most a few hundred entries.
    // Reject obviously corrupted sizes to prevent walking off into unmapped memory.
    const MAX_REASONABLE_ENTRIES: usize = 4096;
    if num_entries > MAX_REASONABLE_ENTRIES {
        log::error!(
            "SetVirtualAddressMap: unreasonable entry count {} (max {})",
            num_entries,
            MAX_REASONABLE_ENTRIES
        );
        return Status::INVALID_PARAMETER;
    }

    log::info!("SetVirtualAddressMap: {} entries", num_entries);

    // Validate every firmware-owned runtime range before the one-way commit.
    // In particular, RuntimeState and the resettable allocation workspace are
    // separate objects in `.runtime_state`; validating only the root would let
    // the OS omit the arena and fault the next authenticated write.
    let map = virtual_map as *const u8;
    let state_phys = crate::runtime_state::physical_address();
    let Some(state_end) =
        state_phys.checked_add(core::mem::size_of::<crate::runtime_state::RuntimeState>() as u64)
    else {
        return Status::INVALID_PARAMETER;
    };
    let Some(new_state) =
        virtual_address_for_range(map, descriptor_size, num_entries, state_phys, state_end)
    else {
        return Status::INVALID_PARAMETER;
    };

    for (start, end) in crate::heap::runtime_workspace_ranges() {
        if virtual_address_for_range(map, descriptor_size, num_entries, start, end).is_none() {
            return Status::INVALID_PARAMETER;
        }
    }
    let new_deferred_buffer = match crate::efi::varstore::deferred::runtime_buffer_range() {
        Some((start, end)) => {
            let Some(address) =
                virtual_address_for_range(map, descriptor_size, num_entries, start, end)
            else {
                return Status::INVALID_PARAMETER;
            };
            Some(address)
        }
        None => None,
    };

    #[cfg(feature = "platform-entry")]
    {
        unsafe extern "C" {
            static __runtime_code_start: u8;
            static __runtime_code_end: u8;
            static __runtime_data_start: u8;
            static __runtime_data_end: u8;
        }
        let required = [
            (
                &raw const __runtime_code_start as u64,
                &raw const __runtime_code_end as u64,
            ),
            (
                (&raw const __runtime_data_start as u64 + EFI_PAGE_SIZE - 1) & !(EFI_PAGE_SIZE - 1),
                &raw const __runtime_data_end as u64,
            ),
        ];
        if required.into_iter().any(|(start, end)| {
            virtual_address_for_range(map, descriptor_size, num_entries, start, end).is_none()
        }) {
            return Status::INVALID_PARAMETER;
        }
    }

    let rt_start = get_runtime_services() as u64;
    let st_start = super::system_table::get_system_table() as u64;
    let required_tables = [
        (
            rt_start,
            rt_start + core::mem::size_of::<efi::RuntimeServices>() as u64,
        ),
        (
            st_start,
            st_start + core::mem::size_of::<efi::SystemTable>() as u64,
        ),
    ];
    if required_tables.into_iter().any(|(start, end)| {
        virtual_address_for_range(map, descriptor_size, num_entries, start, end).is_none()
    }) {
        return Status::INVALID_PARAMETER;
    }

    // The System Table's own runtime pointers are mandatory. VendorTable
    // values may intentionally identify ACPI/SMBIOS physical memory and remain
    // optional, but the configuration entry array itself must stay mapped.
    let st = super::system_table::get_system_table();
    let table_pointers_valid = unsafe {
        let configuration_valid = if (*st).configuration_table.is_null() {
            (*st).number_of_table_entries == 0
        } else {
            (*st)
                .number_of_table_entries
                .checked_mul(core::mem::size_of::<state::ConfigurationTable>())
                .and_then(|size| {
                    let start = (*st).configuration_table as u64;
                    start.checked_add(size as u64).map(|end| (start, end))
                })
                .is_some_and(|(start, end)| {
                    virtual_address_for_range(map, descriptor_size, num_entries, start, end)
                        .is_some()
                })
        };
        let vendor_valid = (*st).firmware_vendor.is_null()
            || virtual_address_for_range(
                map,
                descriptor_size,
                num_entries,
                (*st).firmware_vendor as u64,
                (*st).firmware_vendor as u64 + 2,
            )
            .is_some();
        configuration_valid && vendor_valid
    };
    if !table_pointers_valid {
        return Status::INVALID_PARAMETER;
    }

    let runtime_functions = [
        get_time as *const () as u64,
        set_time as *const () as u64,
        get_wakeup_time as *const () as u64,
        set_wakeup_time as *const () as u64,
        get_variable as *const () as u64,
        get_next_variable_name as *const () as u64,
        set_variable as *const () as u64,
        get_next_high_mono_count as *const () as u64,
        reset_system as *const () as u64,
        update_capsule as *const () as u64,
        query_capsule_capabilities as *const () as u64,
        query_variable_info as *const () as u64,
    ];
    if runtime_functions.into_iter().any(|address| {
        virtual_address_for_range(map, descriptor_size, num_entries, address, address + 1).is_none()
    }) {
        return Status::INVALID_PARAMETER;
    }

    // Step 0: Let platform glue disable physical-only resources before the OS
    // switches EFI runtime services to virtual addressing.
    if let Some(hooks) = crate::state::drivers().platform.hooks {
        hooks.before_set_virtual_address_map();
    }

    // Step 1: Commit to virtual mode. The boot heap contains absolute
    // free-list pointers and cannot cross this transition, so freeze it before
    // any descriptor is converted.
    crate::heap::freeze_for_virtual_address_map();

    // Step 2: Set up globals so ConvertPointer can access the virtual map
    unsafe {
        VIRTUAL_MAP_PTR = virtual_map as *const u8;
        VIRTUAL_MAP_DESCRIPTOR_SIZE = descriptor_size;
        VIRTUAL_MAP_ENTRY_COUNT = num_entries;
    }

    // Step 3: Signal EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE events
    {
        use crate::efi::boot_services::{
            EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, signal_event_group_for_runtime,
        };

        const EFI_EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE: efi::Guid = efi::Guid::from_fields(
            0x13FA7698,
            0xC831,
            0x49C7,
            0x87,
            0xEA,
            &[0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96],
        );
        signal_event_group_for_runtime(&EFI_EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE);

        // Signal legacy events without invoking foreign callbacks while an
        // exclusive FirmwareState borrow is live. A callback may re-enter EFI.
        let mut legacy_events: heapless::Vec<usize, { state::MAX_EVENTS }> = heapless::Vec::new();
        state::with_efi_mut(|efi_state| {
            for (index, entry) in efi_state.events.iter_mut().enumerate() {
                if entry.event_type == EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE {
                    entry.signaled = true;
                    let _ = legacy_events.push(index);
                }
            }
        });
        for event_id in legacy_events {
            let notify = {
                let entry = &state::efi().events[event_id];
                entry
                    .notify_function
                    .map(|function| (function, entry.notify_context))
            };
            if let Some((function, context)) = notify {
                function(event_id as efi::Event, context);
            }
        }
    }

    // Step 4a: Relocate the single pointer-free runtime root.
    let rt_ptr = get_runtime_services();
    // SAFETY: the validated descriptor containing the complete physical root
    // supplies its live virtual alias.
    unsafe {
        crate::runtime_state::relocate(new_state as *mut crate::runtime_state::RuntimeState);
    }
    if let Some(address) = new_deferred_buffer {
        crate::efi::varstore::deferred::relocate_buffer(address);
    }
    log::debug!(
        "SetVirtualAddressMap: relocated runtime state ptr {:#x} -> {:#x}",
        state_phys,
        new_state
    );

    // Step 4b: Relocate RuntimeServices function pointers via ConvertPointer.
    //
    // Each function pointer targets code that may be in a DIFFERENT runtime
    // region than the RT table itself. For example, when CrabEFI is linked as
    // a library into fstart: the RT table (static) lives in BSS/RuntimeServicesData
    // while the function pointer targets live in ROM/RuntimeServicesCode. These
    // two regions have different physical→virtual offsets.
    //
    // We use convert_pointer_internal() which searches the virtual map for the
    // region containing each pointer's target address, rather than assuming a
    // single fixed offset.
    //
    // NOTE: set_virtual_address_map and convert_pointer are NOT relocated per
    // EDK2 convention — they are never called again after this point.
    unsafe {
        let rt = &mut *rt_ptr;
        convert_rt_fn_ptr(&mut rt.get_time);
        convert_rt_fn_ptr(&mut rt.set_time);
        convert_rt_fn_ptr(&mut rt.get_wakeup_time);
        convert_rt_fn_ptr(&mut rt.set_wakeup_time);
        convert_rt_fn_ptr(&mut rt.get_variable);
        convert_rt_fn_ptr(&mut rt.get_next_variable_name);
        convert_rt_fn_ptr(&mut rt.set_variable);
        convert_rt_fn_ptr(&mut rt.get_next_high_mono_count);
        convert_rt_fn_ptr(&mut rt.reset_system);
        convert_rt_fn_ptr(&mut rt.update_capsule);
        convert_rt_fn_ptr(&mut rt.query_capsule_capabilities);
        convert_rt_fn_ptr(&mut rt.query_variable_info);
    }
    log::debug!("SetVirtualAddressMap: relocated RT function pointers via ConvertPointer");

    // Step 4b: Relocate GOT (Global Offset Table) entries.
    //
    // With relocation-model=pic, the compiler emits `call *GOT(%rip)` for
    // compiler_builtins intrinsics (memcpy, memset, memmove, memcmp).
    // The linker fills these GOT entries with absolute physical addresses.
    // After SVAM, the physical addresses are unmapped, so we must adjust
    // each GOT entry by the appropriate virtual offset.
    //
    // Only available when CrabEFI owns the linker script (platform-entry).
    // When linked as a library, the host firmware's linker script controls
    // the GOT and must provide its own SVAM relocation if needed.
    #[cfg(feature = "platform-entry")]
    {
        unsafe extern "C" {
            static _got_start: u8;
            static _got_end: u8;
        }
        let got_start = &raw const _got_start as *mut u64;
        let got_end = &raw const _got_end;
        let got_count = if (got_end as usize) >= (got_start as usize) {
            (got_end as usize - got_start as usize) / core::mem::size_of::<u64>()
        } else {
            log::error!("SetVirtualAddressMap: GOT range is invalid (_got_end < _got_start)");
            0
        };

        for slot in 0..got_count {
            let entry_ptr = unsafe { got_start.add(slot) };
            let phys_val = unsafe { core::ptr::read_volatile(entry_ptr) };

            // Find which runtime region this GOT entry points into
            for i in 0..num_entries {
                let desc = unsafe {
                    &*((virtual_map as *const u8).add(i * descriptor_size)
                        as *const efi::MemoryDescriptor)
                };
                if (desc.attribute & EFI_MEMORY_RUNTIME) == 0 {
                    continue;
                }
                let p_start = desc.physical_start;
                let p_end = desc
                    .number_of_pages
                    .saturating_mul(EFI_PAGE_SIZE)
                    .saturating_add(p_start);
                if phys_val >= p_start && phys_val < p_end {
                    let offset = desc.virtual_start as i64 - p_start as i64;
                    let new_val = (phys_val as i64 + offset) as u64;
                    unsafe { core::ptr::write_volatile(entry_ptr, new_val) };
                    break;
                }
            }
        }
        log::debug!("SetVirtualAddressMap: relocated {} GOT entries", got_count);
    }

    // Step 5: Recompute CRC32 on RuntimeServices table (Windows validates this)
    unsafe {
        use super::boot_services::compute_crc32;
        let rt = &mut *rt_ptr;
        rt.hdr.crc32 = 0;
        let rt_bytes =
            core::slice::from_raw_parts(rt_ptr as *const u8, rt.hdr.header_size as usize);
        rt.hdr.crc32 = compute_crc32(rt_bytes);
    }

    // Step 6: Convert System Table pointers (firmware_vendor, configuration_table, runtime_services)
    // Per EDK2, we must also convert VendorTable pointers inside each configuration
    // table entry -- otherwise the OS dereferences stale physical addresses.
    {
        use super::system_table;
        let st = system_table::get_system_table();
        unsafe {
            // Convert VendorTable pointers inside each configuration table entry.
            // This MUST happen before converting the configuration_table pointer itself,
            // since we need the physical address to access the entries.
            // (EDK2: CoreConvertPointer for each ConfigurationTable[i].VendorTable)
            if !(*st).configuration_table.is_null() {
                let config = (*st).configuration_table;
                let count = (*st).number_of_table_entries;
                for i in 0..count {
                    let entry = &mut *config.add(i);
                    if !entry.vendor_table.is_null() {
                        // Use EFI_OPTIONAL_PTR: if the pointer doesn't fall in a
                        // runtime region (e.g. ACPI tables in ACPIReclaimMemory),
                        // ConvertPointer returns NOT_FOUND and we leave it unchanged.
                        let _ = convert_pointer_internal(0, &mut entry.vendor_table);
                    }
                }
            }

            // Convert firmware_vendor
            if !(*st).firmware_vendor.is_null() {
                let mut vendor_ptr = (*st).firmware_vendor as *mut c_void;
                if convert_pointer_internal(0, &mut vendor_ptr) == Status::SUCCESS {
                    (*st).firmware_vendor = vendor_ptr as *const u16;
                }
            }

            // Convert configuration_table pointer itself
            if !(*st).configuration_table.is_null() {
                let mut config_ptr = (*st).configuration_table as *mut c_void;
                if convert_pointer_internal(EFI_OPTIONAL_PTR, &mut config_ptr) == Status::SUCCESS {
                    (*st).configuration_table = config_ptr as *mut state::ConfigurationTable;
                }
            }

            // Convert runtime_services pointer
            if !(*st).runtime_services.is_null() {
                let mut rt_svc_ptr = (*st).runtime_services as *mut c_void;
                if convert_pointer_internal(0, &mut rt_svc_ptr) == Status::SUCCESS {
                    (*st).runtime_services = rt_svc_ptr as *mut efi::RuntimeServices;
                }
            }

            // Recompute System Table CRC32
            (*st).hdr.crc32 = 0;
            let st_bytes =
                core::slice::from_raw_parts(st as *const u8, (*st).hdr.header_size as usize);
            (*st).hdr.crc32 = super::boot_services::compute_crc32(st_bytes);
        }
    }

    // Step 7: Clear virtual map globals
    unsafe {
        VIRTUAL_MAP_PTR = core::ptr::null();
        VIRTUAL_MAP_DESCRIPTOR_SIZE = 0;
        VIRTUAL_MAP_ENTRY_COUNT = 0;
    }

    log::info!("SetVirtualAddressMap: complete, disabling log crate for virtual mode");

    // CRITICAL: Disable the log crate. After SVAM returns, the OS uses virtual
    // addresses. The log crate stores a &'static dyn Log fat pointer at physical
    // addresses -- any log! call would dereference stale pointers and page-fault.
    // Setting max_level to Off makes the log! macros short-circuit before any
    // pointer dereference.
    log::set_max_level(log::LevelFilter::Off);

    // No physical FirmwareState access is legal after this point. Commit the
    // relocated runtime-root flag before returning to the OS, then retain the
    // local flag for existing runtime-service diagnostics.
    crate::runtime_state::commit_virtual_mode();
    VIRTUAL_MODE.store(true, core::sync::atomic::Ordering::Release);

    #[cfg(feature = "rt-debug")]
    rt_serial::str("[RT] SetVirtualAddressMap returning SUCCESS\n");

    Status::SUCCESS
}

/// Convert a RuntimeServices function pointer using the virtual memory map.
///
/// Reads the physical address stored in `ptr`, searches the virtual map for
/// the runtime region containing that address, and writes back the virtual
/// address. This handles the case where the function pointer target (code) is in a different
/// runtime region than the RuntimeServices table (data) — e.g. when CrabEFI
/// is linked as a library with code in ROM and data in RAM.
///
/// No-op if the address isn't found in any runtime region.
///
/// # Safety
///
/// - The VIRTUAL_MAP globals must be set up (step 2 of SetVirtualAddressMap).
/// - `ptr` must point to a valid function pointer field in RuntimeServices.
unsafe fn convert_rt_fn_ptr<T>(ptr: &mut T) {
    // SAFETY: We read the raw u64 value of the function pointer, convert it
    // via the virtual map, and write back the converted virtual address.
    unsafe {
        let phys_val = core::ptr::read(ptr as *const T as *const u64);
        let mut addr = phys_val as *mut c_void;
        if convert_pointer_internal(0, &mut addr) == Status::SUCCESS {
            core::ptr::write(ptr as *mut T as *mut u64, addr as u64);
        }
    }
}

/// Internal ConvertPointer implementation used by both the EFI callback and
/// our own SetVirtualAddressMap.
fn convert_pointer_internal(debug_disposition: usize, address: &mut *mut c_void) -> Status {
    let phys_addr = *address as u64;

    if phys_addr == 0 {
        return if (debug_disposition & EFI_OPTIONAL_PTR) != 0 {
            Status::SUCCESS
        } else {
            Status::INVALID_PARAMETER
        };
    }

    unsafe {
        if VIRTUAL_MAP_PTR.is_null() {
            return Status::NOT_FOUND;
        }

        for i in 0..VIRTUAL_MAP_ENTRY_COUNT {
            let desc = &*(VIRTUAL_MAP_PTR.add(i * VIRTUAL_MAP_DESCRIPTOR_SIZE)
                as *const efi::MemoryDescriptor);

            if (desc.attribute & EFI_MEMORY_RUNTIME) == 0 {
                continue;
            }

            let phys_end = desc
                .number_of_pages
                .saturating_mul(EFI_PAGE_SIZE)
                .saturating_add(desc.physical_start);
            if phys_addr >= desc.physical_start && phys_addr < phys_end {
                *address = (phys_addr - desc.physical_start + desc.virtual_start) as *mut c_void;
                return Status::SUCCESS;
            }
        }
    }

    Status::NOT_FOUND
}

extern "efiapi" fn convert_pointer(debug_disposition: usize, address: *mut *mut c_void) -> Status {
    if address.is_null() {
        return Status::INVALID_PARAMETER;
    }
    convert_pointer_internal(debug_disposition, unsafe { &mut *address })
}

// ============================================================================
// Variable Services
// ============================================================================

extern "efiapi" fn get_variable(
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    crate::phase::dispatch(|phase| {
        get_variable_for_phase(
            phase,
            variable_name,
            vendor_guid,
            attributes,
            data_size,
            data,
        )
    })
}

fn get_variable_for_phase(
    phase: crate::phase::Phase<'_>,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial::str("[RT] GetVariable name=");
        if !variable_name.is_null() {
            for i in 0..32 {
                let c = unsafe { *variable_name.add(i) };
                if c == 0 {
                    break;
                }
                rt_serial::byte(c as u8);
            }
        }
        rt_serial::str("\n");
    }
    if variable_name.is_null() || vendor_guid.is_null() || data_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };
    let secure_boot = auth::secure_boot_status_for_phase(&phase);

    // Check for synthesized Secure Boot status variables
    if guid == auth::EFI_GLOBAL_VARIABLE_GUID {
        // Check for SetupMode variable
        if name_eq_const(name, auth::SETUP_MODE_NAME) {
            return get_secure_boot_status_variable(
                secure_boot.setup_mode() as u8,
                attributes,
                data_size,
                data,
            );
        }

        // Check for SecureBoot variable
        if name_eq_const(name, auth::SECURE_BOOT_NAME) {
            return get_secure_boot_status_variable(
                secure_boot.secure_boot_enabled() as u8,
                attributes,
                data_size,
                data,
            );
        }
    }

    if let crate::phase::Phase::Runtime(_) = phase {
        return crate::runtime_state::with(|runtime| {
            let found = runtime
                .iter()
                .find(|(var, _)| var.vendor_guid() == guid && name_eq(var.name(), name));
            match found {
                Some((var, payload)) => {
                    if data.is_null() || unsafe { *data_size } < payload.len() {
                        unsafe { *data_size = payload.len() };
                        Status::BUFFER_TOO_SMALL
                    } else {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                payload.as_ptr(),
                                data as *mut u8,
                                payload.len(),
                            );
                            *data_size = payload.len();
                            if !attributes.is_null() {
                                *attributes = var.attributes();
                            }
                        }
                        Status::SUCCESS
                    }
                }
                None => Status::NOT_FOUND,
            }
        });
    }

    let variables = &state::efi().variables;
    let found = variables
        .iter()
        .find(|var| var.in_use && var.vendor_guid == guid && name_eq(&var.name, name));

    match found {
        Some(var) => {
            // Check if variable is accessible at runtime
            // Boot-services-only variables are hidden after ExitBootServices
            if !is_variable_accessible_at_runtime(var.attributes) {
                return Status::NOT_FOUND;
            }

            let required_size = var.data_size;

            if data.is_null() || unsafe { *data_size } < required_size {
                unsafe { *data_size = required_size };
                return Status::BUFFER_TOO_SMALL;
            }

            // Copy data
            unsafe {
                core::ptr::copy_nonoverlapping(var.data.as_ptr(), data as *mut u8, required_size);
                *data_size = required_size;
                if !attributes.is_null() {
                    *attributes = var.attributes;
                }
            }

            Status::SUCCESS
        }
        None => Status::NOT_FOUND,
    }
}

/// Helper function for returning Secure Boot status variables
fn get_secure_boot_status_variable(
    value: u8,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    let required_size = 1usize;

    if data.is_null() || unsafe { *data_size } < required_size {
        unsafe { *data_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    unsafe {
        *(data as *mut u8) = value;
        *data_size = required_size;
        if !attributes.is_null() {
            // These are read-only boot services + runtime access variables
            *attributes = auth::attributes::BOOTSERVICE_ACCESS | auth::attributes::RUNTIME_ACCESS;
        }
    }

    Status::SUCCESS
}

/// Check if a stored variable would shadow a synthesized variable.
///
/// We synthesize SetupMode and SecureBoot variables with EFI_GLOBAL_VARIABLE_GUID.
/// If a stored variable has the same name and GUID, we must skip it during
/// enumeration to avoid infinite loops.
fn is_synthesized_variable(name: &[u16], guid: &Guid) -> bool {
    if *guid != auth::EFI_GLOBAL_VARIABLE_GUID {
        return false;
    }
    // Check if name matches SetupMode or SecureBoot
    name_eq_slice(name, auth::SETUP_MODE_NAME) || name_eq_slice(name, auth::SECURE_BOOT_NAME)
}

/// Compare two UCS-2 slices for equality (delegates to shared utility)
fn name_eq_slice(a: &[u16], b: &[u16]) -> bool {
    crate::efi::utils::ucs2_eq(a, b)
}

/// Compare a pointer-based UCS-2 string with a constant UCS-2 slice
///
/// Bounded by the expected slice length + 1 (for null terminator check)
/// to avoid unbounded reads from the name pointer.
fn name_eq_const(name: *const u16, expected: &[u16]) -> bool {
    let expected_len = crate::efi::utils::ucs2_len(expected);
    let matches = (0..expected_len).all(|i| {
        let a = unsafe { *name.add(i) };
        a == expected[i]
    });
    // Check that the name pointer is also null-terminated at this position
    matches && unsafe { *name.add(expected_len) == 0 }
}

extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial::str("[RT] GetNextVariableName name=");
        if !variable_name.is_null() {
            for i in 0..32 {
                let c = unsafe { *variable_name.add(i) };
                if c == 0 {
                    break;
                }
                rt_serial::byte(c as u8);
            }
        }
        rt_serial::str("\n");
    }
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let current_name = variable_name;
    let current_guid = unsafe { *vendor_guid };

    // Debug: log input (only first 16 chars of name to avoid huge logs)
    let mut input_name_buf = [0u8; 32];
    let input_name_len = unsafe {
        let mut i = 0;
        while i < 16 {
            let c = *current_name.add(i);
            if c == 0 {
                break;
            }
            input_name_buf[i] = c as u8;
            i += 1;
        }
        i
    };
    let input_name_str = core::str::from_utf8(&input_name_buf[..input_name_len]).unwrap_or("?");
    // Convert GUID to bytes for logging (first 4 bytes)
    let guid_bytes: [u8; 16] = unsafe { core::mem::transmute(current_guid) };
    log::trace!(
        "GetNextVariableName: input name='{}' guid={:02x}{:02x}{:02x}{:02x}-...",
        input_name_str,
        guid_bytes[0],
        guid_bytes[1],
        guid_bytes[2],
        guid_bytes[3]
    );

    // If name is empty, return first synthesized variable (SetupMode)
    let is_first = unsafe { *current_name == 0 };

    if is_first {
        log::trace!("GetNextVariableName: first call, returning SetupMode");
        // Return SetupMode as the first variable
        return copy_variable_name(
            auth::SETUP_MODE_NAME,
            auth::EFI_GLOBAL_VARIABLE_GUID,
            variable_name_size,
            variable_name,
            vendor_guid,
        );
    }

    // Check if current variable is a synthesized Secure Boot variable
    // and return the next one in sequence
    if current_guid == auth::EFI_GLOBAL_VARIABLE_GUID {
        if name_eq_const(current_name, auth::SETUP_MODE_NAME) {
            log::trace!("GetNextVariableName: after SetupMode, returning SecureBoot");
            // After SetupMode, return SecureBoot
            return copy_variable_name(
                auth::SECURE_BOOT_NAME,
                auth::EFI_GLOBAL_VARIABLE_GUID,
                variable_name_size,
                variable_name,
                vendor_guid,
            );
        }

        if name_eq_const(current_name, auth::SECURE_BOOT_NAME) {
            // After SecureBoot, continue with the first stored variable
            // that is accessible at runtime (if we're at runtime)
            // IMPORTANT: Skip any stored variables that shadow our synthesized
            // variables (SetupMode, SecureBoot with EFI_GLOBAL_VARIABLE_GUID)
            // to avoid infinite enumeration loops.
            if state::is_exit_boot_services_called() {
                let status = crate::runtime_state::with(|runtime| {
                    runtime
                        .iter()
                        .find(|(var, _)| !is_synthesized_variable(var.name(), &var.vendor_guid()))
                        .map_or(Status::NOT_FOUND, |(var, _)| {
                            copy_variable_name(
                                var.name(),
                                var.vendor_guid(),
                                variable_name_size,
                                variable_name,
                                vendor_guid,
                            )
                        })
                });
                if status != Status::NOT_FOUND {
                    return status;
                }
            } else if let Some(var) = state::efi()
                .variables
                .iter()
                .find(|var| var.in_use && !is_synthesized_variable(&var.name, &var.vendor_guid))
            {
                log::trace!("GetNextVariableName: after SecureBoot, returning first stored var");
                return copy_variable_name(
                    &var.name,
                    var.vendor_guid,
                    variable_name_size,
                    variable_name,
                    vendor_guid,
                );
            }
            log::trace!(
                "GetNextVariableName: after SecureBoot, no stored vars, returning NOT_FOUND"
            );
            return Status::NOT_FOUND;
        }
    }

    if state::is_exit_boot_services_called() {
        return crate::runtime_state::with(|runtime| {
            runtime
                .iter()
                .filter(|(var, _)| !is_synthesized_variable(var.name(), &var.vendor_guid()))
                .skip_while(|(var, _)| {
                    !(var.vendor_guid() == current_guid && name_eq(var.name(), current_name))
                })
                .nth(1)
                .map_or(Status::NOT_FOUND, |(var, _)| {
                    copy_variable_name(
                        var.name(),
                        var.vendor_guid(),
                        variable_name_size,
                        variable_name,
                        vendor_guid,
                    )
                })
        });
    }

    // Search in boot-time stored variables.
    let variables = &state::efi().variables;

    // Count how many variables are accessible (excluding synthesized ones)
    let accessible_count = variables
        .iter()
        .filter(|var| {
            var.in_use
                && is_variable_accessible_at_runtime(var.attributes)
                && !is_synthesized_variable(&var.name, &var.vendor_guid)
        })
        .count();

    // Create iterator over in-use variables and skip to next after current
    // Filter by runtime accessibility to hide boot-services-only variables after ExitBootServices
    // Also skip synthesized variables (SetupMode, SecureBoot) which we handle separately
    let next_var = variables
        .iter()
        .filter(|var| {
            var.in_use
                && is_variable_accessible_at_runtime(var.attributes)
                && !is_synthesized_variable(&var.name, &var.vendor_guid)
        })
        .skip_while(|var| !(var.vendor_guid == current_guid && name_eq(&var.name, current_name)))
        .nth(1); // Skip the current one and get the next

    match next_var {
        Some(var) => {
            log::trace!(
                "GetNextVariableName: returning next stored var (total accessible: {})",
                accessible_count
            );
            copy_variable_name(
                &var.name,
                var.vendor_guid,
                variable_name_size,
                variable_name,
                vendor_guid,
            )
        }
        None => {
            log::trace!(
                "GetNextVariableName: no more vars, returning NOT_FOUND (total accessible: {})",
                accessible_count
            );
            Status::NOT_FOUND
        }
    }
}

/// Copy a null-terminated variable name to the output buffer.
fn copy_variable_name(
    name: &[u16],
    guid: Guid,
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    let Some(terminator) = name.iter().position(|&unit| unit == 0) else {
        return Status::INVALID_PARAMETER;
    };
    let name_len = terminator + 1;
    let required_size = name_len * 2;

    if unsafe { *variable_name_size } < required_size {
        unsafe { *variable_name_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), variable_name, name_len);
        *vendor_guid = guid;
        *variable_name_size = required_size;
    }

    Status::SUCCESS
}

type VariableNameBuf = heapless::Vec<u16, MAX_VARIABLE_NAME_LEN>;
type VariableDataBuf = heapless::Vec<u8, MAX_VARIABLE_DATA_SIZE>;

#[allow(clippy::large_enum_variant)]
enum PersistData {
    Fixed(VariableDataBuf),
    Alloc(AllocVec<u8>),
}

impl PersistData {
    fn try_alloc(data: &[u8]) -> Result<Self, Status> {
        let mut copied = AllocVec::new();
        copied
            .try_reserve(data.len())
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        copied.extend_from_slice(data);
        Ok(Self::Alloc(copied))
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Fixed(data) => data.as_slice(),
            Self::Alloc(data) => data.as_slice(),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum VariablePersistAction {
    None,
    Write {
        guid: Guid,
        name: VariableNameBuf,
        attributes: u32,
        data: PersistData,
        is_append: bool,
    },
    Delete {
        guid: Guid,
        name: VariableNameBuf,
    },
}

#[allow(clippy::large_enum_variant)]
enum SecureBootDbAction {
    None,
    Update(auth::SecureBootVariable, VariableDataBuf),
    Delete(auth::SecureBootVariable, Option<auth::EfiTime>),
}

extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    if variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // The phase-blind ABI is classified exactly once. Keeping the arms as
    // calls to separate inline-never helpers prevents the large boot frame from
    // being merged into an OS runtime stack frame.
    crate::phase::dispatch(|phase| match phase {
        crate::phase::Phase::Runtime(runtime) => {
            if data_size == 0 {
                set_variable_runtime_delete(&runtime, variable_name, vendor_guid, attributes)
            } else {
                set_variable_runtime_write(
                    &runtime,
                    variable_name,
                    vendor_guid,
                    attributes,
                    data_size,
                    data,
                )
            }
        }
        crate::phase::Phase::Boot(boot) => set_variable_full(
            &boot,
            variable_name,
            vendor_guid,
            attributes,
            data_size,
            data,
        ),
    })
}

/// Write a variable after ExitBootServices without a large OS-stack frame.
///
/// Authentication and Secure Boot database parsing use the bounded runtime
/// workspace in [`crate::heap`]. The workspace is reset for each serialized
/// operation, so no post-SVAM allocation can follow a physical boot-heap link.
#[inline(never)]
fn set_variable_runtime_write(
    runtime: &crate::phase::RuntimeCtx<'_>,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    let name_len = ucs2_strlen_ptr(variable_name);
    if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
        return Status::INVALID_PARAMETER;
    }

    let is_authenticated =
        (attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0;
    let is_append = (attributes & auth::attributes::APPEND_WRITE) != 0;
    let raw_limit = if is_authenticated {
        MAX_VARIABLE_DATA_SIZE * 3
    } else {
        MAX_VARIABLE_DATA_SIZE
    };
    if data_size > raw_limit || (data_size != 0 && data.is_null()) {
        return if data_size > raw_limit {
            Status::OUT_OF_RESOURCES
        } else {
            Status::INVALID_PARAMETER
        };
    }

    // A runtime-visible variable must also be boot-services-visible (UEFI 8.2).
    if attributes & auth::attributes::RUNTIME_ACCESS == 0
        || attributes & auth::attributes::BOOTSERVICE_ACCESS == 0
    {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *vendor_guid };
    let name_slice = unsafe { core::slice::from_raw_parts(variable_name, name_len + 1) };
    if guid == auth::EFI_GLOBAL_VARIABLE_GUID
        && (name_slice == auth::SECURE_BOOT_NAME || name_slice == auth::SETUP_MODE_NAME)
    {
        return Status::WRITE_PROTECTED;
    }

    let mut name_vec = VariableNameBuf::new();
    if name_vec.extend_from_slice(name_slice).is_err() {
        return Status::OUT_OF_RESOURCES;
    }
    let key_database = auth::identify_key_database(name_vec.as_slice(), &guid);
    if key_database.is_some() && !is_authenticated {
        return Status::WRITE_PROTECTED;
    }

    let Some(_runtime_operation) = crate::heap::begin_runtime_operation() else {
        return Status::NOT_READY;
    };
    let raw_data = unsafe { core::slice::from_raw_parts(data as *const u8, data_size) };
    let authenticated_timestamp = is_authenticated
        .then(|| auth::EfiVariableAuthentication2::from_bytes(raw_data))
        .flatten()
        .map(|header| header.time_stamp);
    let databases = if is_authenticated {
        match auth::prepare_runtime_databases() {
            Ok(databases) => Some(databases),
            Err(error) => return runtime_auth_status(error),
        }
    } else {
        None
    };
    let mut final_data = if let Some(databases) = databases.as_ref() {
        let auth_target = key_database.unwrap_or(auth::SecureBootVariable::Db);
        let Some(bound) = databases.runtime_preflight_size(auth_target, data_size, data_size)
        else {
            return Status::OUT_OF_RESOURCES;
        };
        if bound > crate::heap::runtime_bytes_remaining() {
            return Status::OUT_OF_RESOURCES;
        }
        match auth::verify_authenticated_variable_with_databases(
            crate::runtime_state::with(|state| state.secure_boot_status()),
            name_vec.as_slice(),
            &guid,
            attributes,
            raw_data,
            databases,
        ) {
            Ok(data) => data,
            Err(error) => return runtime_auth_status(error),
        }
    } else {
        let mut copied = AllocVec::new();
        if copied.try_reserve(raw_data.len()).is_err() {
            return Status::OUT_OF_RESOURCES;
        }
        copied.extend_from_slice(raw_data);
        copied
    };

    let stored_attributes = attributes & !auth::attributes::APPEND_WRITE;
    let mut existing_data = AllocVec::new();
    let existing_attributes = match crate::runtime_state::with(|runtime| {
        runtime
            .get(&guid, name_vec.as_slice())
            .map(|(variable, payload)| {
                if existing_data.try_reserve(payload.len()).is_err() {
                    return Err(Status::OUT_OF_RESOURCES);
                }
                existing_data.extend_from_slice(payload);
                Ok(variable.attributes())
            })
    }) {
        Some(Ok(attributes)) => Some(attributes),
        Some(Err(status)) => return status,
        None => None,
    };
    if existing_attributes.is_some_and(|value| value != stored_attributes) {
        return Status::INVALID_PARAMETER;
    }

    if is_append && existing_attributes.is_some() {
        let combined_len = match existing_data.len().checked_add(final_data.len()) {
            Some(length) if length <= MAX_VARIABLE_DATA_SIZE => length,
            _ => return Status::OUT_OF_RESOURCES,
        };
        let mut combined = AllocVec::new();
        if combined.try_reserve(combined_len).is_err() {
            return Status::OUT_OF_RESOURCES;
        }
        combined.extend_from_slice(existing_data.as_slice());
        combined.extend_from_slice(final_data.as_slice());
        final_data = combined;
    }

    if final_data.len() > MAX_VARIABLE_DATA_SIZE {
        return Status::OUT_OF_RESOURCES;
    }
    if key_database.is_some()
        && !final_data.is_empty()
        && let Err(error) = auth::validate_signature_database(final_data.as_slice())
    {
        return runtime_auth_status(error);
    }

    if final_data.is_empty() {
        if is_append {
            return Status::SUCCESS;
        }
        let exists =
            crate::runtime_state::with(|runtime| runtime.get(&guid, name_vec.as_slice()).is_some());
        if !exists {
            return Status::NOT_FOUND;
        }
        if is_authenticated
            && crate::runtime_state::with(|runtime| {
                runtime.can_set_variable(&guid, name_vec.as_slice(), 0, true)
            })
            .is_err()
        {
            return Status::OUT_OF_RESOURCES;
        }
        let persist_result = if is_authenticated {
            crate::efi::varstore::persist_variable(&guid, name_vec.as_slice(), attributes, raw_data)
        } else {
            crate::efi::varstore::delete_variable(&guid, name_vec.as_slice())
        };
        if let Err(error) = persist_result {
            log::debug!("Variable deletion not persisted: {:?}", error);
            return Status::DEVICE_ERROR;
        }

        let deleted = if let Some(timestamp) = authenticated_timestamp {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&timestamp));
            match crate::runtime_state::with_mut(|runtime| {
                runtime.delete_authenticated_variable(&guid, name_vec.as_slice(), bytes)
            }) {
                Ok(deleted) => deleted,
                Err(_) => return Status::OUT_OF_RESOURCES,
            }
        } else {
            crate::runtime_state::with_mut(|runtime| {
                runtime.delete_variable(&guid, name_vec.as_slice())
            })
        };
        if !deleted {
            return Status::NOT_FOUND;
        }
        if let Some(var_type) = key_database {
            handle_secure_boot_variable_delete_runtime(runtime, var_type);
        }
        return Status::SUCCESS;
    }

    set_runtime_variable_value(
        runtime,
        &guid,
        name_vec.as_slice(),
        stored_attributes,
        final_data.as_slice(),
        if is_authenticated {
            attributes
        } else {
            stored_attributes
        },
        authenticated_timestamp,
        key_database,
        raw_data,
        is_authenticated,
    )
}

fn set_runtime_variable_value(
    runtime: &crate::phase::RuntimeCtx<'_>,
    guid: &Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
    persist_attributes: u32,
    timestamp: Option<auth::EfiTime>,
    key_database: Option<auth::SecureBootVariable>,
    raw_data: &[u8],
    is_authenticated: bool,
) -> Status {
    let mut timestamp = timestamp.map(|timestamp| {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&timestamp));
        bytes
    });
    if persist_attributes & auth::attributes::APPEND_WRITE != 0
        && let (Some(candidate), Some(previous)) = (
            timestamp,
            crate::runtime_state::with(|runtime| runtime.auth_timestamp(guid, name)),
        )
        && let (Ok(candidate_time), Ok(previous_time)) = (
            auth::EfiTime::read_from_bytes(&candidate),
            auth::EfiTime::read_from_bytes(&previous),
        )
        && !candidate_time.is_after(&previous_time)
    {
        timestamp = Some(previous);
    }

    if crate::runtime_state::with(|runtime| {
        runtime.can_set_variable(guid, name, data.len(), is_authenticated)
    })
    .is_err()
    {
        return Status::OUT_OF_RESOURCES;
    }

    if attributes & auth::attributes::NON_VOLATILE != 0 {
        let persist_data = if is_authenticated { raw_data } else { data };
        if let Err(error) =
            crate::efi::varstore::persist_variable(guid, name, persist_attributes, persist_data)
        {
            log::debug!("Variable write not persisted: {:?}", error);
            return Status::DEVICE_ERROR;
        }
    }

    let dropped = match crate::runtime_state::with_mut(|runtime| {
        runtime.set_variable(*guid, name, attributes, data, timestamp)
    }) {
        Ok(dropped) => dropped,
        Err(_) => return Status::OUT_OF_RESOURCES,
    };
    if dropped != 0 {
        return Status::DEVICE_ERROR;
    }

    if let Some(var_type) = key_database {
        handle_secure_boot_variable_update_runtime(runtime, var_type);
    }

    Status::SUCCESS
}

#[inline(never)]
fn set_variable_runtime_delete(
    _runtime: &crate::phase::RuntimeCtx<'_>,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
) -> Status {
    let name_len = ucs2_strlen_ptr(variable_name);
    if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *vendor_guid };
    let name_slice = unsafe { core::slice::from_raw_parts(variable_name, name_len + 1) };

    if guid == auth::EFI_GLOBAL_VARIABLE_GUID
        && (name_slice == auth::SECURE_BOOT_NAME || name_slice == auth::SETUP_MODE_NAME)
    {
        return Status::WRITE_PROTECTED;
    }

    let mut name_vec = VariableNameBuf::new();
    if name_vec.extend_from_slice(name_slice).is_err() {
        return Status::OUT_OF_RESOURCES;
    }

    if auth::identify_key_database(name_vec.as_slice(), &guid).is_some() {
        return Status::WRITE_PROTECTED;
    }

    let Some(existing_attributes) = crate::runtime_state::with(|runtime| {
        runtime
            .get(&guid, name_vec.as_slice())
            .map(|(variable, _)| variable.attributes())
    }) else {
        return Status::NOT_FOUND;
    };
    if existing_attributes & auth::attributes::RUNTIME_ACCESS == 0
        || existing_attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0
    {
        return Status::WRITE_PROTECTED;
    }
    if attributes != 0 && attributes != existing_attributes {
        return Status::INVALID_PARAMETER;
    }

    let Some(_runtime_operation) = crate::heap::begin_runtime_operation() else {
        return Status::NOT_READY;
    };
    if existing_attributes & auth::attributes::NON_VOLATILE != 0
        && let Err(error) = crate::efi::varstore::delete_variable(&guid, name_vec.as_slice())
    {
        log::debug!("Variable deletion not persisted: {:?}", error);
        return Status::DEVICE_ERROR;
    }

    if crate::runtime_state::with_mut(|runtime| runtime.delete_variable(&guid, name_vec.as_slice()))
    {
        Status::SUCCESS
    } else {
        Status::NOT_FOUND
    }
}

#[inline(never)]
fn set_variable_full(
    boot: &crate::phase::BootCtx<'_>,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    if variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };

    // Check name length
    let name_len = ucs2_strlen_ptr(name);
    if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
        return Status::INVALID_PARAMETER;
    }
    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
    let mut name_vec = VariableNameBuf::new();
    if name_vec.extend_from_slice(name_slice).is_err() {
        return Status::OUT_OF_RESOURCES;
    }

    // Check data size.
    let is_auth_write = (attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0;
    let raw_limit = if is_auth_write {
        MAX_VARIABLE_DATA_SIZE * 3
    } else {
        MAX_VARIABLE_DATA_SIZE
    };
    if data_size > raw_limit {
        return Status::OUT_OF_RESOURCES;
    }

    if data_size > 0 && data.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // SecureBoot and SetupMode are computed status variables, not writable.
    if guid == auth::EFI_GLOBAL_VARIABLE_GUID
        && (name_slice == auth::SECURE_BOOT_NAME || name_slice == auth::SETUP_MODE_NAME)
    {
        log::debug!(
            "Rejecting write to read-only variable: {:?}",
            if name_slice == auth::SECURE_BOOT_NAME {
                "SecureBoot"
            } else {
                "SetupMode"
            }
        );
        return Status::WRITE_PROTECTED;
    }

    let is_authenticated =
        (attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0;
    let is_append = (attributes & auth::attributes::APPEND_WRITE) != 0;
    let mut authenticated_timestamp = if is_authenticated && data_size > 0 {
        let raw_data = unsafe { core::slice::from_raw_parts(data as *const u8, data_size) };
        auth::EfiVariableAuthentication2::from_bytes(raw_data).map(|header| header.time_stamp)
    } else {
        None
    };

    let mut final_data_vec = VariableDataBuf::new();
    if is_authenticated && data_size > 0 {
        let raw_data = unsafe { core::slice::from_raw_parts(data as *const u8, data_size) };
        let verified_data: AllocVec<u8> = match auth::verify_authenticated_variable(
            crate::state::boot_secure_boot_status(boot),
            name_vec.as_slice(),
            &guid,
            attributes,
            raw_data,
        ) {
            Ok(verified_data) => verified_data,
            Err(e) => {
                log::warn!("Authenticated variable verification failed: {:?}", e);
                return e.into();
            }
        };
        if final_data_vec
            .extend_from_slice(verified_data.as_slice())
            .is_err()
        {
            return Status::OUT_OF_RESOURCES;
        }
    } else if data_size > 0
        && final_data_vec
            .extend_from_slice(unsafe { core::slice::from_raw_parts(data as *const u8, data_size) })
            .is_err()
    {
        return Status::OUT_OF_RESOURCES;
    }

    let final_data_size = final_data_vec.len();
    if final_data_size > 0
        && crate::logger::is_log_level_variable(&guid, name_vec.as_slice())
        && crate::logger::level_from_data(final_data_vec.as_slice()).is_none()
    {
        return Status::INVALID_PARAMETER;
    }

    let secure_boot_var = auth::identify_key_database(name_vec.as_slice(), &guid);
    if secure_boot_var.is_some() && !is_authenticated {
        return Status::WRITE_PROTECTED;
    }
    let stored_attributes = attributes & !auth::attributes::APPEND_WRITE;
    if is_append
        && let Some(candidate) = authenticated_timestamp
        && let Some(previous_bytes) = state::efi()
            .variables
            .iter()
            .find(|variable| {
                variable.in_use
                    && variable.vendor_guid == guid
                    && crate::efi::utils::ucs2_eq(&variable.name, name_vec.as_slice())
            })
            .map(|variable| variable.auth_timestamp)
        && let Ok(previous) = auth::EfiTime::read_from_bytes(&previous_bytes)
        && !candidate.is_after(&previous)
    {
        authenticated_timestamp = Some(previous);
    }
    if secure_boot_var.is_some()
        && !final_data_vec.is_empty()
        && let Err(error) = auth::validate_signature_database(final_data_vec.as_slice())
    {
        return error.into();
    }

    // APPEND_WRITE is a general variable operation. Secure Boot databases use
    // the same concatenation semantics, while their specialized branch below
    // also rebuilds the authentication database.
    if is_append
        && secure_boot_var.is_none()
        && let Some(existing) = state::efi().variables.iter().find(|variable| {
            variable.in_use
                && variable.vendor_guid == guid
                && crate::efi::utils::ucs2_eq(&variable.name, name_vec.as_slice())
        })
    {
        if existing.attributes != stored_attributes {
            return Status::INVALID_PARAMETER;
        }
        let mut combined = VariableDataBuf::new();
        if combined
            .extend_from_slice(&existing.data[..existing.data_size])
            .is_err()
            || combined
                .extend_from_slice(final_data_vec.as_slice())
                .is_err()
        {
            return Status::OUT_OF_RESOURCES;
        }
        final_data_vec = combined;
    }

    if is_append && final_data_size == 0 {
        return Status::SUCCESS;
    }

    let (status, persist_action, secure_boot_action) = state::with_efi_mut(|efi| {
        let (variables, replay_entries) = (&mut efi.variables, &mut efi.auth_replay);

        let existing_idx = variables.iter().position(|var| {
            var.in_use
                && var.vendor_guid == guid
                && crate::efi::utils::ucs2_eq(&var.name, name_vec.as_slice())
        });
        let free_idx = variables.iter().position(|var| !var.in_use);
        let replay_idx = if is_authenticated {
            replay_entries
                .iter()
                .position(|entry| {
                    entry.in_use
                        && entry.vendor_guid == guid
                        && crate::efi::utils::ucs2_eq(&entry.name, name_vec.as_slice())
                })
                .or_else(|| replay_entries.iter().position(|entry| !entry.in_use))
        } else {
            None
        };
        if is_authenticated && replay_idx.is_none() {
            return (
                Status::OUT_OF_RESOURCES,
                VariablePersistAction::None,
                SecureBootDbAction::None,
            );
        }
        let timestamp_bytes = authenticated_timestamp.map(|timestamp| {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&timestamp));
            bytes
        });
        let mut record_replay = |timestamp: [u8; 16]| {
            if let Some(index) = replay_idx {
                let replay = &mut replay_entries[index];
                replay.name.fill(0);
                replay.name[..name_vec.len()].copy_from_slice(name_vec.as_slice());
                replay.vendor_guid = guid;
                replay.timestamp = timestamp;
                replay.in_use = true;
            }
        };

        if data_size != 0
            && let Some(idx) = existing_idx
            && variables[idx].attributes != stored_attributes
        {
            return (
                Status::INVALID_PARAMETER,
                VariablePersistAction::None,
                SecureBootDbAction::None,
            );
        }

        // Delete variable if data_size is 0 (for authenticated vars, this means empty after header).
        if final_data_size == 0 {
            if let Some(idx) = existing_idx {
                if variables[idx].attributes
                    & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                    != 0
                    && !is_authenticated
                {
                    return (
                        Status::WRITE_PROTECTED,
                        VariablePersistAction::None,
                        SecureBootDbAction::None,
                    );
                }
                if let Some(timestamp) = timestamp_bytes {
                    record_replay(timestamp);
                }
                variables[idx].clear();
                let secure_action = secure_boot_var
                    .map(|var_type| SecureBootDbAction::Delete(var_type, authenticated_timestamp))
                    .unwrap_or(SecureBootDbAction::None);
                let persist_action = VariablePersistAction::Delete {
                    guid,
                    name: name_vec.clone(),
                };
                return (Status::SUCCESS, persist_action, secure_action);
            }
            return (
                Status::NOT_FOUND,
                VariablePersistAction::None,
                SecureBootDbAction::None,
            );
        }

        // Handle APPEND_WRITE for signature databases.
        if is_append
            && let Some(idx) = existing_idx
            && let Some(var_type) = secure_boot_var
        {
            let existing_data = &variables[idx].data[..variables[idx].data_size];
            match append_signature_data(
                existing_data,
                final_data_vec.as_ptr(),
                final_data_size,
                var_type,
            ) {
                Ok(combined) => {
                    if combined.len() > MAX_VARIABLE_DATA_SIZE {
                        return (
                            Status::OUT_OF_RESOURCES,
                            VariablePersistAction::None,
                            SecureBootDbAction::None,
                        );
                    }

                    if variables[idx].set_data(combined.as_slice()).is_err() {
                        return (
                            Status::OUT_OF_RESOURCES,
                            VariablePersistAction::None,
                            SecureBootDbAction::None,
                        );
                    }
                    if let Some(timestamp) = timestamp_bytes {
                        variables[idx].auth_timestamp = timestamp;
                        record_replay(timestamp);
                    }

                    let mut combined_buf = VariableDataBuf::new();
                    if combined_buf.extend_from_slice(combined.as_slice()).is_err() {
                        return (
                            Status::OUT_OF_RESOURCES,
                            VariablePersistAction::None,
                            SecureBootDbAction::None,
                        );
                    }

                    let persist_action = if attributes & auth::attributes::NON_VOLATILE != 0 {
                        let (persist_attrs, persist_data) = if is_authenticated && !is_append {
                            (
                                attributes,
                                PersistData::Alloc(
                                    unsafe {
                                        core::slice::from_raw_parts(data as *const u8, data_size)
                                    }
                                    .to_vec(),
                                ),
                            )
                        } else {
                            (stored_attributes, PersistData::Fixed(combined_buf.clone()))
                        };
                        VariablePersistAction::Write {
                            guid,
                            name: name_vec.clone(),
                            attributes: persist_attrs,
                            data: persist_data,
                            is_append: true,
                        }
                    } else {
                        VariablePersistAction::None
                    };

                    return (
                        Status::SUCCESS,
                        persist_action,
                        SecureBootDbAction::Update(var_type, combined_buf),
                    );
                }
                Err(e) => {
                    return (
                        e.into(),
                        VariablePersistAction::None,
                        SecureBootDbAction::None,
                    );
                }
            }
        }

        let idx = match existing_idx {
            Some(i) => i,
            None => match free_idx {
                Some(i) => i,
                None => {
                    return (
                        Status::OUT_OF_RESOURCES,
                        VariablePersistAction::None,
                        SecureBootDbAction::None,
                    );
                }
            },
        };

        if final_data_size > MAX_VARIABLE_DATA_SIZE {
            return (
                Status::OUT_OF_RESOURCES,
                VariablePersistAction::None,
                SecureBootDbAction::None,
            );
        }

        variables[idx].name[..name_vec.len()].copy_from_slice(&name_vec);
        variables[idx].name[name_vec.len()..].fill(0);
        if variables[idx].set_data(final_data_vec.as_slice()).is_err() {
            return (
                Status::OUT_OF_RESOURCES,
                VariablePersistAction::None,
                SecureBootDbAction::None,
            );
        }
        variables[idx].vendor_guid = guid;
        variables[idx].attributes = stored_attributes;
        variables[idx].auth_timestamp = timestamp_bytes.unwrap_or([0; 16]);
        if let Some(timestamp) = timestamp_bytes {
            record_replay(timestamp);
        }
        variables[idx].in_use = true;

        let secure_action = secure_boot_var
            .map(|var_type| SecureBootDbAction::Update(var_type, final_data_vec.clone()))
            .unwrap_or(SecureBootDbAction::None);

        let persist_action = if attributes & auth::attributes::NON_VOLATILE != 0 {
            let persist_data = if is_authenticated && !is_append {
                match PersistData::try_alloc(unsafe {
                    core::slice::from_raw_parts(data as *const u8, data_size)
                }) {
                    Ok(data) => data,
                    Err(status) => {
                        return (
                            status,
                            VariablePersistAction::None,
                            SecureBootDbAction::None,
                        );
                    }
                }
            } else {
                PersistData::Fixed(final_data_vec.clone())
            };
            VariablePersistAction::Write {
                guid,
                name: name_vec.clone(),
                attributes: if is_authenticated && !is_append {
                    attributes
                } else {
                    stored_attributes
                },
                data: persist_data,
                is_append: false,
            }
        } else {
            VariablePersistAction::None
        };

        (Status::SUCCESS, persist_action, secure_action)
    });

    if status != Status::SUCCESS {
        return status;
    }

    match secure_boot_action {
        SecureBootDbAction::None => {}
        SecureBootDbAction::Update(var_type, data) => {
            update_key_database(var_type, data.as_slice(), authenticated_timestamp);
            handle_secure_boot_variable_update_boot(boot, var_type);
        }
        SecureBootDbAction::Delete(var_type, timestamp) => {
            handle_secure_boot_variable_delete_boot(boot, var_type, timestamp)
        }
    }

    match persist_action {
        VariablePersistAction::None => {}
        VariablePersistAction::Delete { guid, name } => {
            if let Err(e) = crate::efi::varstore::delete_variable(&guid, name.as_slice()) {
                log::debug!("Variable deletion not persisted: {:?}", e);
            }
        }
        VariablePersistAction::Write {
            guid,
            name,
            attributes,
            data,
            is_append,
        } => {
            let _ = is_append;
            match crate::efi::varstore::persist_variable(
                &guid,
                name.as_slice(),
                attributes,
                data.as_slice(),
            ) {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Variable not persisted: {:?}", e);
                }
            }
        }
    }

    if crate::logger::is_log_level_variable(&guid, name_vec.as_slice()) {
        if final_data_size == 0 {
            crate::logger::apply_variable_delete();
        } else {
            crate::logger::apply_variable_write(final_data_vec.as_slice());
        }
    }

    Status::SUCCESS
}

/// Apply a Secure Boot database update while boot services are active.
fn handle_secure_boot_variable_update_boot(
    boot: &crate::phase::BootCtx<'_>,
    var_type: auth::SecureBootVariable,
) {
    if var_type != auth::SecureBootVariable::PK
        || !crate::state::boot_secure_boot_status(boot).setup_mode()
    {
        return;
    }

    auth::enter_user_mode_boot(boot);

    // PK enrollment enters User Mode but does not itself enable policy. Apply
    // the already-persisted preference without performing another SPI write.
    if auth::boot::load_secure_boot_enable_preference() {
        auth::apply_secure_boot_preference_boot(boot, true);
    }
    let _ = auth::boot::update_status_variables();
}

/// Apply a Secure Boot database update to pointer-free runtime state only.
fn handle_secure_boot_variable_update_runtime(
    runtime: &crate::phase::RuntimeCtx<'_>,
    var_type: auth::SecureBootVariable,
) {
    let setup_mode = crate::runtime_state::with(|state| state.secure_boot_status().setup_mode());
    if var_type == auth::SecureBootVariable::PK && setup_mode {
        auth::enter_user_mode_runtime(runtime);
    }
}

/// Apply a Secure Boot database deletion while boot services are active.
fn handle_secure_boot_variable_delete_boot(
    boot: &crate::phase::BootCtx<'_>,
    var_type: auth::SecureBootVariable,
    timestamp: Option<auth::EfiTime>,
) {
    match var_type {
        auth::SecureBootVariable::PK => {
            auth::enter_setup_mode_boot(boot);
            let mut database = auth::pk_database();
            database.clear();
            if let Some(timestamp) = timestamp {
                database.set_timestamp(timestamp);
            }
            drop(database);
            let _ = auth::boot::update_status_variables();
        }
        auth::SecureBootVariable::KEK => {
            let mut database = auth::kek_database();
            database.clear();
            if let Some(timestamp) = timestamp {
                database.set_timestamp(timestamp);
            }
        }
        auth::SecureBootVariable::Db => {
            let mut database = auth::db_database();
            database.clear();
            if let Some(timestamp) = timestamp {
                database.set_timestamp(timestamp);
            }
        }
        auth::SecureBootVariable::Dbx => {
            let mut database = auth::dbx_database();
            database.clear();
            if let Some(timestamp) = timestamp {
                database.set_timestamp(timestamp);
            }
        }
    }
}

/// Apply a Secure Boot database deletion to pointer-free runtime state only.
fn handle_secure_boot_variable_delete_runtime(
    runtime: &crate::phase::RuntimeCtx<'_>,
    var_type: auth::SecureBootVariable,
) {
    if var_type == auth::SecureBootVariable::PK {
        auth::enter_setup_mode_runtime(runtime);
    }
}

/// Update the in-memory key database from variable data
fn update_key_database(
    var_type: auth::SecureBootVariable,
    data: &[u8],
    timestamp: Option<auth::EfiTime>,
) {
    let result = match var_type {
        auth::SecureBootVariable::PK => {
            let mut db = auth::pk_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::KEK => {
            let mut db = auth::kek_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::Db => {
            let mut db = auth::db_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::Dbx => {
            let mut db = auth::dbx_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
    };

    if let Err(e) = result {
        log::warn!(
            "Failed to parse signature lists for {:?}: {:?}",
            var_type,
            e
        );
        return;
    }

    if let Some(timestamp) = timestamp {
        match var_type {
            auth::SecureBootVariable::PK => auth::pk_database().set_timestamp(timestamp),
            auth::SecureBootVariable::KEK => auth::kek_database().set_timestamp(timestamp),
            auth::SecureBootVariable::Db => auth::db_database().set_timestamp(timestamp),
            auth::SecureBootVariable::Dbx => auth::dbx_database().set_timestamp(timestamp),
        }
    }
}

/// Append signature data for APPEND_WRITE operations
fn append_signature_data(
    existing: &[u8],
    new_data: *const u8,
    new_size: usize,
    _var_type: auth::SecureBootVariable,
) -> Result<AllocVec<u8>, auth::AuthError> {
    // For signature databases, we concatenate the signature lists
    let mut combined = AllocVec::with_capacity(existing.len() + new_size);
    combined.extend_from_slice(existing);

    let new_slice = unsafe { core::slice::from_raw_parts(new_data, new_size) };
    combined.extend_from_slice(new_slice);

    Ok(combined)
}

extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("QueryVariableInfo attr=", attributes);
    }
    if maximum_variable_storage_size.is_null()
        || remaining_variable_storage_size.is_null()
        || maximum_variable_size.is_null()
    {
        return Status::INVALID_PARAMETER;
    }

    const SUPPORTED_ATTRIBUTES: u32 = auth::attributes::NON_VOLATILE
        | auth::attributes::BOOTSERVICE_ACCESS
        | auth::attributes::RUNTIME_ACCESS
        | auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    if attributes & !SUPPORTED_ATTRIBUTES != 0
        || attributes & auth::attributes::BOOTSERVICE_ACCESS == 0
        || (state::is_exit_boot_services_called()
            && attributes & auth::attributes::RUNTIME_ACCESS == 0)
    {
        return Status::INVALID_PARAMETER;
    }

    // Volatile and non-volatile variables share this fixed payload arena. Count
    // every entry that can consume it; filtering by the requested attributes
    // would over-report writable space when the other class fills the arena.
    let total_size = MAX_VARIABLES * MAX_VARIABLE_DATA_SIZE;
    let used_size = if state::is_exit_boot_services_called() {
        crate::runtime_state::with(|runtime| runtime.used_bytes())
    } else {
        state::efi()
            .variables
            .iter()
            .filter(|var| var.in_use)
            .map(|var| var.data_size)
            .sum()
    };

    unsafe {
        *maximum_variable_storage_size = total_size as u64;
        *remaining_variable_storage_size = total_size.saturating_sub(used_size) as u64;
        *maximum_variable_size = MAX_VARIABLE_DATA_SIZE as u64;
    }

    Status::SUCCESS
}

// ============================================================================
// Miscellaneous Services
// ============================================================================

extern "efiapi" fn get_next_high_mono_count(_high_count: *mut u32) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("GetNextHighMonoCount -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn reset_system(
    reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    // Use rt_serial_print! instead of log:: — after SetVirtualAddressMap the log
    // crate's vtable pointer is stale and would page-fault.
    rt_serial_print!("ResetSystem called");

    // Before SetVirtualAddressMap the framebuffer logger and the timer are
    // still usable, so announce the caller and hold for RESET_DELAY_MS. This
    // makes a bootloader-requested reset visible on machines with no serial
    // port. Afterwards the log vtable and timing state are stale, so skip it.
    if !VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        log::error!(
            "RESET: RT.ResetSystem(type={:#x}) requested by the running image — resetting in {} ms",
            reset_type,
            crate::RESET_DELAY_MS
        );
        crate::time::delay_ms(crate::RESET_DELAY_MS);
    }

    // Try different reset methods
    match reset_type {
        efi::RESET_COLD | efi::RESET_WARM => {
            crate::arch::reset::keyboard_controller_reset();
            crate::arch::reset::triple_fault();
        }
        efi::RESET_SHUTDOWN => {
            rt_serial_print!("Shutdown not implemented, halting");
        }
        _ => {}
    }

    // If all else fails, halt
    loop {
        crate::arch::halt();
    }
}

extern "efiapi" fn update_capsule(
    capsule_header_array: *mut *mut CapsuleHeader,
    capsule_count: usize,
    scatter_gather_list: efi::PhysicalAddress,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("UpdateCapsule");
    }

    if capsule_header_array.is_null() || capsule_count == 0 {
        return Status::INVALID_PARAMETER;
    }
    if capsule_count > 1 {
        return Status::UNSUPPORTED;
    }

    // After ExitBootServices: stage capsules for next boot via deferred
    // variable buffer. The OS must call ResetSystem() afterwards.
    if state::is_exit_boot_services_called() {
        if scatter_gather_list == 0 {
            return Status::INVALID_PARAMETER;
        }

        // Validate all capsules have PERSIST_ACROSS_RESET flag
        for i in 0..capsule_count {
            let hdr_ptr = unsafe { *capsule_header_array.add(i) };
            if hdr_ptr.is_null() {
                return Status::INVALID_PARAMETER;
            }
            let flags = unsafe { (*hdr_ptr).flags };
            if flags & 0x0001_0000 == 0 {
                // CAPSULE_FLAGS_PERSIST_ACROSS_RESET not set
                return Status::INVALID_PARAMETER;
            }
        }

        // Stage CapsuleUpdateData* variables via the deferred write buffer
        for i in 0..capsule_count {
            if super::capsule::stage_capsule_for_reboot(scatter_gather_list, i).is_err() {
                return Status::DEVICE_ERROR;
            }
        }

        return Status::SUCCESS;
    }

    // Before ExitBootServices this implementation has no safe staging path:
    // returning SUCCESS would make callers believe a capsule was accepted even
    // though it would be dropped. Require the runtime/reset delivery path.
    Status::UNSUPPORTED
}

extern "efiapi" fn query_capsule_capabilities(
    capsule_header_array: *mut *mut CapsuleHeader,
    capsule_count: usize,
    maximum_capsule_size: *mut u64,
    reset_type: *mut ResetType,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if VIRTUAL_MODE.load(core::sync::atomic::Ordering::Acquire) {
        rt_serial_print!("QueryCapsuleCapabilities");
    }

    if capsule_header_array.is_null() || capsule_count == 0 {
        return Status::INVALID_PARAMETER;
    }
    if maximum_capsule_size.is_null() || reset_type.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if capsule_count > 1 {
        return Status::UNSUPPORTED;
    }

    const MAX_CAPSULE_SIZE: u64 = 16 * 1024 * 1024;

    // Check all capsules have PERSIST_ACROSS_RESET and fit the advertised limit.
    for i in 0..capsule_count {
        let hdr_ptr = unsafe { *capsule_header_array.add(i) };
        if hdr_ptr.is_null() {
            return Status::INVALID_PARAMETER;
        }
        let hdr = unsafe { &*hdr_ptr };
        if hdr.flags & super::capsule::header::CAPSULE_FLAGS_PERSIST_ACROSS_RESET == 0 {
            return Status::UNSUPPORTED;
        }
        if hdr.capsule_image_size as u64 > MAX_CAPSULE_SIZE {
            return Status::UNSUPPORTED;
        }
    }

    // Report capabilities:
    // - Maximum capsule size: 16 MB (conservative limit for SPI flash)
    // - Reset type: warm reset (coreboot processes capsules after warm reboot)
    unsafe {
        *maximum_capsule_size = MAX_CAPSULE_SIZE;
        *reset_type = efi::RESET_WARM;
    }

    Status::SUCCESS
}

// ============================================================================
// Helper Functions
// ============================================================================

// read_rtc_time is now shared via crate::efi::auth::time::read_rtc_time()

/// Compare a UCS-2 string in stored array with a pointer-based string.
///
/// The read from `name` is bounded by `stored.len()` to prevent unbounded
/// memory reads from potentially malformed (non-null-terminated) buffers.
fn name_eq(stored: &[u16], name: *const u16) -> bool {
    for (i, &a) in stored.iter().enumerate() {
        // SAFETY: `i` is bounded by `stored.len()`, so we read at most
        // `stored.len()` elements from `name`. The caller must ensure
        // `name` points to at least `stored.len()` valid u16 values.
        let b = unsafe { *name.add(i) };
        if a != b {
            return false;
        }
        if a == 0 {
            return true;
        }
    }
    // stored exhausted without null terminator — check if name also ends here
    // SAFETY: reading one element past the stored length to check for null
    // terminator. Callers of EFI variable services must provide valid buffers.
    unsafe { *name.add(stored.len()) == 0 }
}

// ucs2_strlen consolidated into crate::efi::utils::ucs2_len

/// Get length of UCS-2 string from pointer (not including null terminator)
///
/// Bounded to MAX_VARIABLE_NAME_LEN to prevent unbounded reads from
/// potentially malformed (non-null-terminated) buffers.
fn ucs2_strlen_ptr(s: *const u16) -> usize {
    // Safety: s is a UEFI-provided variable name pointer; we bound the
    // read to MAX_VARIABLE_NAME_LEN to avoid unbounded access.
    let slice = unsafe { core::slice::from_raw_parts(s, MAX_VARIABLE_NAME_LEN) };
    slice
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(MAX_VARIABLE_NAME_LEN)
}
