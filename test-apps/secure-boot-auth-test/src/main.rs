//! Secure Boot authenticated-variable and image-verification test.
//!
//! Interprets `\sbtest\plan.txt` (written by `gen_fixtures.py`) against the
//! fixtures next to it on the ESP. The plan is split into stages separated
//! by cold resets; the current stage is kept in a private NV variable. Every
//! check prints `SBAUTH PASS <id>` or `SBAUTH FAIL <id>` for the host harness.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::null_mut;
use r_efi::efi::{self, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{file, loaded_image, simple_file_system};

static mut SYSTEM_TABLE: *mut SystemTable = null_mut();
static mut IMAGE_HANDLE: Handle = null_mut();
static mut ROOT: *mut file::Protocol = null_mut();

const GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
const SECURITY_DB: Guid = Guid::from_fields(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    0xa3,
    0xbc,
    &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);
/// Test-owned vendor GUID, matching `PRIV_GUID` in gen_fixtures.py.
const TEST_GUID: Guid = Guid::from_fields(
    0x2b7c7c5e,
    0x0d0a,
    0x4b8e,
    0x9a,
    0x59,
    &[0x5c, 0xe0, 0xc3, 0xa0, 0xe7, 0xd1],
);

fn system_table() -> &'static SystemTable {
    // SAFETY: set once in efi_main before any use.
    unsafe { &*SYSTEM_TABLE }
}

fn boot_services() -> &'static efi::BootServices {
    // SAFETY: boot services stay valid while this application runs.
    unsafe { &*system_table().boot_services }
}

fn runtime_services() -> &'static efi::RuntimeServices {
    // SAFETY: runtime services stay valid while this application runs.
    unsafe { &*system_table().runtime_services }
}

struct Console;

impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let out = system_table().con_out;
        let mut buffer = [0u16; 130];
        let mut len = 0;
        for unit in text.encode_utf16() {
            if unit == u16::from(b'\n') {
                buffer[len] = u16::from(b'\r');
                len += 1;
            }
            buffer[len] = unit;
            len += 1;
            if len >= 127 {
                buffer[len] = 0;
                // SAFETY: NUL-terminated UCS-2 string.
                unsafe { ((*out).output_string)(out, buffer.as_mut_ptr()) };
                len = 0;
            }
        }
        buffer[len] = 0;
        // SAFETY: NUL-terminated UCS-2 string.
        unsafe { ((*out).output_string)(out, buffer.as_mut_ptr()) };
        Ok(())
    }
}

macro_rules! say {
    ($($arg:tt)*) => {{
        let _ = writeln!(Console, $($arg)*);
    }};
}

// ---------------------------------------------------------------------------
// Memory and files
// ---------------------------------------------------------------------------

struct Buffer {
    ptr: *mut u8,
    len: usize,
}

impl Buffer {
    fn new(len: usize) -> Option<Self> {
        let mut ptr = null_mut();
        let status = (boot_services().allocate_pool)(efi::LOADER_DATA, len.max(1), &mut ptr);
        (status == Status::SUCCESS).then_some(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    fn copy(data: &[u8]) -> Option<Self> {
        let mut buffer = Self::new(data.len())?;
        buffer.as_mut().copy_from_slice(data);
        Some(buffer)
    }

    fn as_ref(&self) -> &[u8] {
        // SAFETY: `ptr` owns at least `len` bytes.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` owns at least `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        (boot_services().free_pool)(self.ptr.cast());
    }
}

fn root() -> Option<*mut file::Protocol> {
    // SAFETY: single-threaded boot-services application.
    unsafe {
        if ROOT.is_null() {
            let mut image: *mut c_void = null_mut();
            let mut guid = loaded_image::PROTOCOL_GUID;
            if (boot_services().handle_protocol)(IMAGE_HANDLE, &mut guid, &mut image)
                != Status::SUCCESS
            {
                return None;
            }
            let device = (*image.cast::<loaded_image::Protocol>()).device_handle;
            let mut fs: *mut c_void = null_mut();
            let mut guid = simple_file_system::PROTOCOL_GUID;
            if (boot_services().handle_protocol)(device, &mut guid, &mut fs) != Status::SUCCESS {
                return None;
            }
            let fs = fs.cast::<simple_file_system::Protocol>();
            let mut root = null_mut();
            if ((*fs).open_volume)(fs, &mut root) != Status::SUCCESS {
                return None;
            }
            ROOT = root;
        }
        Some(ROOT)
    }
}

fn read_file(name: &str) -> Option<Buffer> {
    let root = root()?;
    let mut path = [0u16; 160];
    let full = "\\sbtest\\".encode_utf16().chain(name.encode_utf16());
    for (slot, unit) in path.iter_mut().zip(full) {
        *slot = if unit == u16::from(b'/') {
            u16::from(b'\\')
        } else {
            unit
        };
    }
    if name.len() + 9 >= path.len() {
        return None;
    }
    let mut handle = null_mut();
    // SAFETY: valid file protocol pointers and NUL-terminated path.
    unsafe {
        if ((*root).open)(root, &mut handle, path.as_mut_ptr(), file::MODE_READ, 0)
            != Status::SUCCESS
        {
            return None;
        }
        let mut info = [0u64; 128];
        let mut size = core::mem::size_of_val(&info);
        let mut guid = file::INFO_ID;
        let status = ((*handle).get_info)(handle, &mut guid, &mut size, info.as_mut_ptr().cast());
        let mut buffer = if status == Status::SUCCESS {
            Buffer::new(info[1] as usize)
        } else {
            None
        };
        if let Some(buffer) = buffer.as_mut() {
            let mut len = buffer.len;
            if ((*handle).read)(handle, &mut len, buffer.ptr.cast()) != Status::SUCCESS
                || len != buffer.len
            {
                ((*handle).close)(handle);
                return None;
            }
        }
        ((*handle).close)(handle);
        buffer
    }
}

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

struct Variable {
    name: [u16; 40],
    guid: Guid,
}

impl Variable {
    fn new(name: &str, guid: Guid) -> Self {
        let mut buffer = [0u16; 40];
        for (slot, unit) in buffer.iter_mut().zip(name.encode_utf16()) {
            *slot = unit;
        }
        Self { name: buffer, guid }
    }

    fn named(alias: &str) -> Option<Self> {
        let (name, guid) = match alias {
            "PK" | "KEK" | "SecureBootEnable" | "SecureBoot" | "SetupMode" => (alias, GLOBAL),
            "db" | "dbx" => (alias, SECURITY_DB),
            "priv1" => ("CrabEfiSbTestPriv1", TEST_GUID),
            "priv2" => ("CrabEfiSbTestPriv2", TEST_GUID),
            "stage" => ("CrabEfiSbTestStage", TEST_GUID),
            _ => return None,
        };
        Some(Self::new(name, guid))
    }

    fn get(&self) -> Result<(u32, Buffer), Status> {
        let mut attributes = 0;
        let mut size = 0;
        let mut name = self.name;
        let mut guid = self.guid;
        let status = (runtime_services().get_variable)(
            name.as_mut_ptr(),
            &mut guid,
            &mut attributes,
            &mut size,
            null_mut(),
        );
        if status != Status::BUFFER_TOO_SMALL {
            return Err(if status == Status::SUCCESS {
                Status::BAD_BUFFER_SIZE
            } else {
                status
            });
        }
        let buffer = Buffer::new(size).ok_or(Status::OUT_OF_RESOURCES)?;
        let status = (runtime_services().get_variable)(
            name.as_mut_ptr(),
            &mut guid,
            &mut attributes,
            &mut size,
            buffer.ptr.cast(),
        );
        if status != Status::SUCCESS || size != buffer.len {
            return Err(status);
        }
        Ok((attributes, buffer))
    }

    fn set(&self, attributes: u32, data: &[u8]) -> Status {
        let mut name = self.name;
        let mut guid = self.guid;
        (runtime_services().set_variable)(
            name.as_mut_ptr(),
            &mut guid,
            attributes,
            data.len(),
            data.as_ptr() as *mut c_void,
        )
    }

    fn byte(&self) -> Option<u8> {
        self.get()
            .ok()
            .and_then(|(_, data)| data.as_ref().first().copied())
    }
}

/// Visit every EFI_SIGNATURE_DATA (owner + data) with its list's type.
/// Returns false on a malformed signature database.
fn for_each_signature(database: &[u8], mut visit: impl FnMut(&[u8], &[u8])) -> bool {
    let mut rest = database;
    while !rest.is_empty() {
        if rest.len() < 28 {
            return false;
        }
        let read = |offset: usize| {
            u32::from_le_bytes(rest[offset..offset + 4].try_into().unwrap()) as usize
        };
        let (list_size, header_size, size) = (read(16), read(20), read(24));
        if list_size < 28 + header_size
            || list_size > rest.len()
            || size < 16
            || (list_size - 28 - header_size) % size != 0
        {
            return false;
        }
        let kind = &rest[..16];
        for signature in rest[28 + header_size..list_size].chunks_exact(size) {
            visit(kind, signature);
        }
        rest = &rest[list_size..];
    }
    true
}

fn contains_signature(database: &[u8], kind: &[u8], signature: &[u8]) -> bool {
    let mut found = false;
    for_each_signature(database, |k, s| found |= k == kind && s == signature);
    found
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

const STATUS_NAMES: &[(&str, Status)] = &[
    ("SUCCESS", Status::SUCCESS),
    ("INVALID_PARAMETER", Status::INVALID_PARAMETER),
    ("UNSUPPORTED", Status::UNSUPPORTED),
    ("BAD_BUFFER_SIZE", Status::BAD_BUFFER_SIZE),
    ("BUFFER_TOO_SMALL", Status::BUFFER_TOO_SMALL),
    ("DEVICE_ERROR", Status::DEVICE_ERROR),
    ("WRITE_PROTECTED", Status::WRITE_PROTECTED),
    ("OUT_OF_RESOURCES", Status::OUT_OF_RESOURCES),
    ("NOT_FOUND", Status::NOT_FOUND),
    ("ACCESS_DENIED", Status::ACCESS_DENIED),
    ("SECURITY_VIOLATION", Status::SECURITY_VIOLATION),
];

struct Name(Status);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match STATUS_NAMES.iter().find(|(_, status)| *status == self.0) {
            Some((name, _)) => f.write_str(name),
            None => write!(f, "{:#x}", self.0.as_usize()),
        }
    }
}

#[derive(Clone, Copy)]
enum Expect {
    Exact(Status),
    /// Any error status; the spec does not pin a code.
    Error,
    /// Not checked (cleanup steps).
    Any,
}

impl Expect {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "ERROR" => Some(Self::Error),
            "ANY" => Some(Self::Any),
            _ => STATUS_NAMES
                .iter()
                .find(|(name, _)| *name == text)
                .map(|(_, status)| Self::Exact(*status)),
        }
    }

    fn matches(self, status: Status) -> bool {
        match self {
            Self::Exact(expected) => status == expected,
            Self::Error => status.is_error(),
            Self::Any => true,
        }
    }

    fn rejects(self) -> bool {
        match self {
            Self::Exact(expected) => expected.is_error(),
            Self::Error => true,
            Self::Any => false,
        }
    }
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(status) => write!(f, "{}", Name(*status)),
            Self::Error => f.write_str("an error"),
            Self::Any => f.write_str("anything"),
        }
    }
}

fn parse_number(text: &str) -> Option<usize> {
    match text.strip_prefix("0x") {
        Some(hex) => usize::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

// ---------------------------------------------------------------------------
// Plan interpreter
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Results {
    passed: usize,
    failed: usize,
}

impl Results {
    fn check(&mut self, id: &str, ok: bool, detail: fmt::Arguments<'_>) {
        if ok {
            self.passed += 1;
            say!("SBAUTH PASS {}: {}", id, detail);
        } else {
            self.failed += 1;
            say!("SBAUTH FAIL {}: {}", id, detail);
        }
    }
}

fn snapshot(variable: &Variable) -> Result<(u32, Buffer), Status> {
    variable.get().and_then(|(attributes, data)| {
        Ok((
            attributes,
            Buffer::copy(data.as_ref()).ok_or(Status::OUT_OF_RESOURCES)?,
        ))
    })
}

fn same(before: &Result<(u32, Buffer), Status>, after: &Result<(u32, Buffer), Status>) -> bool {
    match (before, after) {
        (Ok((a, x)), Ok((b, y))) => a == b && x.as_ref() == y.as_ref(),
        (Err(a), Err(b)) => a == b,
        _ => false,
    }
}

fn step_set(results: &mut Results, id: &str, args: &[&str]) {
    let [alias, attributes, file, expect] = args else {
        return results.check(id, false, format_args!("malformed set step"));
    };
    let (Some(variable), Some(attributes), Some(data), Some(expect)) = (
        Variable::named(alias),
        parse_number(attributes),
        read_file(file),
        Expect::parse(expect),
    ) else {
        return results.check(id, false, format_args!("bad arguments or missing {}", file));
    };
    let before = snapshot(&variable);
    let status = variable.set(attributes as u32, data.as_ref());
    if !expect.matches(status) {
        return results.check(
            id,
            false,
            format_args!("expected {}, got {}", expect, Name(status)),
        );
    }
    if expect.rejects() && !same(&before, &snapshot(&variable)) {
        return results.check(
            id,
            false,
            format_args!("rejected with {} but {} changed", Name(status), alias),
        );
    }
    results.check(id, true, format_args!("{}", Name(status)));
}

fn step_var(results: &mut Results, id: &str, args: &[&str]) {
    let (Some(alias), Some(kind)) = (args.first(), args.get(1)) else {
        return results.check(id, false, format_args!("malformed var step"));
    };
    let Some(variable) = Variable::named(alias) else {
        return results.check(id, false, format_args!("unknown variable {}", alias));
    };
    let current = variable.get();
    if *kind == "absent" {
        return match current {
            Err(Status::NOT_FOUND) => results.check(id, true, format_args!("NOT_FOUND")),
            Err(status) => results.check(
                id,
                false,
                format_args!("expected NOT_FOUND, got {}", Name(status)),
            ),
            Ok((_, data)) => results.check(
                id,
                false,
                format_args!("expected NOT_FOUND, {} has {} bytes", alias, data.len),
            ),
        };
    }
    let (attributes, data) = match current {
        Ok(value) => value,
        Err(status) => {
            return results.check(id, false, format_args!("GetVariable: {}", Name(status)))
        }
    };
    match (*kind, args.get(2), args.get(3)) {
        ("equals", Some(expected_attributes), Some(file)) => {
            let (Some(expected_attributes), Some(expected)) =
                (parse_number(expected_attributes), read_file(file))
            else {
                return results.check(id, false, format_args!("bad arguments"));
            };
            let ok =
                attributes as usize == expected_attributes && data.as_ref() == expected.as_ref();
            results.check(
                id,
                ok,
                format_args!(
                    "attributes {:#x} (want {:#x}), {} bytes (want {}), content {}",
                    attributes,
                    expected_attributes,
                    data.len,
                    expected.len,
                    if data.as_ref() == expected.as_ref() {
                        "equal"
                    } else {
                        "differs"
                    }
                ),
            );
        }
        ("has" | "lacks", Some(file), None) => {
            let Some(expected) = read_file(file) else {
                return results.check(id, false, format_args!("missing {}", file));
            };
            let (mut present, mut total) = (0, 0);
            let valid = for_each_signature(expected.as_ref(), |kind, signature| {
                total += 1;
                present += usize::from(contains_signature(data.as_ref(), kind, signature));
            });
            let ok = valid
                && total > 0
                && if *kind == "has" {
                    present == total
                } else {
                    present == 0
                };
            results.check(
                id,
                ok,
                format_args!("{}/{} entries of {} present", present, total, file),
            );
        }
        ("count", Some(expected), None) => {
            let mut count = 0;
            let valid = for_each_signature(data.as_ref(), |_, _| count += 1);
            let ok = valid && parse_number(expected) == Some(count);
            results.check(
                id,
                ok,
                format_args!("{} entries (want {})", count, expected),
            );
        }
        _ => results.check(id, false, format_args!("malformed var step")),
    }
}

fn step_mode(results: &mut Results, id: &str, args: &[&str]) {
    let (Some(setup), Some(secure)) = (
        args.first().and_then(|value| parse_number(value)),
        args.get(1).and_then(|value| parse_number(value)),
    ) else {
        return results.check(id, false, format_args!("malformed mode step"));
    };
    let actual_setup = Variable::named("SetupMode").and_then(|variable| variable.byte());
    let actual_secure = Variable::named("SecureBoot").and_then(|variable| variable.byte());
    let ok = actual_setup == Some(setup as u8) && actual_secure == Some(secure as u8);
    results.check(
        id,
        ok,
        format_args!(
            "SetupMode={:?} (want {}), SecureBoot={:?} (want {})",
            actual_setup, setup, actual_secure, secure
        ),
    );
}

const HANDLE_SENTINEL: usize = 0x5b5b_0001;

/// LoadImage from a memory buffer. The handle starts as a sentinel so a
/// returned NULL and an untouched output can be told apart.
fn load_image(file: &str) -> Option<(Status, Handle)> {
    let image = read_file(file)?;
    let mut handle = HANDLE_SENTINEL as Handle;
    // SAFETY: valid image buffer and handle output.
    let status = (boot_services().load_image)(
        efi::Boolean::FALSE,
        unsafe { IMAGE_HANDLE },
        null_mut(),
        image.ptr.cast(),
        image.len,
        &mut handle,
    );
    Some((status, handle))
}

fn start_image(handle: Handle) -> Status {
    let mut exit_size = 0;
    let mut exit_data = null_mut();
    (boot_services().start_image)(handle, &mut exit_size, &mut exit_data)
}

fn usable(handle: Handle) -> bool {
    !handle.is_null() && handle as usize != HANDLE_SENTINEL
}

fn step_load(results: &mut Results, id: &str, args: &[&str]) {
    let (Some(file), Some(mode)) = (args.first(), args.get(1)) else {
        return results.check(id, false, format_args!("malformed load step"));
    };
    let Some((status, handle)) = load_image(file) else {
        return results.check(id, false, format_args!("missing {}", file));
    };
    match (*mode, args.get(2).and_then(|magic| parse_number(magic))) {
        ("run", Some(magic)) => {
            if status != Status::SUCCESS {
                return results.check(
                    id,
                    false,
                    format_args!("LoadImage: expected SUCCESS, got {}", Name(status)),
                );
            }
            let exit = start_image(handle);
            results.check(
                id,
                exit.as_usize() == magic,
                format_args!(
                    "loaded, StartImage returned {} (want {:#x})",
                    Name(exit),
                    magic
                ),
            );
        }
        ("verify", None) => {
            // Verification only: never start third-party images such as shim.
            if status == Status::SUCCESS {
                (boot_services().unload_image)(handle);
            }
            results.check(
                id,
                status == Status::SUCCESS,
                format_args!("LoadImage {} (want SUCCESS)", Name(status)),
            );
        }
        ("deny", None) => {
            if status == Status::SUCCESS {
                (boot_services().unload_image)(handle);
                return results.check(id, false, format_args!("LoadImage SUCCESS"));
            }
            // SECURITY_VIOLATION may come with a loaded, never-startable image.
            let started = if status == Status::SECURITY_VIOLATION && usable(handle) {
                let exit = start_image(handle);
                (boot_services().unload_image)(handle);
                Some(exit)
            } else {
                None
            };
            let ok = started.is_none_or(|exit| exit.is_error());
            results.check(id, ok, format_args!("LoadImage {}", Name(status)));
        }
        _ => results.check(id, false, format_args!("malformed load step")),
    }
}

/// UEFI 2.10 7.4.1 LoadImage: ACCESS_DENIED returns NULL in *ImageHandle;
/// SECURITY_VIOLATION returns a loaded image that StartImage refuses.
fn step_load_status(results: &mut Results, id: &str, args: &[&str]) {
    let Some((status, handle)) = args.first().and_then(|file| load_image(file)) else {
        return results.check(id, false, format_args!("missing image"));
    };
    let output = if handle.is_null() {
        "NULL"
    } else if handle as usize == HANDLE_SENTINEL {
        "unchanged"
    } else {
        "a handle"
    };
    let ok = if status == Status::ACCESS_DENIED {
        handle.is_null()
    } else if status == Status::SECURITY_VIOLATION && usable(handle) {
        let exit = start_image(handle);
        (boot_services().unload_image)(handle);
        exit == Status::SECURITY_VIOLATION
    } else {
        false
    };
    results.check(
        id,
        ok,
        format_args!("LoadImage {} with {} in *ImageHandle", Name(status), output),
    );
}

fn step_digest(label: &str) {
    let _ = write!(Console, "SBSTATE {}", label);
    for alias in ["PK", "KEK", "db", "dbx"] {
        let variable = Variable::named(alias).unwrap();
        match variable.get() {
            Ok((attributes, data)) => {
                let _ = write!(
                    Console,
                    " {}={:#x}:{}:{:016x}",
                    alias,
                    attributes,
                    data.len,
                    fnv1a(data.as_ref())
                );
            }
            Err(status) => {
                let _ = write!(Console, " {}={}", alias, Name(status));
            }
        }
    }
    say!("");
}

fn finish_stage(results: &Results, stage: usize) {
    say!(
        "SBAUTH STAGE {} END passed={} failed={}",
        stage,
        results.passed,
        results.failed
    );
}

fn reset(reset_type: efi::ResetType) -> ! {
    (runtime_services().reset_system)(reset_type, Status::SUCCESS, 0, null_mut());
    loop {
        core::hint::spin_loop();
    }
}

fn run() -> Status {
    let Some(stage_variable) = Variable::named("stage") else {
        return Status::ABORTED;
    };
    let stage = stage_variable.byte().map_or(1, usize::from);
    let Some(plan) = read_file("plan.txt") else {
        say!("SBAUTH FAIL plan: cannot read \\sbtest\\plan.txt");
        return Status::NOT_FOUND;
    };
    let Ok(plan) = core::str::from_utf8(plan.as_ref()) else {
        return Status::INVALID_PARAMETER;
    };
    let mut results = Results::default();
    let mut active = false;
    for line in plan.lines() {
        let mut tokens = [""; 8];
        let mut count = 0;
        for token in line.split_whitespace().take(tokens.len()) {
            tokens[count] = token;
            count += 1;
        }
        let tokens = &tokens[..count];
        match tokens {
            [] => continue,
            [comment, ..] if comment.starts_with('#') => continue,
            ["stage", number] => {
                active = parse_number(number) == Some(stage);
                if active {
                    say!("SBAUTH STAGE {} BEGIN", stage);
                }
            }
            _ if !active => continue,
            ["reset"] => {
                finish_stage(&results, stage);
                let next = [stage as u8 + 1];
                let status = stage_variable.set(0x3, &next);
                if status != Status::SUCCESS {
                    say!("SBAUTH FAIL stage-advance: {}", Name(status));
                    return Status::ABORTED;
                }
                reset(efi::RESET_COLD);
            }
            ["end"] => {
                finish_stage(&results, stage);
                stage_variable.set(0, &[]);
                say!("SBAUTH COMPLETE");
                reset(efi::RESET_SHUTDOWN);
            }
            ["digest", label] => step_digest(label),
            // Optional assets, such as a downloaded shim, may be absent.
            ["opt", "load", id, file, args @ ..] => {
                if read_file(file).is_none() {
                    say!("SBAUTH SKIP {}: {} not on the ESP", id, file);
                } else {
                    let mut all = [""; 4];
                    all[0] = file;
                    all[1..=args.len().min(3)].copy_from_slice(&args[..args.len().min(3)]);
                    step_load(&mut results, id, &all[..=args.len().min(3)]);
                }
            }
            [command, id, args @ ..] => match *command {
                "set" => step_set(&mut results, id, args),
                "var" => step_var(&mut results, id, args),
                "mode" => step_mode(&mut results, id, args),
                "load" => step_load(&mut results, id, args),
                "loadstatus" => step_load_status(&mut results, id, args),
                _ => results.check(id, false, format_args!("unknown step {}", command)),
            },
            _ => say!("SBAUTH FAIL plan: malformed line {}", line),
        }
    }
    say!("SBAUTH FAIL plan: stage {} has no reset or end", stage);
    Status::ABORTED
}

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: firmware entry; stored before any other use.
    unsafe {
        SYSTEM_TABLE = system_table;
        IMAGE_HANDLE = image_handle;
    }
    say!("Secure Boot authenticated variable test");
    run()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    say!("SBAUTH FAIL panic");
    loop {
        core::hint::spin_loop();
    }
}
