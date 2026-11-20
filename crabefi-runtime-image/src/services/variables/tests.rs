use super::*;
use crabefi_efi_types::authentication::EfiVariableAuthentication2;

use crate::auth;

use super::journal::{replay_apply_result, replay_record};
use crabefi_runtime_abi::{BridgeRequest, bridge_operation};

const RAW_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
const AUTH_ATTRIBUTES: VariableAttributes =
    RAW_ATTRIBUTES.union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);

extern "C" fn successful_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: tests call this synchronously with a live request.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return efi::Status::INVALID_PARAMETER.as_usize();
    };
    match request.operation {
        bridge_operation::PERSIST_WRITE | bridge_operation::PERSIST_DELETE => {
            efi::Status::SUCCESS.as_usize()
        }
        _ => efi::Status::ACCESS_DENIED.as_usize(),
    }
}

extern "C" fn setup_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: same immediate-call contract as successful_bridge.
    if unsafe { request.as_ref() }
        .is_some_and(|request| request.operation == bridge_operation::AUTHORIZE_SETUP_PK_DELETE)
    {
        efi::Status::SUCCESS.as_usize()
    } else {
        successful_bridge(request)
    }
}

extern "C" fn failing_setup_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: same immediate-call contract as successful_bridge.
    if unsafe { request.as_ref() }
        .is_some_and(|request| request.operation == bridge_operation::AUTHORIZE_SETUP_PK_DELETE)
    {
        efi::Status::SUCCESS.as_usize()
    } else {
        efi::Status::WRITE_PROTECTED.as_usize()
    }
}

extern "C" fn secure_boot_enable_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: same immediate-call contract as successful_bridge.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return efi::Status::INVALID_PARAMETER.as_usize();
    };
    if request.operation != bridge_operation::AUTHORIZE_SETUP_SECURE_BOOT_ENABLE {
        return successful_bridge(request);
    }
    // SAFETY: the runtime image passes its live request data.
    let data = unsafe {
        core::slice::from_raw_parts(request.data_address as *const u8, request.data_len as usize)
    };
    if request.guid == secure_boot::EFI_GLOBAL_VARIABLE_GUID
        && request.attributes == RAW_ATTRIBUTES.bits()
        && data == [0]
    {
        efi::Status::SUCCESS.as_usize()
    } else {
        efi::Status::ACCESS_DENIED.as_usize()
    }
}

fn fixture_payload(data: &'static [u8]) -> &'static [u8] {
    EfiVariableAuthentication2::from_bytes(data)
        .and_then(|authentication| authentication.variable_data(data))
        .unwrap()
}

/// Variable store with a successful boot bridge and a retained buffer.
struct Fixture {
    store: VariableStore,
    transaction: VariableTransaction,
    deferred_transaction: deferred::DeferredTransaction,
    buffer: Vec<u8>,
}

impl Fixture {
    fn new() -> Box<Self> {
        Box::new(Self {
            store: VariableStore::new(),
            transaction: VariableTransaction::new(),
            deferred_transaction: deferred::DeferredTransaction::new(),
            buffer: vec![0; 64 * 1024],
        })
    }

    /// A fixture whose retained buffer holds an initialized journal.
    fn retained() -> Box<Self> {
        let mut fixture = Self::new();
        DeferredRegion::new(&mut fixture.buffer)
            .prepare_retained()
            .unwrap();
        fixture
    }

    fn write(
        &mut self,
        phase: Phase,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        data: &[u8],
    ) -> efi::Status {
        self.write_using_bridge(
            phase,
            guid,
            name,
            attributes,
            data,
            successful_bridge as *const () as u64,
        )
    }

    fn write_using_bridge(
        &mut self,
        phase: Phase,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        data: &[u8],
        bridge: u64,
    ) -> efi::Status {
        efi::status(apply_variable(
            VariableContext {
                store: &mut self.store,
                transaction: &mut self.transaction,
                phase,
                bridge,
                deferred: Some(DeferredSink {
                    transaction: &mut self.deferred_transaction,
                    region: DeferredRegion::new(&mut self.buffer),
                }),
            },
            VariableRequest {
                guid,
                name,
                attributes,
                data,
            },
        ))
    }

    fn apply(
        &mut self,
        phase: Phase,
        variable: SecureBootVariable,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> efi::Status {
        self.write(phase, *variable.guid(), variable.name(), attributes, data)
    }

    fn import(
        &mut self,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        data: &[u8],
        timestamp: Option<VariableTimestamp>,
    ) {
        self.store
            .import(
                &mut self.transaction,
                guid,
                name,
                attributes,
                data,
                timestamp,
            )
            .unwrap();
    }

    /// Enroll the test certificate as KEK, db, dbx and PK with unsigned
    /// Setup Mode envelopes.
    fn enroll(&mut self) {
        let mut envelope = unsigned_envelope(2024);
        envelope.extend_from_slice(include_bytes!("../../../tests/fixtures/pk.esl"));
        for variable in [
            SecureBootVariable::Kek,
            SecureBootVariable::Db,
            SecureBootVariable::Dbx,
            SecureBootVariable::PK,
        ] {
            assert_eq!(
                self.apply(Phase::BootActive, variable, AUTH_ATTRIBUTES, &envelope),
                efi::Status::SUCCESS
            );
        }
        assert!(!self.store.setup_mode());
    }
}

fn timestamp(year: u16) -> VariableTimestamp {
    VariableTimestamp {
        year,
        month: 1,
        day: 1,
        ..VariableTimestamp::default()
    }
}

#[test]
fn firmware_imports_private_attempt_state_but_public_writes_cannot_forge_it() {
    let mut fixture = Fixture::new();
    let guid = capsule::CAPSULE_REPORT_VARIABLE_GUID;
    let name = capsule::ESRT_LAST_ATTEMPT_VARIABLE_NAME;
    fixture.import(guid, name, RAW_ATTRIBUTES, b"firmware", None);

    for (attributes, value) in [
        (RAW_ATTRIBUTES, b"forged".as_slice()),
        (
            RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            b"append".as_slice(),
        ),
        (VariableAttributes::empty(), b"".as_slice()),
    ] {
        assert_eq!(
            fixture.write(Phase::BootActive, guid, name, attributes, value),
            efi::Status::WRITE_PROTECTED
        );
    }

    let slot = fixture.store.find(&guid, name, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(b"firmware".as_slice()));
}

#[test]
fn firmware_imports_the_event_log_but_public_writes_cannot_change_it() {
    let mut fixture = Fixture::retained();
    let guid = event_log::SETTINGS_VARIABLE_GUID;
    let name = event_log::EVENT_LOG_VARIABLE_NAME;
    fixture.import(guid, name, RAW_ATTRIBUTES, b"firmware", None);

    for phase in [Phase::BootActive, Phase::SealedPhysical, Phase::Virtual] {
        for (attributes, value) in [
            (RAW_ATTRIBUTES, b"forged".as_slice()),
            (
                RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
                b"append".as_slice(),
            ),
            (VariableAttributes::empty(), b"".as_slice()),
        ] {
            assert_eq!(
                fixture.write(phase, guid, name, attributes, value),
                efi::Status::WRITE_PROTECTED
            );
        }
    }

    let slot = fixture.store.find(&guid, name, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(b"firmware".as_slice()));
}

#[test]
fn raw_writes_cannot_modify_previously_authenticated_variables() {
    let mut fixture = Fixture::new();
    let guid = [0x42; 16];
    let name = [b'A' as u16, b'u' as u16, b't' as u16, b'h' as u16];

    // Boot import is firmware-authoritative and may enroll an
    // authenticated variable directly.
    fixture.import(guid, &name, AUTH_ATTRIBUTES, b"payload", None);

    let raw = AUTH_ATTRIBUTES.difference(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
    for (attributes, value) in [
        (raw, b"raw".as_slice()),
        (raw | VariableAttributes::APPEND_WRITE, b"append".as_slice()),
        (VariableAttributes::empty(), b"".as_slice()),
    ] {
        assert_eq!(
            fixture.write(Phase::BootActive, guid, &name, attributes, value),
            efi::Status::WRITE_PROTECTED
        );
    }

    // Authenticated requests pass the gate and reach signature
    // verification, which rejects the truncated envelope.
    assert_eq!(
        fixture.write(Phase::BootActive, guid, &name, AUTH_ATTRIBUTES, b"garbage"),
        efi::Status::SECURITY_VIOLATION
    );

    // The authenticated content is untouched by every rejected attempt.
    let slot = fixture.store.find(&guid, &name, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(b"payload".as_slice()));
    assert_eq!(slot.attributes, AUTH_ATTRIBUTES);
}

/// Minimal authenticated-variable envelope with an empty PKCS#7 payload.
/// Enough to pass header validation and carry a timestamp, but never a
/// valid signature.
fn unsigned_envelope(year: u16) -> Vec<u8> {
    use crabefi_efi_types::secure_boot::EFI_CERT_TYPE_PKCS7_GUID;

    let mut envelope = Vec::new();
    envelope.extend_from_slice(&year.to_le_bytes());
    envelope.extend_from_slice(&[1, 1, 0, 0, 0, 0]); // month..pad1
    envelope.extend_from_slice(&0u32.to_le_bytes()); // nanosecond
    envelope.extend_from_slice(&0i16.to_le_bytes()); // timezone
    envelope.push(0); // daylight
    envelope.push(0); // pad2
    envelope.extend_from_slice(&24u32.to_le_bytes()); // dw_length
    envelope.extend_from_slice(&0x0200u16.to_le_bytes()); // w_revision
    envelope.extend_from_slice(&0x0ef1u16.to_le_bytes()); // w_certificate_type
    envelope.extend_from_slice(&EFI_CERT_TYPE_PKCS7_GUID);
    envelope
}

/// One SHA-256 signature list holding `hashes`, each filled with its byte.
fn hash_list(hashes: &[u8]) -> Vec<u8> {
    use crabefi_efi_types::secure_boot::EFI_CERT_SHA256_GUID;

    let mut list = EFI_CERT_SHA256_GUID.to_vec();
    list.extend_from_slice(&(28 + 48 * hashes.len() as u32).to_le_bytes());
    list.extend_from_slice(&0u32.to_le_bytes()); // signature_header_size
    list.extend_from_slice(&48u32.to_le_bytes()); // signature_size
    for hash in hashes {
        list.extend_from_slice(&[0x77; 16]); // owner
        list.extend_from_slice(&[*hash; 32]);
    }
    list
}

fn dbx_envelope(year: u16, hashes: &[u8]) -> Vec<u8> {
    let mut envelope = unsigned_envelope(year);
    envelope.extend_from_slice(&hash_list(hashes));
    envelope
}

#[test]
fn older_appends_extend_signature_databases_without_lowering_the_floor() {
    let dbx = SecureBootVariable::Dbx;
    let append = AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    // Setup Mode: timestamps are enforced, signatures are not.
    let mut fixture = Fixture::new();
    fixture.import(
        *dbx.guid(),
        dbx.name(),
        AUTH_ATTRIBUTES,
        &hash_list(&[1, 2]),
        Some(timestamp(2025)),
    );

    // Microsoft stamps every dbx update 2010. Only new hashes are added.
    let update = dbx_envelope(2010, &[2, 3]);
    assert_eq!(
        fixture.apply(Phase::BootActive, dbx, append, &update),
        efi::Status::SUCCESS
    );
    let merged = [hash_list(&[1, 2]), hash_list(&[3])].concat();
    assert_eq!(fixture.store.key_database_data(dbx), Some(&merged[..]));
    assert_eq!(fixture.store.auth_timestamp(dbx), timestamp(2025));
    assert_eq!(
        fixture.store.auth_history_timestamp(dbx.guid(), dbx.name()),
        Some(timestamp(2025))
    );

    // Repeating it changes nothing and does not touch flash.
    assert_eq!(
        fixture.write_using_bridge(
            Phase::BootActive,
            *dbx.guid(),
            dbx.name(),
            append,
            &update,
            failing_setup_bridge as *const () as u64,
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(fixture.store.key_database_data(dbx), Some(&merged[..]));

    // A newer append advances the floor; an older replacement is a replay.
    assert_eq!(
        fixture.apply(Phase::BootActive, dbx, append, &dbx_envelope(2026, &[4])),
        efi::Status::SUCCESS
    );
    assert_eq!(fixture.store.auth_timestamp(dbx), timestamp(2026));
    assert_eq!(
        fixture.apply(Phase::BootActive, dbx, AUTH_ATTRIBUTES, &update),
        efi::Status::SECURITY_VIOLATION
    );

    // Appends to other variables are exempt too (UEFI 2.10 8.2): the
    // older envelope gets past the floor and fails on its empty signature.
    let (guid, name) = ([0x42; 16], [b'A' as u16]);
    fixture.import(guid, &name, AUTH_ATTRIBUTES, b"x", Some(timestamp(2025)));
    assert!(matches!(
        auth::verify_authenticated_variable(
            &fixture.store,
            &name,
            &guid,
            append.bits(),
            &unsigned_envelope(2010),
        ),
        Err(auth::AuthError::InvalidHeader)
    ));
    assert!(matches!(
        auth::verify_authenticated_variable(
            &fixture.store,
            &name,
            &guid,
            AUTH_ATTRIBUTES.bits(),
            &unsigned_envelope(2010),
        ),
        Err(auth::AuthError::InvalidTimestamp)
    ));
}

/// EDK2 answers EFI_SECURITY_VIOLATION for any envelope that does not
/// authenticate, in every mode (Variable.c SetVariable, AuthService.c
/// VerifyTimeBasedPayload). Linux reports it as EACCES.
#[test]
fn malformed_envelopes_are_security_violations() {
    let valid = dbx_envelope(2026, &[1]);
    let patched = |offset: usize, value: &[u8]| {
        let mut envelope = valid.clone();
        envelope[offset..offset + value.len()].copy_from_slice(value);
        envelope
    };
    let header_errors = [
        Vec::new(),
        b"garbage".to_vec(),
        patched(16, &u32::MAX.to_le_bytes()), // dwLength past the end
        patched(16, &23u32.to_le_bytes()),    // dwLength below the header
        patched(22, &2u16.to_le_bytes()),     // wCertificateType
        patched(24, &[0; 16]),                // CertType
    ];
    let mut garbage_signature = patched(16, &31u32.to_le_bytes());
    garbage_signature.splice(40..40, *b"garbage");
    let mut sha384 = include_bytes!("../../../tests/fixtures/db-update.bin").to_vec();
    let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let oid = sha384
        .windows(sha256.len())
        .position(|window| window == sha256)
        .unwrap();
    sha384[oid + sha256.len() - 1] = 0x02;
    let signature_errors = [valid.clone(), garbage_signature, sha384];

    let mut fixture = Fixture::new();
    for user_mode in [false, true] {
        if user_mode {
            fixture.enroll();
        }
        let mut targets = [
            SecureBootVariable::PK,
            SecureBootVariable::Kek,
            SecureBootVariable::Db,
            SecureBootVariable::Dbx,
        ]
        .map(|variable| (*variable.guid(), variable.name().to_vec(), user_mode))
        .to_vec();
        targets.push(([0x42; 16], utf16("Auth"), true));
        // Setup Mode skips signatures of the Secure Boot databases only.
        for (guid, name, signed) in targets {
            let signature_errors = signature_errors.iter().filter(|_| signed);
            for data in header_errors.iter().chain(signature_errors) {
                assert_eq!(
                    fixture.write(Phase::BootActive, guid, &name, AUTH_ATTRIBUTES, data),
                    efi::Status::SECURITY_VIOLATION
                );
            }
        }
    }
    assert!(!fixture.store.setup_mode());
}

/// GUID of the private authenticated variables in tests/fixtures.
const PRIVATE_GUID: [u8; 16] = [
    0x5e, 0x7c, 0x7c, 0x2b, 0x0a, 0x0d, 0x8e, 0x4b, 0x9a, 0x59, 0x5c, 0xe0, 0xc3, 0xa0, 0xe7, 0xd1,
];

fn utf16(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

/// Timestamp of the tests/fixtures envelopes of `year`.
fn fixture_timestamp(year: u16) -> VariableTimestamp {
    VariableTimestamp {
        year,
        month: 2,
        day: 3,
        hour: 4,
        minute: 5,
        second: 6,
        ..VariableTimestamp::default()
    }
}

fn binding(store: &VariableStore, nonvolatile: bool, name: &[u16]) -> Option<Vec<u8>> {
    let db = store.find(
        &auth::cert_db::GUID,
        auth::cert_db::name(nonvolatile),
        false,
    )?;
    auth::cert_db::find(store.data(db)?, &PRIVATE_GUID, name).map(<[u8]>::to_vec)
}

fn value(store: &VariableStore, name: &[u16]) -> Option<Vec<u8>> {
    store
        .find(&PRIVATE_GUID, name, false)
        .and_then(|slot| store.data(slot))
        .map(<[u8]>::to_vec)
}

#[test]
fn private_variables_bind_to_the_signer_of_their_first_write() {
    let mut fixture = Fixture::retained();
    fixture.enroll();
    let name = utf16("CrabEfiPrivate");
    let append = AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    let mut write = |attributes, data: &[u8]| {
        fixture.write(Phase::BootActive, PRIVATE_GUID, &name, attributes, data)
    };
    // db-direct is in no key database; any signer creates the variable.
    for (attributes, data, expected) in [
        (
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin").as_slice(),
            efi::Status::SUCCESS,
        ),
        (
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-update-rogue.bin"),
            efi::Status::SECURITY_VIOLATION,
        ),
        (
            append,
            include_bytes!("../../../tests/fixtures/private-append-older.bin"),
            efi::Status::SUCCESS,
        ),
    ] {
        assert_eq!(write(attributes, data), expected);
    }
    let store = &fixture.store;
    assert_eq!(value(store, &name), Some(b"AC".to_vec()));
    assert_eq!(
        binding(store, true, &name).as_deref(),
        Some(include_bytes!("../../../tests/fixtures/private-binding.bin").as_slice())
    );
    // The older append does not lower the floor.
    assert_eq!(
        store.auth_history_timestamp(&PRIVATE_GUID, &name),
        Some(fixture_timestamp(2025))
    );

    let update = include_bytes!("../../../tests/fixtures/private-update.bin");
    let mut write = |attributes, data: &[u8]| {
        fixture.write(Phase::BootActive, PRIVATE_GUID, &name, attributes, data)
    };
    for (data, expected) in [
        (update.as_slice(), efi::Status::SUCCESS),
        (update, efi::Status::SECURITY_VIOLATION),
        (
            include_bytes!("../../../tests/fixtures/private-delete.bin"),
            efi::Status::SUCCESS,
        ),
    ] {
        assert_eq!(write(AUTH_ATTRIBUTES, data), expected);
    }
    assert_eq!(value(&fixture.store, &name), None);
    assert_eq!(binding(&fixture.store, true, &name), None);

    // Once deleted, another signer may create it again.
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-recreate-rogue.bin"),
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(value(&fixture.store, &name), Some(b"R".to_vec()));
    assert_eq!(
        binding(&fixture.store, true, &name).as_deref(),
        Some(include_bytes!("../../../tests/fixtures/rogue-binding.bin").as_slice())
    );
}

#[test]
fn private_variables_bind_the_signer_name_and_the_top_level_issuer() {
    let mut fixture = Fixture::retained();
    let name = utf16("CrabEfiPrivateChain");
    let mut write = |data: &[u8]| {
        fixture.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            data,
        )
    };
    for (data, expected) in [
        (
            include_bytes!("../../../tests/fixtures/chain-create.bin").as_slice(),
            efi::Status::SUCCESS,
        ),
        // Same issuer, other subject.
        (
            include_bytes!("../../../tests/fixtures/chain-update-sibling.bin"),
            efi::Status::SECURITY_VIOLATION,
        ),
        // Same signer without its issuer: the top level differs.
        (
            include_bytes!("../../../tests/fixtures/chain-update-leaf.bin"),
            efi::Status::SECURITY_VIOLATION,
        ),
        (
            include_bytes!("../../../tests/fixtures/chain-update.bin"),
            efi::Status::SUCCESS,
        ),
    ] {
        assert_eq!(write(data), expected);
    }
    assert_eq!(value(&fixture.store, &name), Some(b"B".to_vec()));
    assert_eq!(
        binding(&fixture.store, true, &name).as_deref(),
        Some(include_bytes!("../../../tests/fixtures/chain-binding.bin").as_slice())
    );
}

/// Requests, names and data a bridge persisted.
type Persisted = Vec<(BridgeRequest, Vec<u16>, Vec<u8>)>;

std::thread_local! {
    static PERSISTED: core::cell::RefCell<Persisted> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// A successful bridge that records what it persists.
extern "C" fn recording_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: same immediate-call contract as successful_bridge.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return efi::Status::INVALID_PARAMETER.as_usize();
    };
    if request.operation == bridge_operation::PERSIST_WRITE {
        // SAFETY: the runtime image passes live name and data buffers.
        let (name, data) = unsafe {
            (
                core::slice::from_raw_parts(
                    request.name_address as *const u16,
                    request.name_len as usize,
                ),
                core::slice::from_raw_parts(
                    request.data_address as *const u8,
                    request.data_len as usize,
                ),
            )
        };
        PERSISTED
            .with_borrow_mut(|persisted| persisted.push((*request, name.to_vec(), data.to_vec())));
    }
    successful_bridge(request)
}

#[test]
fn private_variable_bindings_persist_and_survive_a_reboot() {
    PERSISTED.with_borrow_mut(Vec::clear);
    let mut fixture = Fixture::retained();
    let (name, volatile) = (utf16("CrabEfiPrivate"), utf16("CrabEfiPrivateVolatile"));
    let bridge = recording_bridge as *const () as u64;
    for (name, attributes, data) in [
        (
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin").as_slice(),
        ),
        (
            &volatile,
            AUTH_ATTRIBUTES.difference(VariableAttributes::NON_VOLATILE),
            include_bytes!("../../../tests/fixtures/volatile-create.bin"),
        ),
    ] {
        assert_eq!(
            fixture.write_using_bridge(
                Phase::BootActive,
                PRIVATE_GUID,
                name,
                attributes,
                data,
                bridge
            ),
            efi::Status::SUCCESS
        );
    }
    // Volatile variables bind in the volatile database only.
    assert!(binding(&fixture.store, false, &volatile).is_some());
    assert_eq!(binding(&fixture.store, true, &volatile), None);

    // The binding reached storage before the variable, and only that one.
    let persisted = PERSISTED.take();
    let names: Vec<_> = persisted.iter().map(|(_, name, _)| name.clone()).collect();
    assert_eq!(names, [auth::cert_db::name(true).to_vec(), name.clone()]);

    let mut reboot = Fixture::new();
    for (request, name, data) in &persisted {
        reboot.import(
            request.guid,
            name,
            VariableAttributes::from_bits(request.attributes).unwrap(),
            data,
            (request.timestamp_valid != 0).then_some(request.timestamp),
        );
    }
    let mut write = |data: &[u8]| {
        reboot.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            data,
        )
    };
    assert_eq!(
        write(include_bytes!(
            "../../../tests/fixtures/private-update-rogue.bin"
        )),
        efi::Status::SECURITY_VIOLATION
    );
    assert_eq!(
        write(include_bytes!("../../../tests/fixtures/private-update.bin")),
        efi::Status::SUCCESS
    );
}

#[test]
fn runtime_private_variable_writes_rebuild_their_binding_on_replay() {
    let mut fixture = Fixture::retained();
    let name = utf16("CrabEfiPrivate");
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin"),
        ),
        efi::Status::SUCCESS
    );
    // The live store enforces the binding at once.
    assert!(binding(&fixture.store, true, &name).is_some());
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-update-rogue.bin"),
        ),
        efi::Status::SECURITY_VIOLATION
    );

    // Only the envelope is journalled; replay rebuilds the binding.
    let mut reboot = Fixture::new();
    let processed = replay_into(&mut fixture, &mut reboot, |record, authenticated, _| {
        assert!(authenticated);
        assert_eq!(record.guid.bytes, PRIVATE_GUID);
    });
    assert_eq!(processed, 1);
    assert_eq!(value(&reboot.store, &name), Some(b"A".to_vec()));
    assert_eq!(
        binding(&reboot.store, true, &name).as_deref(),
        Some(include_bytes!("../../../tests/fixtures/private-binding.bin").as_slice())
    );
}

/// Persists the signer database but fails every other write.
extern "C" fn binding_only_bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: same immediate-call contract as successful_bridge.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return efi::Status::INVALID_PARAMETER.as_usize();
    };
    // SAFETY: the runtime image passes its live name buffer.
    let name = unsafe {
        core::slice::from_raw_parts(
            request.name_address as *const u16,
            request.name_len as usize,
        )
    };
    if request.guid == auth::cert_db::GUID && name == auth::cert_db::name(true) {
        efi::Status::SUCCESS.as_usize()
    } else {
        efi::Status::DEVICE_ERROR.as_usize()
    }
}

/// The signer is bound before the variable is written; a creation that
/// then fails leaves no binding behind.
#[test]
fn a_failed_creation_drops_its_signer_binding() {
    let mut fixture = Fixture::retained();
    let name = utf16("CrabEfiPrivate");
    assert_eq!(
        fixture.write_using_bridge(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin"),
            binding_only_bridge as *const () as u64,
        ),
        efi::Status::DEVICE_ERROR
    );
    assert_eq!(value(&fixture.store, &name), None);
    assert_eq!(binding(&fixture.store, true, &name), None);
    // Any signer may still create it.
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-recreate-rogue.bin"),
        ),
        efi::Status::SUCCESS
    );
}

/// A reset after replay persisted an append but before it acknowledged
/// the record replays it again on the next boot. The append must not
/// apply twice, even with a timestamp that leaves the floor unchanged.
#[test]
fn an_unacknowledged_authenticated_append_applies_once() {
    let mut fixture = Fixture::retained();
    let name = utf16("CrabEfiPrivate");
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin"),
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            include_bytes!("../../../tests/fixtures/private-append-older.bin"),
        ),
        efi::Status::SUCCESS
    );
    let appended = value(&fixture.store, &name).unwrap();
    // The retained buffer as it was before replay acknowledged anything.
    let mut unacknowledged = Fixture::new();
    unacknowledged.buffer = fixture.buffer.clone();

    let mut reboot = Fixture::new();
    assert_eq!(
        reboot.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin"),
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(
        replay_into(&mut fixture, &mut reboot, |record, authenticated, _| {
            assert!(authenticated);
            assert_ne!(record.result_digest, 0);
        }),
        1
    );
    assert_eq!(value(&reboot.store, &name).as_ref(), Some(&appended));
    assert_eq!(
        replay_into(&mut unacknowledged, &mut reboot, |_, _, _| {}),
        1
    );
    assert_eq!(value(&reboot.store, &name), Some(appended));
}

#[test]
fn signer_databases_are_read_only() {
    let mut fixture = Fixture::retained();
    let name = utf16("CrabEfiPrivate");
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            PRIVATE_GUID,
            &name,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/private-create.bin"),
        ),
        efi::Status::SUCCESS
    );
    let mut envelope = unsigned_envelope(2099);
    envelope.extend_from_slice(&4u32.to_le_bytes());
    for nonvolatile in [true, false] {
        for (attributes, data) in [
            (RAW_ATTRIBUTES, &4u32.to_le_bytes()[..]),
            (AUTH_ATTRIBUTES, &envelope[..]),
            (VariableAttributes::empty(), &[][..]),
        ] {
            assert_eq!(
                fixture.write(
                    Phase::BootActive,
                    auth::cert_db::GUID,
                    auth::cert_db::name(nonvolatile),
                    attributes,
                    data
                ),
                efi::Status::WRITE_PROTECTED
            );
        }
    }
    assert!(binding(&fixture.store, true, &name).is_some());
}

/// A newer append that only repeats signatures dbx holds leaves its data
/// as it was but advances its timestamp. The data alone must not make
/// replay take it as applied.
#[test]
fn replay_applies_an_append_that_only_advances_the_timestamp() {
    let dbx = SecureBootVariable::Dbx;
    let append = AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    let stored = hash_list(&[1, 2]);
    let mut fixture = Fixture::retained();
    let mut reboot = Fixture::new();
    for target in [&mut fixture, &mut reboot] {
        target.import(
            *dbx.guid(),
            dbx.name(),
            AUTH_ATTRIBUTES,
            &stored,
            Some(timestamp(2025)),
        );
    }
    assert_eq!(
        fixture.apply(
            Phase::SealedPhysical,
            dbx,
            append,
            &dbx_envelope(2026, &[2])
        ),
        efi::Status::SUCCESS
    );
    assert_eq!(replay_into(&mut fixture, &mut reboot, |_, _, _| ()), 1);
    assert_eq!(reboot.store.key_database_data(dbx), Some(&stored[..]));
    assert_eq!(reboot.store.auth_timestamp(dbx), timestamp(2026));
}

#[test]
fn post_ebs_append_with_an_already_recorded_timestamp_is_not_dropped_on_replay() {
    let dbx = SecureBootVariable::Dbx;
    let append = AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    let stored = hash_list(&[1]);
    let mut fixture = Fixture::retained();
    let mut reboot = Fixture::new();
    // Both updates carry the timestamp dbx already has, as Microsoft's do.
    for target in [&mut fixture, &mut reboot] {
        target.import(
            *dbx.guid(),
            dbx.name(),
            AUTH_ATTRIBUTES | VariableAttributes::RUNTIME_ACCESS,
            &stored,
            Some(timestamp(2010)),
        );
    }
    assert_eq!(
        fixture.apply(
            Phase::SealedPhysical,
            dbx,
            append,
            &dbx_envelope(2010, &[2])
        ),
        efi::Status::SUCCESS
    );

    assert_eq!(replay_into(&mut fixture, &mut reboot, |_, _, _| ()), 1);
    let merged = [stored, hash_list(&[2])].concat();
    assert_eq!(reboot.store.key_database_data(dbx), Some(&merged[..]));
}

#[test]
fn deleted_authenticated_variables_keep_rollback_floors() {
    let mut fixture = Fixture::new();
    let guid = [0x42; 16];
    let name = [b'A' as u16, b'u' as u16, b't' as u16, b'h' as u16];

    // Boot import of the live variable followed by its persisted deletion
    // record (zero-length data, newer timestamp).
    fixture.import(
        guid,
        &name,
        AUTH_ATTRIBUTES,
        b"payload",
        Some(timestamp(2024)),
    );
    fixture.import(guid, &name, AUTH_ATTRIBUTES, &[], Some(timestamp(2025)));

    // The deletion is invisible as a variable but keeps its floor.
    assert!(fixture.store.find(&guid, &name, false).is_none());
    assert_eq!(
        fixture.store.auth_history_timestamp(&guid, &name),
        Some(timestamp(2025))
    );

    // Raw requests cannot re-create or delete the deleted variable.
    for attributes in [
        RAW_ATTRIBUTES,
        RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
    ] {
        assert_eq!(
            fixture.write(Phase::BootActive, guid, &name, attributes, b"raw"),
            efi::Status::WRITE_PROTECTED
        );
    }

    // A stale signed envelope is rejected by the timestamp floor before
    // signature verification even runs.
    assert!(matches!(
        auth::verify_authenticated_variable(
            &fixture.store,
            &name,
            &guid,
            AUTH_ATTRIBUTES.bits(),
            &unsigned_envelope(2024),
        ),
        Err(auth::AuthError::InvalidTimestamp)
    ));
    // A newer envelope passes the floor and fails on the empty signature
    // instead, proving the floor itself did not reject it.
    assert!(matches!(
        auth::verify_authenticated_variable(
            &fixture.store,
            &name,
            &guid,
            AUTH_ATTRIBUTES.bits(),
            &unsigned_envelope(2026),
        ),
        Err(auth::AuthError::InvalidHeader)
    ));

    // Re-creation reclaims the tombstone slot and records the new floor.
    fixture.import(
        guid,
        &name,
        AUTH_ATTRIBUTES,
        b"new payload",
        Some(timestamp(2026)),
    );
    let slot = fixture.store.find(&guid, &name, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(b"new payload".as_slice()));
    assert_eq!(
        fixture.store.auth_history_timestamp(&guid, &name),
        Some(timestamp(2026))
    );
}

#[test]
fn imported_secure_database_deletions_keep_authenticated_history() {
    let mut fixture = Fixture::new();
    let variable = SecureBootVariable::PK;
    let pk = include_bytes!("../../../tests/fixtures/pk.esl");

    fixture.import(
        *variable.guid(),
        variable.name(),
        AUTH_ATTRIBUTES,
        pk,
        Some(timestamp(2024)),
    );
    assert!(!fixture.store.setup_mode());

    fixture.import(
        *variable.guid(),
        variable.name(),
        AUTH_ATTRIBUTES,
        &[],
        Some(timestamp(2025)),
    );

    let store = &fixture.store;
    assert!(store.setup_mode());
    assert!(
        store
            .find(variable.guid(), variable.name(), false)
            .is_none()
    );
    assert_eq!(store.auth_timestamp(variable), timestamp(2025));
    assert_eq!(
        store.auth_history_timestamp(variable.guid(), variable.name()),
        Some(timestamp(2025))
    );

    // Setup Mode permits unsigned authenticated enrollment, but the
    // deletion history must still reject raw re-creation.
    assert_eq!(
        fixture.apply(Phase::BootActive, variable, RAW_ATTRIBUTES, pk),
        efi::Status::WRITE_PROTECTED
    );
    assert!(matches!(
        auth::verify_authenticated_variable(
            &fixture.store,
            variable.name(),
            variable.guid(),
            AUTH_ATTRIBUTES.bits(),
            &unsigned_envelope(2025),
        ),
        Err(auth::AuthError::InvalidTimestamp)
    ));
    assert!(
        auth::verify_authenticated_variable(
            &fixture.store,
            variable.name(),
            variable.guid(),
            AUTH_ATTRIBUTES.bits(),
            &unsigned_envelope(2026),
        )
        .is_ok()
    );
}

#[test]
fn setup_pk_delete_is_transactional_and_preserves_the_authentication_floor() {
    let mut fixture = Fixture::retained();
    fixture.enroll();
    let pk = include_bytes!("../../../tests/fixtures/pk.esl");
    let floor = timestamp(2030);
    fixture.import(
        *SecureBootVariable::PK.guid(),
        SecureBootVariable::PK.name(),
        AUTH_ATTRIBUTES,
        pk,
        Some(floor),
    );
    fixture.import(
        secure_boot::EFI_GLOBAL_VARIABLE_GUID,
        secure_boot::SECURE_BOOT_ENABLE_NAME,
        RAW_ATTRIBUTES,
        &[1],
        None,
    );
    assert!(fixture.store.secure_boot_enabled());

    // A normal unsigned User Mode deletion remains forbidden.
    assert_eq!(
        fixture.apply(
            Phase::BootActive,
            SecureBootVariable::PK,
            VariableAttributes::empty(),
            &[]
        ),
        efi::Status::SECURITY_VIOLATION
    );
    for (bridge, expected) in [
        (
            failing_setup_bridge as *const () as u64,
            efi::Status::WRITE_PROTECTED,
        ),
        (setup_bridge as *const () as u64, efi::Status::SUCCESS),
    ] {
        assert_eq!(
            fixture.write_using_bridge(
                Phase::BootActive,
                *SecureBootVariable::PK.guid(),
                SecureBootVariable::PK.name(),
                VariableAttributes::empty(),
                &[],
                bridge
            ),
            expected
        );
        if expected == efi::Status::SUCCESS {
            assert!(fixture.store.setup_mode());
            assert!(!fixture.store.secure_boot_enabled());
            assert_eq!(
                fixture.store.key_database_data(SecureBootVariable::PK),
                None
            );
        } else {
            assert!(!fixture.store.setup_mode());
            assert!(fixture.store.secure_boot_enabled());
            assert_eq!(
                fixture.store.key_database_data(SecureBootVariable::PK),
                Some(pk.as_slice())
            );
        }
        assert_eq!(
            fixture.store.auth_history_timestamp(
                SecureBootVariable::PK.guid(),
                SecureBootVariable::PK.name()
            ),
            Some(floor)
        );
    }
}

#[test]
fn setup_authorization_cannot_bypass_other_authentication_or_runtime_checks() {
    let mut fixture = Fixture::retained();
    fixture.enroll();
    let bridge = setup_bridge as *const () as u64;
    for variable in [
        SecureBootVariable::Kek,
        SecureBootVariable::Db,
        SecureBootVariable::Dbx,
    ] {
        assert_eq!(
            fixture.write_using_bridge(
                Phase::BootActive,
                *variable.guid(),
                variable.name(),
                VariableAttributes::empty(),
                &[],
                bridge
            ),
            efi::Status::SECURITY_VIOLATION
        );
    }
    for (phase, attributes, data) in [
        (Phase::Importing, VariableAttributes::empty(), &[][..]),
        (Phase::SealedPhysical, VariableAttributes::empty(), &[][..]),
        (Phase::Virtual, VariableAttributes::empty(), &[][..]),
        (Phase::BootActive, RAW_ATTRIBUTES, b"replacement".as_slice()),
        (
            Phase::BootActive,
            RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            &[][..],
        ),
    ] {
        assert_eq!(
            fixture.write_using_bridge(
                phase,
                *SecureBootVariable::PK.guid(),
                SecureBootVariable::PK.name(),
                attributes,
                data,
                bridge
            ),
            efi::Status::SECURITY_VIOLATION
        );
        assert!(!fixture.store.setup_mode());
    }
}

#[test]
fn secure_databases_require_their_attributes() {
    let mut fixture = Fixture::retained();
    let mut envelope = unsigned_envelope(2024);
    envelope.extend_from_slice(include_bytes!("../../../tests/fixtures/pk.esl"));
    let without = |attribute| AUTH_ATTRIBUTES.difference(attribute);
    for variable in [
        SecureBootVariable::PK,
        SecureBootVariable::Kek,
        SecureBootVariable::Db,
        SecureBootVariable::Dbx,
    ] {
        // Setup Mode skips signatures, not the attribute rule.
        for (attributes, data) in [
            (RAW_ATTRIBUTES, &envelope[16 + 24..]),
            (without(VariableAttributes::NON_VOLATILE), &envelope[..]),
            (without(VariableAttributes::RUNTIME_ACCESS), &envelope[..]),
            (
                AUTH_ATTRIBUTES | VariableAttributes::HARDWARE_ERROR_RECORD,
                &envelope[..],
            ),
        ] {
            assert_eq!(
                fixture.apply(Phase::BootActive, variable, attributes, data),
                efi::Status::INVALID_PARAMETER
            );
            assert_eq!(fixture.store.key_database_data(variable), None);
        }
    }
    fixture.enroll();

    // Appends and replacements of enrolled databases keep them too.
    let update = include_bytes!("../../../tests/fixtures/db-update.bin");
    for attributes in [
        without(VariableAttributes::RUNTIME_ACCESS) | VariableAttributes::APPEND_WRITE,
        without(VariableAttributes::NON_VOLATILE),
    ] {
        assert_eq!(
            fixture.apply(
                Phase::BootActive,
                SecureBootVariable::Db,
                attributes,
                update
            ),
            efi::Status::INVALID_PARAMETER
        );
    }
    assert_eq!(
        fixture.apply(
            Phase::BootActive,
            SecureBootVariable::Db,
            AUTH_ATTRIBUTES,
            update
        ),
        efi::Status::SUCCESS
    );
    let slot = fixture
        .store
        .find(
            SecureBootVariable::Db.guid(),
            SecureBootVariable::Db.name(),
            false,
        )
        .unwrap();
    assert_eq!(slot.attributes, AUTH_ATTRIBUTES);
}

#[test]
fn secure_boot_enable_needs_setup_mode_or_physical_presence() {
    let guid = secure_boot::EFI_GLOBAL_VARIABLE_GUID;
    let name = secure_boot::SECURE_BOOT_ENABLE_NAME;
    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(Phase::BootActive, guid, name, RAW_ATTRIBUTES, &[1]),
        efi::Status::SUCCESS
    );
    for phase in [Phase::SealedPhysical, Phase::Virtual] {
        assert_eq!(
            fixture.write(phase, guid, name, RAW_ATTRIBUTES, &[0]),
            efi::Status::WRITE_PROTECTED
        );
    }
    fixture.enroll();
    assert!(fixture.store.secure_boot_enabled());

    let envelope = unsigned_envelope(2099);
    for (attributes, data) in [
        (RAW_ATTRIBUTES, &[0][..]),
        (VariableAttributes::empty(), &[][..]),
        (AUTH_ATTRIBUTES, &envelope[..]),
    ] {
        assert_eq!(
            fixture.write(Phase::BootActive, guid, name, attributes, data),
            efi::Status::SECURITY_VIOLATION
        );
    }
    // The setup action authorizes its exact value, and only at boot.
    let bridge = secure_boot_enable_bridge as *const () as u64;
    assert_eq!(
        fixture.write_using_bridge(Phase::BootActive, guid, name, RAW_ATTRIBUTES, &[1], bridge),
        efi::Status::SECURITY_VIOLATION
    );
    for phase in [Phase::SealedPhysical, Phase::Virtual] {
        assert_eq!(
            fixture.write_using_bridge(phase, guid, name, RAW_ATTRIBUTES, &[0], bridge),
            efi::Status::WRITE_PROTECTED
        );
    }
    assert!(fixture.store.secure_boot_enabled());
    assert_eq!(
        fixture.write_using_bridge(Phase::BootActive, guid, name, RAW_ATTRIBUTES, &[0], bridge),
        efi::Status::SUCCESS
    );
    assert!(!fixture.store.secure_boot_enabled());
    assert!(!fixture.store.setup_mode());
}

#[test]
fn journalled_secure_boot_enable_is_consumed_unapplied() {
    let guid = secure_boot::EFI_GLOBAL_VARIABLE_GUID;
    let name = secure_boot::SECURE_BOOT_ENABLE_NAME;
    let mut fixture = Fixture::retained();
    DeferredRegion::new(&mut fixture.buffer)
        .queue_write(
            &mut fixture.deferred_transaction,
            deferred::DeferredWrite {
                guid,
                name,
                attributes: RAW_ATTRIBUTES,
                data: &[0],
                timestamp: VariableTimestamp::default(),
                authenticated: false,
                deletion: false,
                result_digest: 0,
            },
        )
        .unwrap();
    // Setup Mode would accept the same write at boot.
    let mut reboot = Fixture::new();
    reboot.import(guid, name, RAW_ATTRIBUTES, &[1], None);
    assert_eq!(replay_into(&mut fixture, &mut reboot, |_, _, _| ()), 1);
    let slot = reboot.store.find(&guid, name, false).unwrap();
    assert_eq!(reboot.store.data(slot), Some([1].as_slice()));
}

#[test]
fn enrolled_kek_cannot_delete_pk_or_advance_its_metadata() {
    macro_rules! guest_fixture {
        ($file:literal) => {
            include_bytes!(concat!(
                "../../../../test-apps/secure-boot-auth-test/fixtures/esp/sbtest/",
                $file
            ))
        };
    }
    let kek = guest_fixture!("kek.esl");
    let delete = guest_fixture!("b-pk-delete-signed-by-kek.auth");
    // Same envelope and timestamp in both runs. Only the signer's role
    // changes: acceptance as PK rules out rejection due to malformed CMS.
    for (pk, expected) in [
        (
            guest_fixture!("pk.esl").as_slice(),
            efi::Status::SECURITY_VIOLATION,
        ),
        (kek.as_slice(), efi::Status::SUCCESS),
    ] {
        let mut fixture = Fixture::retained();
        for (var, bytes) in [
            (SecureBootVariable::Kek, kek.as_slice()),
            (SecureBootVariable::PK, pk),
        ] {
            let mut envelope = unsigned_envelope(2024);
            envelope.extend_from_slice(bytes);
            assert_eq!(
                fixture.apply(Phase::BootActive, var, AUTH_ATTRIBUTES, &envelope),
                efi::Status::SUCCESS
            );
        }
        let snapshot = |f: &Fixture| {
            let keys = [SecureBootVariable::PK, SecureBootVariable::Kek].map(|v| {
                let slot = f.store.find(v.guid(), v.name(), false).unwrap();
                (
                    slot.attributes,
                    slot.timestamp,
                    f.store.auth_timestamp(v),
                    f.store.data(slot).unwrap().to_vec(),
                )
            });
            (
                keys,
                f.store.setup_mode(),
                f.store.secure_boot_enabled(),
                f.store.remaining_storage(),
                f.buffer.clone(),
            )
        };
        let before = snapshot(&fixture);
        assert_eq!(
            fixture.apply(
                Phase::Virtual,
                SecureBootVariable::PK,
                AUTH_ATTRIBUTES,
                delete
            ),
            expected
        );
        if expected == efi::Status::SECURITY_VIOLATION {
            assert_eq!(
                snapshot(&fixture),
                before,
                "rejection changed keys, replay floor, mode, or retained journal"
            );
        } else {
            assert!(fixture.store.setup_mode());
            let pk = SecureBootVariable::PK;
            let kek_var = SecureBootVariable::Kek;
            assert!(fixture.store.find(pk.guid(), pk.name(), false).is_none());
            let slot = fixture
                .store
                .find(kek_var.guid(), kek_var.name(), false)
                .unwrap();
            assert_eq!(fixture.store.data(slot).unwrap(), kek.as_slice());
        }
    }
}

#[test]
fn real_service_path_covers_all_secure_databases() {
    let mut fixture = Fixture::retained();
    fixture.enroll();

    assert_eq!(
        fixture.apply(
            Phase::BootActive,
            SecureBootVariable::Kek,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/unauthorized-update.bin"),
        ),
        efi::Status::SECURITY_VIOLATION
    );

    let operations = [
        (
            SecureBootVariable::Db,
            include_bytes!("../../../tests/fixtures/db-update.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/db-append.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/db-delete.bin").as_slice(),
        ),
        (
            SecureBootVariable::Dbx,
            include_bytes!("../../../tests/fixtures/dbx-update.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/dbx-append.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/dbx-delete.bin").as_slice(),
        ),
        (
            SecureBootVariable::Kek,
            include_bytes!("../../../tests/fixtures/kek-update.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/kek-append.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/kek-delete.bin").as_slice(),
        ),
        (
            SecureBootVariable::PK,
            include_bytes!("../../../tests/fixtures/pk-update.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/pk-append.bin").as_slice(),
            include_bytes!("../../../tests/fixtures/pk-delete.bin").as_slice(),
        ),
    ];
    let append_attributes = AUTH_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    for (variable, update, append, delete) in operations {
        for (attributes, data, expected) in [
            (AUTH_ATTRIBUTES, update, efi::Status::SUCCESS),
            (AUTH_ATTRIBUTES, update, efi::Status::SECURITY_VIOLATION),
            (append_attributes, append, efi::Status::SUCCESS),
        ] {
            assert_eq!(
                fixture.apply(Phase::BootActive, variable, attributes, data),
                expected
            );
        }
        assert!(validate_signature_database(
            fixture.store.key_database_data(variable).unwrap()
        ));
        for expected in [efi::Status::SUCCESS, efi::Status::SECURITY_VIOLATION] {
            assert_eq!(
                fixture.apply(Phase::BootActive, variable, AUTH_ATTRIBUTES, delete),
                expected
            );
        }
    }
    assert!(fixture.store.setup_mode());
    assert!(!fixture.store.secure_boot_enabled());
}

#[test]
fn replay_consumes_already_persisted_raw_delete_and_continues() {
    const GUID: [u8; 16] = [0x42; 16];
    let mut buffer = vec![0u8; 64 * 1024];
    let mut transaction = deferred::DeferredTransaction::new();
    DeferredRegion::new(&mut buffer).prepare_retained().unwrap();
    for (name, deletion) in [(&[b'D' as u16][..], true), (&[b'N' as u16][..], false)] {
        DeferredRegion::new(&mut buffer)
            .queue_write(
                &mut transaction,
                deferred::DeferredWrite {
                    guid: GUID,
                    name,
                    attributes: if deletion {
                        VariableAttributes::empty()
                    } else {
                        RAW_ATTRIBUTES
                    },
                    data: if deletion { &[] } else { b"next" },
                    timestamp: VariableTimestamp::default(),
                    authenticated: false,
                    deletion,
                    result_digest: 0,
                },
            )
            .unwrap();
    }

    let mut seen = 0usize;
    assert_eq!(
        DeferredRegion::new(&mut buffer).replay(|_, authenticated, deletion| {
            seen += 1;
            replay_apply_result(
                if deletion {
                    Err(efi::Status::NOT_FOUND)
                } else {
                    Ok(())
                },
                authenticated,
                deletion,
            )
        },),
        Ok(2)
    );
    assert_eq!(seen, 2);
    assert_eq!(
        DeferredRegion::new(&mut buffer)
            .replay(|_, _, _| panic!("acknowledged records replayed twice"),),
        Ok(0)
    );
    assert_eq!(
        replay_apply_result(Err(efi::Status::NOT_FOUND), true, true),
        Err(efi::Status::NOT_FOUND)
    );
}

/// Replay every retained record of `fixture` into `target` at boot,
/// passing each record to `inspect` first.
fn replay_into(
    fixture: &mut Fixture,
    target: &mut Fixture,
    inspect: impl Fn(&deferred::VariableRecord<'_>, bool, bool),
) -> usize {
    DeferredRegion::new(&mut fixture.buffer)
        .replay(|record, authenticated, deletion| {
            inspect(record, authenticated, deletion);
            replay_record(
                &mut target.store,
                &mut target.transaction,
                successful_bridge as *const () as u64,
                record,
                authenticated,
                deletion,
            )
        })
        .unwrap()
}

const TEST_GUID: [u8; 16] = [
    0x3a, 0x1d, 0x56, 0x0b, 0x2b, 0x8f, 0x4c, 0x47, 0x9f, 0x0e, 0x52, 0x7b, 0x9d, 0x04, 0xb2, 0x31,
];
const BOOT_ONLY: VariableAttributes =
    VariableAttributes::NON_VOLATILE.union(VariableAttributes::BOOTSERVICE_ACCESS);
const VOLATILE_RT: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);

#[test]
fn runtime_writes_cannot_change_boot_services_only_variables() {
    const NAME: &[u16] = &[b'B' as u16, b'o' as u16, b'o' as u16, b't' as u16];
    let append = RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE;

    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(Phase::BootActive, TEST_GUID, NAME, BOOT_ONLY, &[1]),
        efi::Status::SUCCESS
    );
    for phase in [Phase::SealedPhysical, Phase::Virtual] {
        for (attributes, data, status) in [
            (append, &[2][..], efi::Status::WRITE_PROTECTED),
            (RAW_ATTRIBUTES, &[2][..], efi::Status::WRITE_PROTECTED),
            (RAW_ATTRIBUTES, &[][..], efi::Status::WRITE_PROTECTED),
            (
                VariableAttributes::empty(),
                &[][..],
                efi::Status::WRITE_PROTECTED,
            ),
            (
                BOOT_ONLY | VariableAttributes::APPEND_WRITE,
                &[2][..],
                efi::Status::WRITE_PROTECTED,
            ),
            (BOOT_ONLY, &[2][..], efi::Status::WRITE_PROTECTED),
        ] {
            assert_eq!(
                fixture.write(phase, TEST_GUID, NAME, attributes, data),
                status,
                "{phase:?} {attributes:?} {data:?}"
            );
        }
    }
    let slot = fixture.store.find(&TEST_GUID, NAME, false).unwrap();
    assert_eq!(slot.attributes, BOOT_ONLY);
    assert_eq!(fixture.store.data(slot), Some(&[1][..]));
    assert_eq!(
        DeferredRegion::new(&mut fixture.buffer)
            .replay(|_, _, _| panic!("a rejected runtime write was journaled")),
        Ok(0)
    );
}

#[test]
fn the_external_boot_policy_cannot_be_created_at_runtime() {
    use crabefi_runtime_abi::settings::{EXTERNAL_BOOT_NAME, SETTINGS_GUID};
    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            SETTINGS_GUID,
            EXTERNAL_BOOT_NAME,
            RAW_ATTRIBUTES,
            &[2]
        ),
        efi::Status::WRITE_PROTECTED
    );
    assert!(
        fixture
            .store
            .find(&SETTINGS_GUID, EXTERNAL_BOOT_NAME, false)
            .is_none()
    );
    // Nor through a journal record.
    DeferredRegion::new(&mut fixture.buffer)
        .queue_write(
            &mut fixture.deferred_transaction,
            deferred::DeferredWrite {
                guid: SETTINGS_GUID,
                name: EXTERNAL_BOOT_NAME,
                attributes: RAW_ATTRIBUTES,
                data: &[2],
                timestamp: VariableTimestamp::default(),
                authenticated: false,
                deletion: false,
                result_digest: 0,
            },
        )
        .unwrap();
    let mut reboot = Fixture::new();
    assert_eq!(replay_into(&mut fixture, &mut reboot, |_, _, _| {}), 1);
    assert!(
        reboot
            .store
            .find(&SETTINGS_GUID, EXTERNAL_BOOT_NAME, false)
            .is_none()
    );
    // Boot-time code still writes it.
    assert_eq!(
        reboot.write(
            Phase::BootActive,
            SETTINGS_GUID,
            EXTERNAL_BOOT_NAME,
            VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
            &[2]
        ),
        efi::Status::SUCCESS
    );
}

/// The runtime guard on its own, for every stored and requested
/// attribute combination that matters.
#[test]
fn runtime_access_checks_the_stored_variable_and_the_request() {
    const NAME: &[u16] = &[b'G' as u16];
    let empty = VariableStore::new();
    let check = |store: &VariableStore, attributes: VariableAttributes, payload_empty: bool| {
        check_runtime_access(
            store,
            &VariableRequest {
                guid: TEST_GUID,
                name: NAME,
                attributes,
                data: &[],
            },
            payload_empty,
        )
    };
    let append = RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE;
    assert_eq!(check(&empty, RAW_ATTRIBUTES, false), Ok(()));
    assert_eq!(check(&empty, append, false), Ok(()));
    assert_eq!(
        check(&empty, VOLATILE_RT, false),
        Err(efi::Status::INVALID_PARAMETER)
    );
    assert_eq!(
        check(&empty, BOOT_ONLY, false),
        Err(efi::Status::INVALID_PARAMETER)
    );
    assert_eq!(
        check(&empty, VariableAttributes::empty(), true),
        Err(efi::Status::NOT_FOUND)
    );
    // With nothing stored, an empty request is a missing deletion or an
    // empty append, whatever its attributes.
    assert_eq!(
        check(&empty, VOLATILE_RT, true),
        Err(efi::Status::NOT_FOUND)
    );
    assert_eq!(
        check(&empty, VOLATILE_RT | VariableAttributes::APPEND_WRITE, true),
        Ok(())
    );
    for (stored, allowed) in [
        (RAW_ATTRIBUTES, true),
        (BOOT_ONLY, false),
        (VOLATILE_RT, false),
    ] {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        assert_eq!(
            store.import(&mut transaction, TEST_GUID, NAME, stored, &[1], None),
            Ok(())
        );
        let expected = if allowed {
            Ok(())
        } else {
            Err(efi::Status::WRITE_PROTECTED)
        };
        assert_eq!(check(&store, append, false), expected, "{stored:?}");
        // The stored variable decides before the request's attributes.
        assert_eq!(check(&store, stored, false), expected, "{stored:?}");
        assert_eq!(check(&store, RAW_ATTRIBUTES, true), expected, "{stored:?}");
        assert_eq!(
            check(&store, VariableAttributes::empty(), true),
            expected,
            "{stored:?}"
        );
    }
}

/// Without a runtime NV backend, writes to a stored boot-only or
/// volatile variable still answer WRITE_PROTECTED, not UNSUPPORTED.
#[test]
fn write_protection_wins_over_a_missing_backend() {
    const NAME: &[u16] = &[b'N' as u16, b'B' as u16];
    for stored in [BOOT_ONLY, VOLATILE_RT] {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        assert_eq!(
            store.import(&mut transaction, TEST_GUID, NAME, stored, &[1], None),
            Ok(())
        );
        let status = efi::status(apply_variable(
            VariableContext {
                phase: Phase::SealedPhysical,
                ..VariableContext::boot(&mut store, &mut transaction, 0)
            },
            VariableRequest {
                guid: TEST_GUID,
                name: NAME,
                attributes: RAW_ATTRIBUTES,
                data: &[2],
            },
        ));
        assert_eq!(status, efi::Status::WRITE_PROTECTED, "{stored:?}");
    }
}

#[test]
fn volatile_variables_are_read_only_at_runtime() {
    const NAME: &[u16] = &[b'V' as u16, b'o' as u16, b'l' as u16];
    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(Phase::BootActive, TEST_GUID, NAME, VOLATILE_RT, &[1]),
        efi::Status::SUCCESS
    );
    assert_eq!(
        fixture.write(Phase::SealedPhysical, TEST_GUID, NAME, VOLATILE_RT, &[2]),
        efi::Status::WRITE_PROTECTED
    );
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            TEST_GUID,
            NAME,
            VariableAttributes::empty(),
            &[]
        ),
        efi::Status::WRITE_PROTECTED
    );
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            TEST_GUID,
            &[b'N' as u16, b'e' as u16, b'w' as u16],
            VOLATILE_RT,
            &[1]
        ),
        efi::Status::INVALID_PARAMETER
    );
    let slot = fixture.store.find(&TEST_GUID, NAME, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(&[1][..]));
}

#[test]
fn appending_nothing_does_not_create_a_variable() {
    const NAME: &[u16] = &[
        b'E' as u16,
        b'm' as u16,
        b'p' as u16,
        b't' as u16,
        b'y' as u16,
    ];
    let mut fixture = Fixture::retained();
    for phase in [Phase::BootActive, Phase::SealedPhysical] {
        assert_eq!(
            fixture.write(
                phase,
                TEST_GUID,
                NAME,
                RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
                &[]
            ),
            efi::Status::SUCCESS
        );
        assert!(fixture.store.find(&TEST_GUID, NAME, false).is_none());
    }
}

/// A journal record the runtime would have refused, such as an append
/// to a boot-only variable queued by an older runtime, is consumed on
/// replay without changing anything, and later records still apply.
#[test]
fn replay_drops_records_the_runtime_would_refuse() {
    const BOOT_NAME: &[u16] = &[b'B' as u16, b'o' as u16, b'o' as u16, b't' as u16];
    const RT_NAME: &[u16] = &[b'R' as u16, b'T' as u16];

    let mut journal = Fixture::retained();
    const EMPTY_NAME: &[u16] = &[b'E' as u16];
    let records: [(&[u16], VariableAttributes, &[u8], bool); 5] = [
        // What an older runtime queued for an NV|BS|RT|APPEND request.
        (BOOT_NAME, BOOT_ONLY, &[1, 9], false),
        (BOOT_NAME, VariableAttributes::empty(), &[], true),
        // An older runtime's empty append to a missing variable, once for
        // a name that is still missing and once for one created since.
        (EMPTY_NAME, RAW_ATTRIBUTES, &[], false),
        (RT_NAME, RAW_ATTRIBUTES, &[], false),
        (
            RT_NAME,
            RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            &[7],
            false,
        ),
    ];
    for (name, attributes, data, deletion) in records {
        DeferredRegion::new(&mut journal.buffer)
            .queue_write(
                &mut journal.deferred_transaction,
                deferred::DeferredWrite {
                    guid: TEST_GUID,
                    name,
                    attributes,
                    data,
                    timestamp: VariableTimestamp::default(),
                    authenticated: false,
                    deletion,
                    result_digest: 0,
                },
            )
            .unwrap();
    }

    let mut reboot = Fixture::new();
    assert_eq!(
        reboot.write(Phase::BootActive, TEST_GUID, BOOT_NAME, BOOT_ONLY, &[1]),
        efi::Status::SUCCESS
    );
    assert_eq!(
        reboot.write(Phase::BootActive, TEST_GUID, RT_NAME, RAW_ATTRIBUTES, &[6]),
        efi::Status::SUCCESS
    );
    assert_eq!(replay_into(&mut journal, &mut reboot, |_, _, _| {}), 5);
    let slot = reboot.store.find(&TEST_GUID, BOOT_NAME, false).unwrap();
    assert_eq!(slot.attributes, BOOT_ONLY);
    assert_eq!(reboot.store.data(slot), Some(&[1][..]));
    assert!(reboot.store.find(&TEST_GUID, EMPTY_NAME, false).is_none());
    let slot = reboot.store.find(&TEST_GUID, RT_NAME, false).unwrap();
    assert_eq!(reboot.store.data(slot), Some(&[6, 7][..]));
}

#[test]
fn appends_must_keep_the_attributes_of_the_variable() {
    const GUID: [u8; 16] = [
        0x7e, 0x41, 0x0c, 0x93, 0x5d, 0x2a, 0x4b, 0x1f, 0x8c, 0x66, 0x30, 0xe1, 0x4a, 0x92, 0x0d,
        0x57,
    ];
    const NAME: &[u16] = &[b'L' as u16, b'o' as u16, b'g' as u16];

    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(Phase::BootActive, GUID, NAME, BOOT_ONLY, &[1]),
        efi::Status::SUCCESS
    );
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            GUID,
            NAME,
            RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            &[2]
        ),
        efi::Status::INVALID_PARAMETER
    );
    assert_eq!(
        fixture.write(
            Phase::BootActive,
            GUID,
            NAME,
            BOOT_ONLY | VariableAttributes::APPEND_WRITE,
            &[3]
        ),
        efi::Status::SUCCESS
    );
    let slot = fixture.store.find(&GUID, NAME, false).unwrap();
    assert_eq!(slot.attributes, BOOT_ONLY);
    assert_eq!(fixture.store.data(slot), Some(&[1, 3][..]));

    // Runtime-accessible variables still take runtime appends.
    const RT_NAME: &[u16] = &[b'R' as u16, b'T' as u16];
    assert_eq!(
        fixture.write(Phase::BootActive, GUID, RT_NAME, RAW_ATTRIBUTES, &[1]),
        efi::Status::SUCCESS
    );
    assert_eq!(
        fixture.write(
            Phase::SealedPhysical,
            GUID,
            RT_NAME,
            RAW_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
            &[2]
        ),
        efi::Status::SUCCESS
    );
    let slot = fixture.store.find(&GUID, RT_NAME, false).unwrap();
    assert_eq!(fixture.store.data(slot), Some(&[1, 2][..]));
}

#[test]
fn raw_post_ebs_write_replays_exact_bytes_once_through_service_logic() {
    const GUID: [u8; 16] = [
        0x11, 0x7c, 0x2c, 0xa5, 0xf4, 0x61, 0xb7, 0x4e, 0xa2, 0x19, 0x5a, 0x96, 0xb8, 0x0d, 0xa1,
        0x02,
    ];
    const NAME: &[u16] = &[
        b'R' as u16,
        b't' as u16,
        b'D' as u16,
        b'e' as u16,
        b'f' as u16,
        b'e' as u16,
        b'r' as u16,
        b'r' as u16,
        b'e' as u16,
        b'd' as u16,
    ];
    const VALUE: &[u8] = b"CrabRT";

    let mut fixture = Fixture::retained();
    assert_eq!(
        fixture.write(Phase::SealedPhysical, GUID, NAME, RAW_ATTRIBUTES, VALUE),
        efi::Status::SUCCESS
    );

    let mut reboot = Fixture::new();
    let processed = replay_into(
        &mut fixture,
        &mut reboot,
        |record, authenticated, deletion| {
            assert!(!authenticated);
            assert!(!deletion);
            assert_eq!(record.attributes, RAW_ATTRIBUTES.bits());
            assert_eq!(record.data, VALUE);
            let name_len = record.name.iter().position(|unit| *unit == 0).unwrap();
            assert_eq!(&record.name[..name_len], NAME);
        },
    );
    assert_eq!(processed, 1);
    let slot = reboot.store.find(&GUID, NAME, false).unwrap();
    assert_eq!(slot.attributes, RAW_ATTRIBUTES);
    assert_eq!(reboot.store.data(slot), Some(VALUE));
    assert_eq!(
        DeferredRegion::new(&mut fixture.buffer)
            .replay(|_, _, _| panic!("acknowledged raw record replayed twice"),),
        Ok(0)
    );
}

#[test]
fn authenticated_post_ebs_write_replays_once_through_service_logic() {
    let mut fixture = Fixture::retained();
    fixture.enroll();
    assert_eq!(
        fixture.apply(
            Phase::SealedPhysical,
            SecureBootVariable::Db,
            AUTH_ATTRIBUTES,
            include_bytes!("../../../tests/fixtures/db-update.bin"),
        ),
        efi::Status::SUCCESS
    );

    let mut reboot = Fixture::new();
    reboot.enroll();
    let processed = replay_into(&mut fixture, &mut reboot, |_, authenticated, _| {
        assert!(authenticated)
    });
    assert_eq!(processed, 1);
    assert_eq!(
        DeferredRegion::new(&mut fixture.buffer)
            .replay(|_, _, _| panic!("acknowledged record replayed twice"),),
        Ok(0)
    );
    assert_eq!(
        reboot.store.key_database_data(SecureBootVariable::Db),
        Some(fixture_payload(include_bytes!(
            "../../../tests/fixtures/db-update.bin"
        )))
    );
}
