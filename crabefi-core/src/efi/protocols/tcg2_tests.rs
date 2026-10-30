use super::*;
use crate::efi::tcg::event_log::Sha1EventLog;
use crate::efi::tcg::measured_boot::EV_S_CRTM_VERSION;
use crate::platform::TpmPcrBanks;
use alloc::{boxed::Box, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

struct MockTpm {
    extends: &'static AtomicUsize,
    fail: bool,
}

impl Tpm2Device for MockTpm {
    fn active_pcr_banks(&self) -> TpmPcrBanks {
        TpmPcrBanks::new(&[TPM_ALG_SHA256])
    }

    fn pcr_extend(&mut self, _: u32, _: &[TpmDigest<'_>]) -> Result<(), TpmError> {
        self.extends.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            Err(TpmError::DeviceError)
        } else {
            Ok(())
        }
    }

    fn submit_command(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, TpmError> {
        Err(TpmError::Unsupported)
    }
}

fn buffer(size: usize) -> &'static mut [u8] {
    Box::leak(vec![0xa5; size].into_boxed_slice())
}

fn prior_log() -> Vec<u8> {
    let mut log = CryptoAgileEventLog::new(buffer(1024), &[TPM_ALG_SHA256]).unwrap();
    log.log_event(
        0,
        EV_S_CRTM_VERSION,
        &[TaggedDigest::zeroed(TPM_ALG_SHA256)],
        b"fstart",
    )
    .unwrap();
    log.log_data().to_vec()
}

fn state_with_capacity(remaining: usize, fail: bool) -> (Tcg2State, &'static AtomicUsize) {
    let prior = prior_log();
    let extends = Box::leak(Box::new(AtomicUsize::new(0)));
    let state = Tcg2State {
        pcr_banks: PcrBanks::from_algorithms(&[TPM_ALG_SHA256]).unwrap(),
        event_log: CryptoAgileEventLog::from_existing(
            buffer(prior.len() + remaining),
            &prior,
            &[TPM_ALG_SHA256],
        )
        .unwrap(),
        hardware_tpm: Some(Tpm2Backend::Driver(Box::leak(Box::new(MockTpm {
            extends,
            fail,
        })))),
        get_event_log_called: false,
    };
    (state, extends)
}

#[test]
fn rejected_software_logs_leave_the_destination_unchanged() {
    let mut unsupported = prior_log();
    let algorithm_offset = core::mem::size_of::<TcgPcrEventHdr>() + 28;
    unsupported[algorithm_offset..algorithm_offset + 2]
        .copy_from_slice(&TPM_ALG_SM3_256.to_le_bytes());
    let mut malformed_tail = prior_log();
    malformed_tail.pop();
    for prior in [vec![0x5a; 80], unsupported, malformed_tail] {
        let area = buffer(1024);
        area[..prior.len()].copy_from_slice(&prior);
        let before = area.to_vec();
        let ptr = area.as_ptr();
        assert!(init_state(area, Some(&prior), false).is_err());
        // SAFETY: failed initialization did not retain the leaked allocation;
        // no code writes it while we check the entire destination.
        assert_eq!(unsafe { core::slice::from_raw_parts(ptr, 1024) }, before);
    }
}

#[test]
fn platform_driver_continues_the_original_area_in_place() {
    let prior = prior_log();
    let area = buffer(1024);
    area[..prior.len()].copy_from_slice(&prior);
    let ptr = area.as_ptr();
    let extends = Box::leak(Box::new(AtomicUsize::new(0)));
    let tpm = Box::leak(Box::new(MockTpm {
        extends,
        fail: false,
    }));
    init_state_with_platform_tpm(area, Some(&prior), tpm, false).unwrap();
    let mut guard = TCG2_STATE.lock();
    let state = guard.as_mut().unwrap();
    assert_eq!(state.event_log.log_data().as_ptr(), ptr);
    assert_eq!(state.event_log.log_data(), prior);
    assert_eq!(
        extend_and_maybe_log(
            state,
            7,
            EV_SEPARATOR,
            &[TaggedDigest::zeroed(TPM_ALG_SHA256)],
            b"CrabEFI",
            true
        ),
        Ok(())
    );
    assert_eq!(&state.event_log.log_data()[..prior.len()], prior);
    assert_eq!(extends.load(Ordering::Relaxed), 1);
    *guard = None;
}

#[test]
fn full_existing_logs_are_rejected() {
    let prior = prior_log();
    assert!(matches!(
        CryptoAgileEventLog::from_existing(buffer(prior.len()), &prior, &[TPM_ALG_SHA256]),
        Err(TcgError::LogFull)
    ));
    let mut sha1 = Sha1EventLog::new(buffer(128));
    sha1.log_event(
        0,
        EV_S_CRTM_VERSION,
        &[TaggedDigest::zeroed(TPM_ALG_SHA1)],
        b"fstart",
    )
    .unwrap();
    let prior = sha1.log_data();
    assert!(matches!(
        Sha1EventLog::from_existing(buffer(prior.len()), prior),
        Err(TcgError::LogFull)
    ));
}

#[test]
fn capacity_is_checked_before_hardware_extend_and_extend_only_still_works() {
    let digests = [
        TaggedDigest::zeroed(TPM_ALG_SHA256),
        TaggedDigest::zeroed(TPM_ALG_SHA1),
    ];
    let data = b"boot event";
    let event = CryptoAgileEvent {
        pcr_index: 7,
        event_type: EV_SEPARATOR,
        digests: &digests,
        event_data: data,
    };
    let (mut state, extends) = state_with_capacity(event.serialized_size() - 1, false);
    let prior = state.event_log.log_data().to_vec();
    assert_eq!(
        extend_and_maybe_log(&mut state, 7, EV_SEPARATOR, &digests, data, true),
        Err(TcgError::LogFull)
    );
    assert_eq!(extends.load(Ordering::Relaxed), 0);
    assert_eq!(
        state.pcr_banks.sha256().unwrap().read(7).unwrap(),
        &[0; SHA256_DIGEST_SIZE]
    );
    assert_eq!(state.event_log.log_data(), prior);
    assert!(state.event_log.is_truncated());
    assert_eq!(
        extend_and_maybe_log(&mut state, 7, EV_SEPARATOR, &digests, data, false),
        Ok(())
    );
    assert_eq!(extends.load(Ordering::Relaxed), 1);
    assert_eq!(state.event_log.log_data(), prior);
}

#[test]
fn exact_fit_appends_and_the_next_event_cannot_extend() {
    let digests = [TaggedDigest::zeroed(TPM_ALG_SHA256)];
    let data = b"boot event";
    let needed = CryptoAgileEvent {
        pcr_index: 7,
        event_type: EV_SEPARATOR,
        digests: &digests,
        event_data: data,
    }
    .serialized_size();
    let (mut state, extends) = state_with_capacity(needed, false);
    let prior = state.event_log.log_data().to_vec();
    assert_eq!(
        extend_and_maybe_log(&mut state, 7, EV_SEPARATOR, &digests, data, true),
        Ok(())
    );
    assert_eq!(&state.event_log.log_data()[..prior.len()], prior);
    assert_eq!(state.event_log.log_data().len(), state.event_log.capacity());
    assert_eq!(
        extend_and_maybe_log(&mut state, 7, EV_SEPARATOR, &digests, data, true),
        Err(TcgError::LogFull)
    );
    assert_eq!(extends.load(Ordering::Relaxed), 1);
}

#[test]
fn hardware_failure_does_not_append_an_event() {
    let (mut state, extends) = state_with_capacity(128, true);
    let prior = state.event_log.log_data().to_vec();
    assert_eq!(
        extend_and_maybe_log(
            &mut state,
            7,
            EV_SEPARATOR,
            &[TaggedDigest::zeroed(TPM_ALG_SHA256)],
            b"event",
            true
        ),
        Err(TcgError::InternalError)
    );
    assert_eq!(extends.load(Ordering::Relaxed), 1);
    assert_eq!(state.event_log.log_data(), prior);
    assert!(!state.event_log.is_truncated());
}

#[test]
fn sha1_preflight_accounts_for_the_header_and_preserves_bytes() {
    let digests = [TaggedDigest::zeroed(TPM_ALG_SHA1)];
    let mut log = Sha1EventLog::new(buffer(core::mem::size_of::<TcgPcrEventHdr>() + 3));
    assert_eq!(log.check_event(&digests, b"four"), Err(TcgError::LogFull));
    assert!(log.log_data().is_empty());
    assert_eq!(log.log_event(0, EV_SEPARATOR, &digests, b"fit"), Ok(()));
    assert_eq!(log.log_data().len(), log.capacity());
}
