//! The ring-0 side of the payload MM request protocol.

use crabefi_runtime_abi::mm::{
    DATA_OFFSET, NAME_OFFSET, Outcome, POLLS_PER_SMI, REQUEST_SIZE, Request, SMI_ATTEMPTS,
    STATUS_BUSY, STATUS_IDLE, STATUS_OFFSET, STATUS_PENDING, Transport, command, exchange,
};

/// A buffer with an MM that answers at a chosen SMI and poll.
struct FakeMm {
    buffer: Vec<u8>,
    smis: u32,
    polls: u32,
    /// Answer at this SMI, after this many polls (None: never).
    answer_at: Option<(u32, u32)>,
    /// Answer when the caller withdraws the request.
    answer_on_withdraw: bool,
    /// Claim the request when the caller withdraws it; answer on the next poll.
    claim_on_withdraw: bool,
    /// A claimed request never completes.
    never_finish: bool,
    /// Bytes written while the request was pending (must stay empty).
    written_while_pending: usize,
    /// Requests MM ran.
    ran: Vec<Request>,
}

impl FakeMm {
    fn new(answer_at: Option<(u32, u32)>) -> Self {
        Self {
            buffer: vec![0; DATA_OFFSET as usize + 64],
            smis: 0,
            polls: 0,
            answer_at,
            answer_on_withdraw: false,
            claim_on_withdraw: false,
            never_finish: false,
            written_while_pending: 0,
            ran: Vec::new(),
        }
    }

    fn status(&self) -> u64 {
        let at = STATUS_OFFSET as usize;
        u64::from_le_bytes(self.buffer[at..at + 8].try_into().unwrap())
    }

    fn set_status(&mut self, status: u64) {
        let at = STATUS_OFFSET as usize;
        self.buffer[at..at + 8].copy_from_slice(&status.to_le_bytes());
    }

    /// What MM does on an SMI: run a pending request and answer it.
    fn run(&mut self) {
        if self.status() != STATUS_PENDING {
            return;
        }
        let request = Request::from_bytes(self.buffer[..REQUEST_SIZE].try_into().unwrap());
        self.ran.push(request);
        self.set_status(0);
    }
}

impl Transport for FakeMm {
    fn write(&mut self, offset: u64, bytes: &[u8]) {
        if self.status() == STATUS_PENDING || self.status() == STATUS_BUSY {
            self.written_while_pending += bytes.len();
        }
        let at = offset as usize;
        self.buffer[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn read(&mut self, offset: u64, bytes: &mut [u8]) {
        let at = offset as usize;
        bytes.copy_from_slice(&self.buffer[at..at + bytes.len()]);
    }

    fn compare_exchange_status(&mut self, current: u64, new: u64) -> u64 {
        if self.answer_on_withdraw {
            self.run();
        }
        if self.claim_on_withdraw && self.status() == STATUS_PENDING {
            self.set_status(STATUS_BUSY);
        }
        let found = self.status();
        if found == current {
            self.set_status(new);
        }
        found
    }

    fn read_status(&mut self) -> u64 {
        self.status()
    }

    fn write_status(&mut self, status: u64) {
        self.set_status(status);
    }

    fn raise_smi(&mut self) {
        self.smis += 1;
        self.polls = 0;
    }

    fn pause(&mut self) {
        if self.status() == STATUS_BUSY && !self.never_finish {
            let request = Request::from_bytes(self.buffer[..REQUEST_SIZE].try_into().unwrap());
            self.ran.push(request);
            self.set_status(0);
            return;
        }
        self.polls += 1;
        if self.answer_at == Some((self.smis, self.polls)) {
            self.run();
        }
    }
}

fn request() -> Request {
    Request {
        magic: 0,
        version: 0,
        command: command::SET_VARIABLE,
        status: 0,
        guid: [7; 16],
        attributes: 7,
        name_size: 4,
        data_size: 3,
        maximum_storage: 0,
        remaining_storage: 0,
        maximum_variable: 0,
        offset: 0,
    }
}

#[test]
fn request_layout_matches_the_structure() {
    let mut request = request();
    request.status = 0x1122_3344_5566_7788;
    request.offset = 0xdead_beef;
    assert_eq!(
        Request::from_bytes(&request.to_bytes()).to_bytes(),
        request.to_bytes()
    );
    assert_eq!(&request.to_bytes()[16..24], &request.status.to_le_bytes());
}

#[test]
fn a_late_answer_is_taken_and_the_request_is_complete_before_it_is_pending() {
    let mut mm = FakeMm::new(Some((2, 3)));
    match exchange(&mut mm, request(), &[b'A' as u16, 0], b"xyz") {
        Outcome::Answered { reply, smis, polls } => {
            assert_eq!(reply.status, 0);
            assert_eq!((smis, polls), (2, 3));
        }
        Outcome::Lost => panic!("answered request reported lost"),
    }
    assert_eq!(mm.written_while_pending, 0);
    assert_eq!(mm.ran.len(), 1);
    assert_eq!(mm.ran[0].guid, [7; 16]);
    let name = NAME_OFFSET as usize;
    assert_eq!(&mm.buffer[name..name + 4], &[b'A', 0, 0, 0]);
    let data = DATA_OFFSET as usize;
    assert_eq!(&mm.buffer[data..data + 3], b"xyz");
}

#[test]
fn an_unanswered_request_is_withdrawn() {
    let mut mm = FakeMm::new(None);
    assert!(matches!(
        exchange(&mut mm, request(), &[0], &[]),
        Outcome::Lost
    ));
    assert_eq!(mm.smis, SMI_ATTEMPTS);
    assert_eq!(mm.status(), STATUS_IDLE);
    // A late SMI now finds nothing to run.
    mm.run();
    assert!(mm.ran.is_empty());
}

#[test]
fn an_answer_racing_the_withdrawal_is_kept() {
    let mut mm = FakeMm::new(None);
    mm.answer_on_withdraw = true;
    assert!(matches!(
        exchange(&mut mm, request(), &[0], &[]),
        Outcome::Answered {
            polls: POLLS_PER_SMI,
            ..
        }
    ));
    assert_eq!(mm.ran.len(), 1);
}

#[test]
fn a_stale_pending_request_never_runs_with_new_data() {
    let mut mm = FakeMm::new(Some((1, 1)));
    // An earlier caller left a pending header behind.
    mm.set_status(STATUS_PENDING);
    let _ = exchange(&mut mm, request(), &[0], b"new");
    assert_eq!(mm.written_while_pending, 0);
    assert_eq!(mm.ran.len(), 1);
}

#[test]
fn a_claimed_request_is_waited_for_not_withdrawn() {
    let mut mm = FakeMm::new(None);
    // MM claims the request as the caller gives up, and answers later.
    mm.claim_on_withdraw = true;
    assert!(matches!(
        exchange(&mut mm, request(), &[0], &[]),
        Outcome::Answered { .. }
    ));
    assert_eq!(mm.ran.len(), 1);
}

#[test]
fn a_buffer_mm_still_holds_is_not_reused() {
    let mut mm = FakeMm::new(Some((1, 1)));
    mm.set_status(STATUS_BUSY);
    mm.never_finish = true;
    assert!(matches!(
        exchange(&mut mm, request(), &[0], b"new"),
        Outcome::Lost
    ));
    assert_eq!(mm.written_while_pending, 0);
    assert_eq!(
        &mm.buffer[DATA_OFFSET as usize..DATA_OFFSET as usize + 3],
        &[0, 0, 0]
    );
}
