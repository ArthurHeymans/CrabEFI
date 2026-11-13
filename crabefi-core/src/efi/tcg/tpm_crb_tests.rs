use super::*;
use alloc::{boxed::Box, vec::Vec};
use std::thread;

const BUFFER: usize = 0x1000;
const RESPONSE: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0, 0, 0xab, 0xcd];
const COMMAND: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7a, 1, 2];

/// A CRB register page with separate command and response buffers.
struct Crb {
    regs: Box<[u32; 0x400]>,
    command: Box<[u8; BUFFER]>,
    response: Box<[u8; BUFFER]>,
}

impl Crb {
    fn new() -> Self {
        let mut crb = Self {
            regs: Box::new([0; 0x400]),
            command: Box::new([0; BUFFER]),
            response: Box::new([0; BUFFER]),
        };
        let command = crb.command.as_ptr() as u64;
        let response = crb.response.as_ptr() as u64;
        crb.set(CTRL_CMD_SIZE, BUFFER as u32);
        crb.set(CTRL_CMD_LADDR, command as u32);
        crb.set(CTRL_CMD_HADDR, (command >> 32) as u32);
        crb.set(CTRL_RSP_SIZE, BUFFER as u32);
        crb.set(CTRL_RSP_ADDR, response as u32);
        crb.set(CTRL_RSP_ADDR + 4, (response >> 32) as u32);
        crb
    }

    fn set(&mut self, offset: u64, value: u32) {
        self.regs[offset as usize / 4] = value;
    }

    fn get(&self, offset: u64) -> u32 {
        // SAFETY: in bounds; the fake TPM thread may have written it.
        unsafe { core::ptr::read_volatile(&self.regs[offset as usize / 4]) }
    }

    fn control_area(&self) -> u64 {
        self.regs.as_ptr() as u64 + CONTROL_AREA
    }

    /// Answer the next start like an AMD fTPM: write the response, report
    /// its length in RSP_SIZE, set CTRL_STS and clear START. Acknowledges a
    /// cmdReady request before. Returns the command it ran.
    fn answer(&self, status: u32) -> thread::JoinHandle<Vec<u8>> {
        let regs = self.regs.as_ptr() as usize;
        let (command, response) = (
            self.command.as_ptr() as usize,
            self.response.as_ptr() as usize,
        );
        thread::spawn(move || {
            let reg = |offset: u64| (regs + offset as usize) as *mut u32;
            // SAFETY: the test keeps the page and buffers alive until joined.
            unsafe {
                while core::ptr::read_volatile(reg(CTRL_START)) == 0 {
                    if core::ptr::read_volatile(reg(CTRL_REQ)) == CTRL_REQ_CMD_READY {
                        core::ptr::write_volatile(reg(CTRL_REQ), 0);
                    }
                    core::hint::spin_loop();
                }
                let ran = core::slice::from_raw_parts(command as *const u8, COMMAND.len()).to_vec();
                core::ptr::copy_nonoverlapping(
                    RESPONSE.as_ptr(),
                    response as *mut u8,
                    RESPONSE.len(),
                );
                core::ptr::write_volatile(reg(CTRL_RSP_SIZE), RESPONSE.len() as u32);
                core::ptr::write_volatile(reg(CTRL_STS), status);
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                core::ptr::write_volatile(reg(CTRL_START), 0);
                ran
            }
        })
    }
}

#[test]
fn acpi_start_rings_the_doorbell_and_restores_the_response_size() {
    let crb = Crb::new();
    let mut transport = unsafe { CrbMmio::open(crb.control_area(), CrbStart::Acpi) }.unwrap();
    let tpm = crb.answer(0);
    let mut response = [0; 64];
    assert_eq!(
        transport.send_command(&COMMAND, &mut response),
        Ok(RESPONSE.len())
    );
    assert_eq!(tpm.join().unwrap(), COMMAND);
    assert_eq!(response[..RESPONSE.len()], RESPONSE);
    // The OS reads the buffer size back; nothing else may be touched.
    assert_eq!(crb.get(CTRL_RSP_SIZE), BUFFER as u32);
    assert_eq!((crb.get(LOC_CTRL), crb.get(CTRL_REQ)), (0, 0));
}

#[test]
fn error_status_fails_the_command() {
    let crb = Crb::new();
    let mut transport = unsafe { CrbMmio::open(crb.control_area(), CrbStart::Acpi) }.unwrap();
    let tpm = crb.answer(CTRL_STS_ERROR);
    assert!(transport.send_command(&COMMAND, &mut [0; 64]).is_err());
    tpm.join().unwrap();
}

#[test]
fn crb_start_idles_the_tpm_after_the_command() {
    let mut crb = Crb::new();
    // Granting locality 0 is the TPM's job; this one has it granted already.
    crb.set(LOC_STATE, LOC_STATE_REG_VALID | LOC_STATE_ASSIGNED);
    let mut transport = unsafe { CrbMmio::open(crb.control_area(), CrbStart::Crb) }.unwrap();
    let tpm = crb.answer(0);
    let mut response = [0; 64];
    assert_eq!(
        transport.send_command(&COMMAND, &mut response),
        Ok(RESPONSE.len())
    );
    tpm.join().unwrap();
    assert_eq!(crb.get(CTRL_REQ), CTRL_REQ_GO_IDLE);
}

#[test]
fn missing_buffers_are_not_a_tpm() {
    let mut crb = Crb::new();
    crb.set(CTRL_CMD_SIZE, 0);
    assert!(unsafe { CrbMmio::open(crb.control_area(), CrbStart::Acpi) }.is_err());
}

#[test]
fn response_larger_than_the_caller_buffer_is_rejected() {
    let crb = Crb::new();
    let mut transport = unsafe { CrbMmio::open(crb.control_area(), CrbStart::Acpi) }.unwrap();
    let tpm = crb.answer(0);
    assert_eq!(
        transport.send_command(&COMMAND, &mut [0; 11]),
        Err(TcgError::EventTooLarge)
    );
    tpm.join().unwrap();
}
