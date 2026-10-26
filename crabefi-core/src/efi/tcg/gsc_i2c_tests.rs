use super::*;
use crate::efi::tcg::Tpm2;
use crate::peripheral::InterruptLatch;
use crate::platform::{Tpm2Device, TpmDigest};
use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use embedded_hal::i2c::{ErrorKind, ErrorType, Operation};

/// Register-level model of a GSC answering canned TPM 2.0 responses.
#[derive(Default)]
struct Gsc {
    access: u8,
    register: u8,
    command: Vec<u8>,
    response: VecDeque<u8>,
    commands: Vec<Vec<u8>>,
    burst_limit: Option<usize>,
}

fn reply(code: u32) -> Vec<u8> {
    let (rc, body): (u32, Vec<u8>) = match code {
        // TPM_RC_INITIALIZE: already started by coreboot.
        0x144 => (0x100, vec![]),
        // GetCapability(PCRS): SHA-256 with all PCRs selected.
        0x17a => (
            0,
            vec![0, 0, 0, 0, 5, 0, 0, 0, 1, 0x00, 0x0b, 3, 0xff, 0xff, 0xff],
        ),
        // A vendor command answering with a multi-burst response.
        0x2000_0000 => (0, (0..90).collect()),
        _ => (0, vec![]),
    };
    let size = 10 + body.len() as u32;
    [
        &0x8001u16.to_be_bytes()[..],
        &size.to_be_bytes(),
        &rc.to_be_bytes(),
        &body,
    ]
    .concat()
}

impl Gsc {
    fn expected(&self) -> Option<usize> {
        let size = self.command.get(2..6)?;
        Some(u32::from_be_bytes(size.try_into().unwrap()) as usize)
    }

    fn status(&self) -> [u8; 4] {
        let mut status = STS_VALID;
        let burst = if self.response.is_empty() {
            MAX_BURST
        } else {
            status |= STS_DATA_AVAIL;
            self.response.len().min(MAX_BURST)
        };
        if self.command.is_empty() && self.response.is_empty() {
            status |= STS_COMMAND_READY;
        }
        if self
            .expected()
            .is_some_and(|size| self.command.len() < size)
        {
            status |= STS_EXPECT;
        }
        let burst = (burst.min(self.burst_limit.unwrap_or(MAX_BURST)) as u16).to_le_bytes();
        [status, burst[0], burst[1], 0]
    }

    fn write(&mut self, register: u8, data: &[u8]) {
        match register {
            ACCESS if data[0] & ACCESS_REQUEST_USE != 0 => {
                self.access = ACCESS_VALID | ACCESS_ACTIVE_LOCALITY
            }
            STS if data[0] & STS_COMMAND_READY != 0 => {
                self.command.clear();
                self.response.clear();
            }
            STS if data[0] & STS_GO != 0 => {
                let code = u32::from_be_bytes(self.command[6..10].try_into().unwrap());
                self.response = reply(code).into();
                self.commands.push(core::mem::take(&mut self.command));
            }
            DATA_FIFO => self.command.extend_from_slice(data),
            _ => panic!("unexpected write to {register:#x}"),
        }
    }

    fn read(&mut self, buffer: &mut [u8]) {
        match self.register {
            DID_VID => buffer.copy_from_slice(&0x0028_1ae0u32.to_le_bytes()),
            ACCESS => buffer[0] = ACCESS_VALID | self.access,
            STS => buffer.copy_from_slice(&self.status()),
            DATA_FIFO => buffer
                .iter_mut()
                .for_each(|byte| *byte = self.response.pop_front().unwrap_or(0xff)),
            register => panic!("unexpected read of {register:#x}"),
        }
    }
}

struct Bus(Box<Gsc>);

impl ErrorType for Bus {
    type Error = ErrorKind;
}

impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), ErrorKind> {
        assert_eq!(address, 0x50);
        match operations {
            [Operation::Write([register])] => self.0.register = *register,
            [Operation::Write([register, data @ ..])] => {
                assert!(data.len() <= MAX_BURST, "transfer exceeds the burst");
                self.0.write(*register, data)
            }
            [Operation::Read(buffer)] => self.0.read(buffer),
            _ => panic!("GSC transfers are single messages"),
        }
        Ok(())
    }
}

/// Ready after every transfer, so tests need no fixed delays.
struct AlwaysReady;

impl InterruptLatch for AlwaysReady {
    fn take(&mut self) -> bool {
        true
    }
}

fn tpm() -> Tpm2<GscI2c<Bus>> {
    let bus = Bus(Box::default());
    let ready = Some(Interrupt::Latched(Box::new(AlwaysReady)));
    Tpm2::new(GscI2c::open(bus, 0x50, ready).unwrap()).unwrap()
}

#[test]
fn initializes_and_extends_with_commands_larger_than_a_burst() {
    let mut tpm = tpm();
    assert_eq!(tpm.active_algorithms(), &[0x000b]);
    let digest = [0x5a; 32];
    Tpm2Device::pcr_extend(
        &mut tpm,
        7,
        &[TpmDigest {
            algorithm: 0x000b,
            digest: &digest,
        }],
    )
    .unwrap();
    let extend = tpm.transport().bus.0.commands.last().unwrap().clone();
    assert!(extend.len() > MAX_BURST);
    assert_eq!(&extend[6..14], &[0, 0, 1, 0x82, 0, 0, 0, 7]);
    assert!(extend.ends_with(&digest));
}

#[test]
fn a_burst_with_no_payload_room_fails_instead_of_looping() {
    let bus = Bus(Box::new(Gsc {
        burst_limit: Some(1),
        ..Gsc::default()
    }));
    let ready = Some(Interrupt::Latched(Box::new(AlwaysReady)));
    let mut transport = GscI2c::open(bus, 0x50, ready).unwrap();
    let command = [0x80, 0x01, 0, 0, 0, 10, 0x20, 0, 0, 0];
    assert_eq!(
        transport.send_command(&command, &mut [0; 128]),
        Err(TcgError::InternalError)
    );
    assert!(transport.bus.0.command.is_empty());
}

#[test]
fn reads_responses_larger_than_a_burst() {
    let mut tpm = tpm();
    let command = [0x80, 0x01, 0, 0, 0, 10, 0x20, 0, 0, 0];
    let mut response = [0; 128];
    let length = tpm.send_command(&command, &mut response).unwrap();
    assert_eq!(length, 100);
    assert!(response[10..100].iter().copied().eq(0..90));
}
