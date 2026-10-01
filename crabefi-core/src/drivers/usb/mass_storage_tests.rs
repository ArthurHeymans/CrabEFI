use super::*;
use alloc::vec::Vec;

/// Scripted BOT peer: records CDBs and payloads, with configurable protection
/// discovery, cache support and a DATA PROTECT check condition.
struct BotPeer {
    command: Option<CommandBlockWrapper>,
    data_pending: bool,
    mode6: Option<bool>,
    mode10: Option<bool>,
    cache_supported: bool,
    cache_timeouts: usize,
    resets: usize,
    fail_reset: bool,
    protect_write: bool,
    short_write: bool,
    commands: Vec<[u8; 16]>,
    payloads: Vec<Vec<u8>>,
}

impl Default for BotPeer {
    fn default() -> Self {
        Self {
            command: None,
            data_pending: false,
            mode6: Some(false),
            mode10: Some(false),
            cache_supported: true,
            cache_timeouts: 0,
            resets: 0,
            fail_reset: false,
            protect_write: false,
            short_write: false,
            commands: Vec::new(),
            payloads: Vec::new(),
        }
    }
}

impl UsbController for BotPeer {
    fn controller_type(&self) -> &'static str {
        "BOT test peer"
    }
    fn max_bulk_transfer_size(&self) -> usize {
        2048
    }
    fn control_transfer(
        &mut self,
        _: u8,
        _: u8,
        request: u8,
        _: u16,
        _: u16,
        _: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        if request == 0xff {
            if self.fail_reset {
                return Err(UsbError::DeviceNotFound);
            }
            self.resets += 1;
            self.command = None;
            self.data_pending = false;
        }
        Ok(0)
    }
    fn create_interrupt_queue(
        &mut self,
        _: u8,
        _: u8,
        _: bool,
        _: u16,
        _: u8,
    ) -> Result<u32, UsbError> {
        Err(UsbError::NotSupported)
    }
    fn poll_interrupt_queue(&mut self, _: u32, _: &mut [u8]) -> Option<usize> {
        None
    }
    fn destroy_interrupt_queue(&mut self, _: u32) {}
    fn bulk_transfer(
        &mut self,
        _: u8,
        _: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        let Some(command) = self.command else {
            assert!(!is_in);
            let command = CommandBlockWrapper::read_from_bytes(data).unwrap();
            self.commands.push(command.cb);
            self.data_pending = command.data_transfer_length != 0;
            self.command = Some(command);
            return Ok(data.len());
        };
        let opcode = command.cb[0];
        if self.data_pending {
            self.data_pending = false;
            if is_in {
                data.fill(0);
                match opcode {
                    scsi_cmd::READ_CAPACITY_10 => {
                        data[..4].copy_from_slice(&1023u32.to_be_bytes());
                        data[4..].copy_from_slice(&512u32.to_be_bytes());
                    }
                    scsi_cmd::MODE_SENSE_6 => {
                        data[0] = 3;
                        data[2] = if self.mode6 == Some(true) { 0x80 } else { 0 };
                    }
                    scsi_cmd::MODE_SENSE_10 => {
                        data[1] = 6;
                        data[3] = if self.mode10 == Some(true) { 0x80 } else { 0 };
                    }
                    scsi_cmd::REQUEST_SENSE => {
                        data[0] = 0x70;
                        data[2] = if self.protect_write { 7 } else { 5 };
                    }
                    _ => {}
                }
            } else {
                assert!(data.len() <= self.max_bulk_transfer_size());
                self.payloads.push(data.to_vec());
                if self.short_write {
                    return Ok(data.len() / 2);
                }
            }
            return Ok(data.len());
        }
        assert!(is_in);
        assert_eq!(data.len(), 13);
        if opcode == scsi_cmd::SYNCHRONIZE_CACHE_10 && self.cache_timeouts > 0 {
            self.cache_timeouts -= 1;
            return Err(UsbError::Timeout);
        }
        data[..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        data[4..8].copy_from_slice(&command.tag.to_le_bytes());
        data[8..12].fill(0);
        let failed = match opcode {
            scsi_cmd::MODE_SENSE_6 => self.mode6.is_none(),
            scsi_cmd::MODE_SENSE_10 => self.mode10.is_none(),
            scsi_cmd::SYNCHRONIZE_CACHE_10 => !self.cache_supported,
            scsi_cmd::WRITE_10 | scsi_cmd::WRITE_16 => self.protect_write,
            _ => false,
        };
        data[12] = if failed {
            csw_status::FAILED
        } else {
            csw_status::PASSED
        };
        self.command = None;
        Ok(data.len())
    }
}

fn device() -> UsbMassStorage {
    UsbMassStorage {
        device_addr: 1,
        bulk_in: 1,
        bulk_out: 2,
        max_packet: 512,
        interface_number: 0,
        lun: 0,
        tag: 1,
        num_blocks: 0,
        block_size: 512,
        // Cache-command tests exercise the writable/probing path. init()
        // independently discovers protection before enabling actual writes.
        read_only: false,
        writes_pending: false,
        write_buffer: Vec::new(),
        vendor: [0; 8],
        product: [0; 16],
    }
}

#[test]
fn protection_discovery_and_cache_support_gate_writes() {
    for (mode6, mode10, cache_supported, read_only) in [
        (Some(false), Some(false), true, false),
        (Some(true), Some(false), true, true),
        (None, Some(false), true, false),
        (None, Some(true), true, true),
        (None, None, true, true),
        (Some(false), Some(false), false, true),
    ] {
        let mut peer = BotPeer {
            mode6,
            mode10,
            cache_supported,
            ..Default::default()
        };
        let mut disk = device();
        disk.init(&mut peer).unwrap();
        assert_eq!(disk.read_only, read_only);
        if read_only {
            assert!(matches!(
                disk.write_sectors_generic(&mut peer, 0, 1, &[0; 512]),
                Err(MassStorageError::WriteProtected)
            ));
            assert!(peer.payloads.is_empty());
        }
    }
}

#[test]
fn clean_read_only_devices_do_not_require_cache_commands() {
    let mut peer = BotPeer {
        cache_supported: false,
        ..Default::default()
    };
    let mut disk = device();
    disk.init(&mut peer).unwrap();
    assert!(disk.read_only);
    let commands = peer.commands.len();
    disk.synchronize_cache(&mut peer).unwrap();
    assert_eq!(peer.commands.len(), commands);
}

#[test]
fn writes_obey_controller_limits_and_reuse_the_bounce_buffer() {
    let mut peer = BotPeer::default();
    let mut disk = device();
    disk.init(&mut peer).unwrap();
    let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    disk.write_sectors_generic(&mut peer, 20, 16, &data)
        .unwrap();
    assert_eq!(peer.payloads.concat(), data);
    let writes: Vec<_> = peer
        .commands
        .iter()
        .filter(|c| c[0] == scsi_cmd::WRITE_10)
        .collect();
    assert_eq!(writes.len(), 4);
    for (index, command) in writes.iter().enumerate() {
        assert_eq!(
            u32::from_be_bytes(command[2..6].try_into().unwrap()),
            20 + index as u32 * 4
        );
        assert_eq!(u16::from_be_bytes(command[7..9].try_into().unwrap()), 4);
    }
    let buffer = disk.write_buffer.as_ptr();
    disk.write_sectors_generic(&mut peer, 20, 16, &data)
        .unwrap();
    assert_eq!(disk.write_buffer.as_ptr(), buffer);
    let count = peer.commands.len();
    assert!(matches!(
        disk.write_sectors_generic(&mut peer, 1023, 2, &[0; 1024]),
        Err(MassStorageError::InvalidParameter)
    ));
    assert_eq!(peer.commands.len(), count);
    disk.synchronize_cache(&mut peer).unwrap();
    assert_eq!(
        peer.commands.last().unwrap()[0],
        scsi_cmd::SYNCHRONIZE_CACHE_10
    );
}

#[test]
fn data_protect_stops_retries_and_updates_media_protection() {
    let mut peer = BotPeer::default();
    let mut disk = device();
    disk.init(&mut peer).unwrap();
    peer.protect_write = true;
    assert!(matches!(
        disk.write_sectors_generic(&mut peer, 0, 1, &[0; 512]),
        Err(MassStorageError::WriteProtected)
    ));
    assert!(disk.read_only);
    assert!(disk.writes_pending);
    assert_eq!(peer.payloads.len(), 1);
    assert_eq!(peer.commands.last().unwrap()[0], scsi_cmd::REQUEST_SENSE);
    // A protection transition must not hide previously accepted or uncertain
    // writes. A failed flush keeps this obligation for the next wrapper/call.
    peer.cache_supported = false;
    assert!(disk.synchronize_cache(&mut peer).is_err());
    assert!(disk.writes_pending);
    peer.cache_supported = true;
    disk.synchronize_cache(&mut peer).unwrap();
    assert!(!disk.writes_pending);
    assert_eq!(
        peer.commands.last().unwrap()[0],
        scsi_cmd::SYNCHRONIZE_CACHE_10
    );
}

#[test]
fn cache_flush_retries_timeouts_only_after_reset_and_remains_bounded() {
    let max_attempts = UsbMassStorage::MAX_READ_RETRIES as usize + 1;
    for (timeouts, expected_commands) in [(1, 2), (max_attempts, max_attempts)] {
        let mut peer = BotPeer {
            cache_timeouts: timeouts,
            ..Default::default()
        };
        let result = device().synchronize_cache(&mut peer);
        if timeouts == 1 {
            assert!(result.is_ok());
            assert!(peer.resets > 0);
        } else {
            assert!(matches!(
                result,
                Err(MassStorageError::Usb(UsbError::Timeout))
            ));
        }
        assert_eq!(peer.commands.len(), expected_commands);
        assert!(
            peer.commands
                .iter()
                .all(|c| c[0] == scsi_cmd::SYNCHRONIZE_CACHE_10)
        );
    }

    let mut peer = BotPeer {
        cache_timeouts: 1,
        fail_reset: true,
        ..Default::default()
    };
    assert!(matches!(
        device().synchronize_cache(&mut peer),
        Err(MassStorageError::Usb(UsbError::DeviceNotFound))
    ));
    assert_eq!(peer.commands.len(), 1);

    // A rejected command is not a transient transport timeout.
    let mut peer = BotPeer {
        cache_supported: false,
        ..Default::default()
    };
    assert!(matches!(
        device().synchronize_cache(&mut peer),
        Err(MassStorageError::CommandFailed)
    ));
    assert_eq!(peer.commands.len(), 1);
}

#[test]
fn short_payload_is_not_a_successful_write() {
    let mut peer = BotPeer::default();
    let mut disk = device();
    disk.init(&mut peer).unwrap();
    peer.short_write = true;
    let cdb = rw_10_cdb(scsi_cmd::WRITE_10, 0, 1);
    assert!(matches!(
        disk.transfer_blocks(&mut peer, &cdb, 1, &mut [0; 512], false),
        Err(MassStorageError::ShortTransfer)
    ));
}
