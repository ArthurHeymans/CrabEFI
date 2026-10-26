//! Translate hub-local SuperSpeedPlus sublink IDs into controller speed IDs.

use super::XhciError;
use alloc::vec::Vec;
use xhci::extended_capabilities::xhci_supported_protocol::{ProtocolSpeedId, PsiType};
use zerocopy::byteorder::{LittleEndian, U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

pub(super) const BOS_DESCRIPTOR_TYPE: u8 = 0x0f;

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
pub(super) struct BosHeader {
    length: u8,
    descriptor_type: u8,
    total_length: U16<LittleEndian>,
    capabilities: u8,
}

impl BosHeader {
    pub fn total_length(bytes: &[u8]) -> Result<usize, XhciError> {
        let header = Self::ref_from_bytes(bytes).map_err(|_| XhciError::InvalidParameter)?;
        let length = usize::from(header.total_length.get());
        if header.length != 5 || header.descriptor_type != BOS_DESCRIPTOR_TYPE || length < 5 {
            return Err(XhciError::InvalidParameter);
        }
        Ok(length)
    }
}

#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct SspHeader {
    length: u8,
    descriptor_type: u8,
    capability_type: u8,
    reserved: u8,
    attributes: U32<LittleEndian>,
    functionality: U16<LittleEndian>,
    reserved2: U16<LittleEndian>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkSpeed {
    rx_lane_bps: u64,
    tx_lane_bps: u64,
    rx_lanes: u8,
    tx_lanes: u8,
}

impl LinkSpeed {
    pub const SUPER: Self = Self {
        rx_lane_bps: 5_000_000_000,
        tx_lane_bps: 5_000_000_000,
        rx_lanes: 1,
        tx_lanes: 1,
    };

    fn default_id(self) -> Option<u8> {
        if self.rx_lane_bps != self.tx_lane_bps || self.rx_lanes != self.tx_lanes {
            return None;
        }
        match (self.rx_lane_bps, self.rx_lanes) {
            (5_000_000_000, 1) => Some(4),
            (10_000_000_000, 1) => Some(5),
            (5_000_000_000, 2) => Some(6),
            (10_000_000_000, 2) => Some(7),
            _ => None,
        }
    }
}

/// Entries from a hub's BOS, whose IDs need not match xHCI PSI IDs.
pub(super) struct SublinkSpeeds(Vec<u32>);

impl SublinkSpeeds {
    pub fn from_bos(bytes: &[u8]) -> Result<Option<Self>, XhciError> {
        let header = bytes.get(..5).ok_or(XhciError::InvalidParameter)?;
        let total = BosHeader::total_length(header)?;
        let mut descriptors = bytes.get(5..total).ok_or(XhciError::InvalidParameter)?;
        for _ in 0..header[4] {
            let length = usize::from(*descriptors.first().ok_or(XhciError::InvalidParameter)?);
            if length < 3 {
                return Err(XhciError::InvalidParameter);
            }
            let descriptor = descriptors
                .get(..length)
                .ok_or(XhciError::InvalidParameter)?;
            descriptors = &descriptors[length..];
            if descriptor[1] != 0x10 || descriptor[2] != 0x0a {
                continue;
            }
            let (ssp, attributes) =
                SspHeader::ref_from_prefix(descriptor).map_err(|_| XhciError::InvalidParameter)?;
            let count = ((ssp.attributes.get() & 0x1f) + 1) as usize;
            let attributes = attributes
                .get(..count * 4)
                .ok_or(XhciError::InvalidParameter)?;
            return Ok(Some(Self(
                attributes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|bytes| U32::<LittleEndian>::read_from_bytes(bytes).unwrap().get())
                    .collect(),
            )));
        }
        Ok(None)
    }

    pub fn port_speed(&self, status: u32) -> Option<LinkSpeed> {
        let rate = |id: u8, transmit: bool| {
            self.0.iter().find_map(|&attribute| {
                let direction = attribute & (1 << 7) != 0;
                if attribute as u8 & 0xf != id || direction != transmit {
                    return None;
                }
                let exponent = (attribute >> 4) & 3;
                let mantissa = (attribute >> 16) & 0xff;
                let rate = u64::from(mantissa) * 1000u64.pow(exponent);
                (rate != 0 && (attribute >> 14) & 3 <= 1).then_some(rate)
            })
        };
        Some(LinkSpeed {
            rx_lane_bps: rate((status & 0xf) as u8, false)?,
            tx_lane_bps: rate(((status >> 4) & 0xf) as u8, true)?,
            rx_lanes: ((status >> 8) & 0xf) as u8 + 1,
            tx_lanes: ((status >> 12) & 0xf) as u8 + 1,
        })
    }
}

#[derive(Default)]
struct SpeedId {
    id: u8,
    rx_bps: u64,
    tx_bps: u64,
}

/// One USB3 Supported Protocol capability and its optional speed table.
pub(super) struct Usb3Protocol {
    pub first_port: u8,
    pub port_count: u8,
    pub minor_revision: u8,
    speeds: Vec<SpeedId>,
}

impl Usb3Protocol {
    pub fn new(first_port: u8, port_count: u8, minor_revision: u8) -> Self {
        Self {
            first_port,
            port_count,
            minor_revision,
            speeds: Vec::new(),
        }
    }

    pub fn contains(&self, port: u8) -> bool {
        port >= self.first_port && port - self.first_port < self.port_count
    }

    pub fn add_psi(&mut self, psi: ProtocolSpeedId) {
        let id = psi.protocol_speed_id_value();
        let rate = u64::from(psi.protocol_speed_id_mantissa())
            * 1000u64.pow(psi.protocol_speed_id_exponent() as u32);
        let index = self
            .speeds
            .iter()
            .position(|speed| speed.id == id)
            .unwrap_or_else(|| {
                self.speeds.push(SpeedId {
                    id,
                    ..SpeedId::default()
                });
                self.speeds.len() - 1
            });
        let speed = &mut self.speeds[index];
        match psi.psi_type() {
            PsiType::Symmetric => {
                speed.rx_bps = rate;
                speed.tx_bps = rate;
            }
            PsiType::AsymmetricRx => speed.rx_bps = rate,
            PsiType::AsymmetricTx => speed.tx_bps = rate,
        }
    }

    pub fn speed_id(&self, link: LinkSpeed) -> Option<u8> {
        let default = link.default_id();
        if self.speeds.is_empty() {
            return default.filter(|id| match id {
                4 => true,
                5 => self.minor_revision >= 0x10,
                6 | 7 => self.minor_revision >= 0x20,
                _ => false,
            });
        }
        let matches = |speed: &&SpeedId| {
            speed.id != 0
                && speed.rx_bps == link.rx_lane_bps * u64::from(link.rx_lanes)
                && speed.tx_bps == link.tx_lane_bps * u64::from(link.tx_lanes)
        };
        self.speeds
            .iter()
            .filter(matches)
            .find(|speed| Some(speed.id) == default)
            .or_else(|| self.speeds.iter().find(matches))
            .map(|speed| speed.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn bos() -> Vec<u8> {
        // Hub-local IDs 1 and 9 deliberately differ from xHCI IDs 4 and 5.
        let mut bytes = vec![5, 0x0f, 33, 0, 1, 28, 0x10, 0x0a, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        for attribute in [0x0005_0031u32, 0x0005_00b1, 0x000a_4039, 0x000a_40b9] {
            bytes.extend_from_slice(&attribute.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn hub_local_ids_and_lane_counts_select_controller_speeds() {
        let speeds = SublinkSpeeds::from_bos(&bos()).unwrap().unwrap();
        let protocol = Usb3Protocol::new(2, 4, 0x20);
        for (status, id) in [(0x11, 4), (0x99, 5), (0x1111, 6), (0x1199, 7)] {
            assert_eq!(
                protocol.speed_id(speeds.port_speed(status).unwrap()),
                Some(id)
            );
        }
        assert!(speeds.port_speed(0x22).is_none());
        assert!(protocol.contains(2));
        assert!(protocol.contains(5));
        assert!(!protocol.contains(1));
        assert!(!protocol.contains(6));
    }

    #[test]
    fn protocol_revision_limits_implied_speed_ids() {
        let speeds = SublinkSpeeds::from_bos(&bos()).unwrap().unwrap();
        assert_eq!(
            Usb3Protocol::new(0, 1, 0).speed_id(LinkSpeed::SUPER),
            Some(4)
        );
        assert_eq!(
            Usb3Protocol::new(0, 1, 0).speed_id(speeds.port_speed(0x99).unwrap()),
            None
        );
        assert_eq!(
            Usb3Protocol::new(0, 1, 0x10).speed_id(speeds.port_speed(0x1199).unwrap()),
            None
        );
    }

    #[test]
    fn advertised_psi_ids_override_defaults() {
        let speeds = SublinkSpeeds::from_bos(&bos()).unwrap().unwrap();
        let registers = [
            0u32,
            0,
            3 << 28,
            0,
            0x000a_0038, // ID 8: symmetric 10 Gbit/s
            0x000a_00b9, // ID 9: asymmetric RX 10 Gbit/s
            0x0005_00f9, // ID 9: asymmetric TX 5 Gbit/s
        ];
        // SAFETY: the aligned backing array contains a header and three PSI DWORDs,
        // and remains live until the accessors are dropped.
        let capability = unsafe {
            xhci::extended_capabilities::XhciSupportedProtocol::new(
                registers.as_ptr() as usize,
                super::super::IdentityMapper,
            )
        };
        let psis = capability.psis.unwrap();
        let mut protocol = Usb3Protocol::new(0, 1, 0x10);
        for index in 0..3 {
            protocol.add_psi(psis.read_volatile_at(index));
        }
        assert_eq!(protocol.speed_id(speeds.port_speed(0x99).unwrap()), Some(8));
        assert_eq!(protocol.speed_id(speeds.port_speed(0x19).unwrap()), Some(9));
        assert_eq!(protocol.speed_id(LinkSpeed::SUPER), None);
    }

    #[test]
    fn malformed_bos_is_rejected() {
        let bytes = bos();
        for length in 0..bytes.len() {
            assert!(SublinkSpeeds::from_bos(&bytes[..length]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid[5] = 0;
        assert!(SublinkSpeeds::from_bos(&invalid).is_err());
        let mut invalid = bytes;
        invalid[9] = 31;
        assert!(SublinkSpeeds::from_bos(&invalid).is_err());
        assert!(
            SublinkSpeeds::from_bos(&[5, 0x0f, 5, 0, 0])
                .unwrap()
                .is_none()
        );
    }
}
