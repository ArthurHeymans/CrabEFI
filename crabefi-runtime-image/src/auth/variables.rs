//! Secure Boot variable names, GUIDs, and authorization relationships.

use crate::efi;

pub const EFI_GLOBAL_VARIABLE_GUID: efi::Guid = efi::Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: efi::Guid = efi::Guid::from_fields(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    0xa3,
    0xbc,
    &[0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);
pub const EFI_CERT_X509_GUID: efi::Guid = efi::Guid::from_fields(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    0x87,
    0xb5,
    &[0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);

pub const PK_NAME: &[u16] = &[b'P' as u16, b'K' as u16];
pub const KEK_NAME: &[u16] = &[b'K' as u16, b'E' as u16, b'K' as u16];
pub const DB_NAME: &[u16] = &[b'd' as u16, b'b' as u16];
pub const DBX_NAME: &[u16] = &[b'd' as u16, b'b' as u16, b'x' as u16];
pub const SETUP_MODE_NAME: &[u16] = &[
    b'S' as u16,
    b'e' as u16,
    b't' as u16,
    b'u' as u16,
    b'p' as u16,
    b'M' as u16,
    b'o' as u16,
    b'd' as u16,
    b'e' as u16,
];
pub const SECURE_BOOT_NAME: &[u16] = &[
    b'S' as u16,
    b'e' as u16,
    b'c' as u16,
    b'u' as u16,
    b'r' as u16,
    b'e' as u16,
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
];
pub const SECURE_BOOT_ENABLE_NAME: &[u16] = &[
    b'S' as u16,
    b'e' as u16,
    b'c' as u16,
    b'u' as u16,
    b'r' as u16,
    b'e' as u16,
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
    b'E' as u16,
    b'n' as u16,
    b'a' as u16,
    b'b' as u16,
    b'l' as u16,
    b'e' as u16,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootVariable {
    PK,
    Kek,
    Db,
    Dbx,
}

impl SecureBootVariable {
    pub const fn index(self) -> usize {
        match self {
            Self::PK => 0,
            Self::Kek => 1,
            Self::Db => 2,
            Self::Dbx => 3,
        }
    }

    pub const fn authorizing_database(self) -> Self {
        match self {
            Self::PK | Self::Kek => Self::PK,
            Self::Db | Self::Dbx => Self::Kek,
        }
    }

    pub const fn guid(self) -> efi::Guid {
        match self {
            Self::PK | Self::Kek => EFI_GLOBAL_VARIABLE_GUID,
            Self::Db | Self::Dbx => EFI_IMAGE_SECURITY_DATABASE_GUID,
        }
    }

    pub const fn name(self) -> &'static [u16] {
        match self {
            Self::PK => PK_NAME,
            Self::Kek => KEK_NAME,
            Self::Db => DB_NAME,
            Self::Dbx => DBX_NAME,
        }
    }
}

pub fn identify_key_database(guid: &[u8; 16], name: &[u16]) -> Option<SecureBootVariable> {
    if *guid == *EFI_GLOBAL_VARIABLE_GUID.as_bytes() {
        if name == PK_NAME {
            return Some(SecureBootVariable::PK);
        }
        if name == KEK_NAME {
            return Some(SecureBootVariable::Kek);
        }
    } else if *guid == *EFI_IMAGE_SECURITY_DATABASE_GUID.as_bytes() {
        if name == DB_NAME {
            return Some(SecureBootVariable::Db);
        }
        if name == DBX_NAME {
            return Some(SecureBootVariable::Dbx);
        }
    }
    None
}

pub fn is_status_variable(guid: &[u8; 16], name: &[u16]) -> bool {
    *guid == *EFI_GLOBAL_VARIABLE_GUID.as_bytes()
        && (name == SETUP_MODE_NAME || name == SECURE_BOOT_NAME)
}
