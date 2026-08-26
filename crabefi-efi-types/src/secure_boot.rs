//! Secure Boot GUIDs, variable names, and name-matching helpers.

/// EFI global variable GUID in UEFI byte order.
pub const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];
/// EFI image security database GUID in UEFI byte order.
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: [u8; 16] = [
    0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
];
/// EFI X.509 certificate type GUID in UEFI byte order.
pub const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
/// EFI RSA-2048 certificate type GUID in UEFI byte order.
pub const EFI_CERT_RSA2048_GUID: [u8; 16] = [
    0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26, 0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6,
];
/// EFI SHA-256 certificate type GUID in UEFI byte order.
pub const EFI_CERT_SHA256_GUID: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];
/// EFI PKCS#7 certificate type GUID in UEFI byte order.
pub const EFI_CERT_TYPE_PKCS7_GUID: [u8; 16] = [
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
];

/// Unterminated UTF-16 Platform Key variable name.
pub const PK_NAME: &[u16] = &[b'P' as u16, b'K' as u16];
/// Unterminated UTF-16 Key Exchange Key variable name.
pub const KEK_NAME: &[u16] = &[b'K' as u16, b'E' as u16, b'K' as u16];
/// Unterminated UTF-16 allowed signature database variable name.
pub const DB_NAME: &[u16] = &[b'd' as u16, b'b' as u16];
/// Unterminated UTF-16 forbidden signature database variable name.
pub const DBX_NAME: &[u16] = &[b'd' as u16, b'b' as u16, b'x' as u16];
/// Unterminated UTF-16 SetupMode status variable name.
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
/// Unterminated UTF-16 SecureBoot status variable name.
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
/// Unterminated UTF-16 SecureBootEnable preference variable name.
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

/// Secure Boot key database identity.
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

    pub const fn guid(self) -> &'static [u8; 16] {
        match self {
            Self::PK | Self::Kek => &EFI_GLOBAL_VARIABLE_GUID,
            Self::Db | Self::Dbx => &EFI_IMAGE_SECURITY_DATABASE_GUID,
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

/// Compares UTF-16 names after truncating each at its first NUL code unit.
///
/// # Returns
///
/// `true` if the names match up to their first NUL code unit, `false` otherwise.
///
/// # Examples
///
/// ```
/// assert!(name_matches(&[b'P' as u16, b'K' as u16, 0], &[b'P' as u16, b'K' as u16]));
/// assert!(!name_matches(&[b'P' as u16, 0], &[b'K' as u16]));
/// ```
pub fn name_matches(left: &[u16], right: &[u16]) -> bool {
    /// Returns the portion of a UTF-16 name before its first NUL unit.
    ///
    /// # Examples
    ///
    /// ```
    /// let name = [b'P' as u16, b'K' as u16, 0, b'x' as u16];
    /// assert_eq!(unterminated(&name), &[b'P' as u16, b'K' as u16]);
    /// ```
    fn unterminated(name: &[u16]) -> &[u16] {
        let length = name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(name.len());
        name.get(..length).unwrap_or(&[])
    }

    unterminated(left) == unterminated(right)
}

/// Identify a Secure Boot key database by vendor GUID and variable name.
pub fn identify_key_database(guid: &[u8; 16], name: &[u16]) -> Option<SecureBootVariable> {
    if guid == &EFI_GLOBAL_VARIABLE_GUID {
        if name_matches(name, PK_NAME) {
            return Some(SecureBootVariable::PK);
        }
        if name_matches(name, KEK_NAME) {
            return Some(SecureBootVariable::Kek);
        }
    } else if guid == &EFI_IMAGE_SECURITY_DATABASE_GUID {
        if name_matches(name, DB_NAME) {
            return Some(SecureBootVariable::Db);
        }
        if name_matches(name, DBX_NAME) {
            return Some(SecureBootVariable::Dbx);
        }
    }
    None
}

/// Return whether a variable is an image-synthesized Secure Boot status value.
pub fn is_status_variable(guid: &[u8; 16], name: &[u16]) -> bool {
    guid == &EFI_GLOBAL_VARIABLE_GUID
        && (name_matches(name, SETUP_MODE_NAME) || name_matches(name, SECURE_BOOT_NAME))
}
