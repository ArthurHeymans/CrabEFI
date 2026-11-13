//! Signer bindings of private authenticated variables, kept like EDK2's
//! AuthVariableLib: "certdb" (NV|BS|RT|AT) for non-volatile and "certdbv"
//! (BS|RT|AT) for volatile variables, under gEfiCertDbGuid.
//!
//! Layout: UINT32 total size, then per variable EFI_GUID VendorGuid, UINT32
//! CertNodeSize, UINT32 NameSize (CHAR16s, no terminator), UINT32
//! CertDataSize, CHAR16 Name[], UINT8 CertData[]. CertData is the 32-byte
//! [`PrivateSigner`](super::crypto::PrivateSigner) digest; EDK2's older
//! whole-certificate entries never match one.

use crabefi_efi_types::secure_boot::name_matches;

use crate::{
    efi::{Status, VariableAttributes},
    store::VariableTransaction,
};

/// gEfiCertDbGuid {d9bee56e-75dc-49d9-b4d7-b534210f637a}.
pub const GUID: [u8; 16] = [
    0x6e, 0xe5, 0xbe, 0xd9, 0xdc, 0x75, 0xd9, 0x49, 0xb4, 0xd7, 0xb5, 0x34, 0x21, 0x0f, 0x63, 0x7a,
];
const NAME: &[u16] = &[
    b'c' as u16,
    b'e' as u16,
    b'r' as u16,
    b't' as u16,
    b'd' as u16,
    b'b' as u16,
];
const VOLATILE_NAME: &[u16] = &[
    b'c' as u16,
    b'e' as u16,
    b'r' as u16,
    b't' as u16,
    b'd' as u16,
    b'b' as u16,
    b'v' as u16,
];
const LIST_HEADER_SIZE: usize = 4;
const NODE_HEADER_SIZE: usize = 28;
pub const DIGEST_SIZE: usize = 32;

/// Whether a variable is one of the binding databases.
pub fn is_cert_db(guid: &[u8; 16], name: &[u16]) -> bool {
    *guid == GUID && (name_matches(name, NAME) || name_matches(name, VOLATILE_NAME))
}

/// The database holding bindings of (non-)volatile variables.
pub fn name(nonvolatile: bool) -> &'static [u16] {
    if nonvolatile { NAME } else { VOLATILE_NAME }
}

pub fn attributes(nonvolatile: bool) -> VariableAttributes {
    let attributes = VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    if nonvolatile {
        attributes | VariableAttributes::NON_VOLATILE
    } else {
        attributes
    }
}

struct Node<'a> {
    guid: &'a [u8],
    /// UTF-16LE name bytes.
    name: &'a [u8],
    data: &'a [u8],
    size: usize,
}

impl Node<'_> {
    fn matches(&self, guid: &[u8; 16], name: &[u16]) -> bool {
        self.guid == guid
            && self.name.len() == name.len().saturating_mul(2)
            && self
                .name
                .as_chunks::<2>()
                .0
                .iter()
                .zip(name)
                .all(|(bytes, unit)| *bytes == unit.to_le_bytes())
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<usize> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(field.try_into().ok()?) as usize)
}

/// The nodes of `db`, or `None` when its list size does not match.
fn nodes(db: &[u8]) -> Option<&[u8]> {
    if db.is_empty() {
        return Some(&[]);
    }
    (read_u32(db, 0)? == db.len()).then(|| db.get(LIST_HEADER_SIZE..))?
}

/// The node at the start of `nodes`, `None` when malformed.
fn node(nodes: &[u8]) -> Option<Node<'_>> {
    let size = read_u32(nodes, 16)?;
    let name_size = read_u32(nodes, 20)?.checked_mul(2)?;
    let data_size = read_u32(nodes, 24)?;
    if NODE_HEADER_SIZE
        .checked_add(name_size)?
        .checked_add(data_size)?
        != size
    {
        return None;
    }
    let (name, data) = nodes
        .get(NODE_HEADER_SIZE..size)?
        .split_at_checked(name_size)?;
    Some(Node {
        guid: nodes.get(..16)?,
        name,
        data,
        size,
    })
}

/// The binding of (`guid`, `name`) in `db`. A malformed database binds
/// nothing, so updates of private variables fail closed.
pub fn find<'a>(db: &'a [u8], guid: &[u8; 16], name: &[u16]) -> Option<&'a [u8]> {
    let mut rest = nodes(db)?;
    while !rest.is_empty() {
        let node = node(rest)?;
        if node.matches(guid, name) {
            return Some(node.data);
        }
        rest = rest.get(node.size..)?;
    }
    None
}

/// Stage `db` without the node of (`guid`, `name`), plus one binding it to
/// `digest` when given. Returns the staged length.
pub fn stage(
    transaction: &mut VariableTransaction,
    db: &[u8],
    guid: &[u8; 16],
    name: &[u16],
    digest: Option<&[u8; DIGEST_SIZE]>,
) -> Result<usize, Status> {
    let mut rest = nodes(db).ok_or(Status::DEVICE_ERROR)?;
    let mut length = LIST_HEADER_SIZE;
    while !rest.is_empty() {
        let node = node(rest).ok_or(Status::DEVICE_ERROR)?;
        if !node.matches(guid, name) {
            length =
                transaction.push(length, rest.get(..node.size).ok_or(Status::DEVICE_ERROR)?)?;
        }
        rest = rest.get(node.size..).ok_or(Status::DEVICE_ERROR)?;
    }
    if let Some(digest) = digest {
        let name_units = u32::try_from(name.len()).map_err(|_| Status::INVALID_PARAMETER)?;
        let node_size = name_units
            .checked_mul(2)
            .and_then(|size| size.checked_add((NODE_HEADER_SIZE + DIGEST_SIZE) as u32))
            .ok_or(Status::INVALID_PARAMETER)?;
        length = transaction.push(length, guid)?;
        length = transaction.push(length, &node_size.to_le_bytes())?;
        length = transaction.push(length, &name_units.to_le_bytes())?;
        length = transaction.push(length, &(DIGEST_SIZE as u32).to_le_bytes())?;
        for unit in name {
            length = transaction.push(length, &unit.to_le_bytes())?;
        }
        length = transaction.push(length, digest)?;
    }
    let list_size = u32::try_from(length).map_err(|_| Status::OUT_OF_RESOURCES)?;
    transaction.push(0, &list_size.to_le_bytes())?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(
        transaction: &mut VariableTransaction,
        db: &[u8],
        name: &[u16],
        digest: Option<&[u8; DIGEST_SIZE]>,
    ) -> Vec<u8> {
        let length = stage(transaction, db, &[0x42; 16], name, digest).unwrap();
        transaction.data(length).unwrap().to_vec()
    }

    #[test]
    fn bindings_are_added_replaced_and_removed_in_the_edk2_layout() {
        let mut transaction = VariableTransaction::new();
        let (a, b) = (&[b'A' as u16][..], &[b'B' as u16, b'b' as u16][..]);
        let db = staged(&mut transaction, &[], a, Some(&[1; DIGEST_SIZE]));
        let mut expected = 66u32.to_le_bytes().to_vec();
        expected.extend_from_slice(&[0x42; 16]);
        expected.extend_from_slice(&62u32.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&32u32.to_le_bytes());
        expected.extend_from_slice(&[b'A', 0]);
        expected.extend_from_slice(&[1; DIGEST_SIZE]);
        assert_eq!(db, expected);

        let db = staged(&mut transaction, &db, b, Some(&[2; DIGEST_SIZE]));
        let db = staged(&mut transaction, &db, a, Some(&[3; DIGEST_SIZE]));
        assert_eq!(find(&db, &[0x42; 16], a), Some(&[3; DIGEST_SIZE][..]));
        assert_eq!(find(&db, &[0x42; 16], b), Some(&[2; DIGEST_SIZE][..]));
        assert_eq!(find(&db, &[0x43; 16], a), None);
        assert_eq!(find(&db, &[0x42; 16], &[b'B' as u16]), None);

        let db = staged(&mut transaction, &db, b, None);
        assert_eq!(find(&db, &[0x42; 16], b), None);
        let db = staged(&mut transaction, &db, a, None);
        assert_eq!(db, 4u32.to_le_bytes());
    }

    #[test]
    fn malformed_databases_bind_nothing_and_are_not_rewritten() {
        let mut transaction = VariableTransaction::new();
        let name = &[b'A' as u16][..];
        let db = staged(&mut transaction, &[], name, Some(&[1; DIGEST_SIZE]));
        // A node size that disagrees with its name and data sizes.
        let mut node_size = db.clone();
        node_size[20] ^= 1;
        for db in [
            db[..db.len() - 1].to_vec(),
            [&[0xff], &db[1..]].concat(),
            [db.clone(), vec![0]].concat(),
            node_size,
        ] {
            assert_eq!(find(&db, &[0x42; 16], name), None);
            assert_eq!(
                stage(&mut transaction, &db, &[0x42; 16], name, None),
                Err(Status::DEVICE_ERROR)
            );
        }
    }
}
