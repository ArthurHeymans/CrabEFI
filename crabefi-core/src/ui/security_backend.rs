//! Firmware-only verification and owned import data for the shared UI.
use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt::Write;
use crabefi_ui::screens::dialog::{Block, LineKind, ReviewSection};
/// Keep the verified bytes owned across review. Never reopen ESP files after consent.
enum PendingImport {
    Keys(crate::efi::auth::key_files::KeyFileSearchResult),
    Dbx(Vec<u8>, crate::efi::auth::dbx_update::DbxSource),
}
fn fingerprint(hash: &[u8; 32]) -> String {
    let mut text = String::new();
    for (i, byte) in hash.iter().enumerate() {
        if i > 0 && i.is_multiple_of(8) {
            text.push(' ');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Gregorian date of a Unix timestamp (UTC).
fn date(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    alloc::format!("{y:04}-{mo:02}-{d:02}")
}

/// Subject common name (or the whole subject's first printable value).
fn common_name(subject: &[u8]) -> Option<String> {
    use crabefi_pkcs7::der::{Tlv, tag};
    let mut rdns = Tlv::parse(subject).ok()?.contents(tag::SEQUENCE).ok()?;
    let mut fallback = None;
    while let Ok(set) = rdns.read() {
        let Ok(mut attrs) = set.contents(tag::SET) else {
            continue;
        };
        while let Ok(attr) = attrs.read() {
            let Ok(mut fields) = attr.contents(tag::SEQUENCE) else {
                continue;
            };
            let (Ok(oid), Ok(value)) = (fields.read().and_then(|t| t.oid()), fields.read()) else {
                continue;
            };
            let text = core::str::from_utf8(value.value).ok().map(String::from);
            if oid == [0x55, 0x04, 0x03] {
                return text;
            }
            if fallback.is_none() {
                fallback = text;
            }
        }
    }
    fallback
}

/// Subject, fingerprint and validity lines for one certificate.
fn certificate_lines(section: ReviewSection, der: &[u8], note: &str) -> ReviewSection {
    let parsed = crabefi_pkcs7::x509::Certificate::parse(der).ok();
    let subject = parsed
        .as_ref()
        .and_then(|c| common_name(c.subject))
        .map_or_else(
            || String::from("(unreadable subject)"),
            |cn| alloc::format!("CN={cn}"),
        );
    let validity = parsed
        .and_then(|c| c.validity().ok())
        .map(|v| alloc::format!("valid {} to {}", date(v.not_before), date(v.not_after)));
    let note = match (note.is_empty(), validity) {
        (true, Some(v)) => v,
        (false, Some(v)) => alloc::format!("{note}, {v}"),
        (_, None) => String::from(note),
    };
    let section = section.line(LineKind::Body, &subject).line(
        LineKind::Fingerprint,
        &alloc::format!("SHA-256 {}", fingerprint(&crate::efi::auth::sha256(der))),
    );
    if note.is_empty() {
        section
    } else {
        section.line(LineKind::Note, &note)
    }
}

fn dbx_effect(append: bool) -> &'static str {
    if append {
        "Adds revocations to the existing dbx. Existing revocations are kept."
    } else {
        "This replaces the existing dbx. Revocations absent from this file are removed, so previously revoked boot software may start again."
    }
}

fn timestamp_text(t: crabefi_efi_types::authentication::EfiTime) -> String {
    let (year, month, day, hour, minute, second, timezone) = (
        t.year, t.month, t.day, t.hour, t.minute, t.second, t.timezone,
    );
    let zone = match timezone {
        0 => String::from("UTC"),
        0x7ff => String::from("timezone unspecified"),
        offset => alloc::format!(
            "UTC{}{h:02}:{m:02}",
            if offset < 0 { '-' } else { '+' },
            h = offset.unsigned_abs() / 60,
            m = offset.unsigned_abs() % 60
        ),
    };
    alloc::format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} {zone}")
}

fn review(
    pending: PendingImport,
    intro: Vec<Block>,
    sections: Vec<ReviewSection>,
    outro: Vec<Block>,
) -> crabefi_ui::ImportReview {
    crabefi_ui::ImportReview {
        payload: Box::new(pending),
        intro,
        sections,
        outro,
    }
}

/// Load and verify the files for an import, keeping the verified bytes.
pub(super) fn prepare(
    action: crabefi_ui::SecurityAction,
) -> Result<crabefi_ui::ImportReview, &'static str> {
    use crate::efi::auth::{self, dbx_update, key_files, sha256};
    use crabefi_ui::SecurityAction;
    match action {
        SecurityAction::EnrollCustomPk => {
            let keys = key_files::find_key_files().ok_or_else(|| {
                crate::secure_boot_menu::custom_pk_error(auth::AuthError::NoSuitableKey)
            })?;
            key_files::validate_key_files(&keys)
                .map_err(crate::secure_boot_menu::custom_pk_error)?;
            let pk = keys.pk.as_deref().ok_or("No PK certificate supplied")?;
            let bundled = auth::enrollment::microsoft_uefi_ca_db_certificate();
            let mut sections = alloc::vec![certificate_lines(
                ReviewSection::labelled("PK"),
                pk,
                "PK.cer"
            )];
            match keys.kek.as_deref() {
                Some(kek) if kek != pk => sections.push(certificate_lines(
                    ReviewSection::labelled("KEK"),
                    kek,
                    "KEK.cer",
                )),
                Some(_) => sections.push(
                    ReviewSection::labelled("KEK")
                        .line(LineKind::Body, "Same certificate as PK")
                        .line(LineKind::Note, "KEK.cer is byte-identical to PK.cer"),
                ),
                None => sections.push(
                    ReviewSection::labelled("KEK")
                        .line(LineKind::Body, "Same certificate as PK")
                        .line(
                            LineKind::Note,
                            "No KEK.cer supplied; PK is also enrolled as KEK",
                        ),
                ),
            }
            let mut db_count = 1;
            if let Some(db) = keys.db.as_deref() {
                db_count += 1;
                if db == pk {
                    sections.push(
                        ReviewSection::labelled("db")
                            .line(LineKind::Body, "Same certificate as PK")
                            .line(LineKind::Note, "db.cer is byte-identical to PK.cer"),
                    );
                } else if keys.kek.as_deref() == Some(db) {
                    sections.push(
                        ReviewSection::labelled("db")
                            .line(LineKind::Body, "Same certificate as KEK")
                            .line(LineKind::Note, "db.cer is byte-identical to KEK.cer"),
                    );
                } else {
                    sections.push(certificate_lines(
                        ReviewSection::labelled("db"),
                        db,
                        "db.cer",
                    ));
                }
            }
            sections.push(certificate_lines(
                ReviewSection::labelled("db"),
                bundled,
                "Bundled with CrabEFI; signs shim and most GPU/NIC option ROMs",
            ));
            let dbx = auth::enrollment::get_enrollment_status().dbx_count;
            let intro = alloc::vec![
                Block::fact("Source", keys.source),
                Block::fact(
                    "Result",
                    &alloc::format!(
                        "Replaces PK (1), KEK (1) and db ({db_count}). dbx ({dbx}) is kept."
                    ),
                ),
            ];
            let outro = alloc::vec![Block::muted(if auth::is_secure_boot_requested() {
                "Enrolling PK leaves Setup Mode. Secure Boot is enforced as soon as the keys are enrolled."
            } else {
                "Enrolling PK leaves Setup Mode. Secure Boot stays off until you enable it on this page."
            })];
            Ok(review(PendingImport::Keys(keys), intro, sections, outro))
        }
        SecurityAction::ImportDbx => {
            let (data, source) = dbx_update::find_dbx_file().ok_or_else(|| {
                crate::secure_boot_menu::dbx_error(auth::AuthError::NoSuitableKey)
            })?;
            let preview = dbx_update::preview_dbx_update(&data, source)
                .map_err(crate::secure_boot_menu::dbx_error)?;
            let mut intro = alloc::vec![
                Block::fact("Source", preview.entries.source),
                Block::fact(
                    "Contents",
                    &alloc::format!(
                        "{} SHA-256 hashes, {} certificates",
                        preview.entries.sha256_count,
                        preview.entries.x509_count
                    ),
                ),
                Block::fact(
                    "Applies as",
                    if preview.append {
                        "Adds to the current revocations"
                    } else {
                        "Replaces the current revocations"
                    },
                ),
            ];
            if let Some(t) = preview.timestamp {
                intro.push(Block::fact("Timestamp", &timestamp_text(t)));
            }
            let mut sections = Vec::new();
            sections.push(match preview.signer_sha256 {
                Some(signer) => ReviewSection::labelled("Signer")
                    .line(LineKind::Body, "Verified against an enrolled KEK or PK")
                    .line(
                        LineKind::Fingerprint,
                        &alloc::format!("SHA-256 {}", fingerprint(&signer)),
                    ),
                None => ReviewSection::labelled("Signer")
                    .line(LineKind::Warn, "Unsigned update")
                    .line(
                        LineKind::Note,
                        "Signature not verified. Allowed only for provisioning in Setup Mode.",
                    ),
            });
            sections.push(
                ReviewSection::labelled("File")
                    .line(LineKind::Body, "Exactly these bytes are imported")
                    .line(
                        LineKind::Fingerprint,
                        &alloc::format!("SHA-256 {}", fingerprint(&sha256(&data))),
                    ),
            );
            let outro = alloc::vec![Block::text(dbx_effect(preview.append))];
            Ok(review(
                PendingImport::Dbx(data, source),
                intro,
                sections,
                outro,
            ))
        }
        _ => Err("Not an import action"),
    }
}

pub(super) fn commit(payload: Box<dyn core::any::Any>) -> Result<&'static str, &'static str> {
    use crate::efi::auth;
    match *payload
        .downcast::<PendingImport>()
        .map_err(|_| "Invalid import payload")?
    {
        PendingImport::Keys(keys) => auth::key_files::enroll_key_files(keys)
            .map(|_| "Custom keys enrolled; the reviewed certificates are now trusted.")
            .map_err(crate::secure_boot_menu::custom_pk_error),
        PendingImport::Dbx(data, source) => auth::dbx_update::enroll_dbx_data(data, source)
            .map(|_| "dbx imported; the reviewed update is committed.")
            .map_err(crate::secure_boot_menu::dbx_error),
    }
}

pub(super) fn enrolled_key_sections() -> Vec<ReviewSection> {
    use crate::efi::auth;
    let complete = auth::boot::key_inventory_complete();
    let mut sections = Vec::new();
    if !complete {
        sections.push(ReviewSection::labelled("Warning").line(LineKind::Warn, "Stored key data is malformed or could not be fully loaded. The identities and counts below are incomplete."));
    }
    for (label, db) in [
        ("PK", auth::pk_database()),
        ("KEK", auth::kek_database()),
        ("db", auth::db_database()),
    ] {
        let mut any = false;
        for der in db.x509_certificates() {
            any = true;
            sections.push(certificate_lines(ReviewSection::labelled(label), der, ""));
        }
        let hashes = db.sha256_hashes().count();
        let other = db.len() - db.x509_certificates().count() - hashes;
        if !any {
            sections.push(
                ReviewSection::labelled(label).line(LineKind::Note, "No certificates enrolled"),
            );
        }
        if hashes > 0 {
            sections.push(ReviewSection::labelled(label).line(
                LineKind::Body,
                &alloc::format!("{hashes} SHA-256 hash entries"),
            ));
        }
        if other > 0 {
            sections.push(ReviewSection::labelled(label).line(
                LineKind::Body,
                &alloc::format!("{other} entries of other signature types"),
            ));
        }
    }
    let dbx = auth::dbx_database();
    let certs = dbx.x509_certificates().count();
    let hashes = dbx.sha256_hashes().count();
    let other = dbx.len() - certs - hashes;
    let mut line = alloc::format!("{hashes} revoked hashes, {certs} revoked certificates");
    if other > 0 {
        let _ = write!(line, ", {other} other entries");
    }
    sections.push(ReviewSection::labelled("dbx").line(LineKind::Body, &line));
    sections
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_fingerprint_preserves_every_sha256_byte() {
        let hash = core::array::from_fn(|i| i as u8);
        assert_eq!(
            fingerprint(&hash),
            "0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f"
        );
    }
    #[test]
    fn unix_dates_are_gregorian() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(2_082_758_399), "2035-12-31");
    }

    #[test]
    fn warnings_match_the_write_mode() {
        assert!(dbx_effect(true).contains("kept"));
        assert!(!dbx_effect(true).contains("removed"));
        assert!(dbx_effect(false).contains("removed"));
    }

    #[test]
    fn timestamps_do_not_claim_an_unconverted_utc_time() {
        let mut time = crabefi_efi_types::authentication::EfiTime::zero();
        time.timezone = 90;
        assert!(timestamp_text(time).ends_with("UTC+01:30"));
        time.timezone = -330;
        assert!(timestamp_text(time).ends_with("UTC-05:30"));
        time.timezone = 0x7ff;
        assert!(timestamp_text(time).ends_with("timezone unspecified"));
        time.timezone = 0;
        assert!(timestamp_text(time).ends_with(" UTC"));
    }
}
