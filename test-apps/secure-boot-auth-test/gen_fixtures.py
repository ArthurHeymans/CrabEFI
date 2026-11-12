#!/usr/bin/env python3
"""Generate the Secure Boot authenticated-variable test fixtures and plan.

All keys are TEST ONLY. They live in fixtures/keys and are created once when
missing; everything else is derived from them. Certificates, signature lists,
EFI_VARIABLE_AUTHENTICATION_2 payloads (no signed attributes) and the PE
images are deterministic. sbsign adds a signing time, so signed images change
on every run; the generator checks their Authenticode digests itself.

Usage: gen_fixtures.py [--out DIR]   (needs python3-cryptography and sbsign)
"""

import argparse
import datetime
import hashlib
import shutil
import struct
import subprocess
import tempfile
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
KEYS = HERE / "fixtures" / "keys"

GLOBAL = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c").bytes_le
SECURITY_DB = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f").bytes_le
PRIV_GUID = uuid.UUID("2b7c7c5e-0d0a-4b8e-9a59-5ce0c3a0e7d1").bytes_le
CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le
CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328").bytes_le
CERT_X509_SHA256 = uuid.UUID("3bd2a492-96c0-4079-b420-fcf98ef103ed").bytes_le
CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7").bytes_le
OWNER = uuid.UUID("c4b10b3e-5e57-4f2a-9d8e-0123456789ab").bytes_le

NV, BS, RT, AT, APPEND = 0x1, 0x2, 0x4, 0x20, 0x40
AUTH = NV | BS | RT | AT

VARS = {
    "PK": ("PK", GLOBAL),
    "KEK": ("KEK", GLOBAL),
    "db": ("db", SECURITY_DB),
    "dbx": ("dbx", SECURITY_DB),
    "priv1": ("CrabEfiSbTestPriv1", PRIV_GUID),
    "priv2": ("CrabEfiSbTestPriv2", PRIV_GUID),
    "SecureBootEnable": ("SecureBootEnable", GLOBAL),
}

# name -> (issuer or None for self-signed, is CA, validity years)
CERTS = {
    "pk": (None, True, (2020, 2050)),
    "pk2": (None, True, (2020, 2050)),
    "kek": (None, True, (2020, 2050)),
    "kek2": (None, True, (2020, 2050)),
    "db-ca": (None, True, (2020, 2050)),
    "db-signer": ("db-ca", False, (2020, 2050)),
    "db-signer2": ("db-ca", False, (2020, 2050)),
    "db-expired": ("db-ca", False, (2001, 2002)),
    "db-direct": (None, False, (2020, 2050)),
    "rogue": (None, True, (2020, 2050)),
}


def key(name):
    path = KEYS / f"test-only-{name}.key.pem"
    if not path.exists():
        KEYS.mkdir(parents=True, exist_ok=True)
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return serialization.load_pem_private_key(path.read_bytes(), None)


def build_certs():
    certs = {}
    for serial, (name, (issuer, ca, (start, end))) in enumerate(CERTS.items(), 1):
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"CrabEFI TEST ONLY {name}")]
        )
        issuer_name = certs[issuer].subject if issuer else subject
        signing_key = key(issuer or name)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(key(name).public_key())
            .serial_number(0x5EC0000 + serial)
            .not_valid_before(datetime.datetime(start, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(end, 1, 1, tzinfo=datetime.UTC))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key(name).public_key()),
                critical=False,
            )
        )
        if not ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False
            )
        certs[name] = builder.sign(signing_key, hashes.SHA256())
    return certs


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# EFI_SIGNATURE_LIST and EFI_VARIABLE_AUTHENTICATION_2
# ---------------------------------------------------------------------------


def esl(signature_type, entries):
    """One EFI_SIGNATURE_LIST holding equally sized EFI_SIGNATURE_DATA."""
    size = 16 + len(entries[0])
    assert all(16 + len(entry) == size for entry in entries)
    body = b"".join(OWNER + entry for entry in entries)
    return signature_type + struct.pack("<III", 28 + len(body), 0, size) + body


def esl_x509(cert):
    return esl(CERT_X509, [der(cert)])


def esl_sha256(*digests):
    return esl(CERT_SHA256, list(digests))


def esl_x509_sha256(cert):
    # EFI_CERT_X509_SHA256: ToBeSignedHash + TimeOfRevocation (zero = always).
    return esl(CERT_X509_SHA256, [hashlib.sha256(cert.tbs_certificate_bytes).digest() + bytes(16)])


def efi_time(n, nanosecond=0, timezone=0, daylight=0):
    """T(n): 2026-01-01T00:00:00Z plus n hours."""
    t = datetime.datetime(2026, 1, 1) + datetime.timedelta(hours=n)
    return struct.pack(
        "<HBBBBBBIhBB", t.year, t.month, t.day, t.hour, t.minute, t.second, 0,
        nanosecond, timezone, daylight, 0,
    )


def tlv(data, offset=0):
    """Return (tag, header length, total length) of the DER element at offset."""
    tag, length = data[offset], data[offset + 1]
    header = 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        header += count
    return tag, header, header + length


def children(data):
    offset, out = 0, []
    while offset < len(data):
        _, header, total = tlv(data, offset)
        out.append(data[offset : offset + total])
        offset += total
    return out


def content(element):
    _, header, total = tlv(element)
    return element[header:total]


def signed_data(contentinfo):
    """Strip the ContentInfo wrapper like efitools' sign-efi-sig-list."""
    oid, explicit = children(content(contentinfo))
    assert oid == bytes.fromhex("06092a864886f70d010702")
    return content(explicit)


def pkcs7_detached(signer, data):
    contentinfo = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(signer[0], signer[1], hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [
                pkcs7.PKCS7Options.DetachedSignature,
                pkcs7.PKCS7Options.Binary,
                pkcs7.PKCS7Options.NoAttributes,
            ],
        )
    )
    return signed_data(contentinfo)


def auth2(var, attrs, payload, signer, n, *, sign_var=None, sign_guid=None,
          sign_attrs=None, nanosecond=0, timezone=0):
    """EFI_VARIABLE_AUTHENTICATION_2 || payload, signed over
    VariableName || VendorGuid || Attributes || TimeStamp || Data."""
    name, guid = VARS[sign_var or var]
    guid = sign_guid or guid
    timestamp = efi_time(n, nanosecond=nanosecond, timezone=timezone)
    message = (
        name.encode("utf-16-le")
        + guid
        + struct.pack("<I", attrs if sign_attrs is None else sign_attrs)
        + timestamp
        + payload
    )
    signature = pkcs7_detached(signer, message) if signer else b""
    header = struct.pack("<IHH", 24 + len(signature), 0x0200, 0x0EF1) + CERT_TYPE_PKCS7
    return timestamp + header + signature + payload


# ---------------------------------------------------------------------------
# PE images
# ---------------------------------------------------------------------------


def pe_image(magic):
    """Minimal x86-64 EFI application: `mov eax, magic; ret`."""
    image = bytearray(0x400)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x44, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x58
    struct.pack_into("<HBBIIIII", image, opt, 0x20B, 0, 0, 0x200, 0, 0, 0x1000, 0x1000)
    struct.pack_into("<QII", image, opt + 24, 0, 0x1000, 0x200)
    struct.pack_into("<IIIH", image, opt + 56, 0x2000, 0x200, 0, 10)  # size, headers, checksum, EFI app
    struct.pack_into("<I", image, opt + 108, 16)  # NumberOfRvaAndSizes
    section = opt + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    code = b"\xb8" + struct.pack("<I", magic) + b"\xc3"
    tag = f"CrabEFI TEST ONLY image {magic:#x}".encode()
    image[0x200 : 0x200 + len(code)] = code
    image[0x210 : 0x210 + len(tag)] = tag
    return bytes(image)


def authenticode_sha256(image):
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    sections = struct.unpack_from("<H", image, pe + 6)[0]
    opt = pe + 24
    checksum = opt + 64
    cert_dir = opt + 112 + 4 * 8
    headers = struct.unpack_from("<I", image, opt + 60)[0]
    cert_offset, cert_size = struct.unpack_from("<II", image, cert_dir)
    digest = hashlib.sha256()
    digest.update(image[:checksum])
    digest.update(image[checksum + 4 : cert_dir])
    digest.update(image[cert_dir + 8 : headers])
    table = opt + struct.unpack_from("<H", image, pe + 20)[0]
    raw = []
    for index in range(sections):
        size, pointer = struct.unpack_from("<II", image, table + 40 * index + 16)
        if size:
            raw.append((pointer, size))
    hashed = headers
    for pointer, size in sorted(raw):
        digest.update(image[pointer : pointer + size])
        hashed += size
    end = len(image) - cert_size
    if end > hashed:
        digest.update(image[hashed:end])
    return digest.digest()


def spc_digest(signed_image):
    """Digest sbsign put into SpcIndirectDataContent (independent oracle)."""
    pe = struct.unpack_from("<I", signed_image, 0x3C)[0]
    offset, _ = struct.unpack_from("<II", signed_image, pe + 24 + 112 + 32)
    length = struct.unpack_from("<I", signed_image, offset)[0]
    contentinfo = signed_image[offset + 8 : offset + length]
    _, explicit = children(content(contentinfo))
    fields = children(content(content(explicit)))
    _, explicit_spc = children(content(fields[2]))
    spc = content(explicit_spc)
    _, digest_info = children(content(spc))
    return content(children(content(digest_info))[1])


def sbsign(image, cert, signer_key, work):
    unsigned = work / "in.efi"
    signed = work / "out.efi"
    cert_path = work / "cert.pem"
    key_path = work / "key.pem"
    unsigned.write_bytes(image)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        signer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    subprocess.run(
        ["sbsign", "--key", key_path, "--cert", cert_path, "--output", signed, unsigned],
        check=True,
        capture_output=True,
    )
    data = signed.read_bytes()
    assert spc_digest(data) == authenticode_sha256(data) == authenticode_sha256(image)
    return data


# ---------------------------------------------------------------------------
# Fixtures and plan
# ---------------------------------------------------------------------------

MAGIC = {
    "img-db-signed": 0x5B01,
    "img-db-direct": 0x5B02,
    "img-unsigned": 0x5B03,
    "img-rogue": 0x5B04,
    "img-hash-db": 0x5B05,
    "img-hash-dbx": 0x5B06,
    "img-expired": 0x5B07,
    "img-x509sha256": 0x5B08,
    "img-tampered": 0x5B09,
}


def generate(out):
    certs = build_certs()
    signers = {name: (certs[name], key(name)) for name in CERTS}
    files = {}
    plan = []

    def put(name, data):
        assert name not in files or files[name] == data, name
        files[name] = data
        return name

    def step(line):
        plan.append(line)

    # Signature lists.
    for name in ["pk", "pk2", "kek", "kek2", "db-ca", "db-direct"]:
        put(f"{name}.esl", esl_x509(certs[name]))
    dummy = [hashlib.sha256(f"CrabEFI TEST ONLY dummy {i}".encode()).digest() for i in range(4)]
    put("dbx-dummy.esl", esl_sha256(dummy[0]))
    put("db-dummy2.esl", esl_sha256(dummy[1]))
    put("db-dummy3.esl", esl_sha256(dummy[2]))
    put("db-dummy4.esl", esl_sha256(dummy[3]))
    put("priv-a.bin", b"CrabEFI TEST ONLY private A")
    put("priv-b.bin", b"CrabEFI TEST ONLY private B")
    put("priv-c.bin", b"CrabEFI TEST ONLY private C")
    put("u8-0.bin", b"\x00")
    put("u8-1.bin", b"\x01")

    # Images.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        plain = {name: pe_image(magic) for name, magic in MAGIC.items()}
        put("img-unsigned.efi", plain["img-unsigned"])
        put("img-hash-db.efi", plain["img-hash-db"])
        for name, signer in [
            ("img-db-signed", "db-signer"),
            ("img-db-direct", "db-direct"),
            ("img-rogue", "rogue"),
            ("img-hash-dbx", "db-signer"),
            ("img-expired", "db-expired"),
            ("img-x509sha256", "db-signer2"),
            ("img-tampered", "db-signer"),
        ]:
            signed = sbsign(plain[name], certs[signer], key(signer), work)
            if name == "img-tampered":
                signed = bytearray(signed)
                signed[0x300] ^= 0xFF  # .text padding, covered by the hash
                signed = bytes(signed)
            put(f"{name}.efi", signed)
    put("db-hash.esl", esl_sha256(authenticode_sha256(plain["img-hash-db"])))
    put(
        "dbx-revoke.esl",
        esl_x509(certs["db-direct"]) + esl_sha256(authenticode_sha256(plain["img-hash-dbx"])),
    )
    put("dbx-x509sha256.esl", esl_x509_sha256(certs["db-signer2"]))

    def auth(case, var, attrs, payload, signer, n, expect, **kwargs):
        data = auth2(var, attrs, files[payload] if payload else b"",
                     signers[signer] if signer else None, n, **kwargs)
        put(f"{case}.auth", data)
        step(f"set {case} {var} {attrs:#x} {case}.auth {expect}")

    def load_ok(case, image):
        step(f"load {case} {image}.efi run {MAGIC[image]:#x}")

    def load_deny(case, image):
        step(f"load {case} {image}.efi deny")

    # ---- Stage 1: Setup Mode enrollment, then User Mode variable rules ----
    step("stage 1")
    step("mode s1-initial-setup-mode 1 0")
    for var in ["PK", "KEK", "db", "dbx"]:
        step(f"var s1-{var}-absent {var} absent")
    # Required attributes, Setup Mode (UEFI 2.10 Table 3.3; EDK2 VarCheck).
    step(f"set s1-kek-raw-attrs KEK {NV | BS | RT:#x} kek.esl INVALID_PARAMETER")
    auth("s1-kek-volatile", "KEK", BS | RT | AT, "kek.esl", "pk", 1, "INVALID_PARAMETER")
    auth("s1-db-no-rt", "db", NV | BS | AT, "db-ca.esl", "kek", 1, "INVALID_PARAMETER")
    # Enrollment: KEK, db, dbx, then self-signed PK.
    auth("s1-enroll-kek", "KEK", AUTH, "kek.esl", "pk", 2, "SUCCESS")
    step(f"var s1-kek-readback KEK equals {AUTH:#x} kek.esl")
    auth("s1-enroll-db", "db", AUTH, "db-ca.esl", "kek", 2, "SUCCESS")
    step(f"var s1-db-readback db equals {AUTH:#x} db-ca.esl")
    auth("s1-enroll-dbx", "dbx", AUTH, "dbx-dummy.esl", "kek", 2, "SUCCESS")
    step(f"var s1-dbx-readback dbx equals {AUTH:#x} dbx-dummy.esl")
    auth("s1-enroll-pk", "PK", AUTH, "pk.esl", "pk", 2, "SUCCESS")
    step(f"var s1-pk-readback PK equals {AUTH:#x} pk.esl")
    step("mode s1-user-mode 0 1")

    # A: time-based authenticated writes on db (User Mode, KEK-signed).
    auth("a-append-new", "db", AUTH | APPEND, "db-direct.esl", "kek", 3, "SUCCESS")
    step("var a-append-new-present db has db-direct.esl")
    step("var a-append-new-kept db has db-ca.esl")
    step("var a-entries-before-dup db count 2")
    auth("a-append-duplicate", "db", AUTH | APPEND, "db-direct.esl", "kek", 4, "SUCCESS")
    step("var a-append-duplicate-not-added db count 2")
    auth("a-append-older-timestamp", "db", AUTH | APPEND, "db-hash.esl", "kek", 1, "SUCCESS")
    step("var a-append-older-present db has db-hash.esl")
    step(f"set a-replay-same-envelope db {AUTH:#x} s1-enroll-db.auth SECURITY_VIOLATION")
    auth("a-older-than-append-floor", "db", AUTH, "db-ca.esl", "kek", 3, "SECURITY_VIOLATION")
    auth("a-equal-timestamp", "db", AUTH, "db-ca.esl", "kek", 4, "SECURITY_VIOLATION")
    auth("a-signed-other-name", "db", AUTH | APPEND, "db-ca.esl", "kek", 20,
         "SECURITY_VIOLATION", sign_var="dbx")
    auth("a-signed-other-guid", "db", AUTH | APPEND, "db-ca.esl", "kek", 20,
         "SECURITY_VIOLATION", sign_guid=GLOBAL)
    auth("a-signed-other-attrs", "db", AUTH | APPEND, "db-ca.esl", "kek", 20,
         "SECURITY_VIOLATION", sign_attrs=AUTH)
    tampered = bytearray(auth2("db", AUTH | APPEND, files["db-ca.esl"], signers["kek"], 20))
    tampered[-1] ^= 0x01
    put("a-tampered-payload.auth", bytes(tampered))
    step(f"set a-tampered-payload db {AUTH | APPEND:#x} a-tampered-payload.auth SECURITY_VIOLATION")
    # UEFI 2.10 8.2.6: Pad1, Nanosecond, TimeZone, Daylight, Pad2 must be zero.
    auth("a-timestamp-nanosecond", "db", AUTH | APPEND, "db-ca.esl", "kek", 1,
         "SECURITY_VIOLATION", nanosecond=1)
    auth("a-timestamp-timezone", "db", AUTH | APPEND, "db-ca.esl", "kek", 1,
         "SECURITY_VIOLATION", timezone=60)
    step(f"set a-unauthenticated-write db {NV | BS | RT:#x} db-ca.esl ERROR")
    auth("a-delete", "db", AUTH, None, "kek", 5, "SUCCESS")
    step("var a-deleted db absent")
    step(f"set a-replay-after-delete db {AUTH:#x} s1-enroll-db.auth SECURITY_VIOLATION")
    step("var a-replay-after-delete-absent db absent")
    auth("a-recreate", "db", AUTH, "db-ca.esl", "kek", 6, "SUCCESS")
    put("db-direct-hash.esl", files["db-direct.esl"] + files["db-hash.esl"])
    auth("a-reappend", "db", AUTH | APPEND, "db-direct-hash.esl", "kek", 7, "SUCCESS")
    step("var a-reappended db has db-direct-hash.esl")

    # B: key hierarchy (User Mode).
    auth("b-kek-signed-by-kek", "KEK", AUTH | APPEND, "kek2.esl", "kek", 3, "SECURITY_VIOLATION")
    auth("b-kek-signed-by-rogue", "KEK", AUTH | APPEND, "kek2.esl", "rogue", 3, "SECURITY_VIOLATION")
    auth("b-kek-signed-by-db", "KEK", AUTH | APPEND, "kek2.esl", "db-direct", 3, "SECURITY_VIOLATION")
    auth("b-kek-signed-by-pk", "KEK", AUTH | APPEND, "kek2.esl", "pk", 3, "SUCCESS")
    step("var b-kek2-present KEK has kek2.esl")
    auth("b-db-signed-by-kek2", "db", AUTH | APPEND, "db-dummy2.esl", "kek2", 8, "SUCCESS")
    auth("b-db-signed-by-pk", "db", AUTH | APPEND, "db-dummy3.esl", "pk", 8, "SUCCESS")
    step("var b-db-signers-present db has db-dummy2.esl")
    step("var b-db-pk-signer-present db has db-dummy3.esl")
    auth("b-db-signed-by-db-key", "db", AUTH | APPEND, "db-dummy4.esl", "db-direct", 9,
         "SECURITY_VIOLATION")
    auth("b-db-signed-by-db-chain", "db", AUTH | APPEND, "db-dummy4.esl", "db-signer", 9,
         "SECURITY_VIOLATION")
    auth("b-db-signed-by-rogue", "db", AUTH | APPEND, "db-dummy4.esl", "rogue", 9,
         "SECURITY_VIOLATION")
    auth("b-dbx-signed-by-db-key", "dbx", AUTH | APPEND, "db-dummy4.esl", "db-direct", 9,
         "SECURITY_VIOLATION")
    auth("b-dbx-signed-by-rogue", "dbx", AUTH | APPEND, "db-dummy4.esl", "rogue", 9,
         "SECURITY_VIOLATION")
    auth("b-pk-signed-by-kek", "PK", AUTH, "pk2.esl", "kek", 3, "SECURITY_VIOLATION")
    auth("b-pk-signed-by-rogue", "PK", AUTH, "pk2.esl", "rogue", 3, "SECURITY_VIOLATION")
    auth("b-pk-signed-by-new-pk", "PK", AUTH, "pk2.esl", "pk2", 3, "SECURITY_VIOLATION")
    auth("b-pk-rotate", "PK", AUTH, "pk2.esl", "pk", 3, "SUCCESS")
    step(f"var b-pk-rotated PK equals {AUTH:#x} pk2.esl")
    auth("b-pk-signed-by-old-pk", "PK", AUTH, "pk.esl", "pk", 4, "SECURITY_VIOLATION")
    auth("b-kek-signed-by-old-pk", "KEK", AUTH | APPEND, "kek2.esl", "pk", 4, "SECURITY_VIOLATION")
    auth("b-kek-signed-by-new-pk", "KEK", AUTH | APPEND, "kek2.esl", "pk2", 4, "SUCCESS")
    auth("b-pk-delete-signed-by-kek", "PK", AUTH, None, "kek", 5, "SECURITY_VIOLATION")
    step("mode b-still-user-mode 0 1")

    # A (private authenticated variables, UEFI 2.10 8.2.6 step 7: the first
    # signer owns the variable; later updates need the same signer).
    auth("p1-create-any-signer", "priv1", AUTH, "priv-a.bin", "rogue", 1, "SUCCESS")
    auth("p2-create", "priv2", AUTH, "priv-a.bin", "db-direct", 1, "SUCCESS")
    step(f"var p2-created priv2 equals {AUTH:#x} priv-a.bin")
    auth("p2-update-same-signer", "priv2", AUTH, "priv-b.bin", "db-direct", 2, "SUCCESS")
    step(f"var p2-updated priv2 equals {AUTH:#x} priv-b.bin")
    auth("p2-append-older-timestamp", "priv2", AUTH | APPEND, "priv-c.bin", "db-direct", 1, "SUCCESS")
    auth("p2-update-other-signer", "priv2", AUTH, "priv-a.bin", "db-signer", 3, "SECURITY_VIOLATION")
    step(f"set p2-replay priv2 {AUTH:#x} p2-update-same-signer.auth SECURITY_VIOLATION")
    auth("p2-delete", "priv2", AUTH, None, "db-direct", 5, "SUCCESS")
    step("var p2-deleted priv2 absent")
    step("digest s1-end")
    step("reset")

    # ---- Stage 2: persistence, image verification, PK deletion ----
    step("stage 2")
    step("digest s2-start")
    step("mode s2-user-mode-after-reset 0 1")
    step(f"set d-replay-after-reset db {AUTH:#x} s1-enroll-db.auth SECURITY_VIOLATION")
    step(f"set d-pk-replay-after-reset PK {AUTH:#x} b-pk-rotate.auth SECURITY_VIOLATION")
    load_ok("c-db-signed", "img-db-signed")
    load_ok("c-db-direct", "img-db-direct")
    load_ok("c-hash-in-db", "img-hash-db")
    load_ok("c-expired-signer", "img-expired")
    load_ok("c-hash-dbx-before-revocation", "img-hash-dbx")
    load_ok("c-x509sha256-before-revocation", "img-x509sha256")
    load_deny("c-unsigned", "img-unsigned")
    load_deny("c-rogue", "img-rogue")
    load_deny("c-tampered", "img-tampered")
    step("loadstatus c-rejection-status img-unsigned.efi")
    auth("c-dbx-revoke", "dbx", AUTH | APPEND, "dbx-revoke.esl", "kek", 10, "SUCCESS")
    auth("c-dbx-x509sha256", "dbx", AUTH | APPEND, "dbx-x509sha256.esl", "kek", 10, "SUCCESS")
    load_deny("c-signer-cert-in-dbx", "img-db-direct")
    load_deny("c-hash-in-dbx", "img-hash-dbx")
    load_deny("c-signer-tbs-hash-in-dbx", "img-x509sha256")
    load_ok("c-db-signed-after-dbx", "img-db-signed")
    auth("d-older-than-floor-after-reset", "db", AUTH, "db-ca.esl", "kek", 8, "SECURITY_VIOLATION")
    auth("e-pk-delete", "PK", AUTH, None, "pk2", 6, "SUCCESS")
    step("var e-pk-deleted PK absent")
    step("mode e-setup-mode-after-pk-delete 1 0")
    load_ok("e-unsigned-without-secure-boot", "img-unsigned")
    step("digest s2-end")
    step("reset")

    # ---- Stage 3: Setup Mode persists, re-enrollment, policy bypass ----
    step("stage 3")
    step("digest s3-start")
    step("mode s3-setup-mode-after-reset 1 0")
    step("var s3-pk-absent PK absent")
    auth("e-pk-reenroll", "PK", AUTH, "pk.esl", "pk", 7, "SUCCESS")
    step("mode e-user-mode-after-reenroll 0 1")
    load_deny("e-unsigned-after-reenroll", "img-unsigned")
    load_deny("e-dbx-persisted", "img-hash-dbx")
    # Attribute changes of existing Secure Boot variables (UEFI 2.10 8.2.6).
    auth("s3-db-append-drops-rt", "db", NV | BS | AT | APPEND, "db-ca.esl", "kek", 1,
         "INVALID_PARAMETER")
    auth("s3-kek-volatile", "KEK", BS | RT | AT, "kek.esl", "pk", 10, "INVALID_PARAMETER")
    # The Secure Boot policy must not be changeable by an unauthenticated write.
    step(f"set f-securebootenable-write SecureBootEnable {NV | BS | RT:#x} u8-0.bin ERROR")
    step("mode f-still-enforcing 0 1")
    load_deny("f-unsigned-still-denied", "img-unsigned")
    step(f"set f-securebootenable-restore SecureBootEnable {NV | BS | RT:#x} u8-1.bin ANY")
    step("digest s3-end")
    step("end")

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name, data in sorted(files.items()):
        (out / name).write_bytes(data)
    # PEM certificates for sbsign; xtask signs the test app with db-signer.
    (HERE / "fixtures" / "certs").mkdir(exist_ok=True)
    for name, cert in certs.items():
        (HERE / "fixtures" / "certs" / f"{name}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
    (out / "plan.txt").write_text("\n".join(plan) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=HERE / "fixtures" / "esp" / "sbtest")
    generate(parser.parse_args().out)


if __name__ == "__main__":
    main()
