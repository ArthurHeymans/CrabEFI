#!/usr/bin/env python3
"""Generate the runtime image's authenticated-variable host-test fixtures.

Reuses the TEST ONLY PKI of test-apps/secure-boot-auth-test (its keys and
gen_fixtures.py helpers): the "pk" certificate is enrolled as PK, KEK, db and
dbx and signs every update; "rogue" signs the unauthorized one. Private
authenticated variables are signed by "db-direct", "rogue" and the "db-ca"
chain; *-binding.bin hold the signer digests EDK2's certdb records for them.
Output is deterministic. db and dbx envelopes carry a ContentInfo-wrapped
SignedData, the others a bare SignedData (as sign-efi-sig-list writes it).

Usage: python3 -I gen_fixtures.py   (needs python3-cryptography)
"""

import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
SUITE = HERE.parents[2] / "test-apps" / "secure-boot-auth-test"
sys.path.insert(0, str(SUITE))
sys.dont_write_bytecode = True

import gen_fixtures as suite  # noqa: E402

AUTH = suite.NV | suite.BS | suite.RT | suite.AT
VARIABLES = {
    "pk": ("PK", suite.GLOBAL),
    "kek": ("KEK", suite.GLOBAL),
    "db": ("db", suite.SECURITY_DB),
    "dbx": ("dbx", suite.SECURITY_DB),
    "private": ("CrabEfiPrivate", suite.PRIV_GUID),
    "chain": ("CrabEfiPrivateChain", suite.PRIV_GUID),
    "volatile": ("CrabEfiPrivateVolatile", suite.PRIV_GUID),
}


def timestamp(year):
    """{year}-02-03T04:05:06; Pad1, Nanosecond, TimeZone, Daylight, Pad2 zero."""
    return struct.pack("<HBBBBBBIhBB", year, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0)


def encode(tag, body):
    """DER element of `tag` holding `body`."""
    if len(body) < 0x80:
        length = bytes([len(body)])
    else:
        raw = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def with_certificates(signed, extra):
    """Bare SignedData `signed` with `extra` added to its certificates."""
    fields = suite.children(suite.content(signed))
    assert fields[3][0] == 0xA0
    certificates = suite.content(fields[3]) + b"".join(suite.der(cert) for cert in extra)
    fields[3] = encode(0xA0, certificates)
    return encode(0x30, b"".join(fields))


def signed_data(signer, message, wrapped, extra=()):
    contentinfo = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(message)
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
    if wrapped:
        assert not extra
        return contentinfo
    # PKCS7SignatureBuilder.add_certificate() does not reach the output.
    return with_certificates(suite.signed_data(contentinfo), extra)


def envelope(variable, attributes, payload, signer, year, extra=()):
    """EFI_VARIABLE_AUTHENTICATION_2 || payload."""
    name, guid = VARIABLES[variable]
    time = timestamp(year)
    message = name.encode("utf-16-le") + guid + struct.pack("<I", attributes) + time + payload
    signature = signed_data(signer, message, variable in ("db", "dbx"), extra)
    header = struct.pack("<IHH", 24 + len(signature), 0x0200, 0x0EF1) + suite.CERT_TYPE_PKCS7
    return time + header + signature + payload


def main():
    certs = suite.build_certs()
    signer = (certs["pk"], suite.key("pk"))
    rogue = (certs["rogue"], suite.key("rogue"))
    certificate_list = suite.esl_x509(certs["pk"])
    files = {"pk.esl": certificate_list, "kek.esl": certificate_list}
    for variable in ["pk", "kek", "db", "dbx"]:
        if variable in ("db", "dbx"):
            update, append = (
                suite.esl_sha256(hashlib.sha256(f"CrabEFI TEST ONLY {variable} {i}".encode()).digest())
                for i in ("update", "append")
            )
        else:
            update = append = certificate_list
        files[f"{variable}-update.bin"] = envelope(variable, AUTH, update, signer, 2025)
        files[f"{variable}-append.bin"] = envelope(
            variable, AUTH | suite.APPEND, append, signer, 2026
        )
        files[f"{variable}-delete.bin"] = envelope(variable, AUTH, b"", signer, 2027)
    files["unauthorized-update.bin"] = envelope("kek", AUTH, certificate_list, rogue, 2028)

    direct = (certs["db-direct"], suite.key("db-direct"))
    leaf = (certs["db-signer"], suite.key("db-signer"))
    sibling = (certs["db-signer2"], suite.key("db-signer2"))
    ca = [certs["db-ca"]]
    for name, args in {
        "private-create": ("private", AUTH, b"A", direct, 2025),
        "private-update": ("private", AUTH, b"B", direct, 2026),
        "private-append-older": ("private", AUTH | suite.APPEND, b"C", direct, 2024),
        "private-update-rogue": ("private", AUTH, b"X", rogue, 2027),
        "private-delete": ("private", AUTH, b"", direct, 2028),
        "private-recreate-rogue": ("private", AUTH, b"R", rogue, 2029),
        "chain-create": ("chain", AUTH, b"A", leaf, 2025, ca),
        "chain-update": ("chain", AUTH, b"B", leaf, 2026, ca),
        "chain-update-sibling": ("chain", AUTH, b"X", sibling, 2027, ca),
        "chain-update-leaf": ("chain", AUTH, b"X", leaf, 2027),
        "volatile-create": ("volatile", suite.BS | suite.RT | suite.AT, b"V", direct, 2025),
    }.items():
        files[f"{name}.bin"] = envelope(*args)
    for name, signer, top in [
        ("private", "db-direct", "db-direct"),
        ("rogue", "rogue", "rogue"),
        ("chain", "db-signer", "db-ca"),
    ]:
        common_name = certs[signer].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        binding = hashlib.sha256(common_name.encode() + certs[top].tbs_certificate_bytes)
        files[f"{name}-binding.bin"] = binding.digest()
    for name, data in files.items():
        (HERE / name).write_bytes(data)


if __name__ == "__main__":
    main()
