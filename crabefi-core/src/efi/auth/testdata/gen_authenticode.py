#!/usr/bin/env python3
"""Generate the multi-signature Authenticode host-test images.

Reuses the TEST ONLY PKI of test-apps/secure-boot-auth-test (its keys and
gen_fixtures.py helpers). Writes one PE image carrying two Authenticode
signatures, rogue then db-signer, the same signatures in the other order, and
the DER certificates the tests enroll. sbsign adds a signing time, so the
images change on every run.

Usage: python3 -I gen_authenticode.py   (needs python3-cryptography and sbsign)
"""

import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE = HERE.parents[4] / "test-apps" / "secure-boot-auth-test"
sys.path.insert(0, str(SUITE))
sys.dont_write_bytecode = True

import gen_fixtures as suite  # noqa: E402

MAGIC = 0x5BA1


def security_directory(image):
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    entry = pe + 24 + 112 + 4 * 8
    return entry, *struct.unpack_from("<II", image, entry)


def with_signatures(first, second):
    """`first` with the attribute certificate table entries of `second` appended."""
    entry, offset, size = security_directory(first)
    _, second_offset, second_size = security_directory(second)
    assert offset + size == len(first) and size % 8 == 0 and second_size % 8 == 0
    combined = bytearray(first + second[second_offset : second_offset + second_size])
    struct.pack_into("<I", combined, entry + 4, size + second_size)
    return bytes(combined)


def main():
    certs = suite.build_certs()
    image = suite.pe_image(MAGIC)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        rogue = suite.sbsign(image, certs["rogue"], suite.key("rogue"), work)
        signer = suite.sbsign(image, certs["db-signer"], suite.key("db-signer"), work)
    outputs = {
        "authenticode-dual.efi": with_signatures(rogue, signer),
        "authenticode-dual-reversed.efi": with_signatures(signer, rogue),
    }
    for name, data in outputs.items():
        assert suite.authenticode_sha256(data) == suite.authenticode_sha256(image)
        (HERE / name).write_bytes(data)
    for name in ["db-ca", "db-signer", "rogue"]:
        (HERE / f"authenticode-{name}.der").write_bytes(suite.der(certs[name]))


if __name__ == "__main__":
    main()
