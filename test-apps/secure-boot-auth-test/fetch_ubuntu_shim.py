#!/usr/bin/env python3
"""Fetch Ubuntu 24.04's signed shim for secure-boot-auth-test's opt-in steps.

Downloads shim-signed 1.58+15.8-0ubuntu1 (noble), checks its SHA-256 and
extracts only the signed shim binaries; nothing from the package is run.
Run as `python3 -I fetch_ubuntu_shim.py OUTDIR`, then
`CRABEFI_SB_SHIM_DIR=OUTDIR ./crabefi test --app secure-boot-auth-test`.
"""

import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

URL = (
    "https://archive.ubuntu.com/ubuntu/pool/main/s/shim-signed/"
    "shim-signed_1.58+15.8-0ubuntu1_amd64.deb"
)
SHA256 = "ba9b5d80e5d886c30664f2bebfb5c2fcce3b9b40f16fc46cba49c19a91c8059c"
WANTED = {"shimx64.efi.signed.latest", "shimx64.efi.dualsigned"}


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=120) as response:
        deb = response.read()
    if hashlib.sha256(deb).hexdigest() != SHA256:
        sys.exit("shim-signed checksum mismatch")
    if deb[:8] != b"!<arch>\n":
        sys.exit("not a .deb")
    offset = 8
    while offset < len(deb):
        name = deb[offset : offset + 16].decode().strip().rstrip("/")
        size = int(deb[offset + 48 : offset + 58].decode().strip())
        body = deb[offset + 60 : offset + 60 + size]
        offset += 60 + size + (size & 1)
        if not name.startswith("data.tar"):
            continue
        with tarfile.open(fileobj=io.BytesIO(body)) as tar:
            for member in tar.getmembers():
                base = member.name.rsplit("/", 1)[-1]
                if member.isfile() and member.name.startswith("./usr/lib/shim/") and base in WANTED:
                    (out / base).write_bytes(tar.extractfile(member).read())
                    print(out / base)


if __name__ == "__main__":
    main()
