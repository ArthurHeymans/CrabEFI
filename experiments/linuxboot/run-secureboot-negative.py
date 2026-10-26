#!/usr/bin/env python3
"""Require EFI_SECURITY_VIOLATION for a single unauthorized EFI image on a test ESP."""
import argparse
import json
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="prepared single-entry test ESP image")
    parser.add_argument("--flash", type=Path, required=True, help="enrolled 8-MiB QEMU pflash template")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    disk, flash = out / "windows.img", out / "flash.fd"
    if disk.exists() or flash.exists():
        parser.error("use a fresh output directory")
    for source, target in [(args.image, disk), (args.flash, flash)]:
        if not source.is_file():
            parser.error("inputs must be regular image files")
        subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(source), str(target)], check=True)
    cmd = ["qemu-system-x86_64", "-machine", "q35", "-enable-kvm", "-cpu", "host", "-m", "4G",
           "-nic", "none", "-drive", f"if=pflash,format=raw,file={flash}",
           "-drive", f"file={disk},format=raw,if=none,id=os",
           "-device", "nvme,drive=os,serial=CRABEFI_INSTALLED,addr=0x3",
           "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"]
    with (out / "serial.log").open("w") as log:
        try:
            code = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=30).returncode
        except subprocess.TimeoutExpired:
            code = 124  # Expected after rejection: firmware deliberately halts.
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", (out / "serial.log").read_text(errors="replace"))
    checks = {"enforcing": "Secure Boot: mode=User, enabled=true" in text,
              "verification_rejected": "BS.LoadImage: Secure Boot verification FAILED" in text,
              "security_violation": "Status(9223372036854775834)" in text,
              "never_started": "BS.StartImage" not in text and "Hello from CrabEFI!" not in text,
              "no_os_handoff": "ExitBootServices SUCCESS" not in text}
    report = {"passed": code in (0, 124) and all(checks.values()), "checks": checks,
              "qemu_exit": code, "command": cmd}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
