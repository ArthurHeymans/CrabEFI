#!/usr/bin/env python3
"""Run a disposable QEMU Windows PE boot and require a Windows-written marker."""
import argparse
import json
import subprocess
from pathlib import Path

MARKER = "CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS"
OFFSET = "@@1048576"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["direct", "linux", "coreboot"])
    parser.add_argument("--media", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rom", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--initrd", type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--tcg", action="store_true")
    args = parser.parse_args()
    if not args.media.is_file():
        parser.error("media must be a regular disk-image file")
    if args.mode in ("direct", "coreboot") and not args.rom:
        parser.error("this mode requires --rom")
    if args.mode == "linux" and not (args.kernel and args.initrd):
        parser.error("linux mode requires --kernel and --initrd")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    disk = out / "windows.img"
    if disk.exists():
        parser.error("output already contains windows.img; use a fresh output directory")
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(args.media), str(disk)], check=True)
    # Never accept a marker inherited from an earlier successful run.
    subprocess.run(["mdel", "-i", str(disk) + OFFSET, "::/crabefi-smoke/success.txt"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ["qemu-system-x86_64", "-machine", "q35", "-m", "4G",
           "-cpu", "max" if args.tcg else "host",
           "-drive", f"file={disk},format=raw,if=none,id=win",
           "-device", "nvme,drive=win,serial=WINPE",
           "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot"]
    if not args.tcg:
        cmd += ["-enable-kvm"]
    if args.mode == "linux":
        # SeaBIOS otherwise puts a 64-bit NVMe BAR far outside CrabEFI's current
        # 64-GiB identity mapping. This is a test-platform constraint, not a fix.
        cmd += ["-fw_cfg", "name=opt/org.seabios/pci64,string=0",
                "-kernel", str(args.kernel), "-initrd", str(args.initrd),
                "-append", "console=ttyS0,115200 rdinit=/init nokaslr maxcpus=1 panic=-1"]
    else:
        cmd += ["-bios", str(args.rom)]
    print("Running:", " ".join(cmd), flush=True)
    timed_out = False
    with (out / "serial.log").open("w") as log:
        try:
            code = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=args.timeout).returncode
        except subprocess.TimeoutExpired:
            timed_out, code = True, -1
    text = (out / "serial.log").read_text(errors="replace")
    result = subprocess.run(["mtype", "-i", str(disk) + OFFSET,
                             "::/crabefi-smoke/success.txt"], capture_output=True, text=True)
    marker = result.stdout.strip() if result.returncode == 0 else ""
    version = subprocess.run(["mtype", "-i", str(disk) + OFFSET,
                              "::/crabefi-smoke/version.txt"], capture_output=True, text=True)
    stages = ["CrabEFI v", "ExitBootServices SUCCESS"]
    if args.mode != "direct":
        stages = ["LINUXBOOT_USERSPACE_RUNNING", "LINUXBOOT_HANDOFF_READY",
                  "LINUXBOOT_KEXEC_EXECUTING"] + stages
    positions = [text.find(stage) for stage in stages]
    passed = (code == 0 and marker == MARKER and all(p >= 0 for p in positions)
              and positions == sorted(positions))
    report = {"mode": args.mode, "passed": passed, "qemu_exit": code,
              "timed_out": timed_out, "marker": marker,
              "windows_version": version.stdout.strip(),
              "stages": dict(zip(stages, positions, strict=True)), "command": cmd}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        print("Last serial lines:\n" + "\n".join(text.splitlines()[-50:]))
        raise SystemExit(1)
    print("PASS: Windows userspace wrote a fresh success marker and shut down")


if __name__ == "__main__":
    main()
