#!/usr/bin/env python3
"""Deploy or boot installed Windows on disposable, network-isolated image copies."""
import argparse
import json
import socket
import subprocess
from pathlib import Path

OFFSET = "@@1048576"
DIRECTORY = "::/crabefi-installed/"
MARKERS = {"deploy": ("deployed.txt", "CRABEFI_INSTALLED_WINDOWS_DEPLOYED"),
           "boot": ("success.txt", "CRABEFI_INSTALLED_WINDOWS_BOOT_SUCCESS")}


def read_guest(disk, name):
    result = subprocess.run(["mtype", "-i", str(disk) + OFFSET, DIRECTORY + name],
                            capture_output=True, text=True, errors="replace")
    return result.stdout.strip() if result.returncode == 0 else ""


def copy_image(source, target):
    if not source.is_file():
        raise ValueError(f"not a regular image file: {source}")
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(source), str(target)], check=True)


def capture_diagnostics(out, number):
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(out / "qmp.sock"))
            stream = connection.makefile("rwb", buffering=0)
            stream.readline()

            def execute(command, arguments=None):
                stream.write((json.dumps({"execute": command, "arguments": arguments or {}}) + "\n").encode())
                while True:
                    reply = json.loads(stream.readline())
                    if "return" in reply or "error" in reply:
                        return reply

            execute("qmp_capabilities")
            status = execute("query-status")
            registers = execute("human-monitor-command", {"command-line": "info registers"})
            screen = execute("screendump", {"filename": str(out / f"boot-{number:02d}-screen.ppm")})
            (out / f"boot-{number:02d}-diagnostics.json").write_text(
                json.dumps({"status": status, "registers": registers, "screen": screen}, indent=2) + "\n")
    except (OSError, ValueError) as error:
        print(f"Could not capture QMP diagnostics: {error}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=MARKERS)
    parser.add_argument("--rom", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--disk", type=Path, help="installed source image (boot only; copied)")
    parser.add_argument("--installer", type=Path, help="patched WinPE image (deploy only; copied)")
    parser.add_argument("--iso", type=Path, help="original installation ISO (deploy only; read-only)")
    parser.add_argument("--direct", action="store_true", help="ROM is direct CrabEFI rather than LinuxBoot")
    parser.add_argument("--timeout", type=int, default=600, help="timeout per firmware boot")
    parser.add_argument("--max-boots", type=int, default=5)
    args = parser.parse_args()
    if args.max_boots < 1 or args.timeout < 1:
        parser.error("max-boots and timeout must be positive")
    if args.phase == "boot" and not args.disk:
        parser.error("boot requires --disk")
    if args.phase == "deploy" and not (args.installer and args.iso and args.iso.is_file()):
        parser.error("deploy requires --installer and a regular --iso file")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    disk = out / "windows.img"
    installer = out / "installer.img"
    if disk.exists():
        parser.error("use a fresh output directory: windows.img already exists")
    if args.phase == "deploy":
        with disk.open("xb") as image:
            image.truncate(64 * 1024**3)
        copy_image(args.installer, installer)
    else:
        copy_image(args.disk, disk)
    filename, expected = MARKERS[args.phase]
    stale = [filename]
    if args.phase == "boot":
        stale += ["version.txt", "installation-type.txt", "environment.txt", "desktop.txt",
                  "operating-system.txt", "boot-loader.txt", "task.txt"]
    for name in stale:
        subprocess.run(["mdel", "-i", str(disk) + OFFSET, DIRECTORY + name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stages = ["CrabEFI v", "ExitBootServices SUCCESS"]
    if not args.direct:
        stages = ["LINUXBOOT_USERSPACE_RUNNING", "LINUXBOOT_HANDOFF_READY",
                  "LINUXBOOT_KEXEC_EXECUTING"] + stages
    rounds = []
    passed = False
    text = ""
    for number in range(1, args.max_boots + 1):
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-enable-kvm", "-cpu", "host",
               "-m", "4G", "-nic", "none", "-bios", str(args.rom),
               "-drive", f"file={disk},format=raw,if=none,id=os",
               "-device", "nvme,drive=os,serial=CRABEFI_INSTALLED,addr=0x3",
               "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
               "-qmp", f"unix:{out}/qmp.sock,server=on,wait=off"]
        if args.phase == "deploy":
            cmd += ["-drive", f"file={installer},format=raw,if=none,id=pe",
                    "-device", "nvme,drive=pe,serial=CRABEFI_WINPE,addr=0x4",
                    "-drive", f"file={args.iso.resolve()},format=raw,media=cdrom,readonly=on"]
        print(f"Firmware boot {number}: {' '.join(cmd)}", flush=True)
        timed_out = False
        log_path = out / f"boot-{number:02d}-serial.log"
        with log_path.open("w") as log, subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT) as vm:
            try:
                code = vm.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                capture_diagnostics(out, number)
                vm.kill()
                vm.wait()
                code, timed_out = -1, True
        text = log_path.read_text(errors="replace")
        positions = [text.find(stage) for stage in stages]
        chain = all(p >= 0 for p in positions) and positions == sorted(positions)
        marker = read_guest(disk, filename)
        rounds.append({"boot": number, "qemu_exit": code, "timed_out": timed_out,
                       "chain": chain, "marker": marker, "command": cmd})
        print(json.dumps(rounds[-1]), flush=True)
        if code == 0 and chain and marker == expected:
            passed = True
            break
        if timed_out or code != 0 or not chain or args.phase == "deploy":
            break
        print("No success marker yet; allowing Windows setup's next firmware boot", flush=True)
    names = ["deployed.txt", "deployment-stage.txt", "partition.txt", "apply-image.txt", "bcdboot.txt",
             "success.txt", "version.txt", "installation-type.txt", "environment.txt", "desktop.txt",
             "operating-system.txt", "boot-loader.txt", "task.txt"]
    evidence = {name: read_guest(disk, name) for name in names}
    for name, value in evidence.items():
        if value:
            (out / name).write_text(value + "\n")
    if args.phase == "boot":
        passed = (passed and "Client" in evidence["installation-type.txt"]
                  and "explorer" in evidence["desktop.txt"].lower()
                  and "SYSTEMDRIVE=C:" in evidence["environment.txt"])
    report = {"phase": args.phase, "passed": passed, "rounds": rounds, "evidence": evidence}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        print("Last serial lines:\n" + "\n".join(text.splitlines()[-40:]))
        raise SystemExit(1)
    print(f"PASS: installed Windows {args.phase}")


if __name__ == "__main__":
    main()
