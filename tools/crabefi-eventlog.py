#!/usr/bin/env python3
"""Print CrabEFI's boot event log (UEFI variable CrabEFIEventLog).

The variable holds a coreboot event log (ELOG, coreboot
src/commonlib/bsd/include/commonlib/bsd/elog.h): an 8-byte header ("ELOG",
version 1, header size 8, 2 reserved bytes), the events, then 0xff. An event
is type, length, BCD year (2 digits), month, day, hour, minute, second, data
and a checksum byte that makes the event sum to zero. Each boot starts with a
System boot event (0x17, little-endian u32 boot counter, time of that boot),
followed by the events coreboot handed over for that boot. CrabEFI keeps the
last 32 boots (at most 2 KiB) and only firmware writes the variable.

    sudo crabefi-eventlog.py                # read it from efivarfs
    crabefi-eventlog.py saved-variable.bin  # efivarfs copy or raw data

coreboot's elogtool reads the same data: tail -c +5 <efivarfs file> > elog.bin
and elogtool list -f elog.bin.
"""

import struct
import sys

EFIVAR = "/sys/firmware/efi/efivars/CrabEFIEventLog-9e80634c-cdc7-41d5-a345-4a297f9c7d1a"

NAMES = {
    0x08: "POST error",
    0x0B: "CPU failure",
    0x16: "Log area cleared",
    0x17: "System boot",
    0x92: "Power fail",
    0x96: "Power on",
    0x97: "Power button",
    0x98: "Power button override",
    0x99: "Reset button",
    0x9A: "System reset",
    0x9B: "RTC reset",
    0x9C: "Watchdog (TCO) reset",
    0x9D: "ACPI enter",
    0x9E: "ACPI wake",
    0x9F: "Wake source",
    0xA3: "Last POST code in previous boot",
    0xA6: "Extra info from previous boot",
    0xA7: "Sleep",
    0xA8: "Wake",
    0xAB: "CPU thermal trip",
    0xB1: "Extended event",
}

WAKE_SOURCES = {0x00: "PCIe", 0x01: "PME", 0x03: "RTC", 0x04: "GPE", 0x06: "power button",
                0x2C: "GPIO"}

# AMD FCH PMxC0 (S5/reset status), as coreboot's soc/amd/common names the bits.
PMXC0 = {0: "ThermalTrip", 1: "FourSecondPwrBtn", 2: "Shutdown", 3: "ThermalTripFromTemp",
         4: "RemotePowerDownFromASF", 5: "ShutDownFan0", 9: "InternalThermalTrip",
         16: "UserRst", 17: "SoftPciRst", 18: "DoInit", 19: "DoReset", 20: "DoFullReset",
         21: "SleepReset", 22: "KbReset", 23: "LtReset/ShutdownMsg", 24: "FailBootRst",
         25: "WatchdogIssueReset", 26: "RemoteResetFromASF", 27: "SyncFlood", 28: "HangReset",
         29: "EcWatchdogRst", 30: "SdpParityErr", 31: "SwSyncFloodFlag"}


def bcd(value):
    return (value >> 4) * 10 + (value & 0xF)


def detail(kind, data):
    if kind == 0x17 and len(data) >= 4:
        return "boot %u" % struct.unpack_from("<I", data)[0]
    if kind == 0xA6 and len(data) >= 4:
        return "0x%08x" % struct.unpack_from("<I", data)[0]
    if kind == 0xA3 and len(data) >= 2:
        return "0x%02x" % struct.unpack_from("<H", data)[0]
    if kind in (0x9D, 0x9E) and data:
        return "S%u" % data[0]
    if kind == 0x9F and len(data) >= 5:
        source, instance = struct.unpack_from("<BI", data)
        return "%s %u" % (WAKE_SOURCES.get(source, "0x%02x" % source), instance)
    if kind == 0xB1 and len(data) >= 5:
        subtype, value = struct.unpack_from("<BI", data)
        if subtype == 3:
            bits = [PMXC0.get(bit, "BIT%u" % bit) for bit in range(32) if value >> bit & 1]
            return "SoC reset status 0x%08x (AMD FCH PMxC0: %s)" % (value, " ".join(bits))
        return "subtype 0x%02x 0x%08x" % (subtype, value)
    return data.hex(" ")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else EFIVAR
    with open(path, "rb") as f:
        log = f.read()
    if log[4:8] == b"ELOG":
        log = log[4:]  # efivarfs prepends the attributes
    if len(log) < 9 or log[:6] != b"ELOG\x01\x08":
        sys.exit("%s: not an event log" % path)
    offset = 8
    while offset < len(log) and log[offset] != 0xFF:
        if offset + 9 > len(log):
            sys.exit("truncated event at offset %u" % offset)
        kind, length = log[offset], log[offset + 1]
        event = log[offset:offset + length]
        if length < 9 or len(event) != length:
            sys.exit("damaged event at offset %u" % offset)
        y, mo, d, h, mi, s = (bcd(b) for b in event[2:8])
        when = "20%02u-%02u-%02u %02u:%02u:%02u" % (y, mo, d, h, mi, s) if mo else "time unknown"
        bad = "" if sum(event) & 0xFF == 0 else "  [bad checksum]"
        text = "%s  %s" % (when, NAMES.get(kind, "type 0x%02x" % kind))
        if length > 9:
            text += ": " + detail(kind, event[8:-1])
        print(("" if kind == 0x17 else "    ") + text + bad)
        offset += length
    if offset >= len(log):
        sys.exit("no end marker: the log is truncated")


if __name__ == "__main__":
    main()
