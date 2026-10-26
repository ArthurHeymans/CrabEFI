#!/usr/bin/env python3
"""Provision the experiment's erased first MiB as a bounded QEMU variable region."""
import argparse
import struct
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rom", type=Path)
    parser.add_argument("vars", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite output flash")
    data = bytearray(args.rom.read_bytes())
    variables = args.vars.read_bytes()
    if len(data) != 0x800000 or data[0x100000:0x100008] != b"__FMAP__":
        parser.error("expected 8-MiB q35 experiment ROM with FMAP at 1 MiB")
    if len(variables) > 0x100000 or variables[40:44] != b"_FVH":
        parser.error("expected an EDK2 variable firmware volume smaller than 1 MiB")
    if any(byte != 255 for byte in data[:0x100000]):
        parser.error("first MiB is not erased; refusing to replace firmware bytes")
    count = struct.unpack_from("<H", data, 0x100000 + 54)[0]
    offset = 0x100000 + 56 + 42 * count
    if offset + 42 > 0x101000 or data[offset:offset+42] != bytes([255]) * 42:
        parser.error("FMAP has no erased area slot")
    for i in range(count):
        start, size, name, _ = struct.unpack_from("<II32sH", data, 0x100000 + 56 + 42*i)
        if start < 0x100000 and size:
            parser.error(f"existing FMAP area overlaps new variable region: {name!r}")
    data[offset:offset+42] = struct.pack("<II32sH", 0, 0x100000, b"SMMSTORE", 0)
    struct.pack_into("<H", data, 0x100000 + 54, count + 1)
    data[:len(variables)] = variables
    args.output.write_bytes(data)
    print(f"Provisioned {args.output}: SMMSTORE [0, 1 MiB), code unchanged")


if __name__ == "__main__":
    main()
