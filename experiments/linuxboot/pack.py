#!/usr/bin/env python3
"""Wrap the fixed-address x86-64 coreboot ELF for kexec's ELF32 Multiboot loader."""
import argparse
import struct
import subprocess
import tempfile
from pathlib import Path

BASE = 0x08000000
ARENA_SIZE = 0x100000


def pack(payload: bytes, wrapper: bytes) -> bytes:
    if payload[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", payload)
    if header[1:4] != (2, 62, 1) or header[9] != 56:
        raise ValueError("expected executable x86-64 ELF with standard program headers")
    segments = []
    for i in range(header[10]):
        kind, flags, offset, virt, phys, size, memory, align = struct.unpack_from(
            "<IIQQQQQQ", payload, header[5] + i * header[9]
        )
        if kind != 1:
            continue
        if (virt != phys or size > memory or offset + size > len(payload)
                or phys + memory > 2**32 or phys < BASE + ARENA_SIZE and phys + memory > BASE):
            raise ValueError("unsupported or overlapping load segment")
        segments.append((phys, memory, flags, payload[offset:offset + size]))
    if not segments or not any(p <= header[4] < p + n for p, n, _, _ in segments):
        raise ValueError("entry point is not in a load segment")
    if len(wrapper) > 0x4000:
        raise ValueError("wrapper overlaps stack/handoff")
    segments.insert(0, (BASE, ARENA_SIZE, 7, wrapper))
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    # The first 12 bytes of the wrapper are the Multiboot header.
    result = bytearray(struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 3, 1, BASE + 12,
                                   52, 0, 0, 52, 32, len(segments), 0, 0, 0))
    offset = 4096
    chunks = []
    for phys, memory, flags, data in segments:
        result.extend(struct.pack("<IIIIIIII", 1, offset, phys, phys,
                                  len(data), memory, flags, 4096))
        chunks.append((offset, data))
        offset = (offset + len(data) + 4095) & ~4095
    for offset, data in chunks:
        result.extend(bytes(offset - len(result)))
        result.extend(data)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    payload = args.payload.read_bytes()
    entry = struct.unpack_from("<Q", payload, 24)[0]
    with tempfile.TemporaryDirectory() as work:
        obj, binary = Path(work) / "wrapper.o", Path(work) / "wrapper.bin"
        subprocess.run(["cc", "-m32", "-c", f"-DPAYLOAD_ENTRY={entry}",
                        str(Path(__file__).with_name("multiboot.S")), "-o", str(obj)], check=True)
        subprocess.run(["objcopy", "-O", "binary", "-j", ".text", str(obj), str(binary)], check=True)
        args.output.write_bytes(pack(payload, binary.read_bytes()))
    print(f"Packed {args.output}; wrapper/stack/handoff reserved at {BASE:#x}..{BASE + ARENA_SIZE:#x}")


if __name__ == "__main__":
    main()
