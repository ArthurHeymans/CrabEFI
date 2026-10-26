"""Focused checks for the kexec wrapper's executable and reservation layout."""
import struct
import unittest

from pack import ARENA_SIZE, BASE, pack


def payload(address=0x100000):
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, address, 64,
                         0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 4096, address, address, 4, 8192, 4096)
    return (header + segment).ljust(4096, b"\0") + b"test"


class PackTests(unittest.TestCase):
    def test_preserves_payload_and_reserves_wrapper_arena(self):
        result = pack(payload(), bytes(12) + b"wrapper")
        self.assertEqual(result[:7], b"\x7fELF\x01\x01\x01")
        header = struct.unpack_from("<16sHHIIIIIHHHHHH", result)
        self.assertEqual(header[4], BASE + 12)
        self.assertEqual(header[10], 2)
        wrapper, image = (struct.unpack_from("<IIIIIIII", result, 52 + 32*i) for i in range(2))
        self.assertEqual(wrapper[2:6], (BASE, BASE, 19, ARENA_SIZE))
        self.assertEqual(image[2:6], (0x100000, 0x100000, 4, 8192))
        self.assertEqual(result[image[1]:image[1] + image[4]], b"test")
        self.assertEqual(wrapper[1], 4096)  # Multiboot header must be within first 8 KiB.

    def test_rejects_payload_overlapping_handoff_arena(self):
        with self.assertRaises(ValueError):
            pack(payload(BASE), b"wrapper")

    def test_rejects_truncated_segment(self):
        with self.assertRaises(ValueError):
            pack(payload()[:-1], b"wrapper")

    def test_rejects_wrong_architecture(self):
        data = bytearray(payload())
        struct.pack_into("<H", data, 18, 183)
        with self.assertRaises(ValueError):
            pack(bytes(data), b"wrapper")


if __name__ == "__main__":
    unittest.main()
