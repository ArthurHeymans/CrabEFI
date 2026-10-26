"""Ensure flash provisioning cannot overwrite code or a non-erased variable arena."""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class FlashTests(unittest.TestCase):
    def run_fixture(self, occupied=False, overlap=False):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            rom = bytearray(b"\xff" * 0x800000)
            header = struct.pack("<8sBBQI32sH", b"__FMAP__", 1, 1, 0, len(rom), b"FLASH", 1)
            rom[0x100000:0x100000+56] = header
            rom[0x100038:0x100038+42] = struct.pack("<II32sH", 0x80000 if overlap else 0x100000,
                                                       0x700000, b"BIOS", 1)
            rom[0x101000:0x101004] = b"CODE"
            if occupied:
                rom[0] = 0
            variables = bytearray(64)
            variables[40:44] = b"_FVH"
            (root / "rom").write_bytes(rom)
            (root / "vars").write_bytes(variables)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("prepare-security-flash.py")),
                                     str(root / "rom"), str(root / "vars"), str(root / "output")],
                                    capture_output=True, text=True)
            output = (root / "output").read_bytes() if (root / "output").exists() else None
            self.assertEqual((root / "rom").read_bytes(), rom)
            return result, output, rom, variables

    def test_only_variable_arena_and_fmap_are_changed(self):
        result, output, original, variables = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(output)
        assert output is not None
        self.assertEqual(output[:len(variables)], variables)
        self.assertEqual(output[0x101000:], original[0x101000:])
        self.assertEqual(struct.unpack_from("<H", output, 0x100000 + 54)[0], 2)
        self.assertEqual(struct.unpack_from("<II", output, 0x100000 + 56 + 42), (0, 0x100000))

    def test_rejects_non_erased_arena(self):
        result, output, _, _ = self.run_fixture(occupied=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(output)

    def test_rejects_overlapping_region(self):
        result, output, _, _ = self.run_fixture(overlap=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(output)


if __name__ == "__main__":
    unittest.main()
