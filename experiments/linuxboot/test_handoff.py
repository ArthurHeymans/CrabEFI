"""Check both SMBIOS entry formats, physical relocation and checksum rejection."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.work.name) / "test-handoff"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(Path(__file__).with_suffix(".c")), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_smbios_3_staging(self):
        subprocess.run([str(self.binary), "3"], check=True)

    def test_smbios_2_staging(self):
        subprocess.run([str(self.binary), "2"], check=True)

    def test_invalid_entry_is_rejected(self):
        result = subprocess.run([str(self.binary), "0"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported SMBIOS entry point", result.stderr)


if __name__ == "__main__":
    unittest.main()
