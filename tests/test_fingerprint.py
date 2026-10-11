import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.fingerprint import fingerprint_pcap


class TestFingerprintPcap(unittest.TestCase):

    def test_empty_pcap_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_pcap = Path(temp_dir) / "empty.pcap"
            empty_pcap.touch()

            with self.assertRaisesRegex(
                ValueError, "Invalid or unreadable PCAP file"
            ):
                fingerprint_pcap(str(empty_pcap))

    def test_corrupted_pcap_raises_clear_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            corrupted_pcap = Path(temp_dir) / "corrupted.pcap"
            corrupted_pcap.write_bytes(b"Invalid PCAP test data")

            with self.assertRaisesRegex(
                ValueError, "Invalid or unreadable PCAP file"
            ):
                fingerprint_pcap(str(corrupted_pcap))


if __name__ == "__main__":
    unittest.main()
