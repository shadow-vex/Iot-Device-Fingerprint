
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.baseline import (
    create_baseline,
    create_baseline_from_observations,
    load_baseline,
    save_baseline,
)


def make_fingerprint(mac="02:00:00:00:00:01", packet_count=2):
    return {
        "mac_address": mac,
        "fingerprint_id": "test-device",
        "ip_addresses": ["192.168.1.10"],
        "protocols": ["IPv4", "TCP"],
        "ports": [443],
        "service_ports": [443],
        "packet_count": packet_count,
        "dns_queries": [],
    }


class TestBaseline(unittest.TestCase):

    def test_create_baseline_from_one_observation(self):
        baseline = create_baseline([make_fingerprint()])
        self.assertIn("02:00:00:00:00:01", baseline["devices"])

    def test_empty_fingerprints_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "No fingerprints"):
            create_baseline([])

    def test_duplicate_mac_is_rejected(self):
        fingerprint = make_fingerprint()

        with self.assertRaisesRegex(ValueError, "Duplicate device MAC"):
            create_baseline([fingerprint, fingerprint])

    def test_negative_packet_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "packet_count"):
            create_baseline([make_fingerprint(packet_count=-1)])

    def test_repeated_baseline_requires_three_observations(self):
        observations = [
            [make_fingerprint()],
            [make_fingerprint()],
        ]

        with self.assertRaisesRegex(ValueError, "At least 3 observations"):
            create_baseline_from_observations(observations)

    def test_repeated_baseline_accepts_three_observations(self):
        observations = [
            [make_fingerprint(packet_count=2)],
            [make_fingerprint(packet_count=4)],
            [make_fingerprint(packet_count=6)],
        ]

        baseline = create_baseline_from_observations(observations)
        device = baseline["devices"]["02:00:00:00:00:01"]

        self.assertEqual(device["observation_count"], 3)
        self.assertEqual(device["packet_count_min"], 2)
        self.assertEqual(device["packet_count_max"], 6)

    def test_corrupted_baseline_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_dir = Path(temp_dir) / "data" / "baselines"
            baseline_dir.mkdir(parents=True)

            (baseline_dir / "baseline.json").write_text(
                '{"devices": invalid}',
                encoding="utf-8",
            )

            with patch("src.baseline.BASELINE_DIR", baseline_dir):
                with self.assertRaisesRegex(
                    ValueError, "Invalid baseline file"
                ):
                    load_baseline()

    def test_load_baseline_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_dir = Path(temp_dir) / "baselines"
            baseline_dir.mkdir()

            with patch("src.baseline.BASELINE_DIR", baseline_dir):
                with self.assertRaisesRegex(
                    ValueError, "must stay inside"
                ):
                    load_baseline("../outside.json")

    def test_save_baseline_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline_dir = Path(temp_dir) / "baselines"

            with patch("src.baseline.BASELINE_DIR", baseline_dir):
                with self.assertRaisesRegex(
                    ValueError, "must stay inside"
                ):
                    save_baseline({"devices": {}}, "../outside.json")


if __name__ == "__main__":
    unittest.main()
