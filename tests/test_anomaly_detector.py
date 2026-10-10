
import unittest

from src.anomaly_detector import detect_anomalies


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.baseline = {
            "devices": {
                "02:00:00:00:00:01": {
                    "fingerprint_id": "device-a",
                    "known_ip_addresses": ["192.168.1.10"],
                    "protocol_counts": {"IPv4": 1, "TCP": 1},
                    "known_ports": [443, 51000],
                    "baseline_packet_count": 2,
                    "baseline_dns_queries": [],
                }
            }
        }

    def test_unknown_device_is_detected(self):
        current = [{
            "mac_address": "02:00:00:00:00:99",
            "ip_addresses": ["192.168.1.99"],
            "protocols": ["IPv4", "TCP"],
            "ports": [22, 52000],
            "packet_count": 1,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertTrue(
            any(a["type"] == "UNKNOWN_DEVICE" for a in alerts)
        )

    def test_new_port_is_detected(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443, 8080],
            "packet_count": 1,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertTrue(
            any(a["type"] == "NEW_PORTS" for a in alerts)
        )

    def test_normal_known_device_has_no_alerts(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443, 51000],
            "packet_count": 2,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
