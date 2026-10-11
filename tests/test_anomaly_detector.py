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
                    "known_service_ports": [443],
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
            "service_ports": [22],
            "source_ports": [52000],
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
            "service_ports": [443, 8080],
            "source_ports": [],
            "packet_count": 1,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertTrue(
            any(
                a["type"] == "NEW_PORTS" and 8080 in a.get("ports", [])
                for a in alerts
            )
        )

    def test_source_port_change_does_not_trigger_new_ports(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443, 62000],
            "service_ports": [443],
            "source_ports": [62000],
            "packet_count": 2,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertFalse(
            any(a["type"] == "NEW_PORTS" for a in alerts)
        )

    def test_normal_known_device_has_no_alerts(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443, 51000],
            "service_ports": [443],
            "source_ports": [51000],
            "packet_count": 2,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, self.baseline)

        self.assertEqual(alerts, [])

    def test_high_packet_count_deviation_is_detected(self):
        baseline = {
            "devices": {
                "02:00:00:00:00:01": {
                    "known_ports": [443],
                    "known_service_ports": [443],
                    "protocol_counts": {"IPv4": 1, "TCP": 1},
                    "known_ip_addresses": ["192.168.1.10"],
                    "observation_count": 3,
                    "packet_count_min": 2,
                    "packet_count_max": 4,
                }
            }
        }

        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443],
            "service_ports": [443],
            "packet_count": 20,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, baseline)

        self.assertTrue(
            any(a["type"] == "PACKET_COUNT_DEVIATION" for a in alerts)
        )

    def test_packet_count_within_tolerance_has_no_count_alert(self):
        baseline = {
            "devices": {
                "02:00:00:00:00:01": {
                    "known_ports": [443],
                    "known_service_ports": [443],
                    "protocol_counts": {"IPv4": 1, "TCP": 1},
                    "known_ip_addresses": ["192.168.1.10"],
                    "observation_count": 3,
                    "packet_count_min": 2,
                    "packet_count_max": 4,
                }
            }
        }

        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP"],
            "ports": [443],
            "service_ports": [443],
            "packet_count": 5,
            "dns_queries": [],
        }]

        alerts = detect_anomalies(current, baseline)

        self.assertFalse(
            any(a["type"] == "PACKET_COUNT_DEVIATION" for a in alerts)
        )

    def test_new_protocol_is_detected(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10"],
            "protocols": ["IPv4", "TCP", "UDP"],
            "service_ports": [443],
            "packet_count": 2,
        }]
        alerts = detect_anomalies(current, self.baseline)
        self.assertTrue(any(
            a["type"] == "NEW_PROTOCOLS"
            and "UDP" in a.get("protocols", [])
            for a in alerts
        ))

    def test_new_ip_address_is_detected(self):
        current = [{
            "mac_address": "02:00:00:00:00:01",
            "ip_addresses": ["192.168.1.10", "192.168.1.25"],
            "protocols": ["IPv4", "TCP"],
            "service_ports": [443],
            "packet_count": 2,
        }]
        alerts = detect_anomalies(current, self.baseline)
        self.assertTrue(any(
            a["type"] == "NEW_IP_ADDRESS"
            and "192.168.1.25" in a.get("ip_addresses", [])
            for a in alerts
        ))


if __name__ == "__main__":
    unittest.main()