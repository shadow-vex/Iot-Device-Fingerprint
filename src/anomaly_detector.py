from datetime import datetime, timezone


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_anomalies(
    current_fingerprints: list[dict],
    baseline: dict,
) -> list[dict]:
    """
    Detect observable differences from a saved device baseline.
    Alerts indicate deviations, not confirmed attacks.
    """
    alerts = []
    known_devices = baseline.get("devices", {})

    for device in current_fingerprints:
        mac = device["mac_address"].lower()
        known = known_devices.get(mac)

        if known is None:
            alerts.append({
                "time": _timestamp(),
                "severity": "medium",
                "type": "UNKNOWN_DEVICE",
                "mac_address": mac,
                "message": "Device MAC was not present in the saved baseline.",
            })
            continue

        # Prefer destination service ports. Fall back for older baselines
        # and fingerprints that do not contain service_ports yet.
        baseline_ports = set(
            known.get("known_service_ports", known.get("known_ports", []))
        )
        current_ports = set(
            device.get("service_ports", device.get("ports", []))
        )
        new_ports = sorted(current_ports - baseline_ports)

        if new_ports:
            alerts.append({
                "time": _timestamp(),
                "severity": "medium",
                "type": "NEW_PORTS",
                "mac_address": mac,
                "ports": new_ports,
                "message": (
                    "New destination service ports observed compared "
                    "with baseline."
                ),
            })

        baseline_protocols = set(known.get("protocol_counts", {}).keys())
        current_protocols = set(device.get("protocols", []))
        new_protocols = sorted(current_protocols - baseline_protocols)

        if new_protocols:
            alerts.append({
                "time": _timestamp(),
                "severity": "low",
                "type": "NEW_PROTOCOLS",
                "mac_address": mac,
                "protocols": new_protocols,
                "message": "New protocol labels observed compared with baseline.",
            })

        baseline_ips = set(known.get("known_ip_addresses", []))
        current_ips = set(device.get("ip_addresses", []))
        new_ips = sorted(current_ips - baseline_ips)

        if new_ips:
            alerts.append({
                "time": _timestamp(),
                "severity": "low",
                "type": "NEW_IP_ADDRESS",
                "mac_address": mac,
                "ip_addresses": new_ips,
                "message": "New IP address observed for this MAC.",
            })

        # Compare packet counts only with repeated-observation baselines.
        if known.get("observation_count", 1) >= 3:
            current_count = device.get("packet_count")
            minimum = known.get("packet_count_min")
            maximum = known.get("packet_count_max")

            if (
                isinstance(current_count, int)
                and isinstance(minimum, (int, float))
                and isinstance(maximum, (int, float))
            ):
                lower_limit = max(0, minimum * 0.5)
                upper_limit = max(maximum * 1.5, maximum + 2)

                if current_count < lower_limit or current_count > upper_limit:
                    alerts.append({
                        "time": _timestamp(),
                        "severity": "medium",
                        "type": "PACKET_COUNT_DEVIATION",
                        "mac_address": mac,
                        "current_packet_count": current_count,
                        "baseline_packet_count_min": minimum,
                        "baseline_packet_count_max": maximum,
                        "message": (
                            "Packet count deviates from the observed baseline. "
                            "Confirm capture durations are comparable."
                        ),
                    })

    return alerts


if __name__ == "__main__":
    print("Anomaly detector loaded successfully.")