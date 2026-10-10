
from datetime import datetime, timezone


def detect_anomalies(
    current_fingerprints: list[dict],
    baseline: dict,
) -> list[dict]:
    """
    Compare current PCAP fingerprints with a saved baseline.
    Flags observable differences; these are not automatically attacks.
    """
    alerts = []
    known_devices = baseline.get("devices", {})

    for device in current_fingerprints:
        mac = device["mac_address"]
        known = known_devices.get(mac)

        if known is None:
            alerts.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "severity": "medium",
                "type": "UNKNOWN_DEVICE",
                "mac_address": mac,
                "message": "Device MAC was not present in the saved baseline.",
            })
            continue

        baseline_ports = set(known.get("known_ports", []))
        current_ports = set(device.get("ports", []))
        new_ports = sorted(current_ports - baseline_ports)

        if new_ports:
            alerts.append({
                "time": datetime.now(timezone.utc).isoformat(),
                "severity": "medium",
                "type": "NEW_PORTS",
                "mac_address": mac,
                "ports": new_ports,
                "message": "New port numbers observed compared with baseline.",
            })

        baseline_protocols = set(
            known.get("protocol_counts", {}).keys()
        )
        current_protocols = set(device.get("protocols", []))
        new_protocols = sorted(current_protocols - baseline_protocols)

        if new_protocols:
            alerts.append({
                "time": datetime.now(timezone.utc).isoformat(),
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
                "time": datetime.now(timezone.utc).isoformat(),
                "severity": "low",
                "type": "NEW_IP_ADDRESS",
                "mac_address": mac,
                "ip_addresses": new_ips,
                "message": "New IP address observed for this MAC.",
            })

    return alerts


if __name__ == "__main__":
    print("Anomaly detector loaded successfully.")

