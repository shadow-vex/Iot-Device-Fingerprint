import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median


BASELINE_DIR = Path("data/baselines")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_fingerprint(item: dict) -> None:
    required = {
        "mac_address",
        "fingerprint_id",
        "ip_addresses",
        "protocols",
        "ports",
        "packet_count",
        "dns_queries",
    }

    missing = required - item.keys()
    if missing:
        raise ValueError(
            f"Fingerprint missing required fields: {sorted(missing)}"
        )

    if not isinstance(item["packet_count"], int) or item["packet_count"] < 0:
        raise ValueError("packet_count must be a non-negative integer.")


def _service_ports(item: dict) -> list[int]:
    """Use destination ports when available; support older fingerprints."""
    return sorted(set(item.get("service_ports", item["ports"])))


def create_baseline(fingerprints: list[dict]) -> dict:
    """Create a backward-compatible baseline from one observation."""
    if not fingerprints:
        raise ValueError("No fingerprints available to create a baseline.")

    devices = {}

    for item in fingerprints:
        _validate_fingerprint(item)
        mac = item["mac_address"].lower()

        if mac in devices:
            raise ValueError(f"Duplicate device MAC in observation: {mac}")

        devices[mac] = {
            "fingerprint_id": item["fingerprint_id"],
            "known_ip_addresses": sorted(set(item["ip_addresses"])),
            "protocol_counts": dict(Counter(item["protocols"])),
            "known_ports": sorted(set(item["ports"])),
            "known_service_ports": _service_ports(item),
            "known_dns_queries": sorted(set(item["dns_queries"])),
            "baseline_packet_count": item["packet_count"],
            "observation_count": 1,
            "packet_count_median": item["packet_count"],
            "packet_count_min": item["packet_count"],
            "packet_count_max": item["packet_count"],
        }

    return {
        "created_at": _timestamp(),
        "baseline_version": 3,
        "source": "PCAP observation",
        "observation_count": 1,
        "devices": devices,
    }


def create_baseline_from_observations(
    observations: list[list[dict]],
) -> dict:
    """
    Build a baseline from multiple independent PCAP observations.
    Capture windows should have comparable durations.
    """
    if len(observations) < 3:
        raise ValueError(
            "At least 3 observations are required for a behavioral baseline."
        )

    device_observations = defaultdict(list)

    for observation in observations:
        if not observation:
            raise ValueError("An observation contains no fingerprints.")

        seen_macs = set()

        for item in observation:
            _validate_fingerprint(item)
            mac = item["mac_address"].lower()

            if mac in seen_macs:
                raise ValueError(
                    f"Duplicate device MAC in observation: {mac}"
                )

            seen_macs.add(mac)
            device_observations[mac].append(item)

    devices = {}

    for mac, records in sorted(device_observations.items()):
        packet_counts = [record["packet_count"] for record in records]

        all_ips = set()
        all_ports = set()
        all_service_ports = set()
        all_dns = set()
        protocol_counts = Counter()

        for record in records:
            all_ips.update(record["ip_addresses"])
            all_ports.update(record["ports"])
            all_service_ports.update(_service_ports(record))
            all_dns.update(record["dns_queries"])
            protocol_counts.update(set(record["protocols"]))

        devices[mac] = {
            "fingerprint_id": records[-1]["fingerprint_id"],
            "known_ip_addresses": sorted(all_ips),
            "protocol_counts": dict(protocol_counts),
            "known_ports": sorted(all_ports),
            "known_service_ports": sorted(all_service_ports),
            "known_dns_queries": sorted(all_dns),
            "observation_count": len(records),
            "packet_count_median": median(packet_counts),
            "packet_count_min": min(packet_counts),
            "packet_count_max": max(packet_counts),
            "baseline_packet_count": int(median(packet_counts)),
        }

    return {
        "created_at": _timestamp(),
        "baseline_version": 3,
        "source": "Repeated PCAP observations",
        "observation_count": len(observations),
        "devices": devices,
    }


def save_baseline(baseline: dict, filename: str = "baseline.json") -> Path:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    output_path = BASELINE_DIR / filename

    output_path.write_text(
        json.dumps(baseline, indent=2),
        encoding="utf-8",
    )

    return output_path


def load_baseline(filename: str = "baseline.json") -> dict:
    path = BASELINE_DIR / filename

    if not path.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {path}. Create one first."
        )

    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    print("Baseline engine loaded successfully.")
    print(f"Baseline storage: {BASELINE_DIR}")