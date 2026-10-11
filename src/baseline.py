
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median


BASELINE_DIR = Path("data/baselines")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_fingerprint(item: dict) -> None:
    """Validate the required fields and basic types in a fingerprint."""
    if not isinstance(item, dict):
        raise ValueError("Each fingerprint must be a JSON object.")

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

    if not isinstance(item["mac_address"], str) or not item["mac_address"].strip():
        raise ValueError("mac_address must be a non-empty string.")

    if not isinstance(item["fingerprint_id"], str) or not item["fingerprint_id"].strip():
        raise ValueError("fingerprint_id must be a non-empty string.")

    packet_count = item["packet_count"]
    if (
        isinstance(packet_count, bool)
        or not isinstance(packet_count, int)
        or packet_count < 0
    ):
        raise ValueError("packet_count must be a non-negative integer.")

    for field in ("ip_addresses", "protocols", "ports", "dns_queries"):
        if not isinstance(item[field], list):
            raise ValueError(f"{field} must be a list.")

    for field in ("ip_addresses", "protocols", "dns_queries"):
        if not all(isinstance(value, str) for value in item[field]):
            raise ValueError(f"Every value in {field} must be a string.")

    for field in ("ports", "service_ports"):
        if field in item:
            values = item[field]
            if not isinstance(values, list):
                raise ValueError(f"{field} must be a list.")
            if any(
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 0 <= port <= 65535
                for port in values
            ):
                raise ValueError(
                    f"Every value in {field} must be an integer from 0 to 65535."
                )


def _service_ports(item: dict) -> list[int]:
    """Use destination ports when available; support older fingerprints."""
    return sorted(set(item.get("service_ports", item["ports"])))


def create_baseline(fingerprints: list[dict]) -> dict:
    """Create a backward-compatible baseline from one observation."""
    if not isinstance(fingerprints, list) or not fingerprints:
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
    """Build a baseline from multiple independent PCAP observations."""
    if not isinstance(observations, list) or len(observations) < 3:
        raise ValueError(
            "At least 3 observations are required for a behavioral baseline."
        )

    device_observations = defaultdict(list)

    for observation in observations:
        if not isinstance(observation, list) or not observation:
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

    if not device_observations:
        raise ValueError("No devices found in observations.")

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
    """Save a baseline JSON file inside the baseline directory."""
    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a JSON object.")

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Baseline filename must be a non-empty string.")

    output_dir = BASELINE_DIR.resolve()
    output_path = (BASELINE_DIR / filename).resolve()

    if not output_path.is_relative_to(output_dir):
        raise ValueError("Baseline filename must stay inside the baseline directory.")

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(baseline, indent=2),
        encoding="utf-8",
    )

    return output_path


def load_baseline(filename: str = "baseline.json") -> dict:
    """Load and validate a baseline JSON file."""
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Baseline filename must be a non-empty string.")

    baseline_dir = BASELINE_DIR.resolve()
    path = (BASELINE_DIR / filename).resolve()

    if not path.is_relative_to(baseline_dir):
        raise ValueError("Baseline filename must stay inside the baseline directory.")

    if not path.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {path}. Create one first."
        )

    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid baseline file {path}: {exc}") from exc

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a JSON object.")

    devices = baseline.get("devices")
    if not isinstance(devices, dict) or not devices:
        raise ValueError(
            "Baseline must contain a non-empty 'devices' object."
        )

    for mac, device in devices.items():
        if not isinstance(mac, str) or not mac.strip():
            raise ValueError("Each baseline device must have a non-empty MAC key.")

        if not isinstance(device, dict):
            raise ValueError(f"Baseline device {mac} must be a JSON object.")

        required_fields = {
            "fingerprint_id",
            "known_ip_addresses",
            "protocol_counts",
            "known_ports",
            "known_service_ports",
            "known_dns_queries",
        }

        missing = required_fields - device.keys()
        if missing:
            raise ValueError(
                f"Baseline device {mac} is missing fields: {sorted(missing)}"
            )

        for field in (
            "known_ip_addresses",
            "known_ports",
            "known_service_ports",
            "known_dns_queries",
        ):
            if not isinstance(device[field], list):
                raise ValueError(
                    f"Baseline device {mac}: {field} must be a list."
                )

        if not isinstance(device["protocol_counts"], dict):
            raise ValueError(
                f"Baseline device {mac}: protocol_counts must be an object."
            )

        for field in ("observation_count", "baseline_packet_count",
                      "packet_count_min", "packet_count_max"):
            if field in device:
                value = device[field]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(
                        f"Baseline device {mac}: {field} must be numeric."
                    )
                if value < 0:
                    raise ValueError(
                        f"Baseline device {mac}: {field} cannot be negative."
                    )

    return baseline


if __name__ == "__main__":
    print("Baseline engine loaded successfully.")
    print(f"Baseline storage: {BASELINE_DIR}")
