
import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter


BASELINE_DIR = Path("data/baselines")


def create_baseline(fingerprints: list[dict]) -> dict:
    """
    Create an initial baseline from observed PCAP fingerprints.
    This is a first prototype; reliable baselines need repeated observations.
    """
    if not fingerprints:
        raise ValueError("No fingerprints available to create a baseline.")

    devices = {}

    for item in fingerprints:
        mac = item["mac_address"]

        devices[mac] = {
            "fingerprint_id": item["fingerprint_id"],
            "known_ip_addresses": sorted(set(item["ip_addresses"])),
            "protocol_counts": dict(Counter(item["protocols"])),
            "known_ports": sorted(set(item["ports"])),
            "baseline_packet_count": item["packet_count"],
            "baseline_dns_queries": sorted(set(item["dns_queries"])),
        }

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "baseline_version": 1,
        "source": "PCAP observation",
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
