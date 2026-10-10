
import argparse
import json
from pathlib import Path

from fingerprint import fingerprint_pcap
from baseline import create_baseline, save_baseline, load_baseline
from anomaly_detector import detect_anomalies


def save_json(data: object, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IoT Device Fingerprinter and Behavior Monitor"
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to a PCAP/PCAPNG capture file",
    )

    parser.add_argument(
        "--mode",
        choices=["baseline", "monitor"],
        required=True,
        help="Create a baseline or compare traffic against one",
    )

    args = parser.parse_args()
    pcap_path = Path(args.pcap)

    fingerprints = fingerprint_pcap(str(pcap_path))

    if not fingerprints:
        print("No Ethernet MAC addresses found in this capture.")
        return

    print(f"\nObserved network identities: {len(fingerprints)}")

    if args.mode == "baseline":
        baseline = create_baseline(fingerprints)
        path = save_baseline(baseline)
        print(f"Baseline saved: {path}")

        save_json(
            fingerprints,
            Path("reports/fingerprints.json"),
        )
        print("Fingerprint report saved: reports/fingerprints.json")

    elif args.mode == "monitor":
        baseline = load_baseline()
        alerts = detect_anomalies(fingerprints, baseline)

        report = {
            "pcap_file": str(pcap_path),
            "observed_identities": len(fingerprints),
            "alert_count": len(alerts),
            "alerts": alerts,
        }

        save_json(report, Path("reports/anomalies.json"))

        print(f"Alerts detected: {len(alerts)}")

        for alert in alerts:
            print(
                f"[{alert['severity'].upper()}] "
                f"{alert['type']} - {alert['mac_address']}"
            )

        print("Anomaly report saved: reports/anomalies.json")


if __name__ == "__main__":
    main()

