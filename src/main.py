
import argparse
import json
from pathlib import Path

from fingerprint import fingerprint_pcap
from baseline import (
    create_baseline,
    create_baseline_from_observations,
    save_baseline,
    load_baseline,
)
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
        help="Path to one PCAP/PCAPNG capture file",
    )

    parser.add_argument(
        "--baseline-pcaps",
        nargs="+",
        help="Three or more PCAP files for repeated-observation baseline",
    )

    parser.add_argument(
        "--mode",
        choices=["baseline", "monitor"],
        required=True,
        help="Create a baseline or compare traffic against one",
    )

    args = parser.parse_args()

    if args.mode == "baseline":
        if args.baseline_pcaps:
            if len(args.baseline_pcaps) < 3:
                parser.error(
                    "--baseline-pcaps requires at least 3 capture files."
                )

            observations = []

            for filename in args.baseline_pcaps:
                pcap_path = Path(filename)

                if not pcap_path.is_file():
                    parser.error(f"PCAP file not found: {pcap_path}")

                fingerprints = fingerprint_pcap(str(pcap_path))

                if not fingerprints:
                    parser.error(
                        f"No Ethernet MAC addresses found in {pcap_path}"
                    )

                observations.append(fingerprints)
                print(
                    f"Loaded {pcap_path}: "
                    f"{len(fingerprints)} network identities"
                )

            baseline = create_baseline_from_observations(observations)
            path = save_baseline(baseline)

            print(f"\nRepeated-observation baseline saved: {path}")
            print(f"Capture observations: {baseline['observation_count']}")
            print(f"Known devices: {len(baseline['devices'])}")

            save_json(
                baseline,
                Path("reports/baseline_report.json"),
            )
            print("Baseline report saved: reports/baseline_report.json")
            return

        if not args.pcap:
            parser.error(
                "Baseline mode requires --pcap or --baseline-pcaps."
            )

        pcap_path = Path(args.pcap)

        if not pcap_path.is_file():
            parser.error(f"PCAP file not found: {pcap_path}")

        fingerprints = fingerprint_pcap(str(pcap_path))

        if not fingerprints:
            parser.error(
                "No Ethernet MAC addresses found in this capture."
            )

        baseline = create_baseline(fingerprints)
        path = save_baseline(baseline)

        print(f"Baseline saved: {path}")
        print(
            "Warning: this baseline uses only one observation. "
            "Use --baseline-pcaps with at least 3 captures for "
            "a repeated-observation baseline."
        )

        save_json(
            fingerprints,
            Path("reports/fingerprints.json"),
        )
        print("Fingerprint report saved: reports/fingerprints.json")

    elif args.mode == "monitor":
        if not args.pcap:
            parser.error("Monitor mode requires --pcap.")

        pcap_path = Path(args.pcap)

        if not pcap_path.is_file():
            parser.error(f"PCAP file not found: {pcap_path}")

        fingerprints = fingerprint_pcap(str(pcap_path))

        if not fingerprints:
            parser.error(
                "No Ethernet MAC addresses found in this capture."
            )

        baseline = load_baseline()
        alerts = detect_anomalies(fingerprints, baseline)

        report = {
            "pcap_file": str(pcap_path),
            "observed_identities": len(fingerprints),
            "alert_count": len(alerts),
            "alerts": alerts,
        }

        save_json(report, Path("reports/anomalies.json"))

        print(f"Observed network identities: {len(fingerprints)}")
        print(f"Alerts detected: {len(alerts)}")

        for alert in alerts:
            print(
                f"[{alert['severity'].upper()}] "
                f"{alert['type']} - {alert['mac_address']}"
            )

        print("Anomaly report saved: reports/anomalies.json")


if __name__ == "__main__":
    main()
