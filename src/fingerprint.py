from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import json

from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, DNS


def fingerprint_pcap(pcap_path: str) -> list[dict]:
    """
    Extract observed network characteristics from a PCAP file.
    These are traffic-based fingerprints, not guaranteed device identities.
    """
    path = Path(pcap_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    devices = defaultdict(
        lambda: {
            "protocols": Counter(),
            "ports": Counter(),
            "packet_count": 0,
            "ip_addresses": set(),
            "dns_queries": set(),
        }
    )

    with PcapReader(str(path)) as packets:
        for packet in packets:
            mac_addresses = set()

            if Ether in packet:
                if packet[Ether].src:
                    mac_addresses.add(packet[Ether].src.lower())
                if not mac_addresses:
                    continue

            protocols = []
            ip_address = None
            ports = []
            dns_query = None

            if IP in packet:
                ip_address = packet[IP].src
                protocols.append("IPv4")
            elif IPv6 in packet:
                ip_address = packet[IPv6].src
                protocols.append("IPv6")

            if TCP in packet:
                protocols.append("TCP")
                ports.append(int(packet[TCP].sport))
                ports.append(int(packet[TCP].dport))

            if UDP in packet:
                protocols.append("UDP")
                ports.append(int(packet[UDP].sport))
                ports.append(int(packet[UDP].dport))

            if DNS in packet and packet[DNS].qd is not None:
                try:
                    dns_query = packet[DNS].qd.qname.decode(
                        "utf-8", errors="replace"
                    ).rstrip(".")
                except (AttributeError, UnicodeDecodeError):
                    dns_query = None

            if not protocols:
                protocols.append("Other")

            for mac in mac_addresses:
                device = devices[mac]
                device["packet_count"] += 1
                device["protocols"].update(protocols)
                device["ports"].update(ports)

                if ip_address:
                    device["ip_addresses"].add(ip_address)

                if dns_query:
                    device["dns_queries"].add(dns_query)

    results = []

    for mac, details in sorted(devices.items()):
        protocols = sorted(details["protocols"].keys())
        ports = sorted(details["ports"].keys())

        # Stable identifier derived from observed MAC + protocol + port set.
        fingerprint_input = json.dumps(
            {"mac": mac, "protocols": protocols, "ports": ports},
            sort_keys=True,
        )
        fingerprint_id = sha256(
            fingerprint_input.encode("utf-8")
        ).hexdigest()[:16]

        results.append(
            {
                "fingerprint_id": fingerprint_id,
                "mac_address": mac,
                "ip_addresses": sorted(details["ip_addresses"]),
                "protocols": protocols,
                "ports": ports,
                "packet_count": details["packet_count"],
                "dns_queries": sorted(details["dns_queries"]),
            }
        )

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract observed device fingerprints from a PCAP."
    )
    parser.add_argument("pcap", help="Path to a PCAP or PCAPNG file")
    parser.add_argument(
        "--output",
        default="reports/fingerprints.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    fingerprints = fingerprint_pcap(args.pcap)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(fingerprints, indent=2),
        encoding="utf-8",
    )

    print(f"Observed network identities: {len(fingerprints)}")
    print(f"Fingerprint report saved to: {output_path}")

