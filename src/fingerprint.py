
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import json

from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, DNS


def fingerprint_pcap(pcap_path: str) -> list[dict]:
    """
    Extract traffic-based characteristics from a PCAP.

    Ports retains all observed TCP/UDP ports for backward compatibility.
    Service ports contain destination ports only.
    These observations do not guarantee a device's identity.
    """
    path = Path(pcap_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    devices = defaultdict(
        lambda: {
            "protocols": Counter(),
            "ports": Counter(),
            "service_ports": Counter(),
            "source_ports": Counter(),
            "packet_count": 0,
            "ip_addresses": set(),
            "dns_queries": set(),
        }
    )

    with PcapReader(str(path)) as packets:
        for packet in packets:
            if Ether not in packet or not packet[Ether].src:
                continue

            mac = packet[Ether].src.lower()
            device = devices[mac]

            protocols = []
            ip_address = None
            source_port = None
            destination_port = None
            dns_query = None

            if IP in packet:
                ip_address = packet[IP].src
                protocols.append("IPv4")
            elif IPv6 in packet:
                ip_address = packet[IPv6].src
                protocols.append("IPv6")

            if TCP in packet:
                protocols.append("TCP")
                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)

            elif UDP in packet:
                protocols.append("UDP")
                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)

            if source_port is not None:
                device["ports"].update([source_port])
                device["source_ports"].update([source_port])

            if destination_port is not None:
                device["ports"].update([destination_port])
                device["service_ports"].update([destination_port])

            if DNS in packet and packet[DNS].qd is not None:
                try:
                    dns_query = packet[DNS].qd.qname.decode(
                        "utf-8", errors="replace"
                    ).rstrip(".")
                except (AttributeError, UnicodeDecodeError):
                    dns_query = None

            if not protocols:
                protocols.append("Other")

            device["packet_count"] += 1
            device["protocols"].update(protocols)

            if ip_address:
                device["ip_addresses"].add(ip_address)

            if dns_query:
                device["dns_queries"].add(dns_query)

    results = []

    for mac, details in sorted(devices.items()):
        protocols = sorted(details["protocols"].keys())
        ports = sorted(details["ports"].keys())
        service_ports = sorted(details["service_ports"].keys())
        source_ports = sorted(details["source_ports"].keys())

        fingerprint_input = json.dumps(
            {
                "mac": mac,
                "protocols": protocols,
                "service_ports": service_ports,
            },
            sort_keys=True,
        )

        fingerprint_id = sha256(
            fingerprint_input.encode("utf-8")
        ).hexdigest()[:16]

        results.append({
            "fingerprint_id": fingerprint_id,
            "mac_address": mac,
            "ip_addresses": sorted(details["ip_addresses"]),
            "protocols": protocols,
            "ports": ports,
            "service_ports": service_ports,
            "source_ports": source_ports,
            "packet_count": details["packet_count"],
            "dns_queries": sorted(details["dns_queries"]),
        })

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
