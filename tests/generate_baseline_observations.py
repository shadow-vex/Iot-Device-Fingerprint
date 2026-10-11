
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap


OUTPUT_DIR = Path("data/pcap")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Synthetic test fixtures only; not captured from a real network.
for observation in range(1, 4):
    packets = [
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / UDP(sport=53000 + observation, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname=f"example{observation}.com"),
        ),

        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=51000 + observation, dport=443, flags="S"),

        Ether(
            src="02:00:00:00:00:03",
            dst="02:00:00:00:00:02",
        )
        / IP(src="192.168.1.11", dst="192.168.1.20")
        / TCP(sport=52000 + observation, dport=80, flags="S"),
    ]

    output_path = OUTPUT_DIR / f"normal_observation_{observation}.pcap"
    wrpcap(str(output_path), packets)

    print(f"Created: {output_path} ({len(packets)} packets)")

print("Synthetic baseline observations generated.")
