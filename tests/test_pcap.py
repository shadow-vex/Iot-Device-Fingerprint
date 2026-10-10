
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

output = Path("data/pcap")
output.mkdir(parents=True, exist_ok=True)

packets = [
    # Simulated device A: DNS request
    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    / IP(src="192.168.1.10", dst="192.168.1.1")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com")),

    # Simulated device A: HTTPS-like TCP traffic
    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=51000, dport=443, flags="S"),

    # Simulated device B: HTTP-like TCP traffic
    Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:02")
    / IP(src="192.168.1.11", dst="192.168.1.20")
    / TCP(sport=52000, dport=80, flags="S"),
]

pcap_path = output / "sample_baseline.pcap"
wrpcap(str(pcap_path), packets)

print(f"Created simulated PCAP: {pcap_path}")
print(f"Packets written: {len(packets)}")

