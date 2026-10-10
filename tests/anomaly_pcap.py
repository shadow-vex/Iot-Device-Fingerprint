
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

output = Path("data/pcap")
output.mkdir(parents=True, exist_ok=True)

packets = [
    # Known simulated device A using a new port: 8080
    Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=51000, dport=8080, flags="S"),

    # Unknown simulated device C
    Ether(src="02:00:00:00:00:04", dst="02:00:00:00:00:02")
    / IP(src="192.168.1.12", dst="192.168.1.20")
    / TCP(sport=53000, dport=22, flags="S"),
]

pcap_path = output / "sample_anomaly.pcap"
wrpcap(str(pcap_path), packets)

print(f"Created simulated anomaly PCAP: {pcap_path}")
print(f"Packets written: {len(packets)}")

