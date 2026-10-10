\# IoT Device Fingerprinter



A Python-based IoT cybersecurity prototype that extracts network fingerprints from PCAP files, stores observed device baselines, and flags unexpected network changes.



\## Features



\- Extracts source MAC addresses from Ethernet packets.

\- Records observed IP addresses, protocols, ports, and DNS queries.

\- Saves device fingerprints and baseline data as JSON.

\- Detects previously unseen MAC addresses.

\- Flags newly observed ports and IP addresses.

\- Generates anomaly reports.

\- Includes automated unit tests.



\## Technology Stack



\- Python

\- Scapy

\- PCAP / PCAPNG

\- JSON

\- Python unittest



\## Project Structure



```text

IoT-Device-Fingerprint/

├── data/

│   ├── pcap/

│   └── baselines/

├── reports/

├── src/

│   ├── main.py

│   ├── fingerprint.py

│   ├── baseline.py

│   └── anomaly\_detector.py

├── tests/

│   ├── create\_test\_pcap.py

│   ├── create\_anomaly\_pcap.py

│   └── test\_anomaly\_detector.py

├── requirements.txt

└── README.md

```



\## Setup



Create and activate a virtual environment:



```powershell

python -m venv .venv

.venv\\Scripts\\Activate.ps1

```



Install dependencies:



```powershell

python -m pip install -r requirements.txt

```



\## Run the Simulation



Create sample baseline traffic:



```powershell

python tests\\create\_test\_pcap.py

```



Create the baseline:



```powershell

python src\\main.py --pcap data\\pcap\\sample\_baseline.pcap --mode baseline

```



Create simulated anomaly traffic:



```powershell

python tests\\create\_anomaly\_pcap.py

```



Monitor the simulated traffic:



```powershell

python src\\main.py --pcap data\\pcap\\sample\_anomaly.pcap --mode monitor

```



\## Run Automated Tests



```powershell

python -m unittest discover -s tests -p "test\_anomaly\_detector.py" -v

```



\## Output Files



\- `data/baselines/baseline.json` — saved baseline.

\- `reports/fingerprints.json` — extracted fingerprints.

\- `reports/anomalies.json` — detected changes.



\## Limitations



This is an early-stage prototype. The included tests use simulated PCAP traffic and do not prove detection of real IoT hardware or real attacks. A MAC address is not a guaranteed device identity. Baseline quality, network capture support, false-positive handling, and real-device validation require further development.



\## Future Enhancements



\- Collect repeated observations over time.

\- Measure packet rates and traffic intervals.

\- Add statistical or machine-learning anomaly detection.

\- Build a monitoring dashboard.

\- Validate with physical IoT hardware such as an ESP32.

\- Add more automated tests and deployment documentation.



