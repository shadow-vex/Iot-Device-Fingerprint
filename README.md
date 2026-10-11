# IoT Device Fingerprinter & Behavioral Anomaly Detection

A Python-based IoT cybersecurity prototype that extracts network fingerprints from PCAP files, builds device baselines from repeated observations, and flags unexpected network behavior.

> **Project status:** Prototype. The supplied PCAPs are synthetic test data. Real IoT hardware and real-world attack detection have not yet been validated.

## Features

- Extracts network fingerprints from Ethernet traffic.
- Records MAC addresses, IP addresses, protocols, ports, and DNS queries where present.
- Separates destination service ports from source ports.
- Builds baselines from at least three traffic observations.
- Detects unknown devices and newly observed destination service ports.
- Flags new IP addresses, protocols, and significant packet-count deviations.
- Generates JSON reports.
- Includes automated unit tests.

## Technology Stack

- Python
- Scapy
- PCAP / PCAPNG
- JSON
- Python `unittest`

## Project Structure

```text
Iot-Device-Fingerprint/
├── data/
│   ├── baselines/
│   └── pcap/
├── reports/
├── src/
│   ├── main.py
│   ├── fingerprint.py
│   ├── baseline.py
│   └── anomaly_detector.py
├── tests/
│   ├── anomaly_pcap.py
│   ├── generate_baseline_observations.py
│   ├── test_anomaly_detector.py
│   └── test_pcap.py
├── requirements.txt
└── README.md
```

Generated PCAPs, baseline JSON files, and report JSON files are excluded from Git by `.gitignore`.

## Prerequisites

- Python installed and available as `python`
- Git
- PowerShell on Windows

## Installation

Clone the repository and open the project directory:

```powershell
git clone https://github.com/shadow-vex/Iot-Device-Fingerprint.git
cd Iot-Device-Fingerprint
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Generate Synthetic Test Data

Generate three baseline observations:

```powershell
python tests/generate_baseline_observations.py
```

Generate simulated anomaly traffic:

```powershell
python tests/anomaly_pcap.py
```

These scripts create synthetic PCAP files for testing; they do not capture real IoT traffic.

## Build a Baseline

Run:

```powershell
python src/main.py --mode baseline --baseline-pcaps data/pcap/normal_observation_1.pcap data/pcap/normal_observation_2.pcap data/pcap/normal_observation_3.pcap
```

Expected output files:

- `data/baselines/baseline.json`
- `reports/baseline_report.json`

## Monitor a Capture

After generating the baseline and synthetic anomaly PCAP, run:

```powershell
python src/main.py --mode monitor --pcap data/pcap/sample_anomaly.pcap
```

The anomaly report is written to `reports/anomalies.json`.

A detected alert indicates a deviation from the baseline. It does not, by itself, prove an attack occurred.

## Run Automated Tests

```powershell
python -m unittest discover -s tests -v
```

The test suite covers selected anomaly-detection behaviors. Passing tests do not establish real-world detection accuracy.

## Security and Privacy

- Capture traffic only on networks you own or are authorized to monitor.
- PCAPs may contain sensitive network metadata.
- Review reports before sharing them.
- MAC addresses can be spoofed or randomized and are not guaranteed device identities.
- Baseline quality and network variation can affect false-positive rates.

## Limitations

- The included PCAP files are synthetic.
- Detection is based on baseline comparisons and thresholds; a trained machine-learning model is not currently implemented.
- Real-device validation, performance benchmarking, and false-positive evaluation remain future work.

## Roadmap

- [x] Extract network fingerprints from PCAP files.
- [x] Build baselines from repeated observations.
- [x] Detect selected behavioral deviations.
- [x] Add automated unit tests for core detection logic.
- [ ] Add GitHub Actions continuous integration.
- [ ] Expand invalid-PCAP and baseline-validation tests.
- [ ] Measure detection accuracy and false-positive rates.
- [ ] Validate with physical IoT hardware.
- [ ] Explore statistical or machine-learning detection.

## Contributing

Bug reports, suggestions, and improvements are welcome. Run the test suite before submitting changes.

## License

No license has been added yet. Add a license file before distributing this project as open-source software.
