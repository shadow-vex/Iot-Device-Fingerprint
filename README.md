# IoT Device Fingerprinter & Behavioral Anomaly Detection

A Python-based IoT cybersecurity prototype that extracts network fingerprints from PCAP files, builds device baselines from repeated observations, and detects selected deviations in network behavior.

> **Project status:** Prototype. Synthetic test data is used. Real IoT hardware and real-world attack detection have not yet been validated.

## Features

- Extracts network fingerprints from Ethernet traffic.
- Records MAC addresses, IP addresses, protocols, ports, and DNS queries where present.
- Separates destination service ports from source ports.
- Builds baselines from at least three traffic observations.
- Detects unknown devices and newly observed destination service ports.
- Flags selected IP, protocol, and packet-count deviations.
- Generates JSON reports.
- Validates baseline data and rejects invalid or unsafe file paths.
- Includes automated regression tests and GitHub Actions CI.

## Technology Stack

- Python
- Scapy
- PCAP / PCAPNG
- JSON
- pytest
- GitHub Actions

## Project Structure

```text
Iot-Device-Fingerprint/
├── .github/
│   └── workflows/
│       └── ci.yml
├── reports/
│   ├── accuracy_tests/
│   └── detection_accuracy_report.md
├── src/
│   ├── main.py
│   ├── fingerprint.py
│   ├── baseline.py
│   └── anomaly_detector.py
├── tests/
│   ├── anomaly_pcap.py
│   ├── generate_baseline_observations.py
│   ├── test_anomaly_detector.py
│   ├── test_baseline.py
│   ├── test_fingerprint.py
│   └── test_pcap.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Prerequisites

- Python 3.12 or a compatible supported Python version
- Git
- PowerShell on Windows

## Installation

Clone the repository:

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

Generate baseline observations:

```powershell
python tests/generate_baseline_observations.py
```

Generate simulated anomaly traffic:

```powershell
python tests/anomaly_pcap.py
```

These scripts generate synthetic test traffic. They do not capture real IoT network traffic.

## Build a Baseline

```powershell
python src/main.py --mode baseline --baseline-pcaps data/pcap/normal_observation_1.pcap data/pcap/normal_observation_2.pcap data/pcap/normal_observation_3.pcap
```

Expected outputs:

- `data/baselines/baseline.json`
- `reports/baseline_report.json`

## Monitor a Capture

After generating the baseline and synthetic anomaly PCAP:

```powershell
python src/main.py --mode monitor --pcap data/pcap/sample_anomaly.pcap
```

The anomaly report is written to `reports/anomalies.json`.

An alert indicates a deviation from the baseline; it does not prove that an attack occurred.

## Run Tests

Run the full test suite:

```powershell
python -m pytest .\tests\ -v
```

**Latest verified local result:** 19 passed, 0 failed.

GitHub Actions automatically runs the test suite for configured pushes and pull requests. Check the [Actions page](https://github.com/shadow-vex/Iot-Device-Fingerprint/actions) for the latest workflow result.

## Security and Privacy

- Capture traffic only on networks you own or are authorized to monitor.
- PCAP files and reports may contain sensitive network metadata.
- Review generated reports before sharing them.
- MAC addresses can be spoofed or randomized and are not guaranteed device identities.
- Baseline quality and network variation can affect false-positive rates.
- Dependency vulnerability scans should be repeated as dependencies change.

## Limitations

- Included test traffic is synthetic.
- Detection uses baseline comparisons and thresholds; a trained machine-learning model is not currently implemented.
- Real-device validation, performance benchmarking, and false-positive evaluation remain future work.
- Passing tests and dependency scans do not guarantee complete security.

## Roadmap

- [x] Extract network fingerprints from PCAP files.
- [x] Build baselines from repeated observations.
- [x] Detect selected behavioral deviations.
- [x] Add baseline validation and regression tests.
- [x] Configure GitHub Actions continuous integration.
- [x] Pin the Scapy dependency version.
- [ ] Expand malformed-PCAP and edge-case testing.
- [ ] Measure detection accuracy and false-positive rates.
- [ ] Validate with physical IoT hardware.
- [ ] Explore statistical or machine-learning detection.

## Contributing

Bug reports, suggestions, and improvements are welcome. Run the test suite before submitting changes.

## License

No license has been added yet. Add a suitable license before distributing this project as open-source software.

## Architecture and Demo Evidence

- [System architecture and data flow](docs/architecture.md)
- [Detection accuracy test report](reports/detection_accuracy_report.md)

The current demonstration uses synthetic traffic. See the report for test scenarios and limitations.
