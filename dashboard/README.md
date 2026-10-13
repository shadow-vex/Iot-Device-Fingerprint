# IoT Device Fingerprinter & Behavioral Anomaly Detection

A cybersecurity prototype that identifies devices from network traffic, builds behavioral baselines, and flags unexpected activity using rule-based anomaly detection.

> **Project status:** Prototype. The included PCAP data is for demonstration and testing. The system has not yet been validated against physical IoT devices or real-world attacks.

## Key Features

- Extract device fingerprints from PCAP network traffic.
- Identify devices using MAC addresses and observed IP addresses.
- Track protocols, DNS queries, and network ports.
- Build baselines from repeated device observations.
- Detect unknown devices and unexpected destination service ports.
- Flag new IP addresses, new protocols, and significant packet-count deviations.
- Expose fingerprints and anomaly reports through a FastAPI backend.
- Display device information and alerts in a React dashboard.
- Run automated tests for core fingerprinting and anomaly-detection logic.

## Technology Stack

**Backend and analysis**
- Python
- FastAPI
- Scapy
- PCAP
- JSON

**Frontend**
- React
- TypeScript
- Vite

**Testing**
- pytest
- Python unittest

## Architecture

1. **PCAP input:** Network packets are provided through capture files.
2. **Fingerprinting:** The analysis extracts device and network characteristics.
3. **Baseline generation:** Repeated observations establish known device behavior.
4. **Anomaly detection:** Rule-based checks identify deviations from the baseline.
5. **API:** FastAPI exposes health, report, anomaly, and fingerprint endpoints.
6. **Dashboard:** React presents device information and detected alerts.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API status |
| GET | `/api/health` | Health check |
| GET | `/api/report` | Analysis report |
| GET | `/api/anomalies` | Anomaly findings |
| GET | `/api/fingerprints` | Device fingerprints |

Base URL for local development: `http://127.0.0.1:8000`

## Requirements

- Python with a compatible version for the installed dependencies
- Node.js and npm
- Git

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/shadow-vex/Iot-Device-Fingerprint.git
cd Iot-Device-Fingerprint
```

### 2. Set up the Python environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Start the backend

From the project root:

```powershell
python -m uvicorn api_server:app --reload
```

The API should be available at `http://127.0.0.1:8000`.

### 4. Start the dashboard

Open a second PowerShell terminal:

```powershell
cd dashboard
npm install
npm run dev
```

Open the local URL printed by Vite in the terminal.

### 5. Run tests

From the project root, with the Python virtual environment activated:

```powershell
python -m pytest -q
```

## Current Verification

The development environment has reported:
- 19 automated tests passing.
- 8 anomaly-detector tests passing separately.
- Successful API responses for health, report, anomalies, and fingerprints.
- Successful TypeScript and Vite production build.

These are development test results, not a claim of real-world detection accuracy.

## Limitations

- Current anomaly detection is rule-based; a trained machine-learning detector has not been verified as part of this implementation.
- Sample PCAP data is used for demonstration.
- Physical IoT hardware testing has not yet been completed.
- Detection results depend on the quality of the captured traffic and baseline data.

## Future Improvements

- Validate detection with physical IoT devices and additional representative traffic.
- Improve baseline management and detection evaluation.
- Add documented test datasets and reproducible demonstrations.
- Evaluate machine-learning approaches against the existing rule-based detector.

## Disclaimer

This project is intended for educational and defensive cybersecurity research. Use only network traffic that you are authorized to inspect.