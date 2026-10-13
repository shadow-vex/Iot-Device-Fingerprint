
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

app = FastAPI(
    title="IoT Device Fingerprinter API",
    description="API for device fingerprints and anomaly reports",
    version="1.2.0",
)

# Allow the local React/Vite dashboard to access this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


def read_report(filename: str) -> Any | None:
    """Read a JSON report safely from the reports directory."""
    report_path = REPORTS_DIR / filename

    if not report_path.is_file():
        return None

    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def get_device_list() -> list[dict[str, Any]]:
    """
    Load fingerprints from fingerprints.json or baseline_report.json.

    Supports both:
    - A list of device objects
    - A dictionary keyed by MAC address
    """
    report = read_report("fingerprints.json")

    if report is None:
        report = read_report("baseline_report.json")

    if isinstance(report, dict):
        devices = report.get("devices", [])
    elif isinstance(report, list):
        devices = report
    else:
        devices = []

    if isinstance(devices, dict):
        normalized_devices = []

        for mac_address, details in devices.items():
            if not isinstance(details, dict):
                continue

            # Keep the MAC key as the authoritative device identity.
            normalized_devices.append({
                **details,
                "mac_address": mac_address,
            })

        return normalized_devices

    if isinstance(devices, list):
        return [
            device
            for device in devices
            if isinstance(device, dict)
        ]

    return []


def get_anomaly_report() -> dict[str, Any]:
    """Return a consistent anomaly report structure."""
    report = read_report("anomalies.json")

    if not isinstance(report, dict):
        report = {}

    raw_alerts = report.get("alerts", [])
    alerts = (
        [alert for alert in raw_alerts if isinstance(alert, dict)]
        if isinstance(raw_alerts, list)
        else []
    )

    try:
        observed = max(0, int(report.get("observed_identities", 0)))
    except (ValueError, TypeError):
        observed = 0

    return {
        "status": (
            "success"
            if read_report("anomalies.json") is not None
            else "unavailable"
        ),
        "pcap_file": report.get("pcap_file"),
        "observed_identities": observed,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


@app.get("/")
def root():
    return {
        "status": "success",
        "message": "IoT Device Fingerprinter API is running",
        "version": app.version,
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "IoT Device Fingerprinter API",
    }


@app.get("/api/report")
def get_report():
    """Combined summary endpoint used by the dashboard."""
    anomalies = get_anomaly_report()
    devices = get_device_list()

    return {
        "status": "success",
        "observed_identities": anomalies["observed_identities"],
        "device_count": len(devices),
        "alert_count": anomalies["alert_count"],
        "alerts": anomalies["alerts"],
        "devices": devices,
        "pcap_file": anomalies["pcap_file"],
    }


@app.get("/api/anomalies")
def get_anomalies():
    return get_anomaly_report()


@app.get("/api/fingerprints")
def get_fingerprints():
    devices = get_device_list()

    fingerprint_report_exists = (
        read_report("fingerprints.json") is not None
    )

    return {
        "status": "success",
        "source": (
            "fingerprints.json"
            if fingerprint_report_exists
            else "baseline_report.json"
        ),
        "count": len(devices),
        "devices": devices,
    }
