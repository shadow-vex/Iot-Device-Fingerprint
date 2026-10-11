# Demo Results and Evidence

## Project
IoT Device Fingerprinter

## Automated Test Results
- Test framework: pytest
- Latest locally verified result: 19 passed, 0 failed.
- CI: GitHub Actions was previously verified as successful.

## Detection Demonstration
The current synthetic evaluation reported:
- One simulated anomaly capture generated two alerts: `NEW_PORTS` and `UNKNOWN_DEVICE`.
- Three simulated normal captures generated zero alerts.

## Evidence and Limitations
- Architecture: [System architecture](../architecture.md)
- Detection report: [Detection accuracy report](../../reports/detection_accuracy_report.md)

These results are from a small synthetic evaluation. They do not establish real-world accuracy, precision, recall, or false-positive rates. Real-device performance has not been validated.

## Safe Usage
Only analyze network captures from networks you own or are explicitly authorized to monitor. PCAP files and reports may contain sensitive network metadata.
