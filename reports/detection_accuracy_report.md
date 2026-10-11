# Detection Accuracy Test Report

## 1. Objective

Evaluate the IoT Device Fingerprinting project's anomaly detection using simulated PCAP test files.

## 2. Test Results

| Test | Expected Scenario | Alerts Detected | Result |
|---|---|---:|---|
| Anomaly Test | New service port and unknown device | 2 | Passed |
| Normal Test 1 | Normal simulated traffic | 0 | Passed |
| Normal Test 2 | Normal simulated traffic | 0 | Passed |
| Normal Test 3 | Normal simulated traffic | 0 | Passed |

## 3. Detected Anomalies

The anomaly test detected these alert types:

- `NEW_PORTS` — a known device used a new service port.
- `UNKNOWN_DEVICE` — a device not present in the baseline was detected.

Both expected anomaly categories were detected in the simulated test.

## 4. Summary

- Total test captures: 4
- Simulated anomaly captures: 1
- Normal captures: 3
- Alerts in anomaly test: 2
- Alerts across normal tests: 0

## 5. Limitations

These results are based on a small simulated dataset. They do not establish real-world accuracy, precision, recall, or false-positive rates. More varied PCAP files and labelled test cases are required for a reliable evaluation.

## 6. Conclusion

The initial tests show that the system detected the two configured anomaly scenarios while producing no alerts for the three tested normal captures. Further testing with larger and more realistic network datasets is recommended.
