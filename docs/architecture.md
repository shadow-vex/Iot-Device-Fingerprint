# IoT Device Fingerprinter - Architecture

## Data Flow

```mermaid
flowchart TD
    A["Synthetic or authorized PCAP"] --> B["Scapy packet reader"]
    B --> C["Fingerprint extraction"]
    C --> D["Device fingerprints"]
    D --> E["Baseline validation and storage"]
    E --> F["Behavioral anomaly detector"]
    F --> G{"Deviation detected?"}
    G -->|Yes| H["Generate JSON alerts"]
    G -->|No| I["No anomaly alert"]
    H --> J["Review reports"]
    I --> J
