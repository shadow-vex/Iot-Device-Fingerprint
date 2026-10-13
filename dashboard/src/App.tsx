
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Cpu,
  Fingerprint,
  LayoutDashboard,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Radio,
  Wifi,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000";
const REQUEST_TIMEOUT_MS = 8000;
const REFRESH_INTERVAL_MS = 10000;

type AlertItem = {
  time?: string;
  type?: string;
  severity?: string;
  mac_address?: string;
  message?: string;
  description?: string;
  ports?: number[];
};

type Device = {
  mac_address?: string;
  fingerprint_id?: string;
  ip_address?: string;
  known_ip_addresses?: string[];
  protocols?: string[];
  protocol_counts?: Record<string, number>;
  packet_count?: number;
  baseline_packet_count?: number;
  observation_count?: number;
  known_ports?: number[];
  known_service_ports?: number[];
  known_dns_queries?: string[];
};

type Report = {
  status?: string;
  pcap_file?: string;
  observed_identities?: number;
  device_count?: number;
  alert_count?: number;
  alerts?: AlertItem[];
  devices?: Device[];
};

function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [page, setPage] = useState("Overview");
  const [lastUpdated, setLastUpdated] = useState("--:--:--");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // Prevent overlapping manual and automatic requests.
  const loadingRef = useRef(false);
  const mountedRef = useRef(false);

  const loadReport = useCallback(async () => {
    if (loadingRef.current || !mountedRef.current) return;

    loadingRef.current = true;
    setLoading(true);
    setError("");
    setSuccessMessage("");

    const controller = new AbortController();

    const timeoutId = window.setTimeout(() => {
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(`${API}/api/report`, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`API request failed (${response.status}).`);
      }

      const data: Report = await response.json();

      if (
        data.status !== "success" ||
        !Array.isArray(data.devices) ||
        !Array.isArray(data.alerts)
      ) {
        throw new Error("The API returned an unexpected report format.");
      }

      if (!mountedRef.current) return;

      setReport(data);
      setApiOnline(true);
      setLastUpdated(new Date().toLocaleTimeString());
      setSuccessMessage("Report synchronized successfully.");
    } catch (err) {
      if (!mountedRef.current) return;

      setApiOnline(false);

      if (err instanceof Error && err.name === "AbortError") {
        setError(
          "Request timed out after 8 seconds. Check the backend and retry."
        );
      } else {
        setError(
          err instanceof Error
            ? err.message
            : "Cannot reach the analysis API."
        );
      }
    } finally {
      window.clearTimeout(timeoutId);
      loadingRef.current = false;

      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    void loadReport();

    const timer = window.setInterval(() => {
      void loadReport();
    }, REFRESH_INTERVAL_MS);

    return () => {
      mountedRef.current = false;
      window.clearInterval(timer);
    };
  }, [loadReport]);

  const alerts = report?.alerts ?? [];
  const devices = report?.devices ?? [];
  const identities = report?.observed_identities ?? devices.length;
  const alertCount = report?.alert_count ?? alerts.length;

  const navItems = [
    { name: "Overview", icon: LayoutDashboard },
    { name: "Device Fingerprints", icon: Fingerprint },
    { name: "Anomaly Alerts", icon: ShieldAlert },
  ];

  return (
    <div className="cyber-shell">
      <aside className="cyber-sidebar">
        <div className="cyber-brand">
          <div className="cyber-logo">
            <Shield size={25} />
            <span />
          </div>
          <div>
            <h1>
              THREAT<span>FORGE</span>
            </h1>
            <p>INDUSTRIAL DEFENSE SYSTEM</p>
          </div>
        </div>

        <div className="cyber-label">OPERATIONS</div>

        <nav className="cyber-nav">
          {navItems.map(({ name, icon: Icon }) => (
            <button
              key={name}
              type="button"
              className={`cyber-nav-item ${
                page === name ? "active" : ""
              }`}
              onClick={() => setPage(name)}
              aria-current={page === name ? "page" : undefined}
            >
              <Icon size={18} />
              <span>{name}</span>
              {page === name && (
                <ArrowUpRight size={15} className="nav-arrow" />
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="backend-card">
            <div className="cyber-label">SENSOR LINK</div>

            <div className="backend-status">
              <span
                className={`cyber-dot ${
                  apiOnline ? "green" : "orange"
                }`}
              />
              {apiOnline ? "API CONNECTED" : "API OFFLINE"}
            </div>

            <p>
              {apiOnline
                ? "Report endpoint responding"
                : "Waiting for backend service"}
            </p>

            <div className="signal-bars">
              <i />
              <i />
              <i />
              <i />
              <i />
            </div>
          </div>

          <div className="defense-note">
            <ShieldCheck size={15} />
            DEFENSIVE MONITORING
          </div>
        </div>
      </aside>

      <main className="cyber-main">
        <header className="cyber-topbar">
          <div className="cyber-crumb">
            <span>THREATFORGE</span>
            <b>/</b>
            <strong>{page}</strong>
          </div>

          <div className="cyber-top-actions">
            <div className="connection-pill">
              <span
                className={`cyber-dot ${
                  apiOnline ? "green" : "orange"
                }`}
              />
              {apiOnline ? "SYSTEM ONLINE" : "SYSTEM OFFLINE"}
            </div>

            <button
              type="button"
              className="cyber-refresh"
              onClick={() => void loadReport()}
              disabled={loading}
              aria-label="Synchronize report data"
              aria-busy={loading}
            >
              <RefreshCw
                size={14}
                className={loading ? "spinning" : ""}
              />
              <span>{loading ? "SYNCING..." : "SYNC DATA"}</span>
            </button>
          </div>
        </header>

        <section className="cyber-heading">
          <div>
            <div className="cyber-eyebrow">
              <span />
              SECURITY OPERATIONS CENTER
            </div>
            <h2>
              {page}<span>.</span>
            </h2>
            <p>IoT visibility. Behavioral intelligence. Network defense.</p>
          </div>

          <div className="engine-chip">
            <div className="engine-icon">
              <Activity size={20} />
            </div>
            <div>
              <small>DETECTION ENGINE</small>
              <strong>PCAP / RULE-BASED</strong>
            </div>
          </div>
        </section>

        {error && (
          <div className="cyber-error" role="alert">
            <AlertTriangle size={16} />
            <span>{error}</span>
            <button
              type="button"
              onClick={() => void loadReport()}
              disabled={loading}
            >
              Retry
            </button>
          </div>
        )}

        {successMessage && !error && (
          <div className="sync-success" role="status">
            <ShieldCheck size={15} />
            {successMessage}
          </div>
        )}

        {page === "Overview" && (
          <>
            <div className="cyber-metrics">
              <Metric
                icon={<Network />}
                label="OBSERVED IDENTITIES"
                value={identities}
                detail="Latest report"
              />
              <Metric
                icon={<AlertTriangle />}
                label="ANOMALY FINDINGS"
                value={alertCount}
                detail="Rule-based alerts"
                danger
              />
              <Metric
                icon={<Wifi />}
                label="API CONNECTIVITY"
                value={apiOnline ? "ONLINE" : "OFFLINE"}
                detail={apiOnline ? "Backend reachable" : "Check API service"}
              />
              <Metric
                icon={<Cpu />}
                label="ANALYSIS SOURCE"
                value="PCAP"
                detail="Offline packet capture"
              />
            </div>

            <div className="cyber-grid">
              <section className="cyber-panel topology-panel">
                <div className="cyber-panel-head">
                  <div>
                    <div className="cyber-label">NETWORK VISIBILITY</div>
                    <h3>Device topology</h3>
                  </div>
                  <span className="panel-tag">
                    <Radio size={13} /> IDENTITY VIEW
                  </span>
                </div>

                <div className="topology-stage">
                  <div className="topology-grid" />
                  <svg
                    className="topology-lines"
                    viewBox="0 0 600 300"
                    preserveAspectRatio="none"
                    aria-hidden="true"
                  >
                    <line x1="300" y1="150" x2="130" y2="65" />
                    <line x1="300" y1="150" x2="470" y2="65" />
                    <line x1="300" y1="150" x2="120" y2="225" />
                    <line x1="300" y1="150" x2="475" y2="225" />
                    <circle cx="300" cy="150" r="70" />
                  </svg>

                  <div className="topology-core">
                    <Shield size={29} />
                    <strong>THREATFORGE</strong>
                    <small>MONITORING CORE</small>
                  </div>

                  {[
                    { cls: "node-one", icon: <Cpu size={18} />, label: "NODE 01" },
                    { cls: "node-two", icon: <Wifi size={18} />, label: "NODE 02" },
                    {
                      cls: "node-three",
                      icon: <Fingerprint size={18} />,
                      label: "NODE 03",
                    },
                    {
                      cls: "node-four",
                      icon: <Network size={18} />,
                      label: "NODE 04",
                    },
                  ].map((node) => (
                    <div className={`topology-node ${node.cls}`} key={node.cls}>
                      <div className="node-icon">{node.icon}</div>
                      <small>{node.label}</small>
                    </div>
                  ))}

                  <div className="topology-caption">
                    <span className="cyber-dot green" />
                    TOPOLOGY VISUALIZATION
                  </div>
                </div>

                <div className="topology-legend">
                  <span>
                    <i className="legend-green" />
                    Connected status is API-derived
                  </span>
                  <span>
                    <i className="legend-orange" />
                    Nodes are illustrative
                  </span>
                </div>
              </section>

              <section className="cyber-panel threat-panel">
                <div className="cyber-panel-head">
                  <div>
                    <div className="cyber-label">THREAT MONITOR</div>
                    <h3>Alert activity</h3>
                  </div>
                  <ShieldAlert size={21} className="orange-text" />
                </div>

                <div className="threat-total">
                  <div>
                    <strong>{alertCount}</strong>
                    <small>REPORTED FINDINGS</small>
                  </div>
                  <span className="threat-orbit">
                    <AlertTriangle size={24} />
                  </span>
                </div>

                <div className="threat-divider" />

                <div className="threat-stat">
                  <span>Observed identities</span>
                  <strong>{identities}</strong>
                </div>

                <div className="threat-stat">
                  <span>Report status</span>
                  <strong className={apiOnline ? "green-text" : "orange-text"}>
                    {apiOnline ? "AVAILABLE" : "OFFLINE"}
                  </strong>
                </div>

                <div className="threat-stat">
                  <span>Last API check</span>
                  <strong>{lastUpdated}</strong>
                </div>

                <button
                  type="button"
                  className="view-findings"
                  onClick={() => setPage("Anomaly Alerts")}
                >
                  INSPECT FINDINGS <ArrowUpRight size={14} />
                </button>
              </section>
            </div>

            <section className="cyber-panel findings-panel">
              <div className="cyber-panel-head">
                <div>
                  <div className="cyber-label">ANOMALY INTELLIGENCE</div>
                  <h3>Latest findings</h3>
                </div>
                <button
                  type="button"
                  className="cyber-link"
                  onClick={() => setPage("Anomaly Alerts")}
                >
                  VIEW ALL <ArrowUpRight size={14} />
                </button>
              </div>

              <AlertTable alerts={alerts.slice(0, 5)} />

              {!alerts.length && (
                <EmptyState
                  text={
                    apiOnline
                      ? "No findings in the current report"
                      : "Waiting for report data"
                  }
                />
              )}
            </section>
          </>
        )}

        {page === "Device Fingerprints" && (
          <section className="cyber-panel detail-panel">
            <div className="cyber-panel-head">
              <div>
                <div className="cyber-label">DEVICE INTELLIGENCE</div>
                <h3>Observed identities</h3>
              </div>
              <span className="panel-tag">{identities} IDENTITIES</span>
            </div>

            <div className="device-overview">
              <div className="device-overview-icon">
                <Fingerprint size={28} />
              </div>
              <div>
                <strong>{identities}</strong>
                <span>Observed network identities</span>
              </div>
              <div className="device-overview-status">
                <span
                  className={`cyber-dot ${apiOnline ? "green" : "orange"}`}
                />
                {apiOnline ? "REPORT AVAILABLE" : "NO API CONNECTION"}
              </div>
            </div>

            {devices.length > 0 ? (
              <div className="cyber-table-wrap">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>MAC ADDRESS</th>
                      <th>IP ADDRESS</th>
                      <th>PACKETS</th>
                      <th>PROTOCOLS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map((device, index) => {
                      const ipAddress =
                        device.ip_address ??
                        device.known_ip_addresses?.join(", ") ??
                        "Not provided";

                      const protocols =
                        device.protocols ??
                        (device.protocol_counts
                          ? Object.keys(device.protocol_counts)
                          : []);

                      const packetCount =
                        device.packet_count ??
                        device.baseline_packet_count ??
                        "—";

                      return (
                        <tr
                          key={`${device.mac_address ?? "device"}-${index}`}
                        >
                          <td className="mono-cell">
                            {device.mac_address ?? "Not provided"}
                          </td>
                          <td className="mono-cell">{ipAddress}</td>
                          <td>{packetCount}</td>
                          <td>{protocols.join(", ") || "Not provided"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                text={
                  apiOnline
                    ? "The API report does not provide a device detail list"
                    : "Connect the API to load report data"
                }
              />
            )}

            <div className="cyber-notice">
              <ShieldCheck size={16} />
              MAC-level identity counts do not necessarily equal physical device
              counts.
            </div>
          </section>
        )}

        {page === "Anomaly Alerts" && (
          <section className="cyber-panel detail-panel">
            <div className="cyber-panel-head">
              <div>
                <div className="cyber-label">DETECTION LOG</div>
                <h3>Anomaly findings</h3>
              </div>
              <span className="panel-tag orange-tag">
                {alertCount} FINDINGS
              </span>
            </div>

            <AlertTable alerts={alerts} />

            {!alerts.length && (
              <EmptyState
                text={
                  apiOnline
                    ? "No anomalies reported in this report"
                    : "Connect the API to load findings"
                }
              />
            )}

            <div className="cyber-notice">
              <AlertTriangle size={16} />
              Findings indicate rule-based deviations; they are not proof of a
              confirmed attack.
            </div>
          </section>
        )}

        <footer className="cyber-footer">
          <span>
            THREATFORGE <b>/</b> IOT DEFENSE CONSOLE
          </span>
          <span>
            <span className={`cyber-dot ${apiOnline ? "green" : "orange"}`} />
            LAST CHECK: {lastUpdated}
          </span>
        </footer>
      </main>
    </div>
  );
}

function Metric({
  icon,
  label,
  value,
  detail,
  danger = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  detail: string;
  danger?: boolean;
}) {
  return (
    <section className={`cyber-metric ${danger ? "danger" : ""}`}>
      <div className="metric-head">
        <span className="metric-icon">{icon}</span>
        <ArrowUpRight size={15} />
      </div>
      <span className="metric-label">{label}</span>
      <strong className="metric-number">{value}</strong>
      <span className="metric-detail">{detail}</span>
      <div className="metric-accent" />
    </section>
  );
}

function AlertTable({ alerts }: { alerts: AlertItem[] }) {
  if (!alerts.length) return null;

  return (
    <div className="cyber-table-wrap">
      <table className="cyber-table">
        <thead>
          <tr>
            <th>SEVERITY</th>
            <th>DETECTION TYPE</th>
            <th>NETWORK IDENTITY</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => {
            const severity = (alert.severity ?? "medium").toLowerCase();

            return (
              <tr key={`${alert.mac_address ?? "alert"}-${index}`}>
                <td>
                  <span className={`severity-chip ${severity}`}>
                    <i />
                    {severity.toUpperCase()}
                  </span>
                </td>
                <td>
                  <strong>
                    {(alert.type ?? "ANOMALY").replaceAll("_", " ")}
                  </strong>
                  {alert.message && (
                    <div className="alert-message">{alert.message}</div>
                  )}
                </td>
                <td className="mono-cell">
                  {alert.mac_address ?? "Not provided"}
                </td>
                <td>
                  <span className="review-chip">
                    <AlertTriangle size={12} /> REVIEW
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="cyber-empty">
      <ShieldCheck size={23} />
      <strong>{text}</strong>
    </div>
  );
}

export default App;
