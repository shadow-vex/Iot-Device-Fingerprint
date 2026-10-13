
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Cpu,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import "./App.css";

const API = "http://127.0.0.1:8000";

type AlertItem = {
  type?: string;
  severity?: string;
  mac_address?: string;
  description?: string;
};

type Report = {
  pcap_file?: string;
  observed_identities?: number;
  alert_count?: number;
  alerts?: AlertItem[];
};

const activityData = [
  { time: "00:00", packets: 24 },
  { time: "04:00", packets: 38 },
  { time: "08:00", packets: 31 },
  { time: "12:00", packets: 68 },
  { time: "16:00", packets: 45 },
  { time: "20:00", packets: 82 },
  { time: "24:00", packets: 56 },
];

function App() {
  const [report, setReport] = useState<Report | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [page, setPage] = useState("Overview");
  const [lastUpdated, setLastUpdated] = useState("--:--");
  const [loading, setLoading] = useState(false);

  async function loadReport() {
    setLoading(true);

    try {
      const response = await fetch(`${API}/api/report`);
      if (!response.ok) throw new Error("Report endpoint unavailable");

      const data = await response.json();
      setReport(data);
      setApiOnline(true);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch {
      setApiOnline(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReport();
    const timer = window.setInterval(loadReport, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const alerts = report?.alerts ?? [];
  const identities = report?.observed_identities ?? 0;
  const alertCount = report?.alert_count ?? alerts.length;

  const navItems = [
    { name: "Overview", icon: LayoutDashboard },
    { name: "Device Fingerprints", icon: Fingerprint },
    { name: "Anomaly Alerts", icon: ShieldAlert },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={25} strokeWidth={2.4} />
            <span />
          </div>
          <div>
            <h1>THREAT<span>FORGE</span></h1>
            <p>IoT THREAT INTELLIGENCE</p>
          </div>
        </div>

        <div className="side-label">COMMAND CENTER</div>

        <nav className="navigation">
          {navItems.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${page === name ? "active" : ""}`}
              onClick={() => setPage(name)}
            >
              <Icon size={19} />
              <span>{name}</span>
              {page === name && <ArrowUpRight size={16} className="nav-arrow" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <div className="status-heading">
              <span className={`status-dot ${apiOnline ? "online" : ""}`} />
              SYSTEM STATUS
            </div>
            <h3>{apiOnline ? "API CONNECTED" : "API DISCONNECTED"}</h3>
            <p>{apiOnline ? "Report service responding" : "Waiting for backend"}</p>
            <div className="status-line"><span /></div>
          </div>
          <div className="sidebar-footer">
            <ShieldCheck size={16} />
            <span>DEFENSIVE MONITORING</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>THREATFORGE</span>
            <span className="slash">/</span>
            <strong>{page}</strong>
          </div>
          <div className="topbar-right">
            <div className="live-badge">
              <span className={`status-dot ${apiOnline ? "online" : ""}`} />
              {apiOnline ? "CONNECTED" : "DEMO / OFFLINE"}
            </div>
            <button className="refresh-button" onClick={loadReport} disabled={loading}>
              <RefreshCw size={15} className={loading ? "spinning" : ""} />
              Refresh
            </button>
            <div className="avatar">TF</div>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow"><span /> IOT SECURITY OPERATIONS</div>
            <h2>{page}<span className="heading-dot">.</span></h2>
            <p>
              {page === "Overview" && "Network visibility. Device intelligence. Threat detection."}
              {page === "Device Fingerprints" && "Inspect identities observed in your packet captures."}
              {page === "Anomaly Alerts" && "Review deviations detected by the baseline rule engine."}
            </p>
          </div>
          <div className="scan-indicator">
            <div className="scan-icon"><Activity size={20} /></div>
            <div>
              <span>ANALYSIS ENGINE</span>
              <strong>PCAP ANALYSIS</strong>
            </div>
          </div>
        </section>

        {page === "Overview" && (
          <>
            <div className="metrics-grid">
              <Metric icon={<Network />} label="OBSERVED IDENTITIES" value={identities} note="From latest report" />
              <Metric icon={<AlertTriangle />} label="DETECTED ANOMALIES" value={alertCount} note="Rule-based alerts" warning />
              <Metric icon={<ShieldCheck />} label="API STATUS" value={apiOnline ? "ONLINE" : "OFFLINE"} note={apiOnline ? "Backend reachable" : "Check API server"} />
              <Metric icon={<Cpu />} label="ANALYSIS MODE" value="PCAP" note="Offline packet analysis" />
            </div>

            <div className="content-grid">
              <section className="panel activity-panel">
                <div className="panel-header">
                  <div>
                    <div className="section-kicker">NETWORK TELEMETRY</div>
                    <h3>Activity overview</h3>
                  </div>
                  <span className="demo-tag"><Zap size={13} /> ILLUSTRATIVE</span>
                </div>
                <div className="chart-caption">Illustrative activity curve · not live packet counts</div>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={activityData}>
                      <defs>
                        <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#f6d743" stopOpacity={0.3} />
                          <stop offset="100%" stopColor="#f6d743" stopOpacity={0.01} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="#252a30" strokeDasharray="4 5" vertical={false} />
                      <XAxis dataKey="time" stroke="#707782" tickLine={false} axisLine={false} />
                      <YAxis stroke="#707782" tickLine={false} axisLine={false} />
                      <Tooltip
                        contentStyle={{ background: "#171a1e", border: "1px solid #3b3d36", borderRadius: 8 }}
                        labelStyle={{ color: "#f6d743" }}
                      />
                      <Area type="monotone" dataKey="packets" stroke="#f6d743" strokeWidth={2} fill="url(#activityFill)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div className="chart-footer"><span>DEMO DATA</span><span>Not a live traffic feed</span></div>
              </section>

              <section className="panel detection-panel">
                <div className="panel-header">
                  <div>
                    <div className="section-kicker">THREAT MONITOR</div>
                    <h3>Detection summary</h3>
                  </div>
                  <ShieldCheck className="yellow-icon" size={23} />
                </div>
                <div className="detection-ring" style={{ "--ring-value": `${Math.min(alertCount * 25, 100)}%` } as React.CSSProperties}>
                  <div>
                    <strong>{alertCount}</strong>
                    <span>ALERTS</span>
                  </div>
                </div>
                <div className="detection-info">
                  <strong>{alertCount > 0 ? "Anomalies detected" : "No anomalies reported"}</strong>
                  <p>Results from the latest analysis report.</p>
                </div>
                <div className="detection-bottom">
                  <span><span className="legend-dot yellow" /> Rule-based engine</span>
                  <span>{lastUpdated}</span>
                </div>
              </section>
            </div>

            <section className="panel recent-panel">
              <div className="panel-header">
                <div>
                  <div className="section-kicker">LATEST REPORT</div>
                  <h3>Recent security findings</h3>
                </div>
                <button className="text-button" onClick={() => setPage("Anomaly Alerts")}>
                  View alerts <ArrowUpRight size={15} />
                </button>
              </div>
              <AlertTable alerts={alerts.slice(0, 4)} />
              {!alerts.length && (
                <div className="empty-state">
                  <ShieldCheck size={24} />
                  <strong>No alerts in current report</strong>
                  <p>Run the monitor against a PCAP file to update findings.</p>
                </div>
              )}
            </section>
          </>
        )}

        {page === "Device Fingerprints" && (
          <section className="panel full-panel">
            <div className="panel-header">
              <div>
                <div className="section-kicker">DEVICE INTELLIGENCE</div>
                <h3>Observed network identities</h3>
              </div>
              <span className="count-tag">{identities} IDENTITIES</span>
            </div>
            <div className="device-summary">
              <Fingerprint size={36} />
              <div>
                <strong>{identities}</strong>
                <p>Identities reported by the most recent PCAP analysis.</p>
              </div>
            </div>
            <p className="notice">
              MAC-level identity count is not proof of the same number of physical IoT devices.
              The current report endpoint provides aggregate identity counts only.
            </p>
          </section>
        )}

        {page === "Anomaly Alerts" && (
          <section className="panel full-panel">
            <div className="panel-header">
              <div>
                <div className="section-kicker">DETECTION LOG</div>
                <h3>Anomaly alerts</h3>
              </div>
              <span className="count-tag">{alertCount} ALERTS</span>
            </div>
            <AlertTable alerts={alerts} />
            {!alerts.length && (
              <div className="empty-state">
                <ShieldCheck size={24} />
                <strong>No anomalies reported</strong>
                <p>Current report contains zero alerts.</p>
              </div>
            )}
          </section>
        )}

        <footer className="page-footer">
          <span>THREATFORGE <span className="footer-separator">/</span> IOT DEFENSE CONSOLE</span>
          <span><Gauge size={14} /> LAST REPORT CHECK: {lastUpdated}</span>
        </footer>
      </main>
    </div>
  );
}

function Metric({
  icon,
  label,
  value,
  note,
  warning = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  note: string;
  warning?: boolean;
}) {
  return (
    <section className={`metric-card ${warning ? "warning-card" : ""}`}>
      <div className="metric-top">
        <div className={`metric-icon ${warning ? "orange-icon" : ""}`}>{icon}</div>
        <ArrowUpRight size={16} className="metric-arrow" />
      </div>
      <span className="metric-label">{label}</span>
      <strong className={`metric-value ${typeof value === "string" && value.length > 6 ? "small-value" : ""}`}>{value}</strong>
      <span className="metric-note">{note}</span>
      <div className="metric-bottom-line" />
    </section>
  );
}

function AlertTable({ alerts }: { alerts: AlertItem[] }) {
  if (!alerts.length) return null;

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>SEVERITY</th>
            <th>DETECTION TYPE</th>
            <th>NETWORK IDENTITY</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => (
            <tr key={`${alert.mac_address ?? "alert"}-${index}`}>
              <td>
                <span className={`severity ${(alert.severity ?? "medium").toLowerCase()}`}>
                  <span /> {(alert.severity ?? "MEDIUM").toUpperCase()}
                </span>
              </td>
              <td><strong>{(alert.type ?? "ANOMALY").replaceAll("_", " ")}</strong></td>
              <td className="mac-address">{alert.mac_address ?? "Not provided"}</td>
              <td><span className="review-tag"><AlertTriangle size={12} /> REVIEW</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
