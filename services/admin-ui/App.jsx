import { useState, useEffect, useCallback } from "react";

const API = "/api/v1";

// ─── Cloudflare-inspired design tokens ───
const T = {
  bg: "#f8f9fa", white: "#ffffff", sidebar: "#1a1a2e", sidebarHover: "#232345", sidebarActive: "#2d2d55",
  orange: "#f48120", orangeLight: "#fff4e8", orangeDark: "#d46a0a",
  blue: "#2563eb", blueLight: "#eff6ff", blueDark: "#1d4ed8",
  green: "#16a34a", greenLight: "#f0fdf4", greenDark: "#15803d",
  red: "#dc2626", redLight: "#fef2f2", redDark: "#b91c1c",
  yellow: "#ca8a04", yellowLight: "#fefce8",
  text: "#111827", t2: "#6b7280", t3: "#9ca3af",
  border: "#e5e7eb", borderLight: "#f3f4f6",
};

const mono = { fontFamily: "'IBM Plex Mono', 'Menlo', monospace", fontSize: 13 };

// ─── API helpers ───
async function api(path, opts = {}) {
  try {
    const r = await fetch(`${API}${path}`, {
      headers: { "Content-Type": "application/json", ...opts.headers },
      ...opts,
    });
    return await r.json();
  } catch (e) {
    console.error(`API ${path}:`, e);
    return null;
  }
}

// ─── Components ───
function Badge({ children, color = "gray", small }) {
  const c = {
    green: { bg: T.greenLight, fg: T.greenDark, dot: T.green },
    red: { bg: T.redLight, fg: T.redDark, dot: T.red },
    orange: { bg: T.orangeLight, fg: T.orangeDark, dot: T.orange },
    blue: { bg: T.blueLight, fg: T.blueDark, dot: T.blue },
    yellow: { bg: T.yellowLight, fg: "#92400e", dot: T.yellow },
    gray: { bg: "#f3f4f6", fg: T.t2, dot: T.t3 },
  }[color] || { bg: "#f3f4f6", fg: T.t2, dot: T.t3 };
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: c.bg, color: c.fg, padding: small ? "1px 8px" : "3px 10px", borderRadius: 4, fontSize: small ? 11 : 12, fontWeight: 500, whiteSpace: "nowrap" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: c.dot }} />
      {children}
    </span>
  );
}

function Card({ children, title, action, noPad }) {
  return (
    <div style={{ background: T.white, borderRadius: 8, border: `1px solid ${T.border}`, overflow: "hidden" }}>
      {title && (
        <div style={{ padding: "14px 20px", borderBottom: `1px solid ${T.borderLight}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: T.text }}>{title}</span>
          {action}
        </div>
      )}
      {noPad ? children : <div style={{ padding: 20 }}>{children}</div>}
    </div>
  );
}

function Metric({ label, value, sub, color }) {
  return (
    <div>
      <div style={{ fontSize: 12, color: T.t2, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || T.text, lineHeight: 1.1, letterSpacing: -0.5 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: T.t3, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Btn({ children, primary, danger, small, onClick }) {
  const s = { padding: small ? "5px 12px" : "8px 16px", borderRadius: 6, fontSize: small ? 12 : 13, fontWeight: 500, cursor: "pointer", border: "none", transition: "all 0.15s" };
  const style = danger ? { ...s, background: T.redLight, color: T.red } : primary ? { ...s, background: T.orange, color: "#fff" } : { ...s, background: T.white, color: T.text, border: `1px solid ${T.border}` };
  return <button style={style} onClick={onClick}>{children}</button>;
}

function TH({ children }) { return <th style={{ padding: "8px 16px", textAlign: "left", fontSize: 11, fontWeight: 600, color: T.t2, textTransform: "uppercase", letterSpacing: 0.8, borderBottom: `1px solid ${T.border}`, whiteSpace: "nowrap" }}>{children}</th>; }
function TD({ children, m, muted }) { return <td style={{ padding: "9px 16px", fontSize: 13, color: muted ? T.t3 : T.text, borderBottom: `1px solid ${T.borderLight}`, whiteSpace: "nowrap", ...(m ? mono : {}) }}>{children}</td>; }

function Modal({ children, onClose, title }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.35)", display: "flex", alignItems: "flex-start", justifyContent: "center", zIndex: 1000, paddingTop: 60 }} onClick={onClose}>
      <div style={{ background: T.white, borderRadius: 12, width: 560, maxWidth: "95vw", boxShadow: "0 20px 60px rgba(0,0,0,0.15)" }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: "16px 24px", borderBottom: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>{title}</span>
          <span onClick={onClose} style={{ cursor: "pointer", color: T.t3, fontSize: 22, lineHeight: 1 }}>×</span>
        </div>
        <div style={{ padding: 24 }}>{children}</div>
      </div>
    </div>
  );
}

function Loading() {
  return <div style={{ textAlign: "center", padding: 60, color: T.t3 }}>Loading...</div>;
}

// ─── Pages ───

function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [prom, setProm] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [authHistory, setAuthHistory] = useState([]);

  // Prometheus query helper
  const promQuery = useCallback(async (query) => {
    try {
      const r = await fetch(`/api/prometheus/api/v1/query?query=${encodeURIComponent(query)}`);
      const d = await r.json();
      if (d.status === "success" && d.data.result.length > 0) return parseFloat(d.data.result[0].value[1]);
      return null;
    } catch { return null; }
  }, []);

  const promQueryAll = useCallback(async (query) => {
    try {
      const r = await fetch(`/api/prometheus/api/v1/query?query=${encodeURIComponent(query)}`);
      const d = await r.json();
      if (d.status === "success") return d.data.result;
      return [];
    } catch { return []; }
  }, []);

  // Prometheus range query for sparkline
  const promRange = useCallback(async (query, stepSec = 60) => {
    try {
      const end = Math.floor(Date.now() / 1000);
      const start = end - 3600;
      const r = await fetch(`/api/prometheus/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${stepSec}`);
      const d = await r.json();
      if (d.status === "success" && d.data.result.length > 0) return d.data.result[0].values.map(v => parseFloat(v[1]));
      return [];
    } catch { return []; }
  }, []);

  // Fetch API stats
  useEffect(() => { api("/dashboard/stats").then(setStats); }, []);

  // Fetch Prometheus metrics
  useEffect(() => {
    async function fetchProm() {
      const jobs = ["freeradius", "mariadb-galera", "redis", "kafka", "policy-engine", "posture-engine", "profiler", "node-exporter", "prometheus"];
      const upResults = await promQueryAll("up");
      const services = jobs.map(j => {
        const match = upResults.find(r => r.metric.job === j);
        return { name: j, up: match ? parseFloat(match.value[1]) : null };
      });

      const [cpu, mem, disk, authRate, rejectRate, galeraSize, galeraState, kafkaLag, certDays, connectedEp] = await Promise.all([
        promQuery('100 - (avg(irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
        promQuery("(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100"),
        promQuery('(1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100'),
        promQuery("rate(freeradius_total_access_requests[5m])"),
        promQuery('100 * rate(freeradius_total_access_rejects[5m]) / (rate(freeradius_total_access_accepts[5m]) + rate(freeradius_total_access_rejects[5m]) + 0.001)'),
        promQuery("mysql_global_status_wsrep_cluster_size"),
        promQuery("mysql_global_status_wsrep_local_state"),
        promQuery("max(kafka_consumergroup_lag_sum)"),
        promQuery("min((probe_ssl_earliest_cert_expiry - time()) / 86400)"),
        promQuery("policy_engine_connected_endpoints"),
      ]);

      setProm({ services, cpu, mem, disk, authRate, rejectRate, galeraSize, galeraState, kafkaLag, certDays, connectedEp });

      // Auth rate sparkline
      const hist = await promRange("rate(freeradius_total_access_requests[1m])");
      setAuthHistory(hist);

      // Active alerts
      try {
        const r = await fetch("/api/prometheus/api/v1/alerts");
        const d = await r.json();
        if (d.status === "success") setAlerts(d.data.alerts.filter(a => a.state === "firing"));
      } catch { /* ignore */ }
    }
    fetchProm();
    const t = setInterval(fetchProm, 15000);
    return () => clearInterval(t);
  }, [promQuery, promQueryAll, promRange]);

  if (!stats) return <Loading />;
  const ep = stats.endpoints || {};
  const au = stats.auth || {};

  const serviceLabel = (name) => ({
    "freeradius": "FreeRADIUS", "mariadb-galera": "MariaDB", "redis": "Redis",
    "kafka": "Kafka", "policy-engine": "Policy Engine", "posture-engine": "Posture",
    "profiler": "Profiler", "node-exporter": "Host", "prometheus": "Prometheus",
  }[name] || name);

  const galeraLabel = (state) => ({ 1: "Joining", 2: "Donor", 3: "Joined", 4: "Synced" }[state] || "Unknown");

  const fmtVal = (v, dec = 1) => v !== null && v !== undefined ? v.toFixed(dec) : "—";

  // Mini sparkline SVG
  const Sparkline = ({ data, color = T.orange, width = 120, height = 32 }) => {
    if (!data || data.length < 2) return <div style={{ width, height }} />;
    const max = Math.max(...data, 0.001);
    const pts = data.map((v, i) => `${(i / (data.length - 1)) * width},${height - (v / max) * (height - 4)}`).join(" ");
    return (
      <svg width={width} height={height} style={{ display: "block" }}>
        <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
      </svg>
    );
  };

  // Resource gauge bar
  const GaugeBar = ({ label, value, thresholds = [60, 80, 90] }) => {
    const v = value !== null ? value : 0;
    const color = v >= thresholds[2] ? T.red : v >= thresholds[1] ? T.yellow : v >= thresholds[0] ? T.orange : T.green;
    return (
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
          <span style={{ fontSize: 12, color: T.t2 }}>{label}</span>
          <span style={{ fontSize: 12, fontWeight: 600, color, ...mono }}>{value !== null ? `${value.toFixed(1)}%` : "—"}</span>
        </div>
        <div style={{ height: 6, background: T.borderLight, borderRadius: 3, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${Math.min(v, 100)}%`, background: color, borderRadius: 3, transition: "width 0.5s ease" }} />
        </div>
      </div>
    );
  };

  return (
    <div>
      {/* ── Row 1: Service Health Banner ── */}
      <Card title="System health" action={
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {alerts.length > 0 && <Badge color="red" small>{alerts.length} active alert{alerts.length > 1 ? "s" : ""}</Badge>}
          <a href="https://10.10.10.173:3000" target="_blank" rel="noopener noreferrer"
            style={{ fontSize: 12, color: T.blue, textDecoration: "none", fontWeight: 500 }}>Open Grafana →</a>
        </div>
      }>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(130px, 1fr))", gap: 8 }}>
          {(prom?.services || []).map(svc => (
            <div key={svc.name} style={{
              display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 6,
              background: svc.up === 1 ? T.greenLight : svc.up === 0 ? T.redLight : T.borderLight,
              border: `1px solid ${svc.up === 1 ? "#bbf7d0" : svc.up === 0 ? "#fecaca" : T.border}`,
            }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: svc.up === 1 ? T.green : svc.up === 0 ? T.red : T.t3 }} />
              <span style={{ fontSize: 12, fontWeight: 500, color: svc.up === 1 ? T.greenDark : svc.up === 0 ? T.redDark : T.t2 }}>
                {serviceLabel(svc.name)}
              </span>
            </div>
          ))}
        </div>
      </Card>

      {/* ── Row 2: Key Metrics ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, margin: "20px 0" }}>
        <Card>
          <Metric label="Total endpoints" value={prom?.connectedEp !== null ? Math.round(prom.connectedEp) : (ep.total || 0)} color={T.blue} />
        </Card>
        <Card>
          <Metric label="Compliant" value={ep.compliant || 0}
            sub={ep.total ? `${Math.round((ep.compliant || 0) / ep.total * 100)}%` : "—"} color={T.green} />
        </Card>
        <Card>
          <Metric label="Non-compliant" value={ep.non_compliant || 0} color={T.red} />
        </Card>
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
            <Metric label="Auth rate" value={fmtVal(prom?.authRate)} sub="req/s" color={T.orange} />
            <Sparkline data={authHistory} />
          </div>
        </Card>
        <Card>
          <Metric label="Reject rate" value={prom?.rejectRate !== null ? `${fmtVal(prom.rejectRate)}%` : `${au.reject_rate || 0}%`}
            color={(prom?.rejectRate || au.reject_rate || 0) > 30 ? T.red : T.yellow} />
        </Card>
      </div>

      {/* ── Row 3: Resources / Galera / Alerts ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20, marginBottom: 20 }}>
        {/* Resources */}
        <Card title="Host resources">
          <GaugeBar label="CPU" value={prom?.cpu} />
          <GaugeBar label="Memory" value={prom?.mem} />
          <GaugeBar label="Disk /" value={prom?.disk} thresholds={[60, 80, 92]} />
        </Card>

        {/* Galera + Infrastructure */}
        <Card title="Infrastructure">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ padding: 12, borderRadius: 6, background: T.borderLight }}>
              <div style={{ fontSize: 11, color: T.t3, marginBottom: 4 }}>Galera cluster</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: prom?.galeraSize === 3 ? T.green : T.red }}>
                {prom?.galeraSize ?? "—"}<span style={{ fontSize: 13, fontWeight: 400, color: T.t3 }}>/3</span>
              </div>
              <div style={{ fontSize: 11, color: T.t3, marginTop: 2 }}>{prom?.galeraState ? galeraLabel(prom.galeraState) : ""}</div>
            </div>
            <div style={{ padding: 12, borderRadius: 6, background: T.borderLight }}>
              <div style={{ fontSize: 11, color: T.t3, marginBottom: 4 }}>Kafka lag</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: (prom?.kafkaLag || 0) > 10000 ? T.red : T.text, ...mono }}>
                {prom?.kafkaLag !== null ? Math.round(prom.kafkaLag).toLocaleString() : "—"}
              </div>
              <div style={{ fontSize: 11, color: T.t3, marginTop: 2 }}>messages</div>
            </div>
            <div style={{ padding: 12, borderRadius: 6, background: T.borderLight, gridColumn: "1 / -1" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontSize: 11, color: T.t3, marginBottom: 4 }}>Certificate expiry</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: (prom?.certDays || 0) < 7 ? T.red : (prom?.certDays || 0) < 30 ? T.yellow : T.green }}>
                    {prom?.certDays !== null ? Math.round(prom.certDays) : "—"}
                    <span style={{ fontSize: 13, fontWeight: 400, color: T.t3 }}> days</span>
                  </div>
                </div>
                <Badge color={(prom?.certDays || 999) < 7 ? "red" : (prom?.certDays || 999) < 30 ? "orange" : "green"} small>
                  {(prom?.certDays || 999) < 7 ? "Critical" : (prom?.certDays || 999) < 30 ? "Warning" : "OK"}
                </Badge>
              </div>
            </div>
          </div>
        </Card>

        {/* Alerts */}
        <Card title="Active alerts" action={
          <Badge color={alerts.length > 0 ? "red" : "green"} small>{alerts.length > 0 ? `${alerts.length} firing` : "All clear"}</Badge>
        } noPad>
          {alerts.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>✓</div>
              <div style={{ fontSize: 13, color: T.t3 }}>No active alerts</div>
            </div>
          ) : (
            <div style={{ maxHeight: 220, overflowY: "auto" }}>
              {alerts.slice(0, 8).map((a, i) => (
                <div key={i} style={{ padding: "10px 16px", borderBottom: `1px solid ${T.borderLight}`, display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: "50%", marginTop: 5, flexShrink: 0,
                    background: a.labels?.severity === "critical" ? T.red : T.yellow,
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: T.text }}>{a.labels?.alertname || "Alert"}</div>
                    <div style={{ fontSize: 11, color: T.t3, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.annotations?.summary || ""}
                    </div>
                  </div>
                  <Badge color={a.labels?.severity === "critical" ? "red" : "orange"} small>
                    {a.labels?.severity || "warn"}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* ── Row 4: Recent Auth + Categories (original) ── */}
      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 20 }}>
        <Card title="Recent authentications" noPad>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><TH>Time</TH><TH>User</TH><TH>Result</TH><TH>MAC</TH><TH>NAS</TH></tr></thead>
            <tbody>
              {(stats.recent_auth || []).map((a, i) => (
                <tr key={i}>
                  <TD m>{(a.time || "").slice(11, 19)}</TD>
                  <TD>{a.username}</TD>
                  <TD><Badge color={a.result === "Access-Accept" ? "green" : "red"} small>{a.result === "Access-Accept" ? "Accept" : "Reject"}</Badge></TD>
                  <TD m>{a.mac || "—"}</TD>
                  <TD m muted>{a.nas || "—"}</TD>
                </tr>
              ))}
              {(!stats.recent_auth || stats.recent_auth.length === 0) && <tr><TD>No recent authentications</TD></tr>}
            </tbody>
          </table>
        </Card>
        <Card title="Endpoint categories">
          {(stats.categories || []).map((c, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
              <span style={{ flex: 1, fontSize: 13 }}>{c.category}</span>
              <span style={{ fontSize: 13, color: T.t2, ...mono }}>{c.count}</span>
            </div>
          ))}
          {(!stats.categories || stats.categories.length === 0) && <div style={{ color: T.t3, fontSize: 13 }}>No endpoints profiled yet</div>}
        </Card>
      </div>
    </div>
  );
}

function EndpointsPage() {
  const [data, setData] = useState(null);
  const [search, setSearch] = useState("");
  const [detail, setDetail] = useState(null);

  const load = useCallback(() => { api(`/endpoints?search=${search}&limit=100`).then(setData); }, [search]);
  useEffect(() => { load(); }, [load]);

  const sendCoa = async (mac, action) => {
    const r = await api("/coa/send", { method: "POST", body: JSON.stringify({ mac_address: mac, action }) });
    alert(r?.success ? `${action} sent to ${mac}` : `Failed: ${r?.error || "unknown"}`);
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search MAC, IP, username, profile..." style={{ flex: 1, padding: "8px 14px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, outline: "none" }} />
        <Btn onClick={load}>Refresh</Btn>
      </div>
      <Card noPad>
        {!data ? <Loading /> : (
          <>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>MAC</TH><TH>IP</TH><TH>User</TH><TH>Profile</TH><TH>Posture</TH><TH>Last seen</TH><TH>Actions</TH></tr></thead>
              <tbody>
                {(data.items || []).map((e, i) => (
                  <tr key={i} style={{ cursor: "pointer" }} onClick={() => setDetail(e)}>
                    <TD m>{e.mac_address}</TD>
                    <TD m>{e.ip_address || "—"}</TD>
                    <TD>{e.username || "—"}</TD>
                    <TD>{e.device_profile || "Unknown"}</TD>
                    <TD><Badge color={e.posture_status === "compliant" ? "green" : e.posture_status === "non_compliant" ? "red" : "gray"} small>{e.posture_status || "unknown"}</Badge></TD>
                    <TD muted>{e.last_seen ? new Date(e.last_seen).toLocaleString() : "—"}</TD>
                    <TD>
                      <div style={{ display: "flex", gap: 4 }} onClick={ev => ev.stopPropagation()}>
                        <Btn small onClick={() => sendCoa(e.mac_address, "reauthenticate")}>ReAuth</Btn>
                        <Btn small danger onClick={() => sendCoa(e.mac_address, "disconnect")}>Disc</Btn>
                      </div>
                    </TD>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ padding: "10px 16px", fontSize: 12, color: T.t3, borderTop: `1px solid ${T.border}` }}>{data.total || 0} endpoints</div>
          </>
        )}
      </Card>
      {detail && (
        <Modal title="Endpoint details" onClose={() => setDetail(null)}>
          {Object.entries(detail).filter(([k]) => !["id"].includes(k)).map(([k, v], i) => (
            <div key={i} style={{ display: "flex", padding: "8px 0", borderBottom: `1px solid ${T.borderLight}`, fontSize: 13 }}>
              <span style={{ width: 160, color: T.t2 }}>{k.replace(/_/g, " ")}</span>
              <span style={{ color: T.text, ...(["mac", "ip"].some(x => k.includes(x)) ? mono : {}) }}>{v != null ? String(v) : "—"}</span>
            </div>
          ))}
          <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
            <Btn primary onClick={() => { sendCoa(detail.mac_address, "reauthenticate"); setDetail(null); }}>Reauthenticate</Btn>
            <Btn onClick={() => { sendCoa(detail.mac_address, "bounce-port"); setDetail(null); }}>Port bounce</Btn>
            <Btn danger onClick={() => { sendCoa(detail.mac_address, "disconnect"); setDetail(null); }}>Disconnect</Btn>
          </div>
        </Modal>
      )}
    </div>
  );
}

function PoliciesPage() {
  const [data, setData] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({});

  const load = () => api("/policies").then(setData);
  useEffect(() => { load(); }, []);

  const save = async () => {
    const body = { ...form, conditions: typeof form.conditions === "string" ? JSON.parse(form.conditions) : form.conditions, actions: typeof form.actions === "string" ? JSON.parse(form.actions) : form.actions };
    if (editing === "new") {
      await api("/policies", { method: "POST", body: JSON.stringify(body) });
    } else {
      await api(`/policies/${editing}`, { method: "PUT", body: JSON.stringify(body) });
    }
    setEditing(null);
    load();
  };

  const del = async (id) => {
    if (confirm("Delete this policy?")) {
      await api(`/policies/${id}`, { method: "DELETE" });
      load();
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <span style={{ fontSize: 13, color: T.t2 }}>{data?.total || 0} authorization rules</span>
        <Btn primary onClick={() => { setForm({ name: "", priority: 100, policy_set: "default", conditions: "{}", actions: '{"vlan":"100"}', enabled: true }); setEditing("new"); }}>+ Create rule</Btn>
      </div>
      <Card noPad>
        {!data ? <Loading /> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><TH>Pri</TH><TH>Name</TH><TH>Set</TH><TH>Conditions</TH><TH>Actions</TH><TH>Hits</TH><TH>On</TH><TH></TH></tr></thead>
            <tbody>
              {(data.items || []).map((p, i) => (
                <tr key={i}>
                  <TD m>{p.priority}</TD>
                  <TD><span style={{ fontWeight: 500 }}>{p.name}</span></TD>
                  <TD><Badge color="gray" small>{p.policy_set}</Badge></TD>
                  <TD m muted>{JSON.stringify(p.conditions).slice(0, 40)}</TD>
                  <TD><span style={{ fontSize: 12, color: T.blue, ...mono }}>{JSON.stringify(p.actions).slice(0, 35)}</span></TD>
                  <TD m muted>{(p.hit_count || 0).toLocaleString()}</TD>
                  <TD><span style={{ width: 8, height: 8, borderRadius: "50%", background: p.enabled ? T.green : T.t3, display: "inline-block" }} /></TD>
                  <TD>
                    <div style={{ display: "flex", gap: 4 }}>
                      <Btn small onClick={() => { setForm({ ...p, conditions: JSON.stringify(p.conditions, null, 2), actions: JSON.stringify(p.actions, null, 2) }); setEditing(p.id); }}>Edit</Btn>
                      <Btn small danger onClick={() => del(p.id)}>Del</Btn>
                    </div>
                  </TD>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {editing && (
        <Modal title={editing === "new" ? "New policy" : `Edit: ${form.name}`} onClose={() => setEditing(null)}>
          <div style={{ marginBottom: 12 }}><label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Name</label><input value={form.name || ""} onChange={e => setForm({ ...form, name: e.target.value })} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
            <div><label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Priority</label><input type="number" value={form.priority || 100} onChange={e => setForm({ ...form, priority: +e.target.value })} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} /></div>
            <div><label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Policy set</label><input value={form.policy_set || ""} onChange={e => setForm({ ...form, policy_set: e.target.value })} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} /></div>
          </div>
          <div style={{ marginBottom: 12 }}><label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Conditions (JSON)</label><textarea value={form.conditions || "{}"} onChange={e => setForm({ ...form, conditions: e.target.value })} rows={3} style={{ width: "100%", padding: 10, borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, ...mono, boxSizing: "border-box", resize: "vertical" }} /></div>
          <div style={{ marginBottom: 16 }}><label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Actions (JSON)</label><textarea value={form.actions || "{}"} onChange={e => setForm({ ...form, actions: e.target.value })} rows={3} style={{ width: "100%", padding: 10, borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, ...mono, boxSizing: "border-box", resize: "vertical", color: T.blue }} /></div>
          <div style={{ display: "flex", gap: 8 }}><Btn primary onClick={save}>Save</Btn><Btn onClick={() => setEditing(null)}>Cancel</Btn></div>
        </Modal>
      )}
    </div>
  );
}

function AuthLogPage() {
  const [data, setData] = useState(null);
  const [search, setSearch] = useState("");
  const load = useCallback(() => { api(`/auth-log?search=${search}&limit=100`).then(setData); }, [search]);
  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search user, MAC, NAS..." style={{ flex: 1, padding: "8px 14px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, outline: "none" }} />
        <Btn onClick={load}>Refresh</Btn>
      </div>
      <Card noPad>
        {!data ? <Loading /> : (
          <>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr><TH>Time</TH><TH>Username</TH><TH>Result</TH><TH>MAC</TH><TH>NAS</TH></tr></thead>
              <tbody>
                {(data.items || []).map((a, i) => (
                  <tr key={i} style={{ background: a.result === "Access-Reject" ? "rgba(220,38,38,0.03)" : "transparent" }}>
                    <TD m>{(a.timestamp || "").replace("T", " ").slice(0, 19)}</TD>
                    <TD>{a.username}</TD>
                    <TD><Badge color={a.result === "Access-Accept" ? "green" : "red"} small>{a.result === "Access-Accept" ? "Accept" : "Reject"}</Badge></TD>
                    <TD m>{a.mac || "—"}</TD>
                    <TD m muted>{a.nas_ip || "—"}</TD>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ padding: "10px 16px", fontSize: 12, color: T.t3, borderTop: `1px solid ${T.border}` }}>{data.total || 0} entries</div>
          </>
        )}
      </Card>
    </div>
  );
}

function NetworkDevicesPage() {
  const [data, setData] = useState(null);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ nasname: "", shortname: "", type: "cisco", secret: "", description: "" });

  const load = () => api("/network-devices").then(setData);
  useEffect(() => { load(); }, []);

  const save = async () => {
    await api("/network-devices", { method: "POST", body: JSON.stringify(form) });
    setAdding(false);
    setForm({ nasname: "", shortname: "", type: "cisco", secret: "", description: "" });
    load();
  };

  const del = async (id) => {
    if (confirm("Remove this NAS?")) {
      await api(`/network-devices/${id}`, { method: "DELETE" });
      load();
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <span style={{ fontSize: 13, color: T.t2 }}>Network devices sending RADIUS requests</span>
        <Btn primary onClick={() => setAdding(true)}>+ Add device</Btn>
      </div>
      <Card noPad>
        {!data ? <Loading /> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><TH>IP / Subnet</TH><TH>Name</TH><TH>Type</TH><TH>Secret</TH><TH>Description</TH><TH></TH></tr></thead>
            <tbody>
              {(data.items || []).map((d, i) => (
                <tr key={i}>
                  <TD m>{d.nasname}</TD>
                  <TD><span style={{ fontWeight: 500 }}>{d.shortname}</span></TD>
                  <TD>{d.type}</TD>
                  <TD m>{d.secret}</TD>
                  <TD muted>{d.description || "—"}</TD>
                  <TD><Btn small danger onClick={() => del(d.id)}>Remove</Btn></TD>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {adding && (
        <Modal title="Add network device" onClose={() => setAdding(false)}>
          {["nasname:IP address or subnet", "shortname:Hostname", "type:Vendor type (cisco, juniper, aruba)", "secret:RADIUS shared secret", "description:Description"].map(f => {
            const [k, label] = f.split(":");
            return (
              <div key={k} style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>{label}</label>
                <input value={form[k] || ""} onChange={e => setForm({ ...form, [k]: e.target.value })} type={k === "secret" ? "password" : "text"} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} />
              </div>
            );
          })}
          <div style={{ display: "flex", gap: 8, marginTop: 16 }}><Btn primary onClick={save}>Add device</Btn><Btn onClick={() => setAdding(false)}>Cancel</Btn></div>
        </Modal>
      )}
    </div>
  );
}

function GuestPage() {
  const [data, setData] = useState(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ email: "", sponsor: "", company: "", duration_hours: 24 });
  const [creds, setCreds] = useState(null);

  const load = () => api("/guest-accounts").then(setData);
  useEffect(() => { load(); }, []);

  const create = async () => {
    const r = await api("/guest-accounts", { method: "POST", body: JSON.stringify(form) });
    if (r?.username) { setCreds(r); load(); }
    setCreating(false);
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <span style={{ fontSize: 13, color: T.t2 }}>{data?.total || 0} guest accounts</span>
        <Btn primary onClick={() => setCreating(true)}>+ Create guest</Btn>
      </div>
      {creds && (
        <Card style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: T.green, marginBottom: 8 }}>Guest account created</div>
          <div style={{ ...mono, fontSize: 14 }}>Username: <strong>{creds.username}</strong></div>
          <div style={{ ...mono, fontSize: 14 }}>Password: <strong>{creds.password}</strong></div>
          <div style={{ fontSize: 12, color: T.t3, marginTop: 4 }}>Valid until: {creds.valid_until}</div>
          <Btn small onClick={() => setCreds(null)} style={{ marginTop: 8 }}>Dismiss</Btn>
        </Card>
      )}
      <Card noPad>
        {!data ? <Loading /> : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><TH>Username</TH><TH>Email</TH><TH>Sponsor</TH><TH>Company</TH><TH>Status</TH><TH>Valid until</TH></tr></thead>
            <tbody>
              {(data.items || []).map((g, i) => (
                <tr key={i}>
                  <TD m>{g.username}</TD>
                  <TD>{g.email || "—"}</TD>
                  <TD>{g.sponsor || "—"}</TD>
                  <TD>{g.company || "—"}</TD>
                  <TD><Badge color={g.status === "active" ? "green" : "gray"} small>{g.status}</Badge></TD>
                  <TD muted>{g.valid_until ? new Date(g.valid_until).toLocaleString() : "—"}</TD>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {creating && (
        <Modal title="Create guest account" onClose={() => setCreating(false)}>
          {["email:Email", "sponsor:Sponsor name", "company:Company"].map(f => {
            const [k, label] = f.split(":");
            return (
              <div key={k} style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>{label}</label>
                <input value={form[k] || ""} onChange={e => setForm({ ...form, [k]: e.target.value })} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} />
              </div>
            );
          })}
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 12, color: T.t2, display: "block", marginBottom: 4 }}>Duration (hours)</label>
            <input type="number" value={form.duration_hours} onChange={e => setForm({ ...form, duration_hours: +e.target.value })} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${T.border}`, fontSize: 13, boxSizing: "border-box" }} />
          </div>
          <Btn primary onClick={create}>Create</Btn>
        </Modal>
      )}
    </div>
  );
}

// ─── Navigation ───
const NAV = [
  { id: "dashboard", name: "Overview", icon: "◎" },
  { section: "Access Control" },
  { id: "endpoints", name: "Endpoints", icon: "◉" },
  { id: "policies", name: "Policies", icon: "⚙" },
  { id: "authlog", name: "Auth Log", icon: "▤" },
  { id: "guests", name: "Guest Portal", icon: "⊕" },
  { section: "Infrastructure" },
  { id: "nas", name: "Network Devices", icon: "⬡" },
];

const PAGES = {
  dashboard: { title: "Overview", sub: "Network access control dashboard", component: DashboardPage },
  endpoints: { title: "Endpoints", sub: "All authenticated devices", component: EndpointsPage },
  policies: { title: "Authorization Policies", sub: "Rules determining access levels", component: PoliciesPage },
  authlog: { title: "Authentication Log", sub: "RADIUS authentication events", component: AuthLogPage },
  nas: { title: "Network Devices", sub: "Switches, WLCs, VPN gateways", component: NetworkDevicesPage },
  guests: { title: "Guest Accounts", sub: "Temporary network access", component: GuestPage },
};

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [health, setHealth] = useState(null);
  useEffect(() => { fetch("/health").then(r => r.json()).then(setHealth).catch(() => setHealth({ status: "error" })); }, []);

  const pg = PAGES[page] || PAGES.dashboard;
  const PageComponent = pg.component;

  return (
    <div style={{ display: "flex", height: "100vh", background: T.bg, fontFamily: "'DM Sans', -apple-system, sans-serif", color: T.text, fontSize: 14 }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />

      <nav style={{ width: 220, background: T.sidebar, display: "flex", flexDirection: "column", flexShrink: 0 }}>
        <div style={{ padding: "20px 18px 16px", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: `linear-gradient(135deg, ${T.orange}, #e85d04)`, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 15, color: "#fff" }}>N</div>
            <div><div style={{ fontSize: 15, fontWeight: 700, color: "#fff" }}>Open NAC</div><div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)" }}>Network Access Control</div></div>
          </div>
        </div>

        <div style={{ padding: "12px 8px", flex: 1, overflowY: "auto" }}>
          {NAV.map((item, i) =>
            item.section ? (
              <div key={i} style={{ padding: "12px 12px 6px", fontSize: 10, fontWeight: 600, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1.2 }}>{item.section}</div>
            ) : (
              <div key={item.id} onClick={() => setPage(item.id)} style={{
                padding: "8px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, marginBottom: 1,
                color: page === item.id ? "#fff" : "rgba(255,255,255,0.5)", fontWeight: page === item.id ? 600 : 400,
                background: page === item.id ? T.sidebarActive : "transparent",
                display: "flex", alignItems: "center", gap: 10,
              }}>
                <span style={{ fontSize: 16, width: 20, textAlign: "center" }}>{item.icon}</span>
                <span>{item.name}</span>
              </div>
            )
          )}
        </div>

        <div style={{ padding: "12px 16px", borderTop: "1px solid rgba(255,255,255,0.08)", fontSize: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, color: health?.status === "ok" ? "#4ade80" : "#f87171" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "currentColor" }} />
            {health?.status === "ok" ? "All systems operational" : "Checking..."}
          </div>
        </div>
      </nav>

      <main style={{ flex: 1, overflow: "auto" }}>
        <div style={{ borderBottom: `1px solid ${T.border}`, background: T.white, padding: "20px 32px" }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{pg.title}</h1>
          <p style={{ fontSize: 13, color: T.t2, margin: "4px 0 0" }}>{pg.sub}</p>
        </div>
        <div style={{ padding: "24px 32px" }}><PageComponent /></div>
      </main>
    </div>
  );
}
