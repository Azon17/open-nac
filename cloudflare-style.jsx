import { useState, useEffect, useCallback } from "react";

const ENDPOINTS = [
  { mac: "aa:bb:cc:dd:ee:01", ip: "10.100.1.50", user: "ivanov@corp.local", profile: "Windows Workstation", vlan: "100", posture: "compliant", auth: "PEAP-MSCHAPv2", nas: "10.0.1.1", port: "Gi0/1", site: "HQ", seen: "2m ago", bytes_in: "1.2 GB", bytes_out: "340 MB" },
  { mac: "aa:bb:cc:dd:ee:02", ip: "10.100.1.51", user: "petrov@corp.local", profile: "macOS Workstation", vlan: "100", posture: "compliant", auth: "EAP-TLS", nas: "10.0.1.1", port: "Gi0/3", site: "HQ", seen: "5m ago", bytes_in: "890 MB", bytes_out: "120 MB" },
  { mac: "aa:bb:cc:dd:ee:03", ip: "10.100.2.20", user: "guest_0412", profile: "Android Phone", vlan: "300", posture: "exempt", auth: "CWA", nas: "10.0.0.10", port: "WLAN", site: "HQ", seen: "12m ago", bytes_in: "45 MB", bytes_out: "12 MB" },
  { mac: "aa:bb:cc:dd:ee:04", ip: "10.100.1.80", user: "—", profile: "IP Phone (Cisco 8845)", vlan: "50", posture: "exempt", auth: "MAB", nas: "10.0.1.2", port: "Gi0/5", site: "HQ", seen: "1m ago", bytes_in: "8 MB", bytes_out: "8 MB" },
  { mac: "aa:bb:cc:dd:ee:05", ip: "10.100.1.90", user: "smirnov@corp.local", profile: "Windows Workstation", vlan: "999", posture: "non_compliant", auth: "PEAP-MSCHAPv2", nas: "10.1.0.1", port: "Gi0/2", site: "Branch B", seen: "8m ago", bytes_in: "2.1 GB", bytes_out: "780 MB" },
  { mac: "aa:bb:cc:dd:ee:06", ip: "10.100.3.15", user: "contractor1@partner.com", profile: "Ubuntu 22.04", vlan: "200", posture: "compliant", auth: "EAP-TTLS", nas: "10.2.0.1", port: "Gi0/1", site: "Branch C", seen: "20m ago", bytes_in: "560 MB", bytes_out: "90 MB" },
  { mac: "aa:bb:cc:dd:ee:07", ip: "10.100.1.95", user: "—", profile: "HP LaserJet Pro", vlan: "250", posture: "exempt", auth: "MAB", nas: "10.0.1.3", port: "Gi0/8", site: "HQ", seen: "3m ago", bytes_in: "120 MB", bytes_out: "2 MB" },
  { mac: "00:11:22:33:44:55", ip: "—", user: "—", profile: "Unknown", vlan: "999", posture: "unknown", auth: "MAB", nas: "10.0.1.2", port: "Gi0/12", site: "HQ", seen: "1m ago", bytes_in: "0", bytes_out: "0" },
  { mac: "aa:bb:cc:dd:ee:08", ip: "10.100.1.60", user: "kozlov@corp.local", profile: "iPhone 15 Pro", vlan: "150", posture: "compliant", auth: "EAP-TLS", nas: "10.0.0.10", port: "WLAN", site: "HQ", seen: "4m ago", bytes_in: "230 MB", bytes_out: "45 MB" },
  { mac: "aa:bb:cc:dd:ee:09", ip: "10.100.1.70", user: "—", profile: "Axis IP Camera", vlan: "260", posture: "exempt", auth: "MAB", nas: "10.0.1.3", port: "Gi0/15", site: "HQ", seen: "1m ago", bytes_in: "4.5 GB", bytes_out: "12 MB" },
];

const POLICIES = [
  { id: 1, name: "Employees — full access", set: "Wired 802.1X", cond: "AD-Group = Domain Users AND Posture = Compliant", result: "VLAN 100 + ACL-EMPLOYEE-FULL", hits: 128470, on: true, pri: 10 },
  { id: 2, name: "Employees — quarantine", set: "Wired 802.1X", cond: "AD-Group = Domain Users AND Posture ≠ Compliant", result: "VLAN 999 + URL-redirect → remediation portal", hits: 3420, on: true, pri: 20 },
  { id: 3, name: "Contractors — limited", set: "Wired 802.1X", cond: "AD-Group = Contractors", result: "VLAN 200 + ACL-CONTRACTOR-LIMITED", hits: 15630, on: true, pri: 30 },
  { id: 4, name: "BYOD mobile — wireless", set: "Wireless", cond: "EAP-TLS Certificate AND Device-Category = Mobile", result: "VLAN 150 + ACL-BYOD-MOBILE", hits: 45120, on: true, pri: 15 },
  { id: 5, name: "Guest — internet only", set: "CWA Portal", cond: "Auth-Source = Guest Portal", result: "VLAN 300 + ACL-GUEST-INTERNET-ONLY", hits: 89210, on: true, pri: 10 },
  { id: 6, name: "VoIP phones", set: "MAB Wired", cond: "Device-Profile = IP Phone*", result: "VLAN 50 + QoS-Policy VOICE-EF", hits: 452300, on: true, pri: 5 },
  { id: 7, name: "Printers & peripherals", set: "MAB Wired", cond: "Device-Category = Peripheral", result: "VLAN 250 + ACL-PRINT-RESTRICTED", hits: 38910, on: true, pri: 10 },
  { id: 8, name: "IoT — cameras & sensors", set: "MAB Wired", cond: "Device-Category = IoT", result: "VLAN 260 + ACL-IOT-ISOLATED", hits: 12340, on: true, pri: 15 },
  { id: 9, name: "Unknown — registration", set: "Default Catch-All", cond: "Device-Profile = Unknown", result: "VLAN 999 + URL-redirect → registration portal", hits: 5670, on: true, pri: 999 },
];

const AUTH_LOG = [
  { t: "14:32:05.412", u: "ivanov@corp.local", mac: "aa:bb:cc:dd:ee:01", m: "PEAP", r: "Accept", v: "100", nas: "hq-sw1", ms: 45, policy: "Employees — full access" },
  { t: "14:31:58.891", u: "00:11:22:33:44:55", mac: "00:11:22:33:44:55", m: "MAB", r: "Accept", v: "999", nas: "hq-sw2", ms: 12, policy: "Unknown — registration" },
  { t: "14:31:42.223", u: "smirnov@corp.local", mac: "aa:bb:cc:dd:ee:05", m: "PEAP", r: "Accept", v: "999", nas: "br-b-sw1", ms: 89, policy: "Employees — quarantine" },
  { t: "14:31:30.105", u: "hacker@evil.com", mac: "de:ad:be:ef:00:01", m: "PEAP", r: "Reject", v: "—", nas: "hq-sw1", ms: 120, policy: "—" },
  { t: "14:31:15.667", u: "petrov@corp.local", mac: "aa:bb:cc:dd:ee:02", m: "EAP-TLS", r: "Accept", v: "100", nas: "hq-sw1", ms: 38, policy: "Employees — full access" },
  { t: "14:30:50.334", u: "guest_0412", mac: "aa:bb:cc:dd:ee:03", m: "CWA", r: "Accept", v: "300", nas: "hq-wlc", ms: 210, policy: "Guest — internet only" },
  { t: "14:30:22.001", u: "unknown_user", mac: "ff:ee:dd:cc:bb:aa", m: "PEAP", r: "Reject", v: "—", nas: "br-c-sw1", ms: 5002, policy: "—" },
  { t: "14:29:55.445", u: "kozlov@corp.local", mac: "aa:bb:cc:dd:ee:08", m: "EAP-TLS", r: "Accept", v: "150", nas: "hq-wlc", ms: 52, policy: "BYOD mobile — wireless" },
];

const CF = {
  bg: "#f5f5f5", white: "#ffffff", sidebar: "#1b1b1b", sidebarHover: "#2a2a2a", sidebarActive: "#333333",
  orange: "#f6821f", orangeLight: "#fff3e8", orangeDark: "#d4710f",
  blue: "#2c7cf6", blueLight: "#ebf3ff", blueDark: "#1a5fd1",
  green: "#2db252", greenLight: "#eaf7ee", greenDark: "#1d8a3e",
  red: "#d63e3e", redLight: "#fdeaea", redDark: "#b02828",
  yellow: "#e6a100", yellowLight: "#fff8e5",
  text: "#1b1b1b", textSecondary: "#6b6b6b", textTertiary: "#9b9b9b",
  border: "#e5e5e5", borderLight: "#efefef",
};

const mono = { fontFamily: "'SF Mono', 'Fira Code', 'Consolas', monospace", fontSize: 13 };

function Badge({ children, color = "gray", small }) {
  const colors = {
    green: { bg: CF.greenLight, fg: CF.greenDark, dot: CF.green },
    red: { bg: CF.redLight, fg: CF.redDark, dot: CF.red },
    orange: { bg: CF.orangeLight, fg: CF.orangeDark, dot: CF.orange },
    blue: { bg: CF.blueLight, fg: CF.blueDark, dot: CF.blue },
    gray: { bg: "#f0f0f0", fg: CF.textSecondary, dot: CF.textTertiary },
    yellow: { bg: CF.yellowLight, fg: "#8a6200", dot: CF.yellow },
  };
  const c = colors[color] || colors.gray;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: c.bg, color: c.fg, padding: small ? "1px 8px" : "3px 10px", borderRadius: 4, fontSize: small ? 11 : 12, fontWeight: 500, whiteSpace: "nowrap", lineHeight: "18px" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: c.dot, flexShrink: 0 }} />
      {children}
    </span>
  );
}

function Card({ children, title, action, noPad, style: sx }) {
  return (
    <div style={{ background: CF.white, borderRadius: 8, border: `1px solid ${CF.border}`, overflow: "hidden", ...sx }}>
      {title && (
        <div style={{ padding: "14px 20px", borderBottom: `1px solid ${CF.borderLight}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: CF.text }}>{title}</span>
          {action}
        </div>
      )}
      {noPad ? children : <div style={{ padding: 20 }}>{children}</div>}
    </div>
  );
}

function Metric({ label, value, sub, trend }) {
  return (
    <div style={{ flex: 1 }}>
      <div style={{ fontSize: 12, color: CF.textSecondary, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 600, color: CF.text, lineHeight: 1.1, letterSpacing: -1 }}>{value}</div>
      {(sub || trend) && (
        <div style={{ fontSize: 12, color: trend === "up" ? CF.green : trend === "down" ? CF.red : CF.textTertiary, marginTop: 4, display: "flex", alignItems: "center", gap: 3 }}>
          {trend === "up" && "↑"}{trend === "down" && "↓"}{sub}
        </div>
      )}
    </div>
  );
}

function TH({ children, w }) {
  return <th style={{ padding: "8px 16px", textAlign: "left", fontSize: 12, fontWeight: 500, color: CF.textSecondary, borderBottom: `1px solid ${CF.border}`, whiteSpace: "nowrap", width: w }}>{children}</th>;
}
function TD({ children, mono: m, muted, w }) {
  return <td style={{ padding: "9px 16px", fontSize: 13, color: muted ? CF.textTertiary : CF.text, borderBottom: `1px solid ${CF.borderLight}`, whiteSpace: "nowrap", ...(m ? mono : {}), width: w }}>{children}</td>;
}

function Btn({ children, primary, danger, small, onClick }) {
  const base = { padding: small ? "5px 12px" : "8px 16px", borderRadius: 4, fontSize: small ? 12 : 13, fontWeight: 500, cursor: "pointer", border: "none", transition: "all 0.1s" };
  const style = danger
    ? { ...base, background: CF.redLight, color: CF.red }
    : primary
    ? { ...base, background: CF.orange, color: "#fff" }
    : { ...base, background: CF.white, color: CF.text, border: `1px solid ${CF.border}` };
  return <button style={style} onClick={onClick}>{children}</button>;
}

function SideNav({ items, active, onSelect }) {
  return (
    <nav style={{ background: CF.sidebar, width: 220, display: "flex", flexDirection: "column", flexShrink: 0 }}>
      <div style={{ padding: "20px 18px 16px", borderBottom: "1px solid #333" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: CF.orange, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 14, color: "#fff" }}>N</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#fff", lineHeight: 1.2 }}>Open NAC</div>
            <div style={{ fontSize: 11, color: "#888" }}>corp.local</div>
          </div>
        </div>
      </div>

      <div style={{ padding: "12px 8px", flex: 1, overflowY: "auto" }}>
        {items.map(section => (
          <div key={section.label} style={{ marginBottom: 16 }}>
            {section.label && <div style={{ padding: "4px 12px 6px", fontSize: 10, fontWeight: 600, color: "#666", textTransform: "uppercase", letterSpacing: 1.2 }}>{section.label}</div>}
            {section.items.map(item => (
              <div key={item.id} onClick={() => onSelect(item.id)} style={{
                padding: "7px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13, marginBottom: 1,
                color: active === item.id ? "#fff" : "#aaa", fontWeight: active === item.id ? 500 : 400,
                background: active === item.id ? CF.sidebarActive : "transparent",
                display: "flex", alignItems: "center", justifyContent: "space-between",
              }}>
                <span>{item.name}</span>
                {item.badge && <span style={{ background: CF.red, color: "#fff", fontSize: 10, padding: "1px 6px", borderRadius: 10, fontWeight: 600 }}>{item.badge}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>

      <div style={{ padding: "12px 16px", borderTop: "1px solid #333", fontSize: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#6f6", marginBottom: 6 }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: "#6f6" }} />All systems operational</div>
        <div style={{ color: "#666", fontSize: 11 }}>FreeRADIUS ×2 · Galera 3/3 · Redis ✓</div>
      </div>
    </nav>
  );
}

function Modal({ children, onClose, title, wide }) {
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)", display: "flex", alignItems: "flex-start", justifyContent: "center", zIndex: 1000, paddingTop: 60, overflowY: "auto" }} onClick={onClose}>
      <div style={{ background: CF.white, borderRadius: 12, width: wide ? 640 : 500, maxWidth: "95vw", boxShadow: "0 20px 60px rgba(0,0,0,0.2)" }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: "16px 24px", borderBottom: `1px solid ${CF.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>{title}</span>
          <span style={{ cursor: "pointer", color: CF.textTertiary, fontSize: 22, lineHeight: 1 }} onClick={onClose}>×</span>
        </div>
        <div style={{ padding: 24 }}>{children}</div>
      </div>
    </div>
  );
}

function FieldRow({ label, value, mono: m }) {
  return (
    <div style={{ display: "flex", padding: "10px 0", borderBottom: `1px solid ${CF.borderLight}` }}>
      <span style={{ width: 160, fontSize: 13, color: CF.textSecondary, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 13, color: CF.text, ...(m ? mono : {}), wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

const postureBadge = s => {
  const m = { compliant: ["green", "Compliant"], non_compliant: ["red", "Non-compliant"], exempt: ["blue", "Exempt"], unknown: ["gray", "Unknown"] };
  const [c, l] = m[s] || m.unknown;
  return <Badge color={c}>{l}</Badge>;
};

const NAV = [
  { label: "", items: [{ id: "overview", name: "Overview" }] },
  { label: "Access control", items: [
    { id: "endpoints", name: "Endpoints", badge: null },
    { id: "sessions", name: "Live sessions" },
    { id: "policies", name: "Authorization policies" },
    { id: "profiling", name: "Device profiling" },
  ]},
  { label: "Services", items: [
    { id: "guest", name: "Guest portal" },
    { id: "posture", name: "Posture assessment" },
    { id: "byod", name: "BYOD / certificates" },
    { id: "tacacs", name: "TACACS+" },
  ]},
  { label: "Infrastructure", items: [
    { id: "nas", name: "Network devices" },
    { id: "radius", name: "RADIUS servers" },
    { id: "logs", name: "Authentication log" },
  ]},
];

export default function App() {
  const [page, setPage] = useState("overview");
  const [detail, setDetail] = useState(null);
  const [policyEdit, setPolicyEdit] = useState(null);
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState("all");

  const filteredEP = ENDPOINTS.filter(e => {
    const q = search.toLowerCase();
    const matchSearch = !q || e.mac.includes(q) || e.ip.includes(q) || e.user.toLowerCase().includes(q) || e.profile.toLowerCase().includes(q);
    const matchTab = tab === "all" || (tab === "compliant" && e.posture === "compliant") || (tab === "issues" && (e.posture === "non_compliant" || e.posture === "unknown")) || (tab === "iot" && ["IP Phone", "HP LaserJet Pro", "Axis IP Camera"].some(p => e.profile.includes(p)));
    return matchSearch && matchTab;
  });

  const renderOverview = () => (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <Card><Metric label="Total endpoints" value={ENDPOINTS.length} sub="+3 last hour" trend="up" /></Card>
        <Card><Metric label="Authentications / min" value="47" sub="avg latency 62ms" /></Card>
        <Card><Metric label="Compliant" value={`${Math.round(ENDPOINTS.filter(e=>e.posture==="compliant").length/ENDPOINTS.length*100)}%`} sub={`${ENDPOINTS.filter(e=>e.posture==="compliant").length} of ${ENDPOINTS.length}`} trend="up" /></Card>
        <Card><Metric label="Active alerts" value="2" sub="1 critical, 1 warning" trend="down" /></Card>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "3fr 2fr", gap: 20 }}>
        <Card title="Recent authentications" noPad action={<span style={{ fontSize: 12, color: CF.blue, cursor: "pointer" }} onClick={() => setPage("logs")}>View all →</span>}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr><TH>Time</TH><TH>Identity</TH><TH>Method</TH><TH>Result</TH><TH>Policy matched</TH><TH>Latency</TH></tr></thead>
            <tbody>
              {AUTH_LOG.slice(0, 6).map((a, i) => (
                <tr key={i}>
                  <TD mono>{a.t.split(".")[0]}</TD>
                  <TD>{a.u.length > 20 ? a.u.slice(0, 20) + "…" : a.u}</TD>
                  <TD><Badge color={a.m === "EAP-TLS" ? "green" : a.m === "PEAP" ? "blue" : a.m === "MAB" ? "gray" : "orange"} small>{a.m}</Badge></TD>
                  <TD><Badge color={a.r === "Accept" ? "green" : "red"} small>{a.r}</Badge></TD>
                  <TD muted>{a.policy}</TD>
                  <TD mono muted>{a.ms}ms</TD>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <Card title="Endpoint categories">
            {[
              { name: "Workstations", n: 3, pct: 30, color: CF.blue },
              { name: "Mobile / BYOD", n: 2, pct: 20, color: CF.orange },
              { name: "VoIP phones", n: 1, pct: 10, color: "#8b5cf6" },
              { name: "Printers", n: 1, pct: 10, color: CF.green },
              { name: "IoT / Cameras", n: 1, pct: 10, color: "#06b6d4" },
              { name: "Unknown", n: 1, pct: 10, color: CF.textTertiary },
            ].map((c, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: c.color, flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: 13, color: CF.text }}>{c.name}</span>
                <span style={{ fontSize: 13, color: CF.textSecondary, ...mono }}>{c.n}</span>
                <div style={{ width: 60, height: 4, borderRadius: 2, background: CF.borderLight }}>
                  <div style={{ height: "100%", borderRadius: 2, background: c.color, width: `${c.pct}%` }} />
                </div>
              </div>
            ))}
          </Card>

          <Card title="Alerts" noPad>
            <div style={{ padding: "12px 20px", background: CF.redLight, borderBottom: `1px solid ${CF.border}`, display: "flex", gap: 10, alignItems: "flex-start" }}>
              <span style={{ color: CF.red, fontSize: 14, marginTop: 1 }}>●</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: CF.red }}>Non-compliant endpoint in production VLAN</div>
                <div style={{ fontSize: 12, color: CF.textSecondary, marginTop: 2 }}>smirnov@corp.local — antivirus definitions expired. Auto-quarantined to VLAN 999.</div>
              </div>
            </div>
            <div style={{ padding: "12px 20px", background: CF.yellowLight, display: "flex", gap: 10, alignItems: "flex-start" }}>
              <span style={{ color: CF.yellow, fontSize: 14, marginTop: 1 }}>●</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: "#8a6200" }}>Branch C — NAS not responding</div>
                <div style={{ fontSize: 12, color: CF.textSecondary, marginTop: 2 }}>br-c-sw1 (10.2.0.1) missed 3 status-server checks. Last response 12 min ago.</div>
              </div>
            </div>
          </Card>

          <Card title="Sites">
            {[
              { name: "HQ (Central)", eps: 7, status: "Operational", color: "green" },
              { name: "Branch B", eps: 1, status: "Operational", color: "green" },
              { name: "Branch C", eps: 1, status: "Degraded", color: "yellow" },
            ].map((s, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 0", borderBottom: i < 2 ? `1px solid ${CF.borderLight}` : "none" }}>
                <span style={{ fontSize: 13, fontWeight: 500 }}>{s.name}</span>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{ fontSize: 12, color: CF.textTertiary }}>{s.eps} endpoints</span>
                  <Badge color={s.color} small>{s.status}</Badge>
                </div>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </div>
  );

  const renderEndpoints = () => (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 16, alignItems: "center" }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter by MAC, IP, username, or device profile…" style={{ flex: 1, padding: "8px 14px", borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 13, outline: "none", color: CF.text, background: CF.white }} />
        <Btn>Export</Btn>
        <Btn primary>+ Register device</Btn>
      </div>

      <div style={{ display: "flex", gap: 1, marginBottom: 16, background: CF.border, borderRadius: 6, overflow: "hidden" }}>
        {[["all", "All"], ["compliant", "Compliant"], ["issues", "Issues"], ["iot", "IoT / OT"]].map(([k, l]) => (
          <div key={k} onClick={() => setTab(k)} style={{ flex: 1, padding: "8px 0", textAlign: "center", fontSize: 13, fontWeight: 500, cursor: "pointer", background: tab === k ? CF.white : CF.bg, color: tab === k ? CF.text : CF.textSecondary, borderBottom: tab === k ? `2px solid ${CF.orange}` : "2px solid transparent" }}>{l}</div>
        ))}
      </div>

      <Card noPad>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr><TH>MAC address</TH><TH>IP</TH><TH>Identity</TH><TH>Device profile</TH><TH>VLAN</TH><TH>Posture</TH><TH>Auth</TH><TH>Site</TH><TH>Seen</TH></tr></thead>
          <tbody>
            {filteredEP.map((e, i) => (
              <tr key={i} onClick={() => setDetail(e)} style={{ cursor: "pointer", background: e.posture === "non_compliant" ? "rgba(214,62,62,0.03)" : "transparent" }}>
                <TD mono>{e.mac}</TD>
                <TD mono>{e.ip}</TD>
                <TD>{e.user}</TD>
                <TD>{e.profile}</TD>
                <TD mono>{e.vlan}</TD>
                <TD>{postureBadge(e.posture)}</TD>
                <TD><Badge color={e.auth.includes("TLS") ? "green" : e.auth.includes("PEAP") || e.auth.includes("TTLS") ? "blue" : e.auth === "MAB" ? "gray" : "orange"} small>{e.auth}</Badge></TD>
                <TD>{e.site}</TD>
                <TD muted>{e.seen}</TD>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: "12px 16px", borderTop: `1px solid ${CF.border}`, fontSize: 12, color: CF.textTertiary, display: "flex", justifyContent: "space-between" }}>
          <span>Showing {filteredEP.length} of {ENDPOINTS.length} endpoints</span>
          <span>Auto-refresh: 10s</span>
        </div>
      </Card>

      {detail && (
        <Modal title="Endpoint details" onClose={() => setDetail(null)} wide>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
            <div>
              <FieldRow label="MAC address" value={detail.mac} mono />
              <FieldRow label="IP address" value={detail.ip} mono />
              <FieldRow label="Identity" value={detail.user} />
              <FieldRow label="Device profile" value={detail.profile} />
              <FieldRow label="Auth method" value={detail.auth} />
              <FieldRow label="Last seen" value={detail.seen} />
            </div>
            <div style={{ paddingLeft: 24 }}>
              <FieldRow label="VLAN" value={detail.vlan} mono />
              <FieldRow label="Posture" value={postureBadge(detail.posture)} />
              <FieldRow label="NAS" value={`${detail.nas} (${detail.port})`} mono />
              <FieldRow label="Site" value={detail.site} />
              <FieldRow label="Traffic in" value={detail.bytes_in} />
              <FieldRow label="Traffic out" value={detail.bytes_out} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 20, paddingTop: 16, borderTop: `1px solid ${CF.border}` }}>
            <Btn primary onClick={() => alert(`CoA Reauthenticate → ${detail.mac}`)}>Reauthenticate</Btn>
            <Btn onClick={() => alert(`CoA Port-Bounce → ${detail.mac}`)}>Port bounce</Btn>
            <Btn danger onClick={() => alert(`CoA Disconnect → ${detail.mac}`)}>Disconnect session</Btn>
            <div style={{ flex: 1 }} />
            <Btn onClick={() => alert("Edit profile")}>Edit profile</Btn>
          </div>
        </Modal>
      )}
    </div>
  );

  const renderPolicies = () => (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: CF.textSecondary }}>{POLICIES.length} rules · {[...new Set(POLICIES.map(p => p.set))].length} policy sets · Rules evaluated top-to-bottom by priority</div>
        <Btn primary>+ Create rule</Btn>
      </div>
      <Card noPad>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr><TH w={40}>#</TH><TH>Rule name</TH><TH>Policy set</TH><TH>Conditions</TH><TH>Authorization result</TH><TH w={80}>Hits</TH><TH w={50}>On</TH></tr></thead>
          <tbody>
            {POLICIES.map((p, i) => (
              <tr key={i} style={{ cursor: "pointer" }} onClick={() => setPolicyEdit(p)}>
                <TD mono muted>{p.pri}</TD>
                <TD><span style={{ fontWeight: 500 }}>{p.name}</span></TD>
                <TD><Badge color="gray" small>{p.set}</Badge></TD>
                <TD><span style={{ fontSize: 12, color: CF.textSecondary, ...mono }}>{p.cond.length > 45 ? p.cond.slice(0, 45) + "…" : p.cond}</span></TD>
                <TD><span style={{ fontSize: 12, color: CF.blue, ...mono }}>{p.result.length > 40 ? p.result.slice(0, 40) + "…" : p.result}</span></TD>
                <TD mono muted>{(p.hits/1000).toFixed(1)}k</TD>
                <TD>
                  <div style={{ width: 32, height: 18, borderRadius: 9, background: p.on ? CF.green : CF.border, position: "relative", cursor: "pointer" }}>
                    <div style={{ width: 14, height: 14, borderRadius: "50%", background: "#fff", position: "absolute", top: 2, left: p.on ? 16 : 2, transition: "left 0.15s", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }} />
                  </div>
                </TD>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      {policyEdit && (
        <Modal title={`Edit rule: ${policyEdit.name}`} onClose={() => setPolicyEdit(null)} wide>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: CF.textSecondary, marginBottom: 6 }}>Rule name</label>
            <input defaultValue={policyEdit.name} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: CF.textSecondary, marginBottom: 6 }}>Policy set</label>
              <select defaultValue={policyEdit.set} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 13, outline: "none", background: CF.white }}>
                <option>Wired 802.1X</option><option>Wireless</option><option>MAB Wired</option><option>CWA Portal</option><option>Default Catch-All</option>
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: CF.textSecondary, marginBottom: 6 }}>Priority</label>
              <input type="number" defaultValue={policyEdit.pri} style={{ width: "100%", padding: "8px 12px", borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 13, outline: "none", boxSizing: "border-box" }} />
            </div>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: CF.textSecondary, marginBottom: 6 }}>Conditions</label>
            <textarea defaultValue={policyEdit.cond} rows={3} style={{ width: "100%", padding: 12, borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 13, outline: "none", resize: "vertical", boxSizing: "border-box", ...mono }} />
            <div style={{ fontSize: 11, color: CF.textTertiary, marginTop: 4 }}>Use AND / OR operators. Available attributes: AD-Group, Posture, Device-Profile, Device-Category, Auth-Method, EAP-Type, NAS-IP, Site, Certificate, Auth-Source</div>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: CF.textSecondary, marginBottom: 6 }}>Authorization result</label>
            <textarea defaultValue={policyEdit.result} rows={2} style={{ width: "100%", padding: 12, borderRadius: 6, border: `1px solid ${CF.border}`, fontSize: 13, outline: "none", resize: "vertical", boxSizing: "border-box", color: CF.blue, ...mono }} />
            <div style={{ fontSize: 11, color: CF.textTertiary, marginTop: 4 }}>Available actions: VLAN, ACL, SGT, dACL, URL-redirect, QoS-Policy, Session-Timeout, CoA-action</div>
          </div>
          <div style={{ display: "flex", gap: 8, paddingTop: 16, borderTop: `1px solid ${CF.border}` }}>
            <Btn primary>Save changes</Btn>
            <Btn onClick={() => setPolicyEdit(null)}>Cancel</Btn>
            <div style={{ flex: 1 }} />
            <Btn danger>Delete rule</Btn>
          </div>
        </Modal>
      )}
    </div>
  );

  const renderLogs = () => (
    <Card title="Authentication log" noPad action={<div style={{ display: "flex", gap: 8 }}><Btn small>Export</Btn><Btn small>Clear filters</Btn></div>}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr><TH>Timestamp</TH><TH>Identity</TH><TH>MAC</TH><TH>Method</TH><TH>Result</TH><TH>VLAN</TH><TH>NAS</TH><TH>Policy matched</TH><TH>Latency</TH></tr></thead>
        <tbody>
          {AUTH_LOG.map((a, i) => (
            <tr key={i} style={{ background: a.r === "Reject" ? "rgba(214,62,62,0.03)" : "transparent" }}>
              <TD mono>{a.t}</TD>
              <TD>{a.u}</TD>
              <TD mono>{a.mac}</TD>
              <TD><Badge color={a.m === "EAP-TLS" ? "green" : a.m === "PEAP" ? "blue" : a.m === "MAB" ? "gray" : "orange"} small>{a.m}</Badge></TD>
              <TD><Badge color={a.r === "Accept" ? "green" : "red"} small>{a.r}</Badge></TD>
              <TD mono>{a.v}</TD>
              <TD>{a.nas}</TD>
              <TD muted>{a.policy}</TD>
              <TD mono style={{ color: a.ms > 1000 ? CF.red : a.ms > 100 ? CF.yellow : CF.textTertiary }}>{a.ms}ms</TD>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );

  const renderNAS = () => (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: CF.textSecondary }}>Network access devices sending RADIUS/TACACS+ requests</div>
        <Btn primary>+ Add device</Btn>
      </div>
      <Card noPad>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr><TH>IP address</TH><TH>Hostname</TH><TH>Model</TH><TH>Site</TH><TH>Protocol</TH><TH>Auth requests</TH><TH>Last seen</TH><TH>Status</TH></tr></thead>
          <tbody>
            {[
              { ip: "10.0.1.1", host: "hq-access-sw1", model: "Catalyst 9300-48P", site: "HQ", proto: "RADIUS + TACACS+", reqs: "12,340", last: "< 1 min", ok: true },
              { ip: "10.0.1.2", host: "hq-access-sw2", model: "Catalyst 9300-24P", site: "HQ", proto: "RADIUS + TACACS+", reqs: "8,921", last: "< 1 min", ok: true },
              { ip: "10.0.1.3", host: "hq-access-sw3", model: "Catalyst 9200-48", site: "HQ", proto: "RADIUS", reqs: "5,102", last: "< 1 min", ok: true },
              { ip: "10.0.0.10", host: "hq-wlc-01", model: "Catalyst 9800-CL", site: "HQ", proto: "RADIUS", reqs: "34,567", last: "< 1 min", ok: true },
              { ip: "10.0.0.20", host: "hq-vpn-gw", model: "ASA 5555-X", site: "HQ", proto: "RADIUS", reqs: "2,103", last: "3 min", ok: true },
              { ip: "10.1.0.1", host: "br-b-sw1", model: "Juniper EX3400-48P", site: "Branch B", proto: "RADIUS + TACACS+", reqs: "3,201", last: "< 1 min", ok: true },
              { ip: "10.2.0.1", host: "br-c-sw1", model: "Aruba CX 6300-48", site: "Branch C", proto: "RADIUS", reqs: "2,890", last: "12 min", ok: false },
            ].map((d, i) => (
              <tr key={i}>
                <TD mono>{d.ip}</TD>
                <TD><span style={{ fontWeight: 500 }}>{d.host}</span></TD>
                <TD>{d.model}</TD>
                <TD>{d.site}</TD>
                <TD><span style={{ fontSize: 12, color: CF.textSecondary }}>{d.proto}</span></TD>
                <TD mono>{d.reqs}</TD>
                <TD muted>{d.last}</TD>
                <TD><Badge color={d.ok ? "green" : "red"} small>{d.ok ? "Active" : "Unreachable"}</Badge></TD>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );

  const pageMap = {
    overview: { title: "Overview", sub: "Network access control dashboard", render: renderOverview },
    endpoints: { title: "Endpoints", sub: "All devices authenticated through NAC", render: renderEndpoints },
    policies: { title: "Authorization policies", sub: "Rules that determine network access level", render: renderPolicies },
    logs: { title: "Authentication log", sub: "Real-time RADIUS authentication events", render: renderLogs },
    nas: { title: "Network devices", sub: "Switches, WLCs, and VPN gateways", render: renderNAS },
    sessions: { title: "Live sessions", sub: "Currently active RADIUS sessions", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>Live sessions view — will be connected to Redis session directory</div></Card> },
    profiling: { title: "Device profiling", sub: "Fingerbank-powered device identification", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>Profiling engine dashboard — Fingerbank + p0f + nmap results</div></Card> },
    guest: { title: "Guest portal", sub: "Self-registration, sponsored, and hotspot access", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>Guest portal management — accounts, templates, active sessions</div></Card> },
    posture: { title: "Posture assessment", sub: "Endpoint compliance via osquery + Fleet", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>Posture compliance dashboard — osquery policies, Fleet integration</div></Card> },
    byod: { title: "BYOD / Certificates", sub: "Device onboarding and certificate lifecycle", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>BYOD onboarding — SCEP/EST enrollment, EJBCA integration</div></Card> },
    tacacs: { title: "TACACS+", sub: "Network device administration", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>TACACS+ device admin — command sets, shell profiles, audit log</div></Card> },
    radius: { title: "RADIUS servers", sub: "FreeRADIUS cluster health and configuration", render: () => <Card><div style={{color: CF.textTertiary, textAlign:"center", padding: 40}}>RADIUS cluster management — node health, thread pool, TPS metrics</div></Card> },
  };

  const pg = pageMap[page] || pageMap.overview;

  return (
    <div style={{ display: "flex", height: "100vh", background: CF.bg, fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif", color: CF.text, fontSize: 14 }}>
      <SideNav items={NAV} active={page} onSelect={setPage} />
      <main style={{ flex: 1, overflow: "auto" }}>
        <div style={{ borderBottom: `1px solid ${CF.border}`, background: CF.white, padding: "20px 32px" }}>
          <h1 style={{ fontSize: 20, fontWeight: 600, margin: 0, lineHeight: 1.3 }}>{pg.title}</h1>
          <p style={{ fontSize: 13, color: CF.textSecondary, margin: "4px 0 0" }}>{pg.sub}</p>
        </div>
        <div style={{ padding: "24px 32px" }}>{pg.render()}</div>
      </main>
    </div>
  );
}
