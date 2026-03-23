import { useState, useEffect } from "react";

const MOCK_ENDPOINTS = [
  { mac: "aa:bb:cc:dd:ee:01", ip: "10.100.1.50", user: "ivanov@corp.local", profile: "Windows Workstation", vlan: "100", posture: "compliant", auth: "PEAP-MSCHAPv2", nas: "10.0.1.1", port: "Gi0/1", site: "HQ", lastSeen: "2 мин назад" },
  { mac: "aa:bb:cc:dd:ee:02", ip: "10.100.1.51", user: "petrov@corp.local", profile: "macOS Workstation", vlan: "100", posture: "compliant", auth: "EAP-TLS", nas: "10.0.1.1", port: "Gi0/3", site: "HQ", lastSeen: "5 мин назад" },
  { mac: "aa:bb:cc:dd:ee:03", ip: "10.100.2.20", user: "guest_0412", profile: "Android Phone", vlan: "300", posture: "exempt", auth: "CWA", nas: "10.0.0.10", port: "WLAN", site: "HQ", lastSeen: "12 мин назад" },
  { mac: "aa:bb:cc:dd:ee:04", ip: "10.100.1.80", user: "—", profile: "IP Phone", vlan: "50", posture: "exempt", auth: "MAB", nas: "10.0.1.2", port: "Gi0/5", site: "HQ", lastSeen: "1 мин назад" },
  { mac: "aa:bb:cc:dd:ee:05", ip: "10.100.1.90", user: "smirnov@corp.local", profile: "Windows Workstation", vlan: "999", posture: "non_compliant", auth: "PEAP-MSCHAPv2", nas: "10.1.0.1", port: "Gi0/2", site: "Branch B", lastSeen: "8 мин назад" },
  { mac: "aa:bb:cc:dd:ee:06", ip: "10.100.3.15", user: "contractor1@partner.com", profile: "Linux Workstation", vlan: "200", posture: "compliant", auth: "EAP-TTLS", nas: "10.2.0.1", port: "Gi0/1", site: "Branch C", lastSeen: "20 мин назад" },
  { mac: "aa:bb:cc:dd:ee:07", ip: "10.100.1.95", user: "—", profile: "Printer", vlan: "250", posture: "exempt", auth: "MAB", nas: "10.0.1.3", port: "Gi0/8", site: "HQ", lastSeen: "3 мин назад" },
  { mac: "00:11:22:33:44:55", ip: "—", user: "—", profile: "Unknown", vlan: "999", posture: "unknown", auth: "MAB", nas: "10.0.1.2", port: "Gi0/12", site: "HQ", lastSeen: "1 мин назад" },
];

const MOCK_POLICIES = [
  { id: 1, name: "Employees Full Access", set: "Wired", condition: "AD-Group = Domain Users AND Posture = Compliant", action: "VLAN 100, ACL EMPLOYEE_FULL", hits: 12847, enabled: true },
  { id: 2, name: "Employees Quarantine", set: "Wired", condition: "AD-Group = Domain Users AND Posture = Non-Compliant", action: "VLAN 999, URL-redirect → Remediation", hits: 342, enabled: true },
  { id: 3, name: "Contractors Limited", set: "Wired", condition: "AD-Group = Contractors", action: "VLAN 200, ACL CONTRACTOR_LIMITED", hits: 1563, enabled: true },
  { id: 4, name: "Guest WiFi", set: "Wireless", condition: "Auth-Method = CWA AND Portal = Guest", action: "VLAN 300, ACL GUEST_INTERNET", hits: 8921, enabled: true },
  { id: 5, name: "BYOD Onboarding", set: "Wireless", condition: "Certificate = None AND Device = Mobile", action: "VLAN 999, URL-redirect → BYOD Portal", hits: 2104, enabled: true },
  { id: 6, name: "VoIP Phones", set: "Wired", condition: "Profile = IP Phone", action: "VLAN 50, QoS DSCP EF", hits: 45230, enabled: true },
  { id: 7, name: "IoT Devices", set: "Wired", condition: "Profile-Category = IoT", action: "VLAN 260, ACL IOT_RESTRICTED", hits: 3891, enabled: true },
  { id: 8, name: "Unknown Devices", set: "Default", condition: "Profile = Unknown", action: "VLAN 999, URL-redirect → Registration", hits: 567, enabled: true },
];

const MOCK_AUTH_LOG = [
  { time: "14:32:05", user: "ivanov@corp.local", mac: "aa:bb:cc:dd:ee:01", method: "PEAP", result: "Accept", vlan: "100", nas: "10.0.1.1", latency: "45ms" },
  { time: "14:31:58", user: "00:11:22:33:44:55", mac: "00:11:22:33:44:55", method: "MAB", result: "Accept", vlan: "999", nas: "10.0.1.2", latency: "12ms" },
  { time: "14:31:42", user: "smirnov@corp.local", mac: "aa:bb:cc:dd:ee:05", method: "PEAP", result: "Accept", vlan: "999", nas: "10.1.0.1", latency: "89ms" },
  { time: "14:31:30", user: "hacker@evil.com", mac: "de:ad:be:ef:00:01", method: "PEAP", result: "Reject", vlan: "—", nas: "10.0.1.1", latency: "120ms" },
  { time: "14:31:15", user: "petrov@corp.local", mac: "aa:bb:cc:dd:ee:02", method: "EAP-TLS", result: "Accept", vlan: "100", nas: "10.0.1.1", latency: "38ms" },
  { time: "14:30:50", user: "guest_0412", mac: "aa:bb:cc:dd:ee:03", method: "CWA", result: "Accept", vlan: "300", nas: "10.0.0.10", latency: "210ms" },
  { time: "14:30:22", user: "unknown", mac: "ff:ee:dd:cc:bb:aa", method: "PEAP", result: "Reject", vlan: "—", nas: "10.2.0.1", latency: "5002ms" },
];

const COLORS = {
  bg: "#0a0e17", card: "#111827", cardHover: "#1a2234", border: "#1e293b",
  accent: "#3b82f6", accentDim: "#1e3a5f", green: "#10b981", greenDim: "#064e3b",
  red: "#ef4444", redDim: "#7f1d1d", amber: "#f59e0b", amberDim: "#78350f",
  purple: "#8b5cf6", purpleDim: "#4c1d95", teal: "#14b8a6", tealDim: "#134e4a",
  text: "#e2e8f0", textDim: "#64748b", textMuted: "#475569",
};

const PostureBadge = ({ status }) => {
  const map = {
    compliant: { bg: COLORS.greenDim, color: COLORS.green, label: "Compliant" },
    non_compliant: { bg: COLORS.redDim, color: COLORS.red, label: "Non-Compliant" },
    exempt: { bg: COLORS.purpleDim, color: COLORS.purple, label: "Exempt" },
    unknown: { bg: "#1e293b", color: COLORS.textDim, label: "Unknown" },
  };
  const s = map[status] || map.unknown;
  return <span style={{ background: s.bg, color: s.color, padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 500, whiteSpace: "nowrap" }}>{s.label}</span>;
};

const AuthBadge = ({ result }) => {
  const isAccept = result === "Accept";
  return <span style={{ background: isAccept ? COLORS.greenDim : COLORS.redDim, color: isAccept ? COLORS.green : COLORS.red, padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 500 }}>{result}</span>;
};

const StatCard = ({ label, value, sub, color }) => (
  <div style={{ background: COLORS.card, borderRadius: 12, padding: "20px 24px", border: `1px solid ${COLORS.border}`, flex: 1, minWidth: 150 }}>
    <div style={{ fontSize: 13, color: COLORS.textDim, marginBottom: 6, letterSpacing: 0.3 }}>{label}</div>
    <div style={{ fontSize: 32, fontWeight: 600, color: color || COLORS.text, lineHeight: 1.1 }}>{value}</div>
    {sub && <div style={{ fontSize: 12, color: COLORS.textMuted, marginTop: 6 }}>{sub}</div>}
  </div>
);

const SidebarItem = ({ icon, label, active, onClick, badge }) => (
  <div onClick={onClick} style={{
    display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", borderRadius: 8, cursor: "pointer", transition: "all 0.15s",
    background: active ? COLORS.accentDim : "transparent", color: active ? COLORS.accent : COLORS.textDim,
    fontSize: 14, fontWeight: active ? 500 : 400, position: "relative",
  }}>
    <span style={{ fontSize: 18, width: 22, textAlign: "center" }}>{icon}</span>
    <span style={{ flex: 1 }}>{label}</span>
    {badge && <span style={{ background: COLORS.redDim, color: COLORS.red, fontSize: 11, padding: "1px 7px", borderRadius: 10, fontWeight: 600 }}>{badge}</span>}
  </div>
);

const TableHead = ({ children }) => (
  <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 11, fontWeight: 500, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 0.8, borderBottom: `1px solid ${COLORS.border}`, whiteSpace: "nowrap" }}>{children}</th>
);

const TableCell = ({ children, mono }) => (
  <td style={{ padding: "10px 14px", fontSize: 13, color: COLORS.text, borderBottom: `1px solid ${COLORS.border}`, fontFamily: mono ? "'JetBrains Mono', monospace" : "inherit", whiteSpace: "nowrap" }}>{children}</td>
);

export default function NACDashboard() {
  const [page, setPage] = useState("dashboard");
  const [time, setTime] = useState(new Date());
  const [endpointFilter, setEndpointFilter] = useState("");
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [policyModal, setPolicyModal] = useState(null);

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 10000);
    return () => clearInterval(t);
  }, []);

  const stats = {
    total: MOCK_ENDPOINTS.length,
    compliant: MOCK_ENDPOINTS.filter(e => e.posture === "compliant").length,
    nonCompliant: MOCK_ENDPOINTS.filter(e => e.posture === "non_compliant").length,
    unknown: MOCK_ENDPOINTS.filter(e => e.profile === "Unknown").length,
    sites: [...new Set(MOCK_ENDPOINTS.map(e => e.site))].length,
    authPerMin: 47,
    rejectRate: "3.2%",
  };

  const filteredEndpoints = MOCK_ENDPOINTS.filter(e =>
    !endpointFilter || e.mac.includes(endpointFilter.toLowerCase()) || e.user.toLowerCase().includes(endpointFilter.toLowerCase()) || e.profile.toLowerCase().includes(endpointFilter.toLowerCase()) || e.ip.includes(endpointFilter)
  );

  const renderDashboard = () => (
    <div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 28 }}>
        <StatCard label="Active endpoints" value={stats.total} sub={`${stats.sites} sites`} color={COLORS.accent} />
        <StatCard label="Compliant" value={stats.compliant} sub={`${Math.round(stats.compliant/stats.total*100)}% of total`} color={COLORS.green} />
        <StatCard label="Non-compliant" value={stats.nonCompliant} sub="Quarantine VLAN" color={COLORS.red} />
        <StatCard label="Auth rate" value={`${stats.authPerMin}/m`} sub={`Reject: ${stats.rejectRate}`} color={COLORS.amber} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        <div style={{ background: COLORS.card, borderRadius: 12, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
          <div style={{ padding: "16px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 15, fontWeight: 500, color: COLORS.text }}>Live authentications</span>
            <span style={{ fontSize: 12, color: COLORS.textMuted }}>Last 5 min</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead><tr>
                <TableHead>Time</TableHead><TableHead>User</TableHead><TableHead>Method</TableHead><TableHead>Result</TableHead><TableHead>VLAN</TableHead><TableHead>Latency</TableHead>
              </tr></thead>
              <tbody>
                {MOCK_AUTH_LOG.map((a, i) => (
                  <tr key={i} style={{ background: i % 2 ? "transparent" : "rgba(255,255,255,0.015)" }}>
                    <TableCell mono>{a.time}</TableCell>
                    <TableCell>{a.user.length > 22 ? a.user.slice(0, 22) + "…" : a.user}</TableCell>
                    <TableCell>{a.method}</TableCell>
                    <TableCell><AuthBadge result={a.result} /></TableCell>
                    <TableCell mono>{a.vlan}</TableCell>
                    <TableCell mono>{a.latency}</TableCell>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ background: COLORS.card, borderRadius: 12, border: `1px solid ${COLORS.border}`, padding: 20 }}>
          <div style={{ fontSize: 15, fontWeight: 500, color: COLORS.text, marginBottom: 20 }}>Endpoint breakdown</div>
          {[
            { label: "Workstations", count: 3, pct: 37, color: COLORS.accent },
            { label: "Mobile devices", count: 1, pct: 12, color: COLORS.teal },
            { label: "VoIP / Phones", count: 1, pct: 12, color: COLORS.purple },
            { label: "Printers", count: 1, pct: 12, color: COLORS.amber },
            { label: "IoT / Cameras", count: 0, pct: 0, color: "#6366f1" },
            { label: "Unknown", count: 1, pct: 12, color: COLORS.textMuted },
          ].map((cat, i) => (
            <div key={i} style={{ marginBottom: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: COLORS.text, marginBottom: 5 }}>
                <span>{cat.label}</span><span style={{ color: COLORS.textDim }}>{cat.count}</span>
              </div>
              <div style={{ height: 6, borderRadius: 3, background: COLORS.border }}>
                <div style={{ height: "100%", borderRadius: 3, background: cat.color, width: `${cat.pct}%`, transition: "width 0.6s" }} />
              </div>
            </div>
          ))}

          <div style={{ marginTop: 28, padding: "14px 16px", background: COLORS.redDim, borderRadius: 10, border: `1px solid rgba(239,68,68,0.2)` }}>
            <div style={{ fontSize: 13, fontWeight: 500, color: COLORS.red, marginBottom: 4 }}>Posture alert</div>
            <div style={{ fontSize: 12, color: "#fca5a5" }}>smirnov@corp.local — antivirus definitions outdated (&gt;7 days). Moved to quarantine VLAN 999.</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderEndpoints = () => (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20, alignItems: "center" }}>
        <input
          placeholder="Search MAC, IP, user, profile..."
          value={endpointFilter}
          onChange={e => setEndpointFilter(e.target.value)}
          style={{ flex: 1, padding: "10px 16px", borderRadius: 8, border: `1px solid ${COLORS.border}`, background: COLORS.card, color: COLORS.text, fontSize: 14, outline: "none" }}
        />
        <div style={{ padding: "10px 18px", borderRadius: 8, background: COLORS.accentDim, color: COLORS.accent, fontSize: 13, fontWeight: 500, cursor: "pointer" }}>Export CSV</div>
      </div>

      <div style={{ background: COLORS.card, borderRadius: 12, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr>
              <TableHead>MAC</TableHead><TableHead>IP</TableHead><TableHead>User</TableHead><TableHead>Profile</TableHead><TableHead>VLAN</TableHead><TableHead>Posture</TableHead><TableHead>Auth</TableHead><TableHead>Site</TableHead><TableHead>Last seen</TableHead><TableHead>Actions</TableHead>
            </tr></thead>
            <tbody>
              {filteredEndpoints.map((e, i) => (
                <tr key={i} style={{ background: i % 2 ? "transparent" : "rgba(255,255,255,0.015)", cursor: "pointer" }} onClick={() => setSelectedEndpoint(e)}>
                  <TableCell mono>{e.mac}</TableCell>
                  <TableCell mono>{e.ip}</TableCell>
                  <TableCell>{e.user}</TableCell>
                  <TableCell>{e.profile}</TableCell>
                  <TableCell mono>{e.vlan}</TableCell>
                  <TableCell><PostureBadge status={e.posture} /></TableCell>
                  <TableCell>{e.auth}</TableCell>
                  <TableCell>{e.site}</TableCell>
                  <TableCell>{e.lastSeen}</TableCell>
                  <TableCell>
                    <div style={{ display: "flex", gap: 6 }}>
                      <span title="CoA Reauthenticate" style={{ cursor: "pointer", fontSize: 16 }} onClick={ev => { ev.stopPropagation(); alert(`CoA Reauthenticate sent to ${e.mac}`); }}>↻</span>
                      <span title="Disconnect" style={{ cursor: "pointer", fontSize: 16 }} onClick={ev => { ev.stopPropagation(); alert(`CoA Disconnect sent to ${e.mac}`); }}>⊘</span>
                    </div>
                  </TableCell>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedEndpoint && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }} onClick={() => setSelectedEndpoint(null)}>
          <div style={{ background: COLORS.card, borderRadius: 16, padding: 28, width: 480, maxHeight: "80vh", overflow: "auto", border: `1px solid ${COLORS.border}` }} onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <div style={{ fontSize: 18, fontWeight: 600, color: COLORS.text }}>Endpoint details</div>
              <div style={{ cursor: "pointer", color: COLORS.textDim, fontSize: 20 }} onClick={() => setSelectedEndpoint(null)}>×</div>
            </div>
            {[
              ["MAC address", selectedEndpoint.mac],
              ["IP address", selectedEndpoint.ip],
              ["Username", selectedEndpoint.user],
              ["Device profile", selectedEndpoint.profile],
              ["VLAN", selectedEndpoint.vlan],
              ["Posture status", selectedEndpoint.posture],
              ["Auth method", selectedEndpoint.auth],
              ["NAS IP", selectedEndpoint.nas],
              ["NAS port", selectedEndpoint.port],
              ["Site", selectedEndpoint.site],
              ["Last seen", selectedEndpoint.lastSeen],
            ].map(([k, v], i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid ${COLORS.border}`, fontSize: 13 }}>
                <span style={{ color: COLORS.textDim }}>{k}</span>
                <span style={{ color: COLORS.text, fontFamily: ["MAC", "IP", "VLAN", "NAS"].some(x => k.includes(x)) ? "'JetBrains Mono', monospace" : "inherit" }}>{v}</span>
              </div>
            ))}
            <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
              <button style={{ flex: 1, padding: "10px", borderRadius: 8, border: "none", background: COLORS.accentDim, color: COLORS.accent, fontSize: 13, fontWeight: 500, cursor: "pointer" }} onClick={() => alert("CoA Reauthenticate sent")}>CoA Reauth</button>
              <button style={{ flex: 1, padding: "10px", borderRadius: 8, border: "none", background: COLORS.redDim, color: COLORS.red, fontSize: 13, fontWeight: 500, cursor: "pointer" }} onClick={() => alert("CoA Disconnect sent")}>Disconnect</button>
              <button style={{ flex: 1, padding: "10px", borderRadius: 8, border: "none", background: COLORS.amberDim, color: COLORS.amber, fontSize: 13, fontWeight: 500, cursor: "pointer" }} onClick={() => alert("Port bounce sent")}>Port Bounce</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderPolicies = () => (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ fontSize: 13, color: COLORS.textDim }}>{MOCK_POLICIES.length} authorization rules across {[...new Set(MOCK_POLICIES.map(p => p.set))].length} policy sets</div>
        <div style={{ padding: "8px 18px", borderRadius: 8, background: COLORS.accentDim, color: COLORS.accent, fontSize: 13, fontWeight: 500, cursor: "pointer" }}>+ New rule</div>
      </div>
      <div style={{ background: COLORS.card, borderRadius: 12, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr>
            <TableHead>#</TableHead><TableHead>Name</TableHead><TableHead>Policy set</TableHead><TableHead>Condition</TableHead><TableHead>Action</TableHead><TableHead>Hits</TableHead><TableHead>Status</TableHead>
          </tr></thead>
          <tbody>
            {MOCK_POLICIES.map((p, i) => (
              <tr key={i} style={{ background: i % 2 ? "transparent" : "rgba(255,255,255,0.015)", cursor: "pointer" }} onClick={() => setPolicyModal(p)}>
                <TableCell mono>{p.id}</TableCell>
                <TableCell><span style={{ fontWeight: 500 }}>{p.name}</span></TableCell>
                <TableCell><span style={{ background: COLORS.border, padding: "2px 10px", borderRadius: 12, fontSize: 12 }}>{p.set}</span></TableCell>
                <TableCell><span style={{ fontSize: 12, color: COLORS.textDim, maxWidth: 240, display: "inline-block", overflow: "hidden", textOverflow: "ellipsis" }}>{p.condition}</span></TableCell>
                <TableCell><span style={{ fontSize: 12, color: COLORS.teal }}>{p.action}</span></TableCell>
                <TableCell mono>{p.hits.toLocaleString()}</TableCell>
                <TableCell><span style={{ width: 8, height: 8, borderRadius: "50%", background: p.enabled ? COLORS.green : COLORS.textMuted, display: "inline-block" }} /></TableCell>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {policyModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }} onClick={() => setPolicyModal(null)}>
          <div style={{ background: COLORS.card, borderRadius: 16, padding: 28, width: 520, border: `1px solid ${COLORS.border}` }} onClick={e => e.stopPropagation()}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
              <div style={{ fontSize: 18, fontWeight: 600, color: COLORS.text }}>{policyModal.name}</div>
              <div style={{ cursor: "pointer", color: COLORS.textDim, fontSize: 20 }} onClick={() => setPolicyModal(null)}>×</div>
            </div>
            <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6 }}>Condition (ISE-style)</label>
            <textarea defaultValue={policyModal.condition} style={{ width: "100%", padding: 12, borderRadius: 8, border: `1px solid ${COLORS.border}`, background: COLORS.bg, color: COLORS.text, fontSize: 13, fontFamily: "'JetBrains Mono', monospace", minHeight: 60, resize: "vertical", outline: "none", boxSizing: "border-box" }} />
            <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, marginTop: 16 }}>Authorization result</label>
            <textarea defaultValue={policyModal.action} style={{ width: "100%", padding: 12, borderRadius: 8, border: `1px solid ${COLORS.border}`, background: COLORS.bg, color: COLORS.teal, fontSize: 13, fontFamily: "'JetBrains Mono', monospace", minHeight: 40, resize: "vertical", outline: "none", boxSizing: "border-box" }} />
            <div style={{ display: "flex", gap: 10, marginTop: 20 }}>
              <button style={{ flex: 1, padding: 10, borderRadius: 8, border: "none", background: COLORS.accent, color: "#fff", fontWeight: 500, cursor: "pointer" }}>Save changes</button>
              <button style={{ padding: "10px 20px", borderRadius: 8, border: `1px solid ${COLORS.border}`, background: "transparent", color: COLORS.textDim, cursor: "pointer" }} onClick={() => setPolicyModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderNAS = () => (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ fontSize: 13, color: COLORS.textDim }}>Network devices sending RADIUS requests</div>
        <div style={{ padding: "8px 18px", borderRadius: 8, background: COLORS.accentDim, color: COLORS.accent, fontSize: 13, fontWeight: 500, cursor: "pointer" }}>+ Add device</div>
      </div>
      <div style={{ background: COLORS.card, borderRadius: 12, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr>
            <TableHead>IP / Subnet</TableHead><TableHead>Name</TableHead><TableHead>Vendor</TableHead><TableHead>Site</TableHead><TableHead>RADIUS secret</TableHead><TableHead>Auth requests</TableHead><TableHead>Status</TableHead>
          </tr></thead>
          <tbody>
            {[
              { ip: "10.0.1.1", name: "hq-access-sw1", vendor: "Cisco Catalyst 9300", site: "HQ", secret: "••••••••••", reqs: "12,340", alive: true },
              { ip: "10.0.1.2", name: "hq-access-sw2", vendor: "Cisco Catalyst 9300", site: "HQ", secret: "••••••••••", reqs: "8,921", alive: true },
              { ip: "10.0.1.3", name: "hq-access-sw3", vendor: "Cisco Catalyst 9200", site: "HQ", secret: "••••••••••", reqs: "5,102", alive: true },
              { ip: "10.0.0.10", name: "hq-wlc-01", vendor: "Cisco 9800-CL", site: "HQ", secret: "••••••••••", reqs: "34,567", alive: true },
              { ip: "10.1.0.1", name: "br-b-sw1", vendor: "Juniper EX3400", site: "Branch B", secret: "••••••••••", reqs: "3,201", alive: true },
              { ip: "10.2.0.1", name: "br-c-sw1", vendor: "Aruba CX 6300", site: "Branch C", secret: "••••••••••", reqs: "2,890", alive: false },
            ].map((d, i) => (
              <tr key={i} style={{ background: i % 2 ? "transparent" : "rgba(255,255,255,0.015)" }}>
                <TableCell mono>{d.ip}</TableCell>
                <TableCell>{d.name}</TableCell>
                <TableCell>{d.vendor}</TableCell>
                <TableCell>{d.site}</TableCell>
                <TableCell mono>{d.secret}</TableCell>
                <TableCell mono>{d.reqs}</TableCell>
                <TableCell>
                  <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: d.alive ? COLORS.green : COLORS.red }} />
                    <span style={{ fontSize: 12, color: d.alive ? COLORS.green : COLORS.red }}>{d.alive ? "Active" : "Down"}</span>
                  </span>
                </TableCell>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const pages = {
    dashboard: { title: "Dashboard", render: renderDashboard },
    endpoints: { title: "Endpoints", render: renderEndpoints },
    policies: { title: "Authorization policies", render: renderPolicies },
    nas: { title: "Network devices", render: renderNAS },
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: COLORS.bg, fontFamily: "'Inter', -apple-system, sans-serif", color: COLORS.text }}>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />

      <aside style={{ width: 240, background: COLORS.card, borderRight: `1px solid ${COLORS.border}`, padding: "20px 12px", flexShrink: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "0 16px 24px", borderBottom: `1px solid ${COLORS.border}`, marginBottom: 16 }}>
          <div style={{ fontSize: 18, fontWeight: 600, color: COLORS.accent, letterSpacing: -0.5 }}>Open NAC</div>
          <div style={{ fontSize: 11, color: COLORS.textMuted, marginTop: 2 }}>Network Access Control</div>
        </div>

        <SidebarItem icon="◎" label="Dashboard" active={page === "dashboard"} onClick={() => setPage("dashboard")} />
        <SidebarItem icon="◉" label="Endpoints" active={page === "endpoints"} onClick={() => setPage("endpoints")} badge={stats.nonCompliant} />
        <SidebarItem icon="⚙" label="Policies" active={page === "policies"} onClick={() => setPage("policies")} />
        <SidebarItem icon="⬡" label="Network devices" active={page === "nas"} onClick={() => setPage("nas")} />

        <div style={{ padding: "12px 16px", fontSize: 11, color: COLORS.textMuted, textTransform: "uppercase", letterSpacing: 1, marginTop: 16 }}>Services</div>
        <SidebarItem icon="◈" label="Profiling" />
        <SidebarItem icon="⊕" label="Posture" />
        <SidebarItem icon="⊞" label="Guest portal" />
        <SidebarItem icon="⊡" label="TACACS+" />
        <SidebarItem icon="◇" label="Certificates" />

        <div style={{ marginTop: "auto", padding: "16px", borderTop: `1px solid ${COLORS.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: COLORS.green }} />
            <span style={{ fontSize: 12, color: COLORS.textDim }}>FreeRADIUS ×2</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: COLORS.green }} />
            <span style={{ fontSize: 12, color: COLORS.textDim }}>Galera 3/3</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: COLORS.green }} />
            <span style={{ fontSize: 12, color: COLORS.textDim }}>Redis Sentinel</span>
          </div>
        </div>
      </aside>

      <main style={{ flex: 1, padding: "28px 32px", overflow: "auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0, color: COLORS.text }}>{pages[page]?.title}</h1>
            <div style={{ fontSize: 13, color: COLORS.textMuted, marginTop: 4 }}>
              {time.toLocaleDateString("ru-RU", { weekday: "long", day: "numeric", month: "long" })} — {time.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })}
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ padding: "6px 14px", borderRadius: 8, background: COLORS.greenDim, color: COLORS.green, fontSize: 12, fontWeight: 500 }}>HQ online</span>
            <span style={{ padding: "6px 14px", borderRadius: 8, background: COLORS.greenDim, color: COLORS.green, fontSize: 12, fontWeight: 500 }}>Branch B online</span>
            <span style={{ padding: "6px 14px", borderRadius: 8, background: COLORS.redDim, color: COLORS.red, fontSize: 12, fontWeight: 500 }}>Branch C degraded</span>
          </div>
        </div>

        {pages[page]?.render()}
      </main>
    </div>
  );
}
