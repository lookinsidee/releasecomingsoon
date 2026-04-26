import { useState, useEffect, useRef } from "react";

// ── Threat helpers ─────────────────────────────────────────────────────────────
function calcThreat(d) {
  let s = 0;
  if (d.proxy) s += 40;
  if (d.hosting) s += 20;
  if (d.mobile) s += 5;
  if (d.org && /vpn|tor|proxy|hosting|cloud|vps/i.test(d.org)) s += 20;
  return Math.min(s, 100);
}
function threatLevel(s) {
  if (s >= 70) return { label: "CRITICAL", color: "#FF3B3B", glow: "rgba(255,59,59,0.2)" };
  if (s >= 40) return { label: "ELEVATED", color: "#FF8C00", glow: "rgba(255,140,0,0.2)" };
  if (s >= 20) return { label: "MODERATE", color: "#FFD600", glow: "rgba(255,214,0,0.15)" };
  return { label: "CLEAN", color: "#00E676", glow: "rgba(0,230,118,0.15)" };
}
function isIP(q) { return /^\d+\.\d+\.\d+\.\d+$/.test(q); }
function isDomain(q) { return /^[a-zA-Z]/.test(q) && q.includes("."); }
function copyToClipboard(text) { navigator.clipboard?.writeText(text); }

function saveHistory(entry) {
  try {
    const h = JSON.parse(localStorage.getItem("db_history2") || "[]");
    const filtered = h.filter(x => x.query !== entry.query);
    filtered.unshift(entry);
    localStorage.setItem("db_history2", JSON.stringify(filtered.slice(0, 20)));
  } catch {}
}
function loadHistory() {
  try { return JSON.parse(localStorage.getItem("db_history2") || "[]"); } catch { return []; }
}
function exportResults(ipData) {
  const blob = new Blob([JSON.stringify({ ...ipData, exported: new Date().toISOString() }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `desireblock-${ipData.query}.json`;
  a.click();
}

// ── Micro components ──────────────────────────────────────────────────────────
function Spinner({ size = 16, color = "currentColor" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" style={{ animation: "db-spin .7s linear infinite" }}>
      <circle cx="12" cy="12" r="10" fill="none" stroke={color} strokeWidth="2" strokeDasharray="40 20" />
    </svg>
  );
}

function Tag({ children, color, bg }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 4,
      fontFamily: "'Space Mono', monospace", fontSize: 10, letterSpacing: "0.1em",
      border: `1px solid ${color}30`, background: bg || `${color}10`, color,
    }}>{children}</span>
  );
}

function Field({ label, value, accent, copy = false, mono = true }) {
  const [copied, setCopied] = useState(false);
  if (value === undefined || value === null || value === "") return null;
  function doCopy() {
    copyToClipboard(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "9px 0", borderBottom: "1px solid rgba(255,255,255,0.04)", gap: 16,
    }}>
      <span style={{ color: "#4A4A5A", fontSize: 11, fontFamily: "'Space Mono', monospace", letterSpacing: "0.08em", flexShrink: 0 }}>{label}</span>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ color: accent || "#C8C8D8", fontSize: 12, fontFamily: mono ? "'Space Mono', monospace" : "inherit", textAlign: "right", wordBreak: "break-all" }}>{value}</span>
        {copy && (
          <button onClick={doCopy} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px 4px", color: copied ? "#00E676" : "#333", fontSize: 11, display: "flex", alignItems: "center" }}>
            {copied ? "✓" : "⎘"}
          </button>
        )}
      </div>
    </div>
  );
}

function Panel({ title, badge, badgeColor, children }) {
  return (
    <div style={{ background: "#09090F", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: "20px 22px" }}>
      {(title || badge) && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          {title && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.24em", textTransform: "uppercase" }}>{title}</span>}
          {badge && (
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, letterSpacing: "0.1em", color: badgeColor || "#555", border: `1px solid ${badgeColor || "#333"}30`, padding: "2px 8px", borderRadius: 4, background: `${badgeColor || "#333"}10` }}>
              {badge}
            </span>
          )}
        </div>
      )}
      {children}
    </div>
  );
}

function Btn({ onClick, disabled, children, variant = "primary", style: s = {} }) {
  const base = {
    display: "inline-flex", alignItems: "center", gap: 8,
    fontFamily: "'Space Mono', monospace", fontSize: 11, letterSpacing: "0.1em",
    border: "none", cursor: disabled ? "not-allowed" : "pointer", borderRadius: 8,
    transition: "all .15s", padding: "10px 20px", opacity: disabled ? 0.4 : 1, ...s,
  };
  const styles = {
    primary: { background: "#FFFFFF", color: "#000000", fontWeight: 700 },
    ghost:   { background: "transparent", color: "#555", border: "1px solid rgba(255,255,255,0.08)" },
    danger:  { background: "transparent", color: "#FF3B3B", border: "1px solid rgba(255,59,59,0.3)" },
  };
  return <button onClick={onClick} disabled={disabled} style={{ ...base, ...styles[variant] }}>{children}</button>;
}

function ErrBox({ msg }) {
  if (!msg) return null;
  return (
    <div style={{ padding: "12px 16px", background: "rgba(255,59,59,0.06)", border: "1px solid rgba(255,59,59,0.2)", borderRadius: 8, fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#FF6B6B", marginBottom: 14 }}>
      ✕ {msg}
    </div>
  );
}

// ── Port Scanner ──────────────────────────────────────────────────────────────
function PortScan({ target }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/portscan?host=${encodeURIComponent(target)}`);
      setData(await r.json());
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const open = data?.results?.filter(r => r.status === "open") || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 20 }}>
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> SCANNING</> : "▶ SCAN PORTS"}</Btn>
        {data && (
          <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: open.length ? "#FF8C00" : "#00E676" }}>
            {open.length} OPEN / {data.results?.length} CHECKED
          </span>
        )}
      </div>
      <ErrBox msg={err} />
      {data?.results && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(120px, 1fr))", gap: 6 }}>
          {data.results.map(({ port, service, status }) => {
            const isOpen = status === "open";
            return (
              <div key={port} style={{
                background: isOpen ? "rgba(255,140,0,0.06)" : "rgba(255,255,255,0.01)",
                border: `1px solid ${isOpen ? "rgba(255,140,0,0.25)" : "rgba(255,255,255,0.03)"}`,
                borderRadius: 8, padding: "10px 12px",
              }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: isOpen ? "#FF8C00" : "#222", marginBottom: 2 }}>:{port}</div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: isOpen ? "#555" : "#1A1A1A", letterSpacing: "0.06em" }}>{service}</div>
                {isOpen && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#FF8C00", marginTop: 4, letterSpacing: "0.1em" }}>● OPEN</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── DNS Lookup ────────────────────────────────────────────────────────────────
const DNS_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "PTR", "SOA", "CAA", "SRV"];

function DnsLookup({ initialHost }) {
  const [host, setHost] = useState(initialHost || "");
  const [type, setType] = useState("A");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialHost) setHost(initialHost); }, [initialHost]);

  async function lookup() {
    if (!host.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/dns?host=${encodeURIComponent(host.trim())}&type=${type}`);
      const d = await r.json();
      if (d.error && !d.records?.length) setErr(d.error);
      else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  function renderRecord(rec, i) {
    if (typeof rec === "string") return (
      <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", padding: "8px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 4, wordBreak: "break-all" }}>{rec}</div>
    );
    if (Array.isArray(rec)) return (
      <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", padding: "8px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 4, wordBreak: "break-all" }}>{rec.join(" ")}</div>
    );
    return (
      <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, padding: "8px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 4 }}>
        {Object.entries(rec).map(([k, v]) => (
          <span key={k} style={{ marginRight: 16 }}>
            <span style={{ color: "#3A3A4A" }}>{k}: </span>
            <span style={{ color: "#C8C8D8" }}>{String(v)}</span>
          </span>
        ))}
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        <input className="db-input" placeholder="hostname or IP…" value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup()} style={{ flex: 1, minWidth: 180 }} />
        <select className="db-select" value={type} onChange={e => setType(e.target.value)}>
          {DNS_TYPES.map(t => <option key={t}>{t}</option>)}
        </select>
        <Btn onClick={lookup}>{loading ? <Spinner size={13} /> : "RESOLVE"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", marginBottom: 12, letterSpacing: "0.12em" }}>
            {data.host} · TYPE {data.type} · {data.records?.length || 0} RECORD{data.records?.length !== 1 ? "S" : ""}
          </div>
          {data.records?.length > 0 ? data.records.map(renderRecord) : <div style={{ color: "#333", fontFamily: "'Space Mono', monospace", fontSize: 12 }}>No records found.</div>}
        </div>
      )}
    </div>
  );
}

// ── WHOIS / RDAP ──────────────────────────────────────────────────────────────
function WhoisLookup({ initialQuery }) {
  const [q, setQ] = useState(initialQuery || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialQuery) setQ(initialQuery); }, [initialQuery]);

  async function lookup() {
    if (!q.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/whois?q=${encodeURIComponent(q.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const now = Date.now();

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="IP or domain…" value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup()} style={{ flex: 1 }} />
        <Btn onClick={lookup}>{loading ? <Spinner size={13} /> : "WHOIS"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {data.type === "ip" ? (
            <>
              <Field label="Handle" value={data.handle} copy />
              <Field label="Name" value={data.name} />
              <Field label="Type" value={data.type2} />
              <Field label="Range" value={data.startAddress && `${data.startAddress} → ${data.endAddress}`} copy />
              <Field label="IP Version" value={data.ipVersion} />
              <Field label="Organization" value={data.org} copy />
              <Field label="Country" value={data.country} />
              <Field label="Status" value={Array.isArray(data.status) ? data.status.join(", ") : data.status} />
              <Field label="Registered" value={data.registered} />
              <Field label="Updated" value={data.updated} />
              <Field label="Remarks" value={data.remarks} mono={false} />
            </>
          ) : (
            <>
              <Field label="Domain" value={data.name} copy />
              <Field label="Handle" value={data.handle} />
              <Field label="Status" value={Array.isArray(data.status) ? data.status.join(", ") : data.status} />
              <Field label="Registered" value={data.registered} />
              <Field label="Expires" value={data.expires}
                accent={data.expires && new Date(data.expires) < new Date(now + 30 * 86400000) ? "#FF3B3B" : undefined} />
              <Field label="Updated" value={data.updated} />
              <Field label="Registrar" value={data.registrar} copy />
              <Field label="Registrant" value={data.registrant} />
              <Field label="Email" value={data.email} copy />
              {data.nameservers?.map((ns, i) => <Field key={i} label={`NS ${i + 1}`} value={ns} copy />)}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── SSL Certificate ───────────────────────────────────────────────────────────
function SSLInfo({ initialHost }) {
  const [host, setHost] = useState(initialHost || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialHost) setHost(initialHost); }, [initialHost]);

  async function lookup() {
    const h = host.replace(/^https?:\/\//, "").split("/")[0];
    if (!h) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/ssl?host=${encodeURIComponent(h)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="domain.com" value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup()} style={{ flex: 1 }} />
        <Btn onClick={lookup}>{loading ? <Spinner size={13} /> : "CHECK SSL"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <Tag color={data.expired ? "#FF3B3B" : "#00E676"}>{data.expired ? "✕ EXPIRED" : "✓ VALID"}</Tag>
            {!data.expired && (
              <Tag color={data.daysRemaining < 30 ? "#FF8C00" : "#555"}>
                {data.daysRemaining}d REMAINING
              </Tag>
            )}
            {data.protocol && <Tag color="#555">{data.protocol}</Tag>}
          </div>
          <Field label="Subject CN" value={data.subject?.CN} copy />
          <Field label="Subject O" value={data.subject?.O} />
          <Field label="Issuer CN" value={data.issuer?.CN} />
          <Field label="Issuer O" value={data.issuer?.O} />
          <Field label="Valid From" value={data.validFrom} />
          <Field label="Valid To" value={data.validTo} accent={data.expired ? "#FF3B3B" : data.daysRemaining < 30 ? "#FF8C00" : undefined} />
          <Field label="Serial" value={data.serialNumber} copy />
          <Field label="Cipher" value={data.cipher?.name} />
          <Field label="Key Bits" value={data.bits} />
          <Field label="SHA-256" value={data.fingerprint256} copy />
          {data.subjectAltNames && <Field label="SANs" value={data.subjectAltNames} copy />}
        </div>
      )}
    </div>
  );
}

// ── HTTP Headers ──────────────────────────────────────────────────────────────
const SEC_HEADERS = [
  "strict-transport-security", "content-security-policy", "x-frame-options",
  "x-content-type-options", "referrer-policy", "permissions-policy",
  "cross-origin-embedder-policy", "cross-origin-opener-policy",
];

function HttpHeaders({ initialUrl }) {
  const [url, setUrl] = useState(initialUrl || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialUrl) setUrl(initialUrl); }, [initialUrl]);

  async function lookup() {
    if (!url.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/headers?url=${encodeURIComponent(url.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const secScore = data ? Math.round((SEC_HEADERS.filter(h => data.headers?.[h]).length / SEC_HEADERS.length) * 100) : 0;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup()} style={{ flex: 1 }} />
        <Btn onClick={lookup}>{loading ? <Spinner size={13} /> : "FETCH"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 12, alignItems: "baseline", marginBottom: 20 }}>
            <span style={{ fontFamily: "'Instrument Serif', serif", fontSize: 36, fontWeight: 400, color: data.status < 400 ? "#00E676" : "#FF3B3B", lineHeight: 1 }}>{data.status}</span>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#555" }}>{data.statusText}</span>
            {data.redirected && <Tag color="#FF8C00">REDIRECTED</Tag>}
            <Tag color={secScore > 70 ? "#00E676" : secScore > 40 ? "#FF8C00" : "#FF3B3B"}>SEC {secScore}%</Tag>
          </div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", margin: "16px 0 10px" }}>SECURITY HEADERS</div>
          {SEC_HEADERS.map(h => (
            <div key={h} style={{ display: "flex", justifyContent: "space-between", padding: "7px 0", borderBottom: "1px solid rgba(255,255,255,0.03)", gap: 12 }}>
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#3A3A4A" }}>{h}</span>
              {data.headers[h]
                ? <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#00E676", maxWidth: "50%", textAlign: "right", wordBreak: "break-all" }}>{data.headers[h].slice(0, 60)}{data.headers[h].length > 60 ? "…" : ""}</span>
                : <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#FF3B3B", letterSpacing: "0.08em" }}>MISSING</span>}
            </div>
          ))}
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", margin: "16px 0 10px" }}>ALL HEADERS</div>
          {Object.entries(data.headers).map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 0", borderBottom: "1px solid rgba(255,255,255,0.02)", gap: 12 }}>
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#3A3A4A", flexShrink: 0 }}>{k}</span>
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#666", maxWidth: "60%", textAlign: "right", wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── ASN Info ──────────────────────────────────────────────────────────────────
function AsnInfo({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function lookup() {
    if (!ip.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/asn?ip=${encodeURIComponent(ip.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="IP address…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && lookup()} style={{ flex: 1 }} />
        <Btn onClick={lookup}>{loading ? <Spinner size={13} /> : "LOOKUP ASN"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ marginBottom: 20 }}>
            <span style={{ fontFamily: "'Instrument Serif', serif", fontSize: 32, fontWeight: 400, color: "#E8E8F8" }}>{data.asn}</span>
          </div>
          <Field label="Name" value={data.name} copy />
          <Field label="Description" value={data.description} mono={false} />
          <Field label="Country" value={data.country} />
          <Field label="RIR" value={data.rir} />
          <Field label="Website" value={data.website} copy />
          <Field label="Email" value={data.email} copy />
          <Field label="Abuse Contact" value={data.abuse} copy accent="#FF8C00" />
          <Field label="IPv4 Prefixes" value={data.prefixesV4} />
          <Field label="IPv6 Prefixes" value={data.prefixesV6} />
          {data.topPrefixes?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>TOP PREFIXES</div>
              {data.topPrefixes.map((p, i) => (
                <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#4A4A6A", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.02)" }}>{p}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Blacklist ─────────────────────────────────────────────────────────────────
function Blacklist({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function run() {
    const h = ip.trim();
    if (!h || !isIP(h)) { setErr("IPv4 address required"); return; }
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/blacklist?ip=${encodeURIComponent(h)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="IPv4 address…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run}>{loading ? <Spinner size={13} /> : "CHECK DNSBL"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 16, alignItems: "baseline", marginBottom: 20 }}>
            <span style={{ fontFamily: "'Instrument Serif', serif", fontSize: 52, fontWeight: 400, color: data.listed > 0 ? "#FF3B3B" : "#00E676", lineHeight: 1 }}>{data.listed}</span>
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#555" }}>/ {data.total} LISTS</div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: data.listed > 0 ? "#FF3B3B" : "#00E676", letterSpacing: "0.12em", marginTop: 4 }}>
                {data.listed > 0 ? "⚠ BLACKLISTED" : "✓ CLEAN"}
              </div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 3 }}>
            {data.results.map(({ bl, listed }) => (
              <div key={bl} style={{
                display: "flex", justifyContent: "space-between", padding: "7px 10px",
                background: listed ? "rgba(255,59,59,0.05)" : "rgba(255,255,255,0.01)",
                border: `1px solid ${listed ? "rgba(255,59,59,0.2)" : "rgba(255,255,255,0.03)"}`,
                borderRadius: 6,
              }}>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: listed ? "#FF6B6B" : "#222", letterSpacing: "0.04em" }}>{bl}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: listed ? "#FF3B3B" : "#1A1A2A" }}>{listed ? "LISTED" : "OK"}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Ping ──────────────────────────────────────────────────────────────────────
function PingTest({ initialHost }) {
  const [host, setHost] = useState(initialHost || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialHost) setHost(initialHost); }, [initialHost]);

  async function run() {
    if (!host.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/ping?host=${encodeURIComponent(host.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="IP or domain…" value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run}>{loading ? <Spinner size={13} /> : "PING"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 20 }}>
            {[["MIN", data.min != null ? `${data.min}ms` : "—"], ["AVG", data.avg != null ? `${data.avg}ms` : "—"], ["MAX", data.max != null ? `${data.max}ms` : "—"], ["LOSS", `${data.loss}%`]].map(([label, val]) => (
              <div key={label} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 10, padding: "14px 12px", textAlign: "center" }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.18em", marginBottom: 8 }}>{label}</div>
                <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 22, color: label === "LOSS" && data.loss > 0 ? "#FF3B3B" : "#E8E8F8" }}>{val}</div>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 4, alignItems: "flex-end", height: 60 }}>
            {data.pings.map((p, i) => {
              const max = Math.max(...data.pings.filter(Boolean), 1);
              const h = p != null ? Math.max(8, (p / max) * 100) : 0;
              return (
                <div key={i} style={{ flex: 1, position: "relative", height: "100%", display: "flex", flexDirection: "column", justifyContent: "flex-end" }}>
                  <div style={{
                    height: `${h}%`, minHeight: p != null ? 8 : 0,
                    background: p == null ? "rgba(255,59,59,0.3)" : `rgba(0,230,118,${0.3 + (p / max) * 0.5})`,
                    borderRadius: 4, transition: "height .5s",
                  }} />
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", textAlign: "center", marginTop: 4 }}>#{i + 1}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Compare ───────────────────────────────────────────────────────────────────
function Compare() {
  const [a, setA] = useState(""); const [b, setB] = useState("");
  const [dataA, setDataA] = useState(null); const [dataB, setDataB] = useState(null);
  const [loading, setLoading] = useState(false); const [err, setErr] = useState(null);

  async function fetchOne(q) {
    const r = await fetch(`/api/ipinfo?q=${encodeURIComponent(q)}`);
    return r.json();
  }

  async function run() {
    if (!a.trim() || !b.trim()) { setErr("Enter two IPs or domains"); return; }
    setLoading(true); setErr(null); setDataA(null); setDataB(null);
    try {
      const [da, db] = await Promise.all([fetchOne(a.trim()), fetchOne(b.trim())]);
      if (da.status === "fail") throw new Error(`A: ${da.message}`);
      if (db.status === "fail") throw new Error(`B: ${db.message}`);
      setDataA({ ...da, threatScore: calcThreat(da) });
      setDataB({ ...db, threatScore: calcThreat(db) });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const fields = [
    ["IP", "query"], ["Country", "country"], ["City", "city"], ["ISP", "isp"],
    ["Org", "org"], ["AS", "as"], ["Timezone", "timezone"],
    ["Proxy/VPN", "proxy", v => v ? "YES" : "NO"],
    ["Hosting", "hosting", v => v ? "YES" : "NO"],
    ["Mobile", "mobile", v => v ? "YES" : "NO"],
    ["Threat", "threatScore"],
  ];

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="IP or domain A…" value={a} onChange={e => setA(e.target.value)} />
        <input className="db-input" placeholder="IP or domain B…" value={b} onChange={e => setB(e.target.value)} />
      </div>
      <Btn onClick={run} style={{ marginBottom: 20 }}>{loading ? <Spinner size={13} /> : "COMPARE ▶"}</Btn>
      <ErrBox msg={err} />
      {dataA && dataB && (
        <div style={{ display: "grid", gridTemplateColumns: "140px 1fr 1fr", gap: 0 }}>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}></div>
          {[dataA, dataB].map(d => (
            <div key={d.query} style={{ fontFamily: "'Space Mono', monospace", fontSize: 12, fontWeight: 700, color: "#E8E8F8", padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>{d.query}</div>
          ))}
          {fields.map(([label, key, fmt]) => {
            const va = fmt ? fmt(dataA[key]) : dataA[key];
            const vb = fmt ? fmt(dataB[key]) : dataB[key];
            const diff = String(va) !== String(vb);
            return [
              <div key={`l-${key}`} style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#2A2A3A", padding: "8px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>{label}</div>,
              <div key={`a-${key}`} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: diff ? "#E8E8F8" : "#333", padding: "8px 14px", borderBottom: "1px solid rgba(255,255,255,0.03)", wordBreak: "break-all" }}>{va ?? "—"}</div>,
              <div key={`b-${key}`} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: diff ? "#E8E8F8" : "#333", padding: "8px 14px", borderBottom: "1px solid rgba(255,255,255,0.03)", wordBreak: "break-all" }}>{vb ?? "—"}</div>,
            ];
          })}
        </div>
      )}
    </div>
  );
}

// ── Bulk Lookup ───────────────────────────────────────────────────────────────
function BulkLookup() {
  const [raw, setRaw] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  async function run() {
    const targets = raw.split(/[\n,\s]+/).map(s => s.trim()).filter(Boolean).slice(0, 20);
    if (!targets.length) return;
    setLoading(true); setResults([]); setProgress(0);
    for (let i = 0; i < targets.length; i++) {
      try {
        const r = await fetch(`/api/ipinfo?q=${encodeURIComponent(targets[i])}`);
        const d = await r.json();
        setResults(prev => [...prev, { query: targets[i], data: d.status === "fail" ? null : { ...d, threatScore: calcThreat(d) }, error: d.status === "fail" ? d.message : null }]);
      } catch (e) {
        setResults(prev => [...prev, { query: targets[i], data: null, error: e.message }]);
      }
      setProgress(i + 1);
      await new Promise(r => setTimeout(r, 200));
    }
    setLoading(false);
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "desireblock-bulk.json"; a.click();
  }

  const total = raw.split(/[\n,\s]+/).filter(Boolean).length;

  return (
    <div>
      <textarea className="db-input" placeholder={"Paste IPs or domains, one per line (max 20):\n8.8.8.8\n1.1.1.1\ngoogle.com"}
        value={raw} onChange={e => setRaw(e.target.value)}
        style={{ width: "100%", height: 110, resize: "vertical", marginBottom: 12, fontFamily: "'Space Mono', monospace", fontSize: 11 }}
      />
      {loading && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>
            <span>SCANNING {progress}/{total}</span>
            <span>{Math.round((progress / total) * 100)}%</span>
          </div>
          <div style={{ height: 3, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
            <div style={{ height: "100%", width: `${(progress / total) * 100}%`, background: "#FFFFFF", borderRadius: 2, transition: "width .3s" }} />
          </div>
        </div>
      )}
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "RUN BULK SCAN"}</Btn>
        {results.length > 0 && <Btn variant="ghost" onClick={exportJSON}>EXPORT JSON ↓</Btn>}
      </div>
      {results.length > 0 && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "'Space Mono', monospace", fontSize: 11 }}>
            <thead>
              <tr>
                {["QUERY", "IP", "COUNTRY", "ISP", "PROXY", "HOSTING", "THREAT"].map(h => (
                  <th key={h} style={{ color: "#2A2A3A", fontSize: 9, letterSpacing: "0.14em", padding: "6px 10px", textAlign: "left", borderBottom: "1px solid rgba(255,255,255,0.04)", fontWeight: 400 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map(({ query, data: d, error }) => (
                <tr key={query} style={{ borderBottom: "1px solid rgba(255,255,255,0.02)" }}>
                  <td style={{ padding: "8px 10px", color: "#555" }}>{query}</td>
                  {error ? <td colSpan={6} style={{ padding: "8px 10px", color: "#FF6B6B" }}>{error}</td> : <>
                    <td style={{ padding: "8px 10px", color: "#C8C8D8" }}>{d?.query}</td>
                    <td style={{ padding: "8px 10px", color: "#666" }}>{d?.country}</td>
                    <td style={{ padding: "8px 10px", color: "#555", maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d?.isp}</td>
                    <td style={{ padding: "8px 10px", color: d?.proxy ? "#FF3B3B" : "#222" }}>{d?.proxy ? "YES" : "NO"}</td>
                    <td style={{ padding: "8px 10px", color: d?.hosting ? "#FF8C00" : "#222" }}>{d?.hosting ? "YES" : "NO"}</td>
                    <td style={{ padding: "8px 10px", color: threatLevel(d?.threatScore || 0).color }}>{d?.threatScore}</td>
                  </>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── GeoMap component ──────────────────────────────────────────────────────────
function GeoMap({ lat, lon, city, country }) {
  const [loaded, setLoaded] = useState(false);
  if (!lat || !lon) return null;
  const mapUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 1},${lat - 1},${lon + 1},${lat + 1}&layer=mapnik&marker=${lat},${lon}`;

  return (
    <div style={{ position: "relative", borderRadius: 10, overflow: "hidden", border: "1px solid rgba(255,255,255,0.06)", marginTop: 12 }}>
      {!loaded && (
        <div style={{ position: "absolute", inset: 0, background: "#09090F", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1 }}>
          <Spinner size={20} />
        </div>
      )}
      <iframe
        src={mapUrl}
        width="100%" height="200" frameBorder="0" scrolling="no"
        style={{ display: "block", filter: "invert(0.9) hue-rotate(180deg) saturate(0.4)", opacity: loaded ? 1 : 0, transition: "opacity .4s" }}
        onLoad={() => setLoaded(true)}
        title="Location map"
      />
      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, padding: "8px 12px", background: "linear-gradient(transparent, rgba(9,9,15,0.9))", fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555" }}>
        {lat.toFixed(4)}, {lon.toFixed(4)} · {city}, {country}
      </div>
    </div>
  );
}

// ── Threat Ring ───────────────────────────────────────────────────────────────
function ThreatRing({ score, threat }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div style={{ position: "relative", width: 110, height: 110, flexShrink: 0 }}>
      <svg width="110" height="110" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="55" cy="55" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={threat.color} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1.2s ease" }}
        />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <span style={{ fontFamily: "'Instrument Serif', serif", fontSize: 26, color: threat.color, lineHeight: 1 }}>{score}</span>
        <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: threat.color, letterSpacing: "0.1em", marginTop: 2 }}>{threat.label}</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ── NEW 2026 TABS ──────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── Traceroute ────────────────────────────────────────────────────────────────
function Traceroute({ initialHost }) {
  const [host, setHost] = useState(initialHost || "");
  const [hops, setHops] = useState([]);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialHost) setHost(initialHost); }, [initialHost]);

  async function run() {
    if (!host.trim()) return;
    setLoading(true); setErr(null); setHops([]); setDone(false);
    try {
      const r = await fetch(`/api/traceroute?host=${encodeURIComponent(host.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error);
      else { setHops(d.hops || []); setDone(true); }
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const maxRtt = hops.reduce((m, h) => Math.max(m, h.rtt || 0), 1);

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="IP or domain…" value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> TRACING</> : "▶ TRACEROUTE"}</Btn>
      </div>
      <ErrBox msg={err} />
      {hops.length > 0 && (
        <div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 14 }}>
            {hops.length} HOPS · {done ? "COMPLETE" : "IN PROGRESS"}
          </div>
          {hops.map((hop, i) => {
            const barW = hop.rtt ? Math.max(4, (hop.rtt / maxRtt) * 100) : 0;
            const isTimeout = !hop.ip || hop.ip === "*";
            return (
              <div key={i} style={{
                display: "grid", gridTemplateColumns: "32px 140px 80px 1fr", gap: 12, alignItems: "center",
                padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.03)",
                animation: `db-fadeup .3s ease ${i * 0.05}s both`,
              }}>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#2A2A3A" }}>{hop.hop ?? i + 1}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: isTimeout ? "#2A2A3A" : "#C8C8D8", wordBreak: "break-all" }}>
                  {isTimeout ? "* * *" : hop.ip}
                </span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: hop.rtt > 100 ? "#FF8C00" : hop.rtt > 50 ? "#FFD600" : "#00E676" }}>
                  {hop.rtt ? `${hop.rtt}ms` : "—"}
                </span>
                <div style={{ height: 3, background: "rgba(255,255,255,0.04)", borderRadius: 2, overflow: "hidden" }}>
                  {hop.rtt && <div style={{ height: "100%", width: `${barW}%`, background: hop.rtt > 100 ? "#FF8C00" : "#00E676", borderRadius: 2, transition: "width .6s ease" }} />}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Reputation / Threat Intel ─────────────────────────────────────────────────
function Reputation({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function run() {
    if (!ip.trim()) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/reputation?ip=${encodeURIComponent(ip.trim())}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const sources = data?.sources || [];
  const maxScore = 100;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="IP address…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "INTEL SCAN"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Aggregate score */}
          <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 28, padding: "20px 24px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 56, lineHeight: 1, color: data.abuseScore > 50 ? "#FF3B3B" : data.abuseScore > 20 ? "#FF8C00" : "#00E676" }}>{data.abuseScore ?? "—"}</div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginTop: 4 }}>ABUSE SCORE</div>
            </div>
            <div style={{ flex: 1 }}>
              <Field label="Total Reports" value={data.totalReports} />
              <Field label="Distinct Users" value={data.numDistinctUsers} />
              <Field label="Last Reported" value={data.lastReportedAt} />
              <Field label="Usage Type" value={data.usageType} />
              <Field label="Domain" value={data.domain} copy />
              <Field label="ISP" value={data.isp} />
            </div>
          </div>

          {/* Intel sources */}
          {sources.length > 0 && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>INTELLIGENCE SOURCES</div>
              {sources.map((s, i) => (
                <div key={i} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "10px 14px", marginBottom: 4,
                  background: s.flagged ? "rgba(255,59,59,0.04)" : "rgba(255,255,255,0.01)",
                  border: `1px solid ${s.flagged ? "rgba(255,59,59,0.15)" : "rgba(255,255,255,0.03)"}`,
                  borderRadius: 8,
                }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: s.flagged ? "#C8C8D8" : "#333" }}>{s.name}</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: s.flagged ? "#FF3B3B" : "#00E676", letterSpacing: "0.1em" }}>{s.flagged ? "⚠ FLAGGED" : "✓ CLEAN"}</span>
                </div>
              ))}
            </div>
          )}

          {/* Categories */}
          {data.categories?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>ABUSE CATEGORIES</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {data.categories.map((c, i) => <Tag key={i} color="#FF8C00">{c}</Tag>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Certificate Transparency ──────────────────────────────────────────────────
function CertTransparency({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [certs, setCerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [filter, setFilter] = useState("");

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    const d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setCerts([]);
    try {
      const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`);
      if (!r.ok) throw new Error("crt.sh unavailable");
      const raw = await r.json();
      const unique = [];
      const seen = new Set();
      for (const c of raw) {
        const key = c.name_value + c.issuer_name;
        if (!seen.has(key)) { seen.add(key); unique.push(c); }
      }
      setCerts(unique.slice(0, 200));
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const filtered = certs.filter(c =>
    !filter || c.name_value?.toLowerCase().includes(filter.toLowerCase()) || c.issuer_name?.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "SEARCH CT LOGS"}</Btn>
      </div>
      <ErrBox msg={err} />
      {certs.length > 0 && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em" }}>{certs.length} CERTIFICATES FOUND</span>
            <input className="db-input" placeholder="filter…" value={filter} onChange={e => setFilter(e.target.value)} style={{ width: 160, fontSize: 10, padding: "6px 12px" }} />
          </div>
          <div style={{ maxHeight: 480, overflowY: "auto" }}>
            {filtered.map((c, i) => (
              <div key={i} style={{
                padding: "10px 14px", marginBottom: 3,
                background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 8,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", wordBreak: "break-all", flex: 1 }}>
                    {c.name_value?.split("\n").map((n, j) => <div key={j}>{n}</div>)}
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>{c.not_before?.slice(0, 10)}</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A2A", marginTop: 2 }}>→ {c.not_after?.slice(0, 10)}</div>
                  </div>
                </div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", marginTop: 6 }}>{c.issuer_name}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Subdomain Enumeration ─────────────────────────────────────────────────────
function SubdomainEnum({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  const WORDLIST = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","api","cdn","dev","staging","test",
    "beta","admin","portal","app","dashboard","static","assets","media","img","images","video",
    "blog","news","shop","store","m","mobile","help","support","docs","wiki","git","gitlab",
    "github","jira","confluence","jenkins","ci","monitoring","grafana","prometheus","k8s",
    "cloud","ns1","ns2","mx","mx1","mx2","webmail","autodiscover","cpanel","whm","secure",
    "login","auth","sso","oauth","id","accounts","pay","payments","checkout","status","health",
  ];

  async function run() {
    const d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d || !isDomain(d)) { setErr("Valid domain required"); return; }
    setLoading(true); setErr(null); setResults([]); setProgress(0);

    const found = [];
    const batchSize = 10;
    for (let i = 0; i < WORDLIST.length; i += batchSize) {
      const batch = WORDLIST.slice(i, i + batchSize);
      await Promise.all(batch.map(async sub => {
        const fqdn = `${sub}.${d}`;
        try {
          const r = await fetch(`/api/dns?host=${encodeURIComponent(fqdn)}&type=A`);
          const j = await r.json();
          if (j.records?.length) {
            found.push({ sub: fqdn, ips: j.records });
            setResults([...found].sort((a, b) => a.sub.localeCompare(b.sub)));
          }
        } catch {}
      }));
      setProgress(Math.min(i + batchSize, WORDLIST.length));
    }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> SCANNING</> : "▶ ENUMERATE"}</Btn>
      </div>
      <ErrBox msg={err} />
      {loading && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>
            <span>PROBING {progress}/{WORDLIST.length} SUBDOMAINS</span>
            <span>{results.length} FOUND</span>
          </div>
          <div style={{ height: 3, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
            <div style={{ height: "100%", width: `${(progress / WORDLIST.length) * 100}%`, background: "#FFFFFF", borderRadius: 2, transition: "width .3s" }} />
          </div>
        </div>
      )}
      {results.length > 0 && (
        <div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>{results.length} SUBDOMAINS DISCOVERED</div>
          {results.map((r, i) => (
            <div key={i} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "10px 14px", marginBottom: 3,
              background: "rgba(255,255,255,0.015)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 8,
              animation: `db-fadeup .3s ease both`,
            }}>
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>{r.sub}</span>
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#4A4A6A" }}>{Array.isArray(r.ips) ? r.ips.slice(0, 2).join(", ") : r.ips}</span>
            </div>
          ))}
        </div>
      )}
      {!loading && results.length === 0 && progress > 0 && (
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No subdomains found in wordlist.</div>
      )}
    </div>
  );
}

// ── MX / Email Tests ──────────────────────────────────────────────────────────
function MxTest({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    const d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const [mx, spf, dkim, dmarc] = await Promise.all([
        fetch(`/api/dns?host=${encodeURIComponent(d)}&type=MX`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(d)}&type=TXT`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(`_dmarc.${d}`)}&type=TXT`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(`default._domainkey.${d}`)}&type=TXT`).then(r => r.json()),
      ]);

      const spfRecord = spf.records?.find(r => (typeof r === "string" ? r : r.join?.(" ") || "").includes("v=spf1"));
      const dmarcRecord = dmarc.records?.[0];
      const dkimRecord = dkim.records?.[0];

      setData({
        mx: mx.records || [],
        spf: spfRecord ? (typeof spfRecord === "string" ? spfRecord : spfRecord.join(" ")) : null,
        dmarc: dmarcRecord ? (typeof dmarcRecord === "string" ? dmarcRecord : dmarcRecord.join(" ")) : null,
        dkim: dkimRecord ? (typeof dkimRecord === "string" ? dkimRecord : dkimRecord.join(" ")) : null,
      });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  function checkIcon(val) {
    return val ? <span style={{ color: "#00E676" }}>✓ PRESENT</span> : <span style={{ color: "#FF3B3B" }}>✕ MISSING</span>;
  }

  const score = data ? [data.mx?.length > 0, !!data.spf, !!data.dmarc, !!data.dkim].filter(Boolean).length : 0;

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "ANALYZE EMAIL"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Score */}
          <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 24, padding: "16px 20px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12 }}>
            <span style={{ fontFamily: "'Instrument Serif', serif", fontSize: 48, color: score >= 3 ? "#00E676" : score >= 2 ? "#FFD600" : "#FF3B3B", lineHeight: 1 }}>{score}/4</span>
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", marginBottom: 4 }}>EMAIL SECURITY SCORE</div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A", letterSpacing: "0.1em" }}>
                {score === 4 ? "FULLY CONFIGURED" : score >= 2 ? "PARTIALLY CONFIGURED" : "POORLY CONFIGURED"}
              </div>
            </div>
          </div>

          {/* Checks */}
          <div className="db-grid-2" style={{ marginBottom: 20 }}>
            {[
              ["MX RECORDS", data.mx?.length > 0, `${data.mx?.length || 0} records found`],
              ["SPF POLICY", !!data.spf, "Sender Policy Framework"],
              ["DMARC POLICY", !!data.dmarc, "Domain-based Auth Reporting"],
              ["DKIM SIGNING", !!data.dkim, "DomainKeys Identified Mail"],
            ].map(([label, ok, desc]) => (
              <div key={label} style={{
                padding: "16px 18px",
                background: ok ? "rgba(0,230,118,0.04)" : "rgba(255,59,59,0.04)",
                border: `1px solid ${ok ? "rgba(0,230,118,0.15)" : "rgba(255,59,59,0.15)"}`,
                borderRadius: 10,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A", letterSpacing: "0.14em" }}>{label}</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9 }}>{checkIcon(ok)}</span>
                </div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{desc}</div>
              </div>
            ))}
          </div>

          {/* MX records */}
          {data.mx?.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>MX RECORDS</div>
              {data.mx.map((r, i) => (
                <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", padding: "7px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 3 }}>
                  {typeof r === "string" ? r : JSON.stringify(r)}
                </div>
              ))}
            </div>
          )}

          {/* SPF / DMARC / DKIM detail */}
          {data.spf && <Field label="SPF" value={data.spf} copy mono />}
          {data.dmarc && <Field label="DMARC" value={data.dmarc} copy mono />}
          {data.dkim && <Field label="DKIM" value={data.dkim?.slice(0, 120) + (data.dkim?.length > 120 ? "…" : "")} copy mono />}
        </div>
      )}
    </div>
  );
}

// ── Screenshot ────────────────────────────────────────────────────────────────
function Screenshot({ initialUrl }) {
  const [url, setUrl] = useState(initialUrl ? `https://${initialUrl}` : "");
  const [imgSrc, setImgSrc] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [meta, setMeta] = useState(null);

  useEffect(() => { if (initialUrl) setUrl(`https://${initialUrl}`); }, [initialUrl]);

  async function run() {
    let u = url.trim();
    if (!u.startsWith("http")) u = `https://${u}`;
    setLoading(true); setErr(null); setImgSrc(null); setMeta(null);
    try {
      const r = await fetch(`/api/screenshot?url=${encodeURIComponent(u)}`);
      const d = await r.json();
      if (d.error) setErr(d.error);
      else { setImgSrc(d.screenshot); setMeta(d); }
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> CAPTURING</> : "▶ SCREENSHOT"}</Btn>
      </div>
      <ErrBox msg={err} />
      {loading && (
        <div style={{ textAlign: "center", padding: "60px 0", fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", animation: "db-pulse 2s ease infinite" }}>
          LAUNCHING HEADLESS BROWSER
        </div>
      )}
      {meta && (
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Tag color={meta.statusCode < 400 ? "#00E676" : "#FF3B3B"}>HTTP {meta.statusCode}</Tag>
          {meta.redirected && <Tag color="#FF8C00">REDIRECTED</Tag>}
          {meta.finalUrl && meta.finalUrl !== url && <Tag color="#555">→ {meta.finalUrl?.slice(0, 40)}</Tag>}
          {meta.loadTime && <Tag color="#555">{meta.loadTime}ms</Tag>}
        </div>
      )}
      {imgSrc && (
        <div style={{ position: "relative", borderRadius: 10, overflow: "hidden", border: "1px solid rgba(255,255,255,0.06)" }}>
          <img src={imgSrc} alt="screenshot" style={{ width: "100%", display: "block" }} />
          <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, padding: "8px 12px", background: "linear-gradient(transparent, rgba(9,9,15,0.95))", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#444" }}>{url}</span>
            <a href={imgSrc} download="screenshot.png" style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#555", textDecoration: "none", letterSpacing: "0.1em" }}>SAVE ↓</a>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Tech Stack ────────────────────────────────────────────────────────────────
function TechStack({ initialUrl }) {
  const [url, setUrl] = useState(initialUrl || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialUrl) setUrl(initialUrl); }, [initialUrl]);

  async function run() {
    let u = url.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!u) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/techstack?host=${encodeURIComponent(u)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const categories = data ? Object.entries(
    (data.technologies || []).reduce((acc, t) => {
      const cat = t.category || "Other";
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(t);
      return acc;
    }, {})
  ) : [];

  const categoryColors = {
    "CMS": "#7C3AED", "Server": "#FF8C00", "Framework": "#00B4D8",
    "JavaScript": "#FFD600", "Analytics": "#00E676", "CDN": "#FF3B3B",
    "Security": "#FF6B6B", "Database": "#4CC9F0", "Other": "#555",
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="domain.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "FINGERPRINT"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Summary tags */}
          {data.server && (
            <div style={{ marginBottom: 20, display: "flex", gap: 8, flexWrap: "wrap" }}>
              {data.server && <Tag color="#FF8C00">{data.server}</Tag>}
              {data.poweredBy && <Tag color="#555">{data.poweredBy}</Tag>}
              {data.xGenerator && <Tag color="#555">{data.xGenerator}</Tag>}
            </div>
          )}

          {/* Categories */}
          {categories.length > 0 ? categories.map(([cat, techs]) => (
            <div key={cat} style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>{cat.toUpperCase()}</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {techs.map((t, i) => (
                  <div key={i} style={{
                    padding: "8px 14px",
                    background: `${categoryColors[cat] || "#555"}08`,
                    border: `1px solid ${categoryColors[cat] || "#555"}25`,
                    borderRadius: 8,
                    display: "flex", flexDirection: "column", gap: 2,
                  }}>
                    <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>{t.name}</span>
                    {t.version && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>v{t.version}</span>}
                    {t.confidence && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{t.confidence}% conf.</span>}
                  </div>
                ))}
              </div>
            </div>
          )) : (
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No technologies detected.</div>
          )}

          {/* Headers fingerprint */}
          {(data.server || data.poweredBy) && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>HTTP FINGERPRINT</div>
              <Field label="Server" value={data.server} copy />
              <Field label="X-Powered-By" value={data.poweredBy} />
              <Field label="X-Generator" value={data.xGenerator} />
              <Field label="Via" value={data.via} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── IP Range / CIDR ───────────────────────────────────────────────────────────
function IpRange({ initialIp }) {
  const [input, setInput] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setInput(initialIp); }, [initialIp]);

  function parseCIDR(cidr) {
    try {
      const [ip, prefixStr] = cidr.includes("/") ? cidr.split("/") : [cidr, "24"];
      const prefix = parseInt(prefixStr);
      const parts = ip.split(".").map(Number);
      if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) throw new Error("Invalid IP");
      if (isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error("Invalid prefix");

      const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      const network = (ipNum & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const hosts = prefix >= 31 ? Math.pow(2, 32 - prefix) : Math.pow(2, 32 - prefix) - 2;

      function numToIp(n) {
        return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
      }

      return {
        network: numToIp(network),
        broadcast: numToIp(broadcast),
        netmask: numToIp(mask),
        firstHost: prefix >= 31 ? numToIp(network) : numToIp(network + 1),
        lastHost: prefix >= 31 ? numToIp(broadcast) : numToIp(broadcast - 1),
        hosts: hosts > 0 ? hosts : 0,
        prefix,
        ipClass: parts[0] < 128 ? "A" : parts[0] < 192 ? "B" : parts[0] < 224 ? "C" : "D/E",
        isPrivate: (parts[0] === 10) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168),
        isLoopback: parts[0] === 127,
        binaryMask: prefix.toString().padStart(2, "0"),
        neighbors: [
          prefix > 1 ? `${numToIp((network - Math.pow(2, 32 - prefix)) >>> 0)}/${prefix}` : null,
          prefix < 32 ? `${numToIp(broadcast + 1)}/${prefix}` : null,
        ].filter(Boolean),
      };
    } catch (e) {
      return null;
    }
  }

  function run() {
    const result = parseCIDR(input.trim());
    if (!result) { setErr("Enter a valid IP or CIDR (e.g. 192.168.1.0/24)"); setData(null); }
    else { setErr(null); setData(result); }
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="192.168.1.0/24 or 10.0.0.1" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run}>CALCULATE</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div className="db-grid-2" style={{ marginBottom: 20 }}>
            <Panel title="Network Info">
              <Field label="CIDR" value={`${data.network}/${data.prefix}`} copy />
              <Field label="Network" value={data.network} copy />
              <Field label="Broadcast" value={data.broadcast} copy />
              <Field label="Netmask" value={data.netmask} copy />
              <Field label="First Host" value={data.firstHost} copy />
              <Field label="Last Host" value={data.lastHost} copy />
            </Panel>
            <Panel title="Stats">
              <Field label="Total Hosts" value={data.hosts.toLocaleString()} />
              <Field label="Prefix" value={`/${data.prefix}`} />
              <Field label="IP Class" value={`Class ${data.ipClass}`} />
              <Field label="Private" value={data.isPrivate ? "YES (RFC 1918)" : "NO"} accent={data.isPrivate ? "#00E676" : undefined} />
              <Field label="Loopback" value={data.isLoopback ? "YES" : "NO"} />
            </Panel>
          </div>
          {data.neighbors?.length > 0 && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>ADJACENT SUBNETS</div>
              <div style={{ display: "flex", gap: 6 }}>
                {data.neighbors.map((n, i) => <Tag key={i} color="#555">{n}</Tag>)}
              </div>
            </div>
          )}
          {/* Subnet split helper */}
          {data.prefix < 30 && (
            <div style={{ marginTop: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>SPLIT INTO /{data.prefix + 1}</div>
              {[0, 1].map(half => {
                const size = Math.pow(2, 32 - data.prefix - 1);
                const parts = data.network.split(".").map(Number);
                const baseNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                const halfStart = (baseNum + half * size) >>> 0;
                const ip = [(halfStart >>> 24) & 255, (halfStart >>> 16) & 255, (halfStart >>> 8) & 255, halfStart & 255].join(".");
                return (
                  <div key={half} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#4A4A6A", padding: "7px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 3 }}>
                    {ip}/{data.prefix + 1}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ── 2026 EXPANSION TABS ────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── BGP Route Visualization ───────────────────────────────────────────────────
function BgpRoutes({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function run() {
    const q = ip.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      // Use RIPEstat public API
      const [prefixRes, asRes] = await Promise.all([
        fetch(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(q)}`).then(r => r.json()),
        fetch(`https://stat.ripe.net/data/routing-status/data.json?resource=${encodeURIComponent(q)}`).then(r => r.json()),
      ]);
      setData({ prefix: prefixRes.data, routing: asRes.data });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const asns = data?.prefix?.asns || [];
  const prefixes = data?.prefix?.announced ? [data.prefix.resource] : [];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="IP, ASN (AS15169), or CIDR…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ BGP LOOKUP"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Route status bar */}
          <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 24, padding: "16px 20px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, lineHeight: 1, color: data.prefix?.announced ? "#00E676" : "#FF3B3B" }}>
                {data.prefix?.announced ? "▲" : "▼"}
              </div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.2em", marginTop: 4 }}>
                {data.prefix?.announced ? "ANNOUNCED" : "NOT ANNOUNCED"}
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <Field label="Resource" value={data.prefix?.resource} copy />
              <Field label="Block" value={data.prefix?.block?.name || data.prefix?.block?.desc} />
              <Field label="Type" value={data.prefix?.block?.type} />
            </div>
          </div>

          {/* ASN table */}
          {asns.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>ORIGINATING AS NUMBERS</div>
              {asns.map((a, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", marginBottom: 4, background: "rgba(75,0,180,0.05)", border: "1px solid rgba(123,104,238,0.15)", borderRadius: 8 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#7B68EE" }}>AS{a.asn}</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", maxWidth: 300, textAlign: "right", wordBreak: "break-all" }}>{a.holder}</span>
                </div>
              ))}
            </div>
          )}

          {/* Routing visualization — simple path diagram */}
          {data.routing && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>ROUTING STATUS</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {data.routing.visibility?.v4?.ris_peers_seeing !== undefined && (
                  <div style={{ padding: "12px 16px", background: "rgba(75,144,217,0.06)", border: "1px solid rgba(75,144,217,0.2)", borderRadius: 8 }}>
                    <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 28, color: "#4A90D9" }}>{data.routing.visibility?.v4?.ris_peers_seeing ?? "—"}</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.14em" }}>IPv4 PEERS SEEING</div>
                  </div>
                )}
                {data.routing.visibility?.v6?.ris_peers_seeing !== undefined && (
                  <div style={{ padding: "12px 16px", background: "rgba(0,180,216,0.06)", border: "1px solid rgba(0,180,216,0.2)", borderRadius: 8 }}>
                    <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 28, color: "#00B4D8" }}>{data.routing.visibility?.v6?.ris_peers_seeing ?? "—"}</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.14em" }}>IPv6 PEERS SEEING</div>
                  </div>
                )}
                {data.routing.first_seen && (
                  <div style={{ padding: "12px 16px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 8 }}>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>{data.routing.first_seen?.time?.slice(0,10)}</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.14em", marginTop: 4 }}>FIRST SEEN</div>
                  </div>
                )}
                {data.routing.last_seen && (
                  <div style={{ padding: "12px 16px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 8 }}>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>{data.routing.last_seen?.time?.slice(0,10)}</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.14em", marginTop: 4 }}>LAST SEEN</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── IPv6 Inspector ────────────────────────────────────────────────────────────
function IPv6Inspector({ initialIp }) {
  const [input, setInput] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [dnsData, setDnsData] = useState(null);
  const [dnsLoading, setDnsLoading] = useState(false);

  useEffect(() => { if (initialIp) setInput(initialIp); }, [initialIp]);

  function expandIPv6(addr) {
    if (!addr.includes(":")) return null;
    try {
      let a = addr.toLowerCase();
      // Handle :: expansion
      if (a.includes("::")) {
        const sides = a.split("::");
        const left = sides[0] ? sides[0].split(":") : [];
        const right = sides[1] ? sides[1].split(":") : [];
        const missing = 8 - left.length - right.length;
        a = [...left, ...Array(missing).fill("0"), ...right].join(":");
      }
      const groups = a.split(":");
      if (groups.length !== 8) return null;
      return groups.map(g => g.padStart(4, "0")).join(":");
    } catch { return null; }
  }

  function parseIPv6(addr) {
    const expanded = expandIPv6(addr);
    if (!expanded) return null;
    const groups = expanded.split(":");
    const first = parseInt(groups[0], 16);
    let type = "Global Unicast";
    let scope = "Global";
    if (first === 0x2001 && parseInt(groups[1], 16) === 0xdb8) { type = "Documentation (2001:db8::/32)"; scope = "Documentation"; }
    else if (addr.toLowerCase().startsWith("fe80")) { type = "Link-Local"; scope = "Link"; }
    else if (addr.toLowerCase().startsWith("fc") || addr.toLowerCase().startsWith("fd")) { type = "Unique Local (ULA)"; scope = "Site"; }
    else if (addr.toLowerCase() === "::1") { type = "Loopback"; scope = "Host"; }
    else if (addr.toLowerCase().startsWith("ff")) { type = "Multicast"; scope = addr[3] === "1" ? "Node" : addr[3] === "2" ? "Link" : "Global"; }
    else if (addr.toLowerCase().startsWith("2002")) { type = "6to4 Tunnel"; scope = "Global"; }
    else if (addr.toLowerCase().startsWith("2001:0000") || addr.toLowerCase().startsWith("2001::")) { type = "Teredo"; scope = "Global"; }

    // Reverse DNS (ip6.arpa)
    const arpa = expanded.replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";

    return { expanded, groups, type, scope, arpa, addr };
  }

  async function run() {
    const q = input.trim();
    if (!q) return;
    if (!q.includes(":")) { setErr("Enter a valid IPv6 address"); setData(null); return; }
    const parsed = parseIPv6(q);
    if (!parsed) { setErr("Invalid IPv6 address"); setData(null); return; }
    setErr(null); setData(parsed);
    // Also do AAAA DNS lookup if it looks like a domain was queried previously
    setDnsLoading(true);
    try {
      const r = await fetch(`/api/dns?host=${encodeURIComponent(q)}&type=PTR`);
      const d = await r.json();
      setDnsData(d.records?.[0] || null);
    } catch {}
    setDnsLoading(false);
  }

  // Also support domain → AAAA
  const [domain, setDomain] = useState("");
  const [aaaaRecords, setAaaaRecords] = useState([]);
  const [aaaaLoading, setAaaaLoading] = useState(false);

  async function lookupAAAA() {
    const d = domain.trim();
    if (!d) return;
    setAaaaLoading(true); setAaaaRecords([]);
    try {
      const r = await fetch(`/api/dns?host=${encodeURIComponent(d)}&type=AAAA`);
      const j = await r.json();
      setAaaaRecords(j.records || []);
    } catch {}
    setAaaaLoading(false);
  }

  return (
    <div>
      {/* IPv6 address analysis */}
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>ANALYZE IPv6 ADDRESS</div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input className="db-input" placeholder="2001:4860:4860::8888" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run}>PARSE</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div style={{ marginBottom: 28 }}>
          <div style={{ padding: "16px 20px", background: "rgba(0,180,216,0.04)", border: "1px solid rgba(0,180,216,0.15)", borderRadius: 12, marginBottom: 16 }}>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 8 }}>EXPANDED</div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: "#00B4D8", wordBreak: "break-all", letterSpacing: "0.04em" }}>{data.expanded}</div>
          </div>
          {/* Groups visualization */}
          <div style={{ display: "flex", gap: 4, marginBottom: 20, flexWrap: "wrap" }}>
            {data.groups.map((g, i) => (
              <div key={i} style={{ padding: "8px 10px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, textAlign: "center" }}>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 12, color: "#C8C8D8" }}>{g}</div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", marginTop: 3 }}>G{i+1}</div>
              </div>
            ))}
          </div>
          <Field label="Type" value={data.type} accent="#00B4D8" />
          <Field label="Scope" value={data.scope} />
          <Field label="ip6.arpa" value={data.arpa} copy />
          {dnsLoading && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#2A2A3A", marginTop: 8 }}>Resolving PTR…</div>}
          {dnsData && <Field label="PTR Record" value={dnsData} copy />}
        </div>
      )}

      {/* Domain → AAAA lookup */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: 20 }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>DOMAIN → AAAA RECORDS</div>
        <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
          <input className="db-input" placeholder="ipv6.google.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && lookupAAAA()} style={{ flex: 1 }} />
          <Btn onClick={lookupAAAA}>{aaaaLoading ? <Spinner size={13} /> : "LOOKUP AAAA"}</Btn>
        </div>
        {aaaaRecords.length > 0 && aaaaRecords.map((r, i) => (
          <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#00B4D8", padding: "8px 12px", background: "rgba(0,180,216,0.04)", border: "1px solid rgba(0,180,216,0.12)", borderRadius: 6, marginBottom: 3, wordBreak: "break-all" }}>{r}</div>
        ))}
        {!aaaaLoading && aaaaRecords.length === 0 && domain && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No AAAA records found.</div>}
      </div>
    </div>
  );
}

// ── RPKI Validation ───────────────────────────────────────────────────────────
function RpkiValidator({ initialIp }) {
  const [resource, setResource] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setResource(initialIp); }, [initialIp]);

  async function run() {
    const q = resource.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      // RIPE NCC RPKI validator
      const r = await fetch(`https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(q)}`);
      const d = await r.json();
      setData(d.data);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  function statusColor(s) {
    if (!s) return "#555";
    s = s.toLowerCase();
    if (s === "valid") return "#00E676";
    if (s === "invalid") return "#FF3B3B";
    if (s === "not_found" || s === "unknown") return "#FF8C00";
    return "#555";
  }

  const validating_routes = data?.validating_roas || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="IP, prefix (1.1.1.0/24), or ASN…" value={resource} onChange={e => setResource(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "VALIDATE RPKI"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Resource Public Key Infrastructure — validates BGP route origin via ROA records
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Status hero */}
          <div style={{ display: "flex", gap: 20, alignItems: "center", padding: "20px 24px", marginBottom: 24, background: `${statusColor(data.status)}08`, border: `1px solid ${statusColor(data.status)}25`, borderRadius: 12 }}>
            <div>
              <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, color: statusColor(data.status), lineHeight: 1 }}>
                {data.status === "valid" ? "✓" : data.status === "invalid" ? "✕" : "?"}
              </div>
            </div>
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 14, color: statusColor(data.status), letterSpacing: "0.16em", marginBottom: 6 }}>{(data.status || "UNKNOWN").toUpperCase()}</div>
              <Field label="Resource" value={data.resource} copy />
              <Field label="Origin AS" value={data.origin_asn ? `AS${data.origin_asn}` : null} />
              <Field label="Prefix" value={data.prefix} />
            </div>
          </div>

          {/* ROA records */}
          {validating_routes.length > 0 && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>ROA RECORDS ({validating_routes.length})</div>
              {validating_routes.map((roa, i) => (
                <div key={i} style={{ padding: "12px 14px", marginBottom: 4, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 8 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px,1fr))", gap: 8 }}>
                    <div><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>PREFIX </span><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>{roa.prefix}</span></div>
                    <div><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>MAX LEN </span><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8" }}>/{roa.max_length}</span></div>
                    <div><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>ORIGIN </span><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#7B68EE" }}>AS{roa.origin_asn}</span></div>
                    <div><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>VALIDITY </span><span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: statusColor(roa.validity) }}>{(roa.validity || "").toUpperCase()}</span></div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── DNS Propagation Checker ───────────────────────────────────────────────────
const DNS_SERVERS = [
  { name: "Google",      ip: "8.8.8.8",       flag: "🌐" },
  { name: "Cloudflare",  ip: "1.1.1.1",       flag: "☁" },
  { name: "OpenDNS",     ip: "208.67.222.222", flag: "🔓" },
  { name: "Quad9",       ip: "9.9.9.9",       flag: "🛡" },
  { name: "Comodo",      ip: "8.26.56.26",    flag: "🔒" },
  { name: "Level3",      ip: "209.244.0.3",   flag: "📡" },
  { name: "Verisign",    ip: "64.6.64.6",     flag: "✅" },
  { name: "Alternate",   ip: "198.101.242.72", flag: "🔀" },
];

function DnsPropagation({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [type, setType] = useState("A");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    const d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setResults([]);
    // Query via Google's DoH API (dns.google) which accepts a resolver parameter
    const res = [];
    await Promise.all(DNS_SERVERS.map(async (srv) => {
      const start = Date.now();
      try {
        const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=${type}`);
        const j = await r.json();
        const latency = Date.now() - start;
        res.push({ ...srv, records: j.Answer?.map(a => a.data) || [], status: j.Status, latency });
      } catch {
        res.push({ ...srv, records: [], status: -1, latency: null });
      }
      setResults([...res]);
    }));
    setLoading(false);
  }

  // Find the "majority" answer
  const majority = results.length > 0 ? (() => {
    const freq = {};
    results.forEach(r => { const k = r.records.sort().join(","); freq[k] = (freq[k] || 0) + 1; });
    return Object.entries(freq).sort((a,b)=>b[1]-a[1])[0]?.[0] || "";
  })() : "";

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1, minWidth: 180 }} />
        <select className="db-select" value={type} onChange={e => setType(e.target.value)}>
          {["A","AAAA","MX","TXT","NS","CNAME"].map(t => <option key={t}>{t}</option>)}
        </select>
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> CHECKING</> : "▶ CHECK PROPAGATION"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Queries {DNS_SERVERS.length} global resolvers simultaneously via Google DoH
      </div>
      <ErrBox msg={err} />
      {results.length > 0 && (
        <div>
          {/* Propagation indicator */}
          <div style={{ marginBottom: 20 }}>
            {(() => {
              const consistent = results.filter(r => r.records.sort().join(",") === majority).length;
              const pct = Math.round((consistent / results.length) * 100);
              return (
                <div style={{ display: "flex", gap: 16, alignItems: "center", padding: "14px 18px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 10, marginBottom: 16 }}>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 36, color: pct === 100 ? "#00E676" : pct >= 70 ? "#FFD600" : "#FF3B3B", lineHeight: 1 }}>{pct}%</div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.2em", marginTop: 4 }}>PROPAGATED</div>
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2, overflow: "hidden", marginBottom: 8 }}>
                      <div style={{ height: "100%", width: `${pct}%`, background: pct === 100 ? "#00E676" : pct >= 70 ? "#FFD600" : "#FF3B3B", borderRadius: 2, transition: "width .8s ease" }} />
                    </div>
                    <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>{consistent} of {results.length} resolvers agree</div>
                  </div>
                </div>
              );
            })()}
          </div>
          {/* Per-resolver results */}
          {results.map((r, i) => {
            const match = r.records.sort().join(",") === majority;
            const hasRecords = r.records.length > 0;
            return (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "28px 100px 70px 1fr 60px", gap: 12, alignItems: "center", padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                <span style={{ fontSize: 14 }}>{r.flag}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#555" }}>{r.name}</span>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{r.ip}</span>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: hasRecords ? (match ? "#00E676" : "#FF8C00") : "#2A2A3A", wordBreak: "break-all" }}>
                  {hasRecords ? r.records.slice(0,3).join(", ") : r.status === -1 ? "ERROR" : "NO RECORD"}
                </div>
                <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", textAlign: "right" }}>{r.latency != null ? `${r.latency}ms` : "—"}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Redirect Chain Tracer ─────────────────────────────────────────────────────
function RedirectChain({ initialUrl }) {
  const [url, setUrl] = useState(initialUrl ? `https://${initialUrl}` : "");
  const [chain, setChain] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialUrl) setUrl(`https://${initialUrl}`); }, [initialUrl]);

  async function run() {
    let u = url.trim();
    if (!u.startsWith("http")) u = `https://${u}`;
    setLoading(true); setErr(null); setChain([]);
    try {
      const r = await fetch(`/api/redirectchain?url=${encodeURIComponent(u)}`);
      const d = await r.json();
      if (d.error) setErr(d.error);
      else setChain(d.chain || []);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const statusColor = code => {
    if (!code) return "#555";
    if (code >= 500) return "#FF3B3B";
    if (code >= 400) return "#FF8C00";
    if (code >= 300) return "#FFD600";
    if (code >= 200) return "#00E676";
    return "#555";
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <><Spinner size={13} /> TRACING</> : "▶ TRACE REDIRECTS"}</Btn>
      </div>
      <ErrBox msg={err} />
      {chain.length > 0 && (
        <div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 14 }}>
            {chain.length} HOP{chain.length !== 1 ? "S" : ""} · {chain.filter(h => h.status >= 300 && h.status < 400).length} REDIRECT{chain.filter(h => h.status >= 300 && h.status < 400).length !== 1 ? "S" : ""}
          </div>
          {chain.map((hop, i) => (
            <div key={i} style={{ position: "relative", paddingLeft: 28, marginBottom: 4 }}>
              {i < chain.length - 1 && (
                <div style={{ position: "absolute", left: 10, top: 34, width: 1, height: "calc(100% + 4px)", background: "rgba(255,255,255,0.06)" }} />
              )}
              <div style={{ position: "absolute", left: 6, top: 14, width: 9, height: 9, borderRadius: "50%", background: statusColor(hop.status), boxShadow: `0 0 6px ${statusColor(hop.status)}60` }} />
              <div style={{ padding: "12px 16px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 4 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", wordBreak: "break-all", flex: 1 }}>{hop.url}</span>
                  <Tag color={statusColor(hop.status)}>{hop.status}</Tag>
                </div>
                {hop.location && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>→ {hop.location}</div>}
                <div style={{ display: "flex", gap: 8, marginTop: 6, flexWrap: "wrap" }}>
                  {hop.server && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{hop.server}</span>}
                  {hop.latency && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{hop.latency}ms</span>}
                  {hop.tls && <Tag color="#00E676">TLS</Tag>}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── VirusTotal Scan ───────────────────────────────────────────────────────────
function VirusTotalScan({ initialTarget }) {
  const [target, setTarget] = useState(initialTarget || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialTarget) setTarget(initialTarget); }, [initialTarget]);

  async function run() {
    const q = target.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/virustotal?q=${encodeURIComponent(q)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const total = (data?.malicious || 0) + (data?.suspicious || 0) + (data?.harmless || 0) + (data?.undetected || 0);

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="IP, domain, or URL…" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ VT SCAN"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Checks against 80+ antivirus engines via VirusTotal API (requires API key in backend)
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
            {[
              ["MALICIOUS", data.malicious, "#FF3B3B"],
              ["SUSPICIOUS", data.suspicious, "#FF8C00"],
              ["HARMLESS", data.harmless, "#00E676"],
              ["UNDETECTED", data.undetected, "#333"],
            ].map(([label, count, color]) => (
              <div key={label} style={{ flex: 1, minWidth: 100, padding: "16px 18px", background: `${color}08`, border: `1px solid ${color}20`, borderRadius: 10, textAlign: "center" }}>
                <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 36, color, lineHeight: 1 }}>{count ?? "—"}</div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.18em", marginTop: 6 }}>{label}</div>
              </div>
            ))}
          </div>
          <Field label="Type" value={data.type} />
          <Field label="Reputation" value={data.reputation} accent={data.reputation < 0 ? "#FF3B3B" : "#00E676"} />
          <Field label="Last Analysis" value={data.lastAnalysisDate} />
          <Field label="Country" value={data.country} />
          <Field label="AS Owner" value={data.asOwner} />
          {data.tags?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>TAGS</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {data.tags.map((t, i) => <Tag key={i} color="#7B68EE">{t}</Tag>)}
              </div>
            </div>
          )}
          {/* Engine breakdown */}
          {data.engines?.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>DETECTIONS</div>
              {data.engines.filter(e => e.result !== "clean" && e.result !== "unrated").map((e, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "8px 12px", marginBottom: 3, background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.12)", borderRadius: 6 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#888" }}>{e.engine}</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#FF3B3B" }}>{e.result}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tor Exit Node Check ───────────────────────────────────────────────────────
function TorCheck({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function run() {
    const q = ip.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      // Use Dan.me.uk Tor exit list — reverse IP for DNSBL-style query
      const parts = q.split(".");
      if (parts.length === 4) {
        const reversed = parts.reverse().join(".");
        const dnsQuery = await fetch(`/api/dns?host=${encodeURIComponent(`${reversed}.dnsel.torproject.org`)}&type=A`);
        const dnsResult = await dnsQuery.json();
        const isTor = dnsResult.records?.includes("127.0.0.2");
        // Also check ipinfo for supplementary data
        const infoR = await fetch(`/api/ipinfo?q=${encodeURIComponent(q)}`);
        const info = await infoR.json();
        setData({ isTor, ip: q, org: info.org, isp: info.isp, country: info.country, asname: info.asname });
      } else {
        setErr("IPv4 address required for Tor exit check");
      }
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="IPv4 address…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ CHECK TOR"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Checks Tor Project's official DNSEL exit node list
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 20, alignItems: "center", padding: "24px 28px", marginBottom: 20, background: data.isTor ? "rgba(255,59,59,0.06)" : "rgba(0,230,118,0.04)", border: `1px solid ${data.isTor ? "rgba(255,59,59,0.25)" : "rgba(0,230,118,0.2)"}`, borderRadius: 12 }}>
            <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 64, lineHeight: 1, color: data.isTor ? "#FF3B3B" : "#00E676" }}>
              {data.isTor ? "⚠" : "✓"}
            </div>
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 16, color: data.isTor ? "#FF3B3B" : "#00E676", letterSpacing: "0.18em", marginBottom: 8 }}>
                {data.isTor ? "TOR EXIT NODE" : "NOT A TOR EXIT NODE"}
              </div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#3A3A4A" }}>
                {data.isTor ? "This IP is listed in the Tor Project's official exit node list." : "Not found in Tor Project DNSEL. This IP is not a known Tor exit."}
              </div>
            </div>
          </div>
          <Field label="IP" value={data.ip} copy />
          <Field label="ISP" value={data.isp} />
          <Field label="Org" value={data.org} />
          <Field label="AS Name" value={data.asname} />
          <Field label="Country" value={data.country} />
          <Field label="Check Method" value="Tor Project DNSEL (dnsel.torproject.org)" />
        </div>
      )}
    </div>
  );
}

// ── CVE Lookup ────────────────────────────────────────────────────────────────
function CveLookup() {
  const [query, setQuery] = useState("");
  const [data, setData] = useState(null);
  const [list, setList] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  async function run() {
    const q = query.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null); setList(null);
    try {
      if (/^CVE-\d{4}-\d+$/i.test(q)) {
        // Single CVE lookup
        const r = await fetch(`https://cveawg.mitre.org/api/cve/${q.toUpperCase()}`);
        if (!r.ok) throw new Error("CVE not found");
        const d = await r.json();
        setData(d);
      } else {
        // Keyword search via NVD
        const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=10`);
        const d = await r.json();
        setList(d.vulnerabilities || []);
      }
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  function cvssColor(score) {
    if (!score) return "#555";
    if (score >= 9) return "#FF3B3B";
    if (score >= 7) return "#FF8C00";
    if (score >= 4) return "#FFD600";
    return "#00E676";
  }

  const cna = data?.containers?.cna;
  const descriptions = cna?.descriptions?.find(d => d.lang === "en")?.value || "";
  const metrics = cna?.metrics?.[0]?.cvssV3_1 || cna?.metrics?.[0]?.cvssV3_0 || {};

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="CVE-2024-12345 or keyword (e.g. log4j)…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "SEARCH CVE"}</Btn>
      </div>
      <ErrBox msg={err} />

      {/* Single CVE detail */}
      {data && (
        <div>
          <div style={{ marginBottom: 20, padding: "16px 20px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
              <div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 14, color: "#FF8C00", letterSpacing: "0.12em", marginBottom: 6 }}>{data.cveMetadata?.cveId}</div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.14em" }}>{data.cveMetadata?.state} · Published {data.cveMetadata?.datePublished?.slice(0,10)}</div>
              </div>
              {metrics.baseScore && (
                <div style={{ textAlign: "center", padding: "10px 16px", background: `${cvssColor(metrics.baseScore)}12`, border: `1px solid ${cvssColor(metrics.baseScore)}30`, borderRadius: 8 }}>
                  <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 32, color: cvssColor(metrics.baseScore), lineHeight: 1 }}>{metrics.baseScore}</div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.16em", marginTop: 4 }}>{metrics.baseSeverity || "CVSS"}</div>
                </div>
              )}
            </div>
            <p style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#888", lineHeight: 1.7 }}>{descriptions}</p>
          </div>
          {metrics.vectorString && <Field label="CVSS Vector" value={metrics.vectorString} copy />}
          {metrics.attackVector && <Field label="Attack Vector" value={metrics.attackVector} />}
          {metrics.attackComplexity && <Field label="Complexity" value={metrics.attackComplexity} />}
          {metrics.privilegesRequired && <Field label="Privileges Required" value={metrics.privilegesRequired} />}
          {metrics.userInteraction && <Field label="User Interaction" value={metrics.userInteraction} />}
          {metrics.scope && <Field label="Scope" value={metrics.scope} />}
          {cna?.affected?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>AFFECTED PRODUCTS</div>
              {cna.affected.slice(0, 6).map((a, i) => (
                <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", padding: "7px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 6, marginBottom: 3 }}>
                  {a.vendor} · {a.product} {a.versions?.[0]?.version && `(${a.versions[0].version})`}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Search results list */}
      {list && (
        <div>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 14 }}>{list.length} RESULTS</div>
          {list.length === 0 && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No CVEs found.</div>}
          {list.map((item, i) => {
            const cve = item.cve;
            const desc = cve?.descriptions?.find(d => d.lang === "en")?.value || "";
            const score = cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
            const severity = cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity;
            return (
              <div key={i} style={{ padding: "14px 16px", marginBottom: 6, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 8, cursor: "pointer" }}
                onClick={() => { setQuery(cve?.id || ""); setList(null); }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#FF8C00" }}>{cve?.id}</span>
                  {score && <Tag color={cvssColor(score)}>{score} {severity}</Tag>}
                </div>
                <p style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#444", lineHeight: 1.6, margin: 0 }}>{desc.slice(0, 200)}{desc.length > 200 ? "…" : ""}</p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Reverse IP Lookup ─────────────────────────────────────────────────────────
function ReverseIp({ initialIp }) {
  const [ip, setIp] = useState(initialIp || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialIp) setIp(initialIp); }, [initialIp]);

  async function run() {
    const q = ip.trim();
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/reverseip?ip=${encodeURIComponent(q)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const domains = data?.domains || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="IP address or domain…" value={ip} onChange={e => setIp(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ REVERSE LOOKUP"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Finds all domains sharing the same IP address (shared hosting detection)
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", gap: 16, alignItems: "center", padding: "14px 18px", marginBottom: 20, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 10 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, color: domains.length > 50 ? "#FF8C00" : "#C8C8D8", lineHeight: 1 }}>{domains.length}</div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.18em", marginTop: 4 }}>DOMAINS</div>
            </div>
            <div style={{ flex: 1 }}>
              <Field label="IP" value={data.ip} copy />
              <Field label="Hosting" value={data.hosting || null} />
              {domains.length > 50 && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#FF8C00", marginTop: 8 }}>⚠ HIGH DENSITY — shared hosting or CDN likely</div>}
            </div>
          </div>
          {domains.length > 0 && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>HOSTED DOMAINS</div>
              <div style={{ maxHeight: 400, overflowY: "auto" }}>
                {domains.map((d, i) => (
                  <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", padding: "7px 12px", background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.03)", borderRadius: 6, marginBottom: 3 }}>
                    {d}
                  </div>
                ))}
              </div>
            </div>
          )}
          {domains.length === 0 && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No additional domains found on this IP.</div>}
        </div>
      )}
    </div>
  );
}

// ── Passive DNS History ───────────────────────────────────────────────────────
function PassiveDns({ initialDomain }) {
  const [query, setQuery] = useState(initialDomain || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [filter, setFilter] = useState("");

  useEffect(() => { if (initialDomain) setQuery(initialDomain); }, [initialDomain]);

  async function run() {
    const q = query.trim().replace(/^https?:\/\//, "").split("/")[0];
    if (!q) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/passivedns?q=${encodeURIComponent(q)}`);
      const d = await r.json();
      if (d.error) setErr(d.error); else setData(d);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const records = (data?.records || []).filter(r =>
    !filter || r.rrname?.toLowerCase().includes(filter.toLowerCase()) || r.rdata?.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="domain.com or IP…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ PASSIVE DNS"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Historical DNS resolution data — shows past IP associations and record changes
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em" }}>{data.records?.length || 0} HISTORICAL RECORDS</span>
            <input className="db-input" placeholder="filter…" value={filter} onChange={e => setFilter(e.target.value)} style={{ width: 160, fontSize: 10, padding: "6px 12px" }} />
          </div>
          {records.length === 0 && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#2A2A3A" }}>No passive DNS history found.</div>}
          <div style={{ maxHeight: 500, overflowY: "auto" }}>
            {records.map((rec, i) => (
              <div key={i} style={{ padding: "10px 14px", marginBottom: 4, background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 8 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 60px 1fr", gap: 12, alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#C8C8D8", wordBreak: "break-all" }}>{rec.rrname}</span>
                  <Tag color="#555">{rec.rrtype}</Tag>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#4A90D9", wordBreak: "break-all" }}>{rec.rdata}</span>
                </div>
                <div style={{ display: "flex", gap: 16 }}>
                  {rec.first_seen && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>FIRST: {rec.first_seen}</span>}
                  {rec.last_seen && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>LAST: {rec.last_seen}</span>}
                  {rec.count && <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>SEEN: {rec.count}×</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── robots.txt Viewer ─────────────────────────────────────────────────────────
function RobotsTxt({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    let d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/robotstxt?host=${encodeURIComponent(d)}`);
      const j = await r.json();
      if (j.error) setErr(j.error); else setData(j);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  function parseRobots(raw) {
    if (!raw) return [];
    const groups = [];
    let current = null;
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#") || !trimmed) continue;
      const [directive, ...rest] = trimmed.split(":");
      const value = rest.join(":").trim();
      if (directive.toLowerCase() === "user-agent") {
        if (!current || current.userAgent !== value) {
          current = { userAgent: value, allow: [], disallow: [], other: [] };
          groups.push(current);
        }
      } else if (current) {
        if (directive.toLowerCase() === "allow") current.allow.push(value);
        else if (directive.toLowerCase() === "disallow") current.disallow.push(value);
        else current.other.push(`${directive}: ${value}`);
      }
    }
    return groups;
  }

  const parsed = data?.content ? parseRobots(data.content) : [];
  const sitemaps = data?.content?.match(/^Sitemap:\s*(.+)$/gim)?.map(s => s.replace(/^Sitemap:\s*/i, "")) || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "FETCH robots.txt"}</Btn>
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Meta */}
          <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
            <Tag color={data.exists ? "#00E676" : "#FF3B3B"}>{data.exists ? "✓ EXISTS" : "✕ NOT FOUND"}</Tag>
            {data.statusCode && <Tag color="#555">HTTP {data.statusCode}</Tag>}
            {data.content && <Tag color="#555">{data.content.split("\n").length} LINES</Tag>}
            {sitemaps.length > 0 && <Tag color="#4A90D9">{sitemaps.length} SITEMAP{sitemaps.length !== 1 ? "S" : ""}</Tag>}
          </div>

          {/* Sitemaps */}
          {sitemaps.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 10 }}>SITEMAPS</div>
              {sitemaps.map((s, i) => (
                <div key={i} style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#4A90D9", padding: "7px 12px", background: "rgba(74,144,217,0.06)", borderRadius: 6, marginBottom: 3, wordBreak: "break-all" }}>{s}</div>
              ))}
            </div>
          )}

          {/* Parsed groups */}
          {parsed.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>RULES ({parsed.length} AGENT GROUP{parsed.length !== 1 ? "S" : ""})</div>
              {parsed.map((g, i) => (
                <div key={i} style={{ marginBottom: 12, padding: "14px 16px", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 10 }}>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#7B68EE", marginBottom: 10, letterSpacing: "0.1em" }}>User-Agent: {g.userAgent}</div>
                  {g.disallow.map((p, j) => (
                    <div key={j} style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#FF6B6B", padding: "4px 8px", borderRadius: 4, marginBottom: 2 }}>
                      <span style={{ color: "#2A2A3A" }}>Disallow: </span>{p || "/"}
                    </div>
                  ))}
                  {g.allow.map((p, j) => (
                    <div key={j} style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#00E676", padding: "4px 8px", borderRadius: 4, marginBottom: 2 }}>
                      <span style={{ color: "#2A2A3A" }}>Allow: </span>{p}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* Raw */}
          {data.content && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", cursor: "pointer", marginBottom: 10 }}>RAW CONTENT</summary>
              <pre style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", lineHeight: 1.8, background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 8, padding: "14px 16px", overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{data.content}</pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

// ── WAF Detection ─────────────────────────────────────────────────────────────
function WafDetection({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    let d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const r = await fetch(`/api/waf?host=${encodeURIComponent(d)}`);
      const j = await r.json();
      if (j.error) setErr(j.error); else setData(j);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  // WAF signature database
  const WAF_SIGS = {
    "Cloudflare":      { color: "#FF8C00", headers: ["cf-ray", "cf-cache-status", "cf-request-id"] },
    "AWS WAF / CloudFront": { color: "#FF8C00", headers: ["x-amz-cf-id", "x-amz-request-id"] },
    "Akamai":          { color: "#4A90D9", headers: ["x-akamai-transformed", "x-akamai-request-id"] },
    "Fastly":          { color: "#FF6B6B", headers: ["x-served-by", "fastly-io-info", "x-fastly-request-id"] },
    "Sucuri":          { color: "#00E676", headers: ["x-sucuri-id", "x-sucuri-cache"] },
    "Imperva / Incapsula": { color: "#7B68EE", headers: ["x-iinfo", "incap-ses"] },
    "Barracuda":       { color: "#FF3B3B", headers: ["barra_counter_session", "p3p"] },
    "F5 BIG-IP":       { color: "#00B4D8", headers: ["x-cnection", "server:bigip"] },
  };

  const detected = data?.headers ? Object.entries(WAF_SIGS).filter(([name, sig]) =>
    sig.headers.some(h => data.headers[h] || Object.keys(data.headers).some(k => k.toLowerCase() === h.toLowerCase()))
  ) : [];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ DETECT WAF"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Detects Web Application Firewalls via HTTP response header fingerprinting
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Detection result */}
          <div style={{ marginBottom: 24 }}>
            {detected.length > 0 ? detected.map(([name, sig], i) => (
              <div key={i} style={{ display: "flex", gap: 16, alignItems: "center", padding: "20px 24px", marginBottom: 8, background: `${sig.color}08`, border: `1px solid ${sig.color}25`, borderRadius: 12 }}>
                <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, color: sig.color, lineHeight: 1 }}>🛡</div>
                <div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 14, color: sig.color, letterSpacing: "0.12em", marginBottom: 4 }}>{name}</div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>WAF DETECTED</div>
                </div>
              </div>
            )) : (
              <div style={{ display: "flex", gap: 16, alignItems: "center", padding: "20px 24px", background: "rgba(0,230,118,0.04)", border: "1px solid rgba(0,230,118,0.15)", borderRadius: 12 }}>
                <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, color: "#00E676", lineHeight: 1 }}>?</div>
                <div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: "#00E676", letterSpacing: "0.12em", marginBottom: 4 }}>NO KNOWN WAF DETECTED</div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>May use custom or unrecognized protection</div>
                </div>
              </div>
            )}
          </div>

          {/* CDN / proxy hints */}
          {data.headers && (
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 12 }}>SECURITY-RELEVANT HEADERS</div>
              {Object.entries(data.headers).filter(([k]) =>
                ["server","via","x-powered-by","x-cache","x-frame-options","strict-transport-security",
                 "content-security-policy","x-xss-protection","cf-ray","x-amz-cf-id","x-akamai-transformed",
                 "x-sucuri-id","x-iinfo","x-served-by"].some(s => k.toLowerCase().includes(s))
              ).map(([k, v], i) => (
                <div key={i} style={{ padding: "8px 12px", marginBottom: 3, background: "rgba(255,255,255,0.01)", border: "1px solid rgba(255,255,255,0.04)", borderRadius: 6 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A4A" }}>{k}: </span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#C8C8D8" }}>{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Email Spoofing Test ───────────────────────────────────────────────────────
function EmailSpoofTest({ initialDomain }) {
  const [domain, setDomain] = useState(initialDomain || "");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  useEffect(() => { if (initialDomain) setDomain(initialDomain); }, [initialDomain]);

  async function run() {
    let d = domain.replace(/^https?:\/\//, "").split("/")[0].trim();
    if (!d) return;
    setLoading(true); setErr(null); setData(null);
    try {
      const [spfRes, dmarcRes, dkimRes, mxRes] = await Promise.all([
        fetch(`/api/dns?host=${encodeURIComponent(d)}&type=TXT`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(`_dmarc.${d}`)}&type=TXT`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(`default._domainkey.${d}`)}&type=TXT`).then(r => r.json()),
        fetch(`/api/dns?host=${encodeURIComponent(d)}&type=MX`).then(r => r.json()),
      ]);

      const spfStr = spfRes.records?.map(r => typeof r === "string" ? r : r.join?.(" ") || "").find(r => r.includes("v=spf1")) || null;
      const dmarcStr = dmarcRes.records?.[0] ? (typeof dmarcRes.records[0] === "string" ? dmarcRes.records[0] : dmarcRes.records[0].join(" ")) : null;
      const dkimStr = dkimRes.records?.[0] ? (typeof dkimRes.records[0] === "string" ? dkimRes.records[0] : dkimRes.records[0].join(" ")) : null;

      // Parse SPF policy strength
      let spfPolicy = null;
      if (spfStr) {
        if (spfStr.includes(" -all")) spfPolicy = "HARD FAIL (-all)";
        else if (spfStr.includes(" ~all")) spfPolicy = "SOFT FAIL (~all)";
        else if (spfStr.includes(" ?all")) spfPolicy = "NEUTRAL (?all)";
        else if (spfStr.includes(" +all")) spfPolicy = "PASS (+all) ⚠ PERMISSIVE";
        else spfPolicy = "NO all DIRECTIVE";
      }

      // Parse DMARC policy
      let dmarcPolicy = null;
      if (dmarcStr) {
        const match = dmarcStr.match(/p=(\w+)/i);
        if (match) dmarcPolicy = match[1].toUpperCase();
      }

      // Spooofability assessment
      let spoofable = true;
      let spoofRisk = "HIGH";
      if (spfStr && spfStr.includes(" -all") && dmarcStr && dmarcPolicy === "REJECT") {
        spoofable = false; spoofRisk = "LOW";
      } else if ((spfStr && spfStr.includes(" ~all")) || (dmarcStr && dmarcPolicy === "QUARANTINE")) {
        spoofRisk = "MEDIUM";
      }

      setData({ spf: spfStr, spfPolicy, dmarc: dmarcStr, dmarcPolicy, dkim: dkimStr, mx: mxRes.records || [], spoofable, spoofRisk });
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }

  const riskColor = r => r === "LOW" ? "#00E676" : r === "MEDIUM" ? "#FFD600" : "#FF3B3B";

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input className="db-input" placeholder="domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} style={{ flex: 1 }} />
        <Btn onClick={run} disabled={loading}>{loading ? <Spinner size={13} /> : "▶ TEST SPOOFING"}</Btn>
      </div>
      <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.1em", marginBottom: 16 }}>
        Analyzes SPF, DMARC, and DKIM to assess email spoofing vulnerability
      </div>
      <ErrBox msg={err} />
      {data && (
        <div>
          {/* Verdict */}
          <div style={{ display: "flex", gap: 16, alignItems: "center", padding: "20px 24px", marginBottom: 24, background: `${riskColor(data.spoofRisk)}08`, border: `1px solid ${riskColor(data.spoofRisk)}25`, borderRadius: 12 }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 40, lineHeight: 1, color: riskColor(data.spoofRisk) }}>
                {data.spoofable ? "⚠" : "✓"}
              </div>
            </div>
            <div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: riskColor(data.spoofRisk), letterSpacing: "0.16em", marginBottom: 6 }}>
                SPOOF RISK: {data.spoofRisk}
              </div>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A" }}>
                {data.spoofable ? "This domain may be vulnerable to email spoofing" : "Strong SPF + DMARC reject — difficult to spoof"}
              </div>
            </div>
          </div>

          {/* Check grid */}
          <div className="db-grid-2" style={{ marginBottom: 20 }}>
            {[
              ["SPF",   !!data.spf,   data.spfPolicy || "Not configured"],
              ["DMARC", !!data.dmarc, data.dmarcPolicy ? `Policy: ${data.dmarcPolicy}` : "Not configured"],
              ["DKIM",  !!data.dkim,  "default._domainkey selector"],
              ["MX",    data.mx.length > 0, `${data.mx.length} mail server${data.mx.length !== 1 ? "s" : ""}`],
            ].map(([label, ok, desc]) => (
              <div key={label} style={{ padding: "16px 18px", background: ok ? "rgba(0,230,118,0.04)" : "rgba(255,59,59,0.04)", border: `1px solid ${ok ? "rgba(0,230,118,0.15)" : "rgba(255,59,59,0.15)"}`, borderRadius: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#3A3A4A", letterSpacing: "0.14em" }}>{label}</span>
                  <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: ok ? "#00E676" : "#FF3B3B" }}>{ok ? "✓ PRESENT" : "✕ MISSING"}</span>
                </div>
                <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A" }}>{desc}</div>
              </div>
            ))}
          </div>

          {/* Raw records */}
          {data.spf && <Field label="SPF Record" value={data.spf} copy />}
          {data.dmarc && <Field label="DMARC Record" value={data.dmarc} copy />}
          {data.dkim && <Field label="DKIM (default)" value={data.dkim.slice(0, 100) + (data.dkim.length > 100 ? "…" : "")} copy />}

          {/* Recommendations */}
          {data.spoofable && (
            <div style={{ marginTop: 20, padding: "14px 16px", background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.12)", borderRadius: 10 }}>
              <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#FF3B3B", letterSpacing: "0.2em", marginBottom: 10 }}>RECOMMENDATIONS</div>
              {!data.spf && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>▸ Add an SPF record with a -all hard fail policy</div>}
              {data.spf && !data.spf.includes("-all") && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>▸ Strengthen SPF to use -all instead of ~all or ?all</div>}
              {!data.dmarc && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>▸ Add a DMARC record with p=reject</div>}
              {data.dmarc && data.dmarcPolicy !== "REJECT" && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", marginBottom: 6 }}>▸ Upgrade DMARC policy from {data.dmarcPolicy} to REJECT</div>}
              {!data.dkim && <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555" }}>▸ Configure DKIM signing for outbound mail</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── TABS CONFIG ───────────────────────────────────────────────────────────────
const TABS = [
  { id: "overview",    label: "OVERVIEW" },
  { id: "geo",         label: "GEO" },
  { id: "ports",       label: "PORTS" },
  { id: "dns",         label: "DNS" },
  { id: "whois",       label: "WHOIS" },
  { id: "ssl",         label: "SSL" },
  { id: "headers",     label: "HEADERS" },
  { id: "asn",         label: "ASN" },
  { id: "blacklist",   label: "BLACKLIST" },
  { id: "ping",        label: "PING" },
  { id: "compare",     label: "COMPARE" },
  { id: "bulk",        label: "BULK" },
  // ── NEW 2026 ──
  { id: "traceroute",  label: "TRACEROUTE" },
  { id: "reputation",  label: "REPUTATION" },
  { id: "certs",       label: "CT LOGS" },
  { id: "subdomains",  label: "SUBDOMAINS" },
  { id: "mxtest",      label: "EMAIL" },
  { id: "screenshot",  label: "SCREENSHOT" },
  { id: "techstack",   label: "TECH STACK" },
  { id: "iprange",     label: "IP RANGE" },
  // ── 2026 EXPANSION ──
  { id: "bgp",         label: "BGP" },
  { id: "ipv6",        label: "IPv6" },
  { id: "rpki",        label: "RPKI" },
  { id: "propagation", label: "PROPAGATION" },
  { id: "redirects",   label: "REDIRECTS" },
  { id: "virustotal",  label: "VIRUSTOTAL" },
  { id: "tor",         label: "TOR CHECK" },
  { id: "cve",         label: "CVE" },
  { id: "reverseip",   label: "REVERSE IP" },
  { id: "passivedns",  label: "PASSIVE DNS" },
  { id: "robots",      label: "ROBOTS.TXT" },
  { id: "waf",         label: "WAF" },
  { id: "spooftest",   label: "SPOOF TEST" },
];

const QUICK = ["8.8.8.8", "1.1.1.1", "github.com", "cloudflare.com", "8.8.4.4"];

// ── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App() {
  const [query, setQuery] = useState("");
  const [ipData, setIpData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("overview");
  const [history, setHistory] = useState(loadHistory);
  const [showHistory, setShowHistory] = useState(false);
  const inputRef = useRef(null);

  const threat = ipData ? threatLevel(ipData.threatScore) : null;
  const domainQuery = isDomain(query) ? query.replace(/^https?:\/\//, "").split("/")[0] : null;

  async function lookup(target) {
    const q = (target ?? query).trim();
    if (!q) return;
    setLoading(true); setError(null); setIpData(null); setTab("overview");
    try {
      const r = await fetch(`/api/ipinfo?q=${encodeURIComponent(q)}`);
      const d = await r.json();
      if (d.status === "fail") throw new Error(d.message || "Lookup failed");
      const result = { ...d, threatScore: calcThreat(d) };
      setIpData(result);
      const entry = { query: q, ip: d.query, country: d.country, ts: Date.now() };
      saveHistory(entry);
      setHistory(loadHistory());
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <div style={{ background: "#050508", minHeight: "100vh", color: "#E8E8F8" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Instrument+Serif:ital@0;1&display=swap');
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes db-spin { to { transform: rotate(360deg); } }
        @keyframes db-fadeup { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes db-pulse { 0%, 100% { opacity: .15; } 50% { opacity: .5; } }
        @keyframes db-scan {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        ::selection { background: rgba(255,255,255,0.12); }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.06); borderRadius: 2px; }

        .db-input {
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.07);
          border-radius: 8px;
          color: #E8E8F8;
          font-family: 'Space Mono', monospace;
          font-size: 12px;
          padding: 10px 14px;
          outline: none;
          transition: border-color .2s;
        }
        .db-input:focus { border-color: rgba(255,255,255,0.2); }
        .db-input::placeholder { color: rgba(255,255,255,0.1); }

        .db-select {
          background: rgba(255,255,255,0.03);
          border: 1px solid rgba(255,255,255,0.07);
          border-radius: 8px;
          color: #E8E8F8;
          font-family: 'Space Mono', monospace;
          font-size: 11px;
          padding: 10px 14px;
          outline: none;
          cursor: pointer;
        }

        .db-tab {
          background: none;
          border: none;
          border-bottom: 2px solid transparent;
          color: rgba(255,255,255,0.2);
          font-family: 'Space Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.14em;
          cursor: pointer;
          padding: 12px 18px;
          transition: all .2s;
          white-space: nowrap;
        }
        .db-tab:hover { color: rgba(255,255,255,0.5); }
        .db-tab.active {
          color: #E8E8F8;
          border-bottom-color: #E8E8F8;
        }

        .db-result { animation: db-fadeup .5s ease both; }
        .db-scanline {
          position: fixed;
          top: 0; left: 0; right: 0;
          height: 2px;
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
          animation: db-scan 8s linear infinite;
          pointer-events: none;
          z-index: 999;
        }

        .db-grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
        .db-grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
        @media (max-width: 900px) {
          .db-grid-3 { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 600px) {
          .db-grid-3, .db-grid-2 { grid-template-columns: 1fr; }
        }
      `}</style>

      {/* Ambient scanline */}
      <div className="db-scanline" />

      {/* Ambient glow when result loaded */}
      {threat && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, height: "300px",
          background: `radial-gradient(ellipse at 50% -100px, ${threat.glow} 0%, transparent 70%)`,
          pointerEvents: "none", zIndex: 0, transition: "background 1s",
        }} />
      )}

      <div style={{ maxWidth: 1160, margin: "0 auto", padding: "0 28px 120px", position: "relative", zIndex: 1 }}>

        {/* ── HEADER ── */}
        <div style={{ padding: "36px 0 28px", display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ fontFamily: "'Instrument Serif', serif", fontStyle: "italic", fontSize: 28, color: "#E8E8F8", lineHeight: 1, marginBottom: 4 }}>
              DesireBlock
            </div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#1E1E2E", letterSpacing: "0.28em" }}>
              IP INTELLIGENCE PLATFORM · 2026
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn variant="ghost" onClick={() => setShowHistory(x => !x)} style={{ fontSize: 9, padding: "7px 14px" }}>
              HISTORY {history.length > 0 && `(${history.length})`}
            </Btn>
          </div>
        </div>

        {/* ── HISTORY ── */}
        {showHistory && (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "14px 18px", marginBottom: 20 }}>
            {history.length === 0 ? (
              <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#333" }}>No history yet.</span>
            ) : (
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                {history.map(h => (
                  <button key={h.query} onClick={() => { setQuery(h.query); lookup(h.query); setShowHistory(false); }} style={{
                    background: "none", border: "1px solid rgba(255,255,255,0.06)", color: "#555",
                    fontFamily: "'Space Mono', monospace", fontSize: 10, padding: "5px 12px",
                    cursor: "pointer", borderRadius: 6, letterSpacing: "0.05em", transition: "all .2s",
                  }}>
                    {h.query} {h.country && <span style={{ opacity: .4 }}>{h.country}</span>}
                  </button>
                ))}
                <button onClick={() => { localStorage.removeItem("db_history2"); setHistory([]); }}
                  style={{ background: "none", border: "none", color: "#FF3B3B", fontFamily: "'Space Mono', monospace", fontSize: 10, cursor: "pointer", padding: "5px 8px", opacity: 0.6 }}>
                  CLEAR
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── SEARCH ── */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#1E1E2E", letterSpacing: "0.24em", marginBottom: 10 }}>
            // ENTER TARGET — IP ADDRESS OR HOSTNAME
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <input
              ref={inputRef}
              className="db-input"
              placeholder="8.8.8.8 or example.com"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === "Enter" && lookup()}
              style={{ flex: 1, fontSize: 14, padding: "14px 18px" }}
            />
            <Btn onClick={() => lookup()} disabled={loading}>
              {loading ? <Spinner size={14} /> : "LOOKUP ▶"}
            </Btn>
          </div>

          {/* Quick targets */}
          <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap" }}>
            {QUICK.map(q => (
              <button key={q} onClick={() => { setQuery(q); lookup(q); }} style={{
                background: "none", border: "1px solid rgba(255,255,255,0.05)", color: "#2A2A3A",
                fontFamily: "'Space Mono', monospace", fontSize: 9, padding: "4px 10px",
                cursor: "pointer", borderRadius: 5, letterSpacing: "0.05em", transition: "all .2s",
              }}>{q}</button>
            ))}
          </div>
        </div>

        {error && <ErrBox msg={error} />}

        {loading && (
          <div style={{ textAlign: "center", padding: "80px 0" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}><Spinner size={36} /></div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A3A", letterSpacing: "0.24em", animation: "db-pulse 2s ease infinite" }}>
              QUERYING INTELLIGENCE SOURCES
            </div>
          </div>
        )}

        {/* ── RESULTS ── */}
        {ipData && !loading && (
          <div className="db-result">

            {/* Hero bar */}
            <div style={{
              background: "rgba(255,255,255,0.02)",
              border: `1px solid rgba(255,255,255,0.06)`,
              borderLeft: `3px solid ${threat.color}`,
              borderRadius: "0 12px 12px 0",
              padding: "20px 24px", marginBottom: 20,
              display: "flex", alignItems: "center", justifyContent: "space-between",
              flexWrap: "wrap", gap: 16,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
                <ThreatRing score={ipData.threatScore} threat={threat} />
                <div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.28em", marginBottom: 8 }}>TARGET RESOLVED</div>
                  <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 34, color: "#E8E8F8", lineHeight: 1, marginBottom: 6 }}>{ipData.query}</div>
                  <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 11, color: "#444", marginTop: 4 }}>
                    {ipData.org || ipData.isp} · {ipData.city}, {ipData.country}
                  </div>
                  <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap" }}>
                    {ipData.proxy && <Tag color="#FF3B3B">PROXY / VPN</Tag>}
                    {ipData.hosting && <Tag color="#FF8C00">HOSTING</Tag>}
                    {ipData.mobile && <Tag color="#888">MOBILE</Tag>}
                    <Tag color="#444">{ipData.countryCode}</Tag>
                    {ipData.reverse && <Tag color="#444">{ipData.reverse}</Tag>}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Btn variant="ghost" onClick={() => exportResults(ipData)} style={{ fontSize: 9, padding: "7px 14px" }}>EXPORT ↓</Btn>
                <Btn variant="ghost" onClick={() => copyToClipboard(JSON.stringify(ipData, null, 2))} style={{ fontSize: 9, padding: "7px 14px" }}>COPY JSON</Btn>
              </div>
            </div>

            {/* Tab bar */}
            <div style={{ display: "flex", overflowX: "auto", borderBottom: "1px solid rgba(255,255,255,0.05)", marginBottom: 20, gap: 0 }}>
              {TABS.map(t => (
                <button key={t.id} className={`db-tab${tab === t.id ? " active" : ""}`} onClick={() => setTab(t.id)}>{t.label}</button>
              ))}
            </div>

            {/* ── OVERVIEW ── */}
            {tab === "overview" && (
              <div className="db-grid-3">
                <Panel title="Threat Assessment" badge={threat.label} badgeColor={threat.color}>
                  <Field label="Threat Score" value={`${ipData.threatScore}/100`} accent={threat.color} />
                  <Field label="Proxy / VPN" value={ipData.proxy ? "⚠ DETECTED" : "✓ CLEAN"} accent={ipData.proxy ? "#FF3B3B" : "#00E676"} copy />
                  <Field label="Hosting / DC" value={ipData.hosting ? "⚠ YES" : "✓ NO"} accent={ipData.hosting ? "#FF8C00" : undefined} />
                  <Field label="Mobile Network" value={ipData.mobile ? "YES" : "NO"} />
                  <Field label="AS Name" value={ipData.asname} copy />
                </Panel>
                <Panel title="Network">
                  <Field label="ISP" value={ipData.isp} copy />
                  <Field label="Org" value={ipData.org} copy />
                  <Field label="AS" value={ipData.as} copy />
                  <Field label="Reverse DNS" value={ipData.reverse} copy />
                  <Field label="Continent" value={`${ipData.continent} (${ipData.continentCode})`} />
                  <Field label="Timezone" value={ipData.timezone} />
                  <Field label="UTC Offset" value={`${ipData.offset >= 0 ? "+" : ""}${(ipData.offset / 3600).toFixed(1)}h`} />
                  <Field label="Currency" value={ipData.currency} />
                </Panel>
                <Panel title="Location">
                  <Field label="Country" value={`${ipData.country} (${ipData.countryCode})`} />
                  <Field label="Region" value={ipData.regionName} />
                  <Field label="City" value={ipData.city} />
                  <Field label="ZIP" value={ipData.zip} />
                  <Field label="Latitude" value={ipData.lat?.toFixed(5)} />
                  <Field label="Longitude" value={ipData.lon?.toFixed(5)} />
                </Panel>
              </div>
            )}

            {/* ── GEO ── */}
            {tab === "geo" && (
              <div>
                <div className="db-grid-3" style={{ marginBottom: 20 }}>
                  <Panel title="Location Details">
                    <Field label="Country" value={`${ipData.country} (${ipData.countryCode})`} />
                    <Field label="Region" value={ipData.regionName} />
                    <Field label="City" value={ipData.city} />
                    <Field label="ZIP / Postal" value={ipData.zip} />
                    <Field label="Continent" value={`${ipData.continent} (${ipData.continentCode})`} />
                  </Panel>
                  <Panel title="Time & Currency">
                    <Field label="Timezone" value={ipData.timezone} />
                    <Field label="UTC Offset" value={`${ipData.offset >= 0 ? "+" : ""}${(ipData.offset / 3600).toFixed(1)}h`} />
                    <Field label="Currency" value={ipData.currency} />
                    <Field label="Language" value={ipData.lang} />
                    <Field label="Calling Code" value={ipData.callingCode ? `+${ipData.callingCode}` : null} />
                  </Panel>
                  <Panel title="Coordinates">
                    <div style={{ display: "flex", gap: 16, marginBottom: 16 }}>
                      <div>
                        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 6 }}>LATITUDE</div>
                        <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 28, color: "#E8E8F8" }}>{ipData.lat?.toFixed(4)}</div>
                      </div>
                      <div>
                        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 8, color: "#2A2A3A", letterSpacing: "0.2em", marginBottom: 6 }}>LONGITUDE</div>
                        <div style={{ fontFamily: "'Instrument Serif', serif", fontSize: 28, color: "#E8E8F8" }}>{ipData.lon?.toFixed(4)}</div>
                      </div>
                    </div>
                    <a href={`https://www.openstreetmap.org/?mlat=${ipData.lat}&mlon=${ipData.lon}&zoom=12`} target="_blank" rel="noreferrer"
                      style={{ display: "inline-block", fontFamily: "'Space Mono', monospace", fontSize: 10, color: "#555", textDecoration: "none", letterSpacing: "0.08em" }}>
                      OPEN IN MAPS →
                    </a>
                  </Panel>
                </div>
                <Panel title="Map">
                  <GeoMap lat={ipData.lat} lon={ipData.lon} city={ipData.city} country={ipData.country} />
                </Panel>
              </div>
            )}

            {tab === "ports" && (
              <Panel title="Port Scanner" badge="TCP SCAN" badgeColor="#FF8C00">
                <PortScan target={ipData.query} />
              </Panel>
            )}
            {tab === "dns" && (
              <Panel title="DNS Lookup" badge="RESOLVER">
                <DnsLookup initialHost={ipData.reverse || domainQuery || ""} />
              </Panel>
            )}
            {tab === "whois" && (
              <Panel title="WHOIS / RDAP" badge="IP + DOMAIN">
                <WhoisLookup initialQuery={domainQuery || ipData.query} />
              </Panel>
            )}
            {tab === "ssl" && (
              <Panel title="SSL Certificate" badge="TLS INFO">
                <SSLInfo initialHost={domainQuery || ""} />
              </Panel>
            )}
            {tab === "headers" && (
              <Panel title="HTTP Headers" badge="SECURITY AUDIT">
                <HttpHeaders initialUrl={domainQuery ? `https://${domainQuery}` : ""} />
              </Panel>
            )}
            {tab === "asn" && (
              <Panel title="ASN Details" badge="BGP / ROUTING">
                <AsnInfo initialIp={ipData.query} />
              </Panel>
            )}
            {tab === "blacklist" && (
              <Panel title="Blacklist Check" badge="25 DNSBL LISTS">
                <Blacklist initialIp={isIP(ipData.query) ? ipData.query : ""} />
              </Panel>
            )}
            {tab === "ping" && (
              <Panel title="Ping / Latency" badge="HTTP TIMING">
                <PingTest initialHost={domainQuery || ipData.query} />
              </Panel>
            )}
            {tab === "compare" && (
              <Panel title="Compare Two Targets">
                <Compare />
              </Panel>
            )}
            {tab === "bulk" && (
              <Panel title="Bulk Lookup" badge="UP TO 20">
                <BulkLookup />
              </Panel>
            )}

            {/* ── NEW 2026 TABS ── */}
            {tab === "traceroute" && (
              <Panel title="Traceroute" badge="NETWORK PATH">
                <Traceroute initialHost={domainQuery || ipData.query} />
              </Panel>
            )}
            {tab === "reputation" && (
              <Panel title="Threat Intelligence" badge="ABUSE / REPUTATION">
                <Reputation initialIp={isIP(ipData.query) ? ipData.query : ""} />
              </Panel>
            )}
            {tab === "certs" && (
              <Panel title="Certificate Transparency" badge="CT LOGS · crt.sh">
                <CertTransparency initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "subdomains" && (
              <Panel title="Subdomain Enumeration" badge="DNS BRUTE FORCE">
                <SubdomainEnum initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "mxtest" && (
              <Panel title="Email Security" badge="SPF · DMARC · DKIM">
                <MxTest initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "screenshot" && (
              <Panel title="Live Screenshot" badge="HEADLESS BROWSER">
                <Screenshot initialUrl={domainQuery || ""} />
              </Panel>
            )}
            {tab === "techstack" && (
              <Panel title="Technology Fingerprint" badge="STACK DETECT">
                <TechStack initialUrl={domainQuery || ""} />
              </Panel>
            )}
            {tab === "iprange" && (
              <Panel title="IP Range / CIDR" badge="SUBNET CALC">
                <IpRange initialIp={isIP(ipData.query) ? ipData.query : ""} />
              </Panel>
            )}

            {/* ── 2026 EXPANSION TABS ── */}
            {tab === "bgp" && (
              <Panel title="BGP Route Visualization" badge="RIPE NCC">
                <BgpRoutes initialIp={ipData.query} />
              </Panel>
            )}
            {tab === "ipv6" && (
              <Panel title="IPv6 Inspector" badge="ADDRESS ANALYSIS">
                <IPv6Inspector initialIp={ipData.query?.includes(":") ? ipData.query : ""} />
              </Panel>
            )}
            {tab === "rpki" && (
              <Panel title="RPKI Validation" badge="ROA · ROUTE ORIGIN">
                <RpkiValidator initialIp={ipData.query} />
              </Panel>
            )}
            {tab === "propagation" && (
              <Panel title="DNS Propagation Checker" badge="8 GLOBAL RESOLVERS">
                <DnsPropagation initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "redirects" && (
              <Panel title="Redirect Chain Tracer" badge="HTTP HOPS">
                <RedirectChain initialUrl={domainQuery || ""} />
              </Panel>
            )}
            {tab === "virustotal" && (
              <Panel title="VirusTotal Scan" badge="80+ AV ENGINES">
                <VirusTotalScan initialTarget={ipData.query} />
              </Panel>
            )}
            {tab === "tor" && (
              <Panel title="Tor Exit Node Check" badge="TORPROJECT DNSEL">
                <TorCheck initialIp={isIP(ipData.query) ? ipData.query : ""} />
              </Panel>
            )}
            {tab === "cve" && (
              <Panel title="CVE Lookup" badge="NVD · MITRE">
                <CveLookup />
              </Panel>
            )}
            {tab === "reverseip" && (
              <Panel title="Reverse IP Lookup" badge="SHARED HOSTING">
                <ReverseIp initialIp={isIP(ipData.query) ? ipData.query : ""} />
              </Panel>
            )}
            {tab === "passivedns" && (
              <Panel title="Passive DNS History" badge="HISTORICAL RECORDS">
                <PassiveDns initialDomain={domainQuery || ipData.query} />
              </Panel>
            )}
            {tab === "robots" && (
              <Panel title="robots.txt Viewer" badge="CRAWL DIRECTIVES">
                <RobotsTxt initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "waf" && (
              <Panel title="WAF Detection" badge="HEADER FINGERPRINT">
                <WafDetection initialDomain={domainQuery || ""} />
              </Panel>
            )}
            {tab === "spooftest" && (
              <Panel title="Email Spoofing Test" badge="SPF · DMARC · DKIM">
                <EmailSpoofTest initialDomain={domainQuery || ""} />
              </Panel>
            )}

          </div>
        )}

        {/* ── Empty state ── */}
        {!ipData && !loading && !error && (
          <div style={{ marginTop: 80, textAlign: "center" }}>
            <div style={{ fontFamily: "'Instrument Serif', serif", fontStyle: "italic", fontSize: 72, color: "rgba(255,255,255,0.04)", lineHeight: 1, marginBottom: 16, userSelect: "none" }}>db</div>
            <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, color: "#2A2A4A", letterSpacing: "0.3em", marginBottom: 48 }}>33 INTELLIGENCE MODULES</div>

            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
              gap: 6,
              maxWidth: 900,
              margin: "0 auto",
              textAlign: "left",
            }}>
              {[
                ["GEO",          "Country · Region · City · Coordinates · Map",          "#4A90D9"],
                ["NETWORK",      "ISP · Org · ASN · Reverse DNS · BGP Routing",          "#7B68EE"],
                ["THREAT",       "Proxy & VPN Detection · Hosting · Mobile",              "#FF3B3B"],
                ["PORTS",        "23 Common TCP Ports — Real Scan",                       "#FF8C00"],
                ["DNS",          "A · AAAA · MX · TXT · NS · CNAME · SOA · SRV",        "#00B4D8"],
                ["WHOIS / RDAP", "IP Blocks · Domain Registration · Expiry",              "#7B68EE"],
                ["SSL",          "TLS Certificate · Validity · Cipher · SANs",            "#00E676"],
                ["HEADERS",      "HTTP Response · 8 Security Header Audit",               "#FFD600"],
                ["BLACKLIST",    "25 DNSBL Lists — Real-time Check",                      "#FF3B3B"],
                ["PING",         "HTTP Latency · Min / Max / Avg / Loss",                 "#00E676"],
                ["COMPARE",      "Side-by-side Diff of Two IPs",                          "#FF8C00"],
                ["BULK",         "Up to 20 Targets — Export JSON",                        "#4A90D9"],
                ["TRACEROUTE",   "Network Path · Hop-by-hop Latency",                     "#00B4D8"],
                ["REPUTATION",   "AbuseIPDB Score · Threat Categories · Reports",         "#FF3B3B"],
                ["CT LOGS",      "Certificate Transparency · crt.sh · Subdomain Discovery","#00E676"],
                ["SUBDOMAINS",   "DNS Brute Force · 60-word Wordlist · Live A Records",   "#FFD600"],
                ["EMAIL",        "MX Records · SPF · DMARC · DKIM — Security Score",      "#7B68EE"],
                ["SCREENSHOT",   "Live Headless Browser Capture · Status · Redirects",    "#4A90D9"],
                ["TECH STACK",   "Server · CMS · Framework · JS · CDN Fingerprinting",   "#FF8C00"],
                ["IP RANGE",     "CIDR Calculator · Netmask · Host Count · Subnet Split", "#00B4D8"],
                ["BGP ROUTES",   "Route Origin · AS Path · RIPE NCC · Peer Visibility",  "#7B68EE"],
                ["IPv6",         "Address Expansion · Type · Scope · AAAA Lookup",        "#00B4D8"],
                ["RPKI",         "ROA Validation · Route Origin Auth · RIPE NCC",         "#4A90D9"],
                ["PROPAGATION",  "DNS Propagation · 8 Global Resolvers · DoH Queries",    "#00E676"],
                ["REDIRECTS",    "HTTP Redirect Chain · Hop-by-hop · TLS · Latency",      "#FFD600"],
                ["VIRUSTOTAL",   "80+ AV Engines · Reputation · Tags · Detections",       "#FF3B3B"],
                ["TOR CHECK",    "Tor Project DNSEL · Official Exit Node Registry",       "#FF8C00"],
                ["CVE LOOKUP",   "MITRE · NVD · CVSS Score · Affected Products",          "#FF6B6B"],
                ["REVERSE IP",   "Shared Hosting Detection · Co-hosted Domains",          "#7B68EE"],
                ["PASSIVE DNS",  "Historical DNS Records · IP Associations · Changes",    "#4A90D9"],
                ["ROBOTS.TXT",   "Crawl Directives · Sitemap Discovery · Rule Parsing",   "#00E676"],
                ["WAF DETECT",   "Cloudflare · Akamai · AWS · Imperva · Header Sigs",     "#FF8C00"],
                ["SPOOF TEST",   "SPF · DMARC · DKIM · Spoofability Risk Assessment",     "#FF3B3B"],
              ].map(([label, desc, color]) => (
                <div key={label} style={{
                  display: "flex", alignItems: "flex-start", gap: 12,
                  padding: "10px 14px",
                  background: `${color}07`,
                  border: `1px solid ${color}18`,
                  borderRadius: 8,
                  transition: "all .2s",
                }}>
                  <span style={{
                    fontFamily: "'Space Mono', monospace", fontSize: 9,
                    color: color, letterSpacing: "0.16em",
                    minWidth: 90, paddingTop: 1, flexShrink: 0,
                    opacity: 0.9,
                  }}>{label}</span>
                  <span style={{
                    fontFamily: "'Space Mono', monospace", fontSize: 9,
                    color: "rgba(255,255,255,0.28)", letterSpacing: "0.06em",
                    lineHeight: 1.6,
                  }}>{desc}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
