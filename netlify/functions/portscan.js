// netlify/functions/portscan.js
// Port scanning via HackerTarget's free API (no key needed, rate limited)
// Falls back to a simulated result set if API is unavailable

const COMMON_PORTS = [
  { port: 21,   service: "FTP" },
  { port: 22,   service: "SSH" },
  { port: 23,   service: "TELNET" },
  { port: 25,   service: "SMTP" },
  { port: 53,   service: "DNS" },
  { port: 80,   service: "HTTP" },
  { port: 110,  service: "POP3" },
  { port: 143,  service: "IMAP" },
  { port: 443,  service: "HTTPS" },
  { port: 445,  service: "SMB" },
  { port: 587,  service: "SMTP/TLS" },
  { port: 993,  service: "IMAPS" },
  { port: 995,  service: "POP3S" },
  { port: 1433, service: "MSSQL" },
  { port: 3306, service: "MySQL" },
  { port: 3389, service: "RDP" },
  { port: 5432, service: "PostgreSQL" },
  { port: 5900, service: "VNC" },
  { port: 6379, service: "Redis" },
  { port: 8080, service: "HTTP-ALT" },
  { port: 8443, service: "HTTPS-ALT" },
  { port: 27017, service: "MongoDB" },
];

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const host = (event.queryStringParameters?.host || "").trim();
  if (!host) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing host" }) };

  try {
    // HackerTarget free port scan API
    const res = await fetch(
      `https://api.hackertarget.com/nmap/?q=${encodeURIComponent(host)}`,
      { signal: AbortSignal.timeout(30000) }
    );
    const text = await res.text();

    if (text.includes("error") || text.includes("API count")) {
      throw new Error("Rate limited");
    }

    // Parse nmap output: "Host: X.X.X.X ()\nPORT     STATE  SERVICE\n22/tcp  open  ssh"
    const results = COMMON_PORTS.map(({ port, service }) => {
      const portStr = `${port}/tcp`;
      const isOpen = text.includes(`${portStr}  open`) || text.includes(`${portStr} open`);
      return { port, service, status: isOpen ? "open" : "closed" };
    });

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ host, results, source: "nmap via hackertarget" }),
    };
  } catch (err) {
    // Fallback: attempt HTTP connections to web ports to infer open/closed
    const webPorts = [80, 443, 8080, 8443];
    const results = await Promise.all(
      COMMON_PORTS.map(async ({ port, service }) => {
        if (!webPorts.includes(port)) return { port, service, status: "unknown" };
        const proto = port === 443 || port === 8443 ? "https" : "http";
        try {
          await fetch(`${proto}://${host}:${port}`, {
            method: "HEAD",
            signal: AbortSignal.timeout(3000),
          });
          return { port, service, status: "open" };
        } catch {
          return { port, service, status: "closed" };
        }
      })
    );

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ host, results, note: "Limited scan — HackerTarget rate limit reached. Upgrade to HackerTarget API key for full scans." }),
    };
  }
};
