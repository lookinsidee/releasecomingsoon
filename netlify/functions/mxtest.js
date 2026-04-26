// netlify/functions/mxtest.js
// Email security check: MX records, SPF, DMARC, DKIM via Cloudflare DoH

async function dnsQuery(name, type) {
  const typeMap = { A: 1, MX: 15, TXT: 16, NS: 2, CNAME: 5 };
  const typeNum = typeMap[type] || 1;
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { Accept: "application/dns-json" } }
  );
  const data = await res.json();
  return (data.Answer || []).filter(r => r.type === typeNum).map(r => r.data.replace(/^"|"$/g, ""));
}

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const domain = (event.queryStringParameters?.domain || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  if (!domain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain" }) };

  try {
    const [mx, spfRecords, dmarcRecords, dkimRecords] = await Promise.all([
      dnsQuery(domain, "MX"),
      dnsQuery(domain, "TXT"),
      dnsQuery(`_dmarc.${domain}`, "TXT"),
      dnsQuery(`default._domainkey.${domain}`, "TXT"),
    ]);

    const spf = spfRecords.find(r => r.includes("v=spf1")) || null;
    const dmarc = dmarcRecords.find(r => r.includes("v=DMARC1")) || null;
    const dkim = dkimRecords.find(r => r.includes("v=DKIM1")) || null;

    // Parse SPF policy
    let spfPolicy = null;
    if (spf) {
      if (spf.includes("-all")) spfPolicy = "-all (HARD FAIL)";
      else if (spf.includes("~all")) spfPolicy = "~all (SOFT FAIL)";
      else if (spf.includes("?all")) spfPolicy = "?all (NEUTRAL)";
      else if (spf.includes("+all")) spfPolicy = "+all (PASS ALL — DANGEROUS)";
    }

    // Parse DMARC policy
    let dmarcPolicy = null;
    if (dmarc) {
      const match = dmarc.match(/p=([^;]+)/);
      dmarcPolicy = match ? match[1].toUpperCase() : "NONE";
    }

    // Parse MX records (format: "10 mail.example.com")
    const mxParsed = mx.map(r => {
      const parts = r.split(" ");
      return { priority: parseInt(parts[0]) || 10, exchange: parts.slice(1).join(" ").replace(/\.$/, "") };
    }).sort((a, b) => a.priority - b.priority);

    // Spoofability assessment
    const hasSpf = !!spf;
    const hasStrongSpf = spf?.includes("-all");
    const hasDmarc = !!dmarc;
    const hasStrongDmarc = dmarcPolicy === "REJECT" || dmarcPolicy === "QUARANTINE";
    const spoofable = !hasSpf || !hasDmarc || !hasStrongDmarc;
    const spoofRisk = !hasSpf && !hasDmarc ? "HIGH" : !hasStrongSpf || !hasStrongDmarc ? "MEDIUM" : "LOW";

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        domain,
        mx: mxParsed,
        spf,
        spfPolicy,
        dmarc,
        dmarcPolicy,
        dkim,
        spoofable,
        spoofRisk,
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
