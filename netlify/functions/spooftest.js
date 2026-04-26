// netlify/functions/spooftest.js
// Email spoofing test — checks SPF, DMARC, DKIM and assesses spoofability risk
// This is an alias/superset of mxtest with extra analysis

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
    // Query all relevant DNS records in parallel
    const [mx, spfRecords, dmarcRecords, dkimDefault, dkimSelector1, dkimSelector2, dkimGoogle] = await Promise.all([
      dnsQuery(domain, "MX"),
      dnsQuery(domain, "TXT"),
      dnsQuery(`_dmarc.${domain}`, "TXT"),
      dnsQuery(`default._domainkey.${domain}`, "TXT"),
      dnsQuery(`selector1._domainkey.${domain}`, "TXT"),
      dnsQuery(`selector2._domainkey.${domain}`, "TXT"),
      dnsQuery(`google._domainkey.${domain}`, "TXT"),
    ]);

    const spf = spfRecords.find(r => r.includes("v=spf1")) || null;
    const dmarc = dmarcRecords.find(r => r.includes("v=DMARC1")) || null;
    const dkim = dkimDefault.find(r => r.includes("v=DKIM1"))
      || dkimSelector1.find(r => r.includes("v=DKIM1"))
      || dkimSelector2.find(r => r.includes("v=DKIM1"))
      || dkimGoogle.find(r => r.includes("v=DKIM1"))
      || null;

    // Parse SPF
    let spfPolicy = null;
    if (spf) {
      if (spf.includes("-all")) spfPolicy = "HARDFAIL";
      else if (spf.includes("~all")) spfPolicy = "SOFTFAIL";
      else if (spf.includes("?all")) spfPolicy = "NEUTRAL";
      else if (spf.includes("+all")) spfPolicy = "PASS_ALL";
    }

    // Parse DMARC
    let dmarcPolicy = null, dmarcPct = null, dmarcRua = null;
    if (dmarc) {
      const pMatch = dmarc.match(/p=([^;]+)/);
      dmarcPolicy = pMatch ? pMatch[1].toUpperCase().trim() : "NONE";
      const pctMatch = dmarc.match(/pct=(\d+)/);
      dmarcPct = pctMatch ? parseInt(pctMatch[1]) : 100;
      const ruaMatch = dmarc.match(/rua=([^;]+)/);
      dmarcRua = ruaMatch ? ruaMatch[1].trim() : null;
    }

    const mxParsed = mx.map(r => {
      const parts = r.split(" ");
      return { priority: parseInt(parts[0]) || 10, exchange: parts.slice(1).join(" ").replace(/\.$/, "") };
    }).sort((a, b) => a.priority - b.priority);

    // Spoofability scoring
    const hasSpf = !!spf;
    const hasHardFailSpf = spfPolicy === "HARDFAIL";
    const hasDmarc = !!dmarc;
    const hasRejectDmarc = dmarcPolicy === "REJECT";
    const hasQuarantineDmarc = dmarcPolicy === "QUARANTINE";
    const hasDkim = !!dkim;

    let spoofRisk = "HIGH";
    if (hasSpf && hasDmarc && (hasRejectDmarc || hasQuarantineDmarc)) spoofRisk = "LOW";
    else if (hasSpf && hasDmarc) spoofRisk = "MEDIUM";
    else if (hasSpf || hasDmarc) spoofRisk = "MEDIUM";

    const spoofable = spoofRisk !== "LOW";

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        domain,
        mx: mxParsed,
        spf,
        spfPolicy,
        dmarc,
        dmarcPolicy,
        dmarcPct,
        dmarcRua,
        dkim,
        spoofable,
        spoofRisk,
        checks: {
          spfPresent: hasSpf,
          spfHardFail: hasHardFailSpf,
          dmarcPresent: hasDmarc,
          dmarcReject: hasRejectDmarc,
          dmarcQuarantine: hasQuarantineDmarc,
          dkimPresent: hasDkim,
        },
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
