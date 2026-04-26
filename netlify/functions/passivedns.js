// netlify/functions/passivedns.js
// Passive DNS history via RIPE NCC stat API (free, no key)
// Also uses HackerTarget as fallback

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const domain = (event.queryStringParameters?.domain || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  if (!domain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain" }) };

  try {
    // RIPE NCC passive DNS (works for IPs and some domains)
    const ripeRes = await fetch(
      `https://stat.ripe.net/data/passive-dns/data.json?resource=${encodeURIComponent(domain)}&limit=50`,
      { signal: AbortSignal.timeout(10000) }
    );
    const ripeData = await ripeRes.json();

    if (ripeData.status === "ok" && ripeData.data?.records?.length) {
      const records = ripeData.data.records.map(r => ({
        rrname: r.rrname?.replace(/\.$/, ""),
        rrtype: r.rrtype,
        rdata: Array.isArray(r.rdata) ? r.rdata.map(d => d.replace(/\.$/, "")).join(", ") : r.rdata,
        firstSeen: r.time_first,
        lastSeen: r.time_last,
        count: r.count,
      }));

      return {
        statusCode: 200, headers,
        body: JSON.stringify({ domain, records, total: records.length, source: "RIPE NCC" }),
      };
    }

    // Fallback: HackerTarget DNS lookup history
    const htRes = await fetch(
      `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      { signal: AbortSignal.timeout(10000) }
    );
    const htText = await htRes.text();

    if (htText.includes("API count")) throw new Error("Rate limit reached on both sources");

    const records = htText.split("\n")
      .filter(Boolean)
      .map(line => {
        const [hostname, ip] = line.split(",");
        return { rrname: hostname?.trim(), rrtype: "A", rdata: ip?.trim(), firstSeen: null, lastSeen: null, count: null };
      })
      .filter(r => r.rrname && r.rdata);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ domain, records, total: records.length, source: "HackerTarget" }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
