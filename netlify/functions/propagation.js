// netlify/functions/propagation.js
// Checks DNS propagation across 8 global resolvers via DoH

const RESOLVERS = [
  { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", location: "Global" },
  { name: "Google", url: "https://dns.google/resolve", location: "Global" },
  { name: "Quad9", url: "https://dns.quad9.net/dns-query", location: "Global" },
  { name: "AdGuard", url: "https://dns.adguard.com/resolve", location: "Global" },
  { name: "NextDNS", url: "https://dns.nextdns.io/dns-query", location: "Global" },
  { name: "OpenDNS", url: "https://doh.opendns.com/dns-query", location: "US" },
  { name: "CleanBrowsing", url: "https://doh.cleanbrowsing.org/doh/family-filter/", location: "Global" },
  { name: "Cloudflare Family", url: "https://family.cloudflare-dns.com/dns-query", location: "Global" },
];

async function queryResolver(resolver, domain, type) {
  const start = Date.now();
  try {
    const res = await fetch(
      `${resolver.url}?name=${encodeURIComponent(domain)}&type=${type}`,
      { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) }
    );
    const data = await res.json();
    const rtt = Date.now() - start;
    const typeNum = { A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2 }[type] || 1;
    const records = (data.Answer || []).filter(r => r.type === typeNum).map(r => r.data.replace(/^"|"$/g, ""));
    return {
      resolver: resolver.name,
      location: resolver.location,
      records,
      rtt,
      status: records.length > 0 ? "propagated" : "not-propagated",
      error: null,
    };
  } catch (err) {
    return {
      resolver: resolver.name,
      location: resolver.location,
      records: [],
      rtt: Date.now() - start,
      status: "error",
      error: err.message,
    };
  }
}

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const domain = (event.queryStringParameters?.domain || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  const type = (event.queryStringParameters?.type || "A").toUpperCase();
  if (!domain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain" }) };

  try {
    const results = await Promise.all(RESOLVERS.map(r => queryResolver(r, domain, type)));
    const propagated = results.filter(r => r.status === "propagated").length;
    return {
      statusCode: 200, headers,
      body: JSON.stringify({ domain, type, results, propagated, total: RESOLVERS.length }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
