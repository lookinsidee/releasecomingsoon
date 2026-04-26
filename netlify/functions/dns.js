// netlify/functions/dns.js
// DNS lookup using Cloudflare's DNS-over-HTTPS (no API key needed)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const { host, type = "A" } = event.queryStringParameters || {};
  if (!host) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing host" }) };

  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    const data = await res.json();

    // Map Cloudflare DoH response to a simple records array
    const typeMap = { A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2, CNAME: 5, PTR: 12, SOA: 6, CAA: 257, SRV: 33 };
    const typeNum = typeMap[type.toUpperCase()] || 1;

    const records = (data.Answer || [])
      .filter(r => r.type === typeNum)
      .map(r => {
        const d = r.data;
        // MX: "10 mail.example.com" → object
        if (type === "MX") {
          const parts = d.split(" ");
          return { priority: parseInt(parts[0]), exchange: parts.slice(1).join(" ") };
        }
        // SOA: return as object
        if (type === "SOA") {
          const [mname, rname, serial, refresh, retry, expire, minimum] = d.split(" ");
          return { mname, rname, serial, refresh, retry, expire, minimum };
        }
        // SRV: "_service._proto TTL IN SRV priority weight port target"
        if (type === "SRV") {
          const parts = d.split(" ");
          return { priority: parts[0], weight: parts[1], port: parts[2], target: parts[3] };
        }
        // TXT: strip surrounding quotes
        if (type === "TXT") return d.replace(/^"|"$/g, "");
        return d;
      });

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ host, type: type.toUpperCase(), records }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
