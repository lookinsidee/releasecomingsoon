// netlify/functions/ping.js
// Measures HTTP latency to a host (true ICMP ping isn't available in serverless)
// Makes 5 sequential HTTP HEAD requests and reports min/avg/max/loss

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const host = (event.queryStringParameters?.host || "").trim();
  if (!host) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing host" }) };

  let url = host;
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  // For raw IPs without a domain, use http
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) url = "http://" + host;

  const COUNT = 5;
  const pings = [];

  for (let i = 0; i < COUNT; i++) {
    const start = Date.now();
    try {
      await fetch(url, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
        cache: "no-store",
      });
      pings.push(Date.now() - start);
    } catch {
      pings.push(null);
    }
    // Small gap between pings
    if (i < COUNT - 1) await new Promise(r => setTimeout(r, 200));
  }

  const valid = pings.filter(p => p !== null);
  const loss = Math.round(((COUNT - valid.length) / COUNT) * 100);

  return {
    statusCode: 200, headers,
    body: JSON.stringify({
      host,
      pings,
      min: valid.length ? Math.min(...valid) : null,
      max: valid.length ? Math.max(...valid) : null,
      avg: valid.length ? Math.round(valid.reduce((a, b) => a + b, 0) / valid.length) : null,
      loss,
      count: COUNT,
    }),
  };
};
