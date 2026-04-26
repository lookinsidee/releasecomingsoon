// netlify/functions/redirects.js
// Traces HTTP redirect chains hop by hop

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  let url = (event.queryStringParameters?.url || "").trim();
  if (!url) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing url" }) };
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  const hops = [];
  let current = url;
  const MAX_HOPS = 15;

  try {
    for (let i = 0; i < MAX_HOPS; i++) {
      const start = Date.now();
      const res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
      });
      const rtt = Date.now() - start;
      const location = res.headers.get("location");
      const isTls = current.startsWith("https://");

      hops.push({
        hop: i + 1,
        url: current,
        status: res.status,
        statusText: res.statusText,
        location: location || null,
        rtt,
        tls: isTls,
      });

      if (res.status < 300 || res.status >= 400 || !location) break;

      // Handle relative redirects
      if (location.startsWith("http://") || location.startsWith("https://")) {
        current = location;
      } else if (location.startsWith("/")) {
        const parsed = new URL(current);
        current = parsed.origin + location;
      } else {
        current = new URL(location, current).href;
      }
    }

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ url, hops, finalUrl: hops[hops.length - 1]?.url }),
    };
  } catch (err) {
    return {
      statusCode: 200, headers,
      body: JSON.stringify({ url, hops, finalUrl: hops[hops.length - 1]?.url || url, error: err.message }),
    };
  }
};
