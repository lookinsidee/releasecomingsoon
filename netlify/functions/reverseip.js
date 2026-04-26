// netlify/functions/reverseip.js
// Reverse IP lookup — finds domains hosted on the same IP via HackerTarget

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IP" }) };

  try {
    const res = await fetch(
      `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(15000) }
    );
    const text = await res.text();

    if (text.includes("API count") || text.includes("error")) {
      throw new Error(text.includes("API count") ? "HackerTarget rate limit reached" : text.trim());
    }

    const domains = text.split("\n").map(d => d.trim()).filter(Boolean);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ip, domains, total: domains.length }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
