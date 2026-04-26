// netlify/functions/robots.js
// Fetches and parses robots.txt from a domain

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const domain = (event.queryStringParameters?.domain || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  if (!domain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain" }) };

  // Try HTTPS first, fall back to HTTP
  const urls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];

  for (const url of urls) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(8000), redirect: "follow" });
      if (!res.ok) continue;

      const text = await res.text();
      if (!text.trim()) continue;

      // Parse robots.txt into structured rules
      const rules = [];
      let currentAgent = null;
      const sitemaps = [];

      for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;

        const [directive, ...rest] = line.split(":");
        const value = rest.join(":").trim();
        const key = directive.trim().toLowerCase();

        if (key === "user-agent") {
          currentAgent = value;
          if (!rules.find(r => r.agent === value)) {
            rules.push({ agent: value, allow: [], disallow: [] });
          }
        } else if (key === "disallow" && currentAgent) {
          const rule = rules.find(r => r.agent === currentAgent);
          if (rule && value) rule.disallow.push(value);
        } else if (key === "allow" && currentAgent) {
          const rule = rules.find(r => r.agent === currentAgent);
          if (rule && value) rule.allow.push(value);
        } else if (key === "sitemap") {
          sitemaps.push(value);
        }
      }

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          domain,
          url,
          raw: text.slice(0, 5000), // cap at 5KB
          rules,
          sitemaps,
          size: text.length,
        }),
      };
    } catch {}
  }

  return {
    statusCode: 200, headers,
    body: JSON.stringify({ domain, error: "robots.txt not found or unreachable", rules: [], sitemaps: [] }),
  };
};
