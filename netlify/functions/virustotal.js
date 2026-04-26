// netlify/functions/virustotal.js
// VirusTotal scan via their free public API (1000 lookups/day)
// IMPORTANT: Add VIRUSTOTAL_KEY to your Netlify environment variables
// Get a free API key at: https://www.virustotal.com/gui/join-us

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const target = (event.queryStringParameters?.target || "").trim();
  if (!target) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing target" }) };

  const apiKey = process.env.VIRUSTOTAL_KEY;
  if (!apiKey) {
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        notice: "VirusTotal API key not configured. Add VIRUSTOTAL_KEY to your Netlify environment variables. Get a free key at virustotal.com",
        target,
      }),
    };
  }

  try {
    // Determine if it's an IP, domain, or URL
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    const isDomain = /^[a-zA-Z]/.test(target) && target.includes(".") && !target.includes("/");

    let endpoint;
    if (isIP) endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`;
    else if (isDomain) endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(target)}`;
    else {
      // URL — must be base64url encoded
      const encoded = btoa(target).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      endpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
    }

    const res = await fetch(endpoint, { headers: { "x-apikey": apiKey } });
    if (!res.ok) throw new Error(`VirusTotal API error: ${res.status}`);
    const json = await res.json();
    const stats = json.data?.attributes?.last_analysis_stats || {};
    const results = json.data?.attributes?.last_analysis_results || {};

    const detections = Object.entries(results)
      .filter(([, v]) => v.result !== "clean" && v.result !== "unrated" && v.result)
      .map(([engine, v]) => ({ engine, result: v.result, category: v.category }));

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        target,
        type: isIP ? "ip" : isDomain ? "domain" : "url",
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        totalEngines: Object.keys(results).length,
        reputation: json.data?.attributes?.reputation || 0,
        tags: json.data?.attributes?.tags || [],
        categories: json.data?.attributes?.categories || {},
        detections: detections.slice(0, 20),
        lastAnalysisDate: json.data?.attributes?.last_analysis_date
          ? new Date(json.data.attributes.last_analysis_date * 1000).toISOString()
          : null,
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
