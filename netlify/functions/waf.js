// netlify/functions/waf.js
// WAF detection by analyzing HTTP response headers and body patterns

const WAF_SIGNATURES = [
  { name: "Cloudflare",    headers: ["cf-ray", "cf-cache-status", "__cfduid"], server: /cloudflare/i,    cookie: /^__cf/ },
  { name: "Akamai",        headers: ["x-akamai-request-id", "akamai-grn"],    server: /akamai/i,         cookie: /^ak_/ },
  { name: "AWS WAF",       headers: ["x-amzn-requestid", "x-amz-cf-id"],      server: /awselb|amazon/i,  cookie: null },
  { name: "Imperva/Incapsula", headers: ["x-iinfo", "x-cdn"],                 server: /imperva|incapsula/i, cookie: /^visid_incap|incap_ses/ },
  { name: "Sucuri",        headers: ["x-sucuri-id", "x-sucuri-cache"],        server: /sucuri/i,         cookie: null },
  { name: "F5 BIG-IP",     headers: ["x-wa-info", "x-cnection"],              server: /big-?ip/i,        cookie: /^BIGipServer/ },
  { name: "Fastly",        headers: ["x-fastly-request-id", "fastly-restarts"], server: /fastly/i,       cookie: null },
  { name: "Varnish",       headers: ["x-varnish", "x-hits"],                  server: /varnish/i,        cookie: null },
  { name: "Nginx",         headers: [],                                        server: /nginx/i,          cookie: null },
  { name: "Apache",        headers: [],                                        server: /apache/i,         cookie: null },
];

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const domain = (event.queryStringParameters?.domain || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  if (!domain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain" }) };

  const url = `https://${domain}`;

  try {
    const res = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
      headers: {
        // Slightly suspicious UA to try to trigger WAF responses
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
      },
    });

    const responseHeaders = {};
    res.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

    const serverHeader = responseHeaders["server"] || "";
    const setCookie = responseHeaders["set-cookie"] || "";

    const detected = [];

    for (const sig of WAF_SIGNATURES) {
      const headerMatch = sig.headers.some(h => responseHeaders[h] !== undefined);
      const serverMatch = sig.server && sig.server.test(serverHeader);
      const cookieMatch = sig.cookie && sig.cookie.test(setCookie);

      if (headerMatch || serverMatch || cookieMatch) {
        detected.push({
          name: sig.name,
          confidence: headerMatch && serverMatch ? "HIGH" : headerMatch || serverMatch ? "MEDIUM" : "LOW",
          signals: [
            headerMatch && "header",
            serverMatch && "server",
            cookieMatch && "cookie",
          ].filter(Boolean),
        });
      }
    }

    // Collect interesting security-related headers
    const relevantHeaders = {};
    const interesting = ["server", "x-powered-by", "via", "x-cache", "x-cdn", "cf-ray",
      "x-akamai-request-id", "x-fastly-request-id", "x-varnish", "x-sucuri-id", "x-iinfo"];
    for (const h of interesting) {
      if (responseHeaders[h]) relevantHeaders[h] = responseHeaders[h];
    }

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        domain,
        detected,
        primaryWaf: detected[0]?.name || null,
        status: res.status,
        relevantHeaders,
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
