// netlify/functions/headers.js
// Fetches HTTP response headers from a URL and audits security headers

export const handler = async (event) => {
  const hdrs = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  let url = (event.queryStringParameters?.url || "").trim();
  if (!url) return { statusCode: 400, headers: hdrs, body: JSON.stringify({ error: "Missing url" }) };
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "follow",
      signal: AbortSignal.timeout(10000),
    });

    const responseHeaders = {};
    res.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    return {
      statusCode: 200, headers: hdrs,
      body: JSON.stringify({
        url,
        status: res.status,
        statusText: res.statusText,
        redirected: res.redirected,
        headers: responseHeaders,
      }),
    };
  } catch (err) {
    // HEAD failed, try GET with no body read
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(10000),
      });
      const responseHeaders = {};
      res.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });
      return {
        statusCode: 200, headers: hdrs,
        body: JSON.stringify({
          url, status: res.status, statusText: res.statusText,
          redirected: res.redirected, headers: responseHeaders,
        }),
      };
    } catch (err2) {
      return { statusCode: 500, headers: hdrs, body: JSON.stringify({ error: err2.message }) };
    }
  }
};
