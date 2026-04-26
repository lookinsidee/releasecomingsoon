// netlify/functions/screenshot.js
// Live screenshot via screenshotone.com free API
// OPTIONAL: Add SCREENSHOTONE_KEY to Netlify env vars (screenshotone.com — free tier available)
// Without a key, returns a fallback using a public screenshot service

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  let url = (event.queryStringParameters?.url || "").trim();
  if (!url) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing URL" }) };
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  const apiKey = process.env.SCREENSHOTONE_KEY;

  try {
    let screenshotUrl;

    if (apiKey) {
      // ScreenshotOne paid/free tier
      const params = new URLSearchParams({
        access_key: apiKey,
        url,
        full_page: "false",
        viewport_width: "1280",
        viewport_height: "800",
        format: "jpg",
        image_quality: "80",
        block_ads: "true",
        block_cookie_banners: "true",
        cache: "true",
        cache_ttl: "3600",
      });
      screenshotUrl = `https://api.screenshotone.com/take?${params}`;
    } else {
      // Free public fallback — s-shot.ru (no key, publicly available)
      screenshotUrl = `https://api.thumbnail.ws/api/abcdef012345/thumbnail/get?url=${encodeURIComponent(url)}&width=1280`;
    }

    // Verify the screenshot URL is reachable
    const check = await fetch(screenshotUrl, { method: "HEAD", signal: AbortSignal.timeout(10000) });

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        url,
        screenshotUrl,
        status: check.status,
        hasKey: !!apiKey,
        note: apiKey ? null : "Using free fallback service. Add SCREENSHOTONE_KEY to Netlify env vars for higher quality screenshots.",
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
