// netlify/functions/techstack.js
// Technology stack fingerprinting via header analysis + body pattern matching

const TECH_SIGNATURES = {
  // Servers
  "Nginx":        { headers: { server: /nginx/i } },
  "Apache":       { headers: { server: /apache/i } },
  "IIS":          { headers: { server: /iis|microsoft/i } },
  "LiteSpeed":    { headers: { server: /litespeed/i } },
  "Caddy":        { headers: { server: /caddy/i } },
  // CDN / Proxy
  "Cloudflare":   { headers: { "cf-ray": /./i } },
  "Fastly":       { headers: { "x-fastly-request-id": /./i } },
  "Varnish":      { headers: { "x-varnish": /./i } },
  "Akamai":       { headers: { "x-akamai-request-id": /./i } },
  // Frameworks / Languages
  "PHP":          { headers: { "x-powered-by": /php/i } },
  "ASP.NET":      { headers: { "x-powered-by": /asp\.net/i, "x-aspnet-version": /./i } },
  "Ruby on Rails":{ headers: { "x-runtime": /./i } },
  "Express.js":   { headers: { "x-powered-by": /express/i } },
  // CMS (body patterns)
  "WordPress":    { body: /wp-content|wp-json|wordpress/i },
  "Drupal":       { body: /drupal\.settings|Drupal\.behaviors/i, headers: { "x-generator": /drupal/i } },
  "Joomla":       { body: /\/media\/jui\/|Joomla!/i },
  "Shopify":      { body: /cdn\.shopify\.com|Shopify\.theme/i },
  "Squarespace":  { body: /squarespace\.com|squarespace-cdn/i },
  "Wix":          { body: /wix\.com|_wixCIDX/i },
  "Webflow":      { body: /webflow\.com/i },
  // Analytics / Marketing
  "Google Analytics": { body: /google-analytics\.com\/analytics\.js|gtag\('config'/i },
  "Google Tag Manager": { body: /googletagmanager\.com\/gtm\.js/i },
  // JS Frameworks (body)
  "React":        { body: /react\.development\.js|react\.production\.min\.js|__reactFiber/i },
  "Vue.js":       { body: /vue\.runtime|__vue__/i },
  "Next.js":      { body: /__NEXT_DATA__|_next\/static/i },
  "Nuxt.js":      { body: /__nuxt__|_nuxt\//i },
  "Angular":      { body: /ng-version=|angular\.min\.js/i },
  // Other
  "jQuery":       { body: /jquery\.min\.js|jquery-\d/i },
  "Bootstrap":    { body: /bootstrap\.min\.css|bootstrap\.min\.js/i },
  "Tailwind CSS": { body: /tailwindcss|tw-|class="[^"]*(?:flex|grid|text-)/i },
  "Stripe":       { body: /js\.stripe\.com/i },
  "Intercom":     { body: /intercomcdn\.com|window\.Intercom/i },
  "HubSpot":      { body: /js\.hs-scripts\.com|hubspot\.com/i },
};

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  let url = (event.queryStringParameters?.url || "").trim();
  if (!url) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing URL" }) };
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    const res = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(12000),
      redirect: "follow",
    });

    const responseHeaders = {};
    res.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

    // Read up to 200KB of body for pattern matching
    const body = await res.text().then(t => t.slice(0, 200000));

    const detected = [];

    for (const [tech, sigs] of Object.entries(TECH_SIGNATURES)) {
      let matched = false;

      if (sigs.headers) {
        for (const [hdr, pattern] of Object.entries(sigs.headers)) {
          if (responseHeaders[hdr] && pattern.test(responseHeaders[hdr])) {
            matched = true;
            break;
          }
        }
      }

      if (!matched && sigs.body && sigs.body.test(body)) matched = true;

      if (matched) {
        // Categorize
        const category = ["Nginx", "Apache", "IIS", "LiteSpeed", "Caddy"].includes(tech) ? "Server"
          : ["Cloudflare", "Fastly", "Varnish", "Akamai"].includes(tech) ? "CDN"
          : ["PHP", "ASP.NET", "Ruby on Rails", "Express.js"].includes(tech) ? "Language/Framework"
          : ["WordPress", "Drupal", "Joomla", "Shopify", "Squarespace", "Wix", "Webflow"].includes(tech) ? "CMS"
          : ["React", "Vue.js", "Next.js", "Nuxt.js", "Angular"].includes(tech) ? "JS Framework"
          : ["Google Analytics", "Google Tag Manager", "HubSpot", "Intercom"].includes(tech) ? "Analytics"
          : "Library/Other";

        detected.push({ name: tech, category });
      }
    }

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        url,
        status: res.status,
        server: responseHeaders["server"] || null,
        poweredBy: responseHeaders["x-powered-by"] || null,
        detected,
        categories: [...new Set(detected.map(d => d.category))],
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
