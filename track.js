// netlify/functions/track.js  (edge function — path: /api/track)
// Gets real visitor IP + full geo + threat intel, saves to Supabase

const SUPABASE_URL = 'https://adxujurerxlrebawarav.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFkeHVqdXJlcnhscmViYXdhcmF2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcwNTU3MjgsImV4cCI6MjA5MjYzMTcyOH0.SeAAFJ6N1qytZDrSMj-ue4J5YU5zPfzpyujDJeHFPJ4';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json',
};

export const handler = async (event, context) => {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };

  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (_) {}

  // ── GET REAL IP ──────────────────────────────────────────────
  const ip =
    context.ip ||
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['cf-connecting-ip'] ||
    event.headers['x-real-ip'] ||
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    null;

  // ── GEO + THREAT via ip-api.com ──────────────────────────────
  let geo = {};
  try {
    const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query';
    const geoRes = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip || '')}?fields=${fields}`);
    const g = await geoRes.json();
    if (g.status === 'success') {
      geo = {
        ip:           g.query,
        city:         g.city         || null,
        region:       g.regionName   || null,
        country:      g.country      || null,
        country_code: g.countryCode  || null,
        org:          g.org          || null,
        asn:          g.as           ? g.as.split(' ')[0] : null,
        postal:       g.zip          || null,
        latitude:     g.lat          || null,
        longitude:    g.lon          || null,
        timezone:     g.timezone     || null,
        is_proxy:     g.proxy        || false,
        is_hosting:   g.hosting      || false,
        is_mobile:    g.mobile       || false,
        isp:          g.isp          || null,
        reverse_dns:  g.reverse      || null,
      };
    }
  } catch (_) {
    geo = { ip };
  }

  // ── TOR CHECK via DNSBL ──────────────────────────────────────
  let is_tor = false;
  if (geo.ip) {
    try {
      const reversed = geo.ip.split('.').reverse().join('.');
      const torRes = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${reversed}.torexit.dan.me.uk&type=A`,
        { headers: { Accept: 'application/dns-json' } }
      );
      const tj = await torRes.json();
      is_tor = tj.Status === 0 && (tj.Answer || []).some(r => r.type === 1);
    } catch (_) {}
  }

  // ── ASSEMBLE PAYLOAD ─────────────────────────────────────────
  const payload = {
    // Identity
    visit_id:         body.visit_id         || null,
    fp_hash:          body.fp_hash          || null,

    // IP & Geo (server-side — accurate, VPN-piercing)
    ip:               geo.ip               || ip,
    isp:              geo.isp              || null,
    reverse_dns:      geo.reverse_dns      || null,
    is_hosting:       geo.is_hosting       || false,
    is_mobile:        geo.is_mobile        || false,
    city:             geo.city,
    region:           geo.region,
    country:          geo.country,
    country_code:     geo.country_code,
    org:              geo.org || body.org   || null,
    asn:              geo.asn,
    postal:           geo.postal,
    latitude:         geo.latitude,
    longitude:        geo.longitude,
    timezone:         geo.timezone || body.timezone || null,
    is_tor,
    is_proxy:         geo.is_proxy || false,

    // Browser (client-side)
    browser:          body.browser          || null,
    platform:         body.platform         || null,
    user_agent:       body.user_agent       || null,
    screen_res:       body.screen_res       || null,
    avail_screen:     body.avail_screen     || null,
    inner_size:       body.inner_size       || null,
    color_depth:      body.color_depth      || null,
    pixel_ratio:      body.pixel_ratio      || null,
    language:         body.language         || null,
    color_scheme:     body.color_scheme     || null,

    // Hardware
    cpu_cores:        body.cpu_cores        || null,
    device_memory:    body.device_memory    || null,
    battery_pct:      body.battery_pct      || null,
    battery_charging: body.battery_charging ?? null,
    touch_screen:     body.touch_screen     ?? null,
    orientation:      body.orientation      || null,
    connection:       body.connection       || null,

    // Fingerprints
    canvas_fp:        body.canvas_fp        || null,
    webgl_vendor:     body.webgl_vendor     || null,
    webgl_renderer:   body.webgl_renderer   || null,
    audio_fp:         body.audio_fp         || null,
    fonts:            body.fonts            || null,
    plugins:          body.plugins          || null,

    // Privacy / threat
    ad_blocker:       body.ad_blocker       ?? null,
    incognito:        body.incognito        ?? null,
    likely_bot:       body.likely_bot       ?? null,
    bot_score:        body.bot_score        || null,
    has_webdriver:    body.has_webdriver    ?? null,
    do_not_track:     body.do_not_track     ?? null,
    prefers_reduced_motion: body.prefers_reduced_motion ?? null,

    // Identity
    known_email:      body.known_email      || null,
    returning_visitor: body.returning_visitor ?? false,
    visit_count:      body.visit_count      || 1,

    // Session
    referrer:         body.referrer         || null,
    page_url:         body.page_url         || null,
    visited_at:       new Date().toISOString(),

    // Behavioral (filled on page exit via sendBeacon)
    scroll_depth:     body.scroll_depth     || null,
    mouse_movements:  body.mouse_movements  || null,
    clicks_total:     body.clicks_total     || null,
    keystrokes_total: body.keystrokes_total || null,
    avg_key_interval_ms: body.avg_key_interval_ms || null,
    mouse_velocity_avg: body.mouse_velocity_avg || null,
  };

  try {
    const sbRes = await fetch(`${SUPABASE_URL}/rest/v1/visits`, {
      method: 'POST',
      headers: {
        apikey:          SUPABASE_KEY,
        Authorization:   `Bearer ${SUPABASE_KEY}`,
        'Content-Type':  'application/json',
        Prefer:          'return=representation',
      },
      body: JSON.stringify(payload),
    });

    if (!sbRes.ok) {
      const errText = await sbRes.text();
      return { statusCode: sbRes.status, headers: CORS, body: JSON.stringify({ error: errText }) };
    }

    const [row] = await sbRes.json();
    return { statusCode: 200, headers: CORS, body: JSON.stringify({ ok: true, id: row?.id || null }) };

  } catch (err) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: err.message }) };
  }
};

export const config = { path: '/api/track' };
