const SUPABASE_URL      = 'https://adxujurerxlrebawarav.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFkeHVqdXJlcnhscmViYXdhcmF2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcwNTU3MjgsImV4cCI6MjA5MjYzMTcyOH0.SeAAFJ6N1qytZDrSMj-ue4J5YU5zPfzpyujDJeHFPJ4';
const TABLE_NAME        = 'visits';

export default async (request, context) => {
  // Only allow POST
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}

  // Get the real visitor IP from Netlify's context
  const ip = context.ip || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null;

  // Geo lookup server-side — Brave can't block this
  let geo = {};
  try {
    const geoResp = await fetch(`https://ipinfo.io/${ip}/json`);
    if (geoResp.ok) {
      const g = await geoResp.json();
      const [lat, lon] = (g.loc || ',').split(',');
      geo = {
        ip:        g.ip       || ip,
        city:      g.city     || null,
        region:    g.region   || null,
        country:   g.country  || null,
        org:       g.org      || null,
        timezone:  g.timezone || null,
        postal:    g.postal   || null,
        asn:       g.org ? g.org.split(' ')[0] : null,
        latitude:  lat ? parseFloat(lat) : null,
        longitude: lon ? parseFloat(lon) : null,
      };
    }
  } catch (_) {
    geo = { ip };
  }

  const payload = {
    ...geo,
    browser:    body.browser    || null,
    platform:   body.platform   || null,
    user_agent: body.user_agent || null,
    visited_at: new Date().toISOString(),
    referrer:   body.referrer   || null,
    page_url:   body.page_url   || null,
  };

  try {
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/${TABLE_NAME}`, {
      method: 'POST',
      headers: {
        'apikey':        SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type':  'application/json',
        'Prefer':        'return=minimal',
      },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) throw new Error('Supabase HTTP ' + resp.status);

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: err.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
};

export const config = { path: '/api/track' };
