// netlify/functions/bgp.js
// BGP route info via RIPE NCC RIS API (free, no key needed)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IP" }) };

  try {
    const [routesRes, peerRes] = await Promise.all([
      fetch(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`),
      fetch(`https://stat.ripe.net/data/routing-status/data.json?resource=${encodeURIComponent(ip)}`),
    ]);

    const [routes, peer] = await Promise.all([routesRes.json(), peerRes.json()]);

    const prefixes = routes.data?.announced_space?.v4?.prefixes || [];
    const asns = routes.data?.asns || [];
    const routingStatus = peer.data;

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ip,
        prefixes: prefixes.slice(0, 10),
        originAsns: asns.map(a => ({ asn: `AS${a.asn}`, name: a.holder })),
        firstSeen: routingStatus?.first_seen?.time,
        lastSeen: routingStatus?.last_seen?.time,
        visibility: routingStatus?.visibility?.v4_full_table_seen,
        peers: routingStatus?.neighbours?.v4 || 0,
        announced: routes.data?.announced || false,
        block: routes.data?.block,
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
