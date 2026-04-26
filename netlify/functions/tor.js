// netlify/functions/tor.js
// Checks if an IP is a Tor exit node using the Tor Project's DNSEL

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Valid IPv4 required" }) };
  }

  try {
    // Tor DNSEL query format: [reversed-target-ip].80.[reversed-querier-ip].ip-port.exitlist.torproject.org
    // Simpler: just query the IP against dan.me.uk Tor list
    const reversed = ip.split(".").reverse().join(".");
    const query = `${reversed}.torexit.dan.me.uk`;

    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data = await res.json();
    const isExit = data.Status === 0 && data.Answer?.some(r => r.type === 1);

    // Also check the full node list
    const query2 = `${reversed}.tor.dan.me.uk`;
    const res2 = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query2)}&type=A`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data2 = await res2.json();
    const isNode = data2.Status === 0 && data2.Answer?.some(r => r.type === 1);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ip,
        isTorExitNode: isExit,
        isTorNode: isNode,
        source: "dan.me.uk DNSBL",
        checked: new Date().toISOString(),
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
