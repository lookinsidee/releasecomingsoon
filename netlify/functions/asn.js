// netlify/functions/asn.js
// ASN lookup using bgpview.io (free, no key needed)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IP" }) };

  try {
    // First get the ASN for this IP
    const ipRes = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`);
    const ipData = await ipRes.json();

    if (ipData.status !== "ok") throw new Error("IP lookup failed");

    const prefix = ipData.data?.prefixes?.[0];
    if (!prefix) throw new Error("No ASN data found for this IP");

    const asn = prefix.asn?.asn;
    if (!asn) throw new Error("No ASN found");

    // Now get ASN details
    const asnRes = await fetch(`https://api.bgpview.io/asn/${asn}`);
    const asnData = await asnRes.json();

    if (asnData.status !== "ok") throw new Error("ASN lookup failed");

    const d = asnData.data;

    // Get prefixes count
    const prefixRes = await fetch(`https://api.bgpview.io/asn/${asn}/prefixes`);
    const prefixData = await prefixRes.json();
    const topPrefixes = prefixData.data?.ipv4_prefixes?.slice(0, 5).map(p => p.prefix) || [];

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        asn: `AS${asn}`,
        name: d.name,
        description: d.description_short,
        country: d.country_code,
        rir: d.rir_allocation?.rir_name,
        website: d.website,
        email: d.email_contacts?.[0],
        abuse: d.abuse_contacts?.[0],
        prefixesV4: prefixData.data?.ipv4_prefixes?.length,
        prefixesV6: prefixData.data?.ipv6_prefixes?.length,
        topPrefixes,
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
