// netlify/functions/rpki.js
// RPKI validation via RIPE NCC Routinator API (free)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IP" }) };

  try {
    // First get the ASN for this IP from RIPE stat
    const prefixRes = await fetch(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`);
    const prefixData = await prefixRes.json();
    const prefix = prefixData.data?.announced_space?.v4?.prefixes?.[0];
    const asns = prefixData.data?.asns || [];
    const asn = asns[0]?.asn;

    if (!asn || !prefix) {
      return {
        statusCode: 200, headers,
        body: JSON.stringify({ ip, valid: false, state: "UNKNOWN", reason: "No BGP announcement found for this IP" }),
      };
    }

    // Check RPKI via RIPE NCC Routinator
    const rpkiRes = await fetch(`https://rpki-validator.ripe.net/api/v1/validity/${asn}/${prefix}`);
    const rpkiData = await rpkiRes.json();

    const validity = rpkiData?.validated_route?.validity;

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ip,
        prefix,
        asn: `AS${asn}`,
        state: validity?.state?.toUpperCase() || "UNKNOWN",
        valid: validity?.state === "valid",
        reason: validity?.description,
        roas: validity?.VRPs?.matched || [],
        covering: validity?.VRPs?.unmatched_as || [],
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
