// netlify/functions/ssl.js
// Fetches SSL certificate details using ssllabs-style approach via SSL checker APIs
// Uses the free ssl-checker approach via fetch to the target + crt.sh fallback

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const host = (event.queryStringParameters?.host || "").trim().replace(/^https?:\/\//, "").split("/")[0];
  if (!host) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing host" }) };

  try {
    // Use the free API from ssl-checker.io
    const res = await fetch(`https://ssl-checker.io/api/v1/check/${encodeURIComponent(host)}`);
    if (!res.ok) throw new Error("SSL check failed");
    const d = await res.json();

    if (!d.valid) {
      // Fallback: try connecting directly
      throw new Error(d.error || "Could not retrieve SSL info");
    }

    const validTo = new Date(d.valid_to);
    const now = new Date();
    const daysRemaining = Math.floor((validTo - now) / 86400000);

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        host,
        subject: { CN: d.cn, O: d.organization },
        issuer: { CN: d.issuer, O: d.issuer_organization },
        validFrom: d.valid_from,
        validTo: d.valid_to,
        daysRemaining,
        expired: daysRemaining < 0,
        serialNumber: d.serial_number,
        fingerprint256: d.sha256_fingerprint,
        subjectAltNames: d.sans?.join(", "),
        protocol: d.protocol,
        bits: d.key_size,
        cipher: { name: d.cipher_suite },
      }),
    };
  } catch (err) {
    // Second attempt using crt.sh for basic cert info
    try {
      const crtRes = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`);
      const certs = await crtRes.json();
      if (certs?.length) {
        const latest = certs[0];
        const validTo = new Date(latest.not_after);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / 86400000);
        return {
          statusCode: 200, headers,
          body: JSON.stringify({
            host,
            subject: { CN: latest.common_name },
            issuer: { CN: latest.issuer_name },
            validFrom: latest.not_before,
            validTo: latest.not_after,
            daysRemaining,
            expired: daysRemaining < 0,
            serialNumber: latest.serial_number,
            note: "Basic info from crt.sh — full TLS details unavailable",
          }),
        };
      }
    } catch {}
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
