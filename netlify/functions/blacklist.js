// netlify/functions/blacklist.js
// Checks an IPv4 address against 25 major DNSBL blacklists
// Uses Cloudflare DNS-over-HTTPS to query each DNSBL

const DNSBL_LISTS = [
  "zen.spamhaus.org",
  "bl.spamcop.net",
  "dnsbl.sorbs.net",
  "spam.dnsbl.sorbs.net",
  "b.barracudacentral.org",
  "bl.emailbasura.org",
  "dnsbl-1.uceprotect.net",
  "dnsbl-2.uceprotect.net",
  "dnsbl-3.uceprotect.net",
  "sbl.spamhaus.org",
  "xbl.spamhaus.org",
  "pbl.spamhaus.org",
  "dul.dnsbl.sorbs.net",
  "smtp.dnsbl.sorbs.net",
  "web.dnsbl.sorbs.net",
  "ix.dnsbl.manitu.net",
  "combined.njabl.org",
  "psbl.surriel.com",
  "bl.deadbeef.com",
  "tor.dan.me.uk",
  "torexit.dan.me.uk",
  "rbl.megarbl.net",
  "all.s5h.net",
  "bogons.cymru.com",
  "db.wpbl.info",
];

async function checkBL(reversedIP, bl) {
  const query = `${reversedIP}.${bl}`;
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data = await res.json();
    // If we get an A record answer, the IP is listed
    const listed = data.Status === 0 && data.Answer?.some(r => r.type === 1);
    return { bl, listed };
  } catch {
    return { bl, listed: false };
  }
}

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Valid IPv4 address required" }) };
  }

  // Reverse the IP octets for DNSBL queries
  const reversed = ip.split(".").reverse().join(".");

  try {
    const results = await Promise.all(DNSBL_LISTS.map(bl => checkBL(reversed, bl)));
    const listed = results.filter(r => r.listed).length;
    return {
      statusCode: 200, headers,
      body: JSON.stringify({ ip, total: DNSBL_LISTS.length, listed, results }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
