// netlify/functions/ipv6.js
// IPv6 address analysis — expand, classify, and DNS-lookup

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IPv6 address" }) };

  try {
    // Expand abbreviated IPv6 to full form
    function expandIPv6(addr) {
      let full = addr;
      if (full.includes("::")) {
        const parts = full.split("::");
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        const missing = 8 - left.length - right.length;
        const middle = Array(missing).fill("0000");
        full = [...left, ...middle, ...right].join(":");
      }
      return full.split(":").map(g => g.padStart(4, "0")).join(":");
    }

    // Classify address type
    function classifyIPv6(addr) {
      if (addr.startsWith("::1")) return "Loopback";
      if (addr.startsWith("fe80")) return "Link-local";
      if (addr.startsWith("fc") || addr.startsWith("fd")) return "Unique Local (ULA)";
      if (addr.startsWith("2002")) return "6to4";
      if (addr.startsWith("2001:db8")) return "Documentation (TEST-NET)";
      if (addr.startsWith("2001:0:")) return "Teredo";
      if (addr.startsWith("ff")) return "Multicast";
      if (addr.startsWith("::ffff")) return "IPv4-mapped";
      if (addr.startsWith("2") || addr.startsWith("3")) return "Global Unicast";
      return "Unknown";
    }

    const expanded = expandIPv6(ip);
    const type = classifyIPv6(ip.toLowerCase());
    const groups = expanded.split(":");
    const compressed = ip;

    // Get AAAA record if this looks like a domain was meant to be queried
    // Also do reverse DNS for the IP
    let reverseDns = null;
    try {
      const reverseAddr = expanded.replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(reverseAddr)}&type=PTR`,
        { headers: { Accept: "application/dns-json" } }
      );
      const data = await res.json();
      reverseDns = data.Answer?.[0]?.data?.replace(/\.$/, "") || null;
    } catch {}

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        input: ip,
        expanded,
        compressed,
        type,
        scope: type.includes("Loopback") ? "Host" : type.includes("Link-local") ? "Link" : type.includes("Unique Local") ? "Site" : "Global",
        groups,
        reverseDns,
        binary: groups.map(g => parseInt(g, 16).toString(2).padStart(16, "0")),
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
