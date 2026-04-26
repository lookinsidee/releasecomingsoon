// netlify/functions/whois.js
// Uses RDAP (the modern WHOIS replacement) - no API key needed

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const q = (event.queryStringParameters?.q || "").trim();
  if (!q) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing query" }) };

  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(q) || q.includes(":");

  try {
    if (isIP) {
      // RDAP for IPs
      const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(q)}`);
      if (!res.ok) throw new Error("RDAP lookup failed");
      const d = await res.json();

      const org = d.entities?.find(e => e.roles?.includes("registrant") || e.roles?.includes("administrative"));
      const orgName = org?.vcardArray?.[1]?.find(f => f[0] === "fn")?.[3] || "";

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          type: "ip",
          handle: d.handle,
          name: d.name,
          type2: d.type,
          startAddress: d.startAddress,
          endAddress: d.endAddress,
          ipVersion: d.ipVersion,
          org: orgName,
          country: d.country,
          status: d.status,
          registered: d.events?.find(e => e.eventAction === "registration")?.eventDate,
          updated: d.events?.find(e => e.eventAction === "last changed")?.eventDate,
          remarks: d.remarks?.[0]?.description?.join(" "),
        }),
      };
    } else {
      // RDAP for domains
      const domain = q.replace(/^https?:\/\//, "").split("/")[0];
      const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
      if (!res.ok) throw new Error("RDAP lookup failed");
      const d = await res.json();

      const registrar = d.entities?.find(e => e.roles?.includes("registrar"));
      const registrant = d.entities?.find(e => e.roles?.includes("registrant"));
      const registrarName = registrar?.vcardArray?.[1]?.find(f => f[0] === "fn")?.[3] || registrar?.handle || "";
      const registrantName = registrant?.vcardArray?.[1]?.find(f => f[0] === "fn")?.[3] || "";
      const email = registrant?.vcardArray?.[1]?.find(f => f[0] === "email")?.[3] || "";
      const nameservers = d.nameservers?.map(ns => ns.ldhName) || [];

      return {
        statusCode: 200, headers,
        body: JSON.stringify({
          type: "domain",
          name: d.ldhName,
          handle: d.handle,
          status: d.status,
          registered: d.events?.find(e => e.eventAction === "registration")?.eventDate,
          expires: d.events?.find(e => e.eventAction === "expiration")?.eventDate,
          updated: d.events?.find(e => e.eventAction === "last changed")?.eventDate,
          registrar: registrarName,
          registrant: registrantName,
          email,
          nameservers,
        }),
      };
    }
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
