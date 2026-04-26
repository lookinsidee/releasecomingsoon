// netlify/functions/ipinfo.js
// Powers the main lookup: IP geolocation, ISP, proxy/VPN/hosting/mobile flags
// Uses ip-api.com (free, no key needed for server-side use)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const q = event.queryStringParameters?.q || "";
  if (!q) return { statusCode: 400, headers, body: JSON.stringify({ status: "fail", message: "Missing query" }) };

  try {
    // ip-api.com supports both IPs and domain names
    const fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
    const url = `http://ip-api.com/json/${encodeURIComponent(q)}?fields=${fields}`;
    const res = await fetch(url);
    const data = await res.json();
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ status: "fail", message: err.message }) };
  }
};
