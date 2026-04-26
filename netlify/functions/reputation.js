// netlify/functions/reputation.js
// IP reputation via AbuseIPDB (free tier: 1000 checks/day)
// IMPORTANT: Set ABUSEIPDB_KEY in your Netlify environment variables

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const ip = (event.queryStringParameters?.ip || "").trim();
  if (!ip) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing IP" }) };

  const apiKey = process.env.ABUSEIPDB_KEY;
  if (!apiKey) {
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        error: null,
        notice: "AbuseIPDB key not configured. Add ABUSEIPDB_KEY to your Netlify environment variables. Get a free key at abuseipdb.com",
        ip,
        abuseScore: null,
      }),
    };
  }

  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { Key: apiKey, Accept: "application/json" } }
    );
    const json = await res.json();
    if (json.errors) throw new Error(json.errors[0]?.detail || "AbuseIPDB error");
    const d = json.data;

    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        ip: d.ipAddress,
        abuseScore: d.abuseConfidenceScore,
        totalReports: d.totalReports,
        numDistinctUsers: d.numDistinctUsers,
        lastReportedAt: d.lastReportedAt,
        countryCode: d.countryCode,
        isp: d.isp,
        domain: d.domain,
        isTor: d.isTor,
        isPublic: d.isPublic,
        categories: d.reports?.slice(0, 5).flatMap(r => r.categories) || [],
        recentReports: d.reports?.slice(0, 10).map(r => ({
          reportedAt: r.reportedAt,
          comment: r.comment?.slice(0, 120),
          categories: r.categories,
        })) || [],
      }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
