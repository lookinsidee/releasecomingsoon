// netlify/functions/cve.js
// CVE lookup via NIST NVD API (free, no key needed but rate limited)

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const q = (event.queryStringParameters?.q || "").trim();
  if (!q) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing CVE ID or keyword" }) };

  try {
    let url;
    // If it looks like a CVE ID, do exact lookup
    if (/^CVE-\d{4}-\d+$/i.test(q)) {
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(q.toUpperCase())}`;
    } else {
      // Keyword search
      url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(q)}&resultsPerPage=10`;
    }

    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`NVD API error: ${res.status}`);
    const data = await res.json();

    const cves = (data.vulnerabilities || []).map(({ cve }) => {
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
      return {
        id: cve.id,
        published: cve.published,
        modified: cve.lastModified,
        status: cve.vulnStatus,
        description: cve.descriptions?.find(d => d.lang === "en")?.value || "",
        cvssScore: metrics?.cvssData?.baseScore || null,
        cvssVector: metrics?.cvssData?.vectorString || null,
        severity: metrics?.cvssData?.baseSeverity || null,
        affectedProducts: cve.configurations?.flatMap(c =>
          c.nodes?.flatMap(n => n.cpeMatch?.map(m => m.criteria) || []) || []
        ).slice(0, 10) || [],
        references: cve.references?.slice(0, 5).map(r => ({ url: r.url, tags: r.tags })) || [],
      };
    });

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ query: q, total: data.totalResults || cves.length, cves }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
