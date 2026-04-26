// netlify/functions/traceroute.js
// Network path traceroute via HackerTarget free API

export const handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
  };

  const host = (event.queryStringParameters?.host || "").trim();
  if (!host) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing host" }) };

  try {
    const res = await fetch(
      `https://api.hackertarget.com/traceroute/?q=${encodeURIComponent(host)}`,
      { signal: AbortSignal.timeout(30000) }
    );
    const text = await res.text();

    if (text.includes("API count") || text.includes("error")) {
      throw new Error(text.includes("API count") ? "HackerTarget rate limit reached" : text);
    }

    // Parse traceroute text output
    // Lines like: " 1  192.168.1.1  1.234 ms"
    const hops = [];
    const lines = text.split("\n").filter(Boolean);
    for (const line of lines) {
      const match = line.match(/^\s*(\d+)\s+(\S+)\s+([\d.]+)\s*ms/);
      if (match) {
        hops.push({
          hop: parseInt(match[1]),
          ip: match[2] === "*" ? null : match[2],
          rtt: parseFloat(match[3]),
          hostname: null,
        });
      } else if (line.match(/^\s*(\d+)\s+\*/)) {
        const hopNum = parseInt(line.match(/^\s*(\d+)/)[1]);
        hops.push({ hop: hopNum, ip: null, rtt: null, hostname: null });
      }
    }

    return {
      statusCode: 200, headers,
      body: JSON.stringify({ host, hops }),
    };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
