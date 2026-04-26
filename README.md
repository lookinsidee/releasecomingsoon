# DesireBlock — IP Intelligence Platform

> 33 intelligence modules in one sleek React app. Powered by Netlify Functions.

---

## Quick Deploy (5 steps)

### 1. Install dependencies
```bash
npm install
```

### 2. Test locally
```bash
npm install -g netlify-cli
netlify dev
```
Open http://localhost:8888 — everything including `/api/*` functions will work.

### 3. Push to GitHub
```bash
git init
git add .
git commit -m "init: DesireBlock IP intelligence platform"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/desireblock.git
git push -u origin main
```

### 4. Connect to Netlify
1. Go to [app.netlify.com](https://app.netlify.com)
2. Click **"Add new site"** → **"Import an existing project"**
3. Choose **GitHub** → select your `desireblock` repo
4. Build settings are auto-detected from `netlify.toml`:
   - Build command: `npm run build`
   - Publish directory: `dist`
5. Click **Deploy site**

### 5. Add environment variables (optional but recommended)
In Netlify → Site settings → Environment variables:

| Variable | Where to get it | Which module |
|---|---|---|
| `ABUSEIPDB_KEY` | [abuseipdb.com](https://www.abuseipdb.com) — free | REPUTATION tab |
| `VIRUSTOTAL_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) — free | VIRUSTOTAL tab |
| `SCREENSHOTONE_KEY` | [screenshotone.com](https://screenshotone.com) — free tier | SCREENSHOT tab |

The app works without these keys — those tabs will show a helpful "add your API key" message.

---

## What works without any API keys

Everything except 3 tabs runs on free, no-key-required APIs:

| Module | Data source |
|---|---|
| IP Lookup, GEO, Threat | ip-api.com |
| DNS | Cloudflare DNS-over-HTTPS |
| WHOIS / RDAP | rdap.org |
| SSL | ssl-checker.io + crt.sh |
| HTTP Headers | Direct fetch |
| ASN | bgpview.io |
| Blacklist (DNSBL) | Cloudflare DoH → 25 lists |
| Ping | HTTP latency |
| Port Scan | HackerTarget (free tier) |
| Traceroute | HackerTarget (free tier) |
| CT Logs | crt.sh (direct from browser) |
| Subdomains | DNS brute-force via Cloudflare DoH |
| Email / SPF / DMARC | Cloudflare DoH |
| BGP Routes | RIPE NCC stat API |
| IPv6 Inspector | Built-in + Cloudflare DoH |
| RPKI | RIPE NCC Routinator |
| DNS Propagation | 8 resolvers via DoH |
| Redirect Chain | Direct fetch |
| Tor Check | dan.me.uk DNSBL |
| CVE Lookup | NIST NVD API |
| Reverse IP | HackerTarget |
| Passive DNS | RIPE NCC + HackerTarget |
| robots.txt | Direct fetch |
| WAF Detection | Header fingerprinting |
| Spoof Test | Cloudflare DoH |
| Tech Stack | Header + body analysis |
| IP Range / CIDR | Built-in (pure JS, no API) |
| Compare | Reuses ip-api.com |
| Bulk Scan | Reuses ip-api.com |

---

## Project Structure

```
desireblock/
├── netlify.toml              # Build config + /api/* routing
├── package.json
├── vite.config.js
├── index.html
├── public/
│   └── favicon.svg
├── src/
│   ├── main.jsx              # React entry point
│   └── App.jsx               # Your full app (3302 lines)
└── netlify/
    └── functions/            # One file per API route
        ├── ipinfo.js         → /api/ipinfo
        ├── dns.js            → /api/dns
        ├── whois.js          → /api/whois
        ├── ssl.js            → /api/ssl
        ├── headers.js        → /api/headers
        ├── asn.js            → /api/asn
        ├── blacklist.js      → /api/blacklist
        ├── ping.js           → /api/ping
        ├── portscan.js       → /api/portscan
        ├── traceroute.js     → /api/traceroute
        ├── reputation.js     → /api/reputation
        ├── mxtest.js         → /api/mxtest
        ├── screenshot.js     → /api/screenshot
        ├── techstack.js      → /api/techstack
        ├── bgp.js            → /api/bgp
        ├── ipv6.js           → /api/ipv6
        ├── rpki.js           → /api/rpki
        ├── propagation.js    → /api/propagation
        ├── redirects.js      → /api/redirects
        ├── virustotal.js     → /api/virustotal
        ├── tor.js            → /api/tor
        ├── cve.js            → /api/cve
        ├── reverseip.js      → /api/reverseip
        ├── passivedns.js     → /api/passivedns
        ├── robots.js         → /api/robots
        ├── waf.js            → /api/waf
        └── spooftest.js      → /api/spooftest
```

---

## Notes

- **HackerTarget rate limits**: Port scan, traceroute, reverse IP, and passive DNS use HackerTarget's free API (100 API calls/day). If you hit the limit, those tabs will show a rate limit error. Upgrade at hackertarget.com for unlimited.
- **ip-api.com**: The core IP lookup is rate-limited to 45 requests/minute on the free tier. For production use, consider getting a paid key.
- **Netlify Functions**: Each function runs as a Node.js serverless Lambda. They time out at 10 seconds by default (configurable to 26s in netlify.toml).
