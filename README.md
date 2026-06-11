#  Extension Content Script Missing Origin Validation — Origin Spoofing via Iframe 

## Links

- [Full Vulnerability Report](https://docs.google.com/document/d/1HxAp2w4_Z2SzTPa_tBXC4tB9EPv_4S5sld7QKOsS20U/edit?usp=sharing)
- [Vercel Demo](https://sec-henna.vercel.app/)
- [Local exploit server](../check/server.js)

## Quick Start

```bash
node server.js
```

Server starts at `http://localhost:3000`.

## Pages

| Path | Description |
|------|-------------|
| `/` | Parent page (main) |
| `/trusted` | Trusted dApp iframe |
| `/exploit` | Exploit iframe |
| `/tonconnect-manifest.json` | TonConnect manifest |


## Cross-origin test

This server runs all pages on a single origin (same-domain).
For a real cross-origin VULN-001 test, use `vulns/check/server.js` with ngrok.

