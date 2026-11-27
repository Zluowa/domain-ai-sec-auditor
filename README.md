# AgentReady & WebSec Bulk Domain Auditor (`v1.0.0`)

[![Release](https://img.shields.io/github/v/release/Zluowa/domain-ai-sec-auditor?sort=semver)](https://github.com/Zluowa/domain-ai-sec-auditor/releases)
[![CI](https://github.com/Zluowa/domain-ai-sec-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Zluowa/domain-ai-sec-auditor/actions/workflows/ci.yml)
[![Node.js](https://img.shields.io/badge/Node.js-24%2B%20%7C%20Zero%20Deps-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Protocol: x402 v2](https://img.shields.io/badge/API-x402%20v2%20Base%20USDC-0052FF)](https://agentready-websec-x402-api.vercel.app/.well-known/x402)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Zluowa/domain-ai-sec-auditor)

**Browserless, zero-dependency Node.js 24 bulk auditor** that inspects **1 to 100 domains per run** across both **AI Search / GEO Readiness** (`robots.txt` 12 AI crawlers, `llms.txt`, `agent.json`, JSON-LD) and **OWASP Web Security Posture** (HTTP headers, TLS certificates, DNS SPF/DMARC/CAA, `security.txt`) — with strict **SSRF IP-pinning** and **smart WAF degradation**.

> Runs as a **Zero-Install CLI**, **Apify Store PPE Actor (`zluowa/agentready-websec-bulk-auditor`)**, and **Live x402 v2 Base USDC API (`agentready-websec-x402-api.vercel.app`)** (also self-hostable).

---

## 30-Second Quick Start (Zero `npm install`)

```bash
# Audit one or more public domains and output a Markdown report
npx --yes github:Zluowa/domain-ai-sec-auditor stripe.com example.com --markdown

# Emit structured JSON with concurrency 5 (ideal for CI, dashboards, or AI agents)
npx --yes github:Zluowa/domain-ai-sec-auditor stripe.com docs.stripe.com --json --concurrency 5
```

> **Security note**: The auditor resolves DNS before connecting and blocks private, loopback, link-local, RFC 2544 (`198.18.0.0/15`), and IPv6 transition/NAT64 addresses to prevent SSRF. If you run behind a local TUN/Fake-IP proxy (`198.18.x.x`), bypass fake-IP mode for target domains so real public IPs are audited.

---

## What It Audits (5 Deterministic Pillars, Zero LLM Hallucinations)

1. **AI-Readiness & GEO Score (0–100)**
   - `/robots.txt` RFC 9309 matrix for **12 major AI crawlers**: `GPTBot`, `OAI-SearchBot`, `ChatGPT-User`, `ClaudeBot`, `Claude-Web`, `PerplexityBot`, `Google-Extended`, `CCBot`, `Applebot-Extended`, `Bytespider`, `Meta-ExternalAgent`, `Amazonbot`
   - `/llms.txt` & `/llms-full.txt` detection (with SPA HTML soft-404 filtering, H1 & Markdown link count)
   - `/sitemap.xml` (plus `Sitemap:` directives declared in `robots.txt`)
   - Homepage `<title>`, `<meta name="description">`, `canonical`, OpenGraph, and `<script type="application/ld+json">` `schema.org` types
   - AI Agent discovery endpoints: `/.well-known/agent.json` (A2A) & `/.well-known/mcp.json`
2. **OWASP HTTP Security Headers**
   - `Strict-Transport-Security` (`max-age` & `includeSubDomains`), `Content-Security-Policy` (`unsafe-inline`/`unsafe-eval` check), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`
   - Dangerous CORS (`ACAO: *` + `Credentials: true`), server version fingerprint leak, HTTP -> HTTPS redirect check
   - **Smart WAF degradation**: if a site returns a datacenter-IP challenge (`403`/`429`/`503`), the auditor flags `httpChallengeDetected: true` and excludes HTTP headers from the score denominator instead of unfairly failing the domain, while still returning full DNS + TLS + discovery results.
3. **TLS / SSL Certificate Health** (`node:tls` connected directly to the SSRF-validated IP)
   - Negotiated TLS version (`TLSv1.3`/`TLSv1.2` vs deprecated), CA trust status, `daysUntilExpiry`, issuer, and SAN hostname match.
4. **DNS Security & Email Authentication** (`node:dns/promises`)
   - `SPF` (`v=spf1`, flags critical `+all` and duplicate records), `DMARC` (`_dmarc.` `reject`/`quarantine`/`none`), `CAA`, and `MX`.
5. **RFC 9116 Security Disclosure**
   - `/.well-known/security.txt` (`Contact` & `Expires` validity).

---

## Real Output Structure & Verified Runs

### Live Network Benchmarks (Verified 2026-11-27)

| Domain | Elapsed | Highlights |
|---|---:|---|
| `stripe.com` | `2.71s` | Overall **90/100 (Grade A)** — detected `69.8 KB` `/llms.txt`, TLSv1.3, SPF/DMARC |
| `docs.stripe.com` | `2.24s` | Detected `99.2 KB` `/llms.txt` + full AI crawler matrix |
| `example.com` | `2.75s` | Full 5-pillar baseline with zero browser overhead |

### Structured JSON Output Excerpt (Deterministic Schema v1)

```json
{
  "schemaVersion": 1,
  "auditorVersion": "1.0.0",
  "domain": "example-ai.dev",
  "status": "audited",
  "billable": true,
  "overallScore": 86,
  "grade": "B",
  "aiReadinessScore": 84,
  "httpSecurityScore": 86,
  "httpChallengeDetected": false,
  "hasLlmsTxt": true,
  "aiBotsAllowed": 12,
  "aiBotsTotal": 12,
  "findingSummary": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "total": 1 }
}
```

### SSRF Guard Behavior (Zero False Billing)

```markdown
### AgentReady & WebSec Audit — stripe.com

- **Status**: `rejected`
- **Reason**: SSRF protection: "stripe.com" resolved to blocked private/reserved IP "198.18.0.128".
```

---

## Apify Cloud Actor & Live Vercel x402 API

### Apify Store Actor (`zluowa/agentready-websec-bulk-auditor`)

Public on Apify as **[`zluowa/agentready-websec-bulk-auditor`](https://apify.com/zluowa/agentready-websec-bulk-auditor)** (`node:24-alpine`, 128–256 MB RAM, Pay-per-event, Limited permissions); the local CLI and self-hosted API remain free.

| Event | Price | Notes |
|---|---:|---|
| `apify-actor-start` | **$0.001** | Charged once per run automatically by Apify (includes 5s free compute) |
| `domain-audited` *(Primary)* | **$0.01** | Charged only per successfully audited public domain (`$0.00` on invalid URLs, SSRF blocks, `NXDOMAIN`, or budget cutoffs) |

- **1 domain trial**: `$0.011`
- **100-domain agency bulk audit**: `$1.001` (~25s on 128–256 MB RAM)

### Live & Self-Hosted Vercel x402 v2 Base USDC API

- **Live Production Endpoint**: [`https://agentready-websec-x402-api.vercel.app`](https://agentready-websec-x402-api.vercel.app) — `POST /api/v1/audit-domain` (`$0.005 USDC` / domain on Base Mainnet `eip155:8453`, no account or API key required; `$0` settled on invalid URLs, SSRF blocks, or unreachable domains). Discovery endpoints: [`/api/health`](https://agentready-websec-x402-api.vercel.app/api/health), [`/.well-known/x402`](https://agentready-websec-x402-api.vercel.app/.well-known/x402), [`/openapi.json`](https://agentready-websec-x402-api.vercel.app/openapi.json), and [`/llms.txt`](https://agentready-websec-x402-api.vercel.app/llms.txt).
- **Self-Hosting**: Deploy the self-contained bundle in [`dist/vercel-app/`](dist/vercel-app) (rebuilt via `npm run build:vercel`) with `X402_PAY_TO=<your_0x_base_address>` and `X402_FACILITATOR_URL=https://facilitator.payai.network`.

---

## Local Development & Verification

```bash
git clone https://github.com/Zluowa/domain-ai-sec-auditor.git
cd domain-ai-sec-auditor
npm test
node cli/agentready.mjs --help
```
