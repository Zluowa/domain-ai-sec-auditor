# AgentReady & WebSec Bulk Domain Auditor

**Browserless, zero-dependency Node.js 24 bulk auditor** that inspects **1 to 100 domains per run** across both **AI Search / GEO readiness** and **Web Security posture** — at **50%–67% lower cost** than legacy single-focus auditors.

## What It Audits (5 Deterministic Pillars, Zero LLM Hallucinations)

1. **AI-Readiness & GEO Score (0–100)**
   - `/robots.txt` RFC 9309 matrix for **12 major AI crawlers**: `GPTBot`, `OAI-SearchBot`, `ChatGPT-User`, `ClaudeBot`, `Claude-Web`, `PerplexityBot`, `Google-Extended`, `CCBot`, `Applebot-Extended`, `Bytespider`, `Meta-ExternalAgent`, `Amazonbot`
   - `/llms.txt` & `/llms-full.txt` detection (with SPA HTML soft-404 filtering, H1 & Markdown link count)
   - `/sitemap.xml` (plus `Sitemap:` directives declared in `robots.txt`)
   - Homepage `<title>`, `<meta name="description">`, `canonical`, OpenGraph, and `<script type="application/ld+json">` `schema.org` types
   - AI Agent discovery endpoints: `/.well-known/agent.json` (A2A) & `/.well-known/mcp.json`
2. **OWASP HTTP Security Headers**
   - `Strict-Transport-Security` (max-age & `includeSubDomains`), `Content-Security-Policy` (`unsafe-inline`/`unsafe-eval` check), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`
   - Dangerous CORS (`ACAO: *` + `Credentials: true`), server version fingerprint leak, HTTP → HTTPS redirect check
   - **Smart WAF degradation**: if a site returns a datacenter-IP challenge (`403`/`429`/`503`), the Actor flags `httpChallengeDetected: true` and excludes HTTP headers from the score denominator instead of unfairly failing the domain, while still returning full DNS + TLS + discovery results.
3. **TLS / SSL Certificate Health** (`node:tls`)
   - Negotiated TLS version (`TLSv1.3`/`TLSv1.2` vs deprecated), CA trust status, `daysUntilExpiry`, issuer, SAN hostname match (expired/self-signed certs scored cleanly without crashing).
4. **DNS Security & Email Authentication** (`node:dns/promises`)
   - `SPF` (`v=spf1`, flags critical `+all` and duplicate records), `DMARC` (`_dmarc.` `reject`/`quarantine`/`none`), `CAA`, and `MX`.
5. **RFC 9116 Security Disclosure**
   - `/.well-known/security.txt` (`Contact` & `Expires` validity).

## Transparent Pay-Per-Event (PPE) Pricing

| Event | Price | Notes |
|---|---:|---|
| `apify-actor-start` | **$0.001** | Charged once per run automatically by Apify (includes 5s free compute) |
| `domain-audited` *(Primary)* | **$0.01** | Charged only per successfully audited public domain |

- **1 domain trial**: `$0.011`
- **100-domain agency bulk audit**: `$1.001` (completes in ~25 seconds on 128–256 MB RAM)
- **Zero false billing**: Invalid URLs, SSRF-blocked private/internal IPs, completely unreachable domains (`NXDOMAIN`), and items truncated by your max-charge budget incur **$0.00**.

## Example Input

```json
{
  "urls": ["https://example.com", "https://stripe.com"],
  "concurrency": 5,
  "timeoutMs": 4000,
  "includeMarkdown": false
}
```
