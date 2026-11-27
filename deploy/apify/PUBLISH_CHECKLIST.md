# Actor #3 Publish Checklist — AgentReady & WebSec Bulk Domain Auditor

## 1. Apify Store PPE Launch (128–256 MB RAM, Zero Browser)

1. Push from `projects/domain-ai-sec-auditor`:
   ```bash
   npx apify-cli push
   ```
2. In Apify Console → **Publication / Monetization → Pay per event**:
   - `apify-actor-start`: `$0.001` (platform automatic)
   - `domain-audited` (**Primary Event**): `$0.01`
   - `minimalMaxTotalChargeUsd`: `$0.05`
3. Categories (verified live Apify Store enums):
   - **`SEO_TOOLS`** (Primary high-traffic directory)
   - **`DEVELOPER_TOOLS`**
   - **`AI_TOOLS`**
   - **`MCP_SERVER`** (enables auto-discovery via `mcp.apify.com`)
4. Permissions: keep default **`Limited permissions`** (required for `mcp.apify.com`).
5. Daily QA Pre-check: open Console → **Source → Input → Restore example input** (`urls: ["https://example.com"]`) and run once to confirm green Dataset `overview` table & `$0.011` total run cost.

## 2. Vercel x402 v2 Base Mainnet USDC Launch ($0.005/domain)

1. Build self-contained bundle:
   ```bash
   npm run build:vercel
   ```
2. Deploy `dist/vercel-app` as a new Vercel project (e.g., `agentready-websec-x402-api`, **do not overwrite existing projects**):
   ```bash
   cd dist/vercel-app
   vercel link --yes --project agentready-websec-x402-api
   ```
3. Configure Environment Variables (Production):
   - `X402_PAY_TO` = `<Base Mainnet 0x... recipient address>`
   - `X402_AMOUNT_USDC` = `5000` (`$0.005 USDC`)
   - `X402_NETWORK` = `eip155:8453`
   - `X402_FACILITATOR_URL` = `https://facilitator.payai.network`
4. Verify live:
   - `GET https://<domain>/api/health` → HTTP 200 (`x402Enabled: true`, `x402PriceUsd: 0.005`)
   - `POST https://<domain>/api/v1/audit-domain` (no payment header) → HTTP 402 + `PAYMENT-REQUIRED` header with `eip155:8453` & `extensions.bazaar`
5. Submit to free 0%-fee directories:
   - PayAPI Market: `POST https://payapi.market/api/agent/submit-listing` with `{"paid_route_url": "https://<domain>/api/v1/audit-domain", "contact_email": "<email>"}`
   - x402-list.com & Loomal.ai Free Tier
