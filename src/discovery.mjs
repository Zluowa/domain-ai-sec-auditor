/**
 * discovery.mjs — x402 v2, CDP Bazaar, OpenAPI 3.1, and llms.txt discovery metadata for AgentReady & WebSec API (v1.0.0)
 */

import { BASE_USDC_MAINNET } from './payment-hooks.mjs';

export const SERVICE_VERSION = '1.0.0';

export function resolveCanonicalBaseUrl({ hostHeader, forwardedProto, publicBaseUrl } = {}) {
  if (publicBaseUrl && typeof publicBaseUrl === 'string' && publicBaseUrl.trim()) {
    return publicBaseUrl.trim().replace(/\/+$/, '');
  }
  const host = String(hostHeader || '127.0.0.1').trim();
  const proto = String(forwardedProto || 'https').replace(/:$/, '').trim();
  return `${proto}://${host}`;
}

export function resolveCanonicalResourceUrl(pathname, opts = {}) {
  const base = resolveCanonicalBaseUrl(opts);
  const cleanPath = pathname.startsWith('/') ? pathname : `/${pathname}`;
  return `${base}${cleanPath}`;
}

export function buildBazaarExtension(pathname) {
  if (pathname !== '/api/v1/audit-domain') return undefined;
  return {
    bazaar: {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          body: {
            url: 'https://example.com',
            includeMarkdown: false,
          },
        },
        output: {
          type: 'json',
          example: {
            domain: 'example.com',
            status: 'audited',
            overallScore: 76,
            grade: 'C',
            aiReadinessScore: 68,
            httpSecurityScore: 52,
            tlsScore: 100,
            dnsScore: 85,
            hasLlmsTxt: false,
            aiBotsAllowed: 12,
            aiBotsTotal: 12,
            dmarcPolicy: 'reject',
            spfPolicy: 'hardfail',
          },
        },
      },
      schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'object',
        properties: {
          input: {
            type: 'object',
            required: ['body'],
            properties: {
              body: {
                type: 'object',
                required: ['url'],
                properties: {
                  url: {
                    type: 'string',
                    description: 'Public domain or HTTP(S) URL to audit (e.g., https://example.com).',
                  },
                  includeMarkdown: {
                    type: 'boolean',
                    description: 'Include a Markdown executive summary in the response.',
                  },
                },
              },
            },
          },
        },
      },
    },
  };
}

export function buildX402DiscoveryManifest({
  baseUrl,
  payTo = null,
  amountUsdcAtomic = '5000',
  network = 'eip155:8453',
} = {}) {
  const priceUsd = Number((Number(amountUsdcAtomic) / 1_000_000).toFixed(6));
  return {
    x402Version: 2,
    service: 'agentready-websec-domain-auditor',
    version: SERVICE_VERSION,
    description:
      'Deterministic 5-pillar domain auditor: AI crawler robots.txt (12 bots), llms.txt, agent.json, JSON-LD, HTTP Security Headers, TLS certificate, DNS SPF/DMARC/CAA, and security.txt.',
    resources: [
      {
        url: `${baseUrl}/api/v1/audit-domain`,
        method: 'POST',
        description: 'Audit a single public domain/URL across AI-readiness (GEO/llms.txt) + WebSec (Headers/TLS/SPF/DMARC/security.txt).',
        pricing: {
          currency: 'USDC',
          network,
          asset: BASE_USDC_MAINNET,
          amountAtomic: String(amountUsdcAtomic),
          priceUsd,
          payTo,
        },
      },
    ],
  };
}

export function buildOpenApiSpec({ baseUrl, x402Enabled = false } = {}) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'AgentReady & WebSec Domain Auditor API',
      version: SERVICE_VERSION,
      description:
        'Zero-dependency deterministic auditor for AI search/crawler readiness (robots.txt 12 AI bots, llms.txt, agent.json, JSON-LD) and web security posture (HTTP headers, TLS, DNS SPF/DMARC/CAA, security.txt).',
    },
    servers: [{ url: baseUrl }],
    paths: {
      '/api/health': {
        get: { summary: 'Health & x402 configuration status', responses: { 200: { description: 'OK' } } },
      },
      '/api/v1/audit-domain': {
        post: {
          summary: 'Audit a public domain/URL across all 5 AI-readiness & WebSec pillars',
          description: x402Enabled
            ? 'Protected by HTTP x402 v2 Base Mainnet USDC micropayment ($0.005 default). Invalid/SSRF/unreachable targets return 400/422 with zero settlement.'
            : 'Open mode (set X402_PAY_TO + X402_FACILITATOR_URL to enforce x402 v2 USDC settlement).',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['url'],
                  properties: {
                    url: { type: 'string', example: 'https://example.com' },
                    includeMarkdown: { type: 'boolean', default: false },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Deterministic 5-pillar audit report' },
            400: { description: 'Invalid target or SSRF blocked (never settled)' },
            402: { description: 'HTTP x402 v2 Payment Required' },
            422: { description: 'Target domain unreachable across DNS, TLS, and HTTP (never settled)' },
          },
        },
      },
    },
  };
}

export function buildLlmsTxt({ baseUrl, x402Enabled = false, amountUsdcAtomic = '5000' } = {}) {
  const priceUsd = Number((Number(amountUsdcAtomic) / 1_000_000).toFixed(6));
  return [
    '# AgentReady & WebSec Domain Auditor API',
    '',
    '> Deterministic pure Node.js 24 domain auditor combining AI-readiness (12 AI crawlers in robots.txt, /llms.txt, /llms-full.txt, /sitemap.xml, /.well-known/agent.json, JSON-LD) with Web Security (OWASP HTTP headers, TLS certificate health, DNS SPF/DMARC/CAA, RFC 9116 security.txt).',
    '',
    '## Pricing & Payment',
    x402Enabled
      ? `- Protocol: HTTP x402 v2 on Base Mainnet (eip155:8453 USDC)`
      : `- Protocol: Open mode (x402 v2 ready when X402_PAY_TO is configured)`,
    `- Price per domain audit: $${priceUsd} USDC (${amountUsdcAtomic} atomic units)`,
    '- Guarantee: SSRF-blocked, malformed, or completely unreachable domains return HTTP 400/422 and are NEVER settled.',
    '',
    '## Endpoints',
    `- Health: ${baseUrl}/api/health`,
    `- x402 Discovery: ${baseUrl}/.well-known/x402`,
    `- OpenAPI 3.1: ${baseUrl}/openapi.json`,
    `- Audit Domain (POST): ${baseUrl}/api/v1/audit-domain`,
    '',
    '## Example Request',
    '```json',
    '{ "url": "https://example.com", "includeMarkdown": false }',
    '```',
    '',
  ].join('\n');
}
