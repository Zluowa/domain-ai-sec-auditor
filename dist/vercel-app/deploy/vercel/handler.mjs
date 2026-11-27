/**
 * deploy/vercel/handler.mjs — Zero-Dependency Vercel Serverless x402 v2 Base USDC API Handler (v1.0.0)
 *
 * Route: POST /api/v1/audit-domain ($0.005 USDC default on Base Mainnet eip155:8453)
 *
 * Security & honesty guarantees:
 *  - Handles Vercel pre-parsed req.body without hanging on stream "end" (prevents 504 deadlock)
 *  - Route whitelist checked BEFORE x402 verification/settlement
 *  - Hard 64 KiB body cap checked BEFORE parsing or settlement
 *  - Executes deterministic domain audit BEFORE facilitator /settle:
 *      - Invalid URL / SSRF blocked -> HTTP 400, NEVER settles
 *      - Completely unreachable domain (NXDOMAIN/timeout across DNS+TLS+HTTP) -> HTTP 422, NEVER settles
 *  - Fails closed (HTTP 503) if X402_PAY_TO is set without X402_FACILITATOR_URL
 *  - Emits CDP Bazaar `extensions.bazaar` inside HTTP 402 PAYMENT-REQUIRED payload
 */

import { auditDomain, domainReportToMarkdown } from '../../src/domain-auditor.mjs';
import {
  buildX402PaymentRequired,
  parseX402PaymentSignature,
  verifyX402WithFacilitator,
  settleX402WithFacilitator,
} from '../../src/payment-hooks.mjs';
import {
  SERVICE_VERSION,
  resolveCanonicalBaseUrl,
  resolveCanonicalResourceUrl,
  buildX402DiscoveryManifest,
  buildOpenApiSpec,
  buildLlmsTxt,
  buildBazaarExtension,
} from '../../src/discovery.mjs';

export const DEFAULT_X402_AMOUNT_USDC = '5000'; // $0.005 USDC (6 decimals)
export const MAX_BODY_BYTES = 64 * 1024; // 64 KiB

export const SUPPORTED_POST_ROUTES = new Set(['/api/v1/audit-domain']);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, PAYMENT-SIGNATURE, X-PAYMENT',
  'Access-Control-Expose-Headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE',
};

function getHeader(req, name) {
  const target = name.toLowerCase();
  const headers = req?.headers || {};
  if (typeof headers.get === 'function') return headers.get(target);
  const val = headers[target] ?? headers[name];
  return Array.isArray(val) ? val[0] : val;
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  const payload = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    ...CORS_HEADERS,
    ...extraHeaders,
  });
  res.end(payload);
}

function sendText(res, statusCode, text, extraHeaders = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    ...CORS_HEADERS,
    ...extraHeaders,
  });
  res.end(text);
}

async function readBoundedJsonBody(req) {
  const contentLength = Number(getHeader(req, 'content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw Object.assign(new Error('Request body exceeds 64 KiB limit'), { statusCode: 413 });
  }

  // Vercel Node.js Runtime pre-consumes stream while keeping req.on as a function
  if (
    req.body !== undefined &&
    (req.readableEnded === true || req.complete === true || typeof req.on !== 'function')
  ) {
    if (Buffer.isBuffer(req.body)) {
      if (req.body.length > MAX_BODY_BYTES) {
        throw Object.assign(new Error('Request body exceeds 64 KiB limit'), { statusCode: 413 });
      }
      const trimmed = req.body.toString('utf8').trim();
      try {
        return trimmed ? JSON.parse(trimmed) : {};
      } catch (err) {
        throw Object.assign(new Error(`Invalid JSON body: ${err.message}`), { statusCode: 400 });
      }
    }
    const serialized = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {});
    if (Buffer.byteLength(serialized, 'utf8') > MAX_BODY_BYTES) {
      throw Object.assign(new Error('Request body exceeds 64 KiB limit'), { statusCode: 413 });
    }
    if (typeof req.body === 'string') {
      const trimmed = req.body.trim();
      try {
        return trimmed ? JSON.parse(trimmed) : {};
      } catch (err) {
        throw Object.assign(new Error(`Invalid JSON body: ${err.message}`), { statusCode: 400 });
      }
    }
    return req.body || {};
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;

    req.on('data', (chunk) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buf.length;
      if (size > MAX_BODY_BYTES) {
        settled = true;
        reject(Object.assign(new Error('Request body exceeds 64 KiB limit'), { statusCode: 413 }));
        if (typeof req.destroy === 'function') req.destroy();
        return;
      }
      chunks.push(buf);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        if (!raw) {
          if (req.body && typeof req.body === 'object') {
            resolve(req.body);
            return;
          }
          resolve({});
          return;
        }
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(Object.assign(new Error(`Invalid JSON body: ${err.message}`), { statusCode: 400 }));
      }
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

function build402Body(challengePayload, errorMsg = 'Payment Required', reason = undefined) {
  return {
    error: errorMsg,
    ...(reason ? { reason } : {}),
    protocol: 'x402-v2',
    ...challengePayload,
    paymentRequired: challengePayload,
  };
}

export function createVercelHandler(
  env = process.env,
  { fetchImpl = globalThis.fetch, auditDomainImpl = auditDomain } = {}
) {
  const payTo = env?.X402_PAY_TO ? String(env.X402_PAY_TO).trim() : '';
  const amountUsdc = String(env?.X402_AMOUNT_USDC || DEFAULT_X402_AMOUNT_USDC).trim();
  const network = String(env?.X402_NETWORK || 'eip155:8453').trim();
  const facilitatorUrl = env?.X402_FACILITATOR_URL ? String(env.X402_FACILITATOR_URL).trim() : '';
  const publicBaseUrl = env?.PUBLIC_BASE_URL ? String(env.PUBLIC_BASE_URL).trim() : undefined;

  if (payTo && !/^0x[a-fA-F0-9]{40}$/.test(payTo)) {
    throw new Error('Invalid X402_PAY_TO EVM address (must be 0x + 40 hex chars).');
  }

  return async function vercelHandler(req, res) {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS_HEADERS);
      res.end();
      return;
    }

    const hostHeader = getHeader(req, 'x-forwarded-host') || getHeader(req, 'host') || '127.0.0.1';
    const forwardedProto = getHeader(req, 'x-forwarded-proto') || (env?.VERCEL ? 'https' : 'http');
    const parsedUrl = new URL(req.url || '/', `${forwardedProto}://${hostHeader}`);
    const pathname = parsedUrl.pathname;

    const baseUrl = resolveCanonicalBaseUrl({ hostHeader, forwardedProto, publicBaseUrl });

    if (req.method === 'GET' && (pathname === '/health' || pathname === '/api/health')) {
      sendJson(res, 200, {
        status: 'ok',
        runtime: 'vercel-serverless',
        service: 'agentready-websec-domain-auditor',
        version: SERVICE_VERSION,
        x402Enabled: Boolean(payTo),
        x402Network: network,
        x402AmountUsdcAtomic: amountUsdc,
        x402PriceUsd: Number((Number(amountUsdc) / 1_000_000).toFixed(6)),
      });
      return;
    }

    if (req.method === 'GET' && (pathname === '/.well-known/x402' || pathname === '/api/well-known-x402')) {
      sendJson(res, 200, buildX402DiscoveryManifest({ baseUrl, payTo: payTo || null, amountUsdcAtomic: amountUsdc, network }));
      return;
    }

    if (req.method === 'GET' && (pathname === '/openapi.json' || pathname === '/api/openapi')) {
      sendJson(res, 200, buildOpenApiSpec({ baseUrl, x402Enabled: Boolean(payTo) }));
      return;
    }

    if (req.method === 'GET' && (pathname === '/llms.txt' || pathname === '/api/llms')) {
      sendText(res, 200, buildLlmsTxt({ baseUrl, x402Enabled: Boolean(payTo), amountUsdcAtomic: amountUsdc }));
      return;
    }

    if (req.method === 'GET' && pathname === '/') {
      sendJson(res, 200, {
        service: 'agentready-websec-domain-auditor',
        runtime: 'vercel-serverless',
        version: SERVICE_VERSION,
        x402Enabled: Boolean(payTo),
        priceUsd: Number((Number(amountUsdc) / 1_000_000).toFixed(6)),
        endpoints: [
          'GET /api/health',
          'GET /.well-known/x402',
          'GET /openapi.json',
          'GET /llms.txt',
          'POST /api/v1/audit-domain',
        ],
      });
      return;
    }

    if (req.method === 'POST' && SUPPORTED_POST_ROUTES.has(pathname)) {
      let gate = { allowed: true, challenge: null, paymentPayload: null };

      if (payTo) {
        const resourceUrl = resolveCanonicalResourceUrl(pathname, { hostHeader, forwardedProto, publicBaseUrl });
        const challenge = buildX402PaymentRequired({
          recipientAddress: payTo,
          amountUsdcAtomic: amountUsdc,
          network,
          resource: resourceUrl,
          description: 'AgentReady & WebSec Domain Audit (AI Bots, llms.txt, Headers, TLS, SPF/DMARC)',
          extensions: buildBazaarExtension(pathname),
        });

        const sigHeader = getHeader(req, 'payment-signature') || getHeader(req, 'x-payment');
        if (!sigHeader) {
          sendJson(res, 402, build402Body(challenge.payload, 'Payment Required'), {
            'PAYMENT-REQUIRED': challenge.headers['PAYMENT-REQUIRED'],
          });
          return;
        }

        const parsed = parseX402PaymentSignature(sigHeader);
        if (!parsed.ok) {
          sendJson(res, 402, build402Body(challenge.payload, 'Invalid x402 payment header', parsed.reason), {
            'PAYMENT-REQUIRED': challenge.headers['PAYMENT-REQUIRED'],
          });
          return;
        }

        const verifyRes = await verifyX402WithFacilitator({
          facilitatorUrl,
          paymentPayload: parsed.paymentPayload,
          paymentRequirements: challenge.payload.accepts[0],
          fetchImpl,
        });

        if (!verifyRes.verified) {
          const status = verifyRes.statusCode || 402;
          sendJson(
            res,
            status,
            status === 402
              ? build402Body(challenge.payload, 'x402 verification failed', verifyRes.reason)
              : { error: 'x402 verification failed', reason: verifyRes.reason },
            status === 402 ? { 'PAYMENT-REQUIRED': challenge.headers['PAYMENT-REQUIRED'] } : {}
          );
          return;
        }

        gate = { allowed: true, challenge, paymentPayload: parsed.paymentPayload, payer: verifyRes.payer };
      }

      let body;
      try {
        body = await readBoundedJsonBody(req);
      } catch (err) {
        sendJson(res, err.statusCode || 400, { error: err.message });
        return;
      }

      const rawUrl = body?.url ?? body?.domain;
      if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
        sendJson(res, 400, { error: 'Provide a non-empty "url" or "domain" string in the JSON request body.' });
        return;
      }

      // Tight 2500ms per-probe timeout ensures total Vercel Serverless latency stays < 4s (well under 10s Hobby cap)
      const report = await auditDomainImpl(rawUrl.trim(), { fetchImpl, timeoutMs: 2500 });
      if (report.status === 'rejected') {
        sendJson(res, 400, { error: report.error, code: report.errorCode, settled: false });
        return;
      }
      if (report.status === 'unreachable' || !report.billable) {
        sendJson(res, 422, { error: report.error || 'Target domain unreachable.', code: report.errorCode, settled: false });
        return;
      }

      const responseData = {
        ...report,
        ...(body.includeMarkdown ? { markdown: domainReportToMarkdown(report) } : {}),
      };

      // Settle ONLY after deterministic domain audit succeeds
      if (payTo) {
        const settleRes = await settleX402WithFacilitator({
          facilitatorUrl,
          paymentPayload: gate.paymentPayload,
          paymentRequirements: gate.challenge.payload.accepts[0],
          fetchImpl,
        });
        if (!settleRes.settled) {
          const status = settleRes.statusCode || 402;
          sendJson(
            res,
            status,
            status === 402
              ? build402Body(gate.challenge.payload, 'x402 settlement failed', settleRes.reason)
              : { error: 'x402 settlement failed', reason: settleRes.reason },
            status === 402 ? { 'PAYMENT-REQUIRED': gate.challenge.headers['PAYMENT-REQUIRED'] } : {}
          );
          return;
        }
        sendJson(res, 200, responseData, { 'PAYMENT-RESPONSE': settleRes.paymentResponseHeader });
        return;
      }

      sendJson(res, 200, responseData);
      return;
    }

    sendJson(res, 404, { error: 'Not Found' });
  };
}
