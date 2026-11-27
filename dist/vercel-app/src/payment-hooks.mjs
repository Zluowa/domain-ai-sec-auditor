/**
 * payment-hooks.mjs — Zero-dependency x402 v2 Base Mainnet USDC helpers (v1.0.0)
 * Pure ESM (Node.js 22+/24+ & Vercel Serverless compatible).
 */

export const BASE_USDC_MAINNET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

export function toBase64Utf8(str) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64');
  }
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function fromBase64Utf8(b64) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(b64, 'base64').toString('utf8');
  }
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function buildX402PaymentRequired({
  recipientAddress,
  amountUsdcAtomic = '5000', // $0.005 USDC (6 decimals)
  network = 'eip155:8453',
  asset = BASE_USDC_MAINNET,
  resource = '/api/v1/audit-domain',
  description = 'AgentReady & WebSec Domain Audit API',
  maxTimeoutSeconds = 60,
  extensions = undefined,
} = {}) {
  if (!recipientAddress || !/^0x[a-fA-F0-9]{40}$/.test(recipientAddress)) {
    throw new Error('Valid EVM Base recipientAddress (0x + 40 hex chars) is required for x402.');
  }
  const payload = {
    x402Version: 2,
    accepts: [
      {
        scheme: 'exact',
        network,
        amount: String(amountUsdcAtomic),
        asset,
        payTo: recipientAddress,
        maxTimeoutSeconds,
        extra: { name: 'USD Coin', version: '2' },
      },
    ],
    resource: { url: resource, description, mimeType: 'application/json' },
    ...(extensions && typeof extensions === 'object' ? { extensions } : {}),
  };
  const encoded = toBase64Utf8(JSON.stringify(payload));
  return {
    statusCode: 402,
    headers: {
      'Content-Type': 'application/json',
      'PAYMENT-REQUIRED': encoded,
    },
    payload,
  };
}

export function parseX402PaymentSignature(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') {
    return { ok: false, reason: 'Missing PAYMENT-SIGNATURE header' };
  }
  try {
    const decoded = fromBase64Utf8(headerValue.trim());
    const obj = JSON.parse(decoded);
    if (!obj || typeof obj !== 'object') {
      return { ok: false, reason: 'Decoded PAYMENT-SIGNATURE is not a JSON object' };
    }
    const version = Number(obj.x402Version);
    if (version !== 1 && version !== 2) {
      return { ok: false, reason: `Unsupported x402Version: ${obj.x402Version}` };
    }
    if (!obj.payload || typeof obj.payload !== 'object') {
      return { ok: false, reason: 'Missing signed EIP-3009 payload object' };
    }
    return { ok: true, paymentPayload: obj };
  } catch (err) {
    return { ok: false, reason: `Invalid base64/JSON PAYMENT-SIGNATURE: ${err.message}` };
  }
}

export async function verifyX402WithFacilitator({
  facilitatorUrl,
  paymentPayload,
  paymentRequirements,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
}) {
  if (!facilitatorUrl) {
    return {
      verified: false,
      statusCode: 503,
      reason: 'No x402 facilitatorUrl configured; refusing to accept unverified payment.',
    };
  }
  const endpoint = `${facilitatorUrl.replace(/\/+$/, '')}/verify`;
  let resp;
  try {
    resp = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paymentPayload, paymentRequirements }),
      signal:
        typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
          ? AbortSignal.timeout(timeoutMs)
          : undefined,
    });
  } catch (err) {
    return {
      verified: false,
      statusCode: 503,
      reason: `x402 facilitator unreachable: ${err?.message || String(err)}`,
    };
  }
  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }
  if (!resp.ok || !body?.isValid) {
    const statusCode = resp.status >= 500 ? 503 : 402;
    return {
      verified: false,
      statusCode,
      reason: body?.invalidReason || `Facilitator rejected payment (HTTP ${resp.status})`,
      facilitatorResponse: body,
    };
  }
  return {
    verified: true,
    statusCode: 200,
    payer: body.payer || null,
    facilitatorResponse: body,
  };
}

export async function settleX402WithFacilitator({
  facilitatorUrl,
  paymentPayload,
  paymentRequirements,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
}) {
  if (!facilitatorUrl) {
    return {
      settled: false,
      statusCode: 503,
      reason: 'No x402 facilitatorUrl configured; refusing to settle payment.',
    };
  }
  const endpoint = `${facilitatorUrl.replace(/\/+$/, '')}/settle`;
  let resp;
  try {
    resp = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ paymentPayload, paymentRequirements }),
      signal:
        typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
          ? AbortSignal.timeout(timeoutMs)
          : undefined,
    });
  } catch (err) {
    return {
      settled: false,
      statusCode: 503,
      reason: `x402 facilitator unreachable: ${err?.message || String(err)}`,
    };
  }
  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }
  if (!resp.ok || !body?.success) {
    const statusCode = resp.status >= 500 ? 503 : 402;
    return {
      settled: false,
      statusCode,
      reason: body?.errorReason || body?.invalidReason || `Facilitator settlement failed (HTTP ${resp.status})`,
      facilitatorResponse: body,
    };
  }
  const receipt = {
    success: true,
    transaction: body.transaction || body.txHash || null,
    network: body.network || paymentRequirements?.network || 'eip155:8453',
    payer: body.payer || null,
  };
  return {
    settled: true,
    statusCode: 200,
    receipt,
    paymentResponseHeader: toBase64Utf8(JSON.stringify(receipt)),
    facilitatorResponse: body,
  };
}
