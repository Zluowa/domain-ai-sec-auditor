#!/usr/bin/env node
/**
 * apify-actor.mjs — Zero-Dependency Apify Pay-Per-Event (PPE) Actor for AgentReady & WebSec Bulk Domain Auditor (v1.0.0)
 *
 * Billing & safety guarantees:
 *  - Hard 1 MiB input byte limit and 100-domain batch cap enforced BEFORE network or billing calls
 *  - Never manually charges synthetic platform start event; initializes prior charged USD from
 *    ACTOR_CHARGED_USD or PLATFORM_START_CHARGE_USD ($0.001) and enforces ACTOR_MAX_TOTAL_CHARGE_USD
 *  - Charges `domain-audited` ($0.01) ONLY AFTER a domain succeeds (`billable === true`) and
 *    BEFORE pushing to Dataset, so Dataset items always record accurate `chargedUsd`/`chargedEvent`
 *    and HTTP 402 spending-limit hits never leak unpaid items or drop the `OUTPUT` summary;
 *    invalid URLs, SSRF-blocked targets, unreachable NXDOMAINs, and budget-truncated items incur ZERO charge
 *  - Deterministic `idempotency-key` per (runId, domain, index) prevents double billing on retries
 *  - Pure Node.js 24 (zero external npm dependencies, 128-256 MB RAM)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUDITOR_VERSION,
  MAX_BATCH_URLS,
  MAX_CONCURRENCY,
  auditDomain,
  domainReportToMarkdown,
} from './domain-auditor.mjs';

export const ACTOR_VERSION = AUDITOR_VERSION;
export const MAX_INPUT_BYTES = 1024 * 1024; // 1 MiB
export const PLATFORM_START_CHARGE_USD = 0.001;
export const DOMAIN_EVENT_NAME = 'domain-audited';
export const DOMAIN_EVENT_PRICE_USD = 0.01;

export class ActorInputError extends Error {
  constructor(message, code = 'INVALID_INPUT', statusCode = 400) {
    super(message);
    this.name = 'ActorInputError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class ActorChargeError extends Error {
  constructor(message, statusCode = 502, responseBody = null) {
    super(message);
    this.name = 'ActorChargeError';
    this.code = 'CHARGE_FAILED';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

function assertBoundedBytes(rawStringOrObj) {
  const serialized =
    typeof rawStringOrObj === 'string' ? rawStringOrObj : JSON.stringify(rawStringOrObj ?? null);
  const bytes = Buffer.byteLength(serialized, 'utf8');
  if (bytes > MAX_INPUT_BYTES) {
    throw new ActorInputError(
      `Actor input exceeds 1 MiB limit (${bytes} > ${MAX_INPUT_BYTES} bytes).`,
      'INPUT_TOO_LARGE',
      413
    );
  }
  return { serialized, bytes };
}

export function parseActorInput(rawInput) {
  const { bytes } = assertBoundedBytes(rawInput);

  let input = rawInput;
  if (typeof rawInput === 'string') {
    const trimmed = rawInput.trim();
    if (!trimmed) throw new ActorInputError('Actor input JSON is empty.');
    try {
      input = JSON.parse(trimmed);
    } catch (err) {
      throw new ActorInputError(`Invalid Actor input JSON: ${err.message}`);
    }
  }

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ActorInputError('Actor input must be a non-null JSON object.');
  }

  // Accept urls: string[] (or Apify requestList objects [{ url }]) or single url
  let rawUrls = input.urls;
  if (!rawUrls && typeof input.url === 'string') {
    rawUrls = [input.url];
  }
  if (!Array.isArray(rawUrls) || rawUrls.length === 0) {
    throw new ActorInputError('Input requires a non-empty "urls" array of domains or URLs.');
  }
  if (rawUrls.length > MAX_BATCH_URLS) {
    throw new ActorInputError(
      `Input "urls" exceeds maximum batch limit (${rawUrls.length} > ${MAX_BATCH_URLS} domains).`,
      'BATCH_TOO_LARGE',
      413
    );
  }

  const urls = rawUrls.map((item, idx) => {
    if (typeof item === 'string') return item.trim();
    if (item && typeof item === 'object' && typeof item.url === 'string') return item.url.trim();
    throw new ActorInputError(`urls[${idx}] must be a domain/URL string or { "url": "..." } object.`);
  });

  const concurrencyRaw = input.concurrency ?? MAX_CONCURRENCY;
  const concurrency = Number(concurrencyRaw);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
    throw new ActorInputError(`Parameter "concurrency" must be an integer between 1 and ${MAX_CONCURRENCY}.`);
  }

  const timeoutRaw = input.timeoutMs ?? 4000;
  const timeoutMs = Number(timeoutRaw);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 15000) {
    throw new ActorInputError('Parameter "timeoutMs" must be an integer between 500 and 15000.');
  }

  return {
    urls,
    concurrency,
    timeoutMs,
    includeMarkdown: Boolean(input.includeMarkdown),
    inputBytes: bytes,
  };
}

export function resolveMaxTotalChargeUsd(env = process.env) {
  const raw = env?.ACTOR_MAX_TOTAL_CHARGE_USD ?? env?.APIFY_MAX_TOTAL_CHARGE_USD;
  if (raw === undefined || raw === null || raw === '') return null;
  const num = Number(raw);
  return Number.isFinite(num) && num >= 0 ? num : null;
}

export function resolvePriorChargedUsd(env = process.env) {
  const raw = env?.ACTOR_CHARGED_USD ?? env?.APIFY_CHARGED_USD;
  if (raw !== undefined && raw !== null && raw !== '') {
    const num = Number(raw);
    if (Number.isFinite(num) && num >= 0) return num;
  }
  return PLATFORM_START_CHARGE_USD;
}

export function createApifyRuntimeClient({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const apiBase = String(env.APIFY_API_BASE_URL || 'https://api.apify.com').replace(/\/+$/, '');
  const token = env.APIFY_TOKEN || '';
  const runId = env.APIFY_ACTOR_RUN_ID || env.ACTOR_RUN_ID || '';
  const datasetId = env.APIFY_DEFAULT_DATASET_ID || env.ACTOR_DEFAULT_DATASET_ID || '';
  const kvStoreId = env.APIFY_DEFAULT_KEY_VALUE_STORE_ID || env.ACTOR_DEFAULT_KEY_VALUE_STORE_ID || '';
  const inputKey = env.APIFY_INPUT_KEY || env.ACTOR_INPUT_KEY || 'INPUT';
  const isAtHome = env.APIFY_IS_AT_HOME === '1' || Boolean(token && runId);
  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};

  return {
    isAtHome,
    runId,
    datasetId,
    kvStoreId,
    inputKey,

    async getInput() {
      if (!isAtHome || !kvStoreId) return null;
      const url = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvStoreId)}/records/${encodeURIComponent(inputKey)}`;
      const resp = await fetchImpl(url, { method: 'GET', headers: authHeaders });
      if (resp.status === 404) {
        throw new ActorInputError(`Input record "${inputKey}" not found in key-value store.`, 'MISSING_INPUT', 400);
      }
      if (!resp.ok) throw new Error(`Failed to fetch Apify input (HTTP ${resp.status})`);
      const rawText = await resp.text();
      assertBoundedBytes(rawText);
      return rawText;
    },

    async charge({ eventName, count = 1, idempotencyKey }) {
      if (!isAtHome) {
        return { charged: true, mode: 'local-dry-run', eventName, count, idempotencyKey };
      }
      if (!token || !runId) {
        throw new ActorChargeError('Missing APIFY_TOKEN or APIFY_ACTOR_RUN_ID for live PPE charge.', 500);
      }
      const url = `${apiBase}/v2/actor-runs/${encodeURIComponent(runId)}/charge`;
      const resp = await fetchImpl(url, {
        method: 'POST',
        headers: {
          ...authHeaders,
          'Content-Type': 'application/json',
          'idempotency-key': idempotencyKey,
        },
        body: JSON.stringify({ eventName, count }),
      });
      let body = null;
      try {
        body = await resp.json();
      } catch {
        body = null;
      }
      if (!resp.ok) {
        throw new ActorChargeError(
          body?.error?.message || `Apify charge API failed for "${eventName}" (HTTP ${resp.status})`,
          resp.status,
          body
        );
      }
      return { charged: true, mode: 'apify-live', eventName, count, idempotencyKey, apiResponse: body };
    },

    async pushDatasetItem(item) {
      if (!isAtHome || !datasetId) return { pushed: false, mode: 'local-dry-run' };
      const url = `${apiBase}/v2/datasets/${encodeURIComponent(datasetId)}/items`;
      const resp = await fetchImpl(url, {
        method: 'POST',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify([item]),
      });
      if (!resp.ok) throw new Error(`Failed to push item to Apify dataset (HTTP ${resp.status})`);
      return { pushed: true, mode: 'apify-live', datasetId };
    },

    async setOutput(summary) {
      if (!isAtHome || !kvStoreId) return { saved: false, mode: 'local-dry-run' };
      const url = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvStoreId)}/records/OUTPUT`;
      const resp = await fetchImpl(url, {
        method: 'PUT',
        headers: { ...authHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify(summary),
      });
      if (!resp.ok) throw new Error(`Failed to save OUTPUT to Apify KV store (HTTP ${resp.status})`);
      return { saved: true, mode: 'apify-live', kvStoreId };
    },
  };
}

export async function runApifyActor({
  input,
  env = process.env,
  fetchImpl = globalThis.fetch,
  lookupImpl,
  tlsProbeImpl,
  dnsProbeImpl,
  auditDomainImpl = auditDomain,
  client = null,
} = {}) {
  const startedAt = Date.now();
  const runtime = client || createApifyRuntimeClient({ env, fetchImpl });
  const rawInput = input !== undefined ? input : await runtime.getInput();
  const parsed = parseActorInput(rawInput);

  const maxTotalChargeUsd = resolveMaxTotalChargeUsd(env);
  const priorChargedUsd = resolvePriorChargedUsd(env);

  // Compute maximum billable domains allowed within user spending cap (accounting for $0.001 start)
  const maxBillableByBudget =
    maxTotalChargeUsd === null
      ? Infinity
      : Math.max(0, Math.floor((maxTotalChargeUsd - priorChargedUsd + 1e-9) / DOMAIN_EVENT_PRICE_USD));

  let chargedCount = 0;
  let chargedUsd = 0;
  let budgetTruncated = false;
  let nextIdx = 0;
  const items = [];
  const chargeReceipts = [];

  // Process domains in bounded waves so concurrent workers NEVER exceed maxBillableByBudget
  while (nextIdx < parsed.urls.length) {
    const remainingBudgetSlots =
      maxBillableByBudget === Infinity ? parsed.urls.length - nextIdx : maxBillableByBudget - chargedCount;
    if (remainingBudgetSlots <= 0) {
      budgetTruncated = true;
      break;
    }

    const waveSize = Math.min(parsed.concurrency, parsed.urls.length - nextIdx, remainingBudgetSlots);
    const waveIndices = [];
    for (let k = 0; k < waveSize; k++) waveIndices.push(nextIdx++);

    const waveResults = await Promise.all(
      waveIndices.map(async (idx) => {
        const target = parsed.urls[idx];
        const report = await auditDomainImpl(target, {
          timeoutMs: parsed.timeoutMs,
          fetchImpl,
          ...(lookupImpl ? { lookupImpl } : {}),
          ...(tlsProbeImpl ? { tlsProbeImpl } : {}),
          ...(dnsProbeImpl ? { dnsProbeImpl } : {}),
        });
        return { idx, report };
      })
    );

    for (const { idx, report } of waveResults) {
      const item = {
        ...report,
        ...(parsed.includeMarkdown ? { markdown: domainReportToMarkdown(report) } : {}),
        chargedEvent: null,
        chargedUsd: 0,
      };

      if (report.billable === true) {
        const projectedTotal = Math.round((priorChargedUsd + chargedUsd + DOMAIN_EVENT_PRICE_USD) * 1_000_000) / 1_000_000;
        if (maxTotalChargeUsd !== null && projectedTotal > maxTotalChargeUsd + 1e-9) {
          budgetTruncated = true;
          break;
        }

        const hash = crypto
          .createHash('sha256')
          .update(`${idx}:${report.domain || report.input}`)
          .digest('hex')
          .slice(0, 12);
        const idempotencyKey = `agentready-${runtime.runId || 'local'}-${idx}-${hash}`;

        let receipt;
        try {
          receipt = await runtime.charge({
            eventName: DOMAIN_EVENT_NAME,
            count: 1,
            idempotencyKey,
          });
        } catch (err) {
          if (err instanceof ActorChargeError && err.statusCode === 402) {
            budgetTruncated = true;
            break;
          }
          throw err;
        }

        chargedCount++;
        chargedUsd = Math.round((chargedUsd + DOMAIN_EVENT_PRICE_USD) * 1_000_000) / 1_000_000;
        item.chargedEvent = DOMAIN_EVENT_NAME;
        item.chargedUsd = DOMAIN_EVENT_PRICE_USD;
        item.billingMode = receipt.mode;

        await runtime.pushDatasetItem(item);
        chargeReceipts.push(receipt);
        items.push(item);
      } else {
        // Invalid URL / SSRF blocked / unreachable NXDOMAIN -> record result with 0 charge
        await runtime.pushDatasetItem(item);
        items.push(item);
      }
    }

    if (budgetTruncated) {
      break;
    }
  }

  const auditedCount = items.filter((i) => i.status === 'audited').length;
  const rejectedCount = items.filter((i) => i.status === 'rejected').length;
  const unreachableCount = items.filter((i) => i.status === 'unreachable').length;
  const projectedTotalRunUsd = Math.round((priorChargedUsd + chargedUsd) * 1_000_000) / 1_000_000;

  const summary = {
    schemaVersion: 1,
    service: 'agentready-websec-bulk-auditor',
    version: ACTOR_VERSION,
    ok: true,
    requestedCount: parsed.urls.length,
    processedCount: items.length,
    auditedCount,
    rejectedCount,
    unreachableCount,
    budgetTruncated,
    chargedEvent: DOMAIN_EVENT_NAME,
    chargedCount,
    chargedUsd,
    platformStartChargeUsd: priorChargedUsd,
    projectedTotalRunUsd,
    maxTotalChargeUsd,
    billingMode: runtime.isAtHome ? 'apify-live' : 'local-dry-run',
    durationMs: Math.max(1, Date.now() - startedAt),
    items,
  };

  await runtime.setOutput(summary);
  return { ok: true, summary, items, chargeReceipts };
}

function loadLocalInput(argv, env) {
  const jsonIdx = argv.indexOf('--input-json');
  if (jsonIdx !== -1 && argv[jsonIdx + 1] !== undefined) return argv[jsonIdx + 1];
  const fileIdx = argv.indexOf('--input-file');
  if (fileIdx !== -1 && argv[fileIdx + 1]) return fs.readFileSync(path.resolve(argv[fileIdx + 1]), 'utf8');
  if (env.AGENTREADY_ACTOR_INPUT) return env.AGENTREADY_ACTOR_INPUT;
  const storageDir = env.APIFY_LOCAL_STORAGE_DIR || env.CRAWLEE_STORAGE_DIR;
  if (storageDir) {
    const candidate = path.join(storageDir, 'key_value_stores', 'default', 'INPUT.json');
    if (fs.existsSync(candidate)) return fs.readFileSync(candidate, 'utf8');
  }
  return undefined;
}

async function main() {
  const env = process.env;
  const runtime = createApifyRuntimeClient({ env });
  const localInput = runtime.isAtHome ? undefined : loadLocalInput(process.argv.slice(2), env);
  try {
    const result = await runApifyActor({ input: localInput, env, client: runtime });
    const storageDir = env.APIFY_LOCAL_STORAGE_DIR || env.CRAWLEE_STORAGE_DIR;
    if (!runtime.isAtHome && storageDir) {
      const kvDir = path.join(storageDir, 'key_value_stores', 'default');
      const dsDir = path.join(storageDir, 'datasets', 'default');
      fs.mkdirSync(kvDir, { recursive: true });
      fs.mkdirSync(dsDir, { recursive: true });
      fs.writeFileSync(path.join(kvDir, 'OUTPUT.json'), JSON.stringify(result.summary, null, 2));
      result.items.forEach((item, i) => {
        const fname = `${String(i + 1).padStart(9, '0')}.json`;
        fs.writeFileSync(path.join(dsDir, fname), JSON.stringify(item, null, 2));
      });
    }
    process.stdout.write(`${JSON.stringify(result.summary, null, 2)}\n`);
  } catch (err) {
    process.stderr.write(
      `${JSON.stringify({ ok: false, error: err.message, code: err.code || 'ACTOR_ERROR', statusCode: err.statusCode || 500, charged: false }, null, 2)}\n`
    );
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  await main();
}
