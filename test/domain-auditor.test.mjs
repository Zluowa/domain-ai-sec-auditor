import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  isBlockedIpAddress,
  normalizeTargetInput,
  assertSafeUrl,
  safeFetch,
  SsrfBlockedError,
} from '../src/ssrf-guard.mjs';
import {
  AI_CRAWLERS,
  parseRobotsTxt,
  parseHomepageSeoAndSchema,
  auditDomain,
} from '../src/domain-auditor.mjs';
import {
  runApifyActor,
  ActorInputError,
  ActorChargeError,
} from '../src/apify-actor.mjs';
import { createVercelHandler } from '../deploy/vercel/handler.mjs';
import { toBase64Utf8, fromBase64Utf8 } from '../src/payment-hooks.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function mockResp(status, body = '', headers = {}) {
  const hdrs = new Headers(headers);
  const buf = Buffer.from(body, 'utf8');
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: hdrs,
    body: new ReadableStream({
      start(controller) {
        if (buf.length > 0) controller.enqueue(buf);
        controller.close();
      },
    }),
    async text() {
      return body;
    },
    async json() {
      return JSON.parse(body);
    },
  };
}

function makeMockRes() {
  let statusCode = 0;
  let headers = {};
  let rawBody = '';
  return {
    writeHead(code, hdrs = {}) {
      statusCode = code;
      headers = { ...hdrs };
    },
    end(chunk = '') {
      rawBody += chunk;
    },
    get statusCode() {
      return statusCode;
    },
    get headers() {
      return headers;
    },
    get body() {
      return rawBody;
    },
    json() {
      return JSON.parse(rawBody);
    },
  };
}

describe('1. SSRF Guard & Streaming OOM Cap', () => {
  it('blocks private/loopback/metadata IPv4, IPv6, IPv4-mapped IPv6, NAT64, octal/decimal/hex IP bypasses, and non-80/443 ports', () => {
    const blockedIps = [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.5.10',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '::1',
      'fc00::1',
      'fd12:3456::1',
      'fe80::1',
      '::ffff:127.0.0.1',
      '::ffff:169.254.169.254',
      '::ffff:7f00:1',
      '::ffff:0:127.0.0.1',
      '64:ff9b::169.254.169.254',
      '64:ff9b:1::127.0.0.1',
      '2002:7f00:0001::',
      '2002:a9fe:a9fe::',
      '2001:0000:4136:e378:8000:63bf:3fff:fdd2',
    ];
    for (const ip of blockedIps) {
      assert.equal(isBlockedIpAddress(ip), true, `Expected ${ip} to be blocked`);
    }
    assert.equal(isBlockedIpAddress('93.184.216.34'), false);
    assert.equal(isBlockedIpAddress('2606:2800:220:1:248:1893:25c8:1946'), false);

    const badTargets = [
      'http://localhost/admin',
      'https://metadata.google.internal/computeMetadata/v1/',
      'http://169.254.169.254/latest/meta-data/',
      'http://2130706433/', // decimal 127.0.0.1
      'http://0x7f000001/', // hex 127.0.0.1
      'http://0177.0.0.1/', // octal 127.0.0.1
      'http://127.1/',
      'http://[::ffff:169.254.169.254]/',
      'https://example.com:8443/',
      'http://user:pass@example.com/',
      'file:///etc/passwd',
      'ftp://example.com/',
    ];
    for (const t of badTargets) {
      assert.throws(() => normalizeTargetInput(t), `Expected target ${t} to throw`);
    }
  });

  it('blocks DNS resolution pointing to private IP and blocks 302 redirect to AWS metadata IP', async () => {
    await assert.rejects(
      () =>
        assertSafeUrl('https://evil-rebind.example', {
          lookupImpl: async () => [
            { address: '93.184.216.34', family: 4 },
            { address: '169.254.169.254', family: 4 },
          ],
        }),
      (err) => err instanceof SsrfBlockedError && err.code === 'SSRF_DNS_IP_BLOCKED'
    );

    const lookupPublic = async (host) => {
      if (host === 'good.example') return [{ address: '93.184.216.34', family: 4 }];
      throw new Error('Unexpected host');
    };
    const fetchRedirectToMeta = async () =>
      mockResp(302, '', { location: 'http://169.254.169.254/latest/meta-data/' });

    await assert.rejects(
      () =>
        safeFetch('https://good.example/', {
          lookupImpl: lookupPublic,
          fetchImpl: fetchRedirectToMeta,
        }),
      (err) => err instanceof SsrfBlockedError
    );
  });

  it('caps streaming response body at 256 KiB without OOM', async () => {
    const hugeChunk = Buffer.alloc(128 * 1024, 'A');
    let chunksSent = 0;
    const hugeResp = {
      status: 200,
      ok: true,
      headers: new Headers({ 'content-type': 'text/html' }),
      body: new ReadableStream({
        pull(controller) {
          if (chunksSent < 10) {
            chunksSent++;
            controller.enqueue(hugeChunk);
          } else {
            controller.close();
          }
        },
      }),
    };
    const res = await safeFetch('https://big.example/', {
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: async () => hugeResp,
      maxBytes: 256 * 1024,
    });
    assert.equal(res.truncated, true);
    assert.equal(res.bytes, 256 * 1024);
    assert.ok(chunksSent <= 4, `Stream should cancel early, got ${chunksSent} chunks`);
  });
});

describe('2. Deterministic 5-Pillar Parser & Auditor', () => {
  it('evaluates RFC 9309 robots.txt across all 12 AI crawlers with specific-agent & longest-path precedence', () => {
    const robots = [
      'User-agent: *',
      'Disallow: /admin',
      'Allow: /',
      '',
      'User-agent: GPTBot',
      'Disallow: /',
      '',
      'User-agent: ClaudeBot',
      'Disallow: /',
      'Allow: /',
      '',
      'User-agent: Bytespider',
      'Disallow: /',
      'Sitemap: https://good.example/sitemap-main.xml',
    ].join('\n');

    const parsed = parseRobotsTxt(robots);
    assert.equal(parsed.totalBots, AI_CRAWLERS.length);
    assert.equal(parsed.crawlerMatrix.GPTBot.status, 'blocked');
    assert.equal(parsed.crawlerMatrix.Bytespider.status, 'blocked');
    assert.equal(parsed.crawlerMatrix.ClaudeBot.status, 'allowed'); // equal-length Allow beats Disallow
    assert.equal(parsed.crawlerMatrix.PerplexityBot.status, 'allowed');
    assert.equal(parsed.blockedCount, 2);
    assert.equal(parsed.allowedCount, 10);
    assert.deepEqual(parsed.sitemaps, ['https://good.example/sitemap-main.xml']);
  });

  it('extracts JSON-LD @graph types, title, description, canonical, and OpenGraph', () => {
    const html = `<!doctype html><html><head>
      <title>Acme AI Security</title>
      <meta name="description" content="Deterministic AI security platform">
      <link rel="canonical" href="https://acme.example/">
      <meta property="og:title" content="Acme AI">
      <script type="application/ld+json">{"@graph":[{"@type":"Organization","name":"Acme"},{"@type":["WebSite","SoftwareApplication"]}]}</script>
    </head><body>Hello</body></html>`;
    const seo = parseHomepageSeoAndSchema(html);
    assert.equal(seo.title, 'Acme AI Security');
    assert.equal(seo.hasCanonical, true);
    assert.deepEqual(seo.jsonLdTypes.sort(), ['Organization', 'SoftwareApplication', 'WebSite']);
  });

  it('audits a healthy domain with soft-404 HTML filtering on /llms.txt and self-signed TLS without crashing', async () => {
    let tlsConnectIpUsed = null;
    const fetchMock = async (url) => {
      if (url === 'https://acme.example/') {
        return mockResp(200, '<!doctype html><html><head><title>Acme</title><meta name="description" content="Desc"><script type="application/ld+json">{"@type":"Organization"}</script></head></html>', {
          'content-type': 'text/html',
          'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
          'cross-origin-opener-policy': 'same-origin',
        });
      }
      if (url === 'http://acme.example/') {
        return mockResp(301, '', { location: 'https://acme.example/' });
      }
      if (url === 'https://acme.example/robots.txt') {
        return mockResp(200, 'User-agent: *\nAllow: /\n', { 'content-type': 'text/plain' });
      }
      if (url === 'https://acme.example/llms.txt') {
        // SPA soft-404 returning HTML -> MUST NOT be counted as valid llms.txt
        return mockResp(200, '<!DOCTYPE html><html><head><title>SPA</title></head></html>', { 'content-type': 'text/html' });
      }
      if (url === 'https://acme.example/sitemap.xml') {
        return mockResp(200, '<?xml version="1.0"?><urlset><url><loc>https://acme.example/</loc></url></urlset>', {
          'content-type': 'application/xml',
        });
      }
      if (url === 'https://acme.example/.well-known/agent.json') {
        return mockResp(200, JSON.stringify({ name: 'Acme Agent', version: '1.0' }), { 'content-type': 'application/json' });
      }
      if (url === 'https://acme.example/.well-known/security.txt') {
        return mockResp(200, 'Contact: mailto:sec@acme.example\nExpires: 2028-01-01T00:00:00Z\n', { 'content-type': 'text/plain' });
      }
      return mockResp(404, 'Not found', { 'content-type': 'text/plain' });
    };

    const report = await auditDomain('acme.example', {
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: fetchMock,
      tlsProbeImpl: async (_host, ip) => {
        tlsConnectIpUsed = ip;
        return {
          reachable: true,
          authorized: false, // self-signed cert must score cleanly without throwing
          authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
          protocol: 'TLSv1.3',
          issuer: 'Self',
          subjectCN: 'acme.example',
          daysUntilExpiry: 60,
          sanMatched: true,
        };
      },
      dnsProbeImpl: async () => ({
        txtRecords: ['v=spf1 include:_spf.google.com -all'],
        dmarcTxtRecords: ['v=DMARC1; p=reject;'],
        caaRecords: [{ issue: 'letsencrypt.org' }],
        mxRecords: [{ exchange: 'mx.acme.example', priority: 10 }],
        anyDnsSucceeded: true,
      }),
    });

    assert.equal(tlsConnectIpUsed, '93.184.216.34'); // verified IP pinned to tls.connect
    assert.equal(report.status, 'audited');
    assert.equal(report.billable, true);
    assert.equal(report.hasLlmsTxt, false);
    assert.equal(report.pillars.aiReadiness.llmsTxt.soft404Html, true);
    assert.equal(report.httpSecurityScore, 100);
    assert.equal(report.dnsScore, 100);
    assert.equal(report.tlsScore, 60); // 100 - 40 for untrusted self-signed
    assert.equal(report.pillars.aiReadiness.agentCard.present, true);
  });

  it('degrades gracefully on WAF 403 challenge when DNS+TLS succeed, and bills $0 when WAF+DNS+TLS all fail', async () => {
    const wafFetch = async () => mockResp(403, '<html><title>Just a moment...</title>cloudflare</html>', { 'cf-mitigated': 'challenge' });

    const withDnsTls = await auditDomain('protected.example', {
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: wafFetch,
      tlsProbeImpl: async () => ({
        reachable: true,
        authorized: true,
        protocol: 'TLSv1.3',
        issuer: 'Cloudflare',
        daysUntilExpiry: 90,
        sanMatched: true,
      }),
      dnsProbeImpl: async () => ({
        txtRecords: ['v=spf1 -all'],
        dmarcTxtRecords: ['v=DMARC1; p=reject'],
        caaRecords: [{ issue: 'digicert.com' }],
        mxRecords: [],
        anyDnsSucceeded: true,
      }),
    });

    assert.equal(withDnsTls.status, 'audited');
    assert.equal(withDnsTls.billable, true);
    assert.equal(withDnsTls.httpChallengeDetected, true);
    assert.equal(withDnsTls.httpSecurityScore, null); // excluded from score denominator
    assert.ok(withDnsTls.overallScore >= 75, `WAF must not tank overall score, got ${withDnsTls.overallScore}`);

    const wafNoSignal = await auditDomain('dead-waf.example', {
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: wafFetch,
      tlsProbeImpl: async () => ({ reachable: false, error: 'ECONNREFUSED' }),
      dnsProbeImpl: async () => ({ txtRecords: [], dmarcTxtRecords: [], caaRecords: [], mxRecords: [], anyDnsSucceeded: false }),
    });
    assert.equal(wafNoSignal.status, 'unreachable');
    assert.equal(wafNoSignal.billable, false);
    assert.equal(wafNoSignal.errorCode, 'WAF_BLOCKED_NO_SIGNAL');
  });
});

describe('3. Apify PPE Actor Billing, Budget Cap, Zero False Charge & Daily QA Prefill', () => {
  it('enforces 100-domain batch cap, never charges SSRF/NXDOMAIN, respects ACTOR_MAX_TOTAL_CHARGE_USD including $0.001 start', async () => {
    const tooMany = Array.from({ length: 101 }, (_, i) => `d${i}.example.com`);
    await assert.rejects(
      () => runApifyActor({ input: { urls: tooMany }, env: {} }),
      (err) => err instanceof ActorInputError && err.statusCode === 413
    );

    const chargedCalls = [];
    const pushedItems = [];
    const mockClient = {
      isAtHome: true,
      runId: 'run-test-123',
      async charge(payload) {
        chargedCalls.push(payload);
        return { charged: true, mode: 'apify-live', ...payload };
      },
      async pushDatasetItem(item) {
        pushedItems.push(item);
        return { pushed: true };
      },
      async setOutput() {
        return { saved: true };
      },
    };

    // Budget $0.025 with default start $0.001 -> max 2 billable domains ($0.021 <= $0.025; 3rd would be $0.031 > $0.025)
    const result = await runApifyActor({
      input: {
        urls: [
          'https://a.example',
          'http://169.254.169.254/latest/meta-data/', // SSRF -> 0 charge
          { url: 'https://b.example' }, // Apify object compatibility
          'https://nxdomain.invalid', // unreachable -> 0 charge
          'https://c.example', // must be budget-truncated -> 0 charge
        ],
        concurrency: 2,
      },
      env: { APIFY_IS_AT_HOME: '1', ACTOR_MAX_TOTAL_CHARGE_USD: '0.025' },
      client: mockClient,
      auditDomainImpl: async (target) => {
        if (target.includes('169.254.169.254')) {
          return { input: target, domain: '169.254.169.254', status: 'rejected', billable: false, errorCode: 'SSRF_IP_BLOCKED' };
        }
        if (target.includes('nxdomain')) {
          return { input: target, domain: 'nxdomain.invalid', status: 'unreachable', billable: false, errorCode: 'ENOTFOUND' };
        }
        return { input: target, domain: new URL(target).hostname, status: 'audited', billable: true, overallScore: 88, grade: 'B' };
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.summary.chargedCount, 2);
    assert.equal(result.summary.chargedUsd, 0.02);
    assert.equal(result.summary.projectedTotalRunUsd, 0.021);
    assert.equal(result.summary.budgetTruncated, true);
    assert.equal(chargedCalls.length, 2);
    assert.ok(chargedCalls.every((c) => c.eventName === 'domain-audited' && c.count === 1 && c.idempotencyKey));
    assert.equal(chargedCalls.some((c) => c.eventName === 'apify-actor-start'), false);
  });

  it('validates .actor/input_schema.json required prefill builds valid daily QA input', async () => {
    const schema = JSON.parse(fs.readFileSync(path.join(rootDir, '.actor', 'input_schema.json'), 'utf8'));
    assert.equal(schema.properties.urls.editor, 'stringList');
    assert.deepEqual(schema.properties.urls.prefill, ['https://example.com']);

    const qaInput = {};
    for (const [k, prop] of Object.entries(schema.properties)) {
      if (prop.prefill !== undefined) qaInput[k] = prop.prefill;
    }
    const res = await runApifyActor({
      input: qaInput,
      env: {},
      auditDomainImpl: async (target) => ({
        input: target,
        domain: 'example.com',
        status: 'audited',
        billable: true,
        overallScore: 82,
        grade: 'B',
      }),
    });
    assert.equal(res.ok, true);
    assert.equal(res.summary.auditedCount, 1);
    assert.equal(res.summary.chargedCount, 1);
  });
});

describe('4. Vercel x402 v2 Base Mainnet USDC Handler', () => {
  const TEST_PAY_TO = '0x1111111111111111111111111111111111111111';

  it('returns 402 with Base Mainnet + CDP extensions.bazaar, handles pre-parsed req.body without 504 hang, never settles SSRF/400, and settles valid 200', async () => {
    let settleCalls = 0;
    const mockFetch = async (url) => {
      if (url.endsWith('/verify')) return mockResp(200, JSON.stringify({ isValid: true, payer: '0x2222222222222222222222222222222222222222' }));
      if (url.endsWith('/settle')) {
        settleCalls++;
        return mockResp(200, JSON.stringify({ success: true, transaction: '0xdeadbeef', network: 'eip155:8453' }));
      }
      return mockResp(404, 'not found');
    };

    const handler = createVercelHandler(
      {
        X402_PAY_TO: TEST_PAY_TO,
        X402_AMOUNT_USDC: '5000',
        X402_NETWORK: 'eip155:8453',
        X402_FACILITATOR_URL: 'https://facilitator.payai.network',
      },
      {
        fetchImpl: mockFetch,
        auditDomainImpl: async (u) => {
          if (u.includes('127.0.0.1')) {
            return { status: 'rejected', billable: false, errorCode: 'SSRF_IP_BLOCKED', error: 'Blocked loopback' };
          }
          return { domain: 'example.com', status: 'audited', billable: true, overallScore: 85, grade: 'B' };
        },
      }
    );

    // 1) No payment header -> 402 + extensions.bazaar
    const res402 = makeMockRes();
    await handler(
      { method: 'POST', url: '/api/v1/audit-domain', headers: { host: 'auditor.vercel.app', 'x-forwarded-proto': 'https' }, readableEnded: true, body: { url: 'https://example.com' } },
      res402
    );
    assert.equal(res402.statusCode, 402);
    const decodedReq = JSON.parse(fromBase64Utf8(res402.headers['PAYMENT-REQUIRED']));
    assert.equal(decodedReq.accepts[0].network, 'eip155:8453');
    assert.equal(decodedReq.accepts[0].amount, '5000');
    assert.ok(decodedReq.extensions?.bazaar?.info?.input);

    const validSig = toBase64Utf8(JSON.stringify({ x402Version: 2, payload: { signature: '0xabc' } }));

    // 2) Pre-parsed Vercel req.body with SSRF target -> 400 and ZERO settle!
    const resSsrf = makeMockRes();
    await handler(
      {
        method: 'POST',
        url: '/api/v1/audit-domain',
        headers: { host: 'auditor.vercel.app', 'payment-signature': validSig },
        readableEnded: true,
        on() {
          throw new Error('Must not hang waiting on stream when Vercel pre-parsed req.body');
        },
        body: { url: 'http://127.0.0.1/' },
      },
      resSsrf
    );
    assert.equal(resSsrf.statusCode, 400);
    assert.equal(settleCalls, 0);

    // 3) Valid request -> 200 + PAYMENT-RESPONSE header + 1 settle
    const resOk = makeMockRes();
    await handler(
      {
        method: 'POST',
        url: '/api/v1/audit-domain',
        headers: { host: 'auditor.vercel.app', 'payment-signature': validSig },
        readableEnded: true,
        body: { url: 'https://example.com', includeMarkdown: true },
      },
      resOk
    );
    assert.equal(resOk.statusCode, 200);
    assert.equal(settleCalls, 1);
    assert.ok(resOk.headers['PAYMENT-RESPONSE']);
    assert.equal(resOk.json().domain, 'example.com');
  });

  it('fails closed with 503 when X402_PAY_TO is set without X402_FACILITATOR_URL', async () => {
    const handler = createVercelHandler({ X402_PAY_TO: TEST_PAY_TO });
    const sig = toBase64Utf8(JSON.stringify({ x402Version: 2, payload: { signature: '0xabc' } }));
    const res = makeMockRes();
    await handler(
      {
        method: 'POST',
        url: '/api/v1/audit-domain',
        headers: { host: 'auditor.vercel.app', 'payment-signature': sig },
        readableEnded: true,
        body: { url: 'https://example.com' },
      },
      res
    );
    assert.equal(res.statusCode, 503);
  });

  it('catches facilitator network errors as HTTP 503 and enforces streaming/DNS timeouts, charge-before-push 402 safety, and zero WAF false findings', async () => {
    // 1) Facilitator network error -> HTTP 503 without throwing
    const handler = createVercelHandler(
      {
        X402_PAY_TO: TEST_PAY_TO,
        X402_FACILITATOR_URL: 'https://facilitator.payai.network',
      },
      {
        fetchImpl: async () => {
          throw new Error('ECONNREFUSED');
        },
      }
    );
    const sig = toBase64Utf8(JSON.stringify({ x402Version: 2, payload: { sig: '0x1' } }));
    const res503 = makeMockRes();
    await handler(
      {
        method: 'POST',
        url: '/api/v1/audit-domain',
        headers: { host: 'auditor.vercel.app', 'payment-signature': sig },
        readableEnded: true,
        body: { url: 'https://example.com' },
      },
      res503
    );
    assert.equal(res503.statusCode, 503);

    // 2) Streaming tarpit aborts cleanly within timeoutMs
    await assert.rejects(
      () =>
        safeFetch('https://tarpit.example/', {
          timeoutMs: 120,
          lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
          fetchImpl: async () => ({
            status: 200,
            headers: new Headers({ 'content-type': 'text/html' }),
            body: new ReadableStream({
              start(controller) {
                controller.enqueue(new TextEncoder().encode('partial'));
              },
            }),
          }),
        }),
      /timed out/i
    );

    // 3) Hung DNS probe is bounded by timeoutMs & WAF 403 emits zero DOM002/DOM003/DOM017
    const t0 = Date.now();
    const wafAndHungDns = await auditDomain('https://waf-slowdns.example', {
      timeoutMs: 150,
      lookupImpl: async () => [{ address: '104.21.1.1', family: 4 }],
      fetchImpl: async () => mockResp(403, '<html><title>Just a moment...</title>cloudflare</html>', { 'cf-mitigated': 'challenge' }),
      tlsProbeImpl: async () => ({
        reachable: true,
        authorized: true,
        protocol: 'TLSv1.3',
        issuer: 'Cloudflare',
        daysUntilExpiry: 120,
        sanMatched: true,
      }),
      dnsProbeImpl: () => new Promise(() => {}),
    });
    assert.ok(Date.now() - t0 < 700);
    assert.equal(wafAndHungDns.status, 'audited');
    const ruleIds = wafAndHungDns.findings.map((f) => f.ruleId);
    assert.equal(ruleIds.some((r) => ['DOM002', 'DOM003', 'DOM017'].includes(r)), false);

    // 4) Apify charge-before-push records chargedUsd=0.01 and stops cleanly on HTTP 402 without leaking unpaid item
    const pushed = [];
    let savedOutput = null;
    let calls = 0;
    const actorRes = await runApifyActor({
      input: { urls: ['https://one.example', 'https://two.example'], concurrency: 1 },
      env: { APIFY_IS_AT_HOME: '1', APIFY_TOKEN: 'tok', APIFY_ACTOR_RUN_ID: 'run_402' },
      auditDomainImpl: async (u) => ({
        input: u,
        domain: new URL(u).hostname,
        status: 'audited',
        billable: true,
        overallScore: 90,
        grade: 'A',
        findings: [],
      }),
      client: {
        isAtHome: true,
        runId: 'run_402',
        async charge(payload) {
          calls++;
          if (calls === 2) throw new ActorChargeError('Limit reached', 402);
          return { charged: true, mode: 'apify-live', ...payload };
        },
        async pushDatasetItem(item) {
          pushed.push(JSON.parse(JSON.stringify(item)));
          return { pushed: true };
        },
        async setOutput(summary) {
          savedOutput = summary;
          return { saved: true };
        },
      },
    });
    assert.equal(pushed.length, 1);
    assert.equal(pushed[0].chargedUsd, 0.01);
    assert.equal(pushed[0].chargedEvent, 'domain-audited');
    assert.equal(actorRes.summary.budgetTruncated, true);
    assert.ok(savedOutput !== null);
  });
});
