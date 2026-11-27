/**
 * domain-auditor.mjs — Deterministic 5-Pillar AI-Readiness & WebSec Domain Auditor (v1.0.0)
 * Zero external dependencies (Node.js 22+/24+: fetch, node:tls, node:dns/promises).
 *
 * Five deterministic pillars:
 *  1. AI-Readiness & GEO: robots.txt 12 AI crawlers matrix, /llms.txt, /llms-full.txt,
 *     /sitemap.xml, homepage JSON-LD/meta/canonical/OG, /.well-known/agent.json & mcp.json
 *  2. HTTP Security Headers & Transport: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
 *     Referrer-Policy, Permissions-Policy, COOP, dangerous CORS, server fingerprint, HTTP->HTTPS
 *  3. TLS / SSL Certificate Health: protocol version, authorization, daysUntilExpiry, issuer, SAN
 *  4. DNS Security & Email Auth: SPF (v=spf1), DMARC (_dmarc.), CAA, MX
 *  5. RFC 9116 Security Disclosure: /.well-known/security.txt (Contact, Expires)
 *
 * Resilient against datacenter-IP WAF challenges (403/429/503): degrades gracefully without
 * crashing or unfairly penalizing blocked HTTP scores, while still returning full DNS + TLS +
 * robots/llms/security.txt findings.
 */

import dns from 'node:dns/promises';
import tls from 'node:tls';

import {
  DEFAULT_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  SsrfBlockedError,
  InvalidTargetError,
  normalizeTargetInput,
  assertSafeUrl,
  safeFetch,
} from './ssrf-guard.mjs';

export const AUDITOR_VERSION = '1.0.0';
export const MAX_BATCH_URLS = 100;
export const MAX_CONCURRENCY = 5;

export const AI_CRAWLERS = Object.freeze([
  'GPTBot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'ClaudeBot',
  'Claude-Web',
  'PerplexityBot',
  'Google-Extended',
  'CCBot',
  'Applebot-Extended',
  'Bytespider',
  'Meta-ExternalAgent',
  'Amazonbot',
]);

const PILLAR_WEIGHTS = Object.freeze({
  aiReadiness: 30,
  httpSecurity: 25,
  tlsSecurity: 20,
  dnsSecurity: 20,
  securityTxt: 5,
});

function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 55) return 'D';
  return 'F';
}

function isSoft404Html(headers, text) {
  const ct = String(headers?.['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml')) return true;
  const head = String(text || '').trimStart().slice(0, 256).toLowerCase();
  return head.startsWith('<!doctype html') || head.startsWith('<html') || head.includes('<head>');
}

function isWafChallengeResponse(status, headers, text) {
  if (status === 403 || status === 429 || status === 503) return true;
  const cfMitigated = String(headers?.['cf-mitigated'] || '').toLowerCase();
  if (cfMitigated.includes('challenge')) return true;
  const snippet = String(text || '').slice(0, 4096).toLowerCase();
  if (
    snippet.includes('just a moment...') &&
    (snippet.includes('cloudflare') || snippet.includes('cf-browser-verification') || snippet.includes('challenge-platform'))
  ) {
    return true;
  }
  return false;
}

/**
 * RFC 9309-aligned robots.txt parser supporting multi-agent groups, longest-path rule matching,
 * and Allow precedence over equal-length Disallow.
 */
export function parseRobotsTxt(rawText) {
  const lines = String(rawText || '').split(/\r?\n/);
  const groups = [];
  const sitemaps = [];
  let currentAgents = [];
  let currentRules = [];
  let seenRuleInGroup = false;

  const flushGroup = () => {
    if (currentAgents.length > 0) {
      groups.push({ agents: currentAgents, rules: currentRules });
    }
    currentAgents = [];
    currentRules = [];
    seenRuleInGroup = false;
  };

  for (const rawLine of lines) {
    const noComment = rawLine.replace(/#.*$/, '').trim();
    if (!noComment) continue;
    const colonIdx = noComment.indexOf(':');
    if (colonIdx === -1) continue;
    const field = noComment.slice(0, colonIdx).trim().toLowerCase();
    const value = noComment.slice(colonIdx + 1).trim();

    if (field === 'sitemap') {
      if (value) sitemaps.push(value);
      continue;
    }
    if (field === 'user-agent') {
      if (seenRuleInGroup) {
        flushGroup();
      }
      if (value) currentAgents.push(value.toLowerCase());
      continue;
    }
    if (field === 'allow' || field === 'disallow') {
      if (currentAgents.length === 0) continue;
      seenRuleInGroup = true;
      currentRules.push({ type: field, path: value });
    }
  }
  flushGroup();

  function ruleMatchesRoot(pattern) {
    if (pattern === '') return false; // Empty Disallow/Allow means no restriction
    if (pattern === '/' || pattern === '/*' || pattern === '*') return true;
    // RFC 9309 wildcard check against "/"
    const anchoredEnd = pattern.endsWith('$');
    const clean = anchoredEnd ? pattern.slice(0, -1) : pattern;
    const escaped = clean.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    try {
      const re = new RegExp(`^${escaped}${anchoredEnd ? '$' : ''}`);
      return re.test('/');
    } catch {
      return false;
    }
  }

  function evaluateBot(botName) {
    const lower = botName.toLowerCase();
    // Exact/prefix match takes precedence over "*"
    const specificRules = [];
    const wildcardRules = [];
    for (const grp of groups) {
      if (grp.agents.some((a) => a === lower)) {
        specificRules.push(...grp.rules);
      } else if (grp.agents.includes('*')) {
        wildcardRules.push(...grp.rules);
      }
    }
    const applicable = specificRules.length > 0 ? specificRules : wildcardRules;
    const matchedBy = specificRules.length > 0 ? 'specific' : wildcardRules.length > 0 ? 'wildcard' : 'default';

    let bestMatch = null;
    for (const rule of applicable) {
      if (!ruleMatchesRoot(rule.path)) continue;
      const len = rule.path.length;
      if (
        !bestMatch ||
        len > bestMatch.len ||
        (len === bestMatch.len && rule.type === 'allow' && bestMatch.type === 'disallow')
      ) {
        bestMatch = { type: rule.type, path: rule.path, len };
      }
    }

    const allowed = !bestMatch || bestMatch.type === 'allow';
    return {
      bot: botName,
      status: allowed ? 'allowed' : 'blocked',
      matchedBy,
      matchedRule: bestMatch ? `${bestMatch.type}: ${bestMatch.path}` : null,
    };
  }

  const crawlerMatrix = {};
  let allowedCount = 0;
  let blockedCount = 0;
  for (const bot of AI_CRAWLERS) {
    const res = evaluateBot(bot);
    crawlerMatrix[bot] = res;
    if (res.status === 'allowed') allowedCount++;
    else blockedCount++;
  }

  return {
    sitemaps: [...new Set(sitemaps)],
    crawlerMatrix,
    allowedCount,
    blockedCount,
    totalBots: AI_CRAWLERS.length,
  };
}

/**
 * Extracts title, meta description, canonical, OpenGraph tags, and JSON-LD schema.org types from HTML.
 */
export function parseHomepageSeoAndSchema(html) {
  const src = String(html || '');

  const titleMatch = src.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim().slice(0, 200) : null;

  const metaTags = [...src.matchAll(/<meta\b[^>]*>/gi)].map((m) => m[0]);
  const getAttr = (tag, attr) => {
    const re = new RegExp(`\\b${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
    const m = tag.match(re);
    return m ? (m[1] ?? m[2] ?? m[3] ?? '').trim() : null;
  };

  let description = null;
  let ogTitle = null;
  let ogDescription = null;
  for (const tag of metaTags) {
    const name = (getAttr(tag, 'name') || '').toLowerCase();
    const prop = (getAttr(tag, 'property') || '').toLowerCase();
    const content = getAttr(tag, 'content');
    if (!content) continue;
    if (name === 'description' && !description) description = content.slice(0, 320);
    if (prop === 'og:title' && !ogTitle) ogTitle = content.slice(0, 200);
    if (prop === 'og:description' && !ogDescription) ogDescription = content.slice(0, 320);
  }

  let canonical = null;
  for (const m of src.matchAll(/<link\b[^>]*>/gi)) {
    const rel = (getAttr(m[0], 'rel') || '').toLowerCase();
    if (rel.split(/\s+/).includes('canonical')) {
      canonical = getAttr(m[0], 'href');
      break;
    }
  }

  const jsonLdTypes = new Set();
  const collectTypes = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) collectTypes(item);
      return;
    }
    if (typeof node['@type'] === 'string') {
      jsonLdTypes.add(node['@type']);
    } else if (Array.isArray(node['@type'])) {
      for (const t of node['@type']) {
        if (typeof t === 'string') jsonLdTypes.add(t);
      }
    }
    if (Array.isArray(node['@graph'])) {
      collectTypes(node['@graph']);
    }
  };

  let jsonLdBlocks = 0;
  for (const m of src.matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    const rawJson = m[1].trim();
    if (!rawJson) continue;
    try {
      const parsed = JSON.parse(rawJson);
      jsonLdBlocks++;
      collectTypes(parsed);
    } catch {
      // ignore malformed JSON-LD block
    }
  }

  return {
    title,
    hasTitle: Boolean(title),
    description,
    hasDescription: Boolean(description),
    canonical,
    hasCanonical: Boolean(canonical),
    openGraph: { hasTitle: Boolean(ogTitle), hasDescription: Boolean(ogDescription) },
    jsonLdBlocks,
    jsonLdTypes: [...jsonLdTypes],
  };
}

/**
 * Default TLS handshake probe via node:tls using a pre-validated IP address + SNI hostname.
 */
export async function defaultTlsProbe(hostname, connectIp, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (val) => {
      if (settled) return;
      settled = true;
      resolve(val);
    };

    let socket;
    try {
      socket = tls.connect({
        host: connectIp || hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      });
    } catch (err) {
      finish({ reachable: false, error: err.message });
      return;
    }

    const timer = setTimeout(() => {
      socket.destroy();
      finish({ reachable: false, error: `TLS handshake timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    socket.once('secureConnect', () => {
      clearTimeout(timer);
      try {
        const protocol = socket.getProtocol() || null;
        const authorized = Boolean(socket.authorized);
        const authorizationError = socket.authorizationError ? String(socket.authorizationError) : null;
        const cert = socket.getPeerCertificate(false) || {};
        const validFrom = cert.valid_from || null;
        const validTo = cert.valid_to || null;
        const issuer = cert.issuer?.O || cert.issuer?.CN || null;
        const subjectCN = cert.subject?.CN || null;
        const subjectAltName = cert.subjectaltname || '';

        let daysUntilExpiry = null;
        if (validTo) {
          const expiryMs = Date.parse(validTo);
          if (Number.isFinite(expiryMs)) {
            daysUntilExpiry = Math.floor((expiryMs - Date.now()) / (24 * 60 * 60 * 1000));
          }
        }

        const sanEntries = subjectAltName
          .split(',')
          .map((s) => s.trim())
          .filter((s) => /^DNS:/i.test(s))
          .map((s) => s.slice(4).toLowerCase());

        const lowerHost = hostname.toLowerCase();
        const matchesPattern = (pat) => {
          if (pat === lowerHost) return true;
          if (pat.startsWith('*.')) {
            const suffix = pat.slice(1); // .example.com
            const firstDot = lowerHost.indexOf('.');
            return firstDot > 0 && lowerHost.slice(firstDot) === suffix;
          }
          return false;
        };
        const sanMatched =
          sanEntries.length > 0
            ? sanEntries.some(matchesPattern)
            : Boolean(subjectCN && matchesPattern(subjectCN.toLowerCase()));

        socket.end();
        socket.destroy();
        finish({
          reachable: true,
          authorized,
          authorizationError,
          protocol,
          issuer,
          subjectCN,
          validFrom,
          validTo,
          daysUntilExpiry,
          sanMatched,
          error: null,
        });
      } catch (err) {
        socket.destroy();
        finish({ reachable: false, error: err.message });
      }
    });

    socket.once('error', (err) => {
      clearTimeout(timer);
      socket.destroy();
      finish({ reachable: false, error: err.message });
    });

    socket.once('timeout', () => {
      clearTimeout(timer);
      socket.destroy();
      finish({ reachable: false, error: `TLS socket timeout (${timeoutMs}ms)` });
    });
  });
}

function withTimeoutFallback(promiseFactory, timeoutMs, fallbackValue) {
  let timer;
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve(fallbackValue), timeoutMs);
  });
  return Promise.race([
    Promise.resolve().then(promiseFactory).catch(() => fallbackValue),
    timeoutPromise,
  ]).finally(() => {
    clearTimeout(timer);
  });
}

/**
 * Default DNS security probe (SPF, DMARC, CAA, MX) using node:dns/promises, bounded by timeoutMs.
 */
export async function defaultDnsProbe(hostname, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const safeCall = (fn) =>
    withTimeoutFallback(
      async () => {
        try {
          return { ok: true, value: await fn() };
        } catch (err) {
          return { ok: false, code: err.code || 'DNS_ERROR', value: [] };
        }
      },
      timeoutMs,
      { ok: false, code: 'DNS_TIMEOUT', value: [] }
    );

  const [txtRes, dmarcRes, caaRes, mxRes] = await Promise.all([
    safeCall(() => dns.resolveTxt(hostname)),
    safeCall(() => dns.resolveTxt(`_dmarc.${hostname}`)),
    safeCall(() => dns.resolveCaa(hostname)),
    safeCall(() => dns.resolveMx(hostname)),
  ]);

  const joinTxt = (rows) =>
    (Array.isArray(rows) ? rows : []).map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));

  return {
    txtRecords: joinTxt(txtRes.value),
    dmarcTxtRecords: joinTxt(dmarcRes.value),
    caaRecords: Array.isArray(caaRes.value) ? caaRes.value : [],
    mxRecords: Array.isArray(mxRes.value) ? mxRes.value : [],
    anyDnsSucceeded: txtRes.ok || dmarcRes.ok || caaRes.ok || mxRes.ok,
  };
}

function evaluateDnsSecurity(dnsRaw, findings) {
  const spfRecords = (dnsRaw.txtRecords || []).filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  let spfPolicy = 'missing';
  let spfRecord = null;
  if (spfRecords.length > 0) {
    spfRecord = spfRecords[0].trim();
    if (/(?:^|\s)\+all(?:\s|$)/i.test(spfRecord)) spfPolicy = 'pass-all-dangerous';
    else if (/(?:^|\s)-all(?:\s|$)/i.test(spfRecord)) spfPolicy = 'hardfail';
    else if (/(?:^|\s)~all(?:\s|$)/i.test(spfRecord)) spfPolicy = 'softfail';
    else if (/(?:^|\s)\?all(?:\s|$)/i.test(spfRecord)) spfPolicy = 'neutral';
    else spfPolicy = 'present-no-all';
  }

  const dmarcRecords = (dnsRaw.dmarcTxtRecords || []).filter((r) => /^v=DMARC1\s*;/i.test(r.trim()));
  let dmarcPolicy = 'missing';
  let dmarcRecord = null;
  if (dmarcRecords.length > 0) {
    dmarcRecord = dmarcRecords[0].trim();
    const pMatch = dmarcRecord.match(/(?:^|;\s*)p\s*=\s*(reject|quarantine|none)\b/i);
    dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : 'invalid';
  }

  const hasCaa = (dnsRaw.caaRecords || []).length > 0;
  const hasMx = (dnsRaw.mxRecords || []).length > 0;

  let score = 0;
  // SPF (40 pts)
  if (spfPolicy === 'hardfail') {
    score += 40;
  } else if (spfPolicy === 'softfail') {
    score += 34;
  } else if (spfPolicy === 'present-no-all' || spfPolicy === 'neutral') {
    score += 20;
    findings.push({
      ruleId: 'DOM012',
      severity: 'MEDIUM',
      category: 'dns',
      message: `SPF record uses weak qualifier (${spfPolicy}).`,
      remediation: 'Tighten SPF record to end with "~all" or "-all".',
    });
  } else if (spfPolicy === 'pass-all-dangerous') {
    score += 0;
    findings.push({
      ruleId: 'DOM011',
      severity: 'CRITICAL',
      category: 'dns',
      message: 'SPF record uses "+all", allowing any IP worldwide to spoof email from this domain.',
      remediation: 'Replace "+all" with "-all" or "~all" immediately.',
    });
  } else {
    findings.push({
      ruleId: 'DOM012',
      severity: 'HIGH',
      category: 'dns',
      message: 'Missing DNS SPF (v=spf1) TXT record.',
      remediation: 'Publish a TXT record such as "v=spf1 -all" (if no mail is sent) or authorize your mail senders.',
    });
  }

  if (spfRecords.length > 1) {
    score = Math.max(0, score - 10);
    findings.push({
      ruleId: 'DOM013',
      severity: 'MEDIUM',
      category: 'dns',
      message: `Multiple SPF TXT records detected (${spfRecords.length}); RFC 7208 requires at most one.`,
      remediation: 'Merge all SPF mechanisms into a single v=spf1 TXT record.',
    });
  }

  // DMARC (45 pts)
  if (dmarcPolicy === 'reject') {
    score += 45;
  } else if (dmarcPolicy === 'quarantine') {
    score += 38;
  } else if (dmarcPolicy === 'none') {
    score += 18;
    findings.push({
      ruleId: 'DOM014',
      severity: 'MEDIUM',
      category: 'dns',
      message: 'DMARC record is in monitor-only mode (p=none).',
      remediation: 'Upgrade _dmarc TXT policy to p=quarantine or p=reject once legitimate senders pass alignment.',
    });
  } else {
    findings.push({
      ruleId: 'DOM014',
      severity: 'HIGH',
      category: 'dns',
      message: 'Missing DNS DMARC (_dmarc) TXT record.',
      remediation: 'Add a _dmarc TXT record (e.g., "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;").',
    });
  }

  // CAA (15 pts)
  if (hasCaa) {
    score += 15;
  } else {
    findings.push({
      ruleId: 'DOM015',
      severity: 'LOW',
      category: 'dns',
      message: 'No DNS CAA record found restricting which Certificate Authorities may issue TLS certificates.',
      remediation: 'Publish DNS CAA records permitting only your chosen Certificate Authority.',
    });
  }

  return {
    evaluated: true,
    score: Math.min(100, Math.max(0, score)),
    spf: { present: spfRecords.length > 0, count: spfRecords.length, policy: spfPolicy, record: spfRecord },
    dmarc: { present: dmarcRecords.length > 0, policy: dmarcPolicy, record: dmarcRecord },
    caa: { present: hasCaa, count: (dnsRaw.caaRecords || []).length },
    mx: { present: hasMx, count: (dnsRaw.mxRecords || []).length },
  };
}

function evaluateTlsSecurity(tlsRaw, findings) {
  if (!tlsRaw || !tlsRaw.reachable) {
    findings.push({
      ruleId: 'DOM009',
      severity: 'HIGH',
      category: 'tls',
      message: `TLS/HTTPS port 443 probe failed: ${tlsRaw?.error || 'unreachable'}.`,
      remediation: 'Enable valid HTTPS/TLS 1.2+ on port 443 with a trusted CA certificate.',
    });
    return {
      evaluated: false,
      reachable: false,
      score: 0,
      error: tlsRaw?.error || 'unreachable',
    };
  }

  let score = 100;
  if (!tlsRaw.authorized) {
    score -= 40;
    findings.push({
      ruleId: 'DOM009',
      severity: 'HIGH',
      category: 'tls',
      message: `TLS certificate failed trust verification (${tlsRaw.authorizationError || 'untrusted'}).`,
      remediation: 'Install a valid full-chain certificate issued by a publicly trusted CA.',
    });
  }
  if (tlsRaw.protocol && !/^TLSv1\.[23]$/i.test(tlsRaw.protocol)) {
    score -= 30;
    findings.push({
      ruleId: 'DOM010',
      severity: 'HIGH',
      category: 'tls',
      message: `Deprecated TLS protocol negotiated: ${tlsRaw.protocol}.`,
      remediation: 'Disable TLSv1.0/TLSv1.1 and enforce TLSv1.2 or TLSv1.3.',
    });
  }
  if (typeof tlsRaw.daysUntilExpiry === 'number') {
    if (tlsRaw.daysUntilExpiry < 0) {
      score -= 50;
      findings.push({
        ruleId: 'DOM009',
        severity: 'CRITICAL',
        category: 'tls',
        message: `TLS certificate expired ${Math.abs(tlsRaw.daysUntilExpiry)} days ago.`,
        remediation: 'Renew and deploy the TLS certificate immediately.',
      });
    } else if (tlsRaw.daysUntilExpiry < 14) {
      score -= 25;
      findings.push({
        ruleId: 'DOM009',
        severity: 'HIGH',
        category: 'tls',
        message: `TLS certificate expires in ${tlsRaw.daysUntilExpiry} days (< 14 days).`,
        remediation: 'Renew the certificate and enable automated ACME renewal.',
      });
    } else if (tlsRaw.daysUntilExpiry < 30) {
      score -= 10;
      findings.push({
        ruleId: 'DOM009',
        severity: 'MEDIUM',
        category: 'tls',
        message: `TLS certificate expires in ${tlsRaw.daysUntilExpiry} days (< 30 days).`,
        remediation: 'Verify automated certificate renewal before expiry.',
      });
    }
  }
  if (tlsRaw.sanMatched === false) {
    score -= 25;
    findings.push({
      ruleId: 'DOM009',
      severity: 'HIGH',
      category: 'tls',
      message: 'TLS certificate SAN/CN does not match the audited hostname.',
      remediation: 'Re-issue certificate including the exact target hostname in Subject Alternative Names.',
    });
  }

  return {
    evaluated: true,
    reachable: true,
    score: Math.max(0, Math.min(100, score)),
    authorized: tlsRaw.authorized,
    authorizationError: tlsRaw.authorizationError,
    protocol: tlsRaw.protocol,
    issuer: tlsRaw.issuer,
    subjectCN: tlsRaw.subjectCN,
    validFrom: tlsRaw.validFrom,
    validTo: tlsRaw.validTo,
    daysUntilExpiry: tlsRaw.daysUntilExpiry,
    sanMatched: tlsRaw.sanMatched,
  };
}

function evaluateHttpSecurity(homeResp, httpRedirectResp, findings) {
  if (!homeResp || homeResp.status === 0) {
    return {
      evaluated: false,
      reachable: false,
      httpChallengeDetected: false,
      statusCode: 0,
      score: null,
      headers: {},
      error: homeResp?.error || 'HTTP unreachable',
    };
  }

  const challenge = isWafChallengeResponse(homeResp.status, homeResp.headers, homeResp.text);
  const h = homeResp.headers || {};

  let httpRedirectsToHttps = null;
  if (httpRedirectResp && httpRedirectResp.status >= 300 && httpRedirectResp.status < 400) {
    const loc = String(httpRedirectResp.headers?.location || '');
    httpRedirectsToHttps = loc.toLowerCase().startsWith('https://');
  } else if (httpRedirectResp && httpRedirectResp.status > 0) {
    httpRedirectsToHttps = false;
  }

  // Graceful WAF degradation: keep real status & headers, but DO NOT tank overall score
  if (challenge) {
    return {
      evaluated: false,
      reachable: true,
      httpChallengeDetected: true,
      statusCode: homeResp.status,
      finalUrl: homeResp.finalUrl,
      httpRedirectsToHttps,
      score: null,
      note: 'Homepage returned WAF/bot-challenge status (403/429/503); HTTP header score excluded from overall denominator to prevent false penalties.',
      headers: {
        strictTransportSecurity: h['strict-transport-security'] || null,
        contentSecurityPolicy: h['content-security-policy'] || null,
        xFrameOptions: h['x-frame-options'] || null,
        xContentTypeOptions: h['x-content-type-options'] || null,
        referrerPolicy: h['referrer-policy'] || null,
        permissionsPolicy: h['permissions-policy'] || null,
        crossOriginOpenerPolicy: h['cross-origin-opener-policy'] || null,
      },
    };
  }

  let score = 0;

  // 1. HSTS (22 pts)
  const hsts = h['strict-transport-security'] || null;
  const maxAgeMatch = hsts ? hsts.match(/max-age\s*=\s*(\d+)/i) : null;
  const hstsMaxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  const hstsSubDomains = Boolean(hsts && /includeSubDomains/i.test(hsts));
  if (hsts && hstsMaxAge >= 31536000) {
    score += hstsSubDomains ? 22 : 18;
  } else if (hsts && hstsMaxAge > 0) {
    score += 10;
    findings.push({
      ruleId: 'DOM004',
      severity: 'LOW',
      category: 'http-security',
      message: `HSTS max-age (${hstsMaxAge}s) is below recommended 1 year (31536000s).`,
      remediation: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    });
  } else {
    findings.push({
      ruleId: 'DOM004',
      severity: 'MEDIUM',
      category: 'http-security',
      message: 'Missing Strict-Transport-Security (HSTS) header.',
      remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    });
  }

  // 2. CSP (22 pts)
  const csp = h['content-security-policy'] || null;
  const cspUnsafeInline = Boolean(csp && /'unsafe-inline'/i.test(csp));
  const cspUnsafeEval = Boolean(csp && /'unsafe-eval'/i.test(csp));
  if (csp && !cspUnsafeInline && !cspUnsafeEval) {
    score += 22;
  } else if (csp) {
    score += 12;
    findings.push({
      ruleId: 'DOM005',
      severity: 'MEDIUM',
      category: 'http-security',
      message: `Content-Security-Policy allows weak directive (${[cspUnsafeInline && 'unsafe-inline', cspUnsafeEval && 'unsafe-eval'].filter(Boolean).join(', ')}).`,
      remediation: 'Replace unsafe-inline/unsafe-eval with nonces or hashes in CSP.',
    });
  } else {
    findings.push({
      ruleId: 'DOM005',
      severity: 'MEDIUM',
      category: 'http-security',
      message: 'Missing Content-Security-Policy (CSP) header.',
      remediation: "Deploy a Content-Security-Policy header restricting script-src and frame-ancestors.",
    });
  }

  // 3. X-Content-Type-Options (12 pts)
  const xcto = h['x-content-type-options'] || null;
  if (xcto && xcto.toLowerCase().trim() === 'nosniff') {
    score += 12;
  } else {
    findings.push({
      ruleId: 'DOM006',
      severity: 'LOW',
      category: 'http-security',
      message: 'Missing X-Content-Type-Options: nosniff header.',
      remediation: 'Set X-Content-Type-Options: nosniff.',
    });
  }

  // 4. Clickjacking defense: X-Frame-Options or CSP frame-ancestors (12 pts)
  const xfo = h['x-frame-options'] || null;
  const hasFrameAncestors = Boolean(csp && /frame-ancestors\b/i.test(csp));
  if (xfo || hasFrameAncestors) {
    score += 12;
  } else {
    findings.push({
      ruleId: 'DOM006',
      severity: 'LOW',
      category: 'http-security',
      message: 'Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors).',
      remediation: 'Set X-Frame-Options: DENY (or SAMEORIGIN) and CSP frame-ancestors.',
    });
  }

  // 5. Referrer-Policy (10 pts)
  const refPol = h['referrer-policy'] || null;
  if (refPol) score += 10;

  // 6. Permissions-Policy (8 pts)
  const permPol = h['permissions-policy'] || null;
  if (permPol) score += 8;

  // 7. Cross-Origin-Opener-Policy (6 pts)
  const coop = h['cross-origin-opener-policy'] || null;
  if (coop) score += 6;

  // 8. HTTP -> HTTPS redirect (8 pts)
  if (httpRedirectsToHttps === true) {
    score += 8;
  } else if (httpRedirectsToHttps === false) {
    findings.push({
      ruleId: 'DOM008',
      severity: 'MEDIUM',
      category: 'http-security',
      message: 'Plain HTTP (port 80) does not automatically redirect to HTTPS.',
      remediation: 'Configure HTTP 301/308 redirect from http:// to https://.',
    });
  } else {
    score += 4; // Port 80 closed/unreachable (acceptable HTTPS-only)
  }

  // Penalty: dangerous CORS wildcard + credentials
  const acao = (h['access-control-allow-origin'] || '').trim();
  const acac = (h['access-control-allow-credentials'] || '').trim().toLowerCase();
  const dangerousCors = acao === '*' && acac === 'true';
  if (dangerousCors) {
    score -= 25;
    findings.push({
      ruleId: 'DOM007',
      severity: 'CRITICAL',
      category: 'http-security',
      message: 'Dangerous CORS misconfiguration: Access-Control-Allow-Origin: * combined with Allow-Credentials: true.',
      remediation: 'Restrict Access-Control-Allow-Origin to explicit trusted origins when credentials are enabled.',
    });
  }

  // Penalty: server version fingerprint leak
  const serverHdr = h['server'] || null;
  const poweredBy = h['x-powered-by'] || null;
  const serverVersionLeak = Boolean((serverHdr && /\/\d+\.\d+/.test(serverHdr)) || poweredBy);
  if (serverVersionLeak) {
    score -= 5;
    findings.push({
      ruleId: 'DOM008',
      severity: 'LOW',
      category: 'http-security',
      message: `Server software version fingerprint exposed (${[serverHdr, poweredBy].filter(Boolean).join(' / ')}).`,
      remediation: 'Suppress X-Powered-By and strip version numbers from the Server header.',
    });
  }

  return {
    evaluated: true,
    reachable: true,
    httpChallengeDetected: false,
    statusCode: homeResp.status,
    finalUrl: homeResp.finalUrl,
    httpRedirectsToHttps,
    dangerousCors,
    serverVersionLeak,
    score: Math.max(0, Math.min(100, score)),
    headers: {
      strictTransportSecurity: hsts,
      hstsMaxAge,
      contentSecurityPolicy: csp ? csp.slice(0, 512) : null,
      xFrameOptions: xfo,
      xContentTypeOptions: xcto,
      referrerPolicy: refPol,
      permissionsPolicy: permPol ? permPol.slice(0, 256) : null,
      crossOriginOpenerPolicy: coop,
      server: serverHdr,
      xPoweredBy: poweredBy,
    },
  };
}

function evaluateAiReadiness({
  robotsResp,
  llmsResp,
  llmsFullResp,
  sitemapResp,
  agentJsonResp,
  mcpJsonResp,
  homeResp,
  findings,
}) {
  // 1. robots.txt (30 pts)
  let robotsInfo = { present: false, statusCode: robotsResp?.status || 0, challengeBlocked: false, parsed: null };
  if (robotsResp && robotsResp.status >= 200 && robotsResp.status < 300 && !isSoft404Html(robotsResp.headers, robotsResp.text)) {
    const parsed = parseRobotsTxt(robotsResp.text);
    robotsInfo = {
      present: true,
      statusCode: robotsResp.status,
      challengeBlocked: false,
      sitemaps: parsed.sitemaps,
      allowedCount: parsed.allowedCount,
      blockedCount: parsed.blockedCount,
      totalBots: parsed.totalBots,
      crawlerMatrix: parsed.crawlerMatrix,
    };
  } else if (robotsResp && isWafChallengeResponse(robotsResp.status, robotsResp.headers, robotsResp.text)) {
    robotsInfo = { present: false, statusCode: robotsResp.status, challengeBlocked: true, crawlerMatrix: {} };
  } else {
    // No robots.txt means all crawlers allowed by default (RFC 9309)
    const defaultMatrix = {};
    for (const bot of AI_CRAWLERS) {
      defaultMatrix[bot] = { bot, status: 'allowed', matchedBy: 'no-robots-txt', matchedRule: null };
    }
    robotsInfo = {
      present: false,
      statusCode: robotsResp?.status || 0,
      challengeBlocked: false,
      sitemaps: [],
      allowedCount: AI_CRAWLERS.length,
      blockedCount: 0,
      totalBots: AI_CRAWLERS.length,
      crawlerMatrix: defaultMatrix,
    };
  }

  // 2. /llms.txt & /llms-full.txt (25 pts)
  const analyzeLlms = (resp) => {
    if (!resp || resp.status < 200 || resp.status >= 300) {
      return { present: false, statusCode: resp?.status || 0, soft404Html: false, bytes: 0 };
    }
    if (isSoft404Html(resp.headers, resp.text)) {
      return { present: false, statusCode: resp.status, soft404Html: true, bytes: 0 };
    }
    const text = resp.text || '';
    const hasH1 = /^#\s+\S+/m.test(text);
    const linkCount = (text.match(/\[[^\]]+\]\(https?:\/\/[^)]+\)/g) || []).length;
    return {
      present: text.trim().length > 0,
      statusCode: resp.status,
      soft404Html: false,
      bytes: resp.bytes,
      hasH1,
      linkCount,
      truncated: resp.truncated,
    };
  };
  const llmsTxt = analyzeLlms(llmsResp);
  const llmsFullTxt = analyzeLlms(llmsFullResp);

  // 3. /sitemap.xml (15 pts)
  let sitemap = { present: false, statusCode: sitemapResp?.status || 0, urlCount: 0, sitemapIndexCount: 0 };
  if (sitemapResp && sitemapResp.status >= 200 && sitemapResp.status < 300 && !isSoft404Html(sitemapResp.headers, sitemapResp.text)) {
    const body = sitemapResp.text || '';
    const looksXml = /<(urlset|sitemapindex)\b/i.test(body) || body.trimStart().startsWith('<?xml');
    if (looksXml) {
      const urlCount = (body.match(/<url\b/gi) || []).length;
      const sitemapIndexCount = (body.match(/<sitemap\b/gi) || []).length;
      sitemap = {
        present: true,
        statusCode: sitemapResp.status,
        urlCount,
        sitemapIndexCount,
        truncated: sitemapResp.truncated,
      };
    }
  }

  // 4. /.well-known/agent.json & /.well-known/mcp.json (10 pts)
  const analyzeJsonWellKnown = (resp) => {
    if (!resp || resp.status < 200 || resp.status >= 300 || isSoft404Html(resp.headers, resp.text)) {
      return { present: false, statusCode: resp?.status || 0 };
    }
    try {
      const obj = JSON.parse(resp.text);
      if (obj && typeof obj === 'object') {
        return {
          present: true,
          statusCode: resp.status,
          name: typeof obj.name === 'string' ? obj.name : null,
          version: typeof obj.version === 'string' ? obj.version : null,
        };
      }
    } catch {
      // not valid JSON
    }
    return { present: false, statusCode: resp.status, invalidJson: true };
  };
  const agentCard = analyzeJsonWellKnown(agentJsonResp);
  const mcpDiscovery = analyzeJsonWellKnown(mcpJsonResp);

  // 5. Homepage HTML SEO + JSON-LD (20 pts)
  const homeOk = Boolean(homeResp && homeResp.status >= 200 && homeResp.status < 400 && !isWafChallengeResponse(homeResp.status, homeResp.headers, homeResp.text));
  const seo = homeOk ? parseHomepageSeoAndSchema(homeResp.text) : null;

  const allHttpChallenged =
    Boolean(homeResp && isWafChallengeResponse(homeResp.status, homeResp.headers, homeResp.text)) &&
    robotsInfo.challengeBlocked &&
    !llmsTxt.present &&
    !sitemap.present &&
    !agentCard.present &&
    !mcpDiscovery.present;

  const llmsBlockedOrUnreachable =
    !llmsResp || llmsResp.status === 0 || isWafChallengeResponse(llmsResp.status, llmsResp.headers, llmsResp.text);
  const sitemapBlockedOrUnreachable =
    !sitemapResp || sitemapResp.status === 0 || isWafChallengeResponse(sitemapResp.status, sitemapResp.headers, sitemapResp.text);

  let score = 0;
  // Robots AI crawler accessibility (30 pts)
  if (!robotsInfo.challengeBlocked) {
    const ratio = robotsInfo.totalBots > 0 ? robotsInfo.allowedCount / robotsInfo.totalBots : 1;
    score += Math.round(ratio * 24) + (robotsInfo.present ? 6 : 3);
    if (robotsInfo.blockedCount > 0) {
      findings.push({
        ruleId: 'DOM001',
        severity: robotsInfo.blockedCount >= 6 ? 'MEDIUM' : 'LOW',
        category: 'ai-readiness',
        message: `robots.txt blocks ${robotsInfo.blockedCount}/${robotsInfo.totalBots} major AI crawlers (${Object.values(robotsInfo.crawlerMatrix).filter((c) => c.status === 'blocked').map((c) => c.bot).join(', ')}).`,
        remediation: 'Review robots.txt rules if you want your site cited by ChatGPT Search, Claude, Perplexity, and AI agents.',
      });
    }
  } else {
    score += 15; // Neutral when WAF blocks robots.txt
  }

  // llms.txt (25 pts)
  if (llmsTxt.present) {
    score += 18 + (llmsTxt.hasH1 ? 4 : 0) + (llmsFullTxt.present ? 3 : 0);
  } else if (!llmsBlockedOrUnreachable && !allHttpChallenged) {
    findings.push({
      ruleId: 'DOM002',
      severity: 'LOW',
      category: 'ai-readiness',
      message: 'Missing /llms.txt AI discovery manifest.',
      remediation: 'Publish /llms.txt with an H1 summary and curated Markdown links to key documentation/product pages.',
    });
  }

  // Sitemap (15 pts)
  if (sitemap.present) {
    score += 15;
  } else if (!sitemapBlockedOrUnreachable && !allHttpChallenged) {
    findings.push({
      ruleId: 'DOM003',
      severity: 'LOW',
      category: 'ai-readiness',
      message: 'No valid XML /sitemap.xml detected.',
      remediation: 'Publish an XML sitemap at /sitemap.xml and declare it in /robots.txt.',
    });
  }

  // Agent discovery endpoints (10 pts)
  if (agentCard.present || mcpDiscovery.present) {
    score += 10;
  }

  // Homepage SEO + JSON-LD (20 pts)
  if (seo) {
    if (seo.hasTitle) score += 5;
    if (seo.hasDescription) score += 4;
    if (seo.hasCanonical) score += 3;
    if (seo.openGraph.hasTitle || seo.openGraph.hasDescription) score += 3;
    if (seo.jsonLdTypes.length > 0) {
      score += 5;
    } else {
      findings.push({
        ruleId: 'DOM016',
        severity: 'LOW',
        category: 'ai-readiness',
        message: 'Homepage lacks JSON-LD schema.org structured data.',
        remediation: 'Add <script type="application/ld+json"> (Organization, WebSite, Product, FAQPage) to improve AI citation accuracy.',
      });
    }
  } else {
    // Do not penalize missing HTML metadata when homepage was WAF-challenged
    score = Math.round((score / 80) * 100);
  }

  const anyProbeResponded =
    !allHttpChallenged &&
    ((robotsResp?.status || 0) > 0 ||
      (llmsResp?.status || 0) > 0 ||
      (sitemapResp?.status || 0) > 0 ||
      (homeResp?.status || 0) > 0);

  return {
    evaluated: anyProbeResponded,
    challengeBlocked: allHttpChallenged,
    score: anyProbeResponded ? Math.max(0, Math.min(100, score)) : null,
    robotsTxt: robotsInfo,
    llmsTxt,
    llmsFullTxt,
    sitemap,
    agentCard,
    mcpDiscovery,
    seo,
  };
}

function evaluateSecurityTxt(secResp, findings) {
  if (!secResp || secResp.status === 0) {
    return {
      evaluated: false,
      present: false,
      statusCode: 0,
      score: null,
    };
  }
  if (isWafChallengeResponse(secResp.status, secResp.headers, secResp.text)) {
    return {
      evaluated: false,
      present: false,
      challengeBlocked: true,
      statusCode: secResp.status,
      score: null,
    };
  }
  if (secResp.status < 200 || secResp.status >= 300 || isSoft404Html(secResp.headers, secResp.text)) {
    findings.push({
      ruleId: 'DOM017',
      severity: 'LOW',
      category: 'security-txt',
      message: 'Missing RFC 9116 /.well-known/security.txt disclosure file.',
      remediation: 'Publish /.well-known/security.txt with Contact: and future Expires: fields.',
    });
    return {
      evaluated: true,
      present: false,
      statusCode: secResp.status,
      score: 0,
    };
  }

  const text = secResp.text || '';
  const contacts = [...text.matchAll(/^Contact:\s*(.+)$/gim)].map((m) => m[1].trim());
  const expiresMatch = text.match(/^Expires:\s*(.+)$/im);
  const expires = expiresMatch ? expiresMatch[1].trim() : null;
  let expired = false;
  if (expires) {
    const ts = Date.parse(expires);
    if (Number.isFinite(ts) && ts < Date.now()) expired = true;
  }

  let score = 40;
  if (contacts.length > 0) score += 35;
  if (expires && !expired) score += 25;
  if (expired) {
    findings.push({
      ruleId: 'DOM018',
      severity: 'LOW',
      category: 'security-txt',
      message: `/.well-known/security.txt Expires date (${expires}) is in the past.`,
      remediation: 'Update Expires: in /.well-known/security.txt to a valid future ISO-8601 timestamp.',
    });
  }

  return {
    evaluated: true,
    present: true,
    statusCode: secResp.status,
    contacts,
    expires,
    expired,
    score: Math.min(100, score),
  };
}

/**
 * Audits a single domain/URL across all 5 pillars with strict SSRF protection and WAF degradation.
 */
export async function auditDomain(
  rawTarget,
  {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_RESPONSE_BYTES,
    fetchImpl = globalThis.fetch,
    lookupImpl = (host, opts) => dns.lookup(host, opts),
    tlsProbeImpl = defaultTlsProbe,
    dnsProbeImpl = defaultDnsProbe,
  } = {}
) {
  const startedAt = Date.now();
  let target;
  try {
    target = normalizeTargetInput(rawTarget);
  } catch (err) {
    return {
      schemaVersion: 1,
      auditorVersion: AUDITOR_VERSION,
      input: String(rawTarget ?? ''),
      domain: null,
      status: 'rejected',
      billable: false,
      errorCode: err.code || 'INVALID_TARGET',
      error: err.message,
      durationMs: Math.max(1, Date.now() - startedAt),
    };
  }

  // Upfront DNS + SSRF validation before launching any network probe
  let safeNet;
  try {
    safeNet = await assertSafeUrl(target.httpsUrl, { lookupImpl });
  } catch (err) {
    if (err instanceof SsrfBlockedError || err instanceof InvalidTargetError) {
      return {
        schemaVersion: 1,
        auditorVersion: AUDITOR_VERSION,
        input: target.input,
        domain: target.hostname,
        status: 'rejected',
        billable: false,
        errorCode: err.code || 'SSRF_BLOCKED',
        error: err.message,
        durationMs: Math.max(1, Date.now() - startedAt),
      };
    }
    // NXDOMAIN or DNS resolution failure -> unreachable, 0 billable!
    return {
      schemaVersion: 1,
      auditorVersion: AUDITOR_VERSION,
      input: target.input,
      domain: target.hostname,
      status: 'unreachable',
      billable: false,
      errorCode: err.code || 'DNS_LOOKUP_FAILED',
      error: err.message,
      durationMs: Math.max(1, Date.now() - startedAt),
    };
  }

  const fetchOpts = { timeoutMs, maxBytes, fetchImpl, lookupImpl };
  const safeCallFetch = async (url, extra = {}) => {
    try {
      return await safeFetch(url, { ...fetchOpts, ...extra });
    } catch (err) {
      if (err instanceof SsrfBlockedError) {
        return { ok: false, status: 0, headers: {}, text: '', bytes: 0, truncated: false, ssrfBlocked: true, error: err.message };
      }
      return { ok: false, status: 0, headers: {}, text: '', bytes: 0, truncated: false, error: err.message };
    }
  };

  const primaryIp = safeNet.addresses[0]?.address || target.hostname;

  // Run all independent probes concurrently via Promise.allSettled for <2.5s latency and crash-safety
  const settled = await Promise.allSettled([
    safeCallFetch(target.httpsUrl, { accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }),
    safeCallFetch(target.httpUrl, { followRedirects: false }),
    safeCallFetch(`${target.origin}/robots.txt`, { accept: 'text/plain,*/*' }),
    safeCallFetch(`${target.origin}/llms.txt`, { accept: 'text/markdown,text/plain,*/*' }),
    safeCallFetch(`${target.origin}/llms-full.txt`, { accept: 'text/markdown,text/plain,*/*' }),
    safeCallFetch(`${target.origin}/sitemap.xml`, { accept: 'application/xml,text/xml,*/*' }),
    safeCallFetch(`${target.origin}/.well-known/agent.json`, { accept: 'application/json,*/*' }),
    safeCallFetch(`${target.origin}/.well-known/mcp.json`, { accept: 'application/json,*/*' }),
    safeCallFetch(`${target.origin}/.well-known/security.txt`, { accept: 'text/plain,*/*' }),
    tlsProbeImpl(target.hostname, primaryIp, { timeoutMs }),
    withTimeoutFallback(
      () => dnsProbeImpl(target.hostname, { timeoutMs }),
      timeoutMs,
      { txtRecords: [], dmarcTxtRecords: [], caaRecords: [], mxRecords: [], anyDnsSucceeded: false, timedOut: true }
    ),
  ]);

  const valOr = (entry, fallback) => (entry.status === 'fulfilled' ? entry.value : fallback);
  const emptyHttp = { ok: false, status: 0, headers: {}, text: '', bytes: 0, truncated: false, error: 'probe failed' };
  const homeResp = valOr(settled[0], emptyHttp);
  const httpRedirectResp = valOr(settled[1], emptyHttp);
  const robotsResp = valOr(settled[2], emptyHttp);
  const llmsResp = valOr(settled[3], emptyHttp);
  const llmsFullResp = valOr(settled[4], emptyHttp);
  const sitemapResp = valOr(settled[5], emptyHttp);
  const agentJsonResp = valOr(settled[6], emptyHttp);
  const mcpJsonResp = valOr(settled[7], emptyHttp);
  const secTxtResp = valOr(settled[8], emptyHttp);
  const tlsRaw = valOr(settled[9], { reachable: false, error: 'TLS probe rejected' });
  const dnsRaw = valOr(settled[10], { txtRecords: [], dmarcTxtRecords: [], caaRecords: [], mxRecords: [], anyDnsSucceeded: false });

  // If homepage redirected to an SSRF target and was blocked, abort as rejected (0 billable)
  if (homeResp?.ssrfBlocked) {
    return {
      schemaVersion: 1,
      auditorVersion: AUDITOR_VERSION,
      input: target.input,
      domain: target.hostname,
      status: 'rejected',
      billable: false,
      errorCode: 'SSRF_REDIRECT_BLOCKED',
      error: homeResp.error,
      durationMs: Math.max(1, Date.now() - startedAt),
    };
  }

  // If robots.txt declares a custom sitemap and /sitemap.xml was absent, probe the first declared sitemap
  let finalSitemapResp = sitemapResp;
  if (
    (!sitemapResp || sitemapResp.status < 200 || sitemapResp.status >= 300 || isSoft404Html(sitemapResp.headers, sitemapResp.text)) &&
    robotsResp &&
    robotsResp.status >= 200 &&
    robotsResp.status < 300 &&
    !isSoft404Html(robotsResp.headers, robotsResp.text)
  ) {
    const parsedRobots = parseRobotsTxt(robotsResp.text);
    const altSitemap = parsedRobots.sitemaps.find((u) => /^https?:\/\//i.test(u));
    if (altSitemap && altSitemap !== `${target.origin}/sitemap.xml`) {
      const altResp = await safeCallFetch(altSitemap, { accept: 'application/xml,text/xml,*/*' });
      if (altResp && !altResp.ssrfBlocked && altResp.status >= 200 && altResp.status < 300) {
        finalSitemapResp = altResp;
      }
    }
  }

  const homeChallenge = homeResp && homeResp.status > 0 && isWafChallengeResponse(homeResp.status, homeResp.headers, homeResp.text);
  const robotsUsable =
    robotsResp && robotsResp.status >= 200 && robotsResp.status < 300 && !isSoft404Html(robotsResp.headers, robotsResp.text);
  const anyUsableHttp = ((homeResp?.status || 0) > 0 && !homeChallenge) || Boolean(robotsUsable);
  const anyTlsSucceeded = Boolean(tlsRaw?.reachable);
  const anyDnsSucceeded = Boolean(dnsRaw?.anyDnsSucceeded);

  // Spec & pre-audit rule: if WAF-only (no DNS & no TLS) OR DNS + TLS + HTTP are ALL unreachable -> fail with 0 charge
  if (!anyUsableHttp && !anyTlsSucceeded && !anyDnsSucceeded) {
    return {
      schemaVersion: 1,
      auditorVersion: AUDITOR_VERSION,
      input: target.input,
      domain: target.hostname,
      status: 'unreachable',
      billable: false,
      httpChallengeDetected: Boolean(homeChallenge),
      errorCode: homeChallenge ? 'WAF_BLOCKED_NO_SIGNAL' : 'TARGET_UNREACHABLE',
      error: homeChallenge
        ? 'Homepage was WAF-challenged and neither DNS nor TLS probes yielded audit data (0 charge).'
        : 'DNS, TLS, and HTTP probes all failed for this domain.',
      durationMs: Math.max(1, Date.now() - startedAt),
    };
  }

  const findings = [];
  const aiReadiness = evaluateAiReadiness({
    robotsResp,
    llmsResp,
    llmsFullResp,
    sitemapResp: finalSitemapResp,
    agentJsonResp,
    mcpJsonResp,
    homeResp,
    findings,
  });
  const httpSecurity = evaluateHttpSecurity(homeResp, httpRedirectResp, findings);
  const tlsSecurity = evaluateTlsSecurity(tlsRaw, findings);
  const dnsSecurity = anyDnsSucceeded
    ? evaluateDnsSecurity(dnsRaw, findings)
    : { evaluated: false, score: null, spf: { present: false }, dmarc: { present: false }, caa: { present: false }, mx: { present: false } };
  const securityTxt = evaluateSecurityTxt(secTxtResp, findings);

  // Weighted average across ONLY evaluated pillars (prevents WAF 403/429 false 0-score penalties)
  const pillars = { aiReadiness, httpSecurity, tlsSecurity, dnsSecurity, securityTxt };
  let weightedSum = 0;
  let weightDenominator = 0;
  for (const [key, weight] of Object.entries(PILLAR_WEIGHTS)) {
    const p = pillars[key];
    if (p && p.evaluated && typeof p.score === 'number') {
      weightedSum += p.score * weight;
      weightDenominator += weight;
    }
  }
  const overallScore = weightDenominator > 0 ? Math.round(weightedSum / weightDenominator) : 0;
  const grade = scoreToGrade(overallScore);

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, total: findings.length };
  for (const f of findings) {
    if (Object.prototype.hasOwnProperty.call(summary, f.severity)) summary[f.severity]++;
  }

  return {
    schemaVersion: 1,
    auditorVersion: AUDITOR_VERSION,
    input: target.input,
    domain: target.hostname,
    url: target.httpsUrl,
    status: 'audited',
    billable: true,
    overallScore,
    grade,
    aiReadinessScore: aiReadiness.score,
    httpSecurityScore: httpSecurity.score,
    tlsScore: tlsSecurity.evaluated ? tlsSecurity.score : null,
    dnsScore: dnsSecurity.score,
    httpChallengeDetected: Boolean(httpSecurity.httpChallengeDetected),
    hasLlmsTxt: Boolean(aiReadiness.llmsTxt?.present),
    aiBotsAllowed: aiReadiness.robotsTxt?.allowedCount ?? null,
    aiBotsTotal: AI_CRAWLERS.length,
    dmarcPolicy: dnsSecurity.dmarc?.policy || 'unknown',
    spfPolicy: dnsSecurity.spf?.policy || 'unknown',
    tlsDaysUntilExpiry: tlsSecurity.daysUntilExpiry ?? null,
    findingSummary: summary,
    findings,
    pillars,
    durationMs: Math.max(1, Date.now() - startedAt),
  };
}

/**
 * Concurrency-bounded bulk domain auditor (max 100 domains, concurrency <= 5).
 */
export async function auditBatchDomains(
  urls,
  {
    concurrency = MAX_CONCURRENCY,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_RESPONSE_BYTES,
    fetchImpl = globalThis.fetch,
    lookupImpl = (host, opts) => dns.lookup(host, opts),
    tlsProbeImpl = defaultTlsProbe,
    dnsProbeImpl = defaultDnsProbe,
    auditDomainImpl = auditDomain,
    canStartNext = null,
    onResult = null,
  } = {}
) {
  if (!Array.isArray(urls) || urls.length === 0) {
    throw new InvalidTargetError('Provide a non-empty "urls" array of domains or URLs.');
  }
  if (urls.length > MAX_BATCH_URLS) {
    const err = new InvalidTargetError(
      `Batch size exceeds maximum limit (${urls.length} > ${MAX_BATCH_URLS} domains).`,
      'BATCH_TOO_LARGE'
    );
    err.statusCode = 413;
    throw err;
  }

  const effectiveConcurrency = Math.max(1, Math.min(MAX_CONCURRENCY, Math.floor(Number(concurrency) || MAX_CONCURRENCY)));
  const results = new Array(urls.length);
  let nextIndex = 0;
  let stoppedEarly = false;

  const worker = async () => {
    while (true) {
      if (stoppedEarly) return;
      if (typeof canStartNext === 'function' && !canStartNext()) {
        stoppedEarly = true;
        return;
      }
      const idx = nextIndex++;
      if (idx >= urls.length) return;
      const target = urls[idx];
      const res = await auditDomainImpl(target, {
        timeoutMs,
        maxBytes,
        fetchImpl,
        lookupImpl,
        tlsProbeImpl,
        dnsProbeImpl,
      });
      results[idx] = res;
      if (typeof onResult === 'function') {
        const keepGoing = await onResult(res, idx);
        if (keepGoing === false) {
          stoppedEarly = true;
          return;
        }
      }
    }
  };

  const workers = Array.from({ length: Math.min(effectiveConcurrency, urls.length) }, () => worker());
  await Promise.all(workers);

  return {
    results: results.filter((r) => r !== undefined),
    stoppedEarly,
  };
}

export function domainReportToMarkdown(report) {
  if (!report || report.status !== 'audited') {
    return `### AgentReady & WebSec Audit — ${report?.domain || report?.input || 'unknown'}\n\n- **Status**: \`${report?.status || 'error'}\`\n- **Reason**: ${report?.error || 'Unavailable'}\n`;
  }
  const httpStatus = report.pillars?.httpSecurity?.statusCode ?? 'WAF';
  const tlsProto = report.pillars?.tlsSecurity?.protocol || 'N/A';
  const sum = report.findingSummary || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const lines = [
    `### AgentReady & WebSec Audit — \`${report.domain}\``,
    '',
    `| Metric | Value |`,
    `|---|---|`,
    `| **Overall Score** | **${report.overallScore}/100 (Grade ${report.grade})** |`,
    `| **AI Readiness / GEO** | ${report.aiReadinessScore ?? 'N/A'}/100 (\`/llms.txt\`: ${report.hasLlmsTxt ? 'Yes' : 'No'}, AI Bots Allowed: ${report.aiBotsAllowed ?? 'N/A'}/${report.aiBotsTotal ?? 12}) |`,
    `| **HTTP Security Headers** | ${report.httpChallengeDetected ? `WAF Challenge (HTTP ${httpStatus}, excluded)` : `${report.httpSecurityScore ?? 'N/A'}/100`} |`,
    `| **TLS / SSL** | ${report.tlsScore ?? 'N/A'}/100 (${tlsProto}, expires in ${report.tlsDaysUntilExpiry ?? 'N/A'}d) |`,
    `| **DNS Email Auth** | ${report.dnsScore ?? 'N/A'}/100 (SPF: \`${report.spfPolicy || 'unknown'}\`, DMARC: \`${report.dmarcPolicy || 'unknown'}\`) |`,
    `| **Findings** | CRITICAL: ${sum.CRITICAL}, HIGH: ${sum.HIGH}, MEDIUM: ${sum.MEDIUM}, LOW: ${sum.LOW} |`,
  ];
  if (findings.length > 0) {
    lines.push('', '#### Key Findings');
    for (const f of findings.slice(0, 12)) {
      lines.push(`- **[${f.severity}] \`${f.ruleId}\`**: ${f.message}`);
    }
  }
  return lines.join('\n') + '\n';
}
