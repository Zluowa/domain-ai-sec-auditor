/**
 * ssrf-guard.mjs — Deterministic SSRF Protection & Bounded Streaming Fetcher (v1.0.0)
 * Zero external dependencies (Node.js 22+/24+).
 *
 * Protections:
 *  - Allows ONLY http: and https: protocols, standard ports (80/443 or omitted), no credentials
 *  - Rejects localhost, *.localhost, *.local, *.internal, cloud metadata hostnames
 *  - Resolves ALL A/AAAA records via dns.lookup({ all: true }) and blocks ANY private, loopback,
 *    link-local, CGNAT, cloud-metadata, multicast, reserved, IPv4-mapped IPv6, or NAT64 address
 *  - Handles redirects manually (max 3 hops), re-validating SSRF + DNS on EVERY hop
 *  - Enforces strict per-request timeout (default 4000ms) and streaming body cap (default 256 KiB)
 */

import dns from 'node:dns/promises';
import net from 'node:net';

export const DEFAULT_TIMEOUT_MS = 4000;
export const MAX_RESPONSE_BYTES = 256 * 1024; // 256 KiB hard OOM cap
export const MAX_REDIRECTS = 3;

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.lan', '.corp'];

export class SsrfBlockedError extends Error {
  constructor(message, code = 'SSRF_BLOCKED') {
    super(message);
    this.name = 'SsrfBlockedError';
    this.code = code;
    this.statusCode = 400;
  }
}

export class InvalidTargetError extends Error {
  constructor(message, code = 'INVALID_TARGET') {
    super(message);
    this.name = 'InvalidTargetError';
    this.code = code;
    this.statusCode = 400;
  }
}

function parseIpv4ToUint32(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = ((value << 8) | n) >>> 0;
  }
  return value;
}

function inIpv4Cidr(ipUint, baseIp, prefixLen) {
  const baseUint = parseIpv4ToUint32(baseIp);
  if (baseUint === null) return false;
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (ipUint & mask) === (baseUint & mask);
}

const BLOCKED_IPV4_CIDRS = [
  ['0.0.0.0', 8],       // "This" network
  ['10.0.0.0', 8],      // RFC 1918 private
  ['100.64.0.0', 10],   // RFC 6598 CGNAT / Tailscale
  ['127.0.0.0', 8],     // Loopback
  ['169.254.0.0', 16],  // Link-local & AWS/GCP/Azure metadata (169.254.169.254)
  ['172.16.0.0', 12],   // RFC 1918 private
  ['192.0.0.0', 24],    // IETF protocol assignments
  ['192.0.2.0', 24],    // TEST-NET-1
  ['192.88.99.0', 24],  // 6to4 relay anycast
  ['192.168.0.0', 16],  // RFC 1918 private
  ['198.18.0.0', 15],   // Benchmark testing
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24],  // TEST-NET-3
  ['224.0.0.0', 4],     // Multicast
  ['240.0.0.0', 4],     // Reserved / Broadcast
];

export function isBlockedIpv4(ip) {
  const u = parseIpv4ToUint32(ip);
  if (u === null) return true; // Fail closed on unparseable IPv4
  for (const [base, prefix] of BLOCKED_IPV4_CIDRS) {
    if (inIpv4Cidr(u, base, prefix)) return true;
  }
  return false;
}

/**
 * Expands any valid IPv6 string (including IPv4-embedded suffix like ::ffff:127.0.0.1)
 * into an array of eight 16-bit unsigned integers.
 */
function expandIpv6Groups(rawIp) {
  const ip = rawIp.split('%')[0].toLowerCase().trim();
  if (!ip) return null;

  let working = ip;
  // Convert trailing embedded IPv4 (e.g., ::ffff:169.254.169.254) into two hex groups
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4Part = working.slice(lastColon + 1);
    const v4Uint = parseIpv4ToUint32(v4Part);
    if (v4Uint === null) return null;
    const hi = ((v4Uint >>> 16) & 0xffff).toString(16);
    const lo = (v4Uint & 0xffff).toString(16);
    working = `${working.slice(0, lastColon)}:${hi}:${lo}`;
  }

  const halves = working.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':').filter((s) => s.length > 0) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter((s) => s.length > 0) : [];

  let groups;
  if (halves.length === 2) {
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }

  const nums = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    nums.push(parseInt(g, 16));
  }
  return nums.length === 8 ? nums : null;
}

export function isBlockedIpv6(ip) {
  const g = expandIpv6Groups(ip);
  if (!g) return true; // Fail closed

  const allZero = g.every((n) => n === 0);
  if (allZero) return true; // :: unspecified

  // ::1 loopback
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1) {
    return true;
  }

  // ::ffff:0:0/96 IPv4-mapped IPv6 and ::/96 IPv4-compatible IPv6
  const isV4Mapped =
    g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0x0000);
  if (isV4Mapped) {
    const v4 = `${(g[6] >>> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >>> 8) & 0xff}.${g[7] & 0xff}`;
    return isBlockedIpv4(v4);
  }

  // ::ffff:0:0:0/96 SIIT IPv4-translated (RFC 2765) -> inspect embedded IPv4
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0xffff && g[5] === 0x0000) {
    const v4 = `${(g[6] >>> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >>> 8) & 0xff}.${g[7] & 0xff}`;
    return isBlockedIpv4(v4);
  }

  // 64:ff9b::/96 NAT64 well-known prefix (RFC 6052) -> inspect embedded IPv4
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    const v4 = `${(g[6] >>> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >>> 8) & 0xff}.${g[7] & 0xff}`;
    return isBlockedIpv4(v4);
  }

  // 64:ff9b:1::/48 NAT64 local-use prefix (RFC 8215) -> always block
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0x0001) {
    return true;
  }

  // 2002::/16 6to4 (RFC 3056) -> inspect embedded IPv4 in g[1], g[2]
  if (g[0] === 0x2002) {
    const v4 = `${(g[1] >>> 8) & 0xff}.${g[1] & 0xff}.${(g[2] >>> 8) & 0xff}.${g[2] & 0xff}`;
    if (isBlockedIpv4(v4)) return true;
  }

  // 2001:0000::/32 Teredo tunneling (RFC 4380) -> always block
  if (g[0] === 0x2001 && g[1] === 0x0000) {
    return true;
  }

  // fc00::/7 Unique Local Addresses (fc00..fdff)
  if ((g[0] & 0xfe00) === 0xfc00) return true;
  // fe80::/10 Link-Local (fe80..febf)
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  // fec0::/10 Site-Local deprecated
  if ((g[0] & 0xffc0) === 0xfec0) return true;
  // ff00::/8 Multicast
  if ((g[0] & 0xff00) === 0xff00) return true;
  // 2001:db8::/32 Documentation
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true;
  // 100::/64 Discard-Only
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;

  return false;
}

export function isBlockedIpAddress(ip) {
  const clean = String(ip || '').trim().replace(/^\[|\]$/g, '');
  const kind = net.isIP(clean);
  if (kind === 4) return isBlockedIpv4(clean);
  if (kind === 6) return isBlockedIpv6(clean);
  return true;
}

export function isBlockedHostname(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (BLOCKED_HOSTNAMES.has(h)) return true;
  for (const suffix of BLOCKED_SUFFIXES) {
    if (h.endsWith(suffix)) return true;
  }
  return false;
}

/**
 * Normalizes a raw domain or URL input into canonical https/http targets.
 * Strictly allows only standard ports (80/443) and http/https schemes.
 */
export function normalizeTargetInput(raw) {
  if (typeof raw !== 'string') {
    throw new InvalidTargetError('Target URL/domain must be a string.');
  }
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048 || /[\s\r\n\t]/.test(trimmed)) {
    throw new InvalidTargetError(`Invalid target URL/domain: "${trimmed.slice(0, 80)}".`);
  }

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    // Reject sneaky scheme prefixes like javascript:, file:, ftp:
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
      throw new InvalidTargetError(`Unsupported URL scheme in target: "${trimmed}".`);
    }
    candidate = `https://${candidate}`;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new InvalidTargetError(`Malformed URL/domain: "${trimmed}".`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new InvalidTargetError(`Unsupported protocol "${parsed.protocol}". Only http: and https: are allowed.`);
  }
  if (parsed.username || parsed.password) {
    throw new SsrfBlockedError('URLs with embedded credentials are not allowed.', 'SSRF_CREDENTIALS_BLOCKED');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    throw new SsrfBlockedError(
      `Non-standard port "${parsed.port}" is blocked (only default 80/443 permitted).`,
      'SSRF_PORT_BLOCKED'
    );
  }

  const rawHost = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!rawHost) {
    throw new InvalidTargetError(`Missing hostname in target: "${trimmed}".`);
  }
  if (isBlockedHostname(rawHost)) {
    throw new SsrfBlockedError(`Blocked internal/reserved hostname "${rawHost}".`, 'SSRF_HOST_BLOCKED');
  }

  const unbracketed = rawHost.replace(/^\[|\]$/g, '');
  const ipKind = net.isIP(unbracketed);
  if (ipKind !== 0) {
    if (isBlockedIpAddress(unbracketed)) {
      throw new SsrfBlockedError(`Blocked private/reserved IP target "${unbracketed}".`, 'SSRF_IP_BLOCKED');
    }
  } else {
    // Require a valid public-looking DNS name with at least one dot
    if (!rawHost.includes('.') || rawHost.includes('..') || !/^[a-z0-9.-]{1,253}$/.test(rawHost)) {
      throw new InvalidTargetError(`Invalid domain name "${rawHost}".`);
    }
  }

  const originHost = ipKind === 6 ? `[${unbracketed}]` : unbracketed;
  const pathname = parsed.pathname && parsed.pathname !== '' ? parsed.pathname : '/';
  const search = parsed.search || '';

  return {
    input: trimmed,
    hostname: unbracketed,
    isIpLiteral: ipKind !== 0,
    origin: `https://${originHost}`,
    httpsUrl: `https://${originHost}${pathname}${search}`,
    httpUrl: `http://${originHost}/`,
    rootHttpsUrl: `https://${originHost}/`,
  };
}

/**
 * Resolves all DNS A/AAAA addresses for a URL's host and rejects if ANY address is private/reserved.
 */
export async function assertSafeUrl(
  urlStr,
  { lookupImpl = (host, opts) => dns.lookup(host, opts) } = {}
) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new InvalidTargetError(`Invalid URL: "${urlStr}".`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new SsrfBlockedError(`Blocked protocol "${parsed.protocol}".`, 'SSRF_PROTOCOL_BLOCKED');
  }
  if (parsed.username || parsed.password) {
    throw new SsrfBlockedError('Blocked URL credentials.', 'SSRF_CREDENTIALS_BLOCKED');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    throw new SsrfBlockedError(`Blocked non-standard port "${parsed.port}".`, 'SSRF_PORT_BLOCKED');
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host || isBlockedHostname(host)) {
    throw new SsrfBlockedError(`Blocked internal hostname "${host}".`, 'SSRF_HOST_BLOCKED');
  }

  const ipKind = net.isIP(host);
  if (ipKind !== 0) {
    if (isBlockedIpAddress(host)) {
      throw new SsrfBlockedError(`Blocked private/reserved IP "${host}".`, 'SSRF_IP_BLOCKED');
    }
    return {
      url: parsed.href,
      hostname: host,
      addresses: [{ address: host, family: ipKind }],
    };
  }

  let records;
  try {
    records = await lookupImpl(host, { all: true, verbatim: true });
  } catch (err) {
    const dnsErr = new Error(`DNS lookup failed for "${host}": ${err.message}`);
    dnsErr.code = err.code || 'DNS_LOOKUP_FAILED';
    throw dnsErr;
  }

  const list = Array.isArray(records) ? records : records ? [records] : [];
  if (list.length === 0) {
    const dnsErr = new Error(`DNS lookup returned no addresses for "${host}".`);
    dnsErr.code = 'ENOTFOUND';
    throw dnsErr;
  }

  for (const rec of list) {
    const addr = typeof rec === 'string' ? rec : rec?.address;
    if (!addr || isBlockedIpAddress(addr)) {
      throw new SsrfBlockedError(
        `SSRF protection: "${host}" resolved to blocked private/reserved IP "${addr}".`,
        'SSRF_DNS_IP_BLOCKED'
      );
    }
  }

  return {
    url: parsed.href,
    hostname: host,
    addresses: list.map((r) => (typeof r === 'string' ? { address: r, family: net.isIP(r) } : r)),
  };
}

function createAbortRace(signal) {
  if (!signal) return { promise: null, cleanup: () => {} };
  let onAbort;
  const toAbortError = () =>
    signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason || 'Request aborted'));
  const promise = new Promise((_, reject) => {
    if (signal.aborted) {
      reject(toAbortError());
      return;
    }
    onAbort = () => reject(toAbortError());
    signal.addEventListener('abort', onAbort, { once: true });
  });
  promise.catch(() => {});
  return {
    promise,
    cleanup: () => {
      if (onAbort) signal.removeEventListener('abort', onAbort);
    },
  };
}

/**
 * Reads a fetch Response body stream up to `maxBytes` (default 256 KiB) to prevent OOM,
 * while strictly honoring an optional AbortSignal so slowloris/tarpit streams cannot hang.
 */
export async function readBoundedResponseText(resp, maxBytes = MAX_RESPONSE_BYTES, { signal } = {}) {
  if (!resp) return { text: '', bytes: 0, truncated: false };
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error(String(signal.reason || 'Request aborted'));
  }

  const abortRace = createAbortRace(signal);

  try {
    if (resp.body && typeof resp.body.getReader === 'function') {
      const reader = resp.body.getReader();
      const chunks = [];
      let total = 0;
      let truncated = false;
      try {
        while (true) {
          const readPromise = reader.read();
          const { done, value } = abortRace.promise
            ? await Promise.race([readPromise, abortRace.promise])
            : await readPromise;
          if (done) break;
          const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
          if (total + buf.length > maxBytes) {
            const remaining = maxBytes - total;
            if (remaining > 0) {
              chunks.push(buf.subarray(0, remaining));
              total += remaining;
            }
            truncated = true;
            try {
              await reader.cancel();
            } catch {
              // ignore cancel error
            }
            break;
          }
          chunks.push(buf);
          total += buf.length;
        }
      } catch (err) {
        try {
          void reader.cancel().catch(() => {});
        } catch {
          // ignore
        }
        throw err;
      } finally {
        try {
          reader.releaseLock();
        } catch {
          // ignore
        }
      }
      return { text: Buffer.concat(chunks).toString('utf8'), bytes: total, truncated };
    }

    // Fallback for mocked Response objects implementing text()
    const raw =
      typeof resp.text === 'function'
        ? await (abortRace.promise ? Promise.race([resp.text(), abortRace.promise]) : resp.text())
        : '';
    const buf = Buffer.from(raw, 'utf8');
    if (buf.length > maxBytes) {
      return { text: buf.subarray(0, maxBytes).toString('utf8'), bytes: maxBytes, truncated: true };
    }
    return { text: raw, bytes: buf.length, truncated: false };
  } finally {
    abortRace.cleanup();
  }
}

function normalizeHeaders(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.forEach === 'function') {
    headers.forEach((val, key) => {
      out[String(key).toLowerCase()] = String(val);
    });
    return out;
  }
  for (const [k, v] of Object.entries(headers)) {
    out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}

/**
 * Performs an SSRF-checked HTTP GET with manual redirects (max 3 hops) and bounded body streaming.
 */
export async function safeFetch(
  initialUrl,
  {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_RESPONSE_BYTES,
    maxRedirects = MAX_REDIRECTS,
    followRedirects = true,
    userAgent = 'AgentReadyWebSecAuditor/1.0 (+https://apify.com)',
    accept = '*/*',
    fetchImpl = globalThis.fetch,
    lookupImpl = (host, opts) => dns.lookup(host, opts),
  } = {}
) {
  let currentUrl = initialUrl;
  const redirectChain = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const safeCheck = await assertSafeUrl(currentUrl, { lookupImpl });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`Request timed out after ${timeoutMs}ms`)), timeoutMs);

    let resp;
    try {
      resp = await fetchImpl(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': userAgent,
          Accept: accept,
        },
        signal: controller.signal,
      });

      const status = Number(resp.status || 0);
      const headers = normalizeHeaders(resp.headers);
      const location = headers.location;

      if (followRedirects && status >= 300 && status < 400 && location) {
        // Drain/cancel body before following redirect
        try {
          await resp.body?.cancel?.();
        } catch {
          // ignore
        }
        if (hop === maxRedirects) {
          return {
            ok: false,
            status,
            finalUrl: currentUrl,
            headers,
            text: '',
            bytes: 0,
            truncated: false,
            redirectChain,
            resolvedAddresses: safeCheck.addresses,
            error: `Exceeded maximum redirect limit (${maxRedirects})`,
          };
        }
        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch {
          return {
            ok: false,
            status,
            finalUrl: currentUrl,
            headers,
            text: '',
            bytes: 0,
            truncated: false,
            redirectChain,
            resolvedAddresses: safeCheck.addresses,
            error: `Invalid redirect Location header: "${location}"`,
          };
        }
        redirectChain.push({ from: currentUrl, status, to: nextUrl });
        currentUrl = nextUrl;
        continue;
      }

      const { text, bytes, truncated } = await readBoundedResponseText(resp, maxBytes, {
        signal: controller.signal,
      });
      return {
        ok: status >= 200 && status < 300,
        status,
        finalUrl: currentUrl,
        headers,
        text,
        bytes,
        truncated,
        redirectChain,
        resolvedAddresses: safeCheck.addresses,
        error: null,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    ok: false,
    status: 0,
    finalUrl: currentUrl,
    headers: {},
    text: '',
    bytes: 0,
    truncated: false,
    redirectChain,
    resolvedAddresses: [],
    error: 'Redirect loop aborted',
  };
}
