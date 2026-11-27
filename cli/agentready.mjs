#!/usr/bin/env node
/**
 * cli/agentready.mjs — Zero-dependency CLI for AgentReady & WebSec Domain Auditor (v1.0.0)
 *
 * Usage:
 *   node cli/agentready.mjs example.com [stripe.com ...] [--json] [--markdown] [--concurrency 5]
 */

import { auditBatchDomains, domainReportToMarkdown } from '../src/domain-auditor.mjs';

const args = process.argv.slice(2);
const urls = [];
let asJson = false;
let asMarkdown = false;
let concurrency = 5;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--json') {
    asJson = true;
  } else if (a === '--markdown') {
    asMarkdown = true;
  } else if (a === '--concurrency' && args[i + 1]) {
    concurrency = Number(args[++i]);
  } else if (a === '--help' || a === '-h') {
    console.log('Usage: agentready-audit <domain|url> [more...] [--json] [--markdown] [--concurrency 1-5]');
    process.exit(0);
  } else if (!a.startsWith('-')) {
    urls.push(a);
  }
}

if (urls.length === 0) {
  console.error('Error: Provide at least one domain or URL (e.g., node cli/agentready.mjs https://example.com).');
  process.exit(1);
}

try {
  const { results } = await auditBatchDomains(urls, { concurrency });
  if (asJson) {
    console.log(JSON.stringify({ count: results.length, results }, null, 2));
  } else if (asMarkdown) {
    console.log(results.map((r) => domainReportToMarkdown(r)).join('\n---\n\n'));
  } else {
    for (const r of results) {
      if (r.status === 'audited') {
        console.log(
          `${r.domain} | Overall ${r.overallScore}/100 (${r.grade}) | AI:${r.aiReadinessScore ?? 'N/A'} HTTP:${r.httpChallengeDetected ? 'WAF' : (r.httpSecurityScore ?? 'N/A')} TLS:${r.tlsScore ?? 'N/A'} DNS:${r.dnsScore ?? 'N/A'} | llms.txt:${r.hasLlmsTxt} | AI-Bots:${r.aiBotsAllowed}/${r.aiBotsTotal} | DMARC:${r.dmarcPolicy}`
        );
      } else {
        console.log(`${r.domain || r.input} | ${r.status.toUpperCase()} (${r.errorCode}): ${r.error}`);
      }
    }
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
