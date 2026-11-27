#!/usr/bin/env node
/**
 * scripts/build-vercel-bundle.mjs — Builds a self-contained zero-dependency Vercel Serverless deployment
 * directory at dist/vercel-app/ ready for `vercel deploy --prod`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const outDir = path.join(rootDir, 'dist', 'vercel-app');

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(path.join(outDir, 'api'), { recursive: true });
fs.mkdirSync(path.join(outDir, 'src'), { recursive: true });
fs.mkdirSync(path.join(outDir, 'deploy', 'vercel'), { recursive: true });

const srcFiles = ['ssrf-guard.mjs', 'domain-auditor.mjs', 'payment-hooks.mjs', 'discovery.mjs'];
for (const f of srcFiles) {
  fs.copyFileSync(path.join(rootDir, 'src', f), path.join(outDir, 'src', f));
}

fs.copyFileSync(
  path.join(rootDir, 'deploy', 'vercel', 'handler.mjs'),
  path.join(outDir, 'deploy', 'vercel', 'handler.mjs')
);
fs.copyFileSync(
  path.join(rootDir, 'deploy', 'vercel', 'vercel.json'),
  path.join(outDir, 'vercel.json')
);

fs.writeFileSync(
  path.join(outDir, 'package.json'),
  JSON.stringify(
    {
      name: 'agentready-websec-x402-api',
      version: '1.0.0',
      private: true,
      type: 'module',
      engines: { node: '>=22.0.0' },
    },
    null,
    2
  ) + '\n'
);

fs.writeFileSync(
  path.join(outDir, 'api', 'index.mjs'),
  `import { createVercelHandler } from '../deploy/vercel/handler.mjs';\n\nconst handler = createVercelHandler(process.env);\n\nexport default async function vercelEntrypoint(req, res) {\n  return handler(req, res);\n}\n`
);

console.log(`Built self-contained Vercel x402 v2 bundle at: ${outDir}`);
