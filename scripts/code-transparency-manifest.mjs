#!/usr/bin/env node
// Build the code-transparency manifest: a deterministic SHA3-256 inventory of
// every file in frontend/. Published to the relay (CT-anchored), so an
// independent monitor can verify that what the server SERVES is what the repo
// SHIPPED, and a targeted "special JS for one visitor" attack becomes visible.
//
// Usage: node scripts/code-transparency-manifest.mjs [frontendDir] [gitCommit]
// Output: canonical JSON on stdout.
import { createHash } from 'crypto';
import { readdirSync, readFileSync, statSync } from 'fs';
import { join, relative } from 'path';

const root = process.argv[2] || 'frontend';
const commit = process.argv[3] || '';

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const files = {};
for (const p of walk(root)) {
  const rel = relative(root, p).split('\\').join('/');
  files[rel] = createHash('sha3-256').update(readFileSync(p)).digest('hex');
}

// Canonical form: insertion order is the sorted walk order and the body has a
// fixed key order, with no timestamp inside the hashed part, so the same tree
// always yields the same manifest_hash regardless of when it runs.
const body = { git_commit: commit, files };
const manifest_hash = createHash('sha3-256').update(JSON.stringify(body)).digest('hex');

process.stdout.write(JSON.stringify({ ...body, manifest_hash, file_count: Object.keys(files).length }, null, 2) + '\n');
