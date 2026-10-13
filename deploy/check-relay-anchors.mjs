#!/usr/bin/env node
// Does every relay still sign with a key /verify trusts?
//
// WHY. /verify checks a ParaSign receipt against the relay keys pinned in
// frontend/js/relay-trust-anchors.js, offline. Each relay keeps its own
// identity on its own volume (RELAY_IDENTITY_FILE). If one is rotated, or its
// volume is lost and it boots with a fresh key, every NEW multi-party proof it
// counter-signs shows red on /verify, while nothing else in the deploy notices
// (hertest 2026-10-04, deel 3: RETIRED_RELAY_ANCHORS empty, no check). The
// procedure is in RUNBOOK.md, "Relay identity key rotation".
//
// WHAT. For every pinned host, GET https://<host>/v2/pubkey and compare the
// key with the pin. Also, offline: every pin and every retired entry carries
// the SHA3-256 fingerprint of its own key, and a retired entry has retired_at.
//
//   node deploy/check-relay-anchors.mjs            offline checks + live hosts
//   node deploy/check-relay-anchors.mjs --offline  the file only (CI does this)
//
// Exit 0 when every host serves its pinned key, 1 when one does not, 2 when a
// host could not be reached (not proven, never silently green).
// deploy/deploy-3.1.sh runs it in phase 6, so also under --verify-only.

import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export const fingerprintOf = (b64) => crypto.createHash('sha3-256').update(Buffer.from(String(b64 || ''), 'base64')).digest('hex');

// Offline: the file is consistent with itself. Returns a list of problems.
export function checkFile({ anchors, retired }) {
  const out = [];
  const seen = new Set();
  for (const a of anchors) {
    if (!a.host || !a.key) { out.push(`pin without host or key: ${JSON.stringify(a).slice(0, 80)}`); continue; }
    if (fingerprintOf(a.key) !== a.fingerprint) out.push(`${a.host}: the pinned fingerprint is not the SHA3-256 of the pinned key`);
    if (seen.has(a.host)) out.push(`${a.host}: pinned twice`);
    seen.add(a.host);
  }
  for (const r of retired) {
    if (!r.host || !r.key) { out.push(`retired entry without host or key: ${JSON.stringify(r).slice(0, 80)}`); continue; }
    if (fingerprintOf(r.key) !== r.fingerprint) out.push(`${r.host} (retired): fingerprint is not the SHA3-256 of the key`);
    if (!/^\d{4}-\d{2}-\d{2}/.test(String(r.retired_at || ''))) out.push(`${r.host} (retired): retired_at missing or not an ISO date`);
    if (anchors.some((a) => a.fingerprint === r.fingerprint)) out.push(`${r.host} (retired): the same key is still pinned as current`);
  }
  return out;
}

// Live: what each host serves against what is pinned for it.
// live = [{ host, public_key } | { host, error }]
export function judge({ anchors, retired, live }) {
  const rows = [];
  for (const a of anchors) {
    const l = live.find((x) => x.host === a.host);
    if (!l || l.error) { rows.push({ host: a.host, state: 'unreachable', detail: l ? l.error : 'not asked' }); continue; }
    const fp = fingerprintOf(l.public_key);
    if (l.public_key === a.key && fp === a.fingerprint) { rows.push({ host: a.host, state: 'pinned', detail: fp.slice(0, 16) }); continue; }
    const wasRetired = retired.find((r) => r.fingerprint === fp);
    rows.push({ host: a.host, state: wasRetired ? 'serving-retired' : 'unpinned', detail: fp });
  }
  return rows;
}

async function loadAnchors() {
  const mod = await import(pathToFileURL(path.join(ROOT, 'frontend/js/relay-trust-anchors.js')).href);
  return { anchors: mod.RELAY_TRUST_ANCHORS, retired: mod.RETIRED_RELAY_ANCHORS };
}

async function fetchLive(hosts) {
  return Promise.all(hosts.map(async (host) => {
    try {
      const r = await fetch(`https://${host}/v2/pubkey`, { signal: AbortSignal.timeout(10000) });
      if (!r.ok) return { host, error: `HTTP ${r.status}` };
      const j = await r.json();
      return { host, public_key: String(j.public_key || '') };
    } catch (e) { return { host, error: e.message }; }
  }));
}

async function main() {
  const offline = process.argv.includes('--offline');
  const { anchors, retired } = await loadAnchors();
  const fileProblems = checkFile({ anchors, retired });
  for (const p of fileProblems) console.log(`  FILE  ${p}`);
  if (fileProblems.length) { console.log('relay anchors: the pin file is inconsistent'); process.exit(1); }
  console.log(`relay anchors: ${anchors.length} pinned, ${retired.length} retired, file consistent`);
  if (offline) return;
  const rows = judge({ anchors, retired, live: await fetchLive(anchors.map((a) => a.host)) });
  for (const r of rows) console.log(`  ${r.state.padEnd(16)} ${r.host.padEnd(24)} ${r.detail}`);
  if (rows.some((r) => r.state === 'unpinned' || r.state === 'serving-retired')) {
    console.log('relay anchors: a relay signs with a key /verify does not pin as current. New proofs from it show red.');
    console.log('  Follow RUNBOOK.md "Relay identity key rotation": old key to RETIRED_RELAY_ANCHORS, new key pinned, same commit.');
    process.exit(1);
  }
  if (rows.some((r) => r.state === 'unreachable')) { console.log('relay anchors: NOT PROVEN, a host did not answer'); process.exit(2); }
  console.log('relay anchors: every relay serves its pinned key');
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch((e) => { console.error('relay anchors: check failed:', e.message); process.exit(2); });
}
