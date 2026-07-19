'use strict';
// GET /v2/parasign/audit-export — ParaSign Business signing-audit export.
// Tier-gated on the (now live) `audit_export` entitlement flag: Business and
// Enterprise only. Pro and below get 403. This is the compliance-export half of
// the ParaSign paid ladder: it hands an auditor the account's tamper-evident
// signing trail plus the Certificate-Transparency signed tree head that anchors
// it, as CSV or JSON.
//
// Data source (NO new storage): the per-key Merkle audit chain relay.js already
// keeps (auditChain) rolled up across the account's keys, plus the live CT signed
// tree head (STH). Driven the DI way (injected state + a fake-free `res`) so the
// tier gate is unit-testable without a socket (test/parasign-audit-export.test.js).
const tierGate = require('./tier-gate');

const DEFAULT_LIMIT = 1000;
const MAX_LIMIT = 10000;

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// deps:
//   res, J                 — HTTP response + JSON stringifier
//   keyData                — authenticated key record (plan info + active)
//   memberKeys             — array of the account's api-keys (per-account rollup)
//   auditFor(key) -> []    — that key's audit-chain entries
//   ctHead() -> {...}|null  — current CT signed tree head (tree_size/tree_hash/ts)
//   verifyChain(entries)   — optional; returns bool chain integrity for a key
//   query                  — parsed querystring ({ format, limit })
function handle({ res, J, keyData, memberKeys, auditFor, ctHead, verifyChain, query }) {
  if (!keyData || keyData.active === false) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(J({ error: 'API key required' }));
  }
  // Tier gate: Business+ (audit_export). Pro and below -> 403.
  if (!tierGate.isAuditExportAllowed(keyData)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(J({
      error: 'tier_upgrade_required',
      feature: 'audit_export',
      message: 'The ParaSign audit export requires a Business plan or higher.',
    }));
  }

  const limit = Math.max(1, Math.min(parseInt((query && query.limit) || String(DEFAULT_LIMIT), 10) || DEFAULT_LIMIT, MAX_LIMIT));

  // Roll the tamper-evident chain up across the account's keys. Per-key chain
  // integrity is reported (a false here is a tamper signal for the auditor).
  const rows = [];
  let chainValid = true;
  for (const key of (memberKeys || [])) {
    const chain = auditFor(key) || [];
    if (typeof verifyChain === 'function' && chain.length && !verifyChain([...chain])) chainValid = false;
    for (const e of chain) {
      rows.push({
        time: e.ts,
        event: e.event,
        doc_hash: e.hash || '',        // .psign document/content fingerprint
        bytes: e.bytes || 0,
        device: e.device || '',
        chain_hash: e.chain_hash || '', // Merkle link (tamper-evidence)
      });
    }
  }
  rows.sort((a, b) => (Date.parse(b.time) || 0) - (Date.parse(a.time) || 0));
  const entries = rows.slice(0, limit);
  const sth = (typeof ctHead === 'function') ? ctHead() : null;

  if (query && query.format === 'csv') {
    res.writeHead(200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': 'attachment; filename="parasign_audit.csv"',
    });
    const header = 'time,event,doc_hash,bytes,device,chain_hash';
    const body = entries.map((e) =>
      [e.time, e.event, e.doc_hash, e.bytes, e.device, e.chain_hash].map(csvCell).join(',')
    ).join('\n');
    return res.end(header + '\n' + body + '\n');
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  return res.end(J({
    ok: true,
    type: 'parasign-audit-export',
    generated_at: new Date().toISOString(),
    chain_valid: chainValid,
    ct_head: sth,               // CT signed tree head: the transparency anchor
    count: entries.length,
    entries,
  }));
}

module.exports = { handle };
