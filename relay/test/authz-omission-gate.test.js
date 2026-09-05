'use strict';
// THE OMISSION GATE. A permission may never be derived from something the
// requester is free to leave out.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review of the critical paths found
// three doors that a stranger could walk through from the open internet, and
// underneath them one shape, repeated:
//
//     const accountId = (d.account_id || '').toString();
//     ...
//     if (accountId) { /* the quota gate, and the meter */ }
//
// Absence read as permission. Leave the field out and the gate is not failed,
// it is skipped. The same shape appeared as `if (keyData && keyData.account_id)`
// around the transfer and sign gates, and as `if (entry.apiKey && entry.apiKey
// !== apiKey)` around the blob owner check. Three sites, one class. Fixing the
// three sites and stopping there would buy nothing: the fourth is one commit
// away, and it is a shape that reads as careful code.
//
// So this scans the source for the shape rather than for the sites. It is a
// linter, not a proof: it catches the shape that was actually written here
// three times, and it is deliberately narrow so that a hit means something.
// The behavioural half of the gate, which proves the sign route really does
// refuse and really does meter, lives in route-omission-gate.test.js.
//
// WHAT IT FLAGS
//   D1  a variable read out of the request body/query (`d.account_id`, and
//       friends) whose mere PRESENCE guards a block that decides a permission:
//       `if (accountId) { ...402/403/quota/gate... }`
//   D2  a permission block guarded by the presence of an identity field on a
//       record: `if (keyData && keyData.account_id) { ...gate... }`. A record
//       written without that field then buys its holder an exemption.
//   D3  a function that answers "allowed" precisely BECAUSE an identity is
//       missing: `if (!accountId) return { allowed: true }`.
//
// A guard only counts when the block it opens contains an authorization signal
// (a 401/402/403, a quota or gate call, `allowed`, `enrolled`, `limit`). A
// presence check around ordinary code is not this bug and is not flagged.
//
// HOW TO ANSWER A RED
//   Invert it. `if (!x) -> refuse` instead of `if (x) -> check`. Or resolve the
//   identity from server-side state (the record, the API key, the session)
//   rather than from the request, which is what POST /v2/envelopes/:id/sign now
//   does: the metered account comes off the envelope, and no account is a 403.
//   Adding a line to ALLOW below is the last resort, not the first, and it needs
//   a reason a reader can check.
//
// Runs anywhere: no redis, no engine, no dependencies, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const FILES = ['relay/relay.js', 'relay/envelope.js', 'admin/server.js'];

// Names that carry an identity or an entitlement. The bug is only interesting
// for these: nobody escalates by omitting a page size.
const IDENTITY = /(account|acct|user_?id|owner|tenant|team|principal|api_?key|apikey|key_?id|role|plan|tier|scope|caller|subject|entitle)/i;

// A block that decides whether someone may do something, rather than what they
// get to see.
const AUTHZ_SIGNAL = /\b(40[123]\b|quota\.|gateSign|gateTransfer|recordSign|recordTransfer|allowed|entitlements\.|enrolled|_limit|Limit\b|denied|forbidden|Forbidden|unauthor|not_authorized|permission)/;

// Reading a field straight off the parsed request body / query / params.
const FROM_REQUEST = /=\s*\(?\s*(?:d|b|body|payload|params|query|q|req\.body|req\.query|req\.params)\s*\.\s*([A-Za-z_$][\w$]*)/;

// ── the allowlist ───────────────────────────────────────────────────────────
// Every entry is a shape that IS the bug and is knowingly still open, with the
// finding that owns it and the round that will close it. `count` is exact: a
// fourth copy of an allowed shape turns this red, because the way this class
// spreads is by being copied.
const ALLOW = [
  {
    file: 'relay/relay.js',
    guard: 'keyData && keyData.account_id',
    count: 2,
    reason:
      'Review 2026-09-05 finding 9. The transfer gate and the /v2/sign gate skip ' +
      'their quota entirely for an API key that carries no account_id, and POST ' +
      '/v2/team/add-device mints exactly such keys. Real, and out of scope for the ' +
      'three-doors branch: it is an entitlement leak, not an unauthenticated door, ' +
      'and the fix is the add-device route rather than these two guards.',
  },
  {
    file: 'relay/relay.js',
    guard: 'entry.apiKey && entry.apiKey !== apiKey',
    count: 2,
    reason:
      'Review 2026-09-05 finding 22 (anonymous blobs). An anonymous blob is stored ' +
      'with apiKey: null, so the owner check is skipped for it. Bounded by the ' +
      '64-hex blob hash, which is CSPRNG and unguessable, so it is not a door; it ' +
      'gets its own round with the rest of the blob ownership model.',
  },
  {
    file: 'relay/relay.js',
    guard: 'e.apiKey && e.apiKey !== apiKey',
    count: 1,
    reason:
      'Same anonymous-blob ownership model as the entry.apiKey pair above. A fourth ' +
      'copy of this guard sits on the status route and answers 404 rather than 403, ' +
      'so it falls outside AUTHZ_SIGNAL and this gate does not see it. Named here so ' +
      'the round that fixes the model knows to look for it as well.',
  },
];

// Blank out comments and string bodies so a hit is code and never prose. Line
// count is preserved exactly, so reported line numbers stay usable.
function stripNonCode(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let state = 'code';
  let quote = '';
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (state === 'code') {
      if (c === '/' && c2 === '/') { state = 'line'; out += '  '; i += 2; continue; }
      if (c === '/' && c2 === '*') { state = 'block'; out += '  '; i += 2; continue; }
      if (c === '"' || c === "'" || c === '`') { state = 'str'; quote = c; out += c; i++; continue; }
      out += c; i++; continue;
    }
    if (state === 'line') {
      if (c === '\n') { state = 'code'; out += '\n'; i++; continue; }
      out += ' '; i++; continue;
    }
    if (state === 'block') {
      if (c === '*' && c2 === '/') { state = 'code'; out += '  '; i += 2; continue; }
      out += (c === '\n' ? '\n' : ' '); i++; continue;
    }
    // inside a string literal
    if (c === '\\') { out += '  '; i += 2; continue; }
    if (c === quote) { state = 'code'; out += c; i++; continue; }
    out += (c === '\n' ? '\n' : ' '); i++; continue;
  }
  return out;
}

// The source of the block an `if (` at `idx` opens, up to its matching brace.
// A braceless if takes the rest of its line, which is the common one-liner
// `if (x) { res.writeHead(403); ... }` case either way.
function blockAfter(code, idx) {
  const open = code.indexOf('{', idx);
  const nl = code.indexOf('\n', idx);
  if (open === -1 || (nl !== -1 && open > nl)) {
    return code.slice(idx, nl === -1 ? code.length : nl);
  }
  let depth = 0;
  for (let i = open; i < code.length && i < open + 20000; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) return code.slice(open, i + 1); }
  }
  return code.slice(open, open + 4000);
}

const lineOf = (code, idx) => code.slice(0, idx).split('\n').length;

function scan(rel) {
  const code = stripNonCode(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  const findings = [];

  // Which local variables were read out of the request, under an identity name.
  const requestVars = new Set();
  for (const line of code.split('\n')) {
    const src = line.match(FROM_REQUEST);
    if (!src) continue;
    const decl = line.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/);
    if (!decl) continue;
    if (IDENTITY.test(decl[1]) || IDENTITY.test(src[1])) requestVars.add(decl[1]);
  }

  // D1. Presence of a request-derived identity guards a permission block.
  const d1 = /if\s*\(\s*([A-Za-z_$][\w$]*)\s*(?:\)|&&)/g;
  for (let m; (m = d1.exec(code)) !== null;) {
    if (!requestVars.has(m[1])) continue;
    const block = blockAfter(code, m.index);
    if (!AUTHZ_SIGNAL.test(block)) continue;
    findings.push({ file: rel, line: lineOf(code, m.index), kind: 'D1', guard: m[1] });
  }

  // D2. Presence of an identity FIELD on a record guards a permission block.
  // Only a PRESENCE test counts: `if (x.field)` or `if (x.field && ...)`. A real
  // comparison such as `if (sess.api_key !== apiKey)` is the correct code and
  // must not be flagged, so `!==` is deliberately not a terminator here.
  const d2 = /if\s*\(\s*(!?[A-Za-z_$][\w$.]*\s*&&\s*)?([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\s*(?:\)|&&)/g;
  for (let m; (m = d2.exec(code)) !== null;) {
    const field = m[2].split('.').pop();
    if (!IDENTITY.test(field)) continue;
    const block = blockAfter(code, m.index);
    if (!AUTHZ_SIGNAL.test(block)) continue;
    const guard = (code.slice(m.index + 3).match(/^\s*\(\s*([^)]*?)\s*(?:\)|\{)/) || [, m[2]])[1];
    findings.push({ file: rel, line: lineOf(code, m.index), kind: 'D2', guard: guard.trim() });
  }

  // D3. Absence of an identity is answered with a permissive return.
  const d3 = /if\s*\(\s*!\s*([A-Za-z_$][\w$.]*)[^)\n]*\)\s*(?:\{[^{}]{0,200}?)?return\s*(?:\{[^{}]{0,200}?allowed\s*:\s*true|true\s*;)/g;
  for (let m; (m = d3.exec(code)) !== null;) {
    const name = m[1].split('.').pop();
    if (!IDENTITY.test(name)) continue;
    findings.push({ file: rel, line: lineOf(code, m.index), kind: 'D3', guard: '!' + m[1] });
  }

  return findings;
}

test('no permission is derived from a field the caller may simply leave out', () => {
  const all = [];
  for (const f of FILES) all.push(...scan(f));

  const remaining = [];
  const used = new Map();
  for (const hit of all) {
    const rule = ALLOW.find((a) => a.file === hit.file && a.guard === hit.guard);
    if (!rule) { remaining.push(hit); continue; }
    used.set(rule, (used.get(rule) || 0) + 1);
  }

  if (remaining.length) {
    const list = remaining
      .map((h) => `  ${h.file}:${h.line}  [${h.kind}]  if (${h.guard})`)
      .join('\n');
    assert.fail(
      'A permission hangs on a field that can be omitted:\n' + list +
      '\n\nOmission must be the SAFEST outcome, never the most permissive one. Invert the\n' +
      'guard (absent -> refuse), or resolve the identity from server-side state instead\n' +
      'of from the request. Only allowlist it in ALLOW above with a reason that holds.');
  }

  // An allowlisted shape that has SPREAD is a new finding wearing an old name.
  for (const rule of ALLOW) {
    const seen = used.get(rule) || 0;
    assert.strictEqual(seen, rule.count,
      `${rule.file}: "if (${rule.guard})" is allowlisted ${rule.count}x and now occurs ${seen}x. ` +
      (seen > rule.count
        ? 'A new copy of a known-bad shape is a new finding: fix it, do not raise the count.'
        : 'One was fixed or moved: lower the count so the remainder stays visible.'));
  }
});

// The gate is only worth having if it can go red. Two synthetic sources: one
// that writes the exact shape the review found, one that writes the fixed
// version. The first must be caught and the second must not.
test('the gate itself fires on the shape it is meant to catch, and not on the fix', () => {
  const tmp = path.join(require('os').tmpdir(), `omission-gate-${process.pid}`);
  fs.mkdirSync(path.join(tmp, 'relay'), { recursive: true });
  const write = (name, body) => {
    fs.writeFileSync(path.join(tmp, 'relay', name), body);
    return 'relay/' + name;
  };

  const broken = write('broken.js', `
    async function handler(req, res, d) {
      const accountId = (d.account_id || '').toString();
      if (accountId) {
        const u = await quota.readUsage(rc, accountId);
        if (u.signs_this_month >= limit) { res.writeHead(402); return res.end('over quota'); }
      }
      return store.sign();
    }
  `);
  const fixed = write('fixed.js', `
    async function handler(req, res, d) {
      const accountId = internalTrusted ? (d.account_id || '').toString() : '';
      const owner = await store.ownerAccountId(id);
      const metered = accountId || owner;
      if (!metered) { res.writeHead(403); return res.end('account_required'); }
      const u = await quota.readUsage(rc, metered);
      if (u.signs_this_month >= limit) { res.writeHead(402); return res.end('over quota'); }
      return store.sign();
    }
  `);

  // scan() reads relative to ROOT, so point it at the scratch tree for these two.
  const realRoot = ROOT;
  const scanIn = (root, rel) => {
    const code = fs.readFileSync(path.join(root, rel), 'utf8');
    const stash = path.join(realRoot, '__omission_gate_probe.js');
    fs.writeFileSync(stash, code);
    try { return scan('__omission_gate_probe.js'); }
    finally { fs.unlinkSync(stash); }
  };

  try {
    const hitsBroken = scanIn(tmp, broken);
    assert.strictEqual(hitsBroken.length, 1,
      'the gate must catch `const accountId = d.account_id; if (accountId) { ...402... }`');
    assert.strictEqual(hitsBroken[0].kind, 'D1');

    const hitsFixed = scanIn(tmp, fixed);
    assert.deepStrictEqual(hitsFixed, [],
      'the gate must stay quiet on the inverted, server-resolved version');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
