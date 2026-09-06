'use strict';
// THE AUDIT-TRAIL GATE. A safeguard may not fail silently.
//
// WHY THIS EXISTS. The 2026-09-05 review of admin/ found six audit writes that
// looked like an audit trail and were not one. Underneath them, two shapes:
//
//     try { logAuditEvent("webauthn_counter_regression", { user_id: ... }); } catch {}
//     try { logAuditEvent(String(user_id).slice(0, 12) + "…", "webauthn_login", {}); } catch {}
//
// The first argument of logAuditEvent(user_id, event_type, metadata) IS the
// redis key (lib/audit.js: AUDIT_KEY = uid => `paramant:user:audit:${uid}`).
// So the first line filed a cloned-authenticator alarm under the key
// "paramant:user:audit:webauthn_counter_regression", and the second filed a
// login under a twelve-character stump plus an ellipsis. Every reader in this
// codebase asks for the FULL user_id -- /api/user/billing/history, the
// developer snapshot, the developer SSE stream -- so not one of those six
// events was ever readable by anything. The trail was present in a review and
// absent in an incident, which is the worst of the three possible states.
//
// And around all six: `try { ... } catch {}` with no await. logAuditEvent is
// async, so the catch is decoration -- it cannot see a rejected promise. With
// no unhandledRejection handler in admin/ and Node's default of throw, a redis
// hiccup on any of those six lines ended the admin process.
//
// THE CLASS, which is what this gate scans for rather than the six sites:
// a guarantee that writes to a place nobody reads, or that disappears into a
// catch that catches nothing.
//
// WHAT IT FLAGS
//   A1  a logAuditEvent call with anything other than three arguments. Two
//       arguments means the event name slid into the user_id slot.
//   A2  a logAuditEvent call that is not awaited. The write is then unordered
//       against the response and its rejection is nobody's.
//   A3  a first argument that is a string literal. The key is an identity that
//       comes from the request or the session, never a constant in the source.
//   A4  a first argument containing .slice(. A truncated key is a key no
//       reader ever asks for. Truncating INSIDE metadata is fine and is not
//       flagged: only the first argument is the key.
//   A5  a bare, unawaited call to a known-async helper as a statement inside a
//       try block. The catch shape is deliberately not part of the test: no
//       catch, empty or not, sees the rejection of a promise nobody awaited.
//
// "Known-async" is kept narrow on purpose, so that a hit means something: the
// helpers this module imports and knows to be async, plus every function the
// scanned file itself declares with `async`.
//
// HOW TO ANSWER A RED
//   Await the call and give it the real identity. If the write genuinely must
//   not block the response, say so explicitly with .catch() on the promise,
//   which this gate accepts, rather than with a try that cannot catch it.
//   Adding a line to ALLOW below is the last resort and needs a reason a
//   reader can check.
//
// The behavioural half of reparation 1 is the trail itself: the readers named
// above all key on the full user_id, and audit-retention.test.js pins what a
// written entry looks like.
//
// Runs anywhere: no redis, no server, no dependencies, plain fs.

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const FILES = ['server.js'].concat(
  fs.readdirSync(path.join(ROOT, 'lib'))
    .filter((f) => f.endsWith('.js'))
    .sort()
    .map((f) => 'lib/' + f)
);

// Helpers this file knows to be async because it imported them from a module
// whose source is not being scanned in the same pass. Everything else comes
// from the file itself (see asyncNamesIn).
const KNOWN_ASYNC = [
  'logAuditEvent', 'getAuditEvents', 'incrInWindow', 'acquireSignupLock',
  'buildDeveloperSnapshot', 'verifyChallenge',
];

// ── the allowlist ───────────────────────────────────────────────────────────
// Every entry is a shape that IS the bug and is knowingly still open, with the
// reason it stays. `count` is exact: a second copy of an allowed shape turns
// this red, because the way this class spreads is by being copied.
const ALLOW = [
  {
    file: 'server.js',
    kind: 'A3',
    site: "logAuditEvent/literal-key:'admin'",
    count: 7,
    reason:
      "The operator pseudo-account, and the one literal in this slot that has a reader. " +
      "Events belonging to no single customer -- a config change, a config backup, a " +
      "restart request, a relay reload, a coupon created or revoked, an account deleted -- " +
      "are filed under the literal 'admin', and GET /admin/config/audit (server.js, " +
      "getAuditEvents('admin', ...)) reads exactly that key back. So these seven are not " +
      "writes into the void. Any OTHER literal gets its own site line here and stays red, " +
      "and an eighth copy of this one turns this red as well: the way a pseudo-account " +
      "becomes a dumping ground is one well-meant call at a time.",
  },
];

// Blank out comments and string bodies so a hit is code and never prose. The
// quote characters themselves survive, which is what lets A3 recognise a string
// literal in the key slot. Line count is preserved exactly, so reported line
// numbers stay usable. Verbatim from relay/test/authz-omission-gate.test.js;
// duplicated rather than shared because admin/ has its own node_modules and
// deliberately reaches into no sibling package (see admin/Dockerfile: the image
// ships server.js, lib/ and public/, and nothing else).
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
    if (c === '\\') { out += '  '; i += 2; continue; }
    if (c === quote) { state = 'code'; out += c; i++; continue; }
    out += (c === '\n' ? '\n' : ' '); i++; continue;
  }
  return out;
}

const lineOf = (code, idx) => code.slice(0, idx).split('\n').length;

// The argument list of the call whose '(' sits at `open`, split on top-level
// commas. Strings are already blanked, so a comma inside one cannot be counted.
// Returns null on an unbalanced list rather than guessing.
function callArgs(code, open) {
  let depth = 0;
  const args = [];
  let cur = '';
  for (let i = open; i < code.length && i < open + 20000; i++) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') {
      depth++;
      if (depth === 1) continue;
    } else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) { args.push(cur); return { args, end: i }; }
    } else if (c === ',' && depth === 1) { args.push(cur); cur = ''; continue; }
    cur += c;
  }
  return null;
}

// The [start, end) spans of every `try {` block in the file.
function tryBlocks(code) {
  const spans = [];
  const re = /\btry\s*\{/g;
  for (let m; (m = re.exec(code)) !== null;) {
    const open = code.indexOf('{', m.index);
    let depth = 0;
    for (let i = open; i < code.length; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') { depth--; if (depth === 0) { spans.push([open, i]); break; } }
    }
  }
  return spans;
}

// Every function this file declares as async, by name. `async function f`,
// `const f = async (`, `f: async (` and `async f(` all count.
function asyncNamesIn(code) {
  const names = new Set(KNOWN_ASYNC);
  const pats = [
    /\basync\s+function\s+([A-Za-z_$][\w$]*)/g,
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*async\b/g,
    /([A-Za-z_$][\w$]*)\s*:\s*async\b/g,
  ];
  for (const re of pats) for (let m; (m = re.exec(code)) !== null;) names.add(m[1]);
  return names;
}

// Is the call at `idx` the start of an expression statement (rather than an
// operand of an await, a return, an assignment, an argument, or a member
// chain)? Only a bare statement is unambiguously fire-and-forget. Deliberately
// strict: a call sitting inside a Promise.all([...]) array ends up on a line of
// its own too, and that one IS awaited, by the Promise.all around it.
function isBareStatement(code, idx) {
  const before = code.slice(Math.max(0, idx - 200), idx).replace(/\s+$/, '');
  return before === '' || /[;{}]$/.test(before);
}

function scanSource(rel, src) {
  const code = stripNonCode(src);
  const findings = [];
  const spans = tryBlocks(code);
  const inTry = (i) => spans.some(([a, b]) => i > a && i < b);

  // A1-A4: every logAuditEvent call site.
  const call = /\blogAuditEvent\s*\(/g;
  for (let m; (m = call.exec(code)) !== null;) {
    const before = code.slice(Math.max(0, m.index - 40), m.index);
    if (/\bfunction\s+$/.test(before)) continue;         // the definition itself
    const open = code.indexOf('(', m.index);
    const parsed = callArgs(code, open);
    if (!parsed) continue;
    const args = parsed.args.map((a) => a.trim()).filter((a, i, all) => !(all.length === 1 && a === ''));
    const line = lineOf(code, m.index);
    const site = `logAuditEvent/${args.length}`;
    // stripNonCode preserves offsets exactly, so the untouched source of the
    // first argument sits at the same place. A literal key is only meaningful
    // in the allowlist if the allowlist can name WHICH literal.
    const firstRaw = src.substr(open + 1, (parsed.args[0] || '').length).trim();

    if (args.length !== 3) {
      findings.push({ file: rel, line, kind: 'A1', site,
        detail: `${args.length} arguments; the signature is (user_id, event_type, metadata)` });
    }
    if (!/\bawait\s*$/.test(before)) {
      findings.push({ file: rel, line, kind: 'A2', site: 'logAuditEvent/no-await',
        detail: 'the write is not awaited, so its rejection belongs to nobody' });
    }
    const first = args[0] || '';
    if (/^['"`]/.test(first)) {
      findings.push({ file: rel, line, kind: 'A3', site: `logAuditEvent/literal-key:${firstRaw}`,
        detail: 'the first argument is a string literal, so a constant is being used as the audit key' });
    }
    if (/\.slice\s*\(/.test(first)) {
      findings.push({ file: rel, line, kind: 'A4', site: 'logAuditEvent/sliced-key',
        detail: 'the first argument is truncated, so the entry lands under a key no reader asks for' });
    }
  }

  // A5: a bare unawaited async call as a statement inside a try block.
  const asyncNames = asyncNamesIn(code);
  for (const name of asyncNames) {
    const re = new RegExp(`\\b${name}\\s*\\(`, 'g');
    for (let m; (m = re.exec(code)) !== null;) {
      const open = code.indexOf('(', m.index);
      if (!inTry(m.index)) continue;
      if (!isBareStatement(code, m.index)) continue;
      const parsed = callArgs(code, open);
      if (!parsed) continue;
      // An explicit .catch() on the promise is a deliberate fire-and-forget and
      // is honest about it; a try around it is not.
      const after = code.slice(parsed.end + 1, parsed.end + 12);
      if (/^\s*\.\s*catch\b/.test(after)) continue;
      findings.push({ file: rel, line: lineOf(code, m.index), kind: 'A5', site: `${name}/unawaited-in-try`,
        detail: `${name}() is async and is not awaited, so the surrounding catch cannot see it fail` });
    }
  }

  return findings;
}

function scan(rel) {
  return scanSource(rel, fs.readFileSync(path.join(ROOT, rel), 'utf8'));
}

test('no audit write lands under a key nobody reads, and none is fire-and-forget', () => {
  const all = [];
  for (const f of FILES) all.push(...scan(f));

  const remaining = [];
  const used = new Map();
  for (const hit of all) {
    const rule = ALLOW.find((a) => a.file === hit.file && a.kind === hit.kind && a.site === hit.site);
    if (!rule) { remaining.push(hit); continue; }
    used.set(rule, (used.get(rule) || 0) + 1);
  }

  if (remaining.length) {
    const list = remaining
      .map((h) => `  ${h.file}:${h.line}  [${h.kind}]  ${h.detail}`)
      .sort()
      .join('\n');
    assert.fail(
      'An audit write cannot be read back, or cannot be seen to fail:\n' + list +
      '\n\nlogAuditEvent(user_id, event_type, metadata) writes to paramant:user:audit:<first\n' +
      'argument>. Every reader asks for the full user_id, so anything else in that slot is\n' +
      'a write into the void. Await the call; truncate inside metadata if you must.');
  }

  for (const rule of ALLOW) {
    const seen = used.get(rule) || 0;
    assert.strictEqual(seen, rule.count,
      `${rule.file}: "${rule.site}" is allowlisted ${rule.count}x and now occurs ${seen}x. ` +
      (seen > rule.count
        ? 'A new copy of a known-bad shape is a new finding: fix it, do not raise the count.'
        : 'One was fixed or moved: lower the count so the remainder stays visible.'));
  }
});

// The other half of "fails silently": a process that dies without saying why.
// relay/relay.js has named both process-level failures since it was written;
// admin/ had neither, so an unawaited rejection anywhere in it ended the panel
// with a bare stack. Static, because the failure this pins cannot be provoked
// from a test without an injection point that would itself be the risk.
test('the process names its own failures instead of dying anonymously', () => {
  const src = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  for (const event of ['unhandledRejection', 'uncaughtException']) {
    assert.match(src, new RegExp(`process\\.on\\(\\s*['"\`]${event}['"\`]`),
      `admin/server.js must register a ${event} handler, the way relay/relay.js does: ` +
      'without one the panel exits on a bare stack with no line saying what failed');
  }
});

// The gate is only worth having if it can go red. Two synthetic sources: one
// that writes the exact shapes the review found, one that writes the repaired
// version. The first must be caught, on every one of its five counts, and the
// second must be silent.
test('the gate itself fires on the shapes it is meant to catch, and not on the fix', () => {
  const broken = `
    async function handler(req, res) {
      try { logAuditEvent("webauthn_counter_regression", { user_id: String(uid).slice(0, 12) }); } catch {}
      try { logAuditEvent(String(uid).slice(0, 12) + "x", "webauthn_login", {}); } catch {}
    }
  `;
  const fixed = `
    async function handler(req, res) {
      try { await logAuditEvent(uid, "webauthn_counter_regression", { stored: 1, presented: 0 }); } catch {}
      try { await logAuditEvent(uid, "webauthn_login", { envelope: String(env).slice(0, 10) }); } catch {}
    }
  `;

  const hits = scanSource('probe.js', broken);
  const kinds = hits.map((h) => h.kind).sort();
  assert.deepStrictEqual(kinds, ['A1', 'A2', 'A2', 'A3', 'A4', 'A5', 'A5'],
    'the gate must see: one two-argument call, two unawaited calls, one literal key, ' +
    `one sliced key, and two fire-and-forget calls inside a try. Got ${JSON.stringify(hits, null, 2)}`);

  assert.deepStrictEqual(scanSource('probe.js', fixed), [],
    'the gate must stay quiet on the awaited, full-identity version, including the ' +
    'truncation that sits harmlessly inside metadata');
});
