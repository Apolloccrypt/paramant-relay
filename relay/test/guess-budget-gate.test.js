'use strict';
// THE GUESSING BUDGET GATE. A route that answers, without a login, whether a
// secret the caller supplied is the right one must make guessing cost
// something, and the cost has to be charged to the thing being attacked and
// not only to the attacker.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review, finding 6.
// POST /v2/session/join takes a pre-shared secret and says whether it matched
// the commitment stored with the session. It has no API key by design: the PSS
// IS the authentication, and the receiver of a transfer is a stranger with no
// account. Until the review it had nothing else either. A wrong secret got a
// 403 and left the session exactly as it was, so whoever held the session id
// could try passphrases as fast as the socket allowed. A PSS is a phrase a
// human picked, and the project's own documentation offers
// "correct-horse-battery-staple" as the worked example, so the keyspace being
// searched is not 2^128, it is a wordlist.
//
// The comparison was `!==` as well, which leaks how far it got, and the error
// text on the create side named SHA-256 while the join side computed SHA3-256.
// Both digests are 64 hex characters, so an SDK author who believed the error
// message built sessions that were syntactically perfect and could never be
// joined, and found out at join time through a 403 that said "wrong secret".
//
// WHAT THE GATE LOCKS DOWN, AS A CLASS.
//
//   PER-SESSION BUDGET   The load-bearing one. A per-IP limit is bounded by
//                        who is attacking, and addresses are cheap: every
//                        attempt in the first test below comes from a
//                        different one, exactly as a botnet would send them.
//                        A budget attached to the session survives that. And
//                        it must DESTROY the session, not merely delay: a
//                        session that reopens after the budget refills has
//                        cost the attacker a wait, not a victory.
//   PER-IP WINDOW        Still needed, because the per-session budget does
//                        nothing against one host sweeping many sessions.
//   STILL USABLE         A route locked so hard that the honest receiver
//                        cannot get in is not a fix. The right secret opens
//                        the session, once.
//   ONE ALGORITHM        The digest the create side documents is the digest
//                        the join side computes.
//
// HOW TO ANSWER A RED
//   A behavioural failure: the budget or the window has been weakened or
//   removed. Both live in relay.js around sessionJoinRateOk and
//   SESSION_JOIN_MAX_ATTEMPTS. Read the header comment there before changing a
//   number; the five is not arbitrary, it is "few enough that a wordlist is
//   useless, many enough that a person can mistype".
//   The static failure at the bottom: a NEW route in front of the auth gate
//   compares a caller-supplied value against a stored secret and charges
//   nothing for a wrong answer. Give that route a limiter and an attempt
//   counter, or, if it truly needs neither, add it to ALLOW with a reason.
//
// Needs nothing but node: no redis, no engine. The sessions this exercises
// live in a Map inside the relay process.
// Run: node --test test/guess-budget-gate.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const RUN = crypto.randomBytes(6).toString('hex');
const OWNER = `pgp_owner_key_for_the_budget_gate_${RUN}`;

// The relay's own documented example of a pre-shared secret, which is the
// point: this is what the passphrases being guessed at actually look like.
const PSS = `correct-horse-battery-staple-${RUN}`;
const commitmentFor = (s) => crypto.createHash('sha3-256').update(s).digest('hex');

// What relay.js enforces today. Read from the source rather than hard-coded, so
// this suite fails loudly on a silent change instead of quietly measuring the
// wrong number.
const RELAY_SRC = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
const MAX_ATTEMPTS = parseInt((RELAY_SRC.match(/SESSION_JOIN_MAX_ATTEMPTS\s*=\s*(\d+)/) || [])[1], 10);
const IP_WINDOW = parseInt(
  (RELAY_SRC.match(/function sessionJoinRateOk\([^)]*\)\s*\{[^}]*?,\s*(\d+)\s*,\s*[\d_]+\s*\)/) || [])[1], 10);

let srv = null;
let checks = 0;
const did = () => { checks++; };
const ready = () => srv !== null;

// Addresses. The per-IP window is global to the relay process, so each test
// gets its own space and no test measures another test's spending.
let _ipN = 0;
const nextIp = () => { _ipN++; return `10.11.${Math.floor(_ipN / 250)}.${(_ipN % 250) + 1}`; };
const CREATE_IP = '10.12.0.1';   // creates take no join budget; kept apart anyway
const SWEEP_IP = '10.13.0.1';    // the one address that measures the per-IP window

before(async () => {
  srv = await boot({
    tag: 'guessbudget',
    users: {
      api_keys: [
        { key: OWNER, plan: 'community', active: true, email: 'demo@example.com', account_id: `acct_demo_${RUN}` },
      ],
    },
  });
});

after(async () => {
  await killAll();
  summary('guess-budget-gate', checks);
});

// A session whose commitment is SHA3-256 of PSS, made the way a sender makes
// one: with an API key, over the real route.
async function newSession(secret = PSS) {
  const r = await srv.post('/v2/session/create', {
    headers: { 'X-Real-IP': CREATE_IP, 'X-Api-Key': OWNER },
    body: { commitment: commitmentFor(secret), ttl_ms: 600000 },
  });
  assert.strictEqual(r.status, 200, `session/create failed: ${r.status} ${r.text}`);
  return r.json.session_id;
}

const join = (sid, pss, ip) => srv.post('/v2/session/join', {
  headers: { 'X-Real-IP': ip },
  body: { session_id: sid, pss, ecdh_pub: 'aa'.repeat(32), kyber_pub: 'bb'.repeat(32) },
});

// ── 1. the budget hangs on the session, so a new address does not refill it ──

test('BUDGET: five wrong guesses end the session, however many addresses they come from', async () => {
  if (!ready()) return;
  assert.ok(Number.isInteger(MAX_ATTEMPTS) && MAX_ATTEMPTS > 0 && MAX_ATTEMPTS <= 20,
    `could not read SESSION_JOIN_MAX_ATTEMPTS out of relay.js (got ${MAX_ATTEMPTS}). If the constant was ` +
    'renamed, this suite is no longer measuring what it thinks it is.');

  const sid = await newSession();

  // Every attempt from a different source address. This is the shape that
  // defeats a purely per-IP defence, and it is not exotic: it is one line of
  // change for anyone renting a proxy pool.
  const left = [];
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    const r = await join(sid, `guess-number-${i}`, nextIp());
    assert.strictEqual(r.status, 403, `attempt ${i + 1} answered ${r.status} ${r.text}`);
    left.push(r.json.attempts_left);
  }
  // The count is visible to the caller on purpose: an honest receiver who
  // mistyped deserves to know how close they are to burning their transfer.
  assert.deepStrictEqual(left, Array.from({ length: MAX_ATTEMPTS }, (_, i) => MAX_ATTEMPTS - 1 - i),
    'each wrong answer must spend exactly one attempt and say how many are left');

  // One more from an address that has spent nothing. If the budget were per-IP
  // only, this would be a fresh start.
  const extra = await join(sid, 'guess-number-fresh-address', nextIp());
  assert.notStrictEqual(extra.status, 200, extra.text);

  // The load-bearing assertion, and it is asserted FIRST on purpose: a budget
  // that only slows an attacker down is a delay, a budget that destroys the
  // session is a cost, and that difference is what this test is for. The RIGHT
  // secret must now fail too. That is the correct end state: a session somebody
  // has guessed at five times is not one anyone should still be able to join,
  // and the sender can mint another in a millisecond.
  const right = await join(sid, PSS, nextIp());
  assert.notStrictEqual(right.status, 200,
    'the correct secret still opened a session that had already absorbed a full guessing budget.\n' +
    'That makes the budget a speed bump: the attacker waits out the window and continues where they\n' +
    'left off, and the sender never learns that anything happened.');

  assert.strictEqual(extra.status, 404,
    'a spent session must be GONE, not merely refusing. A new address must not buy a new budget.');
  assert.strictEqual(right.status, 404, right.text);
  did();
});

// ── 2. the per-IP window, measured against fresh sessions ───────────────────

test('BUDGET: one address gets a bounded number of guesses per minute across all sessions', async () => {
  if (!ready()) return;
  assert.ok(Number.isInteger(IP_WINDOW) && IP_WINDOW > 0 && IP_WINDOW <= 100,
    `could not read the sessionJoinRateOk window out of relay.js (got ${IP_WINDOW})`);

  // A DIFFERENT session every time, so the per-session budget above is never
  // the thing that stops this. What is being measured here is purely the
  // attacker's address, sweeping sessions rather than hammering one.
  const statuses = [];
  for (let i = 0; i < IP_WINDOW + 1; i++) {
    const sid = await newSession(`some-other-secret-${i}`);
    const r = await join(sid, 'not-the-secret', SWEEP_IP);
    statuses.push(r.status);
    if (r.status === 429) {
      assert.strictEqual(r.headers['retry-after'], '60',
        'a 429 without Retry-After tells a well-behaved client nothing and an attacker everything');
      break;
    }
    assert.strictEqual(r.status, 403, `attempt ${i + 1} answered ${r.status} ${r.text}`);
  }
  assert.strictEqual(statuses[statuses.length - 1], 429,
    `${IP_WINDOW + 1} guesses from one address were all accepted (${statuses.join(',')}). The per-session\n` +
    'budget does nothing against a sweep across sessions, so this window is the only thing standing\n' +
    'between one host and every session id it can find.');
  assert.strictEqual(statuses.filter((s) => s === 403).length, IP_WINDOW,
    'the window must allow exactly what it advertises, no more');
  did();
});

// ── 3. the route still works, and only once ─────────────────────────────────

test('USABLE: the right secret joins, and the second join is refused', async () => {
  if (!ready()) return;
  const sid = await newSession();
  const ip = nextIp();

  const ok = await join(sid, PSS, ip);
  assert.strictEqual(ok.status, 200, `the honest receiver could not get in: ${ok.status} ${ok.text}`);
  assert.strictEqual(ok.json.session_id, sid);
  assert.ok(ok.json.joined_at, 'a join records when it happened');

  // First join wins. The session binds the receiver's public keys, and a second
  // join would rebind them: whoever came second would be the one the sender
  // encrypts to. Refusing is the difference between a transfer and a hijack.
  const second = await join(sid, PSS, nextIp());
  assert.strictEqual(second.status, 409, second.text);
  did();
});

// ── 4. one digest, said the same way on both sides ──────────────────────────

test('ALGORITHM: a commitment made with SHA3-256 is joinable, and the create error says SHA3', async () => {
  if (!ready()) return;
  // The whole round trip in one assertion: the commitment is computed here with
  // sha3-256, /create accepts it, /join recomputes it and matches. If either
  // side ever moves to a different digest, this stops passing, which is the
  // only way a test can hold two ends of an agreement together.
  const sid = await newSession();
  const ok = await join(sid, PSS, nextIp());
  assert.strictEqual(ok.status, 200, 'a SHA3-256 commitment must be joinable with the secret behind it');

  // And the message an SDK author reads. This is not cosmetics: the create side
  // said SHA-256 for a long time while the join side computed SHA3-256. Both
  // produce 64 hex characters, so /create accepted the wrong digest happily and
  // the mistake only surfaced at join time as a 403 that blamed the secret. The
  // error text is the only documentation at the moment somebody needs it.
  const bad = await srv.post('/v2/session/create', {
    headers: { 'X-Real-IP': CREATE_IP, 'X-Api-Key': OWNER },
    body: { commitment: 'not-a-digest' },
  });
  assert.strictEqual(bad.status, 400, bad.text);
  assert.match(bad.json.error, /SHA3/,
    'the create error must name the digest the join side actually computes');
  assert.ok(!/SHA-256/.test(bad.json.error),
    `the create error names SHA-256: "${bad.json.error}". /join computes sha3-256, so this message sends\n` +
    'an SDK author to build sessions that can never be joined.');
  did();
});

// ── 5. the class, statically: no free guessing in front of the auth gate ────
//
// The four tests above prove one route. This one asks the question of every
// route, because the next place someone answers "is this secret right?"
// without a login will not be called /v2/session/join.
//
// It is deliberately narrow, in the spirit of authz-omission-gate.test.js: a
// broad scanner that fires on everything teaches people to ignore it. It looks
// only at route blocks that sit BEFORE the auth gate in relay.js (after the
// gate a caller has already been identified and rate limiting is a different
// conversation), and only flags one where a constant-time comparison is made
// against a stored secret or commitment. Route blocks reached through a
// pre-computed regex match are scanned too, but a route whose secret
// comparison is buried in a helper in another file is NOT seen; the
// behavioural tests above are what cover the route we know about.

const AUTH_GATE_MARKER = '!keyData?.active && !isEnvelopePublic';

// Comments blanked, string bodies kept: needed to read route path literals.
// Comments AND string bodies blanked: needed so prose about commitments is
// never mistaken for code that compares one. Both preserve every offset, so
// the two views of the file can be indexed against each other.
function blank(src, keepStrings) {
  let out = '';
  let i = 0;
  let state = 'code';
  let quote = '';
  while (i < src.length) {
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
    if (c === '\\') { out += (keepStrings ? src.slice(i, i + 2) : '  '); i += 2; continue; }
    if (c === quote) { state = 'code'; out += c; i++; continue; }
    out += (keepStrings ? c : (c === '\n' ? '\n' : ' ')); i++; continue;
  }
  return out;
}

// The head of a route block: an exact path, a path prefix, or a variable that
// holds an earlier regex match, each paired with a method test.
const ROUTE_HEAD = new RegExp(
  "if\\s*\\(\\s*(?:" +
  "path\\s*===\\s*'([^'\\n]{1,80})'" +
  "|path\\.startsWith\\s*\\(\\s*'([^'\\n]{1,80})'" +
  "|[A-Za-z_$][\\w$]*\\s*&&\\s*req\\.method" +
  ")", 'g');

// A caller-supplied value checked against a stored secret. Only the
// constant-time helpers and a direct comparison against a `.commitment` /
// `.secret` / `.pss` / `.passphrase` property count. `pin` and `secret` as bare
// words are not enough on their own: too many innocent identifiers contain them.
const SECRET_COMPARE =
  /(?:safeEqual|safeTextEqual|safeHexEqual|timingSafeEqual)\s*\([^;]{0,200}?\b(?:commitment|pss|secret|passphrase)\b|[!=]==\s*[A-Za-z_$][\w$]*\.(?:commitment|pss|secret|passphrase)\b/i;

// Something in the same block that makes a wrong answer cost the caller.
const BUDGET = /RateOk\s*\(|rateLimit\.|bad_attempts|MAX_ATTEMPTS|attempts_left/;

function blockFrom(code, idx) {
  const open = code.indexOf('{', idx);
  if (open === -1) return '';
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) return code.slice(open, i + 1); }
  }
  return code.slice(open);
}

// Returns every pre-gate route block that compares a secret, with whether it
// charges anything for a wrong answer.
function scanSource(src) {
  const withStrings = blank(src, true);
  const code = blank(src, false);
  const gateAt = code.indexOf(AUTH_GATE_MARKER);
  const out = { gateFound: gateAt >= 0, compared: [] };
  if (!out.gateFound) return out;

  ROUTE_HEAD.lastIndex = 0;
  for (let m; (m = ROUTE_HEAD.exec(withStrings)) !== null;) {
    if (m.index > gateAt) continue;
    const body = blockFrom(code, m.index);
    if (!SECRET_COMPARE.test(body)) continue;
    out.compared.push({
      route: m[1] || m[2] || `line ${code.slice(0, m.index).split('\n').length}`,
      line: code.slice(0, m.index).split('\n').length,
      budgeted: BUDGET.test(body),
    });
  }
  return out;
}

// Routes that compare a secret before the auth gate and knowingly charge
// nothing, with the reason. `count` is exact, like the allowlist in
// authz-omission-gate.test.js: an allowed shape that has been COPIED is a new
// finding wearing an old name. Empty today, and that is the point of writing it
// down rather than leaving the concept implicit.
const ALLOW = [];

test('CLASS: no route in front of the auth gate lets a secret be guessed at for free', () => {
  const found = scanSource(RELAY_SRC);
  assert.ok(found.gateFound,
    `the auth gate marker "${AUTH_GATE_MARKER}" is not in relay.js any more, so this scan cannot tell a\n` +
    'pre-auth route from a post-auth one and is silently checking nothing. Update AUTH_GATE_MARKER to\n' +
    'whatever the gate looks like now.');

  // Non-vacuity. /v2/session/join is the route this whole gate exists for, so
  // the scanner must be able to see it. If it stops seeing it, the regexes have
  // drifted and every green below is green over an empty set.
  assert.ok(found.compared.some((r) => r.route === '/v2/session/join'),
    'the scanner no longer recognises POST /v2/session/join as a pre-auth route that compares a secret.\n' +
    'It is the known instance of this class; a scanner that cannot find it finds nothing.');

  const naked = [];
  const used = new Map();
  for (const hit of found.compared) {
    if (hit.budgeted) continue;
    const rule = ALLOW.find((a) => a.route === hit.route);
    if (!rule) { naked.push(hit); continue; }
    used.set(rule, (used.get(rule) || 0) + 1);
  }

  if (naked.length) {
    assert.fail(
      'a route before the auth gate compares a caller-supplied value against a stored secret and\n' +
      'charges nothing for a wrong answer:\n' +
      naked.map((h) => `  relay.js:${h.line}  ${h.route}`).join('\n') +
      '\n\nWithout a login there is nothing to lock out, so the only currency is the attempt itself.\n' +
      'Give the block a per-IP window AND a per-target attempt counter that destroys the target when\n' +
      'it runs out, the way sessionJoinRateOk and SESSION_JOIN_MAX_ATTEMPTS do. Allowlisting it in\n' +
      'ALLOW above is the last resort and needs a reason a reviewer can check.');
  }

  for (const rule of ALLOW) {
    const seen = used.get(rule) || 0;
    assert.strictEqual(seen, rule.count,
      `${rule.route} is allowlisted ${rule.count}x and now occurs ${seen}x. A new copy of a known-bad ` +
      'shape is a new finding: fix it rather than raising the count.');
  }
  did();
});

test('CLASS: the scanner goes red on the shape it is meant to catch, and green on the fix', () => {
  // The unbudgeted version, which is what /v2/session/join looked like before
  // the review: parse, compare, answer, and leave the session standing.
  const broken = `
    if (path === '/v2/thing/join' && req.method === 'POST') {
      const d = JSON.parse(body);
      const sess = sessions.get(d.session_id);
      if (!sess) { res.writeHead(404); return res.end('nope'); }
      const h = crypto.createHash('sha3-256').update(d.pss).digest('hex');
      if (h !== sess.commitment) { res.writeHead(403); return res.end('wrong'); }
      sess.joined = true;
      res.writeHead(200); return res.end('ok');
    }
    } else if (!keyData?.active && !isEnvelopePublic && !isBillingWebhook) {
      res.writeHead(401);
    }
  `;
  const fixed = `
    if (path === '/v2/thing/join' && req.method === 'POST') {
      if (!thingJoinRateOk(clientIp)) { res.writeHead(429); return res.end('slow down'); }
      const d = JSON.parse(body);
      const sess = sessions.get(d.session_id);
      if (!sess) { res.writeHead(404); return res.end('nope'); }
      const h = crypto.createHash('sha3-256').update(d.pss).digest('hex');
      if (!authGate.safeEqual(h, sess.commitment)) {
        sess.bad_attempts = (sess.bad_attempts || 0) + 1;
        if (sess.bad_attempts >= THING_JOIN_MAX_ATTEMPTS) sessions.delete(d.session_id);
        res.writeHead(403);
        return res.end(JSON.stringify({ attempts_left: 1 }));
      }
      sess.joined = true;
      res.writeHead(200); return res.end('ok');
    }
    } else if (!keyData?.active && !isEnvelopePublic && !isBillingWebhook) {
      res.writeHead(401);
    }
  `;

  const b = scanSource(broken);
  assert.ok(b.gateFound, 'the fixture must contain the auth gate marker or the scan is a no-op');
  assert.strictEqual(b.compared.length, 1, 'the scanner must find the one pre-auth secret comparison');
  assert.strictEqual(b.compared[0].route, '/v2/thing/join');
  assert.strictEqual(b.compared[0].budgeted, false,
    'a comparison with no limiter and no attempt counter must read as unbudgeted');

  const f = scanSource(fixed);
  assert.strictEqual(f.compared.length, 1, 'the same route is still recognised after the fix');
  assert.strictEqual(f.compared[0].budgeted, true,
    'a rate check plus an attempt counter that destroys the session must read as budgeted');

  // And a route with a comparison that happens AFTER the gate is somebody
  // else's problem: the caller is identified there and can be locked out as an
  // account, so a bare comparison is not this class.
  const afterGate = `
    } else if (!keyData?.active && !isEnvelopePublic && !isBillingWebhook) {
      res.writeHead(401);
    }
    if (path === '/v2/thing/other' && req.method === 'POST') {
      if (!authGate.safeEqual(given, sess.commitment)) { res.writeHead(403); return res.end('no'); }
    }
  `;
  assert.deepStrictEqual(scanSource(afterGate).compared, [],
    'the scan must stop at the auth gate, or it will flag half the file and be turned off');
  did();
});
