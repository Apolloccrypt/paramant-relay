// Shared machinery for the hourly proof run.
//
// The rule this file exists to enforce: a step is green only when it produced
// evidence. The heartbeat it replaces was green on 2026-09-02 while doing
// nothing at all, because node:test prints a skipped test as `ok N - name #
// SKIP reason` and counts it in `# pass`. Two of the four steps in run
// 33624449015 asserted nothing; the ParaSign one finished its two real tests in
// 1.28 ms and 0.12 ms, which is less time than a TLS handshake. Nothing left
// the runner and the run was green.
//
// So there is no skip here. A missing secret is a hard failure that names the
// secret. Every check records what it saw - ids, hashes, status codes,
// milliseconds - into an evidence file that is uploaded as an artifact. A step
// that writes no evidence cannot report success: run.mjs checks for the file.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const RELAY = (process.env.PARAMANT_RELAY_URL || 'https://relay.paramant.app').replace(/\/$/, '');
export const SITE = (process.env.PARAMANT_BASE_URL || 'https://paramant.app').replace(/\/$/, '');
export const EVIDENCE_DIR = process.env.HEARTBEAT_EVIDENCE_DIR || 'heartbeat-evidence';

// Dry run talks to nothing. It exercises the wiring - argument handling,
// evidence shape, the failure path - so a change to this directory can be
// tested without touching production.
//
// It is never a way to pass, and that is enforced rather than asserted in a
// comment: every dry-run evidence file is marked `dry_run: true`, and run.mjs
// turns any dry run into summary.ok = false and a non-zero exit however many
// steps completed. Writing "a dry run can never stand in for proof" and then
// exiting 0 would be the same species of lie this whole directory exists to
// remove.
export const DRY_RUN = process.env.HEARTBEAT_DRY_RUN === '1';

// Every canary object carries this prefix so anything left behind on the relay
// is identifiable as ours and never mistaken for customer data.
export const PREFIX = 'canary-';

export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
export const nowIso = () => new Date().toISOString();

// A secret that is not set is the failure, not a reason to pass. The message
// names the secret because "the canary is red" without a name costs an hour of
// looking in the wrong place. This is the single most important line in the
// rewrite.
export function requireSecret(name, shapeHint) {
  const v = process.env[name];
  if (v && v.trim()) return v.trim();
  throw new HeartbeatError(
    `secret ${name} is not set`,
    `This step cannot prove anything without ${name}, so it fails instead of skipping.\n` +
    `  Set it with: gh secret set ${name}\n` +
    (shapeHint ? `  Expected shape: ${shapeHint}\n` : '') +
    `  The heartbeat this replaced treated a missing ${name} as a pass; that is the bug being fixed.`,
  );
}

// Carries a short cause for the one-line summary and a long explanation for the
// log. The summary line has to fit on one line in an annotation, the
// explanation does not.
export class HeartbeatError extends Error {
  constructor(cause, detail) {
    super(detail ? `${cause}\n  ${detail.split('\n').join('\n  ')}` : cause);
    this.name = 'HeartbeatError';
    this.cause_short = cause;
  }
}

export function assert(ok, cause, detail) {
  if (!ok) throw new HeartbeatError(cause, detail);
}

// Thresholds. Measured, not guessed: median round trip from the Netherlands on
// 2026-09-01 was 85-124 ms across /health, / and /v2/pubkey, worst sample 205
// ms. A GitHub runner adds roughly 150 ms of transit. The defaults sit an order
// of magnitude above that, wide enough that a cold cache never cries wolf and
// tight enough that a relay taking seconds per request cannot pass.
export const SLOW_MS = Number(process.env.HEARTBEAT_SLOW_MS || 2500);
// Signing does real cryptography and a PDF stamp, so it gets its own, looser
// budget. Still a ceiling: a ceremony that takes half a minute is broken for a
// human even when it returns 200.
export const SLOW_SIGN_MS = Number(process.env.HEARTBEAT_SLOW_SIGN_MS || 15000);

// Every timing is recorded, pass or fail. A threshold that only speaks when it
// trips gives no series to look at, and the first question after an incident is
// always "was it already creeping up?".
export async function timed(evidence, label, budgetMs, fn) {
  const t0 = performance.now();
  let out, failed = null;
  try {
    out = await fn();
  } catch (e) {
    failed = e;
  }
  const ms = Math.round(performance.now() - t0);
  evidence.timings.push({ label, ms, budget_ms: budgetMs, over: ms > budgetMs, at: nowIso() });
  console.log(`    ${label}: ${ms} ms (budget ${budgetMs} ms)`);
  if (failed) throw failed;
  assert(ms <= budgetMs, `${label} took ${ms} ms, over the ${budgetMs} ms budget`,
    'The request succeeded, so this is not an outage. It is the relay getting slow enough ' +
    'that a user notices. Check the relay process, redis and disk before raising the budget.');
  return out;
}

// One HTTP helper for every step, so every request that happens is recorded in
// the same shape and the evidence file is a complete transcript of what the run
// touched.
export async function http(evidence, method, url, { headers = {}, body, timeoutMs = 45000, raw = false } = {}) {
  const started = nowIso();
  const r = await fetch(url, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json', ...headers } : headers,
    body: body !== undefined ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  let bytes = null, text = null, json = null;
  if (raw) {
    bytes = Buffer.from(await r.arrayBuffer());
  } else {
    text = await r.text();
    try { json = JSON.parse(text); } catch { /* keep the raw body for the message */ }
  }
  evidence.requests.push({
    method, url, status: r.status, at: started,
    // Never the body: a response can carry a token. The hash proves identity
    // between two observations without publishing the value.
    body_sha256: bytes ? sha256(bytes) : (text ? sha256(Buffer.from(text)) : null),
    bytes: bytes ? bytes.length : (text ? Buffer.byteLength(text) : 0),
  });
  return { status: r.status, json, text, bytes, headers: r.headers };
}

export function newEvidence(step) {
  return {
    step,
    started_at: nowIso(),
    relay: RELAY,
    site: SITE,
    dry_run: DRY_RUN,
    runner: { run_id: process.env.GITHUB_RUN_ID || null, sha: process.env.GITHUB_SHA || null },
    // What the step claims to have proven, filled in as it goes. An empty list
    // at the end is itself a failure: see run.mjs.
    proofs: [],
    requests: [],
    timings: [],
    artifacts: {},
    cleanup: [],
  };
}

// A proof is a named thing the step actually observed, with the observation
// attached. "the receipt verifies" is worth nothing without the key id and the
// bytes it verified over.
export function proof(evidence, name, detail) {
  evidence.proofs.push({ name, at: nowIso(), ...detail });
  console.log(`    proof: ${name}`);
}

export function writeEvidence(evidence, ok, cause) {
  evidence.finished_at = nowIso();
  evidence.ok = ok;
  if (cause) evidence.cause = cause;
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  const file = path.join(EVIDENCE_DIR, `${evidence.step}.json`);
  fs.writeFileSync(file, JSON.stringify(evidence, null, 2));
  console.log(`  evidence: ${file} (${evidence.proofs.length} proofs, ${evidence.requests.length} requests)`);
  return file;
}

// Runs one step, always writes its evidence, and never lets a throw escape
// without recording why. Returns a result the orchestrator can summarise.
export async function runStep(name, fn) {
  const evidence = newEvidence(name);
  console.log(`\n=== ${name} ===`);
  try {
    await fn(evidence);
    assert(evidence.proofs.length > 0, `${name} produced no proofs`,
      'The step completed without recording a single observation, which means it proved nothing. ' +
      'That is exactly the failure mode this rewrite exists to remove.');
    writeEvidence(evidence, true);
    console.log(`  ${name}: GREEN`);
    return { name, ok: true, proofs: evidence.proofs.length };
  } catch (e) {
    const cause = e instanceof HeartbeatError ? e.cause_short : (e.message || String(e));
    writeEvidence(evidence, false, cause);
    console.log(`  ${name}: RED - ${cause}`);
    console.log(`${e.stack || e.message}`);
    return { name, ok: false, cause, proofs: evidence.proofs.length };
  }
}

// Best effort, and recorded either way. Cleanup that silently fails leaves
// canary data on production with nobody knowing, so the evidence file says
// what was attempted and what came back.
export async function cleanup(evidence, what, fn) {
  try {
    const status = await fn();
    evidence.cleanup.push({ what, ok: true, status, at: nowIso() });
  } catch (e) {
    evidence.cleanup.push({ what, ok: false, error: e.message, at: nowIso() });
    console.log(`    cleanup of ${what} failed: ${e.message} (not fatal, but the object may linger)`);
  }
}
