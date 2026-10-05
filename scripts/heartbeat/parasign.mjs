// Step (a): ParaSign, walked the whole way, in the two halves the product
// actually has.
//
// This is the step the old heartbeat was lying about. On 2026-09-02 it reported
// `ok 1 - parasign: an envelope is created, signed and notarised # SKIP` in
// 1.28 ms and the run went green. Nothing was created, nothing was signed, and
// in the whole retained log window not one human had signed anything either, so
// a broken ceremony would have sat there until a customer found it.
//
// The two halves are not a choice, they are how the product is built:
//
//   /v1 with a psk_ key is the developer API. With a psk_test_ key the sandbox
//   auto-signer completes the envelope inside the create call, which is what
//   produces a full .psign receipt with an ML-DSA-65 notary counter-signature.
//   That receipt is the evidence the product sells, so it gets verified here
//   offline against the relay's published key.
//
//   /v2 with a relay pgp_ key is the multi-party flow, and its sign route is
//   PUBLIC: no key, no header, exactly what a recipient's browser sends. The
//   auto-signer never touches it, so it is the only way to prove that the route
//   a real person clicks still verifies a signature. It also has a negative that
//   nothing else in this repo has: submit a signature that does not verify and
//   require the relay to refuse it.
//
// Doing only the first would leave the public ceremony untested, which is the
// state of the world this rewrite is fixing. Doing only the second would never
// look at a .psign receipt. So both, each with its own required secret.
//
// Nothing about a customer is read, sent or stored. The documents are throwaway
// blobs this file generates, and every object is prefixed canary-.
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import {
  RELAY, SLOW_MS, SLOW_SIGN_MS, PREFIX, DRY_RUN,
  assert, cleanup, http, proof, requireSecret, sha256, timed, HeartbeatError,
} from './lib.mjs';

const require = createRequire(import.meta.url);

// The repo's own code, not a reimplementation. If these move or change shape
// the canary must break loudly rather than quietly test something else.
let signMessageBytes, ctNodeHash, canonicalJSON, ml_dsa65;
try {
  ({ signMessageBytes } = require('../../relay/envelope.js'));
  ({ ctNodeHash } = require('../../relay/lib/ct-hash.js'));
  ({ canonicalJSON } = require('../../relay/parasign.js'));
} catch (e) {
  throw new HeartbeatError('the relay modules this canary verifies against could not be loaded',
    'Expected relay/envelope.js, relay/lib/ct-hash.js and relay/parasign.js relative to ' +
    `scripts/heartbeat/.\n  Original: ${e.message}`);
}
try {
  ({ ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js'));
} catch (e) {
  // Deliberately loud and specific. "Cannot find package" in an hourly alarm
  // reads as "production is broken" when it means "this job did not npm ci".
  throw new HeartbeatError('@noble/post-quantum is not installed, so no signature can be verified',
    'The heartbeat workflow runs `npm ci` before this script. A run that cannot verify a signature ' +
    `proves nothing, so it fails rather than passing quietly.\n  Original: ${e.message}`);
}

// ML-DSA-65 argument order, pinned in one place and checked on load.
//
// @noble/post-quantum 0.6.1 takes sign(message, secretKey) and
// verify(signature, message, publicKey). Three other orders exist in this tree:
// the relay's internal impl contract is verify(sig, msg, pub) (the same one),
// scripts/paramant-sign uses a stale variant, and the ParaSign canary this
// replaces called verify(publicKey, message, signature), which throws a
// RangeError on the installed version. Its secret was never set, so it always
// skipped and nobody found out.
//
// So the order lives here, behind names that say which is which, and the
// round-trip below runs at import: getting this wrong must break loudly at
// startup rather than turn into a mysterious production alarm at 03:17.
const mldsa = {
  keygen: (seed) => ml_dsa65.keygen(seed),
  sign: (secretKey, message) => ml_dsa65.sign(message, secretKey),
  verify: (publicKey, message, signature) => ml_dsa65.verify(signature, message, publicKey),
};

// The round trip that pins that order. Deliberately NOT run at import: a throw
// during module evaluation happens before run.mjs has a step to attribute it to,
// so no summary.json is written, no ::error:: annotation is emitted and the
// alarm degrades into a stack trace nobody parses. Called at the top of each
// step instead, inside the try/catch that runStep already provides, so broken
// crypto arrives as a named red step like any other failure.
//
// It is also what tests/heartbeat-lib.test.mjs calls, so the order is pinned by
// the suite rather than only by a comment.
export function assertMlDsaWrapper() {
  const kp = mldsa.keygen(crypto.randomBytes(32));
  const m = Buffer.from('heartbeat ml-dsa argument-order self-check');
  let ok = false;
  try {
    ok = mldsa.verify(kp.publicKey, m, mldsa.sign(kp.secretKey, m));
  } catch (e) {
    // noble throws a RangeError on a wrong-length argument rather than
    // returning false, which is exactly how the old canary would have died.
    throw new HeartbeatError('the ML-DSA-65 wrapper in parasign.mjs does not round-trip',
      'sign then verify with the same key threw, so the argument order no longer matches the ' +
      `installed @noble/post-quantum. Every signature check below would be meaningless.\n  Original: ${e.message}`);
  }
  if (!ok) {
    throw new HeartbeatError('the ML-DSA-65 wrapper in parasign.mjs does not round-trip',
      'sign then verify with the same key returned false. Either the argument order above is wrong ' +
      'or the installed @noble/post-quantum is not ML-DSA-65 any more.');
  }
  return true;
}

export { mldsa as _mldsa };

// One day, the shortest the envelope store will clamp to. A completed envelope
// cannot be voided (that is the point of completion) and the /v2 router has no
// delete, so the shortest possible retention IS the cleanup.
const TTL_DAYS = 1;

// ── half two: the public sign route, walked as a recipient ──────────────────
// Creating a /v2 envelope needs a relay API key (X-Api-Key, a pgp_ key), not a
// ParaSign bearer key: the two halves of the product authenticate differently
// and the canary must not pretend otherwise. The SIGNING itself deliberately
// carries no credential at all, because that is the whole point of the route.
export async function parasign(evidence) {
  assertMlDsaWrapper();
  const key = requireSecret('PARAMANT_CANARY_KEY', 'a relay API key (pgp_) that may create /v2 envelopes');

  if (DRY_RUN) {
    // The one thing worth exercising without a network: that the repo's message
    // recipe and ML-DSA agree with each other. If this breaks, every real run
    // would be red for a reason that has nothing to do with production.
    const seed = crypto.randomBytes(32);
    const kp = mldsa.keygen(seed);
    const pub = Buffer.from(kp.publicKey).toString('base64');
    const msg = signMessageBytes('canary'.padEnd(24, 'x'), 'ab'.repeat(32), 0, '', 4, pub, '');
    const sig = mldsa.sign(kp.secretKey, msg);
    assert(mldsa.verify(kp.publicKey, msg, sig), 'the repo recipe and ML-DSA-65 disagree locally',
      'signMessageBytes produced a message that its own signature does not verify over. This is a ' +
      'repo-local fault, not a production one.');
    proof(evidence, 'dry run: repo sign-message recipe v4 round-trips through ML-DSA-65', {
      message_sha256: sha256(Buffer.from(msg)), signature_bytes: sig.length, public_key_bytes: kp.publicKey.length,
    });
    return;
  }

  const auth = { 'X-Api-Key': key };

  // Where the CT log stood before we touched anything. Everything the CT check
  // asserts later is relative to this, so a busy log full of other people's
  // entries cannot be mistaken for our signature landing.
  const ctBefore = await http(evidence, 'GET', `${RELAY}/v2/ct/log?limit=1&from=0`, { timeoutMs: 20000 })
    .catch(() => ({ status: 0, json: null }));
  const ctSizeBefore = Number(ctBefore.json?.size ?? -1);
  const ctAvailable = ctBefore.status === 200 && Number.isFinite(ctSizeBefore) && ctSizeBefore >= 0;
  evidence.artifacts.ct = { available: ctAvailable, size_before: ctAvailable ? ctSizeBefore : null };

  // ── 1. create ─────────────────────────────────────────────────────────────
  const runId = crypto.randomUUID();
  const document = Buffer.from(`${PREFIX}parasign document ${runId} ${new Date().toISOString()}`);
  // sha3-256, because that is what the envelope store commits to.
  const docHash = crypto.createHash('sha3-256').update(document).digest('hex');
  evidence.artifacts.envelope = { canary_id: `${PREFIX}${runId}`, doc_sha3_256: docHash, doc_bytes: document.length };

  const created = await timed(evidence, 'POST /v2/envelopes', SLOW_SIGN_MS, () =>
    http(evidence, 'POST', `${RELAY}/v2/envelopes`, {
      headers: auth,
      body: {
        doc_hash: docHash,
        // Two parties: one is signed correctly, the other is used for the
        // negative check below. Both are labelled as canary data.
        parties: [{ label: `${PREFIX}recipient-a` }, { label: `${PREFIX}recipient-b` }],
        original_filename: `${PREFIX}${runId}.bin`,
        binding_mode: 'open',
        ttl_days: TTL_DAYS,
      },
    }));
  assert(created.status !== 401 && created.status !== 403,
    `the relay refused PARAMANT_CANARY_KEY on /v2/envelopes: HTTP ${created.status}`,
    'The key is set but the relay does not accept it for envelope creation. A monitoring credential ' +
    'that no longer works measures nothing, so this is red rather than skipped.');
  assert(created.status !== 429, 'envelope creation is rate-limited for this key (HTTP 429)',
    'The canary creates one envelope per hour against a 50/hour cap, so a 429 means something else is ' +
    'burning the quota on this key.');
  assert(created.status !== 503, 'the envelope store is unavailable (HTTP 503)',
    'The relay answered but redis or the crypto registry is not ready, so ParaSign cannot sign at all.');
  assert(created.status === 200, `envelope creation failed: HTTP ${created.status}`, created.text?.slice(0, 300));
  const env = created.json?.envelope;
  assert(!!env?.id, 'the relay accepted the envelope but returned no id', JSON.stringify(created.json).slice(0, 300));
  const id = env.id;
  evidence.artifacts.envelope.id = id;
  proof(evidence, 'envelope created', {
    id, binding_mode: env.binding_mode, recipe_version: env.recipe_version,
    party_count: env.party_count, ttl_days: TTL_DAYS,
  });

  // ── 2. the document capsule ───────────────────────────────────────────────
  // The relay stores ciphertext only and never learns the key, so what is
  // asserted here is that it stored the exact bytes it was handed: it must
  // agree on the sha256 the upload declared.
  const capsuleHash = sha256(document);
  const doc = await timed(evidence, 'POST /v2/envelopes/:id/document', SLOW_SIGN_MS, () =>
    http(evidence, 'POST', `${RELAY}/v2/envelopes/${id}/document`, {
      headers: { ...auth, 'Content-Type': 'application/octet-stream', 'X-Capsule-Sha256': capsuleHash },
      body: document.toString('latin1'),
    }));
  assert(doc.status === 200, `document upload failed: HTTP ${doc.status}`, doc.text?.slice(0, 300));
  assert(doc.json?.sha256 === capsuleHash, 'the relay stored the capsule under a different hash',
    `Declared ${capsuleHash}, relay says ${doc.json?.sha256}. The recipient would decrypt something ` +
    'other than what was sent.');
  proof(evidence, 'document capsule stored and the relay agrees on its hash', {
    sha256: doc.json.sha256, size: doc.json.size, expires_in: doc.json.expires_in,
  });

  // ── 3. the recipient's view, over the public route ────────────────────────
  const view = await timed(evidence, 'GET /v2/envelopes/:id?p=0 (public party view)', SLOW_MS, () =>
    http(evidence, 'GET', `${RELAY}/v2/envelopes/${id}?p=0`, { timeoutMs: 20000 }));
  assert(view.status === 200, `a recipient cannot read the envelope: HTTP ${view.status}`,
    'This is the first thing a person clicking a signing link does. A failure here is a dead ceremony ' +
    'no matter how healthy the rest of the relay is.');
  const pv = view.json?.envelope;
  assert(pv?.doc_hash === docHash, 'the party view shows a different document hash than the one created',
    `Created ${docHash}, view says ${pv?.doc_hash}.`);
  assert(!!view.json?.sign_message_recipe, 'the party view carries no sign_message_recipe',
    'Without it a recipient client cannot know what bytes to sign.');
  // The relay must not hand a public caller the invite secrets.
  const leaked = JSON.stringify(pv || {}).match(/invite_token/);
  assert(!leaked, 'the public party view leaks invite_token', 'Those are per-party capability secrets.');
  proof(evidence, 'a recipient can read the envelope and is told the sign recipe', {
    status: pv.status, doc_hash: pv.doc_hash, binding_mode: pv.binding_mode,
    recipe_version: pv.recipe_version, recipe: view.json.sign_message_recipe,
  });

  // ── 4-5. sign, and prove a bad signature is refused ───────────────────────
  // Open-mode slots are signer-bound: the effective recipe is v4, which appends
  // the signer's public key so the signature commits to the exact key. Built
  // here with the relay's own signMessageBytes.
  const EFFECTIVE_RECIPE = 4;
  const seed = crypto.randomBytes(32);
  const kp = mldsa.keygen(seed);
  const signerPub = Buffer.from(kp.publicKey).toString('base64');
  const msg = signMessageBytes(id, docHash, 0, '', EFFECTIVE_RECIPE, signerPub, '');
  const sig = mldsa.sign(kp.secretKey, msg);
  const sigB64 = Buffer.from(sig).toString('base64');

  // The negative first, deliberately. Doing it on party 1 leaves party 0 clean,
  // and doing it BEFORE the good signature means a relay that accepts anything
  // is caught before the envelope completes and closes.
  const badPub = Buffer.from(mldsa.keygen(crypto.randomBytes(32)).publicKey).toString('base64');
  const badSig = crypto.randomBytes(sig.length).toString('base64');
  const refused = await timed(evidence, 'POST /v2/envelopes/:id/sign (deliberately invalid)', SLOW_SIGN_MS, () =>
    http(evidence, 'POST', `${RELAY}/v2/envelopes/${id}/sign`, {
      body: { party_index: 1, signer_public_key: badPub, signature: badSig },
    }));
  assert(refused.status === 400 && refused.json?.error === 'bad_signature',
    `the relay accepted a signature that does not verify: HTTP ${refused.status} ${JSON.stringify(refused.json)}`,
    'This is the check that separates "the endpoint answered 200" from "the relay actually verifies". ' +
    'A relay that rubber-stamps would pass every positive test ever written and produce evidence ' +
    'that means nothing.');
  proof(evidence, 'the relay refuses a signature that does not verify', {
    party_index: 1, status: refused.status, error: refused.json?.error,
  });

  // Now the real one, over the public route, exactly as a recipient's browser
  // would send it: no API key, no internal header.
  const signed = await timed(evidence, 'POST /v2/envelopes/:id/sign (party 0)', SLOW_SIGN_MS, () =>
    http(evidence, 'POST', `${RELAY}/v2/envelopes/${id}/sign`, {
      body: { party_index: 0, signer_public_key: signerPub, signature: sigB64 },
    }));
  assert(signed.status !== 400 || signed.json?.error !== 'bad_signature',
    'the relay rejected a correctly built signature as bad_signature',
    'The sign message this canary builds with relay/envelope.js signMessageBytes (recipe v4, open ' +
    'mode) is no longer the message production expects. Either the recipe changed on one side only, ' +
    'or signature verification on the relay is broken. Every recipient is hitting this too.');
  assert(signed.status === 200, `the public sign route failed: HTTP ${signed.status}`, signed.text?.slice(0, 300));
  proof(evidence, 'a recipient signed over the public route and the relay verified it', {
    party_index: 0, status: signed.status, code: signed.json?.code ?? null,
    signed_count: signed.json?.signed_count ?? null,
    signer_pk_sha3_256: crypto.createHash('sha3-256').update(Buffer.from(signerPub, 'base64')).digest('hex'),
    message_sha256: sha256(Buffer.from(msg)),
    signature_bytes: sig.length,
  });

  // ── 6. verify offline, independently of what the relay says ───────────────
  const offline = mldsa.verify(kp.publicKey, msg, sig);
  assert(offline, 'the signature the relay accepted does not verify offline',
    'ML-DSA-65 verification of the exact bytes that were signed failed locally. Either @noble/' +
    'post-quantum disagrees with the relay about ML-DSA-65, or the message recipe differs between ' +
    'the two, and in both cases the evidence the product produces is not sound.');
  proof(evidence, 'the signature verifies offline against ML-DSA-65, without asking the relay', {
    algorithm: 'ML-DSA-65', recipe_version: EFFECTIVE_RECIPE,
    message_sha256: sha256(Buffer.from(msg)),
    public_key_sha256: sha256(Buffer.from(kp.publicKey)),
    signature_sha256: sha256(Buffer.from(sig)),
  });

  // ── 7. the envelope's own account of itself ───────────────────────────────
  const after = await timed(evidence, 'GET /v2/envelopes/:id (status after signing)', SLOW_MS, () =>
    http(evidence, 'GET', `${RELAY}/v2/envelopes/${id}`, { timeoutMs: 20000 }));
  assert(after.status === 200, `the envelope status is unreadable after signing: HTTP ${after.status}`);
  const sc = Number(after.json?.envelope?.signed_count ?? -1);
  assert(sc >= 1, `the relay returned 200 for the signature but reports signed_count ${sc}`,
    'The signature was accepted and then not recorded. That is worse than a refusal: the recipient ' +
    'believes they signed.');
  proof(evidence, 'the signature is recorded in the envelope state', {
    status: after.json.envelope.status, signed_count: sc, party_count: after.json.envelope.party_count,
  });

  // ── 8. the transparency log ───────────────────────────────────────────────
  if (!ctAvailable) {
    // Recorded, not asserted. The CT log is not present in every relay mode, and
    // inventing a requirement production never promised would be its own kind of
    // false alarm. The observation is kept so its absence is at least visible.
    proof(evidence, 'CT log not reachable, so the append was not checked (recorded, not asserted)', {
      status: ctBefore.status,
    });
  } else {
    // The log is a fixed-size window, so read the tail rather than assuming
    // indices. The relay appends synchronously inside the sign handler, but give
    // it a moment: the assertion should fail on a missing append, not on a race.
    let found = null, sizeAfter = ctSizeBefore;
    for (let attempt = 0; attempt < 5 && !found; attempt++) {
      if (attempt) await new Promise((r) => setTimeout(r, 1000));
      const from = Math.max(0, ctSizeBefore - 1);
      const log = await http(evidence, 'GET', `${RELAY}/v2/ct/log?from=${from}&limit=200`, { timeoutMs: 20000 });
      if (log.status !== 200) continue;
      sizeAfter = Number(log.json?.size ?? sizeAfter);
      found = (log.json?.entries || [])
        .filter((e) => e.index >= ctSizeBefore && e.type === 'envelope_sign')
        .pop() || null;
    }
    assert(sizeAfter > ctSizeBefore, `the CT log did not grow (size ${ctSizeBefore} before and after)`,
      'A signature was accepted and recorded but nothing was appended to the transparency log, so the ' +
      'tamper-evidence the product is sold on did not happen.');
    assert(!!found, 'no envelope_sign entry appeared in the CT log after the signature',
      `The log grew from ${ctSizeBefore} to ${sizeAfter}, but none of the new entries is an ` +
      'envelope_sign. The public projection carries no envelope id, so this is the strongest ' +
      'identification available from outside.');

    // The inclusion proof, folded here with the relay's own ctNodeHash. This is
    // the difference between "the log says it has an entry" and "the entry is
    // provably in the tree the log publishes".
    const pr = await timed(evidence, `GET /v2/ct/proof/${found.index}`, SLOW_MS, () =>
      http(evidence, 'GET', `${RELAY}/v2/ct/proof/${found.index}`, { timeoutMs: 20000 }));
    assert(pr.status === 200, `no inclusion proof for CT index ${found.index}: HTTP ${pr.status}`);
    let folded = pr.json.leaf_hash;
    for (const step of pr.json.proof || []) {
      folded = step.position === 'right' ? ctNodeHash(folded, step.hash) : ctNodeHash(step.hash, folded);
    }
    assert(folded === pr.json.tree_hash,
      `the CT inclusion proof for index ${found.index} does not fold to the published tree head`,
      `Folded to ${folded}, the log publishes ${pr.json.tree_hash}. The transparency log is ` +
      'internally inconsistent, which makes every receipt it backs unverifiable.');
    proof(evidence, 'the new signature is in the CT log and its Merkle inclusion proof verifies', {
      size_before: ctSizeBefore, size_after: sizeAfter,
      index: found.index, type: found.type,
      leaf_hash: pr.json.leaf_hash, tree_hash: pr.json.tree_hash,
      proof_steps: (pr.json.proof || []).length,
      recomputed_root: folded,
    });
  }

  // Cleanup. A completed envelope is immutable by design, so there is nothing
  // to delete and the one-day TTL is the disposal. Recorded so this does not
  // read as an oversight.
  evidence.cleanup.push({
    what: `envelope ${id}`,
    ok: true,
    status: `no void route exists on the /v2 router and a complete envelope is immutable by design; ` +
            `created with ttl_days=${TTL_DAYS}, the shortest retention the store accepts`,
  });
}

// ── half one: the .psign receipt and its notary counter-signature ───────────
//
// The developer API, driven with the ParaSign canary key. A psk_test_ key makes
// the sandbox auto-signer complete the envelope inside the create call, which is
// what produces a full receipt: every party's ML-DSA-65 signature plus the
// relay's counter-signature over the canonical JSON of the whole thing.
//
// The counter-signature is the part that matters. A route can answer 200 with a
// receipt nobody can verify, and that is precisely the failure a status page
// cannot see. So it is verified here, offline, against the key the relay
// publishes at /v2/pubkey - not against the key printed inside the receipt,
// which would let a receipt vouch for itself.
export async function parasignReceipt(evidence) {
  assertMlDsaWrapper();
  const key = requireSecret('PARASIGN_CANARY_KEY', 'a ParaSign bearer key, psk_test_ so the run is sandbox-flagged');

  if (DRY_RUN) {
    // Without a network the useful thing to exercise is that the repo's
    // canonicaliser is stable, since the notary signs its output byte for byte.
    const a = canonicalJSON({ b: 1, a: [3, { z: 0, y: 1 }] });
    const b = canonicalJSON({ a: [3, { y: 1, z: 0 }], b: 1 });
    assert(a === b && a === '{"a":[3,{"y":1,"z":0}],"b":1}',
      'relay/parasign.js canonicalJSON is not producing the expected byte string',
      `Got ${a} and ${b}. The notary signs this output, so a change here invalidates every receipt.`);
    proof(evidence, 'dry run: the repo canonicaliser the notary signs over is stable', { canonical: a });
    return;
  }

  const auth = { Authorization: `Bearer ${key}` };
  const runId = crypto.randomUUID();
  const pdf = throwawayPdf(runId);

  const created = await timed(evidence, 'POST /v1/envelopes', SLOW_SIGN_MS, () =>
    http(evidence, 'POST', `${RELAY}/v1/envelopes`, {
      headers: auth,
      body: {
        document: { content_base64: pdf.toString('base64') },
        signers: [{ name: `${PREFIX}signer-a` }, { name: `${PREFIX}signer-b` }],
        // Open, so no mailbox is involved anywhere in this run.
        binding_mode: 'open',
        original_filename: `${PREFIX}${runId}.pdf`,
        ttl_days: TTL_DAYS,
      },
    }));
  assert(created.status !== 401, `the relay refused PARASIGN_CANARY_KEY: HTTP 401`,
    'The bearer key is set but unknown, revoked, or not a psk_ key. A monitoring credential that no ' +
    'longer works measures nothing, so this is red rather than skipped.');
  assert(created.status !== 403, 'PARASIGN_CANARY_KEY has no parasign scope (HTTP 403)',
    'The key authenticates but is not allowed to create envelopes.');
  assert(created.status !== 402, 'the canary key has hit its monthly sign quota (HTTP 402)',
    `The relay says: ${created.text?.slice(0, 200)}. An hourly canary needs headroom of about 1500 ` +
    'signatures a month, so the key needs a plan that allows it.');
  assert(created.status === 201, `envelope creation failed: HTTP ${created.status}`, created.text?.slice(0, 300));
  const env = created.json;
  const id = env?.id;
  assert(!!id, 'the relay accepted the envelope but returned no id', JSON.stringify(env).slice(0, 300));
  evidence.artifacts.v1_envelope = { id, mode: env.mode, doc_hash: env.doc_hash, binding_mode: env.binding_mode };

  // Cleanup is defined before anything else can fail and is invoked from the
  // finally below, so a failure anywhere in the walk still tries to retract. A
  // completed envelope is immutable by design and answers 409 already_complete;
  // that is recorded rather than treated as a cleanup failure.
  evidence._void = async () => {
    await cleanup(evidence, `envelope ${id}`, async () => {
      const v = await http(evidence, 'POST', `${RELAY}/v1/envelopes/${id}/void`,
        { headers: auth, body: { reason: 'heartbeat canary' }, timeoutMs: 20000 });
      return v.status === 409
        ? '409 already_complete: a completed envelope is immutable by design, so ttl_days=1 is the disposal'
        : `HTTP ${v.status}`;
    });
  };

  // Everything from here on runs inside a try/finally so the void is attempted
  // however the run ends. The comment above used to promise that and the code
  // only did it on the success path, which meant a canary envelope was left
  // behind by exactly the runs that mattered: the failing ones.
  try {
    await receiptChecks(evidence, auth, id, env);
  } finally {
    await evidence._void();
    delete evidence._void;
  }
}

// The rest of the receipt walk, extracted only so the caller above can wrap it
// in one try/finally without burying the assertions two levels deep.
async function receiptChecks(evidence, auth, id, env) {
  assert(env.status === 'completed',
    `the sandbox signer did not complete the envelope: status ${env.status}`,
    `mode=${env.mode}. With a psk_test_ key the auto-signer completes the envelope inside the create ` +
    'call. A psk_live_ key never auto-signs, and if the signing engine is down the relay says so in ' +
    `_sandbox_note: ${JSON.stringify(env._sandbox_note ?? null)}.`);
  assert(Array.isArray(env.signers) && env.signers.every((x) => x.status === 'completed'),
    'not every signer slot completed',
    `Slots: ${JSON.stringify((env.signers || []).map((x) => x.status))}.`);
  proof(evidence, 'envelope created and driven to completed by the sandbox signer', {
    id, mode: env.mode, binding_mode: env.binding_mode, doc_hash: env.doc_hash,
    signers: env.signers.map((x) => ({ index: x.index, status: x.status })),
  });

  // ── the receipt ───────────────────────────────────────────────────────────
  const rec = await timed(evidence, 'GET /v1/envelopes/:id/receipt', SLOW_SIGN_MS, () =>
    http(evidence, 'GET', `${RELAY}/v1/envelopes/${id}/receipt`, { headers: auth }));
  assert(rec.status !== 409, 'the receipt is not ready for a completed envelope (HTTP 409)',
    'The envelope reports completed and the notary has produced nothing. That is a receipt that will ' +
    'never arrive for a customer either.');
  assert(rec.status !== 503, 'the notary is unavailable (HTTP 503)',
    'Signing works but nothing can be notarised, so no receipt is verifiable.');
  assert(rec.status === 200, `receipt failed: HTTP ${rec.status}`, rec.text?.slice(0, 300));
  const psign = rec.json;
  assert(psign?.type === 'parasign-envelope-receipt', 'what came back is not a ParaSign envelope receipt',
    `type is ${JSON.stringify(psign?.type)}.`);
  assert(psign.document_hash === env.doc_hash, 'the receipt commits to a different document than the envelope',
    `Envelope ${env.doc_hash}, receipt ${psign.document_hash}.`);
  assert(Array.isArray(psign.parties) && psign.parties.length === 2,
    `the receipt does not carry both parties (${psign.parties?.length})`);
  assert(!!psign.notary_signature, 'no notary counter-signature on the receipt',
    'Without it the receipt is a JSON file anyone could have written.');

  // ── the notary signature, verified against the PUBLISHED key ──────────────
  const pub = await timed(evidence, 'GET /v2/pubkey', SLOW_MS, () =>
    http(evidence, 'GET', `${RELAY}/v2/pubkey`, { timeoutMs: 20000 }));
  assert(pub.status === 200, `/v2/pubkey failed: HTTP ${pub.status}`,
    'Without the published key the receipt can only vouch for itself.');
  assert(psign.notary?.relay_public_key === pub.json?.public_key,
    'the receipt was notarised with a key the relay does not publish',
    'A receipt that verifies only against a key printed inside itself proves nothing. Receipt key ' +
    `sha256 ${sha256(Buffer.from(String(psign.notary?.relay_public_key)))}, published key sha256 ` +
    `${sha256(Buffer.from(String(pub.json?.public_key)))}.`);

  // The signature covers the canonical JSON of the receipt WITHOUT the
  // signature field, built with the relay's own canonicaliser so a change to it
  // shows up here rather than silently invalidating every receipt in the field.
  const { notary_signature, ...signedPart } = psign;
  const notaryMsg = Buffer.from(canonicalJSON(signedPart), 'utf8');
  const notaryOk = mldsa.verify(
    Buffer.from(pub.json.public_key, 'base64'), notaryMsg, Buffer.from(notary_signature, 'base64'));
  assert(notaryOk, 'the notary counter-signature does NOT verify',
    'The relay produced a receipt that its own published key does not vouch for. Every receipt issued ' +
    'in this state is worthless as evidence, and a customer would only find out when they tried to ' +
    'rely on one.');
  proof(evidence, 'the notary counter-signature verifies offline against the published relay key', {
    algorithm: psign.algorithm ?? 'ML-DSA-65',
    canonical_sha256: sha256(notaryMsg), canonical_bytes: notaryMsg.length,
    relay_pk_sha256: sha256(Buffer.from(pub.json.public_key, 'base64')),
    notary_signature_sha256: sha256(Buffer.from(notary_signature, 'base64')),
  });

  // ── each party's own signature ────────────────────────────────────────────
  // Same rule the store applies: open-mode slots are signer-bound, so the
  // effective recipe is 4 whatever the receipt says it stored.
  const effective = (psign.binding_mode || 'open') === 'open' ? 4 : (Number(psign.recipe_version) || 1);
  const parties = [];
  for (const party of psign.parties) {
    assert(!!party.signature && !!party.public_key,
      `party ${party.index} has no signature or no public key`,
      'A completed slot with nothing in it is a slot that was marked done without being signed.');
    const msg = signMessageBytes(
      psign.envelope_id, psign.document_hash, party.index,
      party.email_hash || '', effective, party.public_key, party.appearance_hash || '');
    const ok = mldsa.verify(
      Buffer.from(party.public_key, 'base64'), msg, Buffer.from(party.signature, 'base64'));
    assert(ok, `party ${party.index}'s signature does not verify`,
      `Rebuilt the sign message with relay/envelope.js signMessageBytes at recipe ${effective} and ` +
      'ML-DSA-65 rejects the signature the receipt carries. Either the recipe moved on one side only ' +
      'or the signature is not real.');
    parties.push({
      index: party.index, signer_pk_hash: party.signer_pk_hash ?? null,
      message_sha256: sha256(Buffer.from(msg)), verified: true,
    });
  }
  proof(evidence, "every party's signature in the receipt verifies offline", {
    recipe_used: effective, binding_mode: psign.binding_mode, parties,
  });

  // A sandbox receipt must say so inside the SIGNED evidence, or a test receipt
  // could be passed off as a real one.
  if (env.mode === 'test') {
    assert(psign.mode === 'test', 'a test receipt is not flagged mode:test inside the signed evidence');
    assert(psign.sandbox === true, 'a test receipt is not flagged sandbox:true inside the signed evidence');
    proof(evidence, 'the test nature travels inside the signed evidence', { mode: psign.mode, sandbox: psign.sandbox });
  }

  // ── the stamped document ──────────────────────────────────────────────────
  const doc = await timed(evidence, 'GET /v1/envelopes/:id/document', SLOW_SIGN_MS, () =>
    http(evidence, 'GET', `${RELAY}/v1/envelopes/${id}/document`, { headers: auth, raw: true }));
  assert(doc.status === 200, `signed document failed: HTTP ${doc.status}`);
  assert(doc.bytes.subarray(0, 5).toString('latin1') === '%PDF-', 'what came back is not a PDF',
    `First bytes: ${JSON.stringify(doc.bytes.subarray(0, 16).toString('latin1'))}.`);
  assert(doc.headers.get('x-parasign-stamped') === 'true',
    'the relay served the original PDF, not a stamped one',
    'X-ParaSign-Stamped is false, which the relay sets when the stamp worker fell back to the ' +
    'original. The customer receives an unsigned-looking document.');
  proof(evidence, 'the signed document comes back as a server-stamped PDF', {
    bytes: doc.bytes.length, sha256: sha256(doc.bytes), stamped: true,
  });

}

// A minimal valid PDF, written by hand so the canary carries no PDF dependency
// of its own. pdf-lib lives in the frontend, not in the root install this runs
// from, and a canary that cannot start is not a canary.
function throwawayPdf(mark) {
  const objs = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
  ];
  const stream = `BT /F1 12 Tf 60 780 Td (${PREFIX}parasign ${mark}) Tj ET`;
  objs.push(`5 0 obj\n<< /Length ${stream.length} >>\nstream\n${stream}\nendstream\nendobj\n`);
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (const o of objs) { offsets.push(pdf.length); pdf += o; }
  const xref = pdf.length;
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i++) pdf += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  pdf += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, 'latin1');
}
