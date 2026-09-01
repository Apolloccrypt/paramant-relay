// ParaSign canary: does the signing product still sign, end to end, right now.
//
// The transfer canary proves ParaSend moves a file. Nothing proved that ParaSign
// signs. In the whole retained log window (22 Aug - 1 Sep 2026, 218140 lines)
// there was not one human signing, so a break in the signing ceremony would sit
// there unnoticed for as long as nobody happened to try it. This is the alarm.
//
// It uses a psk_test_ key on purpose. That key drives the sandbox auto-signer,
// so the run needs no human, no mailbox and no real document: the payload is a
// throwaway PDF this file generates. Nothing about a customer is read, sent or
// stored, which is what makes an hourly check compatible with the privacy
// promise the product is sold on.
//
// What it actually proves, in order:
//   1. the relay accepts an envelope and drives it to completed
//   2. the receipt is a real, structurally complete .psign
//   3. the notary counter-signature is an ML-DSA-65 signature over the exact
//      canonical JSON of the receipt, verified here against the relay's own
//      published public key, not merely present
//   4. the signed document comes back as a server-stamped PDF
//   5. the test nature travels inside the signed evidence (mode: test)
//
// Point 3 is the one that matters. A route can answer 200 with a receipt that
// no one can verify; that is exactly the failure a status page cannot see.
//
//   PARASIGN_CANARY_KEY=psk_test_... node --test tests/parasign-canary.test.mjs
//
// It cleans up after itself: the envelope is voided at the end.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

// Loaded dynamically, and the failure is deliberately loud. A static import
// throws ERR_MODULE_NOT_FOUND before a single line of this file runs, and
// "Cannot find package" in an hourly heartbeat reads as "production is broken"
// when it means "this job did not npm ci". The canary still FAILS without it,
// because a run that cannot verify a signature proves nothing and must not pass
// quietly, but it fails saying which job owes it an install.
let ml_dsa65;
try {
  ({ ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js'));
} catch (e) {
  throw new Error(
    '@noble/post-quantum is not installed, so the notary signature cannot be verified.\n' +
    '  This canary runs in .github/workflows/product-heartbeat.yml, which does `npm ci` first.\n' +
    '  It is deliberately excluded from the no-install job in test.yml.\n' +
    `  Original: ${e.message}`);
}

const RELAY = (process.env.PARAMANT_RELAY_URL || 'https://relay.paramant.app').replace(/\/$/, '');
const KEY = process.env.PARASIGN_CANARY_KEY || '';
const skip = KEY ? false : 'PARASIGN_CANARY_KEY not set (needs a psk_test_ key)';

// Canonical JSON exactly as relay/parasign.js does it: sorted keys, no spaces.
// The notary signs this byte string, so a mismatch here is a false alarm.
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(obj).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

// A minimal valid PDF, written by hand so the canary carries no PDF dependency
// of its own. pdf-lib lives in the frontend, not in the root install this runs
// from, and a canary that cannot start is not a canary.
function throwawayPdf() {
  const mark = crypto.randomUUID();
  const objs = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
  ];
  const stream = `BT /F1 12 Tf 60 780 Td (ParaSign canary ${mark}) Tj ET`;
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

const auth = { Authorization: `Bearer ${KEY}` };

async function api(method, path, body) {
  const r = await fetch(`${RELAY}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json', ...auth } : auth,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(45000),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep the raw body for the message */ }
  return { status: r.status, json, text, headers: r.headers };
}

test('parasign: an envelope is created, signed and notarised', { skip }, async (t) => {
  const pdf = throwawayPdf();

  const created = await api('POST', '/v1/envelopes', {
    document: { content_base64: pdf.toString('base64') },
    binding_mode: 'open',
    original_filename: 'canary.pdf',
    signers: [{ name: 'Canary A' }, { name: 'Canary B' }],
  });
  assert.equal(created.status, 201, `create rejected: HTTP ${created.status} ${created.text.slice(0, 300)}`);
  const env = created.json;
  assert.equal(env?.status, 'completed', `the sandbox signer did not complete the envelope: status ${env?.status}`);
  assert.ok(env.signers?.every((s) => s.status === 'completed'), 'not every signer slot completed');
  const id = env.id;

  t.after(async () => { try { await api('POST', `/v1/envelopes/${id}/void`); } catch { /* best effort */ } });

  // ── the receipt, and whether its notary signature actually verifies ────────
  const rec = await api('GET', `/v1/envelopes/${id}/receipt`);
  assert.equal(rec.status, 200, `receipt failed: HTTP ${rec.status} ${rec.text.slice(0, 200)}`);
  const psign = rec.json;
  assert.equal(psign.type, 'parasign-envelope-receipt', 'receipt is not a parasign envelope receipt');
  assert.equal(psign.parties?.length, 2, 'receipt does not carry both parties');
  for (const p of psign.parties) {
    assert.ok(p.signature, `party ${p.index} has no signature`);
    assert.ok(p.public_key, `party ${p.index} has no public key`);
  }
  assert.ok(psign.notary_signature, 'no notary counter-signature on the receipt');
  assert.ok(psign.notary?.relay_public_key, 'the receipt does not name the notary public key');

  // The signature is over the canonical JSON of the receipt WITHOUT the
  // signature field. Verifying it here is the difference between "the endpoint
  // answered" and "the evidence it produced is sound".
  const { notary_signature, ...signed } = psign;
  const okSig = ml_dsa65.verify(
    Buffer.from(psign.notary.relay_public_key, 'base64'),
    Buffer.from(canonicalJSON(signed), 'utf8'),
    Buffer.from(notary_signature, 'base64'),
  );
  assert.ok(okSig, 'the notary signature does NOT verify: the receipt is not sound evidence');

  // The key in the receipt must be the key the relay publishes, or a receipt
  // could verify against a key only the attacker holds.
  const pub = await fetch(`${RELAY}/v2/pubkey`, { signal: AbortSignal.timeout(20000) });
  assert.equal(pub.status, 200, `/v2/pubkey failed: HTTP ${pub.status}`);
  const published = await pub.json();
  assert.equal(
    psign.notary.relay_public_key, published.public_key,
    'the receipt was notarised with a key that is not the published relay key',
  );

  // A sandbox envelope must say so inside the signed evidence, so a test
  // receipt can never be passed off as a real one.
  assert.equal(psign.mode, 'test', 'a psk_test_ receipt is not flagged as test inside the signed evidence');
  assert.equal(psign.sandbox, true, 'a psk_test_ receipt is not flagged as sandbox');
});

test('parasign: the signed document comes back stamped', { skip }, async (t) => {
  const pdf = throwawayPdf();
  const created = await api('POST', '/v1/envelopes', {
    document: { content_base64: pdf.toString('base64') },
    binding_mode: 'open',
    original_filename: 'canary.pdf',
    signers: [{ name: 'Canary' }],
  });
  assert.equal(created.status, 201, `create rejected: HTTP ${created.status} ${created.text.slice(0, 300)}`);
  const id = created.json.id;
  t.after(async () => { try { await api('POST', `/v1/envelopes/${id}/void`); } catch { /* best effort */ } });

  const doc = await fetch(`${RELAY}/v1/envelopes/${id}/document`, { headers: auth, signal: AbortSignal.timeout(45000) });
  assert.equal(doc.status, 200, `document failed: HTTP ${doc.status}`);
  const bytes = Buffer.from(await doc.arrayBuffer());
  assert.equal(bytes.subarray(0, 5).toString('latin1'), '%PDF-', 'what came back is not a PDF');
  assert.equal(
    doc.headers.get('x-parasign-stamped'), 'true',
    'the relay served the original, not a stamped PDF: the stamp worker is down',
  );
});

test('parasign: an unauthenticated create is refused', { skip: false }, async () => {
  const r = await fetch(`${RELAY}/v1/envelopes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ document: { content_base64: '' }, signers: [{ name: 'X' }] }),
    signal: AbortSignal.timeout(20000),
  });
  assert.ok(r.status === 401 || r.status === 403, `an unauthenticated create was not refused: HTTP ${r.status}`);
});
