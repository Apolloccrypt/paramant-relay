const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");

// Lives under crypto/ so the CI relay-crypto job (node --test crypto/*.test.js,
// which builds @paramant/core) exercises it with the real ML-DSA-65 binding.
const { bootstrap } = require("./bootstrap");
const { getSig } = require("./registry");
const parasign = require("../parasign");

bootstrap("core"); // registers ML-KEM-768 + ML-DSA-65
const sig = getSig(0x0002); // ML-DSA-65

// Helpers mirroring how the relay route wires parasign.
function relayDeps(relaySk, relayPk) {
  const relayPkHash = crypto.createHash("sha3-256").update(Buffer.from(relayPk)).digest("hex");
  return { relaySign: (msg) => sig.sign(msg, relaySk), relayPkHash };
}
function verifyDeps(relayPk) {
  return {
    sigVerify: (s, m, p) => { try { return sig.verify(s, m, p); } catch { return false; } },
    // v3 doc-sign envelopes have no notary signature, so relayPk is optional.
    relayPub: relayPk ? Buffer.from(relayPk) : Buffer.alloc(0),
  };
}

// Produce a notarised envelope for a fresh signer + relay identity.
function makeEnvelope(documentBytes, opts = {}) {
  const signer = sig.generateKeyPair();
  const relay = sig.generateKeyPair();
  const docHashHex = crypto.createHash("sha3-256").update(documentBytes).digest("hex");
  // v2 envelopes: the signer signs the domain-separated message (#3/#4), which
  // is what buildEnvelope (default version '2') and verifyEnvelope now expect.
  const signature = sig.sign(parasign.singleSignerMessage(docHashHex), signer.secretKey);
  const envelope = parasign.buildEnvelope(
    {
      documentHashHex: docHashHex,
      signatureB64: Buffer.from(signature).toString("base64"),
      signerPubB64: Buffer.from(signer.publicKey).toString("base64"),
      signerLabel: opts.label || "Alice",
      ttlDays: opts.ttlDays != null ? opts.ttlDays : 365,
      ctLogIndex: 42,
    },
    relayDeps(relay.secretKey, relay.publicKey),
  );
  return { envelope, docHashHex, relayPk: relay.publicKey, relaySk: relay.secretKey };
}

test("valid envelope verifies", () => {
  const doc = Buffer.from("the quick brown fox");
  const { envelope, docHashHex, relayPk } = makeEnvelope(doc);
  const r = parasign.verifyEnvelope({ documentHashHex: docHashHex, envelope }, verifyDeps(relayPk));
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
  assert.strictEqual(envelope.algorithm, "ML-DSA-65");
  assert.ok(envelope.envelope_signature);
});

test("tampered document (hash mismatch) fails", () => {
  const { envelope, relayPk } = makeEnvelope(Buffer.from("original"));
  const otherHash = crypto.createHash("sha3-256").update(Buffer.from("different")).digest("hex");
  const r = parasign.verifyEnvelope({ documentHashHex: otherHash, envelope }, verifyDeps(relayPk));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("document_hash mismatch")), JSON.stringify(r.errors));
});

test("tampered envelope (signer label changed after notarisation) fails", () => {
  const { envelope, docHashHex, relayPk } = makeEnvelope(Buffer.from("doc"));
  envelope.signer.label = "Mallory"; // mutate a signed field
  const r = parasign.verifyEnvelope({ documentHashHex: docHashHex, envelope }, verifyDeps(relayPk));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("notary")), JSON.stringify(r.errors));
});

test("tampered signer signature fails", () => {
  const { envelope, docHashHex, relayPk } = makeEnvelope(Buffer.from("doc"));
  const sigBuf = Buffer.from(envelope.signature, "base64");
  sigBuf[0] ^= 0xff; // flip a byte
  envelope.signature = sigBuf.toString("base64");
  const r = parasign.verifyEnvelope({ documentHashHex: docHashHex, envelope }, verifyDeps(relayPk));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("signer signature invalid")), JSON.stringify(r.errors));
});

test("wrong relay key cannot verify the envelope signature", () => {
  const { envelope, docHashHex } = makeEnvelope(Buffer.from("doc"));
  const stranger = sig.generateKeyPair();
  const r = parasign.verifyEnvelope({ documentHashHex: docHashHex, envelope }, verifyDeps(stranger.publicKey));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("notary")), JSON.stringify(r.errors));
});

test("expired envelope fails", () => {
  // buildEnvelope clamps invalid ttl to 365d, so forge an expired-but-validly-
  // notarised envelope: set expires_at to the past and re-sign with the relay key.
  const { envelope, docHashHex, relayPk, relaySk } = makeEnvelope(Buffer.from("doc"));
  envelope.expires_at = new Date(Date.now() - 86400000).toISOString();
  delete envelope.envelope_signature;
  const canonical = parasign.canonicalJSON(envelope);
  envelope.envelope_signature = Buffer.from(sig.sign(Buffer.from(canonical), relaySk)).toString("base64");
  const r = parasign.verifyEnvelope({ documentHashHex: docHashHex, envelope }, verifyDeps(relayPk));
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("expired")), JSON.stringify(r.errors));
});

// ── v3 doc-sign envelopes (parasign-doc-3) — the .psign the /sign page emits ──
const { signMessageBytes } = require("../envelope");

// Build a v3 .psign the way the browser client does: the signer signs the
// doc-sign message (recipe 3) over the STAMPED hash for pdf/image documents.
function makeV3Envelope(opts = {}) {
  const signer = sig.generateKeyPair();
  const envelopeId = opts.envelopeId || "env_" + crypto.randomBytes(6).toString("hex");
  const partyIndex = opts.partyIndex != null ? opts.partyIndex : 0;
  const stampedHash = crypto.createHash("sha3-256").update(Buffer.from(opts.doc || "stamped-pdf")).digest("hex");
  const emailHash = opts.emailHash != null ? opts.emailHash
    : crypto.createHash("sha3-256").update(Buffer.from("alice@example.com")).digest("hex");
  const msg = signMessageBytes(envelopeId, stampedHash, partyIndex, emailHash, 3);
  const signature = sig.sign(msg, signer.secretKey);
  const envelope = {
    version: "parasign-doc-3", recipe_version: 3, sign_domain: "paramant/parasign/doc/v1",
    algorithm: "ML-DSA-65", hash_algorithm: "SHA3-256",
    original_hash: crypto.createHash("sha3-256").update(Buffer.from("orig")).digest("hex"),
    stamped_hash: stampedHash,
    signer_public_key: Buffer.from(signer.publicKey).toString("base64"),
    signature: Buffer.from(signature).toString("base64"),
    party_email_hash: emailHash,
    multiparty: { envelope_id: envelopeId, party_index: partyIndex },
  };
  return { envelope, stampedHash, signerPk: signer.publicKey };
}

test("v3: valid doc-sign envelope verifies offline (was always INVALID before D3)", () => {
  const { envelope, stampedHash } = makeV3Envelope();
  const r = parasign.verifyEnvelope({ documentHashHex: stampedHash, envelope }, verifyDeps());
  assert.strictEqual(r.valid, true, JSON.stringify(r.errors));
});

test("v3: tampered signature fails", () => {
  const { envelope } = makeV3Envelope();
  const b = Buffer.from(envelope.signature, "base64"); b[0] ^= 0xff;
  envelope.signature = b.toString("base64");
  const r = parasign.verifyEnvelope({ envelope }, verifyDeps());
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("signer signature invalid")), JSON.stringify(r.errors));
});

test("v3: a different email_hash breaks verification (email is bound into the message)", () => {
  const { envelope } = makeV3Envelope();
  envelope.party_email_hash = crypto.createHash("sha3-256").update(Buffer.from("mallory@example.com")).digest("hex");
  const r = parasign.verifyEnvelope({ envelope }, verifyDeps());
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("signer signature invalid")), JSON.stringify(r.errors));
});

test("v3: missing party_email_hash is reported (cannot verify offline)", () => {
  const { envelope } = makeV3Envelope();
  delete envelope.party_email_hash;
  const r = parasign.verifyEnvelope({ envelope }, verifyDeps());
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("party_email_hash")), JSON.stringify(r.errors));
});

test("v3: document-hash binding rejects a mismatched stamped hash", () => {
  const { envelope } = makeV3Envelope();
  const wrong = crypto.createHash("sha3-256").update(Buffer.from("nope")).digest("hex");
  const r = parasign.verifyEnvelope({ documentHashHex: wrong, envelope }, verifyDeps());
  assert.strictEqual(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes("document_hash mismatch")), JSON.stringify(r.errors));
});
