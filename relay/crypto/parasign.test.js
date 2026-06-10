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
    relayPub: Buffer.from(relayPk),
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
