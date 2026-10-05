'use strict';
// The QES layer, in one place, behind one flag.
//
// PARASIGN_QES_PROVIDER is empty by default. Empty means this module does
// nothing at all: no route, no UI, no outbound call, and the .psign receipt
// comes out byte for byte as it does today. The only supported value today is
// "cleverbase-sandbox"; "cleverbase" is reserved for a production client and
// refuses to start without one, because production onboarding at Cleverbase is
// a manual client registration and there is no contract yet.
//
// The three layers stay separate, exactly as designed:
//   1. the PAdES signature inside the PDF, made by a QTSP over a hash,
//   2. the ParaSign .psign receipt with its ML-DSA-65 signatures, unchanged,
//   3. the public log, untouched.
// A verifier can check either one without the other and without contacting us.

const crypto = require('node:crypto');
const pades = require('./pades');
const cms = require('./cms');
const tsa = require('./tsa');
const { CleverbaseClient, SANDBOX_BASE_URL, PRODUCTION_BASE_URL } = require('./cleverbase');

const PROVIDERS = ['cleverbase-sandbox', 'cleverbase'];

function provider(env = process.env) {
  const value = String(env.PARASIGN_QES_PROVIDER || '').trim();
  return PROVIDERS.includes(value) ? value : '';
}

function enabled(env = process.env) { return provider(env) !== ''; }

// A client wired for whichever provider the flag selects. Throws when the flag
// is off, so a caller can never fall through to a live call by accident.
function clientFor(env = process.env, overrides = {}) {
  const name = provider(env);
  if (!name) throw new Error('QES is disabled: PARASIGN_QES_PROVIDER is not set');
  const baseUrl = env.CLEVERBASE_BASE_URL ||
    (name === 'cleverbase-sandbox' ? SANDBOX_BASE_URL : PRODUCTION_BASE_URL);
  if (name === 'cleverbase' && !env.CLEVERBASE_CLIENT_ID) {
    throw new Error('PARASIGN_QES_PROVIDER=cleverbase needs a registered CLEVERBASE_CLIENT_ID');
  }
  return new CleverbaseClient({ env, baseUrl, ...overrides });
}

const fingerprint = (certDer) => crypto.createHash('sha256').update(certDer).digest('hex');

// ── phase 1: everything up to the hash ──────────────────────────────────────

// Reserves the signature in the PDF and works out the one digest the QTSP is
// allowed to see. Returns the digest twice over: `documentDigest` is the
// ByteRange hash, `hashToSign` is the SHA-256 of the signed attributes, and it
// is only the second one that ever goes out.
async function prepareSignature({ pdf, certificateChain, signerName = null, reason = null,
  location = null, signingTime = new Date(), contentsBytes }) {
  if (!Array.isArray(certificateChain) || !certificateChain.length) {
    throw new Error('a signer certificate is required before the document can be prepared');
  }
  const prepared = await pades.prepare(pdf, {
    signerName, reason, location, signingTime, contentsBytes,
    fieldName: 'ParaSign QES',
  });
  const signedAttrsDer = cms.buildSignedAttributes({
    messageDigest: prepared.digest,
    signerCertDer: certificateChain[0],
  });
  return {
    prepared,
    certificateChain,
    signedAttrsDer,
    documentDigest: prepared.digest,
    hashToSign: cms.signedAttributesDigest(signedAttrsDer),
    certificateFingerprint: fingerprint(certificateChain[0]),
  };
}

// ── phase 2: the QTSP has signed ────────────────────────────────────────────

// Assembles the CMS, optionally timestamps it, writes it into the reserved
// space and reports what was actually achieved. `tsaUrl` empty means B-B.
async function finishSignature(session, signatureValue, { tsaUrl = tsa.DEFAULT_TSA_URL,
  providerName = 'cleverbase-sandbox', fetchImpl } = {}) {
  if (!Buffer.isBuffer(signatureValue) || !signatureValue.length) {
    throw new Error('the provider returned no signature value');
  }
  let timeStampToken = null;
  let timestamp = null;
  if (tsaUrl) {
    timeStampToken = await tsa.stamp(cms.sha256(signatureValue), { url: tsaUrl, ...(fetchImpl ? { fetchImpl } : {}) });
    timestamp = tsa.parseTimeStampToken(timeStampToken);
  }
  const der = cms.buildSignedData({
    certificates: session.certificateChain,
    signedAttrsDer: session.signedAttrsDer,
    signatureValue,
    timeStampToken,
  });
  const signed = pades.embed(session.prepared, der);
  return {
    pdf: signed,
    cms: der,
    level: timeStampToken ? 'PAdES-B-T' : 'PAdES-B-B',
    tsaUrl: timeStampToken ? tsaUrl : null,
    timestampedAt: timestamp ? timestamp.genTime : null,
    qes: receiptField({
      providerName,
      certificateFingerprint: session.certificateFingerprint,
      signedAt: timestamp ? timestamp.genTime : session.prepared.signingTime,
    }),
  };
}

// The single extra top-level field the .psign receipt gains. Kept to three
// keys on purpose: the receipt stays a ParaSign artefact, and the QES is
// validated separately by Adobe or DSS against the PDF itself.
function receiptField({ providerName, certificateFingerprint, signedAt }) {
  return {
    provider: providerName,
    certificate_fingerprint: certificateFingerprint,
    signed_at: signedAt,
  };
}

// ── the whole run, for a caller that already holds the tokens ───────────────

// `authorise` is handed the hash and must return { serviceToken, credentialID,
// sad }. That callback is where the signer's browser trip to the Cleverbase app
// happens; there is no way around it, because the API only speaks oauth2code.
async function signPdf({ pdf, client, credentialID, serviceToken, authorise,
  signerName, reason, location, tsaUrl = process.env.QES_TSA_URL !== undefined
    ? process.env.QES_TSA_URL : tsa.DEFAULT_TSA_URL, providerName = 'cleverbase-sandbox' }) {
  const info = await client.credentialInfo(serviceToken, credentialID);
  if (!info.chain.length) throw new Error('the credential carries no certificate');
  const session = await prepareSignature({ pdf, certificateChain: info.chain, signerName, reason, location });
  const sad = await authorise({ hashToSign: session.hashToSign, credentialID });
  const [signatureValue] = await client.signHash({
    serviceToken, credentialID, sad, hashes: [session.hashToSign],
  });
  const out = await finishSignature(session, signatureValue, { tsaUrl, providerName });
  return { ...out, credentialInfo: { status: info.key && info.key.status, keyLength: info.key && info.key.len } };
}

module.exports = {
  PROVIDERS, provider, enabled, clientFor, fingerprint,
  prepareSignature, finishSignature, receiptField, signPdf,
  pades, cms, tsa,
};
