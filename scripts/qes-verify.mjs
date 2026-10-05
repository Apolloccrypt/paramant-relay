#!/usr/bin/env node
// Verify the qualified signature inside a PDF produced by the ParaSign QES
// prototype, without trusting anything ParaSign says about it.
//
//   node scripts/qes-verify.mjs signed.pdf [--json]
//
// What it checks:
//   1. the /ByteRange really covers the whole file except the signature blob,
//   2. the SHA-256 over that ByteRange matches the message-digest attribute,
//   3. the signing-certificate-v2 attribute names the certificate that is in
//      the CMS, so the attributes cannot be replayed under another certificate,
//   4. the RSA signature over the signed attributes verifies against that
//      certificate's public key,
//   5. each certificate in the chain is signed by the next one,
//   6. if there is an RFC 3161 timestamp, that it covers this signature value.
//
// What it does NOT check, and what a real validator would add:
//   - trust. No EU trusted list is consulted, so nothing here proves the issuer
//     is a qualified trust service provider or that the certificate is a
//     qualified certificate with a QSCD.
//   - revocation. No CRL, no OCSP, so a revoked certificate still passes.
//   - full PKIX path validation (RFC 5280): no name constraints, no policy
//     mapping, no basicConstraints path length, no key usage enforcement.
//   - long term validation material. There is no DSS dictionary and no
//     document timestamp, so this is not PAdES-B-LT or B-LTA.
// Use Adobe Acrobat or the EU DSS demo validator for the real verdict.

import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pades = require('../relay/lib/qes/pades.js');
const cms = require('../relay/lib/qes/cms.js');
const tsa = require('../relay/lib/qes/tsa.js');

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const file = args.find((a) => !a.startsWith('--'));

if (!file) {
  console.error('usage: node scripts/qes-verify.mjs <signed.pdf> [--json]');
  process.exit(2);
}

const checks = [];
const add = (ok, name, detail) => { checks.push({ ok, name, detail }); return ok; };
const info = {};

const pdf = readFileSync(file);
info.file = file;
info.bytes = pdf.length;

const byteRange = pades.readByteRange(pdf);
if (!byteRange) {
  add(false, 'byterange_present', 'no /ByteRange found; this PDF carries no signature');
} else {
  info.byte_range = byteRange;
  const [a, b, c, d] = byteRange;
  add(a === 0, 'byterange_starts_at_zero', 'first span starts at ' + a);
  add(c + d === pdf.length, 'byterange_covers_to_eof',
    'covered end is ' + (c + d) + ', file is ' + pdf.length + ' bytes');
  add(pdf[b] === 0x3c && pdf[c - 1] === 0x3e, 'byterange_gap_is_the_signature',
    'the excluded span must be exactly the hex /Contents blob including its angle brackets');

  const digest = pades.digestByteRange(pdf, byteRange);
  info.document_digest_sha256 = digest.toString('hex');

  let parsed = null;
  try {
    parsed = cms.parseSignedData(pades.readContents(pdf, byteRange));
    add(true, 'cms_parses', 'CMS SignedData, ' + parsed.certificates.length + ' certificate(s)');
  } catch (e) {
    add(false, 'cms_parses', e.message);
  }

  if (parsed) {
    info.digest_algorithm = parsed.digestAlgorithm;
    info.signature_algorithm = parsed.signatureAlgorithm;
    add(parsed.digestAlgorithm === cms.OID.sha256, 'digest_algorithm_is_sha256', parsed.digestAlgorithm);
    add(parsed.contentType === cms.OID.data, 'content_type_is_id_data', String(parsed.contentType));

    add(!!parsed.messageDigest && parsed.messageDigest.equals(digest), 'message_digest_matches_document',
      parsed.messageDigest ? parsed.messageDigest.toString('hex') : 'attribute missing');

    const signerDer = parsed.certificates[0];
    let signer = null;
    try { signer = new crypto.X509Certificate(signerDer); } catch (e) { add(false, 'signer_certificate_parses', e.message); }

    if (signer) {
      info.signer = {
        subject: signer.subject.replace(/\n/g, ', '),
        issuer: signer.issuer.replace(/\n/g, ', '),
        serial: signer.serialNumber,
        valid_from: signer.validFrom,
        valid_to: signer.validTo,
        sha256_fingerprint: crypto.createHash('sha256').update(signerDer).digest('hex'),
      };
      add(!!parsed.signingCertificateV2Hash &&
        parsed.signingCertificateV2Hash.equals(cms.sha256(signerDer)),
      'signing_certificate_v2_binds_this_certificate',
      parsed.signingCertificateV2Hash ? parsed.signingCertificateV2Hash.toString('hex') : 'attribute missing');

      let sigOk = false;
      try {
        sigOk = crypto.verify('sha256', parsed.signedAttrsDer, signer.publicKey, parsed.signatureValue);
      } catch (e) { sigOk = false; info.signature_error = e.message; }
      add(sigOk, 'signature_verifies_against_signer_key',
        'RSASSA-PKCS1-v1_5 over ' + parsed.signedAttrsDer.length + ' bytes of signed attributes');

      const now = new Date();
      add(now >= new Date(signer.validFrom) && now <= new Date(signer.validTo),
        'signer_certificate_in_validity_window', signer.validFrom + ' .. ' + signer.validTo);
    }

    // Chain links only. This says the certificates form a chain, not that the
    // chain ends somewhere trustworthy.
    info.chain = [];
    for (let i = 0; i < parsed.certificates.length; i++) {
      const c = new crypto.X509Certificate(parsed.certificates[i]);
      const next = parsed.certificates[i + 1] ? new crypto.X509Certificate(parsed.certificates[i + 1]) : null;
      info.chain.push({ subject: c.subject.replace(/\n/g, ', '), issuer: c.issuer.replace(/\n/g, ', ') });
      if (next) {
        // The cryptographic link is what counts here. checkIssued() also wants
        // matching key identifiers, which not every chain carries, so it is
        // reported rather than required.
        let linked = false;
        try { linked = c.verify(next.publicKey); } catch { linked = false; }
        add(linked, 'chain_link_' + i + '_signed_by_' + (i + 1), c.subject.replace(/\n/g, ', '));
      } else if (parsed.certificates.length > 1 || c.issuer === c.subject) {
        info.chain_ends_at = c.subject.replace(/\n/g, ', ');
      }
    }

    if (parsed.timeStampToken) {
      try {
        const t = tsa.parseTimeStampToken(parsed.timeStampToken);
        info.timestamp = { gen_time: t.genTime, hash_algorithm: t.hashAlgorithm };
        add(t.hashedMessage.equals(cms.sha256(parsed.signatureValue)),
          'timestamp_covers_this_signature', 'imprint ' + t.hashedMessage.toString('hex'));
        const inner = cms.parseSignedData(parsed.timeStampToken);
        if (inner.certificates.length) {
          const tsaCert = new crypto.X509Certificate(inner.certificates[0]);
          info.timestamp.authority = tsaCert.subject.replace(/\n/g, ', ');
          let ok = false;
          try { ok = crypto.verify('sha256', inner.signedAttrsDer, tsaCert.publicKey, inner.signatureValue); } catch { ok = false; }
          add(ok, 'timestamp_token_signature_verifies', info.timestamp.authority);
        }
        info.level = 'PAdES-B-T (claimed; the TSA is not checked against any trusted list)';
      } catch (e) {
        add(false, 'timestamp_parses', e.message);
      }
    } else {
      info.level = 'PAdES-B-B (no timestamp present)';
    }
  }
}

const failed = checks.filter((c) => !c.ok);

if (asJson) {
  console.log(JSON.stringify({ ok: failed.length === 0, info, checks }, null, 2));
} else {
  console.log('QES verification of ' + file);
  console.log('');
  for (const c of checks) console.log('  ' + (c.ok ? 'PASS' : 'FAIL') + '  ' + c.name + (c.detail ? '  (' + c.detail + ')' : ''));
  console.log('');
  if (info.signer) {
    console.log('  signer      ' + info.signer.subject);
    console.log('  issuer      ' + info.signer.issuer);
    console.log('  fingerprint ' + info.signer.sha256_fingerprint);
    console.log('  valid       ' + info.signer.valid_from + ' .. ' + info.signer.valid_to);
  }
  if (info.timestamp) console.log('  timestamp   ' + info.timestamp.gen_time + ' by ' + (info.timestamp.authority || 'unknown TSA'));
  if (info.level) console.log('  level       ' + info.level);
  console.log('');
  console.log('  Not checked: trusted list membership, revocation (CRL/OCSP), full RFC 5280');
  console.log('  path validation, and long term validation material. This tool proves the');
  console.log('  bytes hang together, not that the signature is legally qualified.');
  console.log('');
  console.log(failed.length === 0 ? 'RESULT: all ' + checks.length + ' checks passed'
    : 'RESULT: ' + failed.length + ' of ' + checks.length + ' checks failed');
}

process.exit(failed.length === 0 ? 0 : 1);
