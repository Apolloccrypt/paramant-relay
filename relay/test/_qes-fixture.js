'use strict';
// Test fixtures for the QES layer: a throwaway RSA key with a matching
// self-signed X.509 certificate, and a stand-in for the qualified trust service
// provider that signs the way the real one does.
//
// The certificate is built here rather than committed, because a committed
// certificate needs a committed private key next to it and a repository is the
// wrong place for one. Building it also exercises relay/lib/qes/asn1.js against
// a structure that openssl and node:crypto both have to accept.

const crypto = require('node:crypto');
const a = require('../lib/qes/asn1');

const SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
const DIGEST_INFO_SHA256 = Buffer.from('3031300d060960864801650304020105000420', 'hex');

// RelativeDistinguishedName with a single attribute, PrintableString valued.
function rdn(typeOid, value) {
  return a.set(a.seq(a.oid(typeOid), a.tlv(0x13, Buffer.from(value, 'ascii'))));
}

function name({ country = 'NL', organisation = 'Acme', commonName = 'Demo Signer' }) {
  return a.seq(rdn('2.5.4.6', country), rdn('2.5.4.10', organisation), rdn('2.5.4.3', commonName));
}

// A self-signed certificate. Not a qualified certificate and not pretending to
// be one: no QcStatements, no policy OIDs, no trusted list anywhere near it.
function selfSignedCertificate(options = {}) {
  const { privateKey, publicKey } = options.keyPair || crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const subject = name(options);
  const now = Date.now();
  const notBefore = new Date(now - 3600 * 1000);
  const notAfter = new Date(now + 30 * 24 * 3600 * 1000);

  const spki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

  const extensions = a.explicit(3, a.seq(
    // basicConstraints, critical, CA:FALSE
    a.seq(a.oid('2.5.29.19'), Buffer.from([0x01, 0x01, 0xff]), a.octetString(a.seq())),
    // keyUsage, critical, nonRepudiation only (bit 1)
    a.seq(a.oid('2.5.29.15'), Buffer.from([0x01, 0x01, 0xff]),
      a.octetString(a.bitString(Buffer.from([0x40]), 6)))
  ));

  const tbs = a.seq(
    a.explicit(0, a.integer(2)),                       // v3
    a.integer(crypto.randomBytes(8)),
    a.algorithmIdentifier(SHA256_WITH_RSA),
    subject,                                            // issuer, self-signed
    a.seq(a.utcTime(notBefore), a.utcTime(notAfter)),
    subject,
    spki,
    extensions
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const der = a.seq(tbs, a.algorithmIdentifier(SHA256_WITH_RSA), a.bitString(signature));
  return { der, privateKey, publicKey, notBefore, notAfter };
}

// What a CSC signHash call does: RSASSA-PKCS1-v1_5 over the digest the caller
// hands in. Nothing about the document reaches this function, by construction.
function signHashLikeQtsp(privateKey, digest) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) throw new Error('expected a SHA-256 digest');
  return crypto.privateEncrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.concat([DIGEST_INFO_SHA256, digest])
  );
}

// A one-page PDF to sign, built with the same pdf-lib the browser uses.
async function samplePdf(text = 'Demo contract for Acme', { useObjectStreams = true } = {}) {
  const PDFLib = require('../lib/qes/pades').loadPdfLib();
  const doc = await PDFLib.PDFDocument.create();
  const font = await doc.embedFont(PDFLib.StandardFonts.Helvetica);
  doc.addPage([595.28, 841.89]).drawText(text, { x: 60, y: 760, size: 14, font });
  return Buffer.from(await doc.save({ useObjectStreams }));
}

module.exports = { selfSignedCertificate, signHashLikeQtsp, samplePdf, name, SHA256_WITH_RSA };
