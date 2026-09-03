'use strict';
// RFC 3161 timestamping, enough to lift a PAdES-B-B signature to B-T.
//
// The default TSA is DigiCert's public timestamp service. It is free, needs no
// account and answers over plain HTTP, which is what RFC 3161 specifies. It is
// NOT an EU-qualified timestamp authority: it sits on the CA/Browser-forum
// code-signing side, not on any member state's eIDAS trusted list. A production
// deployment must point QES_TSA_URL at a qualified TSA (a TSA/QTST service on a
// trusted list) before the timestamp counts for anything under eIDAS. Set
// QES_TSA_URL to an empty string to skip timestamping and stay at PAdES-B-B.

const crypto = require('node:crypto');
const a = require('./asn1');

const DEFAULT_TSA_URL = 'http://timestamp.digicert.com';

const OID = {
  sha256: '2.16.840.1.101.3.4.2.1',
  ctTSTInfo: '1.2.840.113549.1.9.16.1.4',
};

function buildRequest(digest, { certReq = true, nonce = true } = {}) {
  if (!Buffer.isBuffer(digest) || digest.length !== 32) throw new Error('TSA: need a 32-byte SHA-256 digest');
  const parts = [
    a.integer(1),
    a.seq(a.algorithmIdentifier(OID.sha256), a.octetString(digest)),
  ];
  if (nonce) parts.push(a.integer(crypto.randomBytes(8)));
  if (certReq) parts.push(Buffer.from([0x01, 0x01, 0xff]));
  return a.seq(parts);
}

// Returns the TimeStampToken (a full CMS ContentInfo, DER) or throws with the
// PKIStatus the TSA reported.
function parseResponse(responseDer) {
  const resp = a.readTlv(responseDer);
  const children = a.readChildren(resp.content);
  const statusInfo = a.readChildren(children[0].content);
  const status = statusInfo[0].content.length ? statusInfo[0].content[statusInfo[0].content.length - 1] : 0;
  if (status !== 0 && status !== 1) throw new Error('TSA rejected the request, PKIStatus ' + status);
  if (!children[1]) throw new Error('TSA returned no timestamp token');
  return Buffer.from(a.rawOf(resp.content, children[1]));
}

// The genTime and message imprint out of a TimeStampToken, so a verifier can
// say when the signature existed and confirm the token covers this signature.
function parseTimeStampToken(tokenDer) {
  const ci = a.readChildren(a.readTlv(tokenDer).content);
  const sd = a.readChildren(ci[1].content)[0];
  const sdChildren = a.readChildren(sd.content);
  const encap = sdChildren[2];
  const encapChildren = a.readChildren(encap.content);
  if (a.decodeOid(encapChildren[0].content) !== OID.ctTSTInfo) throw new Error('not a TimeStampToken');
  const eContent = a.readChildren(encapChildren[1].content)[0];
  const info = a.readChildren(a.readTlv(eContent.content).content);
  // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
  const imprint = a.readChildren(info[2].content);
  const genTimeRaw = info[4].content.toString('ascii');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(genTimeRaw);
  const genTime = m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString() : null;

  const certificates = [];
  for (const node of sdChildren) {
    if (node.tag === 0xa0) {
      for (const c of a.readChildren(node.content)) certificates.push(Buffer.from(a.rawOf(node.content, c)));
    }
  }
  return {
    genTime,
    hashAlgorithm: a.decodeOid(a.readChildren(imprint[0].content)[0].content),
    hashedMessage: Buffer.from(imprint[1].content),
    certificates,
  };
}

// Ask a TSA to timestamp `digest`. `url` empty or null means "do not timestamp".
async function stamp(digest, { url = DEFAULT_TSA_URL, timeoutMs = 15000, fetchImpl = fetch } = {}) {
  if (!url) return null;
  const body = buildRequest(digest);
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query', 'Content-Length': String(body.length) },
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error('TSA HTTP ' + res.status);
  return parseResponse(Buffer.from(await res.arrayBuffer()));
}

module.exports = { DEFAULT_TSA_URL, buildRequest, parseResponse, parseTimeStampToken, stamp };
