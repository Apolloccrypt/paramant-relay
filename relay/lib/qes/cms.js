'use strict';
// CMS SignedData (RFC 5652) for a detached CAdES-BES signature, plus the two
// helpers a remote hash-signing QTSP needs: the DER of the signed attributes
// and the SHA-256 over them. The QTSP only ever sees that 32-byte digest.
//
// Scope is deliberately narrow and matches what Cleverbase's Signing API
// accepts: SHA-256 digests, RSA PKCS#1 v1.5 signatures, one signer.

const crypto = require('node:crypto');
const a = require('./asn1');

const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
};

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// ── certificate field extraction ────────────────────────────────────────────

// Pull issuer (raw Name DER) and serialNumber (raw INTEGER content) straight
// out of the TBSCertificate. node:crypto exposes these only as display strings,
// and IssuerAndSerialNumber needs the original encoding byte for byte.
function certIssuerAndSerial(certDer) {
  const cert = a.readTlv(certDer);
  const tbs = a.readChildren(cert.content)[0];
  const fields = a.readChildren(tbs.content);
  let i = 0;
  if (fields[i] && fields[i].tag === 0xa0) i++; // [0] EXPLICIT Version
  const serial = fields[i++];
  if (!serial || serial.tag !== 0x02) throw new Error('certificate: no serialNumber');
  i++; // signature AlgorithmIdentifier
  const issuer = fields[i];
  if (!issuer || issuer.tag !== 0x30) throw new Error('certificate: no issuer Name');
  return {
    issuerDer: Buffer.from(a.rawOf(tbs.content, issuer)),
    serialDer: Buffer.from(a.rawOf(tbs.content, serial)),
  };
}

function issuerAndSerialNumber(certDer) {
  const { issuerDer, serialDer } = certIssuerAndSerial(certDer);
  return a.seq(issuerDer, serialDer);
}

// ── signed attributes ───────────────────────────────────────────────────────

function attribute(typeOid, ...values) {
  return a.seq(a.oid(typeOid), a.set(values.flat()));
}

// ESSCertIDv2 with the default SHA-256 hash algorithm omitted, as RFC 5035 allows.
function signingCertificateV2(certDer) {
  const essCertId = a.seq(a.octetString(sha256(certDer)));
  return a.seq(a.seq(essCertId));
}

// The SET OF Attribute, DER-sorted. Returned with tag 0x31 (SET OF): this is
// the encoding the signature is computed over, per RFC 5652 5.4. Inside
// SignerInfo the same content bytes are re-tagged [0] IMPLICIT.
function buildSignedAttributes({ messageDigest, signerCertDer, signingTime = null }) {
  if (!Buffer.isBuffer(messageDigest) || messageDigest.length !== 32) {
    throw new Error('messageDigest must be a 32-byte SHA-256 digest');
  }
  const attrs = [
    attribute(OID.contentType, a.oid(OID.data)),
    attribute(OID.messageDigest, a.octetString(messageDigest)),
    attribute(OID.signingCertificateV2, signingCertificateV2(signerCertDer)),
  ];
  // ETSI EN 319 142-1 takes the claimed signing time from the /M entry of the
  // signature dictionary, so the CAdES signing-time attribute stays off by
  // default. Kept as an option for verifiers that still want it.
  if (signingTime) attrs.push(attribute(OID.signingTime, a.utcTime(signingTime)));
  attrs.sort(Buffer.compare);
  return a.set(attrs);
}

// What the QTSP signs. Never the document, never the ByteRange digest: the
// SHA-256 of the signed attributes, which in turn commit to both.
function signedAttributesDigest(signedAttrsDer) {
  return sha256(signedAttrsDer);
}

// ── SignedData ──────────────────────────────────────────────────────────────

// certificates: [signerCertDer, ...chainDer]; signerCertDer must be first.
// signatureValue: the raw RSA PKCS#1 v1.5 signature returned by the QTSP.
// timeStampToken: an RFC 3161 TimeStampToken (a full ContentInfo DER), or null.
function buildSignedData({ certificates, signedAttrsDer, signatureValue, timeStampToken = null }) {
  if (!Array.isArray(certificates) || !certificates.length) throw new Error('certificates required');
  const signerCertDer = certificates[0];

  // Re-tag the SET OF as [0] IMPLICIT without touching the content.
  const attrsNode = a.readTlv(signedAttrsDer);
  const signedAttrsImplicit = a.implicitSet(0, Buffer.from(attrsNode.content));

  const parts = [
    a.integer(1),                                    // version (issuerAndSerialNumber)
    issuerAndSerialNumber(signerCertDer),            // sid
    a.algorithmIdentifier(OID.sha256),               // digestAlgorithm
    signedAttrsImplicit,
    a.algorithmIdentifier(OID.rsaEncryption),        // signatureAlgorithm
    a.octetString(signatureValue),
  ];
  if (timeStampToken) {
    parts.push(a.implicitSet(1, attribute(OID.signatureTimeStampToken, timeStampToken)));
  }
  const signerInfo = a.seq(parts);

  const signedData = a.seq(
    a.integer(1),                                    // version
    a.set(a.algorithmIdentifier(OID.sha256)),        // digestAlgorithms
    a.seq(a.oid(OID.data)),                          // encapContentInfo, detached
    a.implicitSet(0, certificates.map((c) => Buffer.from(c))),
    a.set(signerInfo)
  );

  return a.seq(a.oid(OID.signedData), a.explicit(0, signedData));
}

// ── reading a CMS back ──────────────────────────────────────────────────────

// Everything scripts/qes-verify.mjs needs to check a signature without a
// second ASN.1 library. Returns raw DER for the pieces that must be verified
// byte for byte.
function parseSignedData(cmsDer) {
  const contentInfo = a.readTlv(cmsDer);
  const ciChildren = a.readChildren(contentInfo.content);
  if (a.decodeOid(ciChildren[0].content) !== OID.signedData) throw new Error('not a CMS SignedData');
  const sd = a.readChildren(ciChildren[1].content)[0];
  const sdChildren = a.readChildren(sd.content);

  const certificates = [];
  let signerInfosNode = null;
  for (const node of sdChildren) {
    if (node.tag === 0xa0) {
      for (const c of a.readChildren(node.content)) certificates.push(Buffer.from(a.rawOf(node.content, c)));
    } else if (node.tag === 0x31 && node !== sdChildren[1]) {
      signerInfosNode = node;
    }
  }
  if (!signerInfosNode) throw new Error('CMS: no signerInfos');
  const si = a.readChildren(signerInfosNode.content)[0];
  if (!si) throw new Error('CMS: empty signerInfos');
  const siChildren = a.readChildren(si.content);

  let signedAttrsDer = null;
  let signatureValue = null;
  let timeStampToken = null;
  let digestAlgorithm = null;
  let signatureAlgorithm = null;
  const sid = siChildren[1];

  for (let i = 2; i < siChildren.length; i++) {
    const node = siChildren[i];
    if (node.tag === 0x30 && !digestAlgorithm) {
      digestAlgorithm = a.decodeOid(a.readChildren(node.content)[0].content);
    } else if (node.tag === 0xa0) {
      // [0] IMPLICIT SET OF Attribute; hash it as a real SET OF (tag 0x31).
      signedAttrsDer = a.set(Buffer.from(node.content));
    } else if (node.tag === 0x30 && digestAlgorithm && !signatureAlgorithm) {
      signatureAlgorithm = a.decodeOid(a.readChildren(node.content)[0].content);
    } else if (node.tag === 0x04) {
      signatureValue = Buffer.from(node.content);
    } else if (node.tag === 0xa1) {
      for (const attr of a.readChildren(node.content)) {
        const kids = a.readChildren(attr.content);
        if (a.decodeOid(kids[0].content) === OID.signatureTimeStampToken) {
          const val = a.readChildren(kids[1].content)[0];
          timeStampToken = Buffer.from(a.rawOf(kids[1].content, val));
        }
      }
    }
  }

  const attrs = {};
  if (signedAttrsDer) {
    for (const attr of a.readChildren(a.readTlv(signedAttrsDer).content)) {
      const kids = a.readChildren(attr.content);
      attrs[a.decodeOid(kids[0].content)] = a.readChildren(kids[1].content)[0];
    }
  }

  return {
    certificates,
    signedAttrsDer,
    signatureValue,
    timeStampToken,
    digestAlgorithm,
    signatureAlgorithm,
    sidDer: sid ? Buffer.from(a.rawOf(si.content, sid)) : null,
    messageDigest: attrs[OID.messageDigest] ? Buffer.from(attrs[OID.messageDigest].content) : null,
    contentType: attrs[OID.contentType] ? a.decodeOid(attrs[OID.contentType].content) : null,
    signingCertificateV2Hash: attrs[OID.signingCertificateV2]
      ? Buffer.from(a.readChildren(a.readChildren(a.readChildren(attrs[OID.signingCertificateV2].content)[0].content)[0].content)[0].content)
      : null,
  };
}

module.exports = {
  OID, sha256,
  certIssuerAndSerial, issuerAndSerialNumber,
  buildSignedAttributes, signedAttributesDigest, buildSignedData, parseSignedData,
};
