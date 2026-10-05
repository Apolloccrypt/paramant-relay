'use strict';
// The ASN.1 and CMS layer, plus the flag that keeps all of it switched off.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const a = require('../lib/qes/asn1');
const cms = require('../lib/qes/cms');
const tsa = require('../lib/qes/tsa');
const qes = require('../lib/qes');
const cleverbase = require('../lib/qes/cleverbase');
const fixture = require('./_qes-fixture');

const signer = fixture.selfSignedCertificate({ commonName: 'Demo Signer' });

test('DER encoding matches the well known encodings', () => {
  assert.strictEqual(a.oid('1.2.840.113549.1.1.1').toString('hex'), '06092a864886f70d010101');
  assert.strictEqual(a.oid('2.16.840.1.101.3.4.2.1').toString('hex'), '0609608648016503040201');
  assert.strictEqual(a.integer(0).toString('hex'), '020100');
  assert.strictEqual(a.integer(255).toString('hex'), '020200ff', 'a leading zero keeps the value positive');
  assert.strictEqual(a.integer(127).toString('hex'), '02017f');
  assert.strictEqual(a.utcTime(new Date('2026-09-03T18:00:00Z')).toString('hex'), '170d3236303930333138303030305a');
});

test('lengths above 127 use the long form', () => {
  const body = Buffer.alloc(300, 7);
  const encoded = a.tlv(0x04, body);
  assert.strictEqual(encoded.subarray(0, 4).toString('hex'), '0482012c');
  assert.deepStrictEqual(a.readTlv(encoded).content, body);
});

test('the decoder round-trips what the encoder writes', () => {
  const der = a.seq(a.oid('1.2.3.4'), a.integer(42), a.octetString(Buffer.from('hi')));
  const children = a.readChildren(a.readTlv(der).content);
  assert.strictEqual(children.length, 3);
  assert.strictEqual(a.decodeOid(children[0].content), '1.2.3.4');
  assert.strictEqual(children[1].content[0], 42);
  assert.strictEqual(children[2].content.toString(), 'hi');
});

test('the decoder refuses indefinite lengths, which are not DER', () => {
  assert.throws(() => a.readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00])), /indefinite/);
});

test('signed attributes carry the three CAdES-BES attributes and are DER-sorted', () => {
  const digest = crypto.createHash('sha256').update('document').digest();
  const attrs = cms.buildSignedAttributes({ messageDigest: digest, signerCertDer: signer.der });
  assert.strictEqual(a.readTlv(attrs).tag, 0x31, 'the hashed form is a SET OF');
  const oids = a.readChildren(a.readTlv(attrs).content)
    .map((n) => a.decodeOid(a.readChildren(n.content)[0].content));
  assert.deepStrictEqual(new Set(oids), new Set([cms.OID.contentType, cms.OID.messageDigest, cms.OID.signingCertificateV2]));
  const encoded = a.readChildren(a.readTlv(attrs).content).map((n) => a.rawOf(a.readTlv(attrs).content, n));
  for (let i = 1; i < encoded.length; i++) {
    assert.ok(Buffer.compare(encoded[i - 1], encoded[i]) <= 0, 'SET OF members must be in DER order');
  }
});

test('the message digest has to be a SHA-256 digest', () => {
  assert.throws(() => cms.buildSignedAttributes({ messageDigest: Buffer.alloc(20), signerCertDer: signer.der }),
    /32-byte SHA-256/);
});

test('the provider only ever sees a 32-byte digest', () => {
  const digest = crypto.createHash('sha256').update('document').digest();
  const attrs = cms.buildSignedAttributes({ messageDigest: digest, signerCertDer: signer.der });
  const toSign = cms.signedAttributesDigest(attrs);
  assert.strictEqual(toSign.length, 32);
  assert.notDeepStrictEqual(toSign, digest, 'what goes out is the attribute hash, not the document hash');
});

test('SignedData round-trips and the signature verifies', () => {
  const digest = crypto.createHash('sha256').update('document').digest();
  const attrs = cms.buildSignedAttributes({ messageDigest: digest, signerCertDer: signer.der });
  const signature = fixture.signHashLikeQtsp(signer.privateKey, cms.signedAttributesDigest(attrs));
  const der = cms.buildSignedData({ certificates: [signer.der], signedAttrsDer: attrs, signatureValue: signature });

  const parsed = cms.parseSignedData(der);
  assert.strictEqual(parsed.certificates.length, 1);
  assert.deepStrictEqual(parsed.certificates[0], signer.der);
  assert.deepStrictEqual(parsed.signedAttrsDer, attrs);
  assert.deepStrictEqual(parsed.messageDigest, digest);
  assert.strictEqual(parsed.contentType, cms.OID.data);
  assert.strictEqual(parsed.digestAlgorithm, cms.OID.sha256);
  assert.strictEqual(parsed.signatureAlgorithm, cms.OID.rsaEncryption);
  assert.strictEqual(parsed.timeStampToken, null);

  const cert = new crypto.X509Certificate(parsed.certificates[0]);
  assert.ok(crypto.verify('sha256', parsed.signedAttrsDer, cert.publicKey, parsed.signatureValue));
});

test('IssuerAndSerialNumber is taken from the certificate byte for byte', () => {
  const { issuerDer, serialDer } = cms.certIssuerAndSerial(signer.der);
  const tbs = a.readChildren(a.readTlv(signer.der).content)[0];
  assert.ok(a.rawOf(a.readTlv(signer.der).content, tbs).includes(issuerDer));
  assert.strictEqual(serialDer[0], 0x02, 'the serial keeps its INTEGER tag');
});

test('an unsigned attribute carries the timestamp token through', () => {
  const digest = crypto.createHash('sha256').update('document').digest();
  const attrs = cms.buildSignedAttributes({ messageDigest: digest, signerCertDer: signer.der });
  const signature = fixture.signHashLikeQtsp(signer.privateKey, cms.signedAttributesDigest(attrs));
  // A stand-in token: parseSignedData only has to find and return it intact.
  const token = a.seq(a.oid('1.2.840.113549.1.7.2'), a.explicit(0, a.seq(a.integer(3))));
  const der = cms.buildSignedData({
    certificates: [signer.der], signedAttrsDer: attrs, signatureValue: signature, timeStampToken: token,
  });
  assert.deepStrictEqual(cms.parseSignedData(der).timeStampToken, token);
});

test('an RFC 3161 request says what it should say', () => {
  const digest = crypto.createHash('sha256').update('signature value').digest();
  const req = tsa.buildRequest(digest, { nonce: false });
  const children = a.readChildren(a.readTlv(req).content);
  assert.strictEqual(children[0].content[0], 1, 'version 1');
  const imprint = a.readChildren(children[1].content);
  assert.strictEqual(a.decodeOid(a.readChildren(imprint[0].content)[0].content), '2.16.840.1.101.3.4.2.1');
  assert.deepStrictEqual(imprint[1].content, digest);
  assert.deepStrictEqual(children[2].content, Buffer.from([0xff]), 'certReq is TRUE');
});

test('a TSA that refuses is reported as a refusal, not as a token', () => {
  const rejected = a.seq(a.seq(a.integer(2)));
  assert.throws(() => tsa.parseResponse(rejected), /PKIStatus 2/);
});

test('the feature is off unless the flag names a known provider', () => {
  assert.strictEqual(qes.provider({}), '');
  assert.strictEqual(qes.provider({ PARASIGN_QES_PROVIDER: '' }), '');
  assert.strictEqual(qes.provider({ PARASIGN_QES_PROVIDER: 'true' }), '');
  assert.strictEqual(qes.provider({ PARASIGN_QES_PROVIDER: 'some-other-qtsp' }), '');
  assert.strictEqual(qes.enabled({}), false);
  assert.strictEqual(qes.provider({ PARASIGN_QES_PROVIDER: 'cleverbase-sandbox' }), 'cleverbase-sandbox');
  assert.strictEqual(qes.enabled({ PARASIGN_QES_PROVIDER: 'cleverbase-sandbox' }), true);
});

test('a disabled flag cannot produce a client, and production needs a registered one', () => {
  assert.throws(() => qes.clientFor({}), /QES is disabled/);
  assert.throws(() => qes.clientFor({ PARASIGN_QES_PROVIDER: 'cleverbase' }), /registered CLEVERBASE_CLIENT_ID/);
  const sandbox = qes.clientFor({ PARASIGN_QES_PROVIDER: 'cleverbase-sandbox' });
  assert.strictEqual(sandbox.baseUrl, cleverbase.SANDBOX_BASE_URL);
  assert.ok(sandbox.isSandbox);
});

test('the receipt field is exactly three keys', () => {
  const field = qes.receiptField({
    providerName: 'cleverbase-sandbox',
    certificateFingerprint: 'ab'.repeat(32),
    signedAt: '2026-09-03T18:00:00.000Z',
  });
  assert.deepStrictEqual(Object.keys(field).sort(), ['certificate_fingerprint', 'provider', 'signed_at']);
});

test('the Cleverbase client refuses anything that is not a SHA-256 digest', async () => {
  const client = new cleverbase.CleverbaseClient({ env: {}, fetchImpl: () => { throw new Error('no call expected'); } });
  await assert.rejects(() => client.signHash({ serviceToken: 't', credentialID: 'c', sad: 's', hashes: [] }),
    /at least one hash/);
  await assert.rejects(() => client.signHash({ serviceToken: 't', credentialID: 'c', sad: 's', hashes: [Buffer.alloc(20)] }),
    /32-byte SHA-256/);
});

test('signHash sends only the digest, base64, with the fixed algorithm OIDs', async () => {
  const digest = crypto.createHash('sha256').update('attributes').digest();
  let seen = null;
  const client = new cleverbase.CleverbaseClient({
    env: {},
    fetchImpl: async (url, init) => {
      seen = { url, body: JSON.parse(init.body), headers: init.headers };
      return { ok: true, status: 200, text: async () => JSON.stringify({ signatures: ['AAEC'] }) };
    },
  });
  const [signature] = await client.signHash({ serviceToken: 'svc', credentialID: 'GX0112348', sad: 'SAD', hashes: [digest] });
  assert.strictEqual(seen.url, 'https://connect.acc.cleverbase.com/csc/v1/signatures/signHash');
  assert.strictEqual(seen.headers.Authorization, 'Bearer svc');
  assert.deepStrictEqual(seen.body, {
    credentialID: 'GX0112348',
    SAD: 'SAD',
    hash: [digest.toString('base64')],
    hashAlgo: cleverbase.HASH_ALGO_OID,
    signAlgo: cleverbase.SIGN_ALGO_OID,
  });
  assert.deepStrictEqual(signature, Buffer.from('AAEC', 'base64'));
});

test('the credential authorisation URL binds the exact hashes', () => {
  const client = new cleverbase.CleverbaseClient({
    env: {}, clientId: 'client-1', redirectUri: 'https://example.com/return',
  });
  const digest = crypto.createHash('sha256').update('attributes').digest();
  const url = new URL(client.authorizeUrl({ scope: 'credential', state: 's', credentialID: 'GX0112348', hashes: [digest] }));
  assert.strictEqual(url.searchParams.get('scope'), 'credential');
  assert.strictEqual(url.searchParams.get('numSignatures'), '1');
  assert.strictEqual(url.searchParams.get('hash'),
    digest.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  assert.throws(() => client.authorizeUrl({ scope: 'credential', state: 's', credentialID: 'c', hashes: [] }), /needs hashes/);
  assert.throws(() => client.authorizeUrl({ scope: 'anything', state: 's' }), /service or credential/);
});

test('no more than fifty signatures per authorisation, as the API states', () => {
  const client = new cleverbase.CleverbaseClient({ env: {}, clientId: 'c', redirectUri: 'https://example.com/r' });
  const hashes = Array.from({ length: 51 }, (_, i) => crypto.createHash('sha256').update(String(i)).digest());
  assert.throws(() => client.authorizeUrl({ scope: 'credential', state: 's', credentialID: 'c', hashes }), /at most 50/);
});

test('the account token is an HS256 JWT over the hashed client secret', () => {
  const client = new cleverbase.CleverbaseClient({ env: {}, clientId: 'client-1', clientSecret: 'secret-1' });
  const [header, payload, mac] = client.accountToken('acct_demo').split('.');
  assert.deepStrictEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { typ: 'JWT', alg: 'HS256' });
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  assert.strictEqual(claims.sub, 'acct_demo');
  assert.strictEqual(claims.azp, 'client-1');
  const key = crypto.createHash('sha256').update('secret-1').digest();
  const expected = crypto.createHmac('sha256', key).update(header + '.' + payload).digest('base64url');
  assert.strictEqual(mac, expected);
});
