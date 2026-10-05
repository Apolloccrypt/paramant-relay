'use strict';
// The PAdES writer, at byte level. Three things have to hold or the whole idea
// falls over: the update is genuinely incremental, the ByteRange describes what
// it claims to describe, and the result is still a readable PDF.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const pades = require('../lib/qes/pades');
const cms = require('../lib/qes/cms');
const fixture = require('./_qes-fixture');

// One certificate and one key for the whole file: generating RSA keys is the
// slow part and nothing here depends on them being distinct.
const signer = fixture.selfSignedCertificate({ commonName: 'Demo Signer' });

async function signed(pdf, opts = {}) {
  const prepared = await pades.prepare(pdf, opts);
  const signedAttrsDer = cms.buildSignedAttributes({
    messageDigest: prepared.digest,
    signerCertDer: signer.der,
  });
  const signature = fixture.signHashLikeQtsp(signer.privateKey, cms.signedAttributesDigest(signedAttrsDer));
  const der = cms.buildSignedData({ certificates: [signer.der], signedAttrsDer, signatureValue: signature });
  return { prepared, signedAttrsDer, der, pdf: pades.embed(prepared, der) };
}

for (const useObjectStreams of [true, false]) {
  const label = useObjectStreams ? 'cross-reference stream' : 'classic cross-reference table';

  test('incremental update leaves the original bytes untouched, ' + label, async () => {
    const original = await fixture.samplePdf('Demo contract for Acme', { useObjectStreams });
    const out = await signed(original);
    assert.ok(out.pdf.length > original.length, 'the update has to add bytes');
    assert.deepStrictEqual(
      out.pdf.subarray(0, original.length), original,
      'every byte of the original document must survive the signature verbatim'
    );
    assert.strictEqual(out.pdf.subarray(-6).toString('latin1'), '%%EOF\n');
  });

  test('the update points back at the previous cross-reference section, ' + label, async () => {
    const original = await fixture.samplePdf('Demo contract for Acme', { useObjectStreams });
    const before = pades.readLastXref(original);
    const out = await signed(original);
    const after = pades.readLastXref(out.pdf);
    assert.ok(after.offset > original.length, 'the new section sits in the appended part');
    assert.strictEqual(after.classic, before.classic, 'the update matches the original section type');
    assert.match(out.pdf.toString('latin1').slice(original.length), new RegExp('/Prev\\s+' + before.offset));
  });

  test('ByteRange covers the whole file except the signature blob, ' + label, async () => {
    const original = await fixture.samplePdf('Demo contract for Acme', { useObjectStreams });
    const out = await signed(original);
    const range = pades.readByteRange(out.pdf);
    assert.ok(range, 'the signed PDF must declare a ByteRange');
    const [a, b, c, d] = range;
    assert.strictEqual(a, 0, 'the first span starts at the first byte');
    assert.strictEqual(c + d, out.pdf.length, 'the second span runs to the last byte');
    assert.strictEqual(out.pdf[b], 0x3c, 'the gap opens on the < of /Contents');
    assert.strictEqual(out.pdf[c - 1], 0x3e, 'the gap closes on the > of /Contents');
    assert.deepStrictEqual(range, out.prepared.byteRange, 'the written range is the one prepare() reported');
    // Nothing but hex digits inside the gap: no structure hides in there.
    assert.match(out.pdf.subarray(b + 1, c - 1).toString('latin1'), /^[0-9a-f]+$/);
  });
}

test('the digest handed to the provider is the digest of the ByteRange', async () => {
  const original = await fixture.samplePdf();
  const out = await signed(original);
  const recomputed = pades.digestByteRange(out.pdf, pades.readByteRange(out.pdf));
  assert.deepStrictEqual(recomputed, out.prepared.digest);
  const parsed = cms.parseSignedData(pades.readContents(out.pdf, pades.readByteRange(out.pdf)));
  assert.deepStrictEqual(parsed.messageDigest, recomputed,
    'the message-digest attribute must equal the ByteRange hash');
});

test('embedding the signature changes only the reserved span', async () => {
  const original = await fixture.samplePdf();
  const out = await signed(original);
  assert.strictEqual(out.pdf.length, out.prepared.pdf.length, 'embedding never resizes the file');
  const { start, end } = out.prepared.contents;
  assert.deepStrictEqual(out.pdf.subarray(0, start + 1), out.prepared.pdf.subarray(0, start + 1));
  assert.deepStrictEqual(out.pdf.subarray(end), out.prepared.pdf.subarray(end));
});

test('the signature verifies against the certificate in the CMS', async () => {
  const original = await fixture.samplePdf();
  const out = await signed(original);
  const parsed = cms.parseSignedData(pades.readContents(out.pdf, pades.readByteRange(out.pdf)));
  const cert = new crypto.X509Certificate(parsed.certificates[0]);
  assert.ok(crypto.verify('sha256', parsed.signedAttrsDer, cert.publicKey, parsed.signatureValue));
  assert.deepStrictEqual(parsed.signingCertificateV2Hash, cms.sha256(signer.der),
    'signing-certificate-v2 must name the certificate that is actually in the CMS');
});

test('a single changed byte in the document breaks the signature', async () => {
  const original = await fixture.samplePdf();
  const out = await signed(original);
  const tampered = Buffer.from(out.pdf);
  tampered[100] = tampered[100] ^ 0xff;
  const range = pades.readByteRange(tampered);
  const parsed = cms.parseSignedData(pades.readContents(tampered, range));
  assert.notDeepStrictEqual(pades.digestByteRange(tampered, range), parsed.messageDigest);
});

test('the reserved space is honoured', async () => {
  const original = await fixture.samplePdf();
  const prepared = await pades.prepare(original, { contentsBytes: 2048 });
  assert.throws(() => pades.embed(prepared, Buffer.alloc(4096)), /only 2048 reserved/);
});

test('a signature field reaches the AcroForm and the first page', async () => {
  const PDFLib = pades.loadPdfLib();
  const original = await fixture.samplePdf();
  const out = await signed(original, { fieldName: 'ParaSign QES' });
  const reloaded = await PDFLib.PDFDocument.load(out.pdf);
  const names = reloaded.getForm().getFields().map((f) => f.getName());
  assert.ok(names.includes('ParaSign QES'), 'expected the signature field, found ' + names.join(','));
  assert.strictEqual(reloaded.getPageCount(), 1, 'signing must not add or drop a page');
});

test('an already signed document can be signed again without breaking the first signature', async () => {
  const original = await fixture.samplePdf();
  const first = await signed(original);
  const firstRange = pades.readByteRange(first.pdf);
  const firstDigest = pades.digestByteRange(first.pdf, firstRange);

  const second = await signed(first.pdf, { fieldName: 'ParaSign QES 2' });
  assert.deepStrictEqual(second.pdf.subarray(0, first.pdf.length), first.pdf,
    'the second signature must be an incremental update over the first');
  // The first signature still hashes to the same value, because its ByteRange
  // still describes the same bytes.
  assert.deepStrictEqual(pades.digestByteRange(second.pdf, firstRange), firstDigest);
});
