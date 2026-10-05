// A signed PDF has to stay a PDF. pdf-lib is what ParaSign edits with and
// pdf.js is what it renders with, so if either one chokes on the incremental
// update the feature is broken no matter how correct the CMS is. The verifier
// script runs here too, because a verification tool that only its author can
// run proves nothing.

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const qesRequire = createRequire(import.meta.url);
const qesRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const qesPades = qesRequire('../relay/lib/qes/pades.js');
const qesCms = qesRequire('../relay/lib/qes/cms.js');
const qesFixture = qesRequire('../relay/test/_qes-fixture.js');

const qesSigner = qesFixture.selfSignedCertificate({ commonName: 'Demo Signer' });

async function qesSignedPdf(text) {
  const original = await qesFixture.samplePdf(text);
  const prepared = await qesPades.prepare(original, { signerName: 'Demo Signer', reason: 'Prototype' });
  const attrs = qesCms.buildSignedAttributes({ messageDigest: prepared.digest, signerCertDer: qesSigner.der });
  const signature = qesFixture.signHashLikeQtsp(qesSigner.privateKey, qesCms.signedAttributesDigest(attrs));
  const der = qesCms.buildSignedData({ certificates: [qesSigner.der], signedAttrsDer: attrs, signatureValue: signature });
  return { original, pdf: qesPades.embed(prepared, der) };
}

test('pdf-lib still reads a signed document', async () => {
  const PDFLib = qesPades.loadPdfLib();
  const { pdf } = await qesSignedPdf('Demo contract for Acme');
  const doc = await PDFLib.PDFDocument.load(pdf);
  assert.strictEqual(doc.getPageCount(), 1);
  assert.deepStrictEqual(doc.getPage(0).getSize(), { width: 595.28, height: 841.89 });
});

test('pdf.js still renders the text of a signed document', async () => {
  const pdfjs = await import(pathToFileURL(join(qesRoot, 'frontend/vendor/pdfjs/pdf.min.js')).href);
  pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(join(qesRoot, 'frontend/vendor/pdfjs/pdf.worker.min.js')).href;
  const { pdf } = await qesSignedPdf('Demo contract for Acme');
  const doc = await pdfjs.getDocument({ data: new Uint8Array(pdf), isEvalSupported: false }).promise;
  try {
    assert.strictEqual(doc.numPages, 1);
    const content = await (await doc.getPage(1)).getTextContent();
    assert.strictEqual(content.items.map((i) => i.str).join(''), 'Demo contract for Acme');
  } finally {
    await doc.destroy();
  }
});

test('scripts/qes-verify.mjs passes on a good signature and fails on a tampered one', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qes-verify-'));
  try {
    const { pdf } = await qesSignedPdf('Demo contract for Acme');
    const good = join(dir, 'good.pdf');
    writeFileSync(good, pdf);

    const report = JSON.parse(execFileSync(process.execPath, [join(qesRoot, 'scripts/qes-verify.mjs'), good, '--json'],
      { encoding: 'utf8' }));
    assert.strictEqual(report.ok, true, JSON.stringify(report.checks.filter((c) => !c.ok)));
    assert.ok(report.checks.some((c) => c.name === 'message_digest_matches_document' && c.ok));
    assert.ok(report.checks.some((c) => c.name === 'signature_verifies_against_signer_key' && c.ok));
    assert.match(report.info.level, /PAdES-B-B/, 'no timestamp was requested, so B-B is the honest answer');

    // Flip a byte inside the signed range: the digest must stop matching.
    const tampered = Buffer.from(pdf);
    tampered[200] = tampered[200] ^ 0xff;
    const bad = join(dir, 'bad.pdf');
    writeFileSync(bad, tampered);
    let failed = null;
    try {
      execFileSync(process.execPath, [join(qesRoot, 'scripts/qes-verify.mjs'), bad, '--json'], { encoding: 'utf8' });
    } catch (e) {
      failed = JSON.parse(e.stdout);
    }
    assert.ok(failed, 'the verifier must exit non-zero on a tampered document');
    assert.strictEqual(failed.ok, false);
    assert.ok(failed.checks.some((c) => c.name === 'message_digest_matches_document' && !c.ok));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the receipt marker is a pointer, not the proof', async () => {
  const qes = qesRequire('../relay/lib/qes/index.js');
  const field = qes.receiptField({
    providerName: 'cleverbase-sandbox',
    certificateFingerprint: crypto.createHash('sha256').update(qesSigner.der).digest('hex'),
    signedAt: '2026-09-03T18:00:00.000Z',
  });
  // The .psign stays a ParaSign artefact: the qualified signature is validated
  // against the PDF, never against this field.
  assert.deepStrictEqual(Object.keys(field).sort(), ['certificate_fingerprint', 'provider', 'signed_at']);
  assert.strictEqual(field.certificate_fingerprint.length, 64);
});
