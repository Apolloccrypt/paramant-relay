// Regression test for the ParaShare receive-side filename + MIME bug.
//
// Mirrors the metadata wire format produced by frontend/parashare.html and the
// header-parsing + download logic in frontend/ontvang.html (receiveFile()).
//
// Reported symptom: a sent *.mp4 saved as a *.txt file. Root cause was that
// `fileName` was declared `const` and then reassigned from chunk-0 metadata.
// The reassignment throws a TypeError that the surrounding `catch(_) {}`
// swallowed, so the real filename was lost (stayed 'download') and the
// typeless Blob let the browser infer a .txt extension.
//
// Run: node tests/receive-filename.test.mjs

import assert from 'node:assert/strict';

const META_MAGIC = new Uint8Array([0x50, 0x52, 0x53, 0x48]); // 'PRSH'

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false); // big-endian, like parashare.html
  return b;
}
function concat(...arrs) {
  const len = arrs.reduce((a, x) => a + x.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Sender (parashare.html ~line 1013): META_MAGIC | u32be(metaLen) | metaJSON | fileBytes
function buildChunk0(fileName, fileBytes) {
  const metaBytes = new TextEncoder().encode(JSON.stringify({ file_id: 'abc', file_name: fileName }));
  return concat(META_MAGIC, u32be(metaBytes.length), metaBytes, fileBytes);
}

// Receiver — FIXED logic (current ontvang.html receiveFile)
function receiveFixed(plainPadded, msgFileName) {
  let fileName = msgFileName || 'download';
  let doff = 0;
  if (plainPadded[0] === META_MAGIC[0] && plainPadded[1] === META_MAGIC[1]) {
    doff = 4;
    const metaLen = new DataView(plainPadded.buffer).getUint32(doff, false);
    try {
      const metaObj = JSON.parse(new TextDecoder().decode(plainPadded.slice(doff + 4, doff + 4 + metaLen)));
      if (metaObj.file_name) fileName = metaObj.file_name;
    } catch (_) {}
    doff += 4 + metaLen;
  }
  const fileData = plainPadded.slice(doff);
  return { fileName, blob: new Blob([fileData], { type: 'application/octet-stream' }), fileData };
}

// Receiver — OLD buggy logic (const fileName + typeless Blob), kept to prove the test discriminates
function receiveBuggy(plainPadded, msgFileName) {
  const fileName = msgFileName || 'download'; // const -> reassignment below throws
  let doff = 0;
  if (plainPadded[0] === META_MAGIC[0] && plainPadded[1] === META_MAGIC[1]) {
    doff = 4;
    const metaLen = new DataView(plainPadded.buffer).getUint32(doff, false);
    try {
      const metaObj = JSON.parse(new TextDecoder().decode(plainPadded.slice(doff + 4, doff + 4 + metaLen)));
      if (metaObj.file_name) fileName = metaObj.file_name; // TypeError, swallowed by catch
    } catch (_) {}
    doff += 4 + metaLen;
  }
  const fileData = plainPadded.slice(doff);
  return { fileName, blob: new Blob([fileData]), fileData };
}

const fileBytes = new Uint8Array([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34, 0x32]); // mp4 'ftypmp42'
const payload = buildChunk0('holiday.mp4', fileBytes);

// The receiver always starts with the placeholder 'download' (real name is only in the payload)
const fixed = receiveFixed(payload, 'download');
assert.equal(fixed.fileName, 'holiday.mp4', 'fixed: filename must be recovered from chunk-0 metadata');
assert.equal(fixed.blob.type, 'application/octet-stream', 'fixed: blob must declare octet-stream');
assert.deepEqual(new Uint8Array(await fixed.blob.arrayBuffer()), fileBytes, 'fixed: file bytes must be intact');

const buggy = receiveBuggy(payload, 'download');
assert.equal(buggy.fileName, 'download', 'buggy: const reassignment is swallowed -> name lost (reproduces .txt symptom)');
assert.equal(buggy.blob.type, '', 'buggy: typeless blob');

console.log('PASS: receiveFixed recovers "holiday.mp4" as application/octet-stream with intact bytes;');
console.log('      old const-logic loses the name (reproduces the reported bug).');
