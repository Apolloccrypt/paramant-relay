// The files embedded in a PDF (/Type /EmbeddedFile streams), as raw bytes.
//
// /verify uses this for one question only: does a readable copy carry the
// signed original inside it? The readable copy that /co-sign makes (the pdf
// with every signature drawn on it) embeds the exact bytes everyone signed.
// Nothing here is trusted: a candidate counts only when its SHA3-256 equals
// the hash inside the signatures, so a sloppy parse can miss a file but can
// never make a wrong one pass (eindmatrix DASH-09-L).
//
// Plain byte scanning, no PDF library: an uncompressed stream is taken as it
// is, a /FlateDecode one goes through DecompressionStream('deflate'). Streams
// with other filters are skipped.
//
// Inflating is capped, per stream and over all streams together, because a
// few hundred KB of deflate can unpack to gigabytes and take the tab down
// (review 573, D-L3). A signed original is at most 20 MB (MAX_PDF_BYTES in
// parasign-open-api.js), so 64 MB per stream and 128 MB in total leave room.
// A stream over a cap is not a candidate; the returned list then carries
// tooLarge = true, so /verify can say it did not look instead of pretending
// there was nothing to find.

const MAX_CANDIDATES = 16;
export const MAX_INFLATED = 64 * 1024 * 1024;
export const MAX_INFLATED_TOTAL = 128 * 1024 * 1024;

function latin1(bytes) {
  // One char per byte, so string offsets are byte offsets.
  let out = '';
  const STEP = 0x8000;
  for (let i = 0; i < bytes.length; i += STEP) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(bytes.length, i + STEP)));
  }
  return out;
}

const TOO_LARGE = Symbol('too large');

async function inflate(bytes, budget) {
  if (typeof DecompressionStream !== 'function') return null;
  const cap = Math.min(MAX_INFLATED, budget);
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    const reader = stream.getReader();
    const parts = [];
    let total = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > cap) { try { reader.cancel(); } catch { /* gone */ } return TOO_LARGE; }
      parts.push(value);
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  } catch {
    return null;
  }
}

export function looksLikePdf(bytes) {
  return !!bytes && bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
}

export async function embeddedFiles(bytes) {
  if (!looksLikePdf(bytes)) return [];
  const text = latin1(bytes);
  const out = [];
  out.tooLarge = false;
  let used = 0;
  const re = /\/Type\s*\/EmbeddedFile\b/g;
  let m;
  while ((m = re.exec(text)) && out.length < MAX_CANDIDATES) {
    const objStart = text.lastIndexOf(' obj', m.index);
    const kw = text.indexOf('stream', m.index);
    if (objStart < 0 || kw < 0) continue;
    const dict = text.slice(objStart, kw);
    if (/endobj/.test(dict)) continue;            // not the same object
    let start = kw + 6;
    if (text[start] === '\r') start++;
    if (text[start] === '\n') start++;
    let end = -1;
    const len = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
    if (len) end = start + Number(len[1]);
    if (end < start || end > bytes.length || text.slice(end, end + 12).trim().indexOf('endstream') !== 0) {
      const es = text.indexOf('endstream', start);
      if (es < 0) continue;
      end = es;
      if (text[end - 1] === '\n') end--;
      if (text[end - 1] === '\r') end--;
    }
    let data = bytes.subarray(start, end);
    const filter = /\/Filter\s*(\[\s*)?\/(\w+)/.exec(dict);
    if (filter) {
      if (filter[2] !== 'FlateDecode') continue;
      data = await inflate(data, MAX_INFLATED_TOTAL - used);
      if (data === TOO_LARGE) { out.tooLarge = true; continue; }
      if (!data) continue;
      used += data.length;
    } else {
      data = data.slice();
    }
    out.push({ bytes: data });
    re.lastIndex = kw;
  }
  return out;
}
