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

const MAX_CANDIDATES = 16;
const MAX_INFLATED = 512 * 1024 * 1024;

function latin1(bytes) {
  // One char per byte, so string offsets are byte offsets.
  let out = '';
  const STEP = 0x8000;
  for (let i = 0; i < bytes.length; i += STEP) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(bytes.length, i + STEP)));
  }
  return out;
}

async function inflate(bytes) {
  if (typeof DecompressionStream !== 'function') return null;
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    const reader = stream.getReader();
    const parts = [];
    let total = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_INFLATED) { try { reader.cancel(); } catch { /* gone */ } return null; }
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
      data = await inflate(data);
      if (!data) continue;
    } else {
      data = data.slice();
    }
    out.push({ bytes: data });
    re.lastIndex = kw;
  }
  return out;
}
