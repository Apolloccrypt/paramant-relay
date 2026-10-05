'use strict';
// Content-Disposition for a filename the user chose (RFC 6266, RFC 5987).
//
// Node refuses a header value with a character above U+00FF: writeHead throws
// ERR_INVALID_CHAR and the download becomes a 500. A document called
// "contract-\u{1F4DD}.pdf" or "договор.pdf" is ordinary, so the name goes out twice:
//   filename="..."             an ASCII stand-in for old clients
//   filename*=UTF-8''<pct>     the real name, percent-encoded
// A name that is already plain ASCII goes out once, as filename="...".

const MAX_NAME = 200;

function clean(name) {
  return String(name == null ? '' : name)
    .replace(/[\u0000-\u001f\u007f]/g, '')   // no CR/LF/NUL: header injection
    .replace(/[\\/]/g, '_')                   // no path separators
    .trim()
    .slice(0, MAX_NAME);
}

function asciiFallback(name) {
  return name
    .normalize('NFKD').replace(/[̀-ͯ]/g, '')  // e with accent -> e
    .replace(/[^\x20-\x7e]/g, '_')
    .replace(/["%]/g, '_');
}

// RFC 5987 attr-char: ALPHA DIGIT ! # $ & + - . ^ _ ` | ~
function pctEncode(name) {
  return encodeURIComponent(name)
    .replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function attachment(name, fallback = 'download') {
  const n = clean(name) || fallback;
  const ascii = asciiFallback(n);
  if (ascii === n) return `attachment; filename="${ascii}"`;
  return `attachment; filename="${ascii}"; filename*=UTF-8''${pctEncode(n)}`;
}

module.exports = { attachment };
