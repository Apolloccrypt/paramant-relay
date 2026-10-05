'use strict';
// URL-level SSRF guard (stage 1 of the relay's two-stage check; stage 2
// re-resolves DNS and re-runs this on the resolved IP). Rejects https URLs that
// point at loopback/link-local/RFC1918/ULA, numeric-encoding tricks, non-443
// ports, internal metadata hosts, and IPv4-embedded IPv6 forms.
function isSsrfSafeUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
    // Reject non-hostname forms: pure decimal (2130706433), hex (0x7f000001), short octal
    if (/^\d+$/.test(h)) return false;                  // decimal IP
    if (/^0x[0-9a-f]+$/i.test(h)) return false;          // hex IP
    if (/^(0\d+\.){1,3}\d+$/.test(h)) return false;    // octal octets (0177.0.0.1)
    if (/^\d+\.\d+$/.test(h)) return false;             // short-form (127.1)
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (/^::ffff:/i.test(h)) {
      const v4part = h.replace(/^::ffff:/i, '');
      return isSsrfSafeUrl('https://' + v4part + '/');
    }
    // Other IPv4-in-IPv6 embeddings (defence-in-depth, #21). The URL parser
    // normalises e.g. [64:ff9b::127.0.0.1] to hex (64:ff9b::7f00:1), so detect
    // the translation prefixes directly and also recheck any dotted IPv4 tail.
    // These carry an IPv4 destination the relay must not be tricked into reaching.
    if (/^64:ff9b:/i.test(h)) return false;   // NAT64 (64:ff9b::/96 + 64:ff9b:1::/48)
    if (/^2002:/i.test(h)) return false;      // 6to4 (embeds IPv4 in the next 32 bits)
    const v4tail = h.match(/:((?:\d{1,3}\.){3}\d{1,3})$/);
    if (v4tail) return isSsrfSafeUrl('https://' + v4tail[1] + '/');
    if (h === 'localhost' || h === '0.0.0.0' || h === '0') return false;
    if (/^127\./.test(h)) return false;
    if (/^::1$/.test(h)) return false;
    if (/^169\.254\./.test(h)) return false;
    if (/^fe80/i.test(h)) return false;
    if (/^10\./.test(h)) return false;
    if (/^192\.168\./.test(h)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return false;
    if (/^f[cd]/i.test(h)) return false;                  // IPv6 ULA (fc00::/7)
    if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return false;
    if (h === 'metadata.google.internal' || h === 'metadata.aws.internal') return false;
    // Restrict to standard HTTPS ports only.
    const ALLOWED_PORTS = new Set(['', '443']);
    if (!ALLOWED_PORTS.has(u.port)) return false;
    return true;
  } catch { return false; }
}

module.exports = { isSsrfSafeUrl };
