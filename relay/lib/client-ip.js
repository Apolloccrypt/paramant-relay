'use strict';
// Who the caller is, when the caller is behind a proxy.
//
// WHY THIS FILE EXISTS. The 2026-09-05 hostile review, finding 7. Every per-IP
// limit in the relay keyed on this one line:
//
//     return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
//
// with a comment underneath explaining that nginx sets X-Real-IP
// authoritatively. nginx does that on the apex and on relay.paramant.app. It
// does not do it on the four sector hostnames, and it does not do it in the
// /rp/<sector>/ blocks on the main site, and nginx forwards unknown client
// headers by default. On those hosts the header arrived from the client, so a
// caller picked their own address and every limiter keyed on it: the view
// limiter, the sign limiter, the signer lookup, the claim and status limiters,
// the MFA limiter, the anonymous upload window and the STH ingest window. One
// header, and the rate limiting on the whole relay was decorative.
//
// The other direction is just as bad and needs no attacker: if NOBODY sets the
// header, every request on that hostname falls into one shared bucket keyed on
// the proxy's own address, and one noisy visitor locks out everyone else.
//
// So the nginx configs now set X-Real-IP on every block that reaches a relay
// (and relay/test/trusted-edge-gate.test.js refuses to let a new one be added
// without it), and this file is the lock on the other side of that door: a
// forwarded address is only believed when the connection it arrived on is one
// we put there ourselves.
//
// THE RULE. Trust the header only from a trusted peer, and only when it is
// actually an IP address. An untrusted peer is its own address and nothing else.
// A trusted peer that sends something that is not an address is a broken proxy,
// not an escape hatch, so that falls back to the peer as well.
//
// THE DEFAULT. Loopback plus the RFC1918 and CGNAT ranges. Not a guess: the
// relay is never addressed from the internet directly, only through nginx, and
// in production it runs in a container published as 127.0.0.1:3001->3000
// (docker-compose.yml), so the peer address the container actually sees is the
// docker bridge gateway in 172.16.0.0/12 and NOT 127.0.0.1. A default of
// loopback alone would look correct in the tests and wipe out every real client
// address in production, which is the failure this file is meant to prevent.
// TRUSTED_PROXY_CIDRS overrides it for a deployment that fronts the relay
// differently.

const DEFAULT_TRUSTED = [
  '127.0.0.0/8',      // loopback
  '::1/128',          // loopback, v6
  '10.0.0.0/8',       // RFC1918
  '172.16.0.0/12',    // RFC1918, and the docker bridge lives in here
  '192.168.0.0/16',   // RFC1918
  '100.64.0.0/10',    // CGNAT, where a tailnet address lands
  'fc00::/7',         // unique local, v6
];

// An IPv4 literal as four bytes, or null. Deliberately strict: no leading
// zeros, no shorthand, no hostnames. Anything this does not recognise is not
// treated as an address, which is the safe answer for both callers here.
function v4Bytes(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const out = [];
  for (let i = 1; i <= 4; i++) {
    const part = m[i];
    if (part.length > 1 && part[0] === '0') return null;
    const n = Number(part);
    if (!(n >= 0 && n <= 255)) return null;
    out.push(n);
  }
  return out;
}

// An IPv6 literal as sixteen bytes, or null. Handles the one form that matters
// operationally: `::ffff:10.0.0.1`, which is how a v4 peer arrives on a socket
// bound dual-stack, and which must compare against the v4 ranges above.
function v6Bytes(s) {
  let str = s;
  const zone = str.indexOf('%');
  if (zone !== -1) str = str.slice(0, zone);
  if (!/^[0-9A-Fa-f:.]+$/.test(str)) return null;

  let tail = [];
  const lastColon = str.lastIndexOf(':');
  const maybeV4 = lastColon === -1 ? '' : str.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    const b = v4Bytes(maybeV4);
    if (!b) return null;
    tail = b;
    str = str.slice(0, lastColon + 1) + '0:0';
  }

  const halves = str.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part) => (part === '' ? [] : part.split(':').map((g) => {
    if (g === '' || g.length > 4) return NaN;
    const n = parseInt(g, 16);
    return Number.isNaN(n) ? NaN : n;
  }));
  const head = toGroups(halves[0]);
  const rest = halves.length === 2 ? toGroups(halves[1]) : [];
  if (head.some(Number.isNaN) || rest.some(Number.isNaN)) return null;

  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes = [];
  for (const g of groups) { bytes.push((g >> 8) & 0xff, g & 0xff); }
  if (tail.length) { bytes[12] = tail[0]; bytes[13] = tail[1]; bytes[14] = tail[2]; bytes[15] = tail[3]; }
  return bytes;
}

// Normalise to a 16-byte comparison form so a v4 address and its v6-mapped
// twin compare equal. Returns null for anything that is not an address.
function toBytes(ip) {
  const s = String(ip == null ? '' : ip).trim();
  if (!s) return null;
  const v4 = v4Bytes(s);
  if (v4) return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4];
  return v6Bytes(s);
}

function isIpLiteral(ip) { return toBytes(ip) !== null; }

// "10.0.0.0/8" -> a matcher. A bare address is treated as a /32 or /128.
function parseCidr(spec) {
  const s = String(spec || '').trim();
  if (!s) return null;
  const slash = s.lastIndexOf('/');
  const addr = slash === -1 ? s : s.slice(0, slash);
  const bytes = toBytes(addr);
  if (!bytes) return null;
  const isV4 = v4Bytes(addr) !== null;
  let bits = slash === -1 ? (isV4 ? 32 : 128) : parseInt(s.slice(slash + 1), 10);
  if (!Number.isInteger(bits) || bits < 0) return null;
  if (isV4) {
    if (bits > 32) return null;
    bits += 96; // the mapped prefix is fixed, so a v4 /8 is a /104 in this form
  } else if (bits > 128) return null;
  return { bytes, bits };
}

function inCidr(bytes, cidr) {
  let bits = cidr.bits;
  for (let i = 0; i < 16 && bits > 0; i++) {
    const take = bits >= 8 ? 8 : bits;
    const mask = take === 8 ? 0xff : (0xff << (8 - take)) & 0xff;
    if ((bytes[i] & mask) !== (cidr.bytes[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

function parseTrusted(spec) {
  const list = String(spec == null ? '' : spec).split(',').map((s) => s.trim()).filter(Boolean);
  const source = list.length ? list : DEFAULT_TRUSTED;
  return source.map(parseCidr).filter(Boolean);
}

// Build the resolver once, at boot, so a per-request call is a few integer
// comparisons and never re-parses the configuration.
//
// `headerName` is the header the edge is configured to set. It is a parameter
// rather than a constant because the admin panel and the relay have historically
// disagreed about it, and a second copy of this logic is how they drifted.
function makeClientIp({ trusted, headerName = 'x-real-ip' } = {}) {
  const nets = parseTrusted(trusted);
  const header = String(headerName).toLowerCase();

  function trusts(peer) {
    const b = toBytes(peer);
    if (!b) return false;
    for (const n of nets) if (inCidr(b, n)) return true;
    return false;
  }

  function clientIp(req) {
    const peer = (req && req.socket && req.socket.remoteAddress) || '';
    if (!trusts(peer)) return peer || 'unknown';
    const raw = req && req.headers ? req.headers[header] : '';
    // A comma-separated list is a forwarding chain that reached us through
    // something we did not configure. The nearest hop is the only one our own
    // edge could have written, so that is the one that counts.
    const first = String(raw == null ? '' : raw).split(',')[0].trim();
    if (!first || !isIpLiteral(first)) return peer || 'unknown';
    return first;
  }

  clientIp.trusts = trusts;   // exposed so a test can assert the boundary itself
  clientIp.header = header;
  return clientIp;
}

module.exports = { makeClientIp, isIpLiteral, toBytes, parseCidr, inCidr, DEFAULT_TRUSTED };
