'use strict';
// Log redaction for the admin panel's process log (stdout -> container log).
//
// /privacy says an IP is processed transiently for security and abuse
// prevention and is not logged for analytics or profiling, and /security says
// nginx access logging is off. Three admin paths contradicted that: the signup
// route logged the full client IP twice (once with the full e-mail address next
// to it) and the TOTP-reset rate limiter logged it a third time. A container log
// is not transient, so those three lines were the only place on the hosted
// deployment where a full visitor IP came to rest.
//
// The form is truncation, not hashing, because the repo already truncates
// everywhere else it masks an IP (relay/relay.js maskIp, admin/lib/audit.js
// _maskIp, admin/server.js maskIp for the sessions API). Truncation needs no
// salt to rotate and no key to lose.
//
//   IPv4 -> /24  203.0.113.42            -> 203.0.113.x
//   IPv6 -> /48  2001:db8:85a3::8a2e:1   -> 2001:db8:85a3::x
//
// The host part is written as a literal `x`, not as `0`. That is deliberate:
// `203.0.113.0` is still a syntactically complete IPv4 address, so a reader
// (and a test) cannot tell a truncated address from a real one. `203.0.113.x`
// is not an address at all, which is what makes "no full IP reaches the log"
// something a regex can assert.

// Finding an address inside a longer log line. Deliberately narrow: this runs
// over ordinary log text, so a pattern that also eats a clock time or a C++
// scope operator would corrupt lines it was meant to leave alone.
const IPV4_RE = /(?<![0-9A-Za-z.:])\d{1,3}(?:\.\d{1,3}){3}(?![0-9A-Za-z.])/g;
// Every valid IPv6 literal is either written out in full (exactly eight
// hextets, seven colons) or carries a "::". A clock time is neither, which is
// what keeps 12:34:56 out of this.
const IPV6_RE = new RegExp(
  [
    // ::ffff:203.0.113.42, what a dual-stack socket hands over. First, so the
    // embedded IPv4 tail is consumed here and not left behind by IPV4_RE.
    '::[Ff]{4}:\\d{1,3}(?:\\.\\d{1,3}){3}',
    // written out in full
    '(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}',
    // compressed, with hextets before the "::"
    '(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?',
    // compressed, with nothing before it (::1, ::)
    '::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?',
  ].map(alt => '(?<![0-9A-Za-z:.])' + alt).join('|'),
  'g'
);
// A plaintext address. maskEmailForLog leaves `a***@domain`, whose local part
// stops being in this class after the first character, so a masked address is
// not matched a second time.
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

// Truncate a client IP for the process log. IPv4 keeps the /24, IPv6 the /48.
// Anything that is not recognisably an address becomes `***`, so an unparsed
// value can never fall through unmasked. 'unknown' is the getClientIp fallback
// and carries nothing, so it is passed through as-is.
function maskIpForLog(ip) {
  const raw = String(ip == null ? '' : ip).trim();
  if (!raw || raw === 'unknown') return raw;
  // A link-local address arrives with a zone id (fe80::1%eth0). It says nothing
  // about the subject, so drop it rather than carry it into the masked form.
  const s = raw.split('%')[0];
  // IPv4-mapped IPv6 (::ffff:203.0.113.42) is what a dual-stack socket hands
  // over. Mask the embedded v4 address, not the v6 wrapper around it.
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(s);
  const bare = mapped ? mapped[1] : s;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) {
    return bare.split('.').slice(0, 3).join('.') + '.x';
  }
  if (bare.includes(':')) {
    const head = expandIpv6Prefix(bare);
    return head ? head + '::x' : '***';
  }
  return '***';
}

// The first three hextets of an IPv6 address, which is its /48. A "::" stands
// for a run of zero hextets, so it has to be expanded first: without that,
// fe80::1 and 2001:db8:85a3::1 would both be read off their written form and
// the second one would lose a hextet it actually has. Returns '' if the value
// does not read as an address at all.
function expandIpv6Prefix(addr) {
  const halves = addr.split('::');
  if (halves.length > 2) return '';
  const split = h => (h ? h.split(':') : []);
  const head = split(halves[0]);
  const tail = halves.length === 2 ? split(halves[1]) : [];
  if (![...head, ...tail].every(h => /^[0-9A-Fa-f]{1,4}$/.test(h))) return '';
  const total = head.length + tail.length;
  if (halves.length === 1) {
    if (total !== 8) return '';
  } else if (total > 7) {
    return '';
  }
  const zeros = halves.length === 2 ? Array(8 - total).fill('0') : [];
  return [...head, ...zeros, ...tail].slice(0, 3).join(':');
}

// Mask an e-mail for the process log: first local character plus the full
// domain, e.g. demo@example.com -> d***@example.com. The domain is kept
// because a log without it cannot answer "which provider is flooding us",
// which is the reason these lines exist at all.
function maskEmailForLog(e) {
  const s = String(e == null ? '' : e);
  const at = s.indexOf('@');
  if (at < 1) return s ? '***' : '';
  return s[0] + '***' + s.slice(at);
}

// Last line of defence. Runs over the finished log line and masks any full
// address that a call site forgot to mask, so a new console.log on one of
// these paths cannot reintroduce the bug by omission. Order matters: e-mails
// first, because an address may carry a domain that looks like nothing else,
// then IPv6 before IPv4 so ::ffff:203.0.113.42 is handled as one token.
function redact(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(EMAIL_RE, m => maskEmailForLog(m))
    .replace(IPV6_RE, m => (m.includes(':') ? maskIpForLog(m) : m))
    .replace(IPV4_RE, m => maskIpForLog(m));
}

// console.<level> with every string argument passed through redact(). The
// three admin paths that used to write a full IP call this instead of console
// directly, so the masking cannot be skipped by editing one call site.
function logRedacted(level, ...args) {
  const fn = typeof console[level] === 'function' ? console[level] : console.log;
  fn.apply(console, args.map(redact));
}

module.exports = { maskIpForLog, maskEmailForLog, redact, logRedacted };
