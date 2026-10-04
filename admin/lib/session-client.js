'use strict';
// Two rules for a signed-in session, kept out of server.js so they can be
// tested on their own.
//
// 1. HOW LONG A SESSION LIVES. One hour without activity, twelve hours at most.
//    The Redis record always slid (every authenticated call pushed its TTL out
//    by an hour), but the cookie was set once at login with Max-Age=3600 and
//    never again. So the browser threw the cookie away sixty minutes after
//    login however busy the person was, and a half-filled signing request was
//    lost with it (tester 5, 2026-10-04, finding 6). Now every authenticated
//    response re-issues the cookie with the same lifetime the record gets, so
//    the two cannot drift: min(one hour, what is left of the twelve).
//
// 2. WHICH CLIENT MAY USE IT. Finding 22i of the 2026-09-05 review bound a
//    session to the exact user-agent string that logged in, so a lifted cookie
//    did not work from another machine. Exact was too tight for honest use:
//    Safari's "Request Desktop Website" swaps the whole string (iPhone becomes
//    Macintosh), and every browser update changes the version numbers. Both
//    logged people out mid-task. The binding now compares the browser ENGINE
//    (WebKit, Blink, Gecko), which none of those change: every browser on iOS
//    is WebKit in mobile and desktop mode alike, Chrome and Edge stay Blink
//    across updates and the desktop toggle, Firefox stays Gecko. A client that
//    is no browser at all (curl, a script) is compared on its string with the
//    version numbers taken out. What it still stops: a cookie replayed from a
//    different kind of client. What it no longer stops: a cookie replayed from
//    another browser of the same engine. That is the trade, chosen on purpose;
//    the cookie is httpOnly and Secure, and the binding was a second line, not
//    the first.

const USER_SESSION_IDLE_S = 3600;               // one hour without activity
const USER_SESSION_MAX_AGE_MS = 12 * 3600 * 1000; // twelve hours, whatever happens

// Seconds this session may still live, for both the cookie and the record.
// Never more than the idle hour, never past the absolute cap, never below 1
// (a zero Max-Age would delete the cookie on a request that was just allowed).
function sessionLifetimeS(createdAt, now = Date.now()) {
  const left = Math.floor((Number(createdAt) + USER_SESSION_MAX_AGE_MS - now) / 1000);
  if (!Number.isFinite(left)) return USER_SESSION_IDLE_S;
  return Math.max(1, Math.min(USER_SESSION_IDLE_S, left));
}

function clientFamily(ua) {
  const s = String(ua || '');
  if (/\bFirefox\/\d/.test(s) && /\bGecko\/\d/.test(s)) return 'gecko';
  if (/\b(Chrome|Chromium)\/\d/.test(s)) return 'blink';
  if (/\bAppleWebKit\/\d/.test(s)) return 'webkit';
  return 'other:' + s.replace(/[\d._]+/g, '').trim().slice(0, 200);
}

module.exports = { USER_SESSION_IDLE_S, USER_SESSION_MAX_AGE_MS, sessionLifetimeS, clientFamily };
