'use strict';
// Who the customer is, carried from the admin to the relay.
//
// The relay rate limits envelope views (30 a minute), signatures (10 a minute)
// and MFA attempts per client address. Every one of those calls on the web path
// reaches the relay through this admin, and the admin used to send no address at
// all. The relay then saw the admin container as the client, so every customer
// shared one bucket: ten signatures anywhere in the country in one minute and
// the eleventh signer got a 429, which the activation route turned into "this
// invitation belongs to a different email address" (tester 2, 2026-10-04, A4).
//
// The fix is one header, X-Paramant-Client-IP, that the admin sets on every call
// that also carries X-Internal-Auth. The relay believes it only next to that
// secret (relay/lib/client-ip.js withInternalClientIp), so nobody outside can
// use it to choose an address, and nginx blanks it on the way in as well.
//
// Where the address comes from: X-Real-IP, which nginx sets to $remote_addr on
// every /api/user/ block (deploy/nginx-paramant-live.conf), the same header the
// admin's own limiters already key on. The admin port is published on loopback
// only, so nginx is the one thing that can reach it.
//
// How it reaches the outgoing call: an AsyncLocalStorage set once per request,
// so callRelay and relayFetch pick it up without threading a parameter through
// forty call sites. A call made outside any request (a timer, the boot) carries
// no header and the relay falls back to its own edge rule, as before.

const net = require('net');
const { AsyncLocalStorage } = require('async_hooks');

const HEADER = 'X-Paramant-Client-IP';
const store = new AsyncLocalStorage();

function requestClientIp(req) {
  const raw = (req && req.headers && req.headers['x-real-ip']) || '';
  const first = String(raw).split(',')[0].trim();
  if (net.isIP(first)) return first;
  const peer = (req && req.socket && req.socket.remoteAddress) || '';
  return net.isIP(peer) ? peer : '';
}

// Express middleware: everything downstream of next() runs inside the store.
function middleware(req, res, next) {
  store.run({ clientIp: requestClientIp(req) }, next);
}

// The header to add to an internal relay call, or {} outside a request.
function headers() {
  const ctx = store.getStore();
  const ip = ctx && ctx.clientIp;
  return ip && net.isIP(ip) ? { [HEADER]: ip } : {};
}

module.exports = { HEADER, middleware, headers, requestClientIp, _store: store };
