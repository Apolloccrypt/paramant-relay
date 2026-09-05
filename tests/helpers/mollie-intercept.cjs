'use strict';
// TEST-ONLY preload (node --require). Sends https requests for api.mollie.com
// to the fake Mollie in FAKE_MOLLIE_URL and leaves every other https request
// alone.
//
// Why this shape. relay/lib/mollie.js hard-codes the host so that no request
// can ever be pointed somewhere else by an attacker, and that is worth keeping.
// Rather than open a "base url" env var that would exist in production for the
// sake of a test, the test replaces the transport. relay.js, the checkout
// route, the webhook route and lib/mollie.js all run unmodified.
//
// Does nothing at all unless FAKE_MOLLIE_URL is set, so loading it in a
// production process is inert.

const routes = new Map();
if (process.env.FAKE_MOLLIE_URL) routes.set('api.mollie.com', new URL(process.env.FAKE_MOLLIE_URL));
// The mail sink. Without it a test cannot see the one thing the customer is
// promised in writing: the warning before his term ends, the invoice, the
// cancellation confirmation. RESEND_API_KEY unset makes the relay skip sending
// silently, which is exactly the state in which nobody notices a missing mail.
if (process.env.FAKE_RESEND_URL) routes.set('api.resend.com', new URL(process.env.FAKE_RESEND_URL));

if (routes.size) {
  const https = require('https');
  const http = require('http');
  const realRequest = https.request.bind(https);

  https.request = function request(a, b, c) {
    let opts = a, cb = b;
    if (typeof a === 'string' || a instanceof URL) { opts = Object.assign({}, typeof b === 'object' && b ? b : {}); cb = typeof b === 'function' ? b : c;
      const u = new URL(String(a)); opts.host = u.hostname; opts.path = u.pathname + u.search; }
    const host = String((opts && (opts.host || opts.hostname)) || '').split(':')[0];
    const to = routes.get(host);
    if (!to) return realRequest(a, b, c);
    const redirected = Object.assign({}, opts, { host: to.hostname, hostname: to.hostname, port: to.port, protocol: 'http:', agent: false });
    return http.request(redirected, cb);
  };
  https.get = function get(a, b, c) {
    const req = https.request(a, b, c);
    req.end();
    return req;
  };
}

// The admin plane mails with global fetch (undici), which never passes through
// https.request, so the same redirection has to be done a second time. Without
// this the cancellation mail is invisible to a test even though it is sent.
if (routes.size && typeof globalThis.fetch === 'function') {
  const realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = function fetchPatched(input, init) {
    try {
      const raw = typeof input === 'string' ? input : (input && input.url) || '';
      const u = new URL(raw);
      const to = routes.get(u.hostname);
      if (to) {
        u.protocol = 'http:'; u.hostname = to.hostname; u.port = to.port;
        return realFetch(u.toString(), init);
      }
    } catch (_) { /* not a URL we can rewrite */ }
    return realFetch(input, init);
  };
}
