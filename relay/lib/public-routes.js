'use strict';
// Which relay routes are reachable without a credential, and why.
//
// WHY THIS FILE EXISTS. POST /v2/anon-inbound takes an upload with no API key,
// outside getEntitlements and outside the transfer quota, and frontend/docs.html
// advertises it with Auth "n/a". feat/close-anon-inbound (20 July 2026) proposed
// closing it and sat unlanded for 47 days. It is deliberately NOT closed here:
// the route carries first-party traffic today. scripts/heartbeat/parasend.mjs
// proves the anonymous transfer path on every run (upload, fetch, byte compare,
// burn) and admin/server.js POST /api/drop/upload proxies to it behind its own
// per-email and per-IP daily caps. Closing it silently would take out the
// product heartbeat and the drop flow in the same commit. The route keeps its
// Deprecation and Sunset headers (31 December 2026) and retires on announcement,
// not by surprise.
//
// What is closed instead is the drift. The keyless surface was knowable only by
// reading 9000 lines of relay.js and hoping; docs.html said "n/a" in a table
// nothing checked. This module is the declaration, and
// tests/public-route-surface.test.mjs holds three things to it: the docs match
// it, it matches relay.js, and no new keyless route joins it unannounced.
//
// A route belongs here ONLY if it is meant to answer a caller carrying no
// credential at all. A route that authenticates by some other means (an invite
// token, a signed webhook, X-Admin-Token) is not public and does not belong.

// Routes the API documentation may mark Auth "n/a", each with the reason it is
// safe to answer an anonymous caller. `docs` is the exact path string used in
// the frontend/docs.html route table; `src` is the comparison in relay.js that
// dispatches it, which the suite uses to prove the handler really does sit
// above the API-key gate and not below it.
const PUBLIC_ROUTES = [
  { method: 'GET',  docs: '/health',
    src: "path === '/health'",
    why: 'liveness and version. Deliberately unauthenticated so a monitor can reach it.' },
  { method: 'POST', docs: '/v2/anon-inbound',
    why: 'the deprecated anonymous upload. Rate limited per IP (ANON_RATE_PER_HOUR), '
       + 'capped at 5 MB, one read, 24h TTL. Sunset 2026-12-31. Live traffic: the '
       + 'product heartbeat and the admin drop flow.',
    src: "path === '/v2/anon-inbound'",
    deprecated: true },
  { method: 'GET',  docs: '/v2/check-key',
    src: "path === '/v2/check-key'",
    why: 'a client must be able to discover which relay accepts its key before it has one.' },
  { method: 'GET',  docs: '/v2/did/:did',
    src: 'path.match(/^\\/v2\\/did\\/([^/]+)$/)',
    why: 'DID documents are public by definition (W3C DID resolution).' },
  { method: 'GET',  docs: '/v2/ct/log',
    src: "path === '/v2/ct/log'",
    why: 'the transparency log is worthless if only the operator can read it.' },
  { method: 'GET',  docs: '/v2/relays',
    src: "path === '/v2/relays'",
    why: 'relay discovery. A client picks a relay before it authenticates to one.' },
];

// The identifiers in the API-key gate in relay.js that let a request past it.
// Each one is a hole in the gate by design; the point of pinning them is that a
// SEVENTH cannot appear without this list, and this comment, being updated.
//
//   isAdminPath            /v2/admin/*, which requires X-Admin-Token instead
//   isEnvelopePublic       an external signing party reaching their own envelope
//   isBillingWebhook       the payment provider, verified by signature in-route
//   isInternalBillingCancel the admin plane, verified by X-Internal-Auth
//
// None of these are anonymous: each authenticates by something other than an
// API key. That is why they are listed apart from PUBLIC_ROUTES.
const KEY_GATE_EXEMPTIONS = [
  'isAdminPath',
  'isEnvelopePublic',
  'isBillingWebhook',
  'isInternalBillingCancel',
];

module.exports = { PUBLIC_ROUTES, KEY_GATE_EXEMPTIONS };
