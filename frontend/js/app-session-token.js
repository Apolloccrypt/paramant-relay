/* The credential the signed-in app pages run on.
 *
 * WHAT THIS REPLACES. /pricing and /dashboard used to call
 * GET /api/user/account/key, take the account's pgp_ key into a variable and
 * authenticate to the relay with it. That key has no expiry and no scope: once
 * it was in the tab, anything that got to run on the page could read it and
 * keep it, and it stayed a full data-plane credential afterwards. #401 fixed
 * exactly that for /parashare; this file is the same trade for the other two
 * pages, so the key stops reaching the browser on the normal path at all.
 *
 * WHAT IT HANDS OUT. POST /api/user/app/token mints a pst_ session token with
 * purpose `app`: fifteen minutes, and the relay accepts it on five routes
 * (POST /v2/billing/checkout, POST /v2/billing/redeem,
 * GET /v2/user/history, GET /v2/parasign/audit-export,
 * GET /v2/parasign/inbox) and refuses it on everything else. It is a DIFFERENT token from the one /parashare holds, not a
 * wider one: neither allowlist contains the other, so giving these pages a
 * credential did not give the send page anything extra. See
 * relay/lib/session-token.js for the lists.
 *
 * WHAT IT DOES NOT DO.
 *   * it never persists. No localStorage, no sessionStorage, no cookie: the
 *     token lives in this closure and dies with the tab. A credential written
 *     to storage outlives the reason it was minted, which is the bug #401 also
 *     closed on /parashare;
 *   * it never falls back to the api-key. If the mint fails, the caller gets an
 *     error and shows it. A fallback would put the key back in the browser on
 *     exactly the days something is already wrong;
 *   * it does not renew on a timer. Nothing here polls, so a tab left open on
 *     /pricing holds an expired string and nothing else. The next call mints.
 *
 * REFRESH. Two ways, both driven by use rather than by the clock: a token
 * inside its last thirty seconds is treated as spent (a request started at
 * 14:59 must not arrive at 15:01), and a 401 from the relay makes the caller
 * ask again with force = true. One retry, never a loop: a second 401 is a real
 * refusal, and retrying it would turn a signed-out tab into a mint loop.
 *
 * CSP-safe: external file, no inline script. Classic script, no module, because
 * both callers are classic scripts.
 */
(function () {
  'use strict';

  var TOKEN_URL = '/api/user/app/token';
  /* The margin, in ms. A request that leaves with 30 s of life on the token
   * arrives with less; the relay judges on arrival. */
  var SPEND_MARGIN_MS = 30000;

  var cached = null;      /* { token: string, expires_at: number } */
  var inflight = null;    /* the promise of a mint already on the wire */

  function fresh(entry) {
    return !!entry && typeof entry.token === 'string' &&
      entry.expires_at - Date.now() > SPEND_MARGIN_MS;
  }

  function mint() {
    if (inflight) return inflight;
    inflight = fetch(TOKEN_URL, {
      method: 'POST',
      credentials: 'include',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    }).then(function (r) {
      if (!r.ok) throw new Error('token_http_' + r.status);
      return r.json();
    }).then(function (j) {
      if (!j || !j.token) throw new Error('token_unavailable');
      /* expires_in_s is the relay's own TTL, passed through by the admin. A
       * response without it is not trusted to a longer life than the shortest
       * one the relay can hand out. */
      var ttl = Number(j.expires_in_s);
      if (!isFinite(ttl) || ttl <= 0) ttl = 60;
      cached = { token: j.token, expires_at: Date.now() + ttl * 1000 };
      return cached.token;
    }).catch(function (err) {
      cached = null;
      throw err;
    }).then(function (t) {
      inflight = null;
      return t;
    }, function (err) {
      inflight = null;
      throw err;
    });
    return inflight;
  }

  /* The token to put in an Authorization header, minting one when the one in
   * hand is spent. force = true throws the current one away first, which is
   * what a caller does after a 401. */
  function get(force) {
    if (force) cached = null;
    if (fresh(cached)) return Promise.resolve(cached.token);
    return mint();
  }

  /* Run `send(token)` with a token, and once more with a fresh one if the relay
   * answers 401. `send` must resolve to a Response. Every caller wants this
   * shape, and writing the retry once is the only way both pages retry the
   * same. */
  function withToken(send) {
    return get(false).then(send).then(function (r) {
      if (r && r.status === 401) return get(true).then(send);
      return r;
    });
  }

  window.paAppToken = { get: get, withToken: withToken };
})();
