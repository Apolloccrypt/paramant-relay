// The signer's half of the document key, remembered in THIS browser.
//
// An invitation link carries one half of the document key in its fragment
// (#ks=). A link sent again from the dashboard ("Stuur mij de link opnieuw")
// cannot: the server never had that half to put in. So the resent link opened
// the request and not the document (eindmatrix COSIGN-46-A). When a signer
// opens the full invitation, this browser keeps that half, and a later link
// for the same request and the same party opens the document here too.
//
// The same rules as the sender's own signer links (paramant.cosign.links.v1):
// never sent to us, sealed under the account key (js/account-seal.js, review
// #573 M4), gone at sign-out and when another account signs in here
// (js/nav-auth.js), gone once this party has signed, and gone when the
// signing period ends, at most after eight days, checked on every page load.
// The half opens nothing without the other half, which the relay gives only
// to the signed-in invited address.

import { sealPut, sealGet, sealDel, SEAL_MAX_MS } from './account-seal.js?v=1';

export const SHARE_PREFIX = 'paramant.cosign.share.v1:';
export const SHARE_MAX_MS = SEAL_MAX_MS;

function shareKey(envId, partyIndex) { return 'paramant.cosign.share.v1:' + String(envId) + ':' + String(Number(partyIndex) || 0); }

// value: the 'v1.<43 chars>' text after '#ks='. Resolves true when it was
// kept, false without an account key (nothing is kept readable).
export async function rememberShare(envId, partyIndex, value, signUntil, now = Date.now(), opts = {}) {
  if (!envId || !/^v1\.[A-Za-z0-9_-]{43}$/.test(String(value || ''))) return false;
  const until = Date.parse(signUntil || '');
  const cap = now + SHARE_MAX_MS;
  const exp = Number.isFinite(until) ? Math.min(until, cap) : cap;
  if (!(exp > now)) return false;
  return sealPut(shareKey(envId, partyIndex), { s: value }, exp, { now, ...opts });
}

export async function recallShare(envId, partyIndex, now = Date.now(), opts = {}) {
  if (!envId) return null;
  const rec = await sealGet(shareKey(envId, partyIndex), { now, ...opts });
  if (!rec || !/^v1\.[A-Za-z0-9_-]{43}$/.test(String(rec.s || ''))) {
    if (rec) sealDel(shareKey(envId, partyIndex));
    return null;
  }
  return rec.s;
}

// Gone once this party has signed: the half has no use left.
export function forgetShare(envId, partyIndex) { if (envId) sealDel(shareKey(envId, partyIndex)); }
