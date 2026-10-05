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
// never sent to us, gone at sign-out and when another account signs in here
// (js/nav-auth.js), and gone when the signing period ends, at most after eight
// days. The half opens nothing without the other half, which the relay gives
// only to the signed-in invited address.

export const SHARE_PREFIX = 'paramant.cosign.share.v1:';
export const SHARE_MAX_MS = 8 * 864e5;

function shareKey(envId, partyIndex) { return 'paramant.cosign.share.v1:' + String(envId) + ':' + String(Number(partyIndex) || 0); }

// value: the 'v1.<43 chars>' text after '#ks='.
export function rememberShare(envId, partyIndex, value, signUntil, now = Date.now()) {
  if (!envId || !/^v1\.[A-Za-z0-9_-]{43}$/.test(String(value || ''))) return false;
  const until = Date.parse(signUntil || '');
  const cap = now + SHARE_MAX_MS;
  const exp = Number.isFinite(until) ? Math.min(until, cap) : cap;
  if (!(exp > now)) return false;
  try { localStorage.setItem(shareKey(envId, partyIndex), JSON.stringify({ s: value, exp })); return true; } catch { return false; }
}

export function recallShare(envId, partyIndex, now = Date.now()) {
  if (!envId) return null;
  try {
    const rec = JSON.parse(localStorage.getItem(shareKey(envId, partyIndex)) || 'null');
    if (!rec || !(now < Number(rec.exp)) || !/^v1\.[A-Za-z0-9_-]{43}$/.test(String(rec.s || ''))) {
      localStorage.removeItem(shareKey(envId, partyIndex));
      return null;
    }
    return rec.s;
  } catch {
    try { localStorage.removeItem(shareKey(envId, partyIndex)); } catch { /* storage off */ }
    return null;
  }
}
