'use strict';
// Which relay identity key belongs to which relay name, on the server side.
//
// WHY THIS EXISTS. POST /v2/sth/ingest mirrors signed tree heads from other
// relays, and /v2/sth/peers publishes that mirror. Until 3.1.1 the route
// accepted any head with a valid signature under the key that came WITH the
// head, whatever relay_id it named. Measured on 2026-10-06: relay.paramant.app
// mirrored 20 "peers", 15 of them keys that called themselves
// https://health.paramant.app with trees of 1 to 35 leaves, plus
// relay.telling.test and relay.p10-test.nl from local acceptance stacks. None
// fitted the real health tree. A mirror that stores any self-declared name is
// exactly the place a split view hides, and the one monitor we have
// (scripts/paramant-verify-peers) raised a false alarm on it every run.
//
// So a relay name that is pinned here may only be used with its pinned key, a
// pinned key may only use its own name, and a peer that is not pinned at all
// never reaches the public mirror.
//
// THE SOURCE OF TRUTH is frontend/js/relay-trust-anchors.js: the same keys the
// browser uses to check a receipt. The relay image does not ship frontend/, so
// the fingerprints are repeated here, and tests/fleet-pins-match-anchors
// .test.mjs fails the moment the two disagree. A fingerprint is SHA3-256 of
// the raw ML-DSA-65 public key, the same value /v2/sth/ingest computes.
//
// A self-hosted fleet, or a local test fleet, pins its own relays with
// PEER_STH_PINS="host=fingerprint,host=fingerprint". Those come on top of the
// Paramant pins and can never replace one: a host that is already pinned keeps
// its pinned key.

const PARAMANT_FLEET = Object.freeze({
  'relay.paramant.app':   '3d9b960c107a5145dc7412b5953d52c0f5d5b89a654f2da296b1133164befd61',
  'health.paramant.app':  '8376424bc4128148103a4b604bc257efbe5d7cb3fbd826a78306c905f39e5126',
  'legal.paramant.app':   '10f3313c87cbabdc38c8fd349fb9eb1b309a525894ae81262d9e810912f5e859',
  'finance.paramant.app': '48a26c5b9ae76a760cb170313c6850679c584e57525eb15217ad152729284d03',
  'iot.paramant.app':     'ce56ff0fafeedaa160c91dc7afee038b17dfb397665a9b2c88b0d3f77acd28c6',
});

// The Paramant domain. A name under it that is not pinned is not ours to
// mirror, and a head that claims one is impersonation, not an unknown peer.
const PARAMANT_DOMAIN = /(^|\.)paramant\.app$/i;

// relay_id is RELAY_SELF_URL (https://health.paramant.app) or, without one,
// SECTOR + '.paramant.app'. Both reduce to a lowercase host; a port is kept
// only when it is not the default, so a local fleet on 127.0.0.1:3001 and
// :3002 are two names. Anything unparsable is null.
function hostOfRelayId(relayId) {
  const s = String(relayId == null ? '' : relayId).trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'https://' + s);
    return u.host.toLowerCase() || null;
  } catch {
    return null;
  }
}

function parseExtraPins(spec) {
  const out = new Map();
  for (const part of String(spec || '').split(',')) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.lastIndexOf('=');
    if (eq <= 0) continue;
    const host = hostOfRelayId(p.slice(0, eq));
    const fp = p.slice(eq + 1).trim().toLowerCase();
    if (host && /^[0-9a-f]{64}$/.test(fp)) out.set(host, fp);
  }
  return out;
}

function buildPins(extraSpec) {
  const byHost = new Map(Object.entries(PARAMANT_FLEET));
  for (const [host, fp] of parseExtraPins(extraSpec)) {
    if (!byHost.has(host)) byHost.set(host, fp);
  }
  const byKey = new Map();
  for (const [host, fp] of byHost) {
    if (!byKey.has(fp)) byKey.set(fp, new Set());
    byKey.get(fp).add(host);
  }
  return { byHost, byKey };
}

// The verdict for one head: 'pinned' (mirror it publicly), 'unpinned' (an
// unknown peer: keep it out of the public mirror) or a refusal with a reason.
function classifyPeer(pins, relayId, pkHash) {
  const host = hostOfRelayId(relayId);
  if (!host) return { verdict: 'refused', reason: 'relay_id_unparsable', host: null };
  const pinned = pins.byHost.get(host);
  if (pinned && pinned !== pkHash) return { verdict: 'refused', reason: 'relay_id_pinned_to_other_key', host };
  const ownHosts = pins.byKey.get(pkHash);
  if (ownHosts && !ownHosts.has(host)) return { verdict: 'refused', reason: 'pinned_key_other_relay_id', host };
  if (pinned) return { verdict: 'pinned', host };
  if (PARAMANT_DOMAIN.test(host.replace(/:\d+$/, ''))) return { verdict: 'refused', reason: 'unpinned_paramant_host', host };
  return { verdict: 'unpinned', host };
}

function isParamantUrl(u) {
  const h = hostOfRelayId(u);
  return !!h && PARAMANT_DOMAIN.test(h.replace(/:\d+$/, ''));
}

// May this relay send heads to, or register with, a paramant.app host?
// Only when it IS a pinned Paramant relay (its own key is the pin for its own
// RELAY_SELF_URL) and is not running as test or development, unless
// PARAMANT_FLEET_GOSSIP says 1 or 0 explicitly. See broadcastSTH in relay.js
// for how local stacks ended up gossiping to production.
function mayTalkToParamantFleet({ env = {}, selfUrl, selfPkHash, pins }) {
  if (env.PARAMANT_FLEET_GOSSIP === '1') return true;
  if (env.PARAMANT_FLEET_GOSSIP === '0') return false;
  if (/^(test|development|dev)$/i.test(env.NODE_ENV || '')) return false;
  if (!selfUrl || !selfPkHash || !pins) return false;
  const selfHost = hostOfRelayId(selfUrl);
  return isParamantFleetHost(selfHost) && pins.byHost.get(selfHost) === selfPkHash;
}

function isParamantFleetHost(host) {
  return Object.prototype.hasOwnProperty.call(PARAMANT_FLEET, String(host || '').toLowerCase());
}

module.exports = { PARAMANT_FLEET, PARAMANT_DOMAIN, hostOfRelayId, parseExtraPins, buildPins, classifyPeer, isParamantFleetHost, isParamantUrl, mayTalkToParamantFleet };
