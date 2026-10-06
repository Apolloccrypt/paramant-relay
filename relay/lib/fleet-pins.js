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

// Retired keys: a relay that rotated its identity key keeps its OLD key here,
// in the same commit that pins the new one (RUNBOOK.md, "Relay identity key
// rotation"). Same entries as RETIRED_RELAY_ANCHORS in
// frontend/js/relay-trust-anchors.js, held equal by
// tests/fleet-pins-match-anchors.test.mjs. What a retired pin does:
//   - the heads that key already sent stay in the public mirror, so the
//     evidence of the old tree is not moved to purged/ at the next start;
//   - a NEW head signed with it is refused (403, reason retired_key): a key
//     that was rotated out may be a key someone else now holds.
// Empty today: no relay has rotated since the pins were taken on 2026-09-05.
const RETIRED_PARAMANT_FLEET = Object.freeze([
  // { host: 'health.paramant.app', fingerprint: '<64 hex>', retired_at: 'JJJJ-MM-DD' },
]);

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

// PEER_STH_RETIRED_PINS="host=fingerprint,..." does for a self-hosted fleet
// what RETIRED_PARAMANT_FLEET does for ours. One host may have several.
function parseRetiredPins(spec) {
  const out = [];
  for (const part of String(spec || '').split(',')) {
    const p = part.trim();
    const eq = p.lastIndexOf('=');
    if (eq <= 0) continue;
    const host = hostOfRelayId(p.slice(0, eq));
    const fp = p.slice(eq + 1).trim().toLowerCase();
    if (host && /^[0-9a-f]{64}$/.test(fp)) out.push({ host, fingerprint: fp, retired_at: null });
  }
  return out;
}

function buildPins(extraSpec, retiredList = RETIRED_PARAMANT_FLEET) {
  const byHost = new Map(Object.entries(PARAMANT_FLEET));
  for (const [host, fp] of parseExtraPins(extraSpec)) {
    if (!byHost.has(host)) byHost.set(host, fp);
  }
  const byKey = new Map();
  for (const [host, fp] of byHost) {
    if (!byKey.has(fp)) byKey.set(fp, new Set());
    byKey.get(fp).add(host);
  }
  // fingerprint -> { hosts, retired_at }. A key that is pinned as current is
  // never also retired (the test on the anchor file enforces that too).
  const retired = new Map();
  for (const r of retiredList || []) {
    const host = hostOfRelayId(r && r.host);
    const fp = String((r && r.fingerprint) || '').toLowerCase();
    if (!host || !/^[0-9a-f]{64}$/.test(fp) || byKey.has(fp)) continue;
    if (!retired.has(fp)) retired.set(fp, { hosts: new Set(), retired_at: r.retired_at || null });
    retired.get(fp).hosts.add(host);
  }
  return { byHost, byKey, retired };
}

// The verdict for one head: 'pinned' (mirror it publicly), 'unpinned' (an
// unknown peer: keep it out of the public mirror) or a refusal with a reason.
function classifyPeer(pins, relayId, pkHash) {
  const host = hostOfRelayId(relayId);
  if (!host) return { verdict: 'refused', reason: 'relay_id_unparsable', host: null };
  // health.paramant.app. (or %2e, or an ideographic full stop) is the same
  // name in DNS but not the same string as the pin, so it used to slip past as
  // an unknown peer. A name never needs the dot: refuse it outright.
  if (/\.$/.test(host.replace(/:\d+$/, ''))) return { verdict: 'refused', reason: 'relay_id_trailing_dot', host };
  const old = pins.retired && pins.retired.get(pkHash);
  if (old && old.hosts.has(host)) return { verdict: 'retired', host, retired_at: old.retired_at };
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

// Why this relay does or does not talk to the fleet, for /health and the log.
function fleetGossipState({ env = {}, selfUrl, selfPkHash, pins }) {
  if (mayTalkToParamantFleet({ env, selfUrl, selfPkHash, pins })) return { on: true, reason: 'pinned' };
  if (env.PARAMANT_FLEET_GOSSIP === '0') return { on: false, reason: 'PARAMANT_FLEET_GOSSIP=0' };
  if (/^(test|development|dev)$/i.test(env.NODE_ENV || '')) return { on: false, reason: `NODE_ENV=${env.NODE_ENV}` };
  const selfHost = hostOfRelayId(selfUrl);
  if (!isParamantFleetHost(selfHost)) return { on: false, reason: 'not_a_paramant_host' };
  const old = pins && pins.retired && pins.retired.get(selfPkHash);
  if (old && old.hosts.has(selfHost)) return { on: false, reason: 'own_key_retired' };
  return { on: false, reason: 'own_key_not_pinned' };
}

module.exports = { PARAMANT_FLEET, RETIRED_PARAMANT_FLEET, parseRetiredPins, PARAMANT_DOMAIN, fleetGossipState, hostOfRelayId, parseExtraPins, buildPins, classifyPeer, isParamantFleetHost, isParamantUrl, mayTalkToParamantFleet };
