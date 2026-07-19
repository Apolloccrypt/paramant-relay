'use strict';
// Per-tier feature gate. Single decision point for the billing-hardening features
// so an endpoint never hand-rolls a plan-string comparison: it reads the product
// entitlement from lib/entitlements.js (the source of truth) and asks a named
// predicate. Pure: no I/O, no globals. Unit-tested in test/tier-gate.test.js.
//
// `keyData` is any account/key record carrying plan info (plan / plan_parasend /
// plan_parasign / parasign). getEntitlements tolerates every shape and clamps an
// unknown tier to the product floor, so a malformed record never over-grants.
const entitlements = require('./entitlements');

// Product tier ladders (from entitlements.js):
//   parasend: community | pro | enterprise
//   parasign: free | pro | business | enterprise
function parasendTier(keyData) { return entitlements.getEntitlements(keyData || {}).parasend.tier; }
function parasignTier(keyData) { return entitlements.getEntitlements(keyData || {}).parasign.tier; }

// "Pro+" on ParaSend: pro or enterprise (community is the free floor -> denied).
function isParasendProPlus(keyData) {
  const t = parasendTier(keyData);
  return t === 'pro' || t === 'enterprise';
}

// "Pro+" on ParaSign: pro, business or enterprise (free is the floor -> denied).
function isParasignProPlus(keyData) {
  const t = parasignTier(keyData);
  return t === 'pro' || t === 'business' || t === 'enterprise';
}

// History (send history + link management) is a Pro capability on EITHER product,
// so an account that is Pro on one product but free on the other still sees its
// own activity. Free/community on both -> denied.
function isHistoryAllowed(keyData) {
  return isParasendProPlus(keyData) || isParasignProPlus(keyData);
}

// ParaSign signing-audit export: Business+ (drawn straight from the live
// entitlement feature flag so the flag and the gate can never drift).
function isAuditExportAllowed(keyData) {
  return !!entitlements.getEntitlements(keyData || {}).parasign.features.audit_export;
}

module.exports = {
  parasendTier,
  parasignTier,
  isParasendProPlus,
  isParasignProPlus,
  isHistoryAllowed,
  isAuditExportAllowed,
};
