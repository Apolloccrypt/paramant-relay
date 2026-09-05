'use strict';
// The field gate: nothing reaches a CT log entry, or the preimage of a leaf,
// unless it is named here.
//
// WHY THIS FILE EXISTS. The public transparency log is the one place where a
// mistake is permanent and public at the same time. An entry is written to
// CT_FILE, projected onto /v2/ct/log and /ct/feed, and committed to by a leaf
// hash that can never be recomputed differently. There is no taking a field
// back out: freezing the tree is the only remedy, and a frozen tree costs every
// receipt that ever came out of it.
//
// The three findings this gate generalises were each a different field, and
// each looked correct where it was written:
//   * the millisecond ts in /ct/feed and in the signed head - a field that was
//     fine in the stored entry and wrong the moment it was published;
//   * device_hash, a stable deterministic function of a participant key, which
//     is still on the entry and is kept OUT of the public projection by hand,
//     in a comment, at one call site;
//   * the leaf preimage itself, which commits to guessable inputs and no salt.
// None of those is a bug in the same place, so a fix in the same place cannot
// be the answer. What they share is that a value reached a leaf or a log entry
// without anyone having to say out loud that it should.
//
// So: every entry field, every declared event type, and every payload key is
// on a list here, and relay/test/ct-fields.test.js holds these lists against a
// second copy written out by hand. Adding a field turns the build red twice -
// once here, once in the test - and the only way to green is for someone to
// write down what the new field is and why the log may carry it. That is the
// whole mechanism, and it is deliberately annoying.
//
// Pure module: no relay, no I/O, no crypto. Unit-tested without a boot.

// On every entry, whatever it records. `type` is absent on the oldest family
// (key_reg), which is why the projections read `e.type || 'key_reg'`.
const COMMON_FIELDS = ['index', 'type', 'leaf_hash', 'tree_hash', 'ts', 'proof'];

// Per family, the fields that family adds. A family is what the appending code
// KNOWS it is writing, passed in explicitly: sniffing it back out of the `type`
// string would make the gate guess, and a gate that guesses is not a gate.
const EXTRA_FIELDS = {
  // ctAppend - a device enrolling its public key.
  key_reg: ['device_hash'],
  // ctAppendRelayReg - a relay announcing itself to the fleet.
  relay_reg: ['device_hash', 'relay_url', 'relay_sector', 'relay_version', 'relay_edition', 'relay_pk_hash'],
  // ctAppendTransfer - a file moving through the relay.
  transfer: ['blob_hash', 'sector'],
  // ctAppendParasign - a single-signer ParaSign signature.
  parasign: ['document_hash', 'signer_pk_hash'],
  // ctAppendSigningPkEvent - a signing key enrolled or revoked.
  signing_pk: ['user_id_hash', 'signer_pk_hash'],
  // ctAppendEnvelope - a multi-party envelope lifecycle event.
  envelope: ['envelope_id', 'payload'],
  // ctAppendEvent - a DID-keyed event. Today only the code manifest.
  did_event: ['did', 'payload'],
};

// The event-type names each family may use. These are not decoration: the name
// is concatenated into the entry's `type`, and for the signing-key family it is
// hashed into the leaf preimage by way of the value hash. An undeclared name is
// a leaf format nobody has seen.
//
// This list is also a repair. ctAppendSigningPkEvent used to accept exactly
// 'signing_pk_enrolled' and 'signing_pk_revoked' and throw on anything else,
// while two of its four call sites passed 'signing_pk_enrolled_tofu' and
// 'signing_pk_enrolled_attested'. Both threw into the route's outer catch, so
// trust-on-first-use and attested enrolment answered 500 AFTER storing the key,
// and neither ever reached the transparency log. A hand-written guard listing
// two of four names is exactly what a gate with a test behind it prevents.
const EVENT_TYPES = {
  signing_pk: [
    'signing_pk_enrolled',
    'signing_pk_enrolled_tofu',
    'signing_pk_enrolled_attested',
    'signing_pk_revoked',
  ],
  envelope: [
    'envelope_create',
    'envelope_view',
    'envelope_sign',
    'envelope_complete',
    'envelope_void',
  ],
  did_event: [
    'code_manifest_published',
  ],
};

// Keys allowed inside an entry's `payload`. The payload is not published by
// /v2/ct/log or /ct/feed, but it IS written to CT_FILE and it IS hashed into
// the leaf, so it is the easiest place on the whole entry for something to
// arrive unnoticed. Per event type, because the shapes have nothing in common.
const PAYLOAD_FIELDS = {
  envelope_create: ['doc_hash', 'party_count', 'binding_mode'],
  envelope_view: ['party_index'],
  envelope_sign: ['party_index', 'signer_pk_hash', 'appearance_hash'],
  envelope_complete: ['signed_count'],
  envelope_void: ['reason_hash', 'reason_len'],
  code_manifest_published: ['git_commit', 'file_count'],
};

const FAMILIES = Object.keys(EXTRA_FIELDS);

function allowedFields(family) {
  const extra = EXTRA_FIELDS[family];
  if (!extra) throw new Error(`ct-fields: unknown entry family "${family}"`);
  return [...COMMON_FIELDS, ...extra];
}

function allowedEventTypes(family) {
  return EVENT_TYPES[family] || null;   // null: this family has no event type
}

// Is this a name the family may use? Families without an event type accept
// none at all, which is what keeps a name from drifting into one by accident.
function isAllowedEventType(family, eventType) {
  const list = EVENT_TYPES[family];
  return Array.isArray(list) && list.includes(eventType);
}

// Gate a payload on its own, by entry type. Callers use this BEFORE hashing,
// because the leaf commits to the payload and the entry must store the same
// object the leaf committed to. An entry type with no declared payload shape
// carries no payload at all: nothing about it has been agreed.
function gatePayload(type, payload) {
  const src = (payload && typeof payload === 'object' && !Array.isArray(payload)) ? payload : {};
  const allowed = PAYLOAD_FIELDS[type];
  const out = {};
  const rejected = [];
  for (const [k, v] of Object.entries(src)) {
    if (allowed && allowed.includes(k)) out[k] = v;
    else rejected.push(k);
  }
  return { payload: out, rejected };
}

// The gate. Returns { entry, rejected } where `entry` carries only named
// fields and `rejected` names what was dropped.
//
// It STRIPS rather than throws, and that choice is the point. An undeclared
// field is by construction one no reader knows about, so removing it breaks
// nothing that exists, while letting it through writes it to disk and to a
// public endpoint permanently. Throwing would take the route down instead, and
// a transparency log that refuses to record a real event to avoid recording a
// stray field has chosen the worse of the two. The caller logs what came back
// in `rejected`, and relay/test/ct-fields.test.js is what turns the build red
// before any of this has to happen in production.
function gateEntry(family, entry) {
  const allowed = new Set(allowedFields(family));
  const out = {};
  const rejected = [];
  for (const [k, v] of Object.entries(entry)) {
    if (allowed.has(k)) out[k] = v;
    else rejected.push(k);
  }
  if (out.payload !== undefined) {
    const p = gatePayload(entry.type, out.payload);
    out.payload = p.payload;
    for (const k of p.rejected) rejected.push(`payload.${k}`);
  }
  return { entry: out, rejected };
}

module.exports = {
  COMMON_FIELDS, EXTRA_FIELDS, EVENT_TYPES, PAYLOAD_FIELDS, FAMILIES,
  allowedFields, allowedEventTypes, isAllowedEventType, gateEntry, gatePayload,
};
