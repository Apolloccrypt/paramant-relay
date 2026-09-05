'use strict';
// The field gate, held against a second copy of itself and against the code
// that feeds it.
//
// WHY THIS SUITE EXISTS. relay/lib/ct-fields.js is a list, and a list that only
// one file reads is a comment with syntax. What makes it a gate is this suite,
// and it works in two directions at once:
//
//   OUTWARD  the declared lists are compared to a copy written out by hand
//            below. Adding a field to ct-fields.js turns this red until someone
//            writes it here too, next to a sentence saying what it is. That is
//            the "somebody thought about it" step, and it is meant to cost a
//            minute of attention rather than be a formality.
//   INWARD   every event-type literal the relay really passes is scanned out of
//            relay.js and envelope.js and held against the declaration. This is
//            the half that makes it safe for ctRequireEventType to THROW: a
//            name the code uses can never be missing from the list without this
//            going red first.
//
// The inward half is not hypothetical. Two of the four call sites of
// ctAppendSigningPkEvent passed 'signing_pk_enrolled_tofu' and
// 'signing_pk_enrolled_attested' to a guard that named only two other strings,
// so both threw, both routes answered 500 after storing the key, and neither
// enrolment ever reached the transparency log. And ctAppendEnvelope prefixed
// 'envelope_' onto names that already carried it, publishing
// 'envelope_envelope_sign' while scripts/heartbeat/parasign.mjs searched the
// public log for 'envelope_sign'. Two guards that could not fire, both found by
// writing the list down and then checking it against the callers.
// Run: node --test relay/test/ct-fields.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const ctFields = require('../lib/ct-fields');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };

after(() => summary('ct-fields', checks));

// ── The hand-written copy ────────────────────────────────────────────────────
// Deliberately not imported, not generated, not derived. If this drifts from
// ct-fields.js the build goes red, and the way to green is to read both.

// On every entry regardless of what it records.
const COMMON = ['index', 'type', 'leaf_hash', 'tree_hash', 'ts', 'proof'];

const EXTRA = {
  // A device enrolling its public key. device_hash is sha3(device_id +
  // apiKey[0:8]): stable, deterministic and per-customer, which is exactly why
  // /v2/ct/log omits it from the public projection by hand.
  key_reg: ['device_hash'],
  // A relay announcing itself to the fleet. All of this is about the relay, a
  // published server, and none of it about a customer.
  relay_reg: ['device_hash', 'relay_url', 'relay_sector', 'relay_version', 'relay_edition', 'relay_pk_hash'],
  // A file moving through. blob_hash is the sha256 the sender supplied; it is
  // the input that makes the unsalted leaf confirmable by anyone holding the
  // file, and it is the reason a salted second tree is the next piece of work.
  transfer: ['blob_hash', 'sector'],
  // A single-signer ParaSign signature: which key signed which document hash.
  parasign: ['document_hash', 'signer_pk_hash'],
  // A signing key enrolled or revoked, against a hashed user id.
  signing_pk: ['user_id_hash', 'signer_pk_hash'],
  // A multi-party envelope lifecycle event. The payload shape is per type.
  envelope: ['envelope_id', 'payload'],
  // A DID-keyed event. Today only the code-transparency manifest uses it.
  did_event: ['did', 'payload'],
};

const EVENTS = {
  signing_pk: ['signing_pk_enrolled', 'signing_pk_enrolled_tofu', 'signing_pk_enrolled_attested', 'signing_pk_revoked'],
  envelope: ['envelope_create', 'envelope_view', 'envelope_sign', 'envelope_complete', 'envelope_void'],
  did_event: ['code_manifest_published'],
};

const PAYLOADS = {
  // The document hash, how many parties, and which binding mode. No names, no
  // addresses, no document.
  envelope_create: ['doc_hash', 'party_count', 'binding_mode'],
  // Which slot opened it. A number, not a person.
  envelope_view: ['party_index'],
  // Which slot signed, with which key, over which rendered appearance.
  envelope_sign: ['party_index', 'signer_pk_hash', 'appearance_hash'],
  envelope_complete: ['signed_count'],
  // The reason is hashed and its length recorded; the text itself never enters
  // the log, which is what keeps a free-text field out of a permanent record.
  envelope_void: ['reason_hash', 'reason_len'],
  code_manifest_published: ['git_commit', 'file_count'],
};

const sorted = (a) => [...a].sort();

test('the declared entry fields are the ones written down here, family by family', () => {
  assert.deepStrictEqual(sorted(ctFields.COMMON_FIELDS), sorted(COMMON),
    'COMMON_FIELDS changed. A field that goes on EVERY entry is the widest change '
    + 'possible to the log; say what it is here before it ships.');
  assert.deepStrictEqual(sorted(ctFields.FAMILIES), sorted(Object.keys(EXTRA)),
    'a whole entry family was added or removed');
  for (const family of Object.keys(EXTRA)) {
    assert.deepStrictEqual(sorted(ctFields.EXTRA_FIELDS[family]), sorted(EXTRA[family]),
      `the fields of the ${family} entry changed`);
    assert.deepStrictEqual(sorted(ctFields.allowedFields(family)), sorted([...COMMON, ...EXTRA[family]]),
      `allowedFields(${family}) is not COMMON plus the family's own`);
  }
  did();
});

test('the declared event types and payload keys are the ones written down here', () => {
  assert.deepStrictEqual(sorted(Object.keys(ctFields.EVENT_TYPES)), sorted(Object.keys(EVENTS)));
  for (const family of Object.keys(EVENTS)) {
    assert.deepStrictEqual(sorted(ctFields.EVENT_TYPES[family]), sorted(EVENTS[family]),
      `the event types of the ${family} family changed`);
  }
  assert.deepStrictEqual(sorted(Object.keys(ctFields.PAYLOAD_FIELDS)), sorted(Object.keys(PAYLOADS)));
  for (const type of Object.keys(PAYLOADS)) {
    assert.deepStrictEqual(sorted(ctFields.PAYLOAD_FIELDS[type]), sorted(PAYLOADS[type]),
      `the payload of ${type} changed`);
  }
  did();
});

test('every event type the relay really passes is declared', () => {
  // The inward half. Read the call sites, not the list, and hold what the code
  // does against what it says it does.
  const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
  const relay = read('relay.js');
  const envelope = read('envelope.js');

  const literals = (src, fn) => {
    const found = new Set();
    const re = new RegExp(`${fn}\\(\\s*["']([^"']+)["']`, 'g');
    let m;
    while ((m = re.exec(src)) !== null) found.add(m[1]);
    return found;
  };

  const signingPk = literals(relay, 'ctAppendSigningPkEvent');
  assert.ok(signingPk.size >= 4, `expected at least four signing-key call sites, read ${signingPk.size}. `
    + 'A scan that finds nothing passes over everything, which is the failure this test exists to prevent.');
  for (const t of signingPk) {
    assert.ok(ctFields.isAllowedEventType('signing_pk', t),
      `relay.js passes signing-key event type "${t}", which ctRequireEventType would throw on. `
      + 'This is the exact break that made trust-on-first-use enrolment answer 500.');
  }

  // envelope.js calls through the injected `this.ctAppend`; relay.js wires it
  // to ctAppendEnvelope. Both spellings are scanned so neither file can add a
  // name the other does not know about.
  const envTypes = new Set([...literals(envelope, 'this\\.ctAppend'), ...literals(relay, 'ctAppendEnvelope')]);
  assert.ok(envTypes.size >= 5, `expected at least five envelope call sites, read ${envTypes.size}`);
  for (const t of envTypes) {
    assert.ok(ctFields.isAllowedEventType('envelope', t),
      `envelope.js fires "${t}", which is not declared. Note the names already start with `
      + '"envelope_": ctAppendEnvelope must not add that prefix a second time.');
  }

  const didTypes = literals(relay, 'ctAppendEvent');
  assert.ok(didTypes.size >= 1, 'expected at least one ctAppendEvent call site');
  for (const t of didTypes) {
    assert.ok(ctFields.isAllowedEventType('did_event', t), `relay.js passes DID event type "${t}", not declared`);
  }
  did();
});

test('a name the heartbeat searches for is a name the log really publishes', () => {
  // scripts/heartbeat/parasign.mjs filters the PUBLIC projection for a type
  // string. That filter is the strongest evidence the ParaSign heartbeat
  // collects, and it silently matched nothing for as long as the entry type was
  // written 'envelope_' + 'envelope_sign'. A guard that cannot fire reports
  // green, and green is what people act on.
  const hb = fs.readFileSync(path.join(__dirname, '..', '..', 'scripts', 'heartbeat', 'parasign.mjs'), 'utf8');
  const wanted = [...hb.matchAll(/e\.type === ['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.ok(wanted.length >= 1, 'the heartbeat still filters the CT log by entry type');
  const declared = new Set(Object.values(ctFields.EVENT_TYPES).flat());
  for (const t of wanted) {
    assert.ok(declared.has(t), `the heartbeat looks for CT entries of type "${t}" and nothing publishes that`);
  }
  did();
});

test('every append function really passes its entry through the gate', () => {
  // A gate nothing calls is a list. There are seven append functions and each
  // builds its own entry literal, so "it is gated" has to be checked per
  // function rather than assumed from the module being imported.
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  const names = [...src.matchAll(/^function (ctAppend\w*)\(/gm)].map((m) => m[1]);
  assert.ok(names.length >= 7, `expected at least seven ctAppend* functions, read ${names.length}`);
  for (const name of names) {
    const start = src.indexOf(`function ${name}(`);
    // Up to the next top-level function, which is where this one ends.
    const rest = src.slice(start + 1);
    const nextIdx = rest.search(/^function \w+\(/m);
    const body = nextIdx === -1 ? rest : rest.slice(0, nextIdx);
    assert.match(body, /ctGateEntry\(/,
      `${name} builds a CT entry without passing it through ctGateEntry. Every field that `
      + 'reaches the log has to be declared, and a function that skips the gate is how one '
      + 'gets in without anyone naming it.');
  }
  did();
});

test('an undeclared field is dropped, and named in what comes back', () => {
  const { entry, rejected } = ctFields.gateEntry('transfer', {
    index: 7, type: 'transfer', leaf_hash: 'a'.repeat(64), tree_hash: 'b'.repeat(64),
    blob_hash: 'c'.repeat(64), sector: 'health', ts: '2026-09-05T19:00:00.000Z', proof: [],
    sender_email: 'someone@example.test',    // the shape of the mistake
    device_hash: 'd'.repeat(64),             // real elsewhere, undeclared here
  });
  assert.deepStrictEqual(sorted(rejected), ['device_hash', 'sender_email']);
  assert.ok(!('sender_email' in entry) && !('device_hash' in entry), 'neither reached the entry');
  assert.deepStrictEqual(sorted(Object.keys(entry)),
    sorted(['index', 'type', 'leaf_hash', 'tree_hash', 'blob_hash', 'sector', 'ts', 'proof']),
    'and everything declared came through untouched');
  did();
});

test('a declared field is not dropped, in any family', () => {
  // The other side of the previous test. A gate that drops everything also
  // passes a test that only checks that something was dropped.
  for (const family of ctFields.FAMILIES) {
    const full = {};
    for (const k of ctFields.allowedFields(family)) full[k] = (k === 'payload') ? {} : `value-of-${k}`;
    if (family === 'envelope') full.type = 'envelope_view';
    if (family === 'did_event') full.type = 'code_manifest_published';
    const { entry, rejected } = ctFields.gateEntry(family, full);
    assert.deepStrictEqual(rejected, [], `${family}: the gate rejected one of its own declared fields`);
    assert.deepStrictEqual(sorted(Object.keys(entry)), sorted(Object.keys(full)), `${family}: a field went missing`);
  }
  did();
});

test('a payload key nobody declared does not reach the leaf', () => {
  const ok = ctFields.gatePayload('envelope_sign', { party_index: 1, signer_pk_hash: 'e'.repeat(64) });
  assert.deepStrictEqual(ok.rejected, []);
  assert.deepStrictEqual(ok.payload, { party_index: 1, signer_pk_hash: 'e'.repeat(64) });

  const bad = ctFields.gatePayload('envelope_void', { reason_len: 12, reason: 'the customer changed his mind' });
  assert.deepStrictEqual(bad.rejected, ['reason'],
    'the void reason is recorded as a hash and a length on purpose; the text itself '
    + 'must never enter a permanent public record');
  assert.deepStrictEqual(bad.payload, { reason_len: 12 });

  // An entry type with no declared payload shape carries no payload at all.
  const unknown = ctFields.gatePayload('envelope_something_new', { anything: 1 });
  assert.deepStrictEqual(unknown.rejected, ['anything']);
  assert.deepStrictEqual(unknown.payload, {});
  did();
});

test('an unknown family is an error, not a quiet pass-through', () => {
  assert.throws(() => ctFields.allowedFields('made_up'), /unknown entry family/);
  assert.throws(() => ctFields.gateEntry('made_up', { index: 0 }), /unknown entry family/);
  assert.strictEqual(ctFields.isAllowedEventType('made_up', 'anything'), false);
  assert.strictEqual(ctFields.isAllowedEventType('transfer', 'transfer'), false,
    'a family with no event types accepts none, so a name cannot drift into one');
  did();
});
