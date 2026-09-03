// The severity classifier behind the Rust gate in scripts/security/posture.sh.
//
// WHY. The first version of that gate read `database_specific.severity`, which
// RustSec advisories do not have. Every one of them classified as unrated and
// none of them failed the gate. The shapes below are the REAL responses from
// api.osv.dev on 2026-09-03, kept verbatim, so the thing this suite pins is the
// data as it actually arrives and not as anyone remembered it.
//
// Node builtins only, so it runs in the "Root integration suites" job.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cvss3Score, bandForScore, classify, fails } from '../scripts/security/osv-severity.mjs';

// Verbatim from https://api.osv.dev/v1/vulns/<id>, fields trimmed to what the
// classifier reads.
const RUSTSEC_V3_CRITICAL = {
  id: 'RUSTSEC-2021-0079',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H' }],
  database_specific: { license: 'CC0-1.0' },
};
const RUSTSEC_V3_MODERATE = {
  id: 'RUSTSEC-2020-0071',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
  database_specific: { license: 'CC0-1.0' },
};
const RUSTSEC_NO_SEVERITY = {
  id: 'RUSTSEC-2026-0190',
  severity: null,
  database_specific: { license: 'CC0-1.0' },
};
const GHSA_V4_WITH_WORD = {
  id: 'GHSA-3rjw-m598-pq24',
  severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P' }],
  database_specific: { severity: 'MODERATE' },
};

test('the CVSS v3.1 base score matches the specification', () => {
  // Roundup, not round-half-up: the second and third cases land on a boundary
  // where the two functions differ by a tenth.
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H'), 9.1);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 6.2);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N'), 7.2);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), 1.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('a vector that is not a vector scores nothing, and nothing is not zero', () => {
  assert.equal(cvss3Score('not a vector'), null);
  assert.equal(cvss3Score('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), null);
  assert.equal(bandForScore(null), null);
});

test('a RustSec advisory is classified from severity[], which is all it has', () => {
  // The regression this file exists for. database_specific holds a licence and
  // nothing else, so a classifier that reads it sees no severity at all.
  assert.equal(RUSTSEC_V3_CRITICAL.database_specific.severity, undefined);
  assert.equal(classify(RUSTSEC_V3_CRITICAL).band, 'critical');
  assert.equal(classify(RUSTSEC_V3_MODERATE).band, 'moderate');
});

test('a 9.1 RustSec advisory fails the gate', () => {
  assert.equal(fails(classify(RUSTSEC_V3_CRITICAL).band), true,
    'this is the advisory the old gate let through');
  assert.equal(fails(classify(RUSTSEC_V3_MODERATE).band), false);
});

test('no severity of any kind is unknown, and unknown is red', () => {
  assert.equal(classify(RUSTSEC_NO_SEVERITY).band, 'unknown');
  assert.equal(fails('unknown'), true,
    'not knowing how bad something is must be a human decision, not a pass');
  assert.equal(classify({ id: 'x' }).band, 'unknown');
  assert.equal(classify({}).band, 'unknown');
});

test('a CVSS_V4 advisory resolves through the published word', () => {
  // v4 is a lookup table, not a formula, so it is deliberately not scored here.
  assert.equal(classify(GHSA_V4_WITH_WORD).band, 'moderate');
  // Take the word away and the gate must not shrug.
  const bare = { id: 'x', severity: GHSA_V4_WITH_WORD.severity, database_specific: {} };
  assert.equal(classify(bare).band, 'unknown');
});

test('when the vector and the published word disagree, the worse one wins', () => {
  // Measured over seven GHSA advisories carrying both: five agreed, one was
  // rated up by GitHub and one rated down. Either direction must not lower the
  // verdict.
  const ratedDown = {
    id: 'rated-down',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H' }],
    database_specific: { severity: 'MODERATE' },
  };
  assert.equal(classify(ratedDown).band, 'critical');
  assert.equal(fails(classify(ratedDown).band), true);

  const ratedUp = {
    id: 'rated-up',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' }],
    database_specific: { severity: 'HIGH' },
  };
  assert.equal(classify(ratedUp).band, 'high');
  assert.equal(fails(classify(ratedUp).band), true);
});
