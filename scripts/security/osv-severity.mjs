// Turn an OSV advisory into one word: none, low, moderate, high, critical, or
// unknown. posture.sh fails on high, critical and unknown.
//
// WHY THIS FILE EXISTS, and it is the whole point of it. The first version of
// the Rust gate read `database_specific.severity`. Verified live on 2026-09-03:
// RustSec advisories do not have that field. RUSTSEC-2020-0071 and
// RUSTSEC-2021-0079 both carry `database_specific: {"license": "CC0-1.0"}` and
// put their severity in `severity[]` as a CVSS_V3 vector; RUSTSEC-2026-0190 has
// neither. So every RustSec advisory read as the empty string, fell through to
// the "anything else" branch, and did not fail the gate. RUSTSEC-2021-0079
// scores 9.1 and would have passed. The gate was blind on exactly the ecosystem
// it was written for, and it reported green while blind, which is the failure
// this whole scanner exists to refuse.
//
// Two sources, and the WORSE of them wins:
//
//   * the CVSS_V3 vector, scored here by the v3.1 formula;
//   * `database_specific.severity`, the word GitHub publishes.
//
// They disagree, by design: GitHub's word is editorial and is sometimes a band
// away from the arithmetic (measured over seven GHSA advisories that carry
// both: five agreed, one was rated up, one rated down). A gate that trusts
// either one alone can be talked out of a finding, so it takes the maximum.
//
// CVSS_V4 is not scored here. Its base score is a MacroVector lookup, not a
// formula, and a wrong implementation would be worse than none. A v4-only
// advisory therefore resolves through the published word, and if there is no
// word it is `unknown`, which is red. Not knowing is a state a human has to
// resolve, never one the gate resolves for itself.

import { pathToFileURL } from 'node:url';

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
};

// CVSS v3.1 Roundup (spec section 7.1). Round-half-up on the second decimal is
// not the same function and gives 6.1 where the spec says 6.2.
function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  const p = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    if (k && v) p[k] = v;
  }
  const changed = p.S === 'C';
  const av = W.AV[p.AV];
  const ac = W.AC[p.AC];
  const ui = W.UI[p.UI];
  const pr = (changed ? W.PR_C : W.PR_U)[p.PR];
  const c = W.CIA[p.C];
  const i = W.CIA[p.I];
  const a = W.CIA[p.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * av * ac * pr * ui;
  return roundup(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
}

const ORDER = ['none', 'low', 'moderate', 'high', 'critical'];

export function bandForScore(score) {
  if (score === null || score === undefined) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'moderate';
  if (score > 0) return 'low';
  return 'none';
}

export function classify(advisory) {
  const bands = [];
  const why = [];

  const list = Array.isArray(advisory && advisory.severity) ? advisory.severity : [];
  const v3 = list.find((s) => s && s.type === 'CVSS_V3');
  if (v3) {
    const score = cvss3Score(v3.score);
    const band = bandForScore(score);
    if (band) { bands.push(band); why.push(`cvss3 ${score}`); }
    else why.push('cvss3 vector unparseable');
  }
  const v4 = list.find((s) => s && s.type === 'CVSS_V4');
  if (v4) why.push('cvss4 not scored here');

  const word = advisory && advisory.database_specific && advisory.database_specific.severity;
  if (word) {
    const w = String(word).toLowerCase();
    if (ORDER.includes(w)) { bands.push(w); why.push(`published ${w}`); }
    else why.push(`published severity not recognised: ${w}`);
  }

  if (!bands.length) {
    return { band: 'unknown', why: why.length ? why.join(', ') : 'no severity of any kind on this advisory' };
  }
  // The worse of the two. Neither an editorial downgrade nor a missing word
  // may talk the gate out of a finding.
  const band = bands.reduce((a, b) => (ORDER.indexOf(b) > ORDER.indexOf(a) ? b : a));
  return { band, why: why.join(', ') };
}

export function fails(band) {
  return band === 'high' || band === 'critical' || band === 'unknown';
}

// Read a stream of advisories (one JSON object per line) and print
// "id<TAB>band<TAB>why" for each. Order in, order out.
function main() {
  let raw = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (d) => { raw += d; });
  process.stdin.on('end', () => {
    const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
    for (const line of lines) {
      let advisory;
      try {
        advisory = JSON.parse(line);
      } catch {
        // A detail request that came back as anything but json is not a pass.
        process.stdout.write('?\tunknown\tadvisory detail was not json\n');
        continue;
      }
      const { band, why } = classify(advisory);
      process.stdout.write(`${advisory.id || '?'}\t${band}\t${why}\n`);
    }
  });
}

// Only when run as a command. Importing this file (the known-answer test does)
// must not park on a stdin that never closes.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
