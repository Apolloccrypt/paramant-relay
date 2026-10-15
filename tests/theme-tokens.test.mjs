// One token source, and a drift counter that can only go down.
//
// Why this file exists. Until the theme round of October 2026 the site had two
// light token sets (design-system.css and app-2026.css, with a different ink,
// a different hairline, a different focus ring and a different motion scale),
// a dead third one (_design.css), a private palette on /ophalen that ignored
// the switch, fifteen raw radius values, about twenty black shadows that
// vanished on the dark ground and six monospace stacks. Every one of those was
// written by hand in a page, because nothing said it should not be.
//
// What it checks.
//   1. Symmetry. Every colour role design-system.css defines for the light
//      edition is defined for the dark edition too, and the other way round.
//      A role that exists in one edition only falls back to the light value in
//      the dark, which is how a white card ends up on a dark page.
//   2. The deprecated alias block holds aliases only: every old name points at
//      a role with var(), so an old name can never carry a colour of its own.
//   3. Drift. Outside the token blocks every page, stylesheet and script is
//      counted for raw colours (#hex, rgb(), rgba() that is not rgba(var(..))),
//      border-radius in raw px, box-shadow that is not a token, and
//      font-family stacks written out instead of var(--sans)/var(--mono). The
//      counts per file live in tests/theme-tokens.baseline.json. A count may
//      go down and never up, and a new file starts at zero. When you lower a
//      count, lower the baseline with it:
//
//        THEME_TOKENS_WRITE=1 node tests/theme-tokens.test.mjs
//
//      Writing only ever lowers numbers: a file that grew keeps its old count
//      and the test stays red until the raw value is a token.
//
// Run: node --test tests/theme-tokens.test.mjs
//      THEME_TOKENS_REPORT=1 node tests/theme-tokens.test.mjs   (totals)
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', 'frontend');
const BASELINE = path.join(HERE, 'theme-tokens.baseline.json');
const DS = path.join(ROOT, 'design-system.css');

// Third-party and generated files are not ours to tokenise.
const SKIP = [/\.min\.js$/, /(^|\/)vendor\//, /(^|\/)lib\/pdf/, /(^|\/)node_modules\//];

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(html|css|js)$/.test(e.name)) out.push(p);
  }
  return out;
}

// The token blocks are the one place a raw value may live.
function stripTokens(src) {
  return src.replace(/\/\* @tokens:start \*\/[\s\S]*?\/\* @tokens:end \*\//g, '');
}

// In a page only the style is style: <style> blocks and style="" attributes.
// The rest of an HTML file is words and links, and an id like #fade is not a
// colour.
function styleOf(file, src) {
  if (file.endsWith('.css')) return stripTokens(src);
  if (file.endsWith('.js')) return src;
  const parts = [];
  for (const m of src.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)) parts.push(m[1]);
  for (const m of src.matchAll(/\sstyle="([^"]*)"/gi)) parts.push(m[1]);
  for (const m of src.matchAll(/\s(?:fill|stroke|stop-color)="(#[0-9a-fA-F]{3,8})"/g)) parts.push(m[1]);
  return parts.join('\n');
}

const TOKEN_ONLY = /^\s*(?:none|inherit|initial|unset|0|var\(--[\w-]+\)(?:\s*,\s*var\(--[\w-]+\))*)\s*(?:!important)?\s*$/;

export function count(file, src) {
  const s = styleOf(file, src).replace(/\/\*[\s\S]*?\*\//g, '');
  const colour = (s.match(/#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{1}|[0-9a-fA-F]{3}|[0-9a-fA-F]{5})?\b/g) || []).length
    + (s.match(/\brgba?\((?!\s*var\()/g) || []).length;
  let radius = 0;
  for (const m of s.matchAll(/border(?:-(?:top|bottom)-(?:left|right))?-radius\s*:\s*([^;}"\n]+)/g)) {
    if (/\b(?!0px)\d*\.?\d+px\b/.test(m[1]) && !/var\(/.test(m[1])) radius++;
  }
  let shadow = 0;
  for (const m of s.matchAll(/box-shadow\s*:\s*([^;}"\n]+)/g)) if (!TOKEN_ONLY.test(m[1])) shadow++;
  let font = 0;
  for (const m of s.matchAll(/font-family\s*:\s*([^;}"\n]+)/g)) {
    if (!/^\s*(?:var\(--(?:sans|mono)\)|inherit|initial|unset)\s*(?:!important)?\s*$/.test(m[1])) font++;
  }
  return { colour, radius, shadow, font };
}

export function measure() {
  const out = {};
  for (const f of walk(ROOT).sort()) {
    const rel = path.relative(ROOT, f);
    if (SKIP.some((r) => r.test(rel))) continue;
    const c = count(f, fs.readFileSync(f, 'utf8'));
    if (c.colour || c.radius || c.shadow || c.font) out[rel] = c;
  }
  return out;
}

function block(src, selectorRe) {
  const m = src.match(selectorRe);
  if (!m) return null;
  const start = src.indexOf('{', m.index) + 1;
  let depth = 1, i = start;
  while (depth && i < src.length) { if (src[i] === '{') depth++; else if (src[i] === '}') depth--; i++; }
  const body = src.slice(start, i - 1).replace(/\/\*[\s\S]*?\*\//g, '');
  const props = new Map();
  for (const d of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) props.set(d[1], d[2].trim());
  return props;
}

const ds = fs.readFileSync(DS, 'utf8');
const LIGHT = block(ds, /\/\* @roles:light \*\/\s*:root[^{]*\{/);
const DARK = block(ds, /\/\* @roles:dark \*\/\s*:root\[data-theme="dark"\]\s*\{/);
const ALIAS = block(ds, /\/\* @aliases \*\/\s*:root\s*\{/);

if (process.env.THEME_TOKENS_REPORT || process.env.THEME_TOKENS_WRITE) {
  const now = measure();
  const tot = { colour: 0, radius: 0, shadow: 0, font: 0 };
  for (const c of Object.values(now)) for (const k in tot) tot[k] += c[k];
  console.log('totals', tot, 'files', Object.keys(now).length);
  if (process.env.THEME_TOKENS_WRITE) {
    let old = {};
    try { old = JSON.parse(fs.readFileSync(BASELINE, 'utf8')); } catch {}
    const next = {};
    for (const [f, c] of Object.entries(now)) {
      const o = old[f];
      next[f] = o
        ? Object.fromEntries(Object.keys(c).map((k) => [k, Math.min(c[k], o[k] ?? 0)]))
        : c;
    }
    fs.writeFileSync(BASELINE, JSON.stringify(next, null, 1) + '\n');
    console.log('baseline written');
  }
}

test('design-system.css has the three marked token blocks', () => {
  assert.ok(LIGHT && LIGHT.size, 'no /* @roles:light */ :root block');
  assert.ok(DARK && DARK.size, 'no /* @roles:dark */ :root[data-theme="dark"] block');
  assert.ok(ALIAS && ALIAS.size, 'no /* @aliases */ :root block');
});

test('every colour role is defined in light and in dark', () => {
  const onlyLight = [...LIGHT.keys()].filter((k) => !DARK.has(k));
  const onlyDark = [...DARK.keys()].filter((k) => !LIGHT.has(k));
  assert.deepEqual(onlyLight, [], `defined in light, missing in dark: ${onlyLight.join(', ')}`);
  assert.deepEqual(onlyDark, [], `defined in dark, missing in light: ${onlyDark.join(', ')}`);
});

test('the deprecated block only points old names at roles', () => {
  const raw = [...ALIAS].filter(([, v]) => !/^var\(--[\w-]+\)$/.test(v)).map(([k, v]) => `${k}: ${v}`);
  assert.deepEqual(raw, [], `an alias carries its own value:\n  ${raw.join('\n  ')}`);
  const roles = new Set([...LIGHT.keys()]);
  const scales = block(ds, /\/\* @scales \*\/\s*:root\s*\{/) || new Map();
  for (const k of scales.keys()) roles.add(k);
  const dangling = [...ALIAS].filter(([, v]) => {
    const t = v.match(/var\((--[\w-]+)\)/)[1];
    return !roles.has(t) && !ALIAS.has(t);
  }).map(([k, v]) => `${k}: ${v}`);
  assert.deepEqual(dangling, [], `an alias points at nothing:\n  ${dangling.join('\n  ')}`);
});

test('raw colours, radii, shadows and font stacks never grow', () => {
  const base = JSON.parse(fs.readFileSync(BASELINE, 'utf8'));
  const now = measure();
  const grew = [];
  for (const [f, c] of Object.entries(now)) {
    const b = base[f] || { colour: 0, radius: 0, shadow: 0, font: 0 };
    for (const k of Object.keys(c)) if (c[k] > (b[k] ?? 0)) grew.push(`${f}: ${k} ${b[k] ?? 0} -> ${c[k]}`);
  }
  assert.deepEqual(grew, [], `\nRaw values grew. Use a token from design-system.css instead:\n  ${grew.join('\n  ')}\n`);
});
