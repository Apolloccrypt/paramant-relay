// Conformance-suite path resolution — the SINGLE place that knows where the
// three real crypto implementations and the two shared-contract source files
// live. Everything is overridable by env var so this directory can be copied
// verbatim into the standalone SDK repo (just point the env vars at the new
// layout). No relay runtime is imported anywhere in this suite.
//
// Resolution order for every path: explicit env var > in-repo default >
// dev fallback. If a REQUIRED dependency is missing we do not silently skip or
// mock — config.requireDep() throws with the exact thing that is absent.

import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(here, '..', '..');

function firstExisting(candidates) {
  for (const c of candidates) {
    if (c && existsSync(c)) return c;
  }
  return null;
}

// An explicitly-set env override is AUTHORITATIVE: returned verbatim, never
// quietly replaced by a fallback. If it points nowhere the adapter fails loudly
// downstream (that is the intended behaviour — no silent substitution). Only
// when the override is unset do we auto-detect among in-repo/dev candidates.
function resolveDep(envName, candidates) {
  const explicit = process.env[envName];
  if (explicit) return explicit;
  return firstExisting(candidates);
}

// ── The three real crypto implementations ──────────────────────────────────

// @noble/post-quantum — the crypto behind sdk-js.
export const nobleDir = resolveDep('PARAMANT_NOBLE_DIR', [
  join(repoRoot, 'sdk-js', 'node_modules', '@noble', 'post-quantum'),
  join(repoRoot, 'node_modules', '@noble', 'post-quantum'),
  // dev fallback (relay repo has no @noble in its own node_modules):
  '/home/mick/paramant-audit/repo/sdk-js/node_modules/@noble/post-quantum',
]);

// @paramant/core NAPI binding — the crypto behind the relay.
export const coreNode = resolveDep('PARAMANT_CORE_NODE', [
  join(repoRoot, 'node_modules', '@paramant', 'core', 'index.node'),
  '/home/mick/paramant-core/crates/paramant-core-node/index.node',
]);

// Python interpreter that can import pqcrypto + cryptography — the crypto
// behind sdk-py. The system python3 here has neither, so we need a venv.
export const python = resolveDep('PARAMANT_PY', [
  join(repoRoot, '.venv', 'bin', 'python'),
  '/home/mick/paramant-audit/.venv/bin/python',
]);

// ── Shared-contract source files (anchored to docs/wire-format-v1.md) ───────

export const sdkJsWire = resolveDep('PARAMANT_SDK_JS_WIRE', [
  join(repoRoot, 'sdk-js', 'src', 'wire-format.js'),
]);

export const sdkPyDir = resolveDep('PARAMANT_SDK_PY_DIR', [
  join(repoRoot, 'sdk-py'),
]);

// Optional — present in the relay repo, absent in the SDK repo. Tested when
// found, skipped-with-message when not (never silently passed).
export const relayWire = resolveDep('PARAMANT_RELAY_WIRE', [
  join(repoRoot, 'relay', 'crypto', 'wire-format.js'),
]);

export const relayParasign = resolveDep('PARAMANT_RELAY_PARASIGN', [
  join(repoRoot, 'relay', 'parasign.js'),
]);

export const specDoc = join(repoRoot, 'docs', 'wire-format-v1.md');

// ── Adapter locations ───────────────────────────────────────────────────────

export const adapters = {
  noble: join(here, 'adapters', 'noble-adapter.mjs'),
  core: join(here, 'adapters', 'core-adapter.mjs'),
  pqcrypto: join(here, 'adapters', 'pqcrypto-adapter.py'),
};

// Env handed to every spawned adapter so adapters never re-detect paths.
export function adapterEnv() {
  return {
    ...process.env,
    PARAMANT_NOBLE_DIR: nobleDir || '',
    PARAMANT_CORE_NODE: coreNode || '',
    PARAMANT_SDK_PY_DIR: sdkPyDir || '',
    PARAMANT_SDK_JS_WIRE: sdkJsWire || '',
    PARAMANT_RELAY_WIRE: relayWire || '',
  };
}

// Throw loudly, naming exactly what is missing, instead of degrading to a mock.
export function requireDep(label, value, hint) {
  if (!value) {
    throw new Error(
      `CONFORMANCE DEPENDENCY MISSING: ${label} could not be located. ${hint}\n` +
      `A conformance test that is green because a real implementation was ` +
      `unavailable is worse than no test. Refusing to run with a stub.`
    );
  }
  return value;
}
