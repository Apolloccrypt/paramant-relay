// JSON vector-bus: drive a crypto adapter (in its own runtime) by writing one
// JSON request to its stdin and reading one JSON response from its stdout.
// Bytes cross the bus as hex strings. Synchronous on purpose — the cross-impl
// roundtrips chain (output of impl A feeds impl B), so sequential is clearest.
//
// If an adapter cannot load its real crypto library it prints
// {"ok":false,"error":...} and exits non-zero; we re-throw that verbatim so a
// missing lib fails the test loudly and names itself. Never a silent mock.

import { execFileSync } from 'node:child_process';
import { adapters, adapterEnv, python, requireDep } from '../config.mjs';

export const hex = {
  toBytes: (h) => new Uint8Array(Buffer.from(h, 'hex')),
  fromBytes: (b) => Buffer.from(b).toString('hex'),
};

function run(cmd, args, request) {
  let stdout;
  try {
    stdout = execFileSync(cmd, args, {
      input: JSON.stringify(request),
      env: adapterEnv(),
      maxBuffer: 64 * 1024 * 1024,
      encoding: 'utf8',
    });
  } catch (e) {
    // execFileSync throws on non-zero exit; surface adapter stderr/stdout.
    const out = (e.stdout || '').toString().trim();
    const err = (e.stderr || '').toString().trim();
    let parsed = null;
    try { parsed = JSON.parse(out); } catch { /* not json */ }
    const detail = parsed?.error || err || e.message;
    throw new Error(`[${args[args.length - 1] ?? cmd} adapter] op=${request.op} failed: ${detail}`);
  }
  const res = JSON.parse(stdout);
  if (!res.ok) throw new Error(`[adapter] op=${request.op} returned error: ${res.error}`);
  return res;
}

// impl ∈ 'noble' | 'core' | 'pqcrypto'
export function call(impl, op, args = {}) {
  if (impl === 'pqcrypto') {
    requireDep('Python venv with pqcrypto', python,
      'Set PARAMANT_PY to a python that can `import pqcrypto` and `import cryptography`.');
    return run(python, [adapters.pqcrypto], { op, ...args });
  }
  return run(process.execPath, [adapters[impl]], { op, ...args });
}

export const IMPLS = ['noble', 'core', 'pqcrypto'];
