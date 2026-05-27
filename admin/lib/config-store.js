'use strict';

// Reads and writes a dotenv-style config file under the control of the admin
// panel. Whitelist-driven (admin/lib/config-schema.js): only known keys are
// ever read out or written.
//
// The file path is NOT hardcoded. Set ADMIN_CONFIG_ENV_PATH to the env file the
// relays load (typically a file on a shared volume mounted into both the admin
// and relay containers). If it is unset, the feature reports as unavailable
// rather than guessing a path -- we never silently edit the wrong file.

const fs   = require('fs');
const path = require('path');

const schema = require('./config-schema');

function envPath() {
  return process.env.ADMIN_CONFIG_ENV_PATH || '';
}

function isEnabled() {
  return Boolean(envPath());
}

// ---- dotenv parse/serialise (comment- and order-preserving) ----------------

// Parse into { lines: [...], map: { KEY: {value, lineIndex} } }. We keep the
// original lines so writing back preserves comments, blank lines, and any keys
// outside our whitelist untouched.
function parse(raw) {
  const lines = raw.split('\n');
  const map = {};
  lines.forEach((line, i) => {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (m) map[m[1]] = { value: m[2], lineIndex: i };
  });
  return { lines, map };
}

function readRaw() {
  const p = envPath();
  if (!p) throw new Error('config_unavailable');
  if (!fs.existsSync(p)) return ''; // treat missing file as empty; we can create it
  return fs.readFileSync(p, 'utf8');
}

// ---- masking ---------------------------------------------------------------

function maskSecret(value) {
  if (!value) return { set: false, masked: '', length: 0 };
  return { set: true, masked: '********', length: value.length };
}

// ---- public read ------------------------------------------------------------

// Returns the whitelisted keys with current values. Secrets are masked and
// never returned in plaintext.
function readConfig() {
  const { map } = parse(readRaw());
  const keys = Object.entries(schema).map(([name, spec]) => {
    const present = Object.prototype.hasOwnProperty.call(map, name);
    const rawVal  = present ? map[name].value : '';
    const base = {
      name,
      type: spec.type,
      ui: spec.ui,
      group: spec.group,
      default: spec.default,
      options: spec.options || null,
      min: spec.min ?? null,
      max: spec.max ?? null,
      description: spec.description || '',
      class: spec.class,
      secret: Boolean(spec.secret),
      readonly: Boolean(spec.readonly),
      set: present,
    };
    if (spec.secret) {
      base.value = null;            // never leak the value
      base.secret_state = maskSecret(rawVal);
    } else {
      base.value = present ? rawVal : '';
    }
    return base;
  });
  return { keys };
}

// ---- validation -------------------------------------------------------------

// Coerce + validate a single change against the schema. Returns
// { ok, value, error }. The returned value is the STRING to write to the file.
function validateChange(key, value) {
  const spec = schema[key];
  if (!spec) return { ok: false, error: `key_not_whitelisted: ${key}` };
  if (spec.readonly) return { ok: false, error: `key_readonly: ${key}` };

  switch (spec.type) {
    case 'boolean': {
      const v = (value === true || value === 'true') ? 'true'
              : (value === false || value === 'false') ? 'false'
              : null;
      if (v === null) return { ok: false, error: `${key}: expected boolean` };
      return { ok: true, value: v };
    }
    case 'number': {
      const n = Number(value);
      if (!Number.isFinite(n)) return { ok: false, error: `${key}: expected number` };
      if (spec.min != null && n < spec.min) return { ok: false, error: `${key}: below min ${spec.min}` };
      if (spec.max != null && n > spec.max) return { ok: false, error: `${key}: above max ${spec.max}` };
      return { ok: true, value: String(n) };
    }
    case 'enum': {
      const v = String(value);
      if (!spec.options.includes(v)) return { ok: false, error: `${key}: not in [${spec.options.join(', ')}]` };
      return { ok: true, value: v };
    }
    case 'string':
    default: {
      const v = String(value);
      if (/[\n\r]/.test(v)) return { ok: false, error: `${key}: newlines not allowed` };
      return { ok: true, value: v };
    }
  }
}

// ---- atomic write with backup ----------------------------------------------

// changes: [{ key, value }]. Validates ALL before writing ANY (all-or-nothing).
// Returns { ok, applied: [{key, requires_restart}], backup, error }.
function writeConfig(changes) {
  const p = envPath();
  if (!p) return { ok: false, error: 'config_unavailable' };
  if (!Array.isArray(changes) || changes.length === 0) {
    return { ok: false, error: 'no_changes' };
  }

  // Validate everything first.
  const resolved = [];
  for (const ch of changes) {
    const r = validateChange(ch.key, ch.value);
    if (!r.ok) return { ok: false, error: r.error };
    resolved.push({ key: ch.key, value: r.value });
  }

  const raw = readRaw();
  const { lines, map } = parse(raw);

  // Apply: replace in place, or append if absent.
  for (const { key, value } of resolved) {
    if (Object.prototype.hasOwnProperty.call(map, key)) {
      lines[map[key].lineIndex] = `${key}=${value}`;
    } else {
      // append before trailing empty lines
      lines.push(`${key}=${value}`);
    }
  }
  const out = lines.join('\n');

  // Backup the current file (if it exists) before writing.
  let backup = null;
  if (fs.existsSync(p)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    backup = `${p}.pre-change-${stamp}`;
    fs.copyFileSync(p, backup);
  }

  // Atomic write: write temp in the same dir, then rename.
  const tmp = path.join(path.dirname(p), `.${path.basename(p)}.tmp-${process.pid}`);
  fs.writeFileSync(tmp, out, { mode: 0o600 });
  fs.renameSync(tmp, p);

  const applied = resolved.map(({ key }) => ({
    key,
    requires_restart: schema[key].class, // 'relay-restart' | 'admin-restart'
  }));
  return { ok: true, applied, backup };
}

// Mask a value for audit logging (secret -> length only; non-secret -> value).
function auditValue(key, value) {
  const spec = schema[key];
  if (!spec) return '?';
  if (spec.secret) return value ? `set(${String(value).length})` : 'unset';
  return String(value);
}

module.exports = {
  isEnabled, envPath, readConfig, writeConfig, validateChange, auditValue, maskSecret,
};
