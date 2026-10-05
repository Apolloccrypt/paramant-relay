'use strict';
// Whitelist of CLI commands available in /admin/cli.
// Each command has: handler, args-schema, audit-log class, require-totp.
//
// SECURITY MODEL
//   - This is a WHITELIST, not a shell. No arbitrary commands run.
//   - Handlers live in scripts/cli/ and are non-interactive (no whiptail,
//     no sudo prompt, no pager). The host TUI scripts in scripts/ are NOT
//     used here because they assume a systemd host and block on prompts.
//   - Args are validated against the schema below, then passed POSITIONALLY
//     to the handler in declared order. spawn() is called WITHOUT a shell,
//     so values are never word-split or interpreted by /bin/sh.
//   - class 'read' commands run without TOTP; 'mutate' commands require a
//     fresh valid TOTP code (verified against the relay) per execution.

const path = require('path');

// Non-interactive web-CLI handlers, kept separate from the host TUI scripts.
const SCRIPTS_DIR = path.resolve(__dirname, '../../scripts/cli');

const COMMANDS = {
  'status': {
    description: 'Show paramant relay overall status',
    handler: 'paramant-status.sh',
    args: [],
    class: 'read',
    totp: false,
  },
  'health': {
    description: 'Deep health check (all services)',
    handler: 'paramant-doctor.sh',
    args: [],
    class: 'read',
    totp: false,
  },
  'logs': {
    description: 'Tail logs of a service',
    handler: 'paramant-logs.sh',
    args: [
      { name: 'service', type: 'enum', options: ['relay', 'admin', 'nats', 'frontend'], required: true },
      { name: 'tail', type: 'number', default: 100, min: 1, max: 1000 },
    ],
    class: 'read',
    totp: false,
  },
  'key list': {
    description: 'List active API keys (masked)',
    handler: 'paramant-key-list.sh',
    needsAdminToken: true,
    args: [],
    class: 'read',
    totp: false,
  },
  'key add': {
    description: 'Add new API key for a user',
    handler: 'paramant-key-add.sh',
    needsAdminToken: true,
    args: [
      { name: 'email', type: 'email', required: true },
      { name: 'plan', type: 'enum', options: ['free', 'pro', 'enterprise'], default: 'free' },
    ],
    class: 'mutate',
    totp: true,
  },
  'key revoke': {
    description: 'Revoke an API key by hash-prefix',
    handler: 'paramant-key-revoke.sh',
    needsAdminToken: true,
    args: [
      { name: 'key_prefix', type: 'string', minLength: 8, required: true },
    ],
    class: 'mutate',
    totp: true,
  },
  'config show': {
    description: 'Show current .env (secrets masked)',
    handler: 'paramant-config-show.sh',
    args: [],
    class: 'read',
    totp: false,
  },
  'relay list': {
    description: 'List configured sector-relays',
    handler: 'paramant-relay-list.sh',
    args: [],
    class: 'read',
    totp: false,
  },
  'audit recent': {
    description: 'Show recent audit-log entries',
    handler: 'paramant-audit-recent.sh',
    needsAdminToken: true,
    args: [
      { name: 'limit', type: 'number', default: 50, min: 1, max: 500 },
    ],
    class: 'read',
    totp: false,
  },
  'nats status': {
    description: 'NATS JetStream connectivity check',
    handler: 'paramant-nats-status.sh',
    args: [],
    class: 'read',
    totp: false,
  },
  'restart': {
    description: 'Restart a service (docker compose restart)',
    handler: 'paramant-restart.sh',
    args: [
      { name: 'service', type: 'enum', options: ['relay', 'admin', 'frontend', 'all'], required: true },
    ],
    class: 'mutate',
    totp: true,
  },
  'backup create': {
    description: 'Create immediate backup',
    handler: 'paramant-backup.sh',
    needsAdminToken: true,
    args: [],
    class: 'mutate',
    totp: true,
  },
  'help': {
    description: 'Show available commands',
    handler: '__help__',
    args: [],
    class: 'read',
    totp: false,
  },
};

// Arg names whose values must never appear in audit logs in the clear.
const SECRET_ARG_NAMES = new Set(['totp', 'key', 'api_key', 'token', 'password', 'secret']);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Validate a raw args object against a command's schema.
// Returns { ok: true, values: {...} } or { ok: false, error: '...' }.
// `values` is the normalized arg map (defaults applied, numbers coerced).
function validateArgs(cmd, rawArgs) {
  const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
  const values = {};
  for (const spec of cmd.args) {
    let v = args[spec.name];
    const missing = v === undefined || v === null || v === '';
    if (missing) {
      if (spec.required) return { ok: false, error: `Missing required arg: ${spec.name}` };
      if (spec.default !== undefined) v = spec.default;
      else continue;
    }
    switch (spec.type) {
      case 'enum':
        v = String(v);
        if (!spec.options.includes(v)) {
          return { ok: false, error: `Arg ${spec.name} must be one of: ${spec.options.join(', ')}` };
        }
        break;
      case 'number': {
        const n = Number(v);
        if (!Number.isFinite(n) || !Number.isInteger(n)) {
          return { ok: false, error: `Arg ${spec.name} must be an integer` };
        }
        if (spec.min !== undefined && n < spec.min) return { ok: false, error: `Arg ${spec.name} must be >= ${spec.min}` };
        if (spec.max !== undefined && n > spec.max) return { ok: false, error: `Arg ${spec.name} must be <= ${spec.max}` };
        v = n;
        break;
      }
      case 'email':
        v = String(v);
        if (!EMAIL_RE.test(v) || v.length > 254) return { ok: false, error: `Arg ${spec.name} must be a valid email` };
        break;
      case 'string':
        v = String(v);
        if (spec.minLength !== undefined && v.length < spec.minLength) {
          return { ok: false, error: `Arg ${spec.name} must be at least ${spec.minLength} chars` };
        }
        if (spec.maxLength !== undefined && v.length > spec.maxLength) {
          return { ok: false, error: `Arg ${spec.name} must be at most ${spec.maxLength} chars` };
        }
        // Defense-in-depth: even though we never pass through a shell, reject
        // control characters and shell metacharacters outright.
        if (/[\x00-\x1f\x7f`$;&|<>(){}\\]/.test(v)) {
          return { ok: false, error: `Arg ${spec.name} contains disallowed characters` };
        }
        // Reject a leading '-' so a value can never be read by a handler script
        // as an option flag instead of a positional argument (option/argument
        // injection). A '--' terminator in buildArgv is NOT usable here because
        // the handlers consume argv as their own $1/$2 positionals (see note on
        // buildArgv), so this upstream rejection is the guard.
        if (v[0] === '-') {
          return { ok: false, error: `Arg ${spec.name} must not start with '-'` };
        }
        break;
      default:
        return { ok: false, error: `Unknown arg type for ${spec.name}` };
    }
    values[spec.name] = v;
  }
  return { ok: true, values };
}

// Build the positional argv array for spawn(), in schema declared order.
// NOTE: handlers in scripts/cli read these as their OWN positional params
// ($1, $2, ...), so we must NOT prepend a '--' option terminator here -- that
// would land as $1 and shift every real value by one, breaking the handlers.
// Option/flag injection is instead blocked upstream in validateArgs(), which
// rejects any string value beginning with '-'; non-string args are enum/number
// /email and can never be a bare flag.
function buildArgv(cmd, values) {
  return cmd.args
    .filter(spec => values[spec.name] !== undefined)
    .map(spec => String(values[spec.name]));
}

// Produce a copy of an args map safe for audit logging.
function maskArgs(values) {
  const out = {};
  for (const [k, v] of Object.entries(values || {})) {
    if (SECRET_ARG_NAMES.has(k)) out[k] = '***';
    else if (k === 'key_prefix' && typeof v === 'string') out[k] = v.slice(0, 8) + '...';
    else out[k] = v;
  }
  return out;
}

// Least-privilege environment for a spawned handler. PATH/HOME + non-secret
// operational vars only; the sensitive secrets (ADMIN_TOKEN, REDIS_*, RESEND_*,
// PARAMANT_*) are NOT broadcast. ADMIN_TOKEN is added only for commands that
// call the relay admin API (cmd.needsAdminToken). Pure + unit-tested.
function buildChildEnv(cmd, processEnv, sectors, adminToken) {
  processEnv = processEnv || {};
  sectors = sectors || {};
  const env = {
    PATH: processEnv.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: processEnv.HOME || '/tmp',
  };
  for (const [k, v] of Object.entries(processEnv)) {
    if (/^(PORT|BASE_PATH|NODE_ENV|RELAY_|SECTOR|NATS_|COMPOSE_|BACKUP_)/.test(k)) env[k] = v;
  }
  if (sectors.health) env.RELAY_URL = sectors.health;
  env.RELAY_SECTORS = Object.entries(sectors).map(([n, u]) => `${n}=${u}`).join(',');
  if (cmd && cmd.needsAdminToken && adminToken) env.ADMIN_TOKEN = adminToken;
  return env;
}

module.exports = { COMMANDS, SCRIPTS_DIR, validateArgs, buildArgv, maskArgs, SECRET_ARG_NAMES, buildChildEnv };
