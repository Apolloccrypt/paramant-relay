'use strict';
// Email allowlist for the hidden /developer dashboard. Pure + env-injectable so
// the gate can be unit-tested without booting the admin server (same pattern as
// lib/webauthn.js and lib/account-recovery.js).
//
// Rules:
//   - the allowlist comes from env.DEVELOPER_ALLOWLIST (comma-separated) — never
//     hardcoded in the code;
//   - empty allowlist + NODE_ENV=development  => open (local dev/test only);
//   - empty allowlist otherwise (incl. production, where NODE_ENV is unset)
//     => closed for everyone, so access always requires an explicit entry.

function developerAllowlist(env) {
  env = env || process.env;
  return String(env.DEVELOPER_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function isDeveloper(email, env) {
  env = env || process.env;
  const list = developerAllowlist(env);
  if (list.length === 0) return env.NODE_ENV === 'development';
  return list.includes(String(email || '').trim().toLowerCase());
}

module.exports = { developerAllowlist, isDeveloper };
