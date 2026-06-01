'use strict';
// Per-account storage for the /developer dashboard's saved tool commands
// (cross-device counterpart of the browser localStorage cache). Pure helpers +
// a Redis key; the endpoints in admin/server.js are gated by authUser +
// developerGate and scope every read/write to the session's user_id.
//
// SECURITY MODEL
//   - the stored value is the NON-SENSITIVE run command (bucket, recipient);
//     never the API key -- the UI templates it as $PARAMANT_API_KEY. We refuse
//     to persist anything that looks like a literal pgp_ key, as defence in
//     depth (so even a buggy client cannot park a secret here).
//   - only catalogue tool names are accepted; unknown keys are dropped.
//   - per-command and per-account size caps bound storage abuse.
//   - the config is data only -- it is NEVER executed server-side.

const { DEVELOPER_TOOLS } = require('./developer-tools');

const TOOL_NAMES = new Set(DEVELOPER_TOOLS.map((t) => t.name));
const MAX_CMD = 2000;
const MAX_TOTAL = 20000;
const KEY = (uid) => `paramant:user:devcfg:${uid}`;

// Validate a single save. Pure. -> { ok, tool, command } | { ok:false, error }.
function validateConfig(tool, command) {
  if (typeof tool !== 'string' || !TOOL_NAMES.has(tool)) return { ok: false, error: 'unknown_tool' };
  if (typeof command !== 'string') return { ok: false, error: 'command_must_be_string' };
  if (command.length > MAX_CMD) return { ok: false, error: 'command_too_long' };
  // The run command must use $PARAMANT_API_KEY, never a literal key. Refuse to
  // store anything that looks like one.
  if (/\bpgp_[A-Za-z0-9_-]{6,}/.test(command)) return { ok: false, error: 'inline_key_not_allowed' };
  return { ok: true, tool, command };
}

// Merge a validated entry into the existing JSON map, dropping unknown tools and
// enforcing the total cap. Pure. -> { ok, map, json } | { ok:false, error }.
function mergeConfig(existingJson, tool, command) {
  let map = {};
  if (existingJson) { try { map = JSON.parse(existingJson) || {}; } catch (e) { map = {}; } }
  if (typeof map !== 'object' || Array.isArray(map)) map = {};
  for (const k of Object.keys(map)) if (!TOOL_NAMES.has(k)) delete map[k];
  map[tool] = command;
  const json = JSON.stringify(map);
  if (json.length > MAX_TOTAL) return { ok: false, error: 'config_too_large' };
  return { ok: true, map, json };
}

// Remove one tool's entry. Pure. -> json string.
function removeConfig(existingJson, tool) {
  let map = {};
  if (existingJson) { try { map = JSON.parse(existingJson) || {}; } catch (e) { map = {}; } }
  if (typeof map !== 'object' || Array.isArray(map)) map = {};
  delete map[tool];
  for (const k of Object.keys(map)) if (!TOOL_NAMES.has(k)) delete map[k];
  return JSON.stringify(map);
}

module.exports = { validateConfig, mergeConfig, removeConfig, KEY, TOOL_NAMES, MAX_CMD, MAX_TOTAL };
