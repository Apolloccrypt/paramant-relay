// settings.js — user preferences + local transfer history (chrome.storage.local).
// Imported by the service worker, popup, options page, and content scripts.

export const TTL_OPTIONS = [
  { ms: 1 * 60 * 60 * 1000,  key: 'ttl_1h' },
  { ms: 6 * 60 * 60 * 1000,  key: 'ttl_6h' },
  { ms: 24 * 60 * 60 * 1000, key: 'ttl_24h' },
  { ms: 3 * 24 * 60 * 60 * 1000, key: 'ttl_3d' },
  { ms: 7 * 24 * 60 * 60 * 1000, key: 'ttl_7d' },
];

export const DEFAULTS = Object.freeze({
  ttl_ms:         24 * 60 * 60 * 1000, // default 24h (relay caps to the plan ceiling)
  link_format:    'block',             // 'block' = formatted card, 'plain' = bare link
  relay_override: '',                  // '' = auto-discover across sectors
});

const SETTINGS_KEY = 'paramant_settings';
const HISTORY_KEY  = 'paramant_history';
const HISTORY_MAX  = 50;

export async function getSettings() {
  const { [SETTINGS_KEY]: stored } = await chrome.storage.local.get(SETTINGS_KEY);
  return { ...DEFAULTS, ...(stored || {}) };
}

export async function setSettings(patch) {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

// ── Transfer history (local only; never leaves the device) ──────────────────────

export async function addHistory(entry) {
  const list = await getHistory();
  list.unshift({ ...entry, at: Date.now() });
  await chrome.storage.local.set({ [HISTORY_KEY]: list.slice(0, HISTORY_MAX) });
}

export async function getHistory() {
  const { [HISTORY_KEY]: list } = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(list) ? list : [];
}

export async function clearHistory() {
  await chrome.storage.local.remove(HISTORY_KEY);
}
