import { getSettings, setSettings, clearHistory, TTL_OPTIONS } from '../shared/settings.js';

const TTL_LABELS = { ttl_1h: '1 hour', ttl_6h: '6 hours', ttl_24h: '24 hours', ttl_3d: '3 days', ttl_7d: '7 days' };
const t = (key, fallback) => chrome.i18n.getMessage(key) || fallback || key;

const ttlSelect   = document.getElementById('ttl');
const relayInput  = document.getElementById('relay');
const clearBtn    = document.getElementById('clear-history');
const savedToast  = document.getElementById('saved');

function applyI18n() {
  for (const node of document.querySelectorAll('[data-i18n]')) {
    const msg = chrome.i18n.getMessage(node.dataset.i18n);
    if (msg) node.textContent = msg;
  }
}

function buildTtlOptions(selectedMs) {
  ttlSelect.textContent = '';
  for (const opt of TTL_OPTIONS) {
    const o = document.createElement('option');
    o.value = String(opt.ms);
    o.textContent = t(opt.key, TTL_LABELS[opt.key]);
    if (opt.ms === selectedMs) o.selected = true;
    ttlSelect.appendChild(o);
  }
}

let saveTimer;
function flashSaved() {
  savedToast.hidden = false;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { savedToast.hidden = true; }, 1500);
}

async function init() {
  applyI18n();
  const s = await getSettings();

  buildTtlOptions(s.ttl_ms);
  relayInput.value = s.relay_override || '';
  const fmt = document.querySelector(`input[name="link_format"][value="${s.link_format}"]`);
  if (fmt) fmt.checked = true;

  ttlSelect.addEventListener('change', async () => {
    await setSettings({ ttl_ms: parseInt(ttlSelect.value, 10) });
    flashSaved();
  });

  for (const radio of document.querySelectorAll('input[name="link_format"]')) {
    radio.addEventListener('change', async () => {
      if (radio.checked) { await setSettings({ link_format: radio.value }); flashSaved(); }
    });
  }

  relayInput.addEventListener('change', async () => {
    const v = relayInput.value.trim();
    if (v && !/^https:\/\/[^\s]+$/i.test(v)) {
      relayInput.setCustomValidity('Enter a full https:// URL');
      relayInput.reportValidity();
      return;
    }
    relayInput.setCustomValidity('');
    await setSettings({ relay_override: v.replace(/\/+$/, '') });
    flashSaved();
  });

  clearBtn.addEventListener('click', async () => {
    await clearHistory();
    flashSaved();
  });
}

init();
