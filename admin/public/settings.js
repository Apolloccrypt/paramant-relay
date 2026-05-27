'use strict';

// Visual config editor. Reuses the admin session from the SPA (sessionStorage
// 'adm_session'); redirects to the login at /admin/ if absent or rejected.

var SESSION = sessionStorage.getItem('adm_session') || '';
if (!SESSION) location.href = '/admin/';

var state = {
  keys: [],          // schema + current values from the server
  dirty: {},         // key -> new value (string) pending save
  group: null,       // active group
  modalKey: null,    // secret key being replaced
};

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toast(msg, type) {
  var el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = msg;
  el.setAttribute('role', 'status');
  document.body.appendChild(el);
  requestAnimationFrame(function () { requestAnimationFrame(function () { el.classList.add('show'); }); });
  setTimeout(function () { el.classList.remove('show'); setTimeout(function () { el.remove(); }, 250); }, 3200);
}

function api(path, opts) {
  opts = opts || {};
  var headers = { 'X-Session': SESSION, 'Content-Type': 'application/json' };
  if (opts.headers) for (var k in opts.headers) headers[k] = opts.headers[k];
  return fetch('/admin/api' + path, { method: opts.method || 'GET', headers: headers, body: opts.body })
    .then(function (r) {
      if (r.status === 401) { sessionStorage.removeItem('adm_session'); location.href = '/admin/'; throw new Error('unauthorized'); }
      var ct = r.headers.get('content-type') || '';
      return (ct.indexOf('json') >= 0 ? r.json().catch(function () { return null; }) : Promise.resolve(null))
        .then(function (data) { return { ok: r.ok, status: r.status, data: data }; });
    });
}

function groups() {
  var seen = [];
  state.keys.forEach(function (k) { if (seen.indexOf(k.group) < 0) seen.push(k.group); });
  return seen;
}

function renderSidebar() {
  var side = document.getElementById('side');
  side.innerHTML = '';
  groups().forEach(function (g) {
    var b = document.createElement('button');
    b.textContent = g;
    if (g === state.group) b.className = 'active';
    b.onclick = function () { state.group = g; render(); };
    side.appendChild(b);
  });
}

function fieldValue(k) {
  // Returns the value to display: dirty override, else current.
  if (Object.prototype.hasOwnProperty.call(state.dirty, k.name)) return state.dirty[k.name];
  return k.secret ? null : (k.value || '');
}

function setDirty(name, value) {
  state.dirty[name] = value;
  refreshFooter();
  render();
}

function badge(k) {
  if (k.readonly) return '<span class="badge badge-ro">read-only</span>';
  if (k.class === 'admin-restart') return '<span class="badge badge-admin">admin restart</span>';
  return '<span class="badge badge-restart">relay restart</span>';
}

function controlHtml(k) {
  var dirty = Object.prototype.hasOwnProperty.call(state.dirty, k.name);
  if (k.secret) {
    var ss = k.secret_state || { set: false };
    var stateTxt = dirty ? 'pending new value' : (ss.set ? 'set (' + ss.length + ' chars)' : 'not set');
    var btn = k.readonly ? '' : '<button class="replace-btn" data-replace="' + esc(k.name) + '">Replace</button>';
    return '<div class="secret-row"><span class="secret-state">' + esc(stateTxt) + '</span>' + btn + '</div>';
  }
  if (k.readonly) {
    return '<input type="text" value="' + esc(fieldValue(k)) + '" disabled>';
  }
  if (k.type === 'boolean') {
    var on = String(fieldValue(k)) === 'true';
    return '<label class="toggle"><input type="checkbox" data-key="' + esc(k.name) + '"' + (on ? ' checked' : '') + '><span class="track"></span></label>';
  }
  if (k.type === 'enum') {
    var opts = (k.options || []).map(function (o) {
      return '<option value="' + esc(o) + '"' + (String(fieldValue(k)) === String(o) ? ' selected' : '') + '>' + esc(o) + '</option>';
    }).join('');
    return '<select data-key="' + esc(k.name) + '">' + opts + '</select>';
  }
  if (k.ui === 'slider' && k.type === 'number') {
    var v = fieldValue(k) === '' ? k.default : fieldValue(k);
    return '<div class="slider-row">' +
      '<input type="range" data-key="' + esc(k.name) + '" min="' + k.min + '" max="' + k.max + '" value="' + esc(v) + '">' +
      '<input type="number" data-key="' + esc(k.name) + '" data-mirror="1" min="' + k.min + '" max="' + k.max + '" value="' + esc(v) + '"></div>';
  }
  if (k.type === 'number') {
    return '<input type="number" data-key="' + esc(k.name) + '"' +
      (k.min != null ? ' min="' + k.min + '"' : '') + (k.max != null ? ' max="' + k.max + '"' : '') +
      ' value="' + esc(fieldValue(k)) + '">';
  }
  return '<input type="text" data-key="' + esc(k.name) + '" value="' + esc(fieldValue(k)) + '">';
}

function render() {
  renderSidebar();
  var host = document.getElementById('fields');
  host.innerHTML = '';
  var list = state.keys.filter(function (k) { return k.group === state.group; });
  list.forEach(function (k) {
    var dirty = Object.prototype.hasOwnProperty.call(state.dirty, k.name);
    var div = document.createElement('div');
    div.className = 'field' + (dirty ? ' dirty' : '');
    div.innerHTML =
      '<div class="f-top"><span class="f-name">' + esc(k.name) + '</span>' + badge(k) + '</div>' +
      '<div class="f-desc">' + esc(k.description) + '</div>' +
      controlHtml(k) +
      '<div class="f-default" style="margin-top:8px">default: ' + esc(String(k.default)) + '</div>';
    host.appendChild(div);
  });
  wireControls();
}

function wireControls() {
  document.querySelectorAll('[data-key]').forEach(function (el) {
    var key = el.getAttribute('data-key');
    if (el.type === 'checkbox') {
      el.onchange = function () { setDirty(key, el.checked ? 'true' : 'false'); };
    } else if (el.type === 'range') {
      el.oninput = function () {
        var mirror = document.querySelector('input[type=number][data-key="' + key + '"]');
        if (mirror) mirror.value = el.value;
        setDirtyNoRender(key, el.value);
      };
      el.onchange = function () { setDirty(key, el.value); };
    } else {
      el.onchange = function () { setDirty(key, el.value); };
    }
  });
  document.querySelectorAll('[data-replace]').forEach(function (btn) {
    btn.onclick = function () { openModal(btn.getAttribute('data-replace')); };
  });
}

// Update dirty without a full re-render (keeps slider focus while dragging).
function setDirtyNoRender(name, value) {
  state.dirty[name] = value;
  refreshFooter();
}

function refreshFooter() {
  var n = Object.keys(state.dirty).length;
  document.getElementById('foot-info').textContent = n ? (n + ' unsaved change' + (n > 1 ? 's' : '')) : 'No unsaved changes';
  document.getElementById('save').disabled = n === 0;
  document.getElementById('discard').disabled = n === 0;
}

// ---- secret replace modal ---------------------------------------------------
function openModal(key) {
  state.modalKey = key;
  var spec = state.keys.find(function (k) { return k.name === key; });
  document.getElementById('modal-title').textContent = 'Replace ' + key;
  document.getElementById('modal-desc').textContent = (spec && spec.description) || 'Enter a new value. It is sent over your authenticated session and stored in the env file.';
  document.getElementById('modal-input').value = '';
  document.getElementById('modal-bg').classList.add('show');
  document.getElementById('modal-input').focus();
}
function closeModal() { state.modalKey = null; document.getElementById('modal-bg').classList.remove('show'); }

// ---- load + save ------------------------------------------------------------
function load() {
  api('/admin/config').then(function (r) {
    if (r.status === 503) {
      document.getElementById('unavailable').style.display = 'block';
      document.getElementById('unavailable').textContent =
        (r.data && r.data.message) || 'Visual config editor is not enabled (ADMIN_CONFIG_ENV_PATH unset).';
      document.getElementById('side').innerHTML = '';
      return;
    }
    if (!r.ok || !r.data) { toast('Failed to load config', 'err'); return; }
    state.keys = r.data.keys || [];
    if (!state.group && state.keys.length) state.group = state.keys[0].group;
    render();
    refreshFooter();
  });
}

function save() {
  var changes = Object.keys(state.dirty).map(function (k) { return { key: k, value: state.dirty[k] }; });
  if (!changes.length) return;
  document.getElementById('save').disabled = true;
  api('/admin/config', { method: 'PUT', body: JSON.stringify({ changes: changes }) }).then(function (r) {
    if (!r.ok) {
      toast((r.data && r.data.message) || 'Save failed', 'err');
      document.getElementById('save').disabled = false;
      return;
    }
    var n = (r.data.applied || []).length;
    toast(n + ' change' + (n > 1 ? 's' : '') + ' saved', 'ok');
    state.dirty = {};
    if (r.data.requires_restart) document.getElementById('banner').classList.add('show');
    load();
  });
}

function init() {
  document.getElementById('save').onclick = save;
  document.getElementById('discard').onclick = function () { state.dirty = {}; refreshFooter(); render(); };
  document.getElementById('modal-cancel').onclick = closeModal;
  document.getElementById('modal-bg').onclick = function (e) { if (e.target.id === 'modal-bg') closeModal(); };
  document.getElementById('modal-ok').onclick = function () {
    var v = document.getElementById('modal-input').value;
    if (state.modalKey) setDirty(state.modalKey, v);
    closeModal();
  };
  document.getElementById('restart-btn').onclick = function () {
    api('/admin/config/restart', { method: 'POST' }).then(function (r) {
      toast((r.data && r.data.message) || 'Restart the relays manually to apply.', '');
    });
  };
  load();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
