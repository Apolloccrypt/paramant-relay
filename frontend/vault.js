// Paramant Vault — client-side file encryption to a .prmnt container.
//
// MVP = passphrase mode: PBKDF2-SHA256 -> AES-256-GCM, all in the browser via
// WebCrypto. Nothing is uploaded; the server never sees the file or the key
// (server-blind by design). AES-256 is quantum-resistant, so this is already
// post-quantum-safe for confidentiality. The .prmnt header is versioned so the
// public-key / passkey (ML-KEM) key-slots can be added later without breaking it.
//
// .prmnt container (binary):
//   MAGIC "PRMNT" (5) | VERSION (1) | KDF id (1) | ITER u32-LE (4)
//   | SALT (16) | NONCE (12) | CIPHERTEXT (AES-256-GCM)
// Plaintext inside the ciphertext: [metaLen u32-LE (4)][meta JSON][file bytes],
// so the original filename/type is encrypted too (not leaked in the container).

(function () {
  'use strict';

  const MAGIC = new Uint8Array([0x50, 0x52, 0x4d, 0x4e, 0x54]); // "PRMNT"
  const VERSION = 1;
  const KDF_PBKDF2 = 1;
  const ITER = 210000;
  const HDR_LEN = 5 + 1 + 1 + 4 + 16 + 12; // 39

  const te = new TextEncoder();
  const td = new TextDecoder();
  const $ = (id) => document.getElementById(id);

  function rand(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }

  async function deriveKey(passphrase, salt, iter) {
    const base = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  function packPlain(meta, bytes) {
    const metaBuf = te.encode(JSON.stringify(meta));
    const out = new Uint8Array(4 + metaBuf.length + bytes.length);
    new DataView(out.buffer).setUint32(0, metaBuf.length, true);
    out.set(metaBuf, 4);
    out.set(bytes, 4 + metaBuf.length);
    return out;
  }

  function unpackPlain(buf) {
    const metaLen = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, true);
    if (metaLen > buf.length - 4) throw new Error('Damaged .prmnt file.');   // bounds before slice/parse
    const meta = JSON.parse(td.decode(buf.subarray(4, 4 + metaLen)));
    return { meta, bytes: buf.subarray(4 + metaLen) };
  }

  async function encryptFile(file, passphrase) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const salt = rand(16), nonce = rand(12);
    const key = await deriveKey(passphrase, salt, ITER);
    const meta = { name: file.name, type: file.type || 'application/octet-stream', size: bytes.length };
    const plain = packPlain(meta, bytes);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plain));
    const out = new Uint8Array(HDR_LEN + ct.length);
    out.set(MAGIC, 0);
    out[5] = VERSION;
    out[6] = KDF_PBKDF2;
    new DataView(out.buffer).setUint32(7, ITER, true);
    out.set(salt, 11);
    out.set(nonce, 27);
    out.set(ct, HDR_LEN);
    return out;
  }

  async function decryptFile(file, passphrase) {
    const buf = new Uint8Array(await file.arrayBuffer());
    if (buf.length < HDR_LEN) throw new Error('That is not a .prmnt file.');
    for (let i = 0; i < 5; i++) if (buf[i] !== MAGIC[i]) throw new Error('That is not a .prmnt file.');
    if (buf[5] !== VERSION) throw new Error('This .prmnt was made with a newer version.');
    const iter = new DataView(buf.buffer, buf.byteOffset + 7, 4).getUint32(0, true);
    // iter is unauthenticated header data; clamp so a crafted/corrupt file can't drive
    // PBKDF2 to billions of rounds and freeze the tab (DoS) before the passphrase check.
    if (iter < 1000 || iter > 1000000) throw new Error('That is not a .prmnt file.');
    const salt = buf.subarray(11, 27), nonce = buf.subarray(27, 39), ct = buf.subarray(39);
    const key = await deriveKey(passphrase, salt, iter);
    let plain;
    try {
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct));
    } catch (e) {
      throw new Error('Wrong passphrase, or the file is damaged.');
    }
    return unpackPlain(plain);
  }

  function downloadBytes(bytes, name, type) {
    const blob = new Blob([bytes], { type: type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
  }

  // ── UI ─────────────────────────────────────────────────────────────────────
  const state = { mode: 'lock', file: null };

  function setStatus(el, msg, kind) {
    el.textContent = msg || '';
    el.className = 'vt-status' + (kind ? ' ' + kind : '');
    el.hidden = !msg;
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function wirePanel(cfg) {
    const drop = $(cfg.drop), input = $(cfg.input), info = $(cfg.info);
    const run = $(cfg.run), status = $(cfg.status);
    let file = null;

    function pick(f) {
      file = f;
      if (f) {
        info.hidden = false;
        info.textContent = f.name + ' · ' + fmtSize(f.size);
      } else {
        info.hidden = true;
      }
      validate();
    }

    function validate() {
      const pw = cfg.pw ? $(cfg.pw).value : '';
      const pw2 = cfg.pw2 ? $(cfg.pw2).value : null;
      let ok = !!file && pw.length >= 6;
      if (pw2 !== null) ok = ok && pw === pw2;
      run.disabled = !ok;
    }

    drop.addEventListener('click', () => input.click());
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('drag'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
    drop.addEventListener('drop', (e) => {
      e.preventDefault(); drop.classList.remove('drag');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]);
    });
    input.addEventListener('change', () => { if (input.files[0]) pick(input.files[0]); });
    if (cfg.pw) $(cfg.pw).addEventListener('input', validate);
    if (cfg.pw2) $(cfg.pw2).addEventListener('input', validate);

    run.addEventListener('click', async () => {
      if (!file) return;
      run.disabled = true;
      const orig = run.textContent;
      run.textContent = cfg.busy;
      setStatus(status, '', '');
      try {
        const pw = $(cfg.pw).value;
        if (cfg.mode === 'lock') {
          const out = await encryptFile(file, pw);
          downloadBytes(out, file.name + '.prmnt', 'application/octet-stream');
          setStatus(status, 'Locked. Your .prmnt file is downloading. Keep your passphrase safe — without it the file cannot be opened.', 'ok');
        } else {
          const { meta, bytes } = await decryptFile(file, pw);
          downloadBytes(bytes, meta.name || 'unlocked', meta.type);
          setStatus(status, 'Opened. Your original file (' + (meta.name || 'file') + ') is downloading.', 'ok');
        }
      } catch (e) {
        setStatus(status, e.message || 'Something went wrong.', 'err');
      }
      run.textContent = orig;
      run.disabled = false;
    });
  }

  function switchMode(mode) {
    state.mode = mode;
    document.querySelectorAll('.vt-tab').forEach((t) => {
      const on = t.dataset.mode === mode;
      t.classList.toggle('on', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $('panel-lock').hidden = mode !== 'lock';
    $('panel-open').hidden = mode !== 'open';
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!window.crypto || !crypto.subtle) {
      const w = $('vt-unsupported'); if (w) w.hidden = false;
      return;
    }
    document.querySelectorAll('.vt-tab').forEach((t) => t.addEventListener('click', () => switchMode(t.dataset.mode)));
    wirePanel({ mode: 'lock', drop: 'lock-drop', input: 'lock-input', info: 'lock-info', pw: 'lock-pw', pw2: 'lock-pw2', run: 'lock-run', status: 'lock-status', busy: 'Locking…' });
    wirePanel({ mode: 'open', drop: 'open-drop', input: 'open-input', info: 'open-info', pw: 'open-pw', run: 'open-run', status: 'open-status', busy: 'Opening…' });
    switchMode('lock');
  });
})();
