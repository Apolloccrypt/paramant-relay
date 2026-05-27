'use strict';
/* Paramant web debug CLI -- vanilla + vendored xterm.js (no external CDN). */

/* -- Config ----------------------------------------------------------------- */
const BASE = '/admin';
const API = BASE + '/api';
const SESSION = sessionStorage.getItem('adm_session') || '';

/* Without an admin session there is nothing to do -- bounce to the login SPA. */
if (!SESSION) { location.href = BASE + '/'; }

/* -- ANSI helpers ----------------------------------------------------------- */
const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', blue: '\x1b[34m', gray: '\x1b[90m',
};
const PROMPT = `${C.green}paramant${C.reset}${C.dim}>${C.reset} `;
const PROMPT_LEN = 'paramant> '.length;

/* -- Terminal --------------------------------------------------------------- */
const term = new Terminal({
  fontFamily: '"SF Mono", Menlo, Monaco, Consolas, "Courier New", monospace',
  fontSize: 13,
  lineHeight: 1.2,
  cursorBlink: true,
  scrollback: 5000,
  theme: {
    background: '#1c1c1e', foreground: '#f5f5f7',
    cursor: '#f5f5f7', cursorAccent: '#1c1c1e',
    selectionBackground: 'rgba(10,132,255,0.40)',
    black: '#1c1c1e', red: '#ff453a', green: '#30d158', yellow: '#ffd60a',
    blue: '#0a84ff', magenta: '#bf5af2', cyan: '#64d2ff', white: '#f5f5f7',
    brightBlack: '#8e8e93',
  },
});
term.open(document.getElementById('terminal'));

/* Minimal manual fit (no fit addon vendored): estimate cols/rows from box. */
function fit() {
  const el = document.getElementById('terminal');
  const cw = 13 * 0.6;             // approx monospace cell width at 13px
  const ch = 13 * 1.2 + 2;         // line height
  const cols = Math.max(20, Math.floor((el.clientWidth - 12) / cw));
  const rows = Math.max(6, Math.floor((el.clientHeight - 8) / ch));
  try { term.resize(cols, rows); } catch {}
}
fit();
window.addEventListener('resize', fit);

/* -- State ------------------------------------------------------------------ */
let COMMANDS = {};            // name -> spec, fetched from server
let buf = '';                 // current input buffer
let pos = 0;                  // cursor position within buf
let running = false;          // a command is executing
let currentAbort = null;      // AbortController for the running command
const history = [];
let histIdx = -1;             // -1 = editing fresh line

/* -- Output helpers --------------------------------------------------------- */
function writeln(s = '') { term.write(s + '\r\n'); }
function errln(s) { writeln(`${C.red}${s}${C.reset}`); }

function prompt() {
  buf = ''; pos = 0; histIdx = -1;
  term.write('\r\n' + PROMPT);
}

/* Redraw the current input line after an edit (single-line commands). */
function redraw() {
  term.write('\r' + PROMPT + buf + '\x1b[K');
  const back = buf.length - pos;
  if (back > 0) term.write(`\x1b[${back}D`);
}

/* -- Connection status ------------------------------------------------------ */
function setConn(state, text) {
  const el = document.getElementById('conn');
  el.className = 'connection-status' + (state ? ' ' + state : '');
  el.textContent = text;
}

/* -- API -------------------------------------------------------------------- */
async function loadCommands() {
  try {
    const r = await fetch(API + '/admin/cli/commands', { headers: { 'X-Session': SESSION } });
    if (r.status === 401) { location.href = BASE + '/'; return; }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    COMMANDS = {};
    for (const c of data.commands) COMMANDS[c.name] = c;
    setConn('connected', 'connected');
  } catch (e) {
    setConn('error', 'disconnected');
    errln('Could not load command list: ' + e.message);
  }
}

/* -- TOTP modal ------------------------------------------------------------- */
function promptTotp(cmdName) {
  return new Promise(resolve => {
    const modal = document.getElementById('totp-modal');
    const input = document.getElementById('totp-input');
    const err = document.getElementById('totp-err');
    const okBtn = document.getElementById('totp-ok');
    const cancelBtn = document.getElementById('totp-cancel');
    document.getElementById('totp-cmd').textContent =
      `"${cmdName}" changes state. Enter your 6-digit TOTP code to proceed.`;
    err.textContent = ''; input.value = '';
    modal.classList.add('open');
    setTimeout(() => input.focus(), 50);

    function cleanup(val) {
      modal.classList.remove('open');
      okBtn.onclick = cancelBtn.onclick = input.onkeydown = null;
      term.focus();
      resolve(val);
    }
    function submit() {
      const code = input.value.replace(/\D/g, '');
      if (code.length !== 6) { err.textContent = 'Enter exactly 6 digits.'; return; }
      cleanup(code);
    }
    okBtn.onclick = submit;
    cancelBtn.onclick = () => cleanup(null);
    input.onkeydown = e => {
      if (e.key === 'Enter') { e.preventDefault(); submit(); }
      else if (e.key === 'Escape') { e.preventDefault(); cleanup(null); }
    };
  });
}

/* -- Command parsing -------------------------------------------------------- */
/* Match the longest whitelist command name that prefixes the tokens. */
function parse(line) {
  const tokens = line.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  const two = tokens.slice(0, 2).join(' ');
  let name = null, rest = [];
  if (COMMANDS[two]) { name = two; rest = tokens.slice(2); }
  else if (COMMANDS[tokens[0]]) { name = tokens[0]; rest = tokens.slice(1); }
  else return { unknown: tokens[0] };
  const spec = COMMANDS[name];
  const args = {};
  spec.args.forEach((a, i) => { if (rest[i] !== undefined) args[a.name] = rest[i]; });
  return { name, spec, args };
}

/* -- Help ------------------------------------------------------------------- */
function printHelp() {
  writeln(`${C.bold}Paramant CLI -- available commands${C.reset}`);
  writeln(`${C.gray}(commands marked [totp] require a 6-digit code)${C.reset}`);
  writeln('');
  const names = Object.keys(COMMANDS).sort();
  for (const name of names) {
    const c = COMMANDS[name];
    const tag = c.totp ? ` ${C.yellow}[totp]${C.reset}` : '';
    const argHint = c.args.map(a => {
      const opt = a.required ? '' : '?';
      const t = a.type === 'enum' ? a.options.join('|') : a.type;
      return `${C.dim}<${a.name}:${t}${opt}>${C.reset}`;
    }).join(' ');
    writeln(`  ${C.cyan}${name}${C.reset} ${argHint}`);
    writeln(`      ${C.gray}${c.description}${tag}${C.reset}`);
  }
  writeln('');
  writeln(`${C.gray}Tab: complete  Up/Down: history  Ctrl+K: clear  Ctrl+C: cancel${C.reset}`);
}

/* -- Execute ---------------------------------------------------------------- */
async function execute(line) {
  const parsed = parse(line);
  if (!parsed) { prompt(); return; }
  if (parsed.unknown) {
    errln(`Unknown command: ${parsed.unknown}  (type 'help')`);
    prompt(); return;
  }
  if (parsed.name === 'help') { printHelp(); prompt(); return; }

  const { name, spec, args } = parsed;

  /* Client-side check for missing required args (server re-validates). */
  for (const a of spec.args) {
    if (a.required && args[a.name] === undefined) {
      errln(`Missing required argument: ${a.name}`);
      prompt(); return;
    }
  }

  let totp;
  if (spec.totp || spec.class === 'mutate') {
    totp = await promptTotp(name);
    if (!totp) { writeln(`${C.gray}cancelled${C.reset}`); prompt(); return; }
  }

  running = true;
  currentAbort = new AbortController();
  try {
    const resp = await fetch(API + '/admin/cli/exec', {
      method: 'POST',
      headers: { 'X-Session': SESSION, 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: name, args, totp }),
      signal: currentAbort.signal,
    });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      errln(e.error || `Request failed (HTTP ${resp.status})`);
      finishRun(); return;
    }
    await streamSse(resp);
  } catch (e) {
    if (e.name === 'AbortError') writeln(`${C.yellow}^C cancelled${C.reset}`);
    else errln('Execution error: ' + e.message);
  }
  finishRun();
}

function finishRun() {
  running = false; currentAbort = null;
  prompt();
}

/* Read a text/event-stream body and dispatch 'output' / 'done' events. */
async function streamSse(resp) {
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let acc = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    acc += dec.decode(value, { stream: true });
    let idx;
    while ((idx = acc.indexOf('\n\n')) >= 0) {
      const raw = acc.slice(0, idx);
      acc = acc.slice(idx + 2);
      handleEvent(raw);
    }
  }
}

function handleEvent(raw) {
  let event = 'message', data = '';
  for (const line of raw.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) data += line.slice(5).trim();
  }
  let payload; try { payload = JSON.parse(data); } catch { return; }
  if (event === 'output') {
    if (payload.stream === 'stderr') term.write(C.red + payload.chunk + C.reset);
    else term.write(payload.chunk);
  } else if (event === 'done') {
    const code = payload.exit_code;
    const ms = payload.duration_ms != null ? ` ${payload.duration_ms}ms` : '';
    if (code === 0) writeln(`${C.green}[exit 0]${C.reset}${C.gray}${ms}${C.reset}`);
    else writeln(`${C.red}[exit ${code}${payload.signal ? ' ' + payload.signal : ''}]${C.reset}${C.gray}${ms}${C.reset}`);
  }
}

/* -- Tab completion --------------------------------------------------------- */
function complete() {
  const prefix = buf.trimStart();
  const matches = Object.keys(COMMANDS).filter(n => n.startsWith(prefix) && n !== prefix);
  if (matches.length === 0) return;
  if (matches.length === 1) {
    buf = matches[0] + ' '; pos = buf.length; redraw();
  } else {
    /* List candidates, then restore the input line. */
    term.write('\r\n');
    writeln(matches.map(m => `${C.cyan}${m}${C.reset}`).join('   '));
    term.write(PROMPT + buf);
  }
}

/* -- Input handling --------------------------------------------------------- */
term.onData(data => {
  /* Ctrl+C: cancel a running command, or clear the current input line. */
  if (data === '\x03') {
    if (running && currentAbort) { currentAbort.abort(); return; }
    term.write('^C'); prompt(); return;
  }
  if (running) return; /* ignore keystrokes while a command streams */

  switch (data) {
    case '\r': { /* Enter */
      const line = buf;
      term.write('\r\n');
      if (line.trim()) { history.push(line); execute(line); }
      else prompt();
      return;
    }
    case '\x7f': /* Backspace */
      if (pos > 0) { buf = buf.slice(0, pos - 1) + buf.slice(pos); pos--; redraw(); }
      return;
    case '\t': /* Tab */
      complete();
      return;
    case '\x1b[A': /* Up */
      if (history.length === 0) return;
      if (histIdx === -1) histIdx = history.length;
      histIdx = Math.max(0, histIdx - 1);
      buf = history[histIdx]; pos = buf.length; redraw();
      return;
    case '\x1b[B': /* Down */
      if (histIdx === -1) return;
      histIdx++;
      if (histIdx >= history.length) { histIdx = -1; buf = ''; } else buf = history[histIdx];
      pos = buf.length; redraw();
      return;
    case '\x1b[C': /* Right */
      if (pos < buf.length) { pos++; term.write('\x1b[C'); }
      return;
    case '\x1b[D': /* Left */
      if (pos > 0) { pos--; term.write('\x1b[D'); }
      return;
    case '\x1b[H': pos = 0; redraw(); return; /* Home */
    case '\x1b[F': pos = buf.length; redraw(); return; /* End */
  }

  /* Printable input (filter control chars; allow pasted multi-char). */
  if (data >= ' ' || data.length > 1) {
    const clean = data.replace(/[\x00-\x1f\x7f]/g, '');
    if (!clean) return;
    buf = buf.slice(0, pos) + clean + buf.slice(pos);
    pos += clean.length;
    redraw();
  }
});

/* Cmd/Ctrl+K and Cmd/Ctrl+L clear the screen (handled before xterm sees it). */
term.attachCustomKeyEventHandler(e => {
  if (e.type === 'keydown' && (e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'l')) {
    term.clear();
    term.write('\r' + PROMPT + buf + '\x1b[K');
    return false;
  }
  return true;
});

document.getElementById('help-btn').addEventListener('click', () => {
  if (running) return;
  term.write('\r\n'); printHelp(); prompt(); term.focus();
});

/* -- Boot ------------------------------------------------------------------- */
(async () => {
  writeln(`${C.bold}Paramant debug CLI${C.reset}`);
  writeln(`${C.gray}Whitelisted commands only. Type 'help' to begin.${C.reset}`);
  await loadCommands();
  term.write(PROMPT);
  term.focus();
})();
