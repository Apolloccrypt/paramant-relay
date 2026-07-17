// Screen-flash liveness, proof of concept.
//
// The screen emits a random sequence of colours (a light nonce). The front
// camera watches your face. Real skin reflects that changing light back with
// the right timing and colour; a printed photo or a replayed video cannot,
// because the challenge is only chosen at the moment of capture. We measure the
// correlation between what the screen emitted and what the camera saw.
//
// Everything runs on this device. The video frames never leave the page: the
// network counter stays at zero (that is the counter proving itself).
'use strict';

const $ = (id) => document.getElementById(id);
const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
const lum = (r, g, b) => 0.2126 * r + 0.7152 * g + 0.0722 * b;

let stream = null;
let running = false;

// A random challenge: N steps, each a colour the screen will show. Mixing full
// R / G / B / white / dark so we can measure a per-channel response, not just
// brightness. The order is unpredictable, so it cannot be pre-rendered.
function buildChallenge(n) {
  const palette = [
    { r: 255, g: 30, b: 30 }, { r: 30, g: 255, b: 30 }, { r: 40, g: 60, b: 255 },
    { r: 255, g: 255, b: 255 }, { r: 12, g: 12, b: 18 }, { r: 255, g: 210, b: 40 },
  ];
  const seq = [];
  let prev = -1;
  for (let i = 0; i < n; i++) {
    let k; do { k = Math.floor(Math.random() * palette.length); } while (k === prev);
    prev = k; seq.push(palette[k]);
  }
  return seq;
}

async function start() {
  if (running) return;
  $('lv-error').hidden = true;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
  } catch (e) {
    $('lv-error').textContent = 'Camera access is needed and was blocked: ' + (e.message || e);
    $('lv-error').hidden = false;
    return;
  }
  running = true;
  $('lv-start').disabled = true;
  $('lv-result').hidden = true;

  const video = $('lv-video');
  video.srcObject = stream;
  await video.play().catch(() => {});

  const cv = document.createElement('canvas');
  cv.width = 64; cv.height = 48;
  const ctx = cv.getContext('2d', { willReadFrequently: true });

  // Full-screen flash: the whole viewport becomes the light source so the
  // monitor actually illuminates the face. A small preview stays on top so the
  // user can keep framed. Without this the screen emits almost no usable light.
  const overlay = $('lv-flash');
  document.body.classList.add('lv-flashing');
  overlay.classList.add('on');

  const STEP_MS = 300, STEPS = 16;
  const challenge = buildChallenge(STEPS);
  let current = challenge[0];
  const samples = [];   // { t, em:{r,g,b}, me:{r,g,b} }
  const t0 = performance.now();

  // Flash stepper: drives the full-screen colour.
  let step = 0;
  overlay.style.background = `rgb(${current.r},${current.g},${current.b})`;
  const flashTimer = setInterval(() => {
    step++;
    if (step >= challenge.length) { clearInterval(flashTimer); return; }
    current = challenge[step];
    overlay.style.background = `rgb(${current.r},${current.g},${current.b})`;
  }, STEP_MS);

  // Sample loop: read the centre region of the camera each frame.
  function sampleLoop() {
    if (!running) return;
    const t = performance.now() - t0;
    if (t > STEP_MS * STEPS + 200) { finish(samples, challenge); return; }
    try {
      ctx.drawImage(video, 0, 0, cv.width, cv.height);
      // Centre box: the face fills the middle; avoid the edges (background).
      const x0 = 20, y0 = 14, w = 24, h = 20;
      const d = ctx.getImageData(x0, y0, w, h).data;
      let R = 0, G = 0, B = 0, n = 0;
      for (let i = 0; i < d.length; i += 4) { R += d[i]; G += d[i + 1]; B += d[i + 2]; n++; }
      samples.push({ t, em: current, me: { r: R / n, g: G / n, b: B / n } });
      $('lv-live').textContent = 'measuring… ' + samples.length + ' frames';
    } catch (_) { /* frame not ready */ }
    requestAnimationFrame(sampleLoop);
  }
  requestAnimationFrame(sampleLoop);
}

// Pearson correlation with a small lag search (the physical response lags the
// emission by a frame or two; the best-lag correlation is the liveness signal).
function bestCorr(a, b) {
  const n = Math.min(a.length, b.length);
  if (n < 6) return 0;
  const norm = (arr) => {
    const m = arr.reduce((s, x) => s + x, 0) / arr.length;
    const sd = Math.sqrt(arr.reduce((s, x) => s + (x - m) * (x - m), 0) / arr.length) || 1;
    return arr.map((x) => (x - m) / sd);
  };
  const A = norm(a), B = norm(b);
  let best = 0;
  for (let lag = 0; lag <= 4; lag++) {
    let s = 0, c = 0;
    for (let i = 0; i + lag < n; i++) { s += A[i] * B[i + lag]; c++; }
    if (c) best = Math.max(best, s / c);
  }
  return best;
}

// Chromaticity: colour ratios that survive the camera's auto-exposure. When the
// screen flashes red, the face gets redder in RATIO even if the webcam pulls the
// overall brightness back down. This is the robust liveness signal on a monitor.
function chroma(c) { const s = c.r + c.g + c.b + 1; return { r: c.r / s, g: c.g / s, b: c.b / s }; }

function finish(samples, challenge) {
  running = false;
  $('lv-flash').classList.remove('on');
  document.body.classList.remove('lv-flashing');
  $('lv-start').disabled = false;
  if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }

  const em = samples.map((s) => chroma(s.em));
  const me = samples.map((s) => chroma(s.me));
  // Did the measured chromaticity move at all? If not, nothing was illuminating.
  const chVar = (() => { const arr = me.map((c) => c.r); const m = arr.reduce((a, b) => a + b, 0) / (arr.length || 1); return arr.reduce((a, b) => a + (b - m) * (b - m), 0) / (arr.length || 1); })();

  const rCorr = bestCorr(em.map((c) => c.r), me.map((c) => c.r));
  const gCorr = bestCorr(em.map((c) => c.g), me.map((c) => c.g));
  const bCorr = bestCorr(em.map((c) => c.b), me.map((c) => c.b));
  const colourCoherence = clamp((rCorr + gCorr + bCorr) / 3, 0, 1);
  // Brightness still helps a bit as a secondary signal (dark room, phone close).
  const lumCorr = bestCorr(samples.map((s) => lum(s.em.r, s.em.g, s.em.b)), samples.map((s) => lum(s.me.r, s.me.g, s.me.b)));

  const score = Math.round(clamp(0.8 * colourCoherence + 0.2 * clamp(lumCorr, 0, 1), 0, 1) * 100);

  let verdict, cls;
  if (chVar < 0.00002) { verdict = 'Inconclusive: no colour change reached the camera. Face the screen straight on and retry (the screen must light your face).'; cls = 'warn'; }
  else if (score >= 45) { verdict = 'Responds to the light challenge. Consistent with a live, present subject.'; cls = 'ok'; }
  else if (score >= 22) { verdict = 'Weak response. Sit closer to the screen with less room light, then retry.'; cls = 'warn'; }
  else { verdict = 'No coherent response to the challenge. A photo or a replayed video looks like this.'; cls = 'err'; }

  const out = $('lv-result');
  out.hidden = false;
  out.className = 'lv-result ' + cls;
  out.innerHTML =
    '<p class="lv-score">Liveness score: <b>' + score + ' / 100</b></p>' +
    '<p class="lv-verdict">' + verdict + '</p>' +
    '<div class="lv-bars">' +
    bar('red light reflects back', rCorr) +
    bar('green light reflects back', gCorr) +
    bar('blue light reflects back', bCorr) +
    bar('brightness follows (secondary)', lumCorr) +
    '</div>' +
    '<p class="lv-note">Measured on colour ratio, which survives the camera&rsquo;s auto-exposure. The challenge was random and only known at capture, so a pre-recorded video cannot match it. Proof of concept: production adds face-region tracking and the document check. Best results sitting close to the screen with modest room light.</p>';
  $('lv-live').textContent = '';
}

function bar(label, v) {
  const pct = Math.round(clamp(v, 0, 1) * 100);
  return '<div class="lv-bar"><span>' + label + '</span><i style="width:' + pct + '%"></i><em>' + pct + '%</em></div>';
}

// Network meter: proves the video never uploads.
function initNetMeter() {
  const el = $('lv-netcount');
  if (!el || !('PerformanceObserver' in window)) return;
  let count = 0, base = false;
  new PerformanceObserver((list) => {
    for (const e of list.getEntries()) { if (!base) continue; count++; el.textContent = String(count); el.parentElement.classList.add('dirty'); }
  }).observe({ type: 'resource', buffered: false });
  window.addEventListener('load', () => setTimeout(() => { base = true; }, 1000));
  if (document.readyState === 'complete') setTimeout(() => { base = true; }, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
  initNetMeter();
  $('lv-start').addEventListener('click', start);
});
