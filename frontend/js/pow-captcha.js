(function () {
  'use strict';

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hasLeadingZeroBits(hex, bits) {
    const full = Math.floor(bits / 4);
    const rem = bits % 4;
    for (let i = 0; i < full; i++) if (hex[i] !== '0') return false;
    if (rem === 0) return true;
    return (parseInt(hex[full], 16) & (0xF << (4 - rem))) === 0;
  }

  async function solveChallenge(id, salt, difficulty, onProgress) {
    let nonce = 0;
    const t0 = performance.now();
    while (true) {
      const hash = await sha256Hex(id + salt + String(nonce));
      if (hasLeadingZeroBits(hash, difficulty)) {
        return { nonce, elapsed_ms: Math.round(performance.now() - t0) };
      }
      nonce++;
      if (onProgress && nonce % 10000 === 0) {
        onProgress(nonce);
        await new Promise(r => setTimeout(r, 0)); // yield to UI
      }
    }
  }

  async function getCaptchaProof(onProgress) {
    const res = await fetch('/api/captcha/challenge');
    if (!res.ok) throw new Error('captcha_unavailable');
    const { challenge_id, salt, difficulty } = await res.json();
    const { nonce, elapsed_ms } = await solveChallenge(challenge_id, salt, difficulty, onProgress);
    return { challenge_id, nonce, elapsed_ms };
  }

  window.ParamantCaptcha = { getCaptchaProof };
})();
