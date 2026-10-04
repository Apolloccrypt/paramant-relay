// Text the standard PDF fonts cannot write, shared by /sign and /co-sign.
// See the comment above makeTextKit's caller in sign-flow.js: text the standard
// font can write stays in it; anything else goes in Noto Sans, embedded whole;
// a script Noto does not cover becomes a sharp image of that text. /co-sign
// used to replace every such letter with "?": "Ayşe Yılmaz" came out as
// "Ay?e Y?lmaz" in every co-signed PDF (acceptance test 2026-10-04).
function loadScriptOnce(src) {
  if (document.querySelector('script[src="' + src + '"]')) return;
  const el = document.createElement('script');
  el.src = src;
  document.head.appendChild(el);
}

const FONTKIT_SRC = '/vendor/fontkit/fontkit.umd.min.js?v=1';
const UNICODE_FONT_SRC = '/vendor/fonts/NotoSans-ParaSign.ttf?v=1';

async function waitForFontkit() {
  if (window.fontkit) return window.fontkit;
  loadScriptOnce(FONTKIT_SRC);
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (window.fontkit) return resolve(window.fontkit);
      if (Date.now() - start > 15000) return reject(Object.assign(new Error('fontkit failed to load'), { code: 'font_unavailable' }));
      setTimeout(tick, 50);
    };
    tick();
  });
}

export function canEncode(font, s) {
  try { font.encodeText(String(s)); return true; } catch (e) { return false; }
}

// One text writer per bake. roles: regular, bold, italic, mono. prepare() must
// run (once, with every string the bake will write) before width()/draw().
export function makeTextKit(PDFLib, pdfDoc, std) {
  let uni = null, uniSet = null;
  const images = new Map();
  const CSS = { regular: '400 {px}px sans-serif', bold: '700 {px}px sans-serif', italic: 'italic 400 {px}px serif', mono: '400 {px}px monospace' };
  const REF = 96;   // px per 1pt-at-size-1 x 4: the fallback image is drawn at 4x
  let measureCtx = null;
  const ctx2d = () => measureCtx || (measureCtx = document.createElement('canvas').getContext('2d'));
  const uniCovers = (s) => [...String(s)].every((ch) => /\s/.test(ch) || uniSet.has(ch.codePointAt(0)));
  const route = (s, role) => {
    const f = std[role] || std.regular;
    if (canEncode(f, s)) return { kind: 'std', font: f };
    if (uni && uniCovers(s)) return { kind: 'uni', font: uni };
    return { kind: 'img' };
  };
  const imgWidth1 = (s, role) => {
    const c = ctx2d();
    c.font = CSS[role].replace('{px}', String(REF));
    return c.measureText(String(s)).width / REF;
  };
  return {
    async prepare(strings) {
      const need = strings.filter((x) => x && !canEncode(std.regular, x));
      if (!need.length || uni) return;
      try {
        const fk = await waitForFontkit();
        const res = await fetch(UNICODE_FONT_SRC, { cache: 'force-cache' });
        if (!res.ok) throw new Error('font http ' + res.status);
        pdfDoc.registerFontkit(fk);
        // Whole font, not a subset: pdf-lib's fontkit subsetter dropped and
        // swapped glyphs of this font ("Ayşe Yılmaz" came out as "Ayse"). The
        // font is 211 KB and only travels in a PDF that needs it.
        uni = await pdfDoc.embedFont(new Uint8Array(await res.arrayBuffer()), { subset: false });
        uniSet = new Set(uni.getCharacterSet());
      } catch (e) {
        // No font: the image fallback still writes every name, just not as text.
        try { console.warn('[paramant] unicode font unavailable, using image text', e); } catch (_) { /* no console */ }
        uni = null;
      }
    },
    width(s, size, role = 'regular') {
      const r = route(s, role);
      return r.kind === 'img' ? imgWidth1(s, role) * size : r.font.widthOfTextAtSize(String(s), size);
    },
    async draw(pg, s, { x, y, size, role = 'regular', color, opacity }) {
      const text = String(s);
      const r = route(text, role);
      if (r.kind !== 'img') {
        const o = { x, y, size, font: r.font, color };
        if (opacity !== undefined) o.opacity = opacity;
        pg.drawText(text, o);
        return;
      }
      const key = role + '|' + (color ? [color.red, color.green, color.blue].join(',') : '') + '|' + text;
      let img = images.get(key);
      if (!img) {
        const c = document.createElement('canvas');
        const k = c.getContext('2d');
        const font = CSS[role].replace('{px}', String(REF));
        k.font = font;
        const w = Math.max(1, Math.ceil(k.measureText(text).width) + 4);
        c.width = w; c.height = Math.ceil(REF * 1.35);
        k.font = font;
        k.textBaseline = 'alphabetic';
        k.fillStyle = color ? `rgb(${Math.round(color.red * 255)},${Math.round(color.green * 255)},${Math.round(color.blue * 255)})` : '#000';
        k.fillText(text, 0, REF * 1.05);
        const b64 = c.toDataURL('image/png').split(',')[1];
        const bin = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
        img = { embed: await pdfDoc.embedPng(bin), w: c.width / REF, h: c.height / REF };
        images.set(key, img);
      }
      // Baseline at 1.05 of the reference size from the top: put it on y.
      const o = { x, y: y - (img.h - 1.05) * size, width: img.w * size, height: img.h * size };
      if (opacity !== undefined) o.opacity = opacity;
      pg.drawImage(img.embed, o);
    },
  };
}
