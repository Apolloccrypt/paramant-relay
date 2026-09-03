// Contrast and tap-target audit over the six marketing screens, in both themes
// and at both widths, so the accessibility claims in the PR are measured rather
// than asserted.
//
// Every text node is flattened against its first OPAQUE ancestor background,
// the way a browser actually paints it, and element opacity is folded in: a
// label at .5 opacity is 3.35:1 no matter what its colour token says, and that
// is exactly the defect this found on the homepage.
//
// It is a report, not a gate: it prints what it measured and exits 0. The
// numbers it produced on the branch that introduced it are 4118 text pairs over
// 24 combinations with nothing under AA, lowest 4.94.
//
// Run: node scripts/audit-marketing-a11y.mjs
import { chromium } from 'playwright';
import http from 'node:http'; import fs from 'node:fs'; import path from 'node:path';
const ROOT=path.join(path.dirname(new URL(import.meta.url).pathname),'..','frontend');
const MIME={'.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.json':'application/json','.ico':'image/x-icon'};
const al={'/':'/index.html','/pricing':'/pricing.html','/parasign':'/parasign.html','/parasend':'/parasend.html','/about':'/about.html','/security':'/security.html'};
const s=http.createServer((q,r)=>{let p=decodeURIComponent(new URL(q.url,'http://x').pathname);p=al[p]||p;const f=path.join(ROOT,p);fs.readFile(f,(e,b)=>{if(e){r.writeHead(404);return r.end();}r.writeHead(200,{'content-type':MIME[path.extname(f)]||'application/octet-stream'});r.end(b);});});
await new Promise(r=>s.listen(0,'127.0.0.1',r));
const O=`http://localhost:${s.address().port}`;
const br=await chromium.launch();

const SCRIPT = () => {
  const parse = (c) => { const m=c.match(/[\d.]+/g)||[]; return [ +m[0]||0, +m[1]||0, +m[2]||0, m[3]===undefined?1:+m[3] ]; };
  const over = (fg,bg)=>{const a=fg[3];return [fg[0]*a+bg[0]*(1-a), fg[1]*a+bg[1]*(1-a), fg[2]*a+bg[2]*(1-a),1];};
  const lum = (c)=>{const f=(v)=>{v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);};return .2126*f(c[0])+.7152*f(c[1])+.0722*f(c[2]);};
  const ratio=(a,b)=>{const l1=lum(a),l2=lum(b);return (Math.max(l1,l2)+.05)/(Math.min(l1,l2)+.05);};
  const bgOf=(el)=>{
    const stack=[]; let n=el;
    while(n){ const c=parse(getComputedStyle(n).backgroundColor); if(c[3]>0){stack.push(c); if(c[3]===1) break;} n=n.parentElement; }
    let base=parse(getComputedStyle(document.documentElement).backgroundColor); if(base[3]<1) base=[255,255,255,1];
    let out=base;
    for(let i=stack.length-1;i>=0;i--) out=over(stack[i],out);
    return out;
  };
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  const bad=[]; let pairs=0; let min={r:99,what:''};
  for(let n=walker.nextNode();n;n=walker.nextNode()){
    const t=(n.nodeValue||'').trim(); if(!t) continue;
    const el=n.parentElement; if(!el) continue;
    if(['SCRIPT','STYLE','NOSCRIPT'].includes(el.tagName)) continue;
    const cs=getComputedStyle(el);
    if(cs.visibility==='hidden'||cs.display==='none') continue;
    const rect=el.getBoundingClientRect(); if(!rect.width||!rect.height) continue;
    const size=parseFloat(cs.fontSize); const weight=+cs.fontWeight||400;
    const large = size>=24 || (size>=18.66 && weight>=700);
    const need = large?3:4.5;
    const bg=bgOf(el);
    // Element opacity paints the text AND its own background against whatever
    // is behind, so it lowers contrast exactly like an alpha on the colour.
    let op=1; for(let a=el; a && a!==document.documentElement; a=a.parentElement) op*=parseFloat(getComputedStyle(a).opacity||'1');
    const c0=parse(cs.color); c0[3]=c0[3]*op;
    const fg=over(c0,bg);
    const r=ratio(fg,bg);
    pairs++;
    if(r<min.r) min={r:+r.toFixed(2),what:`${el.tagName}.${el.className||''} "${t.slice(0,40)}" ${cs.color} on rgb(${bg.slice(0,3).map(Math.round)})`};
    if(r<need) bad.push(`${r.toFixed(2)} (need ${need}) ${el.tagName}.${(el.className||'').toString().slice(0,40)} ${size}px/${weight} "${t.slice(0,48)}" ${cs.color} on rgb(${bg.slice(0,3).map(Math.round).join(',')})`);
  }
  // tap targets on a coarse pointer
  const small=[];
  for(const el of document.querySelectorAll('a[href],button,input,select,summary,[role="button"]')){
    const cs=getComputedStyle(el); if(cs.display==='none'||cs.visibility==='hidden') continue;
    const r=el.getBoundingClientRect(); if(!r.width||!r.height) continue;
    if(el.closest('p, li, .about-band p, .ps-band p')) continue; // inline reading links
    if(r.height<44||r.width<24) small.push(`${Math.round(r.width)}x${Math.round(r.height)} ${el.tagName}.${(el.className||'').toString().slice(0,34)} "${(el.textContent||'').trim().slice(0,32)}"`);
  }
  return { pairs, bad, min, small };
};

let totalPairs=0, totalBad=0, allMin=99, minWhat='';
const smallSeen=new Set();
for(const [slug] of Object.entries(al)){
  for(const scheme of ['light','dark']){
    for(const [w,h,coarse] of [[390,844,true],[1440,900,false]]){
      const ctx=await br.newContext({viewport:{width:w,height:h},colorScheme:scheme, ...(coarse?{hasTouch:true,isMobile:true}:{})});
      const pg=await ctx.newPage();
      await pg.route('**/api/user/session/verify',r=>r.fulfill({status:401,contentType:'application/json',body:'{"authenticated":false}'}));
      await pg.goto(O+slug,{waitUntil:'networkidle'});
      const res=await pg.evaluate(SCRIPT);
      totalPairs+=res.pairs; totalBad+=res.bad.length;
      if(res.min.r<allMin){allMin=res.min.r;minWhat=`${slug} ${scheme} ${w}: ${res.min.what}`;}
      if(res.bad.length) console.log(`--- ${slug} ${scheme} ${w}x${h}: ${res.bad.length} under AA`), res.bad.slice(0,12).forEach(b=>console.log('    '+b));
      if(coarse) res.small.forEach(x=>smallSeen.add(`${slug} ${scheme}: ${x}`));
      await ctx.close();
    }
  }
}
console.log(`\nCONTRAST: ${totalPairs} text pairs over 24 combinations, ${totalBad} under AA.`);
console.log(`lowest measured: ${allMin}  (${minWhat})`);
console.log(`\nTAP TARGETS under 44px on a coarse pointer at 390px: ${smallSeen.size}`);
[...smallSeen].slice(0,25).forEach(x=>console.log('    '+x));
await br.close();s.close();
