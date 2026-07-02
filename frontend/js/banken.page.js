'use strict';

async function demoKeygen(){
  const kp = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const pub = Array.from(new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey))).map(b=>b.toString(16).padStart(2,'0')).join('');
  document.getElementById('demo-pub').style.display='block';
  document.getElementById('demo-pub-val').textContent=pub;
  document.getElementById('demo-result').style.display='block';
  document.getElementById('demo-result').textContent='✓ Keypair gegenereerd. Publieke sleutel klaar om te delen met uw counterparty.';
}

act('click','demoKeygen',()=>demoKeygen());act('click','copyText',(el)=>{ if(navigator.clipboard) navigator.clipboard.writeText(el.textContent); });
