(function(){
  const RELAYS = [
    {name:"relay",   url:"https://relay.paramant.app",   stat:"ps-main"},
    {name:"health",  url:"https://health.paramant.app",  stat:"ps-health"},
    {name:"legal",   url:"https://legal.paramant.app",   stat:"ps-legal"},
    {name:"finance", url:"https://finance.paramant.app", stat:"ps-finance"},
    {name:"iot",     url:"https://iot.paramant.app",     stat:"ps-iot"},
  ];

  const pc = document.getElementById("pipeCanvas");
  const pctx = pc.getContext("2d");
  let pdots = [], relayStatus = {};

  function resizeCanvas(c){
    const r = c.getBoundingClientRect();
    c.width  = r.width  * devicePixelRatio;
    c.height = r.height * devicePixelRatio;
  }

  function drawPipe(){
    resizeCanvas(pc);
    const cw = pc.width/devicePixelRatio, ch = pc.height/devicePixelRatio;
    pctx.clearRect(0,0,cw,ch);
    const LX = 100, RX = cw - 20;

    RELAYS.forEach((r,i) => {
      const y = ((i+1)/(RELAYS.length+1)) * ch;
      const on = relayStatus[r.name]?.ok || relayStatus[r.name]?.status === 'ok';

      pctx.strokeStyle = "#252525";
      pctx.lineWidth = 1;
      pctx.setLineDash([4, 8]);
      pctx.beginPath(); pctx.moveTo(LX, y); pctx.lineTo(RX, y); pctx.stroke();
      pctx.setLineDash([]);

      pctx.fillStyle = "#161616";
      pctx.strokeStyle = on ? "#2d7a50" : "#383838";
      pctx.lineWidth = 1.5;
      pctx.beginPath(); pctx.arc(LX-24, y, 11, 0, Math.PI*2); pctx.fill(); pctx.stroke();

      pctx.fillStyle = on ? "#3aaa70" : "#484848";
      pctx.beginPath(); pctx.arc(LX-24, y, 4, 0, Math.PI*2); pctx.fill();

      pctx.fillStyle = on ? "#cccccc" : "#666";
      pctx.font = "500 11px 'SF Mono','Fira Code',monospace";
      pctx.textAlign = "left";
      pctx.fillText(r.name.toUpperCase(), LX+4, y+4);

      if(relayStatus[r.name]?.uptime_s != null){
        pctx.fillStyle = "#666";
        pctx.font = "10px 'SF Mono','Fira Code',monospace";
        pctx.textAlign = "right";
        pctx.fillText(Math.floor(relayStatus[r.name].uptime_s/3600)+"h up", RX-6, y+4);
      }
    });

    pdots.forEach(d => {
      const y = ((d.relay+1)/(RELAYS.length+1)) * ch;
      d.x += d.speed;
      const alpha = Math.min(1, Math.min(d.x - LX, RX - d.x) / 40);
      const a = Math.max(0, alpha);

      pctx.globalAlpha = a * 0.18;
      pctx.fillStyle = "#3aaa70";
      pctx.beginPath(); pctx.arc(d.x, y, 9, 0, Math.PI*2); pctx.fill();

      pctx.globalAlpha = a * 0.95;
      pctx.fillStyle = "#3aaa70";
      pctx.beginPath(); pctx.arc(d.x, y, 3.5, 0, Math.PI*2); pctx.fill();

      pctx.globalAlpha = 1;
    });
    pdots = pdots.filter(d => d.x < RX);
  }

  function spawnDot(i){ pdots.push({x:100,relay:i,speed:1.5+Math.random()*1.5}); }

  function updateLiveCount(){
    const online = RELAYS.filter(r => relayStatus[r.name]?.ok).length;
    const el = document.getElementById("stat-relay-count");
    if(el) el.textContent = online || RELAYS.length;

    const stxt = document.getElementById("stxt");
    const sdot = document.getElementById("sdot");
    if(stxt){
      const checked = Object.keys(relayStatus).length;
      if(checked === 0) return;
      if(online === RELAYS.length){
        stxt.textContent = "All relays operational \u00b7 v2.4.5";
        if(sdot) sdot.style.background = "#3aaa70";
      } else if(online > 0){
        stxt.textContent = online + " of " + RELAYS.length + " relays online";
        if(sdot) sdot.style.background = "#e67e22";
      } else {
        stxt.textContent = "Relay status unknown";
        if(sdot) sdot.style.background = "#555";
      }
    }
  }

  async function pollRelay(r,i){
    try{
      const d = await fetch(r.url+"/health",{signal:AbortSignal.timeout(4000)}).then(x=>x.json());
      relayStatus[r.name] = {...d, ok: d.ok || d.status === 'ok'};
      const el = document.getElementById(r.stat);
      if(el) el.textContent = d.uptime_s != null ? "v"+d.version+" · "+Math.floor(d.uptime_s/3600)+"h" : "v"+d.version;
      spawnDot(i);
    }catch(e){
      relayStatus[r.name]={ok:false};
      const el=document.getElementById(r.stat);
      if(el) el.textContent="offline";
    }
    updateLiveCount();
  }

  RELAYS.forEach((r,i)=>{ pollRelay(r,i); setInterval(()=>pollRelay(r,i),20000); });
  RELAYS.forEach((_,i)=>setTimeout(()=>spawnDot(i),i*300+100));
  setInterval(()=>{
    const online=RELAYS.map((r,i)=>({r,i})).filter(x=>relayStatus[x.r.name]?.ok);
    if(online.length){ const pick=online[Math.floor(Math.random()*online.length)]; spawnDot(pick.i); }
  },2000);

  function loop(){
    drawPipe();
    const el=document.getElementById("pipe-ts");
    if(el) el.textContent=new Date().toLocaleTimeString();
    requestAnimationFrame(loop);
  }
  loop();
})();
