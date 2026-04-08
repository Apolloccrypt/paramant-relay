fetch('https://health.paramant.app/v2/ct/log?limit=1',{signal:AbortSignal.timeout(5000)})
  .then(function(r){return r.json()})
  .then(function(d){
    var ce=document.getElementById('ct-count');
    var re=document.getElementById('ct-root');
    if(ce && d.size!=null) ce.textContent=d.size.toLocaleString();
    if(re && d.root && d.root!=='0'.repeat(64)) re.textContent=d.root.slice(0,16)+'...'+d.root.slice(-8);
  }).catch(function(){});

fetch('https://health.paramant.app/health',{signal:AbortSignal.timeout(5000)}).then(function(r){return r.json()}).then(function(d){
  if(d.ok){
    document.getElementById('sdot').style.background='#2d6a4f';
    document.getElementById('stxt').textContent='All relays operational \u00b7 v'+d.version;
  }else{
    document.getElementById('stxt').textContent='Relay degraded';
  }
}).catch(function(){
  document.getElementById('sdot').style.background='#555';
  document.getElementById('stxt').textContent='Relay status unknown';
});
