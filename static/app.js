let humanToken='', sessionId='', streamController=null;
const $=id=>document.getElementById(id);
const show=value=>{$('result').textContent=typeof value==='string'?value:JSON.stringify(value,null,2);};
async function api(path,body,method='POST'){
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await r.json(); if(!r.ok)throw new Error(JSON.stringify(data)); return data;
}
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function passkey(kind){
  if(!window.PublicKeyCredential)throw new Error('請使用支援 WebAuthn 的 Chrome / Edge，網址需為 http://localhost:8080');
  const o=await api('/identity/'+kind+'/options',{}),p=o.publicKey;
  p.challenge=decode(p.challenge);
  if(p.user)p.user.id=decode(p.user.id);
  for(const k of ['allowCredentials','excludeCredentials'])if(p[k])p[k]=p[k].map(c=>({...c,id:decode(c.id)}));
  const c=kind==='register'?await navigator.credentials.create({publicKey:p}):await navigator.credentials.get({publicKey:p});
  const response={clientDataJSON:encode(c.response.clientDataJSON)};
  if(kind==='register'){response.attestationObject=encode(c.response.attestationObject);response.transports=c.response.getTransports?.()||[];}
  else{response.authenticatorData=encode(c.response.authenticatorData);response.signature=encode(c.response.signature);response.userHandle=c.response.userHandle?encode(c.response.userHandle):null;}
  const result=await api('/identity/'+kind+'/verify',{ceremony:o.ceremony,credential:{id:c.id,rawId:encode(c.rawId),type:c.type,response}});
  if(kind==='login'){humanToken=result.token;$('identity').textContent='alice · Passkey 已驗證（15 分鐘）';show({subject:result.subject,authenticated:true});}
  else show(result);
}
function action(id,fn){$(id).onclick=async()=>{try{await fn();await refresh();}catch(e){show(e.message);}};}
action('register',()=>passkey('register'));action('login',()=>passkey('login'));
action('session',async()=>{if(!humanToken)throw new Error('先使用 Passkey 驗證');const s=await api('/agent/session',{human_token:humanToken,path:$('path').value});sessionId=s.session_id;show({state:s.state,scope:s.scope,last:s.last});});
async function request(method='GET') {if(!sessionId)throw new Error('先建立 Session');const path=method==='POST'?'/api/salary':$('path').value;if(path==='/api/stream')throw new Error('請使用開啟持續串流按鈕');show(await api('/agent/request',{session_id:sessionId,path,method}));}
action('get',()=>request());action('post',()=>request('POST'));
action('revoke',async()=>{if(!sessionId)throw new Error('先建立 Session');await api('/revoke',{session_id:sessionId});});
for(const b of document.querySelectorAll('[data-sim]'))b.onclick=async()=>{try{show(await api('/simulate',{action:b.dataset.sim}));await refresh();}catch(e){show(e.message);}};
action('burst',async()=>{for(let i=0;i<14;i++)await request();});
action('policy',async()=>show(await api('/policy',{threshold:Number($('threshold').value),grants:{alice:['GET /api/salary','GET /api/profile','GET /api/stream']}},'PUT')));
action('remove-grant',async()=>show(await api('/policy',{threshold:Number($('threshold').value),grants:{alice:[]}},'PUT')));
action('stream',async()=>{
  if(!sessionId)throw new Error('先建立 /api/stream Session');streamController?.abort();streamController=new AbortController();
  const r=await fetch('/agent/stream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId}),signal:streamController.signal});
  if(!r.ok)throw new Error(await r.text());const reader=r.body.getReader(),decoder=new TextDecoder();show('');
  try{while(true){const {done,value}=await reader.read();if(done)break;$('result').textContent+=decoder.decode(value,{stream:true});$('result').scrollTop=$('result').scrollHeight;}}catch(e){if(e.name!=='AbortError')throw e;}
});
action('stop-stream',async()=>streamController?.abort());
async function refresh(){
  try{
    const r=await fetch('/view');if(!r.ok)throw new Error('控制平面不可用');const v=await r.json();$('connection').textContent='Control Plane · ONLINE';
    const s=v.sessions.find(s=>s.session_id===sessionId),d=s?.last;
    $('subject').textContent=s?.subject||'alice（待驗證）';$('device').textContent=v.snapshot.device.id+(v.snapshot.device.compromised?' · COMPROMISED':'');
    $('request').textContent=d?.request?d.request.method+' '+d.request.path:'—';$('context').textContent=JSON.stringify(v.snapshot.context,null,2);
    $('score').textContent=d?`${d.trust_score} / Risk ${d.risk_score??'—'}`:'—';
    // Last request DENY should be visible even while its existing session stays active.
    const lastAction=v.events.find(e=>e.kind==='pa_action');const latestDecision=v.events.find(e=>e.kind==='pe_decision');
    $('decision').textContent=s?.state==='REVOKED'?'REVOKE':lastAction?.decision||lastAction?.last?.decision||d?.decision||latestDecision?.decision||'—';
    const lastRequest=lastAction?.request||lastAction?.last?.request||d?.request;
    if(lastRequest)$('request').textContent=lastRequest.method+' '+lastRequest.path;
    $('decision').className=$('decision').textContent==='ALLOW'?'allow':'deny';
    $('action').textContent=lastAction?.pa_action||s?.pa_action||'—';$('pep').textContent=s?.state==='REVOKED'?'BLOCKED':lastAction?.pep_state||s?.pep_state||'—';
    $('session-state').textContent=s?`${s.state} · ${s.scope.method} ${s.scope.path}`:'尚未建立 session';
    $('events').replaceChildren();for(const e of v.events.slice(0,30)){const row=document.createElement('div');row.className='event';row.textContent=new Date(e.timestamp*1000).toLocaleTimeString()+' · '+e.kind+' · '+(e.decision||e.pa_action||e.action||'')+' '+(e.reasons?.join(', ')||'');$('events').append(row);}
  }catch(e){$('connection').textContent=e.message;}
}
refresh();setInterval(refresh,1500);
