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
  if(kind==='login'){humanToken=result.token;$('identity').textContent='Passkey 已驗證 · 有效 15 分鐘';$('identity').className='authenticated';$('flow-subject').classList.add('verified');$('flow-identity-state').textContent='身分已驗證';show({subject:result.subject,authenticated:true});}
  else show(result);
}
function action(id,fn){$(id).onclick=async()=>{const button=$(id);button.disabled=true;try{await fn();await refresh();}catch(e){show(e.message);}finally{button.disabled=false;}};}
action('register',()=>passkey('register'));action('login',()=>passkey('login'));
action('session',async()=>{if(!humanToken)throw new Error('先使用 Passkey 驗證');const s=await api('/agent/session',{human_token:humanToken,path:$('path').value});sessionId=s.session_id;show({state:s.state,scope:s.scope,last:s.last});});
async function request(method='GET') {if(!sessionId)throw new Error('先建立 Session');const path=method==='POST'?'/api/salary':$('path').value;if(path==='/api/stream')throw new Error('請使用開啟持續串流按鈕');show(await api('/agent/request',{session_id:sessionId,path,method}));}
action('get',()=>request());action('post',()=>request('POST'));
action('revoke',async()=>{if(!sessionId)throw new Error('先建立 Session');await api('/revoke',{session_id:sessionId});});
for(const b of document.querySelectorAll('[data-sim]'))b.onclick=async()=>{b.disabled=true;try{show(await api('/simulate',{action:b.dataset.sim}));await refresh();}catch(e){show(e.message);}finally{b.disabled=false;}};
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
    const r=await fetch('/view');if(!r.ok)throw new Error('控制平面不可用');const v=await r.json();$('connection').textContent='控制平面已連線';$('connection-dot').className='online';
    const s=v.sessions.find(s=>s.session_id===sessionId),d=s?.last;
    $('subject').textContent=s?.subject||'alice（待驗證）';$('device').textContent=v.snapshot.device.id+(v.snapshot.device.compromised?' · COMPROMISED':'');
    $('request').textContent=d?.request?d.request.method+' '+d.request.path:'—';$('context').textContent=JSON.stringify(v.snapshot.context,null,2);
    $('score').textContent=d?`${d.trust_score} / Risk ${d.risk_score??'—'}`:'—';
    // Last request DENY should be visible even while its existing session stays active.
    const lastAction=v.events.find(e=>e.kind==='pa_action');const latestDecision=v.events.find(e=>e.kind==='pe_decision');
    $('decision').textContent=s?.state==='REVOKED'?'REVOKE':lastAction?.decision||lastAction?.last?.decision||d?.decision||latestDecision?.decision||'—';
    const lastRequest=lastAction?.request||lastAction?.last?.request||d?.request;
    if(lastRequest)$('request').textContent=lastRequest.method+' '+lastRequest.path;
    const decision=$('decision').textContent;
    $('decision').className='tag '+(decision==='ALLOW'?'allow':decision==='—'?'neutral':'deny');
    $('action').textContent=lastAction?.pa_action||s?.pa_action||'—';$('pep').textContent=s?.state==='REVOKED'?'BLOCKED':lastAction?.pep_state||s?.pep_state||'—';
    $('session-state').textContent=s?`${s.state} · ${s.scope.method} ${s.scope.path}`:'尚未建立 session';
    const evaluation=s?.state==='REVOKED'?d:lastAction?.trust_score!=null?lastAction:d||lastAction?.last||latestDecision;
    renderAssessment(evaluation,decision,s);
    renderEvents(v.events);
  }catch(e){$('connection').textContent='控制平面未連線';$('connection-dot').className='offline';}
}

const reasonLabels={required_conditions_met:'必要條件皆符合',human_identity_invalid_or_expired:'身分驗證失效或已過期',unmanaged_device:'裝置未納入管理',device_compromised:'裝置已遭入侵',least_privilege:'超出授權範圍（最小權限）',outdated_os:'作業系統版本過期',high_risk_ip:'來源 IP 被標記為高風險',abnormal_behavior:'偵測到異常流量行為',control_plane_unavailable:'控制平面不可用，停止授權',administrator_revocation:'管理者主動撤銷授權'};
const reasonText=values=>(values||[]).map(value=>reasonLabels[value]||value).join('；');
function renderAssessment(evaluation,decision,session){
  const score=Number(evaluation?.trust_score),hasScore=evaluation?.trust_score!=null&&Number.isFinite(score);
  $('trust-number').textContent=hasScore?score:'—';
  $('gauge-value').setAttribute('stroke-dasharray',`${hasScore?Math.max(0,Math.min(100,score)):0} 100`);
  $('score-gauge').classList.toggle('denied',decision==='DENY'||decision==='REVOKE');
  $('score').textContent=hasScore?`Risk ${evaluation.risk_score??'—'} · 門檻 ${evaluation.threshold??'—'}`:'等待評估';
  $('decision-label').textContent={ALLOW:'ALLOW · 允許存取',DENY:'DENY · 拒絕請求',REVOKE:'REVOKE · 撤銷授權'}[decision]||'等待評估';
  $('decision-reason').textContent=reasonText(evaluation?.reasons)||'完成身分驗證與資源存取後，這裡會顯示 PE 的判斷原因。';
  $('session-badge').textContent=session?.state||'NO SESSION';
  $('session-badge').className='tag '+(session?.state==='REVOKED'?'deny':session?.state==='ACTIVE'?'allow':'neutral');
  const blocked=$('pep').textContent==='BLOCKED',allowed=['FORWARD','AUTHORIZED'].includes($('pep').textContent);
  $('flow-pep').classList.toggle('blocked',blocked);$('flow-pep').classList.toggle('allowed',allowed);
  $('flow-pdp').classList.toggle('blocked',decision==='DENY'||decision==='REVOKE');$('flow-pdp').classList.toggle('allowed',decision==='ALLOW');
  $('flow-resource').classList.toggle('blocked',blocked);$('flow-resource').classList.toggle('allowed',$('pep').textContent==='FORWARD');
  $('flow-pep-state').textContent=blocked?'已阻擋':allowed?'路徑已授權':'等待請求';
  $('flow-pdp-state').textContent=decision==='—'?'持續重新評估':decision;
  $('flow-resource-state').textContent=blocked?'存取被阻擋':$('pep').textContent==='FORWARD'?'PEP 已放行':'等待授權';
}
function renderEvents(events){
  $('events').replaceChildren();$('event-count').textContent=`${events.length} 筆紀錄`;
  if(!events.length){const empty=document.createElement('p');empty.className='empty-state';empty.textContent='尚無活動。每次存取與重新評估都會留下紀錄。';$('events').append(empty);return;}
  const kinds={pa_action:'PA 授權動作',pe_decision:'PE 信任決策',request:'存取請求',simulation:'情境訊號',policy:'政策更新'};
  for(const e of events.slice(0,30)){
    const row=document.createElement('div');row.className='event';
    const time=document.createElement('span');time.className='event-time';time.textContent=new Date(e.timestamp*1000).toLocaleTimeString('zh-TW',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const body=document.createElement('div');body.className='event-body';const title=document.createElement('div');title.className='event-title';
    const kind=document.createElement('strong');kind.textContent=kinds[e.kind]||e.kind;title.append(kind);
    const decision=e.decision||e.last?.decision;
    if(decision){const badge=document.createElement('span');badge.className='tag '+(decision==='ALLOW'?'allow':'deny');badge.textContent=decision;title.append(badge);}
    const description=document.createElement('span');description.textContent=reasonText(e.reasons||e.last?.reasons)||e.pa_action||e.action||'已記錄';body.append(title,description);row.append(time,body);$('events').append(row);
  }
}
for(const link of document.querySelectorAll('.nav-item'))link.addEventListener('click',()=>{for(const other of document.querySelectorAll('.nav-item'))other.classList.toggle('active',other===link);});
refresh();setInterval(refresh,1500);
