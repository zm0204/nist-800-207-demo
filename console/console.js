const $=id=>document.getElementById(id);
let csrf='',humanToken='',writeToken='',sessions={},busy=false,lastResult=null;
const dump=value=>JSON.stringify(value,null,2);
async function api(path,body,method=body===undefined?'GET':'POST'){
  const response=await fetch(path,{method,headers:{'Content-Type':'application/json','x-mesh-console':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await response.json();if(!response.ok)throw new Error(data.detail||dump(data));return data;
}
function error(message){$('error').textContent=message;$('error').hidden=!message;}
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function passkey(kind){
  if(!window.PublicKeyCredential)throw new Error('請使用支援 WebAuthn 的 Chrome / Edge，網址為 http://localhost:18081');
  const subject=$('subject').value;
  let options={subject};
  if(kind==='register'){
    options={};
    const invite=await api('/api/inspector/invite',{subject});options={invitation:invite.invitation};
  }
  const o=await api('/api/identity/'+kind+'/options',options),p=o.publicKey;
  p.challenge=decode(p.challenge);if(p.user)p.user.id=decode(p.user.id);
  for(const key of ['allowCredentials','excludeCredentials'])if(p[key])p[key]=p[key].map(c=>({...c,id:decode(c.id)}));
  const c=kind==='register'?await navigator.credentials.create({publicKey:p}):await navigator.credentials.get({publicKey:p});
  if(!c)throw new Error('Passkey 操作已取消');
  const response={clientDataJSON:encode(c.response.clientDataJSON)};
  if(kind==='register'){response.attestationObject=encode(c.response.attestationObject);response.transports=c.response.getTransports?.()||[];}
  else{response.authenticatorData=encode(c.response.authenticatorData);response.signature=encode(c.response.signature);response.userHandle=c.response.userHandle?encode(c.response.userHandle):null;}
  const result=await api('/api/identity/'+kind+'/verify',{ceremony:o.ceremony,credential:{id:c.id,rawId:encode(c.rawId),type:c.type,response}});
  if(kind==='login'){
    humanToken=result.token;sessions={};writeToken='';$('human-label').textContent=result.subject+' · Passkey 已驗證';$('user-value').textContent=result.subject+' / '+(result.subject==='bob'?'hr':'employee');$('auth-state').textContent='PASSKEY VERIFIED';$('auth-state').className='pill allow';
  }else{$('auth-state').textContent='PASSKEY ENROLLED · 請登入';}
  return result;
}
async function credential(resource,scope,stepUpToken){
  if(!humanToken)throw new Error('請先使用真正的 Passkey 登入');
  if(!sessions[resource]){const s=await api('/api/agent/session',{human_token:humanToken,resource});sessions[resource]=s.session_id;$('device-value').textContent=s.device_id;$('session-value').textContent=s.state+' · '+s.scope.path;}
  const token=await api('/api/agent/exchange',{session_id:sessions[resource],scope,step_up_token:stepUpToken});
  $('jwt-expiry').textContent='已簽發 JWT · 有效 '+token.expires_in+' 秒';$('auth-state').textContent='SESSION + JWT';
  return token.access_token;
}
function action(id,fn){$(id).addEventListener('click',async()=>{if(busy)return;busy=true;error('');for(const el of document.querySelectorAll('button'))el.disabled=true;try{await fn();}catch(e){error(String(e.message));}finally{busy=false;for(const el of document.querySelectorAll('button'))el.disabled=false;}});}
action('register',()=>passkey('register'));
action('login',async()=>{await passkey('login');await credential($('resource').value);});
action('step-up',async()=>{const fresh=await passkey('login');writeToken=await credential('salary','salary:write',fresh.token);$('auth-state').textContent='FRESH SALARY:WRITE';});
$('subject').addEventListener('change',()=>{humanToken='';writeToken='';sessions={};$('human-label').textContent='尚未登入';$('user-value').textContent='NOT_OBSERVED';$('device-value').textContent='NOT_OBSERVED';$('session-value').textContent='尚未建立';$('auth-state').textContent='NO SESSION';$('auth-state').className='pill neutral';$('jwt-expiry').textContent='短效 JWT 最長 120 秒';});
function preview(){const resource=$('resource').value;$('preview').textContent='GET /api/'+resource+'/'+$('owner').value;$('scope-label').textContent='需要 '+resource+':read';}
$('resource').addEventListener('change',preview);$('owner').addEventListener('change',preview);
const labels={'device-gateway':'Device Ingress',frontend:'Frontend PEP',salary:'Salary PEP',profile:'Profile PEP',external_pe:'External PE',resource:'Resource 執行'};
function render(result){
  lastResult=result;
  $('empty').hidden=true;$('result').hidden=false;$('attempt-id').textContent=result.attempt_id;
  const statuses=result.responses.map(r=>r.status);$('http-status').textContent='HTTP '+statuses.join(' → ');$('http-status').className='pill '+(statuses.every(s=>s===200)?'allow':statuses.some(s=>s===403||s===401)?'deny':'neutral');
  $('stages').replaceChildren();
  for(const stage of result.stages){
    const el=document.createElement('div');el.className='stage '+(stage.status==='VERIFIED_PASS'?'pass':stage.status==='VERIFIED_BLOCK'?'block':'unknown');
    const title=document.createElement('strong');title.textContent=labels[stage.component]||stage.component;
    const state=document.createElement('small');state.textContent=stage.status;el.append(title,state);$('stages').append(el);
  }
  const pe=result.stages.find(s=>s.component==='external_pe')?.evidence||[];
  $('response').textContent=dump(result.responses);
  $('decision').textContent=pe.length?dump(pe.map(e=>({decision:e.decision,reason:e.reason,subject:e.claims?.sub,recent_requests:e.recent_requests,quarantined:e.quarantined}))):'NOT_OBSERVED · 尚無可關聯的 PE 決策';
  $('claims').textContent=pe.find(e=>e.claims)?dump(pe.find(e=>e.claims).claims):'NOT_OBSERVED';
  $('evidence').textContent=dump(result);
  $('execution-note').textContent=result.execution_query_observed?'已直接查詢受保護服務的執行紀錄：'+result.executions.length+' 筆。這是此次 Attempt 的執行觀測。':'NOT_OBSERVED · 無法查詢資源執行紀錄；不能宣稱後端未執行。';
}
async function experiment(adjust=false){
  const attack=$('attack').value,resource=adjust?'salary':$('resource').value;
  const token=adjust?writeToken:['missing-jwt','invalid-jwt','plaintext'].includes(attack)?'':await credential(resource);
  if(adjust&&!token)throw new Error('先按 Passkey Step-Up，取得短效 salary:write Scope');
  const job=await api('/api/inspector/experiments',{token,resource,owner:$('owner').value,operation:adjust?'adjust':'read',attack,amount:60000});
  $('http-status').textContent='執行中 · 等待真實回應';$('http-status').className='pill neutral';
  const deadline=Date.now()+180000;
  while(Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,600));const state=await api('/api/inspector/jobs/'+job.id);if(state.state==='error')throw new Error(state.error);if(state.state==='done'){render(state.result);return;}}
  throw new Error('觀測逾時；請檢查 PE 恢復與叢集狀態。');
}
action('run',()=>experiment());action('adjust',()=>experiment(true));
action('reread',async()=>{if(!lastResult)throw new Error('先送出一筆實驗請求');const fresh=await api('/api/inspector/evidence/'+lastResult.attempt_id);render({...lastResult,...fresh});});
function mode(advanced){$('inspector-panel').hidden=!advanced;$('inspector-mode').classList.toggle('active',advanced);$('demo-mode').classList.toggle('active',!advanced);}
$('demo-mode').onclick=()=>mode(false);$('inspector-mode').onclick=()=>mode(true);
action('certificates',async()=>{$('public-certs').textContent=dump(await api('/api/inspector/certificates'));});
async function refresh(){try{const status=await api('/api/inspector/status');const ready=(status.workloads||[]).filter(w=>w.ready===w.desired).length;$('connection').textContent=status.available?status.context+' · '+ready+'/'+status.workloads.length+' workloads ready':'隔離叢集未連線 · NOT_OBSERVED';$('status-dot').classList.toggle('online',status.available&&ready===status.workloads.length);$('policies').textContent=status.policies?dump(status.policies):'NOT_OBSERVED';}catch(e){$('connection').textContent='環境讀取失敗 · UNKNOWN';}}
try{csrf=(await api('/api/console/session')).token;await refresh();}catch(e){error(e.message);}
setInterval(refresh,15000);

action('recover',async()=>{await api('/api/inspector/recover',{subject:$('subject').value});$('auth-state').textContent='OPERATOR RISK RECOVERY';});
