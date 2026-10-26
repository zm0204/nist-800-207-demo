const $=id=>document.getElementById(id);
let csrf='',subject=null,resource='salary',busy=false;
const names={alice:'Alice',bob:'Bob',carol:'Carol'};
const reasons={resource_ownership_denied:'你沒有權限查看這位員工的資料。',behavioral_quarantine:'此帳號目前受到存取限制，請聯絡管理者。',subject_risk_denied:'此帳號目前受到存取限制。',device_risk_denied:'此裝置目前無法存取。',session_scope_exceeded:'目前的授權範圍不允許此操作。',identity_expired:'登入已過期，請重新登入。',passkey_login_required:'請先登入。',experiment_in_progress:'系統正處理另一筆請求，請稍後再試。',ConnectError:'服務連線失敗，請稍後再試。',ReadTimeout:'服務連線逾時，請稍後再試。'};
async function api(path,body){
  const r=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json','x-portal-csrf':csrf},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await r.json();
  if(r.status===401&&subject){
    subject=null;$('resource-panel').hidden=true;update();
    try{const fresh=await fetch('/api/portal/session');csrf=(await fresh.json()).csrf;}catch{csrf='';}
  }
  if(!r.ok)throw new Error(reasons[data.detail]||data.detail||'服務暫時無法使用');return data;
}
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function update(){const logged=!!subject;$('login-panel').hidden=logged;$('workspace').hidden=!logged;$('logout').hidden=!logged;if(logged){$('greeting').textContent='你好，'+names[subject];$('owner').value=subject;}else{$('salary-editor').hidden=true;}}
async function action(fn){if(busy)return;busy=true;$('error').hidden=true;document.querySelectorAll('button').forEach(b=>b.disabled=true);try{await fn();}catch(e){$('error').textContent=e.name==='NotAllowedError'?'Passkey 操作未完成，請再試一次。':String(e.message);$('error').hidden=false;}finally{busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);}}
$('login-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{const selected=document.querySelector('input[name="subject"]:checked').value;const o=await api('/api/portal/login/options',{subject:selected});const p=o.publicKey;p.challenge=decode(p.challenge);p.allowCredentials=p.allowCredentials.map(c=>({...c,id:decode(c.id)}));const c=await navigator.credentials.get({publicKey:p});if(!c)throw new Error('Passkey 操作已取消');const result=await api('/api/portal/login/verify',{ceremony:o.ceremony,credential:{id:c.id,rawId:encode(c.rawId),type:c.type,response:{clientDataJSON:encode(c.response.clientDataJSON),authenticatorData:encode(c.response.authenticatorData),signature:encode(c.response.signature),userHandle:c.response.userHandle?encode(c.response.userHandle):null}}});subject=result.subject;csrf=result.csrf;update();});});
$('logout').addEventListener('click',()=>action(async()=>{await api('/api/portal/logout',{});subject=null;$('resource-panel').hidden=true;const s=await api('/api/portal/session');csrf=s.csrf;update();}));
for(const card of document.querySelectorAll('[data-resource]'))card.addEventListener('click',()=>{resource=card.dataset.resource;document.querySelectorAll('[data-resource]').forEach(c=>c.classList.toggle('selected',c===card));$('resource-title').textContent=resource==='salary'?'Salary':'Profile';$('resource-panel').hidden=false;$('salary-editor').hidden=resource!=='salary';$('result').hidden=true;$('attempt').hidden=true;$('result-status').textContent='';$('owner').focus();});
function field(dl,title,value,kind=''){const wrap=document.createElement('div'),dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=title;dd.textContent=value??'—';dd.className=kind;wrap.append(dt,dd);dl.append(wrap);}
function render(result){const response=result.responses[0]||{},ok=response.status>=200&&response.status<300;const status=$('result-status');status.className='status '+(ok?'pass':response.status===401||response.status===403?'block':'unknown');status.textContent=response.status?'HTTP '+response.status:'連線失敗';const host=$('result');host.replaceChildren();host.hidden=false;if(ok&&response.data){host.className='data-view';const data=response.data;const dl=document.createElement('dl');const labels={owner:'員工',subject:'員工',employee:'員工',name:'姓名',employee_name:'姓名',department:'部門',title:'職稱',email:'電子郵件',role:'職務',currency:'幣別',amount:'薪資',salary:'薪資',employee_id:'員工編號'};for(const [key,value]of Object.entries(data)){if(['attempt_id','request_id','execution_id','service','resource','synthetic','adjusted'].includes(key))continue;if(value&&typeof value==='object'){for(const [k,v]of Object.entries(value)){if(typeof v!=='object')field(dl,labels[k]||k,names[v]||v,k==='amount'?'amount':'');}}else field(dl,labels[key]||key,names[value]||value,key==='amount'?'amount':'');}host.append(dl);}else{host.className='rejection';const reason=result.reason||response.data?.detail||response.error;host.textContent=reasons[reason]||((response.status===401||response.status===403)?'此請求未獲授權。':'服務暫時無法完成請求。');}$('attempt').textContent='請求 '+result.attempt_id;$('attempt').hidden=false;}
$('access-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{$('result').hidden=true;$('attempt').hidden=true;$('result-status').textContent='查詢中…';const job=await api('/api/portal/access',{resource,owner:$('owner').value});$('attempt').textContent='請求 '+job.attempt_id;$('attempt').hidden=false;const deadline=Date.now()+180000;while(Date.now()<deadline){await new Promise(r=>setTimeout(r,650));const value=await api('/api/portal/jobs/'+job.id);if(value.state==='done'){render(value.result);return;}if(value.state==='error')throw new Error(value.error);}throw new Error('請求仍在處理，請稍後再試。');});});
async function submitAdjustment(){
  const o=await api('/api/portal/step-up/options',{}),p=o.publicKey;
  p.challenge=decode(p.challenge);p.allowCredentials=p.allowCredentials.map(c=>({...c,id:decode(c.id)}));
  const c=await navigator.credentials.get({publicKey:p});if(!c)throw new Error('Passkey 操作已取消');
  await api('/api/portal/step-up/verify',{ceremony:o.ceremony,credential:{id:c.id,rawId:encode(c.rawId),type:c.type,response:{clientDataJSON:encode(c.response.clientDataJSON),authenticatorData:encode(c.response.authenticatorData),signature:encode(c.response.signature),userHandle:c.response.userHandle?encode(c.response.userHandle):null}}});
  const job=await api('/api/portal/salary/adjust',{owner:$('owner').value,amount:Number($('amount').value)});
  $('attempt').textContent='請求 '+job.attempt_id;$('attempt').hidden=false;
  const deadline=Date.now()+180000;
  while(Date.now()<deadline){await new Promise(r=>setTimeout(r,650));const value=await api('/api/portal/jobs/'+job.id);if(value.state==='done'){render(value.result);return;}if(value.state==='error')throw new Error(value.error);}
  throw new Error('請求仍在處理，請稍後再試。');
}
$('salary-form').addEventListener('submit',e=>{e.preventDefault();action(async()=>{$('result').hidden=true;$('result-status').textContent='驗證身分…';await submitAdjustment();});});
try{const s=await api('/api/portal/session');csrf=s.csrf;subject=s.subject;update();}catch(e){$('error').textContent='無法連線至服務。';$('error').hidden=false;}
