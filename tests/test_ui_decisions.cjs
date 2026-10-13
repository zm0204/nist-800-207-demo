const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
function element(){
  const classes=new Set();
  return {textContent:'',className:'',children:[],setAttribute(){},
    scrollIntoView(){},
    classList:{toggle(name,on){if(on)classes.add(name);else classes.delete(name);},contains:name=>classes.has(name)},
    append(...items){this.children.push(...items);},replaceChildren(){this.children=[];}};
}
function dashboard(view){
  const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],element()]));
  const context=vm.createContext({document:{getElementById:id=>elements[id],querySelectorAll:()=>[],createElement:element},
    fetch:async()=>({ok:true,json:async()=>view}),setInterval(){},Date});
  vm.runInContext(source,context);
  return {elements,context,refresh:()=>vm.runInContext("sessionId='selected'; refresh()",context)};
}
const evaluation=(decision='ALLOW',request={method:'GET',path:'/api/profile'})=>({decision,request,trust_score:100,risk_score:0,threshold:60,reasons:decision==='ALLOW'?['required_conditions_met']:['least_privilege']});
function view(action,state='ACTIVE'){
  return {snapshot:{device:{id:'device-a'},context:{}},sessions:[{session_id:'selected',session_ref:'ref-a',subject:'alice',state,
    scope:{method:'GET',path:'/api/salary'},last:evaluation('ALLOW',{method:'GET',path:'/api/salary'}),last_action:action,last_request_action:action}],events:[]};
}
const mismatch=()=>({action_id:'profile-action',operation:'request',request:{method:'GET',path:'/api/profile'},
  policy_evaluation:evaluation(),pdp_decision:'DENY',pa_action:'DENY_REQUEST',pa_reason:'session_scope_mismatch',pep_state:'BLOCKED',http_status:403});
test('scope mismatch shows PE ALLOW, PA denial and overall DENY for the same request',async()=>{
  const d=dashboard(view(mismatch()));await d.refresh();
  assert.equal(d.elements.decision.textContent,'DENY');
  assert.match(d.elements['decision-label'].textContent,/ALLOW/);
  assert.equal(d.elements.action.textContent,'DENY_REQUEST');
  assert.match(d.elements['pa-reason'].textContent,/Session Scope Mismatch/);
  assert.equal(d.elements.pep.textContent,'403 · BLOCKED');
  assert.equal(d.elements.request.textContent,'GET /api/profile');
  assert.equal(d.elements['session-badge'].textContent,'ACTIVE');
  assert.equal(d.elements['flow-pdp-state'].textContent,'DENY');
  assert.ok(d.elements['decision-context'].textContent.includes('profile-action'));
});
test('foreign PA actions and background PE evaluations cannot replace the selected request, even after audit eviction',async()=>{
  const v=view(mismatch());v.events=[{kind:'pa_action',session_ref:'ref-b',decision:'ALLOW',pa_action:'AUTHORIZE_REQUEST',pep_state:'FORWARD',request:{method:'GET',path:'/api/salary'}},
    {kind:'pe_decision',...evaluation('ALLOW',{method:'GET',path:'/api/salary'})}];
  const d=dashboard(v);await d.refresh();
  assert.equal(d.elements.decision.textContent,'DENY');
  assert.equal(d.elements.request.textContent,'GET /api/profile');
  v.events=[];await d.refresh();assert.equal(d.elements.pep.textContent,'403 · BLOCKED');
});
test('allowed and policy denied requests render their independent PE decision',async()=>{
  for(const [pe,pdp,pa,pep,status] of [['ALLOW','ALLOW','AUTHORIZE_REQUEST','FORWARD',200],['DENY','DENY','DENY_REQUEST','BLOCKED',403]]){
    const a={...mismatch(),policy_evaluation:evaluation(pe),pdp_decision:pdp,pa_action:pa,pa_reason:pe==='DENY'?'policy_denied':'required_conditions_met',pep_state:pep,http_status:status};
    const d=dashboard(view(a));await d.refresh();
    assert.equal(d.elements.decision.textContent,pdp);
    assert.match(d.elements['decision-label'].textContent,new RegExp(pe));
    assert.equal(d.elements.pep.textContent,`${status} · ${pep}`);
  }
});
test('background revocation is labelled separately from the preserved last request',async()=>{
  const v=view(mismatch(),'REVOKED');v.sessions[0].last_action={...mismatch(),operation:'reevaluation',policy_evaluation:evaluation('REVOKE',{method:'GET',path:'/api/salary'}),
    request:{method:'GET',path:'/api/salary'},pa_action:'REVOKE_SESSION',pa_reason:'policy_revoked',pdp_decision:'REVOKE',http_status:null};
  const d=dashboard(v);await d.refresh();
  assert.equal(d.elements.decision.textContent,'REVOKE');
  assert.match(d.elements['decision-context'].textContent,/背景重新評估/);
  assert.match(d.elements['recent-request'].textContent,/GET \/api\/profile.*403.*BLOCKED/);
  assert.equal(d.elements.pep.textContent,'BLOCKED'); // No HTTP request was made by a background evaluation.
});
test('fail closed and administrator revocation never claim PE returned REVOKE',async()=>{
  for(const reason of ['control_plane_unavailable','administrator_revocation']){
    const a={...mismatch(),policy_evaluation:null,pdp_decision:'REVOKE',pa_action:'REVOKE_SESSION',pa_reason:reason};
    const d=dashboard(view(a,'REVOKED'));await d.refresh();
    assert.match(d.elements['decision-label'].textContent,/未取得 PE 決策/);
    assert.equal(d.elements.decision.textContent,'REVOKE');
  }
});
test('unselected sessions and legacy records do not turn an arbitrary event into a current access result',async()=>{
  const v=view(null);v.events=[{kind:'pa_action',decision:'ALLOW',pa_action:'AUTHORIZE_REQUEST',pep_state:'FORWARD'}];
  const d=dashboard(v);await d.refresh();
  assert.equal(d.elements.decision.textContent,'—');
  assert.equal(d.elements.pep.textContent,'—');
  v.sessions=[];await d.refresh();assert.equal(d.elements.decision.textContent,'—');
});
test('PA audit rows name both the PE result and the PA reason instead of showing an unqualified ALLOW',()=>{
  const d=dashboard(view(mismatch()));
  vm.runInContext(`renderEvents([${JSON.stringify({kind:'pa_action',timestamp:1,session_ref:'ref-a',decision:'ALLOW',...mismatch()})}])`,d.context);
  const row=d.elements.events.children[0],body=row.children[1],title=body.children[0];
  assert.equal(title.children[1].textContent,'PDP DENY · PE ALLOW');
  assert.match(body.children[1].textContent,/DENY_REQUEST.*Session Scope Mismatch.*GET \/api\/profile.*profile-action/);
});
test('failed session creation shows its denial while preserving the existing active session',async()=>{
  const allowed={...mismatch(),pdp_decision:'ALLOW',pa_action:'AUTHORIZE_REQUEST',pep_state:'FORWARD',http_status:200};
  const v=view(allowed),denied={...mismatch(),operation:'session',policy_evaluation:evaluation('DENY'),pa_action:'DENY_SESSION',pa_reason:'policy_denied'};
  const d=dashboard(v);await d.refresh();
  d.context.fetch=async url=>({ok:url!=='/agent/session',headers:{get:()=> 'application/json'},json:async()=>url==='/agent/session'?{authorization:denied}:v});
  vm.runInContext("humanToken='verified';",d.context);d.elements.path.value='/api/profile';
  await d.elements.session.onclick();
  assert.equal(d.elements.action.textContent,'DENY_SESSION');
  assert.equal(d.elements.decision.textContent,'DENY');
  assert.equal(d.elements['session-badge'].textContent,'ACTIVE');
  assert.match(d.elements['decision-context'].textContent,/建立 Session/);
});
test('unavailable view marks displayed decisions as historical rather than claiming current authorization',async()=>{
  const d=dashboard(view({...mismatch(),pdp_decision:'ALLOW',pa_action:'AUTHORIZE_REQUEST',pep_state:'FORWARD',http_status:200}));
  await d.refresh();d.context.fetch=async()=>({ok:false});await d.refresh();
  assert.match(d.elements.connection.textContent,/未連線/);
  assert.match(d.elements['decision-context'].textContent,/上次紀錄.*無法確認目前授權/);
  assert.equal(d.elements.decision.textContent,'ALLOW');
});
