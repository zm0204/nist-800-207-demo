// Presentation of existing evidence only. HTTP results never establish gate success.
const unknown = id => ({component:id,status:'NOT_OBSERVED',evidence:[]});
export function observedStage(result,id){
  return result?.stages.find(stage=>stage.component===id)||unknown(id);
}

export function observerModel(result){
  const resource=result?.request.resource||'salary';
  const intruder=result?.origin==='inspector'&&result?.caller?.service_account==='intruder';
  const node=(id,label,source=id)=>({id,label,...observedStage(result,source)});
  const authentication=[intruder?node('jwt_identity','JWT 驗證'):node('identity','Identity 驗證'),node('pa_session','PA Session')];
  if(result?.request.method==='POST')authentication.push(node('step_up','Passkey Step-Up'));
  authentication.push(node('token_exchange','JWT 交換'));
  const receiver=node('receiver','接收端 Envoy Sidecar',resource);
  const pe=node('external_pe','External PE');
  const details=receiver.evidence.map(e=>e.response_code_details||'');
  let customStatus='NOT_OBSERVED';
  if(details.some(d=>/ext_authz_denied|ext_authz_error/.test(d)))customStatus='VERIFIED_BLOCK';
  else if(details.some(d=>d==='via_upstream')||
          pe.status==='VERIFIED_PASS'&&details.some(d=>d.includes('rbac_access_denied')))
    customStatus='VERIFIED_PASS';
  const mechanisms=[
    {id:'custom',parent:'receiver',label:'CUSTOM · ext_authz',status:customStatus,
      evidence:[...receiver.evidence,...pe.evidence]},
    {...node('native_deny','Native DENY'),parent:'receiver'},
    {...(observedStage(result,'native_policy').status==='VERIFIED_BLOCK'
      ?node('native_policy','Native 授權'):node('native_allow','Native ALLOW')),parent:'receiver'},
  ];
  const app=node('resource',resource==='profile'?'Profile App':'Salary App');
  return {
    authentication,receiver,mechanisms,pe,resource:app,
    caller:intruder?{...node('intruder','Intruder · sa/intruder','caller_workload'),statusLabel:'mTLS 身分已辨識'}:null,
    eventLabel:intruder?'Intruder Workload · 使用 '+(result.subject==='alice'?'Alice':'Bob')+' JWT':null,
    gateway:node('device-gateway','Device Gateway'),frontend:node('frontend','Frontend'),
    loginContext:intruder?'JWT Subject：'+(result.subject==='alice'?'Alice':'Bob')+' · Actual Caller Workload：Intruder（sa/intruder）'
      :observedStage(result,'identity').status==='VERIFIED_PASS'?'Passkey 登入（先前完成）':'登入狀態未觀測',
    dataEdges:intruder?[
      {from:'intruder',to:'receiver',status:receiver.status},
      {from:'receiver',to:'resource',status:app.status},
    ]:[
      {from:'device-gateway',to:'frontend',status:observedStage(result,'frontend').status},
      {from:'frontend',to:'receiver',status:receiver.status},
      {from:'receiver',to:'resource',status:app.status},
    ],
    authorizationEdges:[
      {from:'custom',to:'external_pe',status:pe.status},
      {from:'external_pe',to:'custom',status:customStatus},
    ],
  };
}
