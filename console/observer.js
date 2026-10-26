import {observerModel,observedStage} from './observer-model.mjs';

const ns='http://www.w3.org/2000/svg',$=id=>document.getElementById(id);
const results={alice:null,bob:null},seen={alice:null,bob:null};
let evidenceSubject=null;
const statusLabels={VERIFIED_PASS:'已驗證通過',VERIFIED_BLOCK:'已驗證拒絕',NOT_REACHED:'未到達',NOT_OBSERVED:'未觀測',UNKNOWN:'未知'};
const reasons={resource_ownership_denied:'不在授權的員工範圍內',behavioral_quarantine:'帳號已因存取行為受到限制',session_scope_exceeded:'Session 授權範圍不足',subject_risk_denied:'帳號風險限制',device_risk_denied:'裝置風險限制',ConnectError:'連線失敗',ReadTimeout:'連線逾時'};
const pointLabels={identity:'Identity 驗證',pa_session:'PA Session',step_up:'Passkey Step-Up',token_exchange:'PA／JWT 交換',external_pe:'External PE',native_policy:'接收端 Sidecar · 原生授權',salary:'Salary Sidecar',profile:'Profile Sidecar','device-gateway':'Device Gateway',frontend:'Frontend'};
const tone=status=>status==='VERIFIED_PASS'?'pass':status==='VERIFIED_BLOCK'?'block':'unknown';

function el(name,attrs={},text){
  const element=document.createElementNS(ns,name);
  for(const [key,value]of Object.entries(attrs))element.setAttribute(key,value);
  if(text!==undefined)element.textContent=text;
  return element;
}

function openEvidence(subject,id){
  const result=results[subject],graph=observerModel(result);
  const item=[...graph.authentication,...graph.mechanisms,graph.receiver,graph.pe,graph.resource,graph.gateway,graph.frontend].find(n=>n.id===id);
  $('evidence-title').textContent=(subject==='alice'?'Alice':'Bob')+' · '+item.label;
  $('evidence-status').textContent=statusLabels[item.status]||item.status;
  let evidence=item.evidence,context='';
  if(id==='identity')context='本次為 Identity introspection；Passkey 登入是在先前完成。';
  if(id==='pa_session')context='Session 建立或由 PA exchange 重新驗證，請依下方來源判讀。';
  if(id==='step_up')context='敏感操作的獨立 Passkey 再驗證，與一般請求驗證分開。';
  if(id==='receiver'){
    const native=observedStage(result,'native_policy');
    evidence=[{component:graph.receiver.component,status:graph.receiver.status,evidence:graph.receiver.evidence}];
    if(native.status!=='NOT_OBSERVED')evidence.push(native);
    context='接收端 Sidecar 執行 CUSTOM → DENY → ALLOW。原生拒絕若無法區分規則，不推定命中 DENY 或缺少 ALLOW。';
  }
  const detail=evidence?.length?JSON.stringify(evidence,null,2):'尚無足夠的元件證據。';
  $('evidence-detail').textContent=(context?context+'\n\n':'')+detail;
  evidenceSubject=subject;
  $('evidence-panel').hidden=false;
}

function closeEvidence(subject){
  if(!subject||evidenceSubject===subject){$('evidence-panel').hidden=true;evidenceSubject=null;}
}

function edge(svg,subject,from,to,status,points,kind='data'){
  const color=tone(status);
  svg.append(el('polyline',{
    points,class:'edge '+color+' '+kind+'-path',
    'data-from':from,'data-to':to,'data-kind':kind,'data-status':status,
    'marker-end':'url(#arrow-'+subject+'-'+color+')',
  }));
}

function node(svg,subject,item,x,y,width=114,height=58,kind='service'){
  const group=el('g',{class:'node '+kind,role:'button',tabindex:'0',
    'data-node':item.id,'data-parent':item.parent||'',
    'aria-label':item.label+'，'+statusLabels[item.status]});
  group.append(el('rect',{x:x-width/2,y:y-height/2,width,height,rx:kind==='control'?6:9}),
    el('text',{x,y:y-3},item.label),
    el('text',{x,y:y+14,class:'node-status'},statusLabels[item.status]||item.status));
  group.addEventListener('click',()=>openEvidence(subject,item.id));
  group.addEventListener('keydown',event=>{
    if(event.key==='Enter'||event.key===' '){event.preventDefault();openEvidence(subject,item.id);}
  });
  svg.append(group);
}

function diagram(subject,graph){
  const svg=el('svg',{viewBox:'0 0 640 405',class:'flow-svg',role:'img','aria-label':(subject==='alice'?'Alice':'Bob')+' 請求流程'});
  svg.append(el('title',{},'資料路徑：Device Gateway → Frontend → 接收端 Envoy Sidecar → '+graph.resource.label+'。External PE 為 ext_authz 分支；Native AuthorizationPolicy 由 Sidecar 執行。'));
  const defs=el('defs');
  for(const [color,fill]of [['pass','#13745c'],['block','#c94747'],['unknown','#a9b3b1']]){
    const marker=el('marker',{id:'arrow-'+subject+'-'+color,viewBox:'0 0 10 10',refX:9,refY:5,
      markerWidth:7,markerHeight:7,markerUnits:'userSpaceOnUse',orient:'auto'});
    marker.append(el('path',{d:'M 0 0 L 10 5 L 0 10 Z',fill}));defs.append(marker);
  }
  svg.append(defs,el('text',{x:12,y:17,class:'section-label'},'本次身分與授權驗證'));
  const count=graph.authentication.length,width=count===4?138:160;
  const centers=count===4?[83,241,399,557]:[102,320,538];
  edge(svg,subject,'login_context','identity',graph.authentication[0].status,
    '3,57 '+(centers[0]-width/2)+',57','verification');
  graph.authentication.forEach((item,index)=>{
    if(index)edge(svg,subject,graph.authentication[index-1].id,item.id,item.status,
      (centers[index-1]+width/2)+',57 '+(centers[index]-width/2)+',57','verification');
    node(svg,subject,item,centers[index],57,width,52,'verification');
  });
  svg.append(el('line',{x1:12,y1:104,x2:628,y2:104,class:'diagram-divider'}),
    el('text',{x:12,y:129,class:'section-label'},'資料路徑'));

  // Receiving sidecar is the data-plane boundary; PE is an authorization branch.
  svg.append(el('rect',{x:315,y:145,width:175,height:232,rx:12,class:'sidecar-frame',
    'data-container':'receiver','aria-label':'接收端 Envoy Sidecar'}));
  edge(svg,subject,'device-gateway','frontend',graph.dataEdges[0].status,'123,205 159,205');
  edge(svg,subject,'frontend','receiver',graph.dataEdges[1].status,'277,205 332,205');
  edge(svg,subject,'receiver','resource',graph.dataEdges[2].status,'472,325 532,325');
  edge(svg,subject,'custom','external_pe',graph.authorizationEdges[0].status,'472,195 532,195','authorization');
  edge(svg,subject,'external_pe','custom',graph.authorizationEdges[1].status,'532,215 472,215','authorization');
  svg.append(el('text',{x:502,y:181,class:'branch-label'},'ext_authz'));
  edge(svg,subject,'custom','native_deny',graph.mechanisms[1].status,'402,227 402,243','mechanism');
  edge(svg,subject,'native_deny','native_allow',graph.mechanisms[2].status,'402,287 402,303','mechanism');

  node(svg,subject,graph.gateway,66,205);
  node(svg,subject,graph.frontend,218,205,118);
  node(svg,subject,graph.receiver,402,166,169,34,'receiver-title');
  graph.mechanisms.forEach((item,index)=>node(svg,subject,item,402,205+index*60,140,44,'control'));
  node(svg,subject,graph.pe,582,205,100);
  node(svg,subject,graph.resource,582,325,100);
  return svg;
}

function draw(subject,result){
  const graph=observerModel(result),host=$('flow-'+subject);
  host.replaceChildren();
  const header=document.createElement('header'),avatar=document.createElement('span'),who=document.createElement('div'),
    title=document.createElement('h2'),role=document.createElement('p'),badge=document.createElement('span');
  avatar.className='avatar '+subject;avatar.textContent=subject==='alice'?'A':'B';
  who.className='who';title.textContent=subject==='alice'?'Alice':'Bob';
  role.textContent=subject==='alice'?'員工':'人事管理';who.append(title,role);
  const code=result?.responses?.[0]?.status;
  badge.className='status '+(code>=200&&code<300?'pass':code===401||code===403?'block':'unknown');
  badge.textContent=result?(code?'HTTP '+code:'連線失敗'):'等待請求';
  header.append(avatar,who,badge);
  const context=document.createElement('p');context.className='flow-context';context.textContent=graph.loginContext;
  host.append(header,context,diagram(subject,graph));
  const summary=document.createElement('div');summary.className='flow-summary';
  if(result){
    const request=document.createElement('div');request.className='request';
    request.textContent=(result.request.resource==='salary'?'Salary':'Profile')+
      (result.request.method==='POST'?' 修改':'')+' ／ '+({alice:'Alice',bob:'Bob',carol:'Carol'}[result.request.owner]);
    summary.append(request);
    if(result.reason||result.denial_point){
      const reason=document.createElement('div');reason.className='reason';
      reason.textContent=(pointLabels[result.denial_point]||result.denial_point||'連線')+' · '+
        (reasons[result.reason]||result.reason||'請求遭拒絕');summary.append(reason);
    }
    const id=document.createElement('div');id.className='request-id';
    id.textContent='Attempt '+result.attempt_id+' · Request '+(result.request_id||'未觀測');summary.append(id);
  }else{
    const empty=document.createElement('span');empty.className='pending';empty.textContent='尚無請求紀錄';summary.append(empty);
  }
  host.append(summary);
}

$('close-evidence').onclick=()=>closeEvidence();
async function poll(){
  try{
    const response=await fetch('/api/observer/attempts');if(!response.ok)throw new Error();
    const summaries=await response.json();
    for(const subject of ['alice','bob']){
      const next=summaries[subject];
      if(!next&&seen[subject]){results[subject]=null;seen[subject]=null;closeEvidence(subject);draw(subject,null);}
      if(next&&next.attempt_id!==seen[subject]){
        const detail=await fetch('/api/observer/attempts/'+encodeURIComponent(next.attempt_id));
        if(!detail.ok)throw new Error();
        results[subject]=await detail.json();seen[subject]=next.attempt_id;closeEvidence(subject);draw(subject,results[subject]);
      }
    }
    $('poll-state').textContent='已連線 · '+new Date().toLocaleTimeString('zh-TW',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }catch{
    $('poll-state').textContent='監控連線中斷；保留上次已觀測的結果。';
  }finally{setTimeout(poll,2000);}
}
for(const subject of ['alice','bob'])draw(subject,null);
poll();
