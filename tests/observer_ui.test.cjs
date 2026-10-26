const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const {pathToFileURL}=require('node:url');

class Element{
  constructor(){this.children=[];this.attributes={};this.events={};this.hidden=false;this.textContent='';}
  setAttribute(name,value){this.attributes[name]=value;}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=[...children];}
  addEventListener(name,callback){this.events[name]=callback;}
}
function attempt(id,blocked=false){
  return {attempt_id:id,request_id:'request-'+id,request:{resource:'salary',owner:'alice',method:'GET'},
    responses:[{status:blocked?403:200}],stages:[
      {component:'external_pe',status:blocked?'VERIFIED_BLOCK':'VERIFIED_PASS',evidence:[{attempt_id:id,decision:blocked?'DENY':'ALLOW'}]},
      {component:'salary',status:blocked?'VERIFIED_BLOCK':'VERIFIED_PASS',evidence:[{response_code_details:blocked?'ext_authz_denied':'via_upstream'}]},
    ]};
}

test('new attempt closes its stale evidence panel while another employee update preserves it',async()=>{
  const model=await import(pathToFileURL(path.join(__dirname,'../console/observer-model.mjs')).href);
  const elements=new Map(),state={alice:attempt('a',true),bob:attempt('b')};
  const document={getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement(){return new Element();},createElementNS(){return new Element();}};
  const fetch=async(url)=>({ok:true,json:async()=>url==='/api/observer/attempts'
    ?Object.fromEntries(Object.entries(state).map(([subject,value])=>[subject,value?{attempt_id:value.attempt_id}:null]))
    :Object.values(state).find(value=>value?.attempt_id===url.split('/').at(-1))});
  // Supply the actual model to a DOM test harness; leave production polling unchanged.
  const source=fs.readFileSync(path.join(__dirname,'../console/observer.js'),'utf8')
    .replace(/^import[^\n]*\n/,'').replace(/\npoll\(\);\s*$/,'');
  const app=await vm.runInNewContext('(async()=>{'+source+';return {poll,openEvidence};})()',
    {document,fetch,setTimeout(){},Date,Error,...model});
  await app.poll();
  app.openEvidence('alice','custom');
  assert.equal(elements.get('evidence-panel').hidden,false);
  assert.match(elements.get('evidence-detail').textContent,/'a'|"a"/);
  state.bob=attempt('b2');await app.poll();
  assert.equal(elements.get('evidence-panel').hidden,false);
  state.alice=attempt('a2');await app.poll();
  assert.equal(elements.get('evidence-panel').hidden,true);
  const summary=elements.get('flow-alice').children.at(-1);
  assert.ok(summary.children.some(element=>element.textContent.includes('Attempt a2')));
  const bobGraph=elements.get('flow-bob').children;
  const intrusion=attempt('intrusion');
  intrusion.subject='alice';intrusion.origin='inspector';
  intrusion.caller={name:'intruder',service_account:'intruder',principal:'spiffe://cluster.local/ns/zta-identity/sa/intruder'};
  intrusion.stages.find(s=>s.component==='salary').evidence=[{response_code_details:'rbac_access_denied_matched_policy[none]'}];
  intrusion.stages.push({component:'native_policy',status:'VERIFIED_BLOCK',evidence:[{response_code_details:'rbac_access_denied_matched_policy[none]'}]});
  intrusion.stages.push({component:'resource',status:'NOT_REACHED',evidence:[]});
  intrusion.execution_query_observed=true;intrusion.execution_count=0;
  state.alice=intrusion;await app.poll();
  const descendants=element=>[element,...element.children.flatMap(descendants)];
  const aliceNodes=descendants(elements.get('flow-alice'));
  assert.ok(aliceNodes.some(n=>n.textContent==='Intruder Workload · 使用 Alice JWT'));
  assert.ok(aliceNodes.some(n=>n.attributes['data-from']==='custom'&&n.attributes['data-to']==='external_pe'&&n.attributes.class.includes('pass')));
  assert.ok(aliceNodes.some(n=>n.attributes['data-to']==='native_policy'&&n.attributes.class.includes('block')));
  assert.ok(!aliceNodes.some(n=>n.attributes['data-node']==='frontend'));
  assert.ok(aliceNodes.some(n=>n.textContent==='mTLS 身分已辨識'));
  assert.equal(elements.get('flow-bob').children,bobGraph);
  app.openEvidence('alice','intruder');
  assert.match(elements.get('evidence-detail').textContent,/mTLS principal/);
  app.openEvidence('alice','resource');
  assert.match(elements.get('evidence-detail').textContent,/Resource Execution Journal/);
  assert.match(elements.get('evidence-detail').textContent,/"execution_count": 0/);
  assert.ok(!elements.get('evidence-detail').textContent.includes('尚無足夠'));
  state.alice=attempt('normal-again');await app.poll();
  assert.ok(descendants(elements.get('flow-alice')).some(n=>n.attributes['data-node']==='frontend'));
  assert.ok(!descendants(elements.get('flow-alice')).some(n=>n.attributes['data-node']==='intruder'));
  app.openEvidence('alice','custom');
  state.alice=null;await app.poll();
  assert.equal(elements.get('evidence-panel').hidden,true);
});
