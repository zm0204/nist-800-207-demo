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
  app.openEvidence('alice','custom');
  state.alice=null;await app.poll();
  assert.equal(elements.get('evidence-panel').hidden,true);
});
