const {test}=require('node:test');
const assert=require('node:assert/strict');
const {pathToFileURL}=require('node:url');
const path=require('node:path');
const model=()=>import(pathToFileURL(path.join(__dirname,'../console/observer-model.mjs')).href);
const fixture=(stages=[],method='GET',resource='salary')=>({request:{resource,owner:'alice',method},responses:[{status:200}],stages:stages.map(([component,status])=>({component,status,evidence:[]}))});

test('business data goes through receiving sidecar and never through PE or native policy as a service',async()=>{
  const {observerModel}=await model();
  const graph=observerModel(fixture());
  assert.deepEqual(graph.dataEdges.map(e=>[e.from,e.to]),[['device-gateway','frontend'],['frontend','receiver'],['receiver','resource']]);
  assert.deepEqual(graph.mechanisms.map(n=>[n.id,n.parent]),[['custom','receiver'],['native_deny','receiver'],['native_allow','receiver']]);
  assert.deepEqual(graph.authorizationEdges.map(e=>[e.from,e.to]),[['custom','external_pe'],['external_pe','custom']]);
  assert.equal(graph.resource.label,'Salary App');
  assert.equal(observerModel(fixture([],'GET','profile')).resource.label,'Profile App');
});

test('GET identity introspection never appears as a newly performed WebAuthn ceremony',async()=>{
  const {observerModel}=await model();
  const graph=observerModel(fixture([['identity','VERIFIED_PASS'],['pa_session','VERIFIED_PASS'],['token_exchange','VERIFIED_PASS']]));
  assert.deepEqual(graph.authentication.map(n=>n.id),['identity','pa_session','token_exchange']);
  assert.equal(graph.authentication[0].label,'Identity 驗證');
  assert.equal(graph.loginContext,'Passkey 登入（先前完成）');
  assert.ok(!graph.authentication.some(n=>/WebAuthn|Passkey/.test(n.label)));
});

test('sensitive attempt shows step-up evidence separately from request identity validation',async()=>{
  const {observerModel}=await model();
  const graph=observerModel(fixture([['identity','VERIFIED_PASS'],['step_up','VERIFIED_PASS']],'POST'));
  assert.deepEqual(graph.authentication.map(n=>n.id),['identity','pa_session','step_up','token_exchange']);
  assert.equal(graph.authentication.find(n=>n.id==='step_up').status,'VERIFIED_PASS');
  const unobserved=observerModel(fixture([],'POST')).authentication.find(n=>n.id==='step_up');
  assert.equal(unobserved.status,'NOT_OBSERVED');
});

test('CUSTOM deny colors its evidence branch red and leaves native controls and app gray',async()=>{
  const {observerModel}=await model();
  const attempt=fixture([['salary','VERIFIED_BLOCK'],['external_pe','VERIFIED_BLOCK'],['resource','NOT_REACHED']]);
  attempt.stages[0].evidence=[{response_code_details:'ext_authz_denied'}];
  const graph=observerModel(attempt);
  assert.ok(graph.authorizationEdges.every(e=>e.status==='VERIFIED_BLOCK'));
  assert.equal(graph.mechanisms.find(n=>n.id==='custom').status,'VERIFIED_BLOCK');
  assert.ok(graph.mechanisms.filter(n=>n.id.startsWith('native_')).every(n=>n.status==='NOT_OBSERVED'));
  assert.equal(graph.dataEdges.at(-1).status,'NOT_REACHED');
});

test('ambiguous native denial stays on sidecar without inventing which native rule matched',async()=>{
  const {observerModel}=await model();
  const attempt=fixture([['salary','VERIFIED_BLOCK'],['external_pe','VERIFIED_PASS'],['native_policy','VERIFIED_BLOCK'],['resource','NOT_REACHED']]);
  attempt.stages[0].evidence=[{response_code_details:'rbac_access_denied_matched_policy[none]'}];
  const graph=observerModel(attempt);
  assert.equal(graph.receiver.status,'VERIFIED_BLOCK');
  assert.ok(graph.mechanisms.filter(n=>n.id.startsWith('native_')).every(n=>n.status==='NOT_OBSERVED'));
  assert.ok(graph.authorizationEdges.every(e=>e.status==='VERIFIED_PASS'));
});

test('HTTP success alone never turns missing component evidence green',async()=>{
  const {observerModel}=await model();
  const graph=observerModel(fixture());
  assert.ok([...graph.dataEdges,...graph.authorizationEdges,...graph.authentication,...graph.mechanisms].every(n=>n.status==='NOT_OBSERVED'));
  assert.equal(graph.loginContext,'登入狀態未觀測');
});

test('PE ALLOW without sidecar response does not prove ext_authz return or native success',async()=>{
  const {observerModel}=await model();
  const graph=observerModel(fixture([['external_pe','VERIFIED_PASS']]));
  assert.equal(graph.pe.status,'VERIFIED_PASS');
  assert.equal(graph.authorizationEdges[0].status,'VERIFIED_PASS');
  assert.equal(graph.authorizationEdges[1].status,'NOT_OBSERVED');
  assert.ok(graph.mechanisms.every(n=>n.status==='NOT_OBSERVED'));
});

test('sidecar ext_authz failure is blocked without fabricating a PE decision',async()=>{
  const {observerModel}=await model();
  const attempt=fixture([['salary','VERIFIED_BLOCK'],['resource','NOT_REACHED']]);
  attempt.stages[0].evidence=[{response_code_details:'ext_authz_error'}];
  const graph=observerModel(attempt);
  assert.equal(graph.pe.status,'NOT_OBSERVED');
  assert.equal(graph.authorizationEdges[0].status,'NOT_OBSERVED');
  assert.equal(graph.authorizationEdges[1].status,'VERIFIED_BLOCK');
  assert.equal(graph.mechanisms[0].status,'VERIFIED_BLOCK');
});

test('receiving proxy and PE success preserve the completed native checks and actual resource evidence',async()=>{
  const {observerModel}=await model();
  const attempt=fixture([['salary','VERIFIED_PASS'],['external_pe','VERIFIED_PASS'],['native_deny','VERIFIED_PASS'],['native_allow','VERIFIED_PASS'],['resource','VERIFIED_PASS']]);
  attempt.stages[0].evidence=[{response_code_details:'via_upstream'}];
  const graph=observerModel(attempt);
  assert.ok(graph.authorizationEdges.every(e=>e.status==='VERIFIED_PASS'));
  assert.ok(graph.mechanisms.every(e=>e.status==='VERIFIED_PASS'));
  assert.equal(graph.dataEdges.at(-1).status,'VERIFIED_PASS');
});
