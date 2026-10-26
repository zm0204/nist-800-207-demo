const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

test('expired employee login returns to login and refreshes CSRF without reload',async()=>{
  const elements=new Map();
  const document={
    getElementById(id){if(!elements.has(id))elements.set(id,{hidden:false,textContent:'',value:'',addEventListener(){}});return elements.get(id);},
    querySelectorAll(){return [];}
  };
  let calls=0;
  const fetch=async(url)=>{
    calls++;
    if(calls===1){assert.equal(url,'/api/portal/session');return {ok:true,status:200,json:async()=>({subject:'alice',csrf:'old'})};}
    if(calls===2){assert.equal(url,'/api/portal/access');return {ok:false,status:401,json:async()=>({detail:'passkey_login_required'})};}
    assert.equal(url,'/api/portal/session');return {ok:true,status:200,json:async()=>({subject:null,csrf:'new'})};
  };
  const source=fs.readFileSync(path.join(__dirname,'../console/portal.js'),'utf8');
  const app=await vm.runInNewContext('(async()=>{'+source+';return {api,state:()=>({subject,csrf})};})()',{document,fetch,setTimeout,Uint8Array,Error});
  assert.equal(elements.get('login-panel').hidden,true);
  await assert.rejects(app.api('/api/portal/access',{resource:'salary',owner:'alice'}));
  assert.equal(app.state().subject,null);
  assert.equal(app.state().csrf,'new');
  assert.equal(elements.get('login-panel').hidden,false);
  assert.equal(elements.get('workspace').hidden,true);
});

test('Alice salary edit signs WebAuthn and sends actual adjustment instead of frontend denial',async()=>{
  const elements=new Map();
  const document={getElementById(id){if(!elements.has(id))elements.set(id,{hidden:false,textContent:'',value:id==='owner'?'alice':id==='amount'?'61000':'',addEventListener(){},replaceChildren(){}});return elements.get(id);},querySelectorAll(){return [];}};
  const calls=[];
  const fetch=async(url,options)=>{
    calls.push({url,body:options?.body?JSON.parse(options.body):null});
    const data={
      '/api/portal/session':{subject:'alice',csrf:'csrf'},
      '/api/portal/step-up/options':{ceremony:'ceremony',publicKey:{challenge:'YQ',allowCredentials:[{id:'YQ'}]}},
      '/api/portal/step-up/verify':{verified:true},
      '/api/portal/salary/adjust':{id:'job',attempt_id:'attempt'},
      '/api/portal/jobs/job':{state:'done',result:{attempt_id:'attempt',reason:'session_scope_exceeded',responses:[{status:403}]}}
    }[url];
    assert.ok(data,'unexpected endpoint '+url);
    return {ok:true,status:200,json:async()=>data};
  };
  let signed=false;
  const navigator={credentials:{get:async()=>{signed=true;const b=Uint8Array.from([1]).buffer;return{id:'credential',type:'public-key',rawId:b,response:{clientDataJSON:b,authenticatorData:b,signature:b,userHandle:null}};}}};
  const source=fs.readFileSync(path.join(__dirname,'../console/portal.js'),'utf8');
  const app=await vm.runInNewContext('(async()=>{'+source+';return {submitAdjustment};})()',{document,fetch,navigator,setTimeout:fn=>fn(),Uint8Array,Error,Date,atob,btoa});
  await app.submitAdjustment();
  assert.ok(signed);
  assert.deepEqual(calls.find(c=>c.url==='/api/portal/salary/adjust').body,{owner:'alice',amount:61000});
  assert.ok(calls.find(c=>c.url==='/api/portal/step-up/verify').body.credential.response.signature);
  assert.equal(elements.get('result-status').textContent,'HTTP 403');
});
