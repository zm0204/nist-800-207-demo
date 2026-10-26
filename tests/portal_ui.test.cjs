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
