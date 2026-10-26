const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

test('bare or refreshed Inspector cannot start enrollment and explains how to reopen authorized entry',async()=>{
  const elements=new Map();
  const document={getElementById(id){if(!elements.has(id))elements.set(id,{disabled:false,hidden:false,textContent:'',addEventListener(){}});return elements.get(id);},querySelectorAll(){return [];}};
  let calls=0;
  const fetch=async()=>{calls++;return{ok:false,status:403,json:async()=>({detail:'operator_authorization_required'})};};
  const location={hash:'#experiment'};
  const source=fs.readFileSync(path.join(__dirname,'../console/console.js'),'utf8');
  await vm.runInNewContext('(async()=>{'+source+';})()',{document,fetch,location,window:{location,addEventListener(){}},URLSearchParams,setInterval(){},Error});
  assert.equal(calls,0);
  assert.equal(elements.get('register').disabled,true);
  assert.equal(elements.get('recover').disabled,true);
  assert.equal(elements.get('error').hidden,false);
  assert.match(elements.get('error').textContent,/register_portal_passkey\.cmd/);
});
