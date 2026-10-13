const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/app.js'),'utf8');
function client(response){
  const context=vm.createContext({fetch:async()=>response});
  vm.runInContext(source.slice(0,source.indexOf('const decode=')),context);
  return ()=>vm.runInContext("api('/identity/login/options',{})",context);
}
test('plaintext tunnel 401 explains expired email access instead of a JSON syntax error',async()=>{
  await assert.rejects(client(new Response('Unauthorized\n',{status:401}))(),/遠端入口驗證.*失效/);
});
test('error text brings the response panel into view',()=>{
  let visible=false;
  const result={textContent:'',scrollIntoView:()=>{visible=true;}};
  const context=vm.createContext({document:{getElementById:()=>result}});
  vm.runInContext(source.slice(0,source.indexOf('const decode=')),context);
  vm.runInContext("show('遠端入口驗證已失效')",context);
  assert.equal(result.textContent,'遠端入口驗證已失效');
  assert.equal(visible,true);
});
test('successful API responses and application JSON errors retain their meaning',async()=>{
  const result=await client(new Response('{"ok":true}',{headers:{'Content-Type':'application/json'}}))();
  assert.equal(result.ok,true);
  await assert.rejects(client(new Response('{"detail":"先建立 Passkey"}',{status:400,headers:{'Content-Type':'application/json'}}))(),/先建立 Passkey/);
});
