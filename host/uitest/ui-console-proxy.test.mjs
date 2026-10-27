import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {createServer,isSafe,rewrite,PREFIX}=require('../ui-console-proxy.cjs');
const listen=server=>new Promise((ok,bad)=>server.once('error',bad).listen(0,'127.0.0.1',()=>ok(server.address().port)));
const close=server=>new Promise(resolve=>server.close(resolve));
test('proxy exposes only the static RedX database UI and rewrites same-origin assets',async t=>{
 let hits=[];
 const upstream=http.createServer((req,res)=>{
  hits.push(req.url);
  if(req.url==='/ui/'){
   res.writeHead(200,{'content-type':'text/html; charset=utf-8',
    'content-security-policy':"default-src 'none'; script-src 'self'; connect-src 'self'"});
   return res.end('<script src="/ui/js/main.js"></script><link href="/ui/css/app.css">');
  }
  if(req.url==='/ui/js/main.js'){
   res.writeHead(200,{'content-type':'text/javascript; charset=utf-8'});
   return res.end("import './util.js'; fetch('/v1/dbs'); const x='/ui/css/app.css';");
  }
  res.writeHead(404);res.end();
 });
 const port=await listen(upstream);t.after(()=>close(upstream));
 const proxy=createServer({upstreamPort:port});
 const exposed=await listen(proxy);t.after(()=>close(proxy));
 const base='http://127.0.0.1:'+exposed;
 const response=await fetch(base+PREFIX+'/');
 assert.equal(response.status,200);
 assert.match(response.headers.get('content-security-policy'),/script-src 'self'/);
 const body=await response.text();
 assert.match(body,/src="\/v1\/console\/js\/main.js"/);
 assert.match(body,/href="\/v1\/console\/css\/app.css"/);
 const js=await fetch(base+PREFIX+'/js/main.js');
 assert.equal(js.status,200);
 const code=await js.text();
 assert.match(code,/fetch\('\/v1\/dbs'\)/);
 assert.match(code,/\/v1\/console\/css\/app.css/);
 assert.deepEqual(hits,['/ui/','/ui/js/main.js']);
});
test('proxy rejects data paths, unknown methods and traversal',async t=>{
 const upstream=http.createServer((req,res)=>res.end('unsafe'));
 const port=await listen(upstream);t.after(()=>close(upstream));
 const proxy=createServer({upstreamPort:port});
 const uiPort=await listen(proxy);t.after(()=>close(proxy));
 const base='http://127.0.0.1:'+uiPort;
 for(const path of ['/v1/dbs','/v1/admin/status']){
  const r=await fetch(base+path);
  assert.equal(r.status,404,path);
 }
 for(const path of ['/v1/console/.env','/v1/console/foo.pem','/v1/console/data.csv','/v1/console/a%2fb.js']){
  const r=await fetch(base+path);
  assert.equal(r.status,400,path);
 }
 const r=await fetch(base+PREFIX+'/',{method:'POST'});
 assert.equal(r.status,405);
 assert.equal((await fetch(base+PREFIX,{redirect:'manual'})).status,308);
});
test('URL guard accepts the expected UI file layout only',()=>{
 assert.ok(isSafe('/js/main.js'));
 assert.ok(isSafe('/icons/redx-128.png'));
 assert.ok(isSafe('/css/app.css'));
 for(const x of ['/../../key','.env','/a//b.js','/private.key','/uploads/tokens.txt'])assert.equal(isSafe(x),false,x);
 assert.equal(rewrite('<script src="/ui/js/main.js">'),'<script src="/v1/console/js/main.js">');
});
