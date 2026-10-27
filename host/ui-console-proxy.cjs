'use strict';
// Read-only static interface proxy for the existing RedX database UI.
// The actual protected /v1 APIs remain on redxd with their existing auth,
// per-tenant database isolation, plan gates and owner restrictions.
const http=require('node:http'),fs=require('node:fs');
const PREFIX='/v1/console';
const PORT=Number(process.env.REDX_CONSOLE_PROXY_PORT||17782);
const ALLOWED=/^[a-zA-Z0-9_.\/-]+$/;
const EXT=/\.(?:js|css|html|json|svg|ico|png|webp|jpg|jpeg|woff2?|ttf)$/i;
function isSafe(path){
 if(path==='/'||path==='')return true;
 if(!ALLOWED.test(path)||path.includes('..')||path.includes('//')||path.includes('\\'))return false;
 return EXT.test(path);
}
function rewrite(source){
 return source.replace(/(["'])\/ui\//g,'$1'+PREFIX+'/')
   .replace(/url\((["']?)\/ui\//g,'url($1'+PREFIX+'/');
}
function createServer({upstreamPort=7790,forgeCSSPath=process.env.REDX_CONSOLE_FORGE_CSS||'/opt/redx/lib/ui-console-forge.css'}={}){
 return http.createServer((req,res)=>{
   const headers={
     'cache-control':'no-cache',
     'x-content-type-options':'nosniff',
     'referrer-policy':'no-referrer',
     'x-frame-options':'DENY'
   };
   if(req.method!=='GET'&&req.method!=='HEAD'){
     res.writeHead(405,{...headers,'allow':'GET, HEAD'});return res.end();
   }
   if(!req.url||req.url.includes('?')||req.url.includes('#')||req.url.includes('%')||req.url.includes('..')){
     res.writeHead(400,headers);return res.end();
   }
   if(req.url===PREFIX){
     res.writeHead(308,{...headers,location:PREFIX+'/'});return res.end();
   }
   if(!req.url.startsWith(PREFIX+'/')){
     res.writeHead(404,headers);return res.end();
   }
   const relative=req.url.slice(PREFIX.length);
   if(!isSafe(relative)){
     res.writeHead(400,headers);return res.end();
   }
   if(relative==='/css/forge.css'){
     try{
       const body=fs.readFileSync(forgeCSSPath);
       res.writeHead(200,{...headers,'content-type':'text/css; charset=utf-8',
         'content-length':String(body.length)});
       return res.end(req.method==='HEAD'?undefined:body);
     }catch{
       res.writeHead(404,headers);return res.end();
     }
   }
   const target='/ui'+relative;
   const upstream=http.request({
     hostname:'127.0.0.1',port:upstreamPort,method:'GET',path:target,
     headers:{accept:'*/*','accept-encoding':'identity'},timeout:6500
   },up=>{
     const chunks=[];let total=0;
     up.on('data',buf=>{
       total+=buf.length;
       if(total>5*1024*1024){up.destroy(Error('static response too large'));return}
       chunks.push(buf);
     });
     up.on('end',()=>{
       const body=Buffer.concat(chunks);
       const original=up.headers['content-type']||'application/octet-stream';
       const textual=/^(?:text\/|application\/(?:javascript|json))/.test(original);
       let rendered=textual?rewrite(body.toString('utf8')):null;
       if(relative==='/'&&rendered!==null&&rendered.includes('</head>')){
         rendered=rendered.replace('</head>',
           '<link rel="stylesheet" href="'+PREFIX+'/css/forge.css"></head>');
       }
       const result=rendered!==null?Buffer.from(rendered):body;
       const responseHeaders={...headers,'content-type':original,'content-length':String(result.length)};
       for(const name of ['content-security-policy','permissions-policy']){
         if(typeof up.headers[name]==='string')responseHeaders[name]=up.headers[name];
       }
       res.writeHead(up.statusCode||502,responseHeaders);
       res.end(req.method==='HEAD'?undefined:result);
     });
   });
   upstream.on('error',()=>{
     if(!res.headersSent){res.writeHead(502,headers);res.end();}
     else res.destroy();
   });
   upstream.end();
 });
}
if(require.main===module){
 if(!Number.isInteger(PORT)||PORT<1025||PORT>65535)throw Error('Invalid loopback port');
 const server=createServer();
 server.listen(PORT,'127.0.0.1',()=>console.log('RedX console static proxy serving on loopback'));
 for(const sig of ['SIGTERM','SIGINT'])process.once(sig,()=>server.close(()=>process.exit(0)));
}
module.exports={createServer,isSafe,rewrite,PREFIX};
