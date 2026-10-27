import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {connectTor} from './rpc.mjs';
import {DEFAULT_RPCS,fetchOne} from './fetch.mjs';
import {loadSdk,need,stringify} from './wire.mjs';
import {checkedPath,readPublic,profile,descriptor} from './selection.mjs';
import {save} from './acquire.mjs';
import {cacheOptions,admitted,prepareBase} from './cache.mjs';
import {fetchCachedOne} from './acquire_cached.mjs';
export async function execute(pp,ps,dp,ds,output,a,urls=DEFAULT_RPCS,k=loadSdk()){
 const rawP=readPublic(pp,ps),rawD=readPublic(dp,ds),selected=profile(rawP,ps),d=descriptor(rawD,ds,selected,ps),info=admitted(a,rawP,ps,rawD,ds,k);output=checkedPath(output);
 need(!fs.existsSync(output),'OUTPUT_EXISTS','fresh cached acquisition output');fs.mkdirSync(output,{recursive:true,mode:0o700});const attempts=[];
 for(let index=0;index<urls.length;index++){
  const endpoint=new URL(urls[index]);need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'ENDPOINT','public Tor TLS endpoint');
  const root=path.join(output,`attempt-${String(index+1).padStart(3,'0')}`);fs.mkdirSync(root,{mode:0o700});let connection,phase='authenticate-and-copy-local-prefix';
  try{
   // Synchronous guarded reads/copies must finish before WebSocket heartbeat
   // timers or the fixed live frontier exist.
   const prepared=prepareBase(info,a,root);phase='connect-tor';
   connection=await connectTor(k,endpoint.href);let value,used=root;phase='fresh-fixed-delta-and-current-view';
   try{value=await fetchCachedOne(k,connection.rpc,selected,ps,d,ds,root,info,a,prepared);}
   catch(error){if(!['CACHE_STALE','REORG','STALE_FRONTIER','STALE_CURRENT_VIEW'].includes(error.category))throw error;used=path.join(root,'full-fallback');fs.mkdirSync(used,{mode:0o700});value=await fetchOne(k,connection.rpc,selected,ps,d,ds,used);value.cache_fallback={category:error.category,full_acquisition:true};}
   value.source={rpc_url:endpoint.href,attempt:index+1,assertion_scope:'Selected validating-node prefix; cache is not consensus proof'};value.attempts=attempts;const relative=path.relative(output,used).split(path.sep).join('/');
   value.pages.forEach(r=>{r.path=path.posix.join(relative,r.path);});value.current_view.post_query_delta.pages.forEach(r=>{r.path=path.posix.join(relative,r.path);});save(path.join(output,'fetch.json'),value);return value;
  }catch(error){const message=String(error.message??error),hint=message.match(/WebSocket disconnected|not connected|connection closed|timed? ?out|missing|changed|stale|invalid/i)?.[0]??'public acquisition error';const line=String(error.stack??'').match(/(?:kaspa\.js|[A-Za-z_]+\.mjs):\d+:\d+/)?.[0]??null;const failed={rpc_url:endpoint.href,status:'INCOMPLETE',category:error.category??'DATA_UNAVAILABLE',phase,error_class:error.name??typeof error,safe_hint:hint,public_source_line:line,recorded_at:new Date().toISOString()};save(path.join(root,'INCOMPLETE.json'),failed);attempts.push(failed);}finally{if(connection)await connection.close();}
 }
 const value={schema:'kpxa-gn3-network-fetch/v1',status:'INCOMPLETE',attempts,balance_known:false,no_empty_balance_inference:true};save(path.join(output,'INCOMPLETE.json'),value);return value;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const [pp,ps,dp,ds,output,...rest]=process.argv.slice(2),cache=[],urls=[];let sdk;
  for(let i=0;i<rest.length;i++){if(rest[i]==='--rpc')urls.push(rest[++i]);else if(rest[i]==='--sdk-dir')sdk=rest[++i];else{cache.push(rest[i]);if(rest[i]!=='--trusted-local-cache')cache.push(rest[++i]);}}
  const result=await execute(pp,ps,dp,ds,output,cacheOptions(cache),urls.length?urls:DEFAULT_RPCS,loadSdk(sdk));process.stdout.write(stringify({status:result.status,transactions:result.transactions?.length})+'\n');if(result.status==='INCOMPLETE')process.exitCode=2;
 }catch(error){process.stderr.write(`cached acquisition incomplete: ${error.category??'ERROR'}\n`);process.exitCode=2;}
}
