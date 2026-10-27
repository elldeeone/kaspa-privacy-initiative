import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {connectReadOnlyBorsh,publicAcquisitionDiagnostic} from './readonly_borsh_observed_retry_strict_rpc.mjs';
import {DEFAULT_RPCS,fetchOne} from './fetch.mjs';
import {loadSdk,need,stringify} from './wire.mjs';
import {checkedPath,readPublic,profile,descriptor,strictJson} from './selection.mjs';
import {save} from './acquire.mjs';
import {cacheOptions,admitted} from './cache.mjs';
import {prepareBaseParallel} from './cache_prepare_parallel.mjs';
import {fetchCachedOne} from './acquire_cached.mjs';
const NETWORK_NAMES=['ingress/readonly_borsh_worker.mjs','diagnostics/borsh_stage_worker.mjs','chain/readonly_borsh_observed_retry_strict_rpc.mjs','chain/fetch_borsh_parallel_observed_retry_strict.mjs','ingress/BORSH-RPC-SDK-01.json','chain/cache_prepare_parallel.mjs'];
export function acquisitionSources(selected,a){
 const manifest=strictJson(readPublic(selected.path,selected.sha256)),base=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
 need(manifest.schema==='kpxa-public-offline-pool-selection/v1','ACQUISITION_SOURCE','explicit outer source selection');
 need(manifest.parent_runtime.path===a['runtime-source']&&manifest.parent_runtime.sha256===a['runtime-source-sha256']&&manifest.parent_admission.path===a['cache-admission']&&manifest.parent_admission.sha256===a['cache-admission-sha256'],'ACQUISITION_SOURCE','same baseline cache and financial roles');
 const rows=new Map(manifest.source_members.map(r=>[r.path,r]));need(rows.size===manifest.source_members.length,'ACQUISITION_SOURCE','unique source members');
 return NETWORK_NAMES.map(name=>{const file=path.join(base,name),row=rows.get(file);need(row&&Object.keys(row).sort().join(',')==='path,sha256','ACQUISITION_SOURCE','selected network source member');readPublic(row.path,row.sha256);return row;}).sort((x,y)=>x.path.localeCompare(y.path));
}
export async function execute(pp,ps,dp,ds,output,a,acquisition,urls=DEFAULT_RPCS,k=loadSdk()){
 const sources=acquisitionSources(acquisition,a);
 const rawP=readPublic(pp,ps),rawD=readPublic(dp,ds),selected=profile(rawP,ps),d=descriptor(rawD,ds,selected,ps),info=admitted(a,rawP,ps,rawD,ds,k);output=checkedPath(output);
 need(!fs.existsSync(output),'OUTPUT_EXISTS','fresh cached acquisition output');fs.mkdirSync(output,{recursive:true,mode:0o700});const attempts=[];
 for(let index=0;index<urls.length;index++){
  const endpoint=new URL(urls[index]);need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'ENDPOINT','public Tor TLS endpoint');
  const root=path.join(output,`attempt-${String(index+1).padStart(3,'0')}`);fs.mkdirSync(root,{mode:0o700});let connection,phase='authenticate-and-copy-local-prefix';
  try{
   // All six guarded-reader copies must finish before WebSocket heartbeat
   // timers or the fixed live frontier exist.
   const prepared=await prepareBaseParallel(info,a,root);phase='connect-tor';
   connection=await connectReadOnlyBorsh(k,endpoint.href,acquisition,path.join(root,'PUBLIC-BORSH-EVENTS.jsonl'));let value,used=root;phase='fresh-fixed-delta-and-current-view';
   try{value=await fetchCachedOne(k,connection.rpc,selected,ps,d,ds,root,info,a,prepared);}
   catch(error){if(!['CACHE_STALE','REORG','STALE_FRONTIER','STALE_CURRENT_VIEW'].includes(error.category))throw error;used=path.join(root,'full-fallback');fs.mkdirSync(used,{mode:0o700});value=await fetchOne(k,connection.rpc,selected,ps,d,ds,used);value.cache_fallback={category:error.category,full_acquisition:true};}
   value.source={rpc_url:endpoint.href,attempt:index+1,assertion_scope:'Selected validating-node prefix; cache is not consensus proof'};value.attempts=attempts;const relative=path.relative(output,used).split(path.sep).join('/');
   value.pages.forEach(r=>{r.path=path.posix.join(relative,r.path);});value.current_view.post_query_delta.pages.forEach(r=>{r.path=path.posix.join(relative,r.path);});const saved=save(path.join(output,'fetch.json'),value);
   save(path.join(output,'ACQUISITION-SOURCES.json'),{schema:'kpxa-public-acquisition-sources/v1',scope:'public-readonly-network-acquisition',outer_selection_sha256:acquisition.sha256,source_members:sources,baseline_runtime_sources:{path:a['runtime-source'],sha256:a['runtime-source-sha256']},baseline_admission:{path:a['cache-admission'],sha256:a['cache-admission-sha256']},fetch:{path:path.join(output,'fetch.json'),sha256:saved.sha256},transport:'TOR_SOCKS5H_TLS_BORSH',rpc_deadline_seconds:900,financial_or_consensus_authority:false});return value;
  }catch(error){if(connection){await connection.close();connection=null;}const publicBorsh=publicAcquisitionDiagnostic(error);const message=String(error.message??error),hint=message.match(/WebSocket disconnected|not connected|connection closed|timed? ?out|missing|changed|stale|invalid/i)?.[0]??'public acquisition error';const line=String(error.stack??'').match(/(?:kaspa\.js|[A-Za-z_]+\.mjs):\d+:\d+/)?.[0]??null;const failed={rpc_url:endpoint.href,status:'INCOMPLETE',category:error.category??'DATA_UNAVAILABLE',phase,error_class:error.name??typeof error,safe_hint:hint,public_source_line:line,...(publicBorsh?{public_borsh_diagnostic:publicBorsh,public_borsh_events:'PUBLIC-BORSH-EVENTS.jsonl'}:{}),recorded_at:new Date().toISOString()};save(path.join(root,'INCOMPLETE.json'),failed);attempts.push(failed);}finally{if(connection)await connection.close();}
 }
 const value={schema:'kpxa-gn3-network-fetch/v1',status:'INCOMPLETE',attempts,balance_known:false,no_empty_balance_inference:true};save(path.join(output,'INCOMPLETE.json'),value);return value;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const [pp,ps,dp,ds,output,...rest]=process.argv.slice(2),cache=[],urls=[];let sdk,acquisitionPath,acquisitionSha;
  for(let i=0;i<rest.length;i++){if(rest[i]==='--acquisition-source'){need(!acquisitionPath,'ARGUMENT','duplicate acquisition source');acquisitionPath=rest[++i];}else if(rest[i]==='--acquisition-source-sha256'){need(!acquisitionSha,'ARGUMENT','duplicate acquisition source pin');acquisitionSha=rest[++i];}else if(rest[i]==='--rpc')urls.push(rest[++i]);else if(rest[i]==='--sdk-dir')sdk=rest[++i];else{cache.push(rest[i]);if(rest[i]!=='--trusted-local-cache')cache.push(rest[++i]);}}
  need(acquisitionPath&&acquisitionSha,'ARGUMENT','explicit acquisition source required');const result=await execute(pp,ps,dp,ds,output,cacheOptions(cache),{path:acquisitionPath,sha256:acquisitionSha},urls.length?urls:DEFAULT_RPCS,loadSdk(sdk));process.stdout.write(stringify({status:result.status,transactions:result.transactions?.length})+'\n');if(result.status==='INCOMPLETE')process.exitCode=2;
 }catch(error){process.stderr.write(`cached acquisition incomplete: ${error.category??'ERROR'}\n`);process.exitCode=2;}
}
