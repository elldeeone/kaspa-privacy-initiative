// A read-only network process remains responsive while the caller performs sync guards.
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {guardedRead} from './public.mjs';
import {strictJson} from './json.mjs';
import {startTorBridge} from '../ingress/bridge.mjs';
import {METHODS,SDK_MANIFEST_ROW,exact,loopback} from '../ingress/readonly_borsh_worker.mjs';
const WORKER=fileURLToPath(new URL('../ingress/readonly_borsh_worker.mjs',import.meta.url));
const SELF=fileURLToPath(import.meta.url);
const NODE='/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node';
const need=(condition,message)=>{if(!condition)throw new Error(message);};
function unavailable(){const e=new Error('read-only Borsh acquisition unavailable');e.category='DATA_UNAVAILABLE';return e;}
export function sourceSelection(row){
 exact(row,['path','sha256']);const selected=strictJson(guardedRead(row.path,row.sha256));need(Array.isArray(selected.source_members),'outer source members');
 const seen=new Set();for(const member of selected.source_members){need(typeof member.path==='string'&&!seen.has(member.path),'unique source path');seen.add(member.path);guardedRead(member.path,member.sha256);}
 for(const required of [WORKER,SELF,SDK_MANIFEST_ROW.path])need(selected.source_members.some(r=>r.path===required),'missing read-only source');
 need(selected.source_members.some(r=>r.path===SDK_MANIFEST_ROW.path&&r.sha256===SDK_MANIFEST_ROW.sha256),'selected network SDK manifest');
 const sdk=strictJson(guardedRead(SDK_MANIFEST_ROW.path,SDK_MANIFEST_ROW.sha256));
 return {schema:'kpxa-readonly-borsh-acquisition-sources/v1',outer_profile_sha256:row.sha256,sdk_manifest:SDK_MANIFEST_ROW,sdk_files:sdk.files.map(x=>({path:path.join(sdk.directory,x.name),bytes:x.bytes,sha256:x.sha256})),request_timeout_ms:900000};
}
export function ipcClient(child){
 const lines=createInterface({input:child.stdout,crlfDelay:Infinity});let readyResolve,readyReject,pending=null,lastId=0,closed=false,failed=false,readySeen=false;
 const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
 const exited=new Promise(resolve=>{for(const event of ['exit','close','error'])child.once(event,resolve);});
 function fail(){failed=true;const e=unavailable();readyReject(e);if(pending){pending.reject(e);pending=null;}if(child.exitCode===null)child.kill('SIGTERM');}
 child.stderr.resume();child.once('error',fail);child.once('exit',()=>{readyReject(unavailable());if(pending){pending.reject(unavailable());pending=null;}});child.stdin.on('error',fail);lines.on('close',()=>{if(!closed)fail();});
 lines.on('line',line=>{
  try{const v=strictJson(line);
   if(!readySeen){exact(v,['ready','network_id','transport','rpc_deadline_seconds']);need(v.ready===true&&v.network_id==='testnet-10'&&v.transport==='TOR_SOCKS5H_TLS_BORSH'&&v.rpc_deadline_seconds===900,'worker ready');readySeen=true;readyResolve();return;}
   need(pending&&v.id===pending.id&&typeof v.ok==='boolean','worker response id');
   if(v.ok){exact(v,['id','ok','params']);need(v.params&&typeof v.params==='object'&&!Array.isArray(v.params),'worker result object');const p=pending;pending=null;p.resolve(v.params);}
   else{exact(v,['id','ok','error_class','category']);need(v.error_class==='ReadOnlyRpcFailure'&&v.category==='DATA_UNAVAILABLE','worker failure shape');const p=pending;pending=null;p.reject(unavailable());}
  }catch{fail();}
 });
 const rpc={};for(const method of METHODS)rpc[method]=async(params={})=>{
  await ready;need(!closed&&!failed&&child.exitCode===null,'worker closed');need(pending===null,'read-only singleflight');need(lastId<Number.MAX_SAFE_INTEGER,'request ids exhausted');const id=++lastId;
  return new Promise((resolve,reject)=>{pending={id,resolve,reject};child.stdin.write(JSON.stringify({id,method,params})+'\n');});
 };
 const close=async()=>{if(closed)return;closed=true;lines.close();if(pending){pending.reject(unavailable());pending=null;}child.stdin.end();if(child.exitCode===null){let timer;await Promise.race([exited,new Promise(resolve=>{timer=setTimeout(resolve,5000);})]);clearTimeout(timer);if(child.exitCode===null){child.kill('SIGTERM');await exited;}}};
 return {ready,rpc,close};
}
export async function connectReadOnlyBorsh(_oldFinancialSdk,upstream,outerSelectionRow){
 const u=new URL(upstream);need(u.protocol==='wss:'&&u.port===''&&['vector-10.kaspa.green','electron-10.kaspa.blue'].includes(u.hostname)&&u.pathname==='/kaspa/testnet-10/wrpc/borsh'&&!u.username&&!u.password&&!u.search&&!u.hash,'selected testnet Borsh peer');
 const acquisitionSources=sourceSelection(outerSelectionRow);let bridge,client;
 try{bridge=await startTorBridge({upstream:u.href});const child=spawn(NODE,[WORKER,'--url',loopback(bridge.url)],{env:{PATH:'/usr/bin:/bin'},stdio:['pipe','pipe','pipe']});client=ipcClient(child);await client.ready;
  return {rpc:client.rpc,transport:'TOR_SOCKS5H_TLS_BORSH',acquisitionSources,close:async()=>{try{await client.close();}finally{await bridge.close();}}};
 }catch(e){try{if(client)await client.close();}finally{if(bridge)await bridge.close();}throw e;}
}
