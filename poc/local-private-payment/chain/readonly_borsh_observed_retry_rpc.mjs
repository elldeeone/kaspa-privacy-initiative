// Non-live observed retry sibling: one classified read reconnect, unchanged IPC.
import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {guardedRead} from './public.mjs';
import {strictJson} from './json.mjs';
import {startTorBridge} from '../ingress/bridge.mjs';
import {METHODS,SDK_MANIFEST_ROW,exact,loopback} from '../ingress/readonly_borsh_worker.mjs';
const OLD_WORKER=fileURLToPath(new URL('../ingress/readonly_borsh_worker.mjs',import.meta.url));
const WORKER=fileURLToPath(new URL('../diagnostics/borsh_stage_worker.mjs',import.meta.url));
const SELF=fileURLToPath(import.meta.url);
const NODE='/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node';
const need=(condition,message)=>{if(!condition)throw new Error(message);};
const ERRORS=['Error','TypeError','RangeError','SyntaxError','ReferenceError','AggregateError','RuntimeError','DOMException','object','string','number','boolean','undefined','bigint','symbol','function'];
const HINTS=['DISCONNECTED','TIMEOUT','MEMORY','STACK','STRING_LENGTH','WASM_RUNTIME','JSON_VALIDATION','INTEGER_VALIDATION','SERIALIZATION','UNCLASSIFIED_PUBLIC_ERROR'];
const DIAGNOSTICS=new WeakMap();
function unavailable(snapshot){const e=new Error('read-only Borsh acquisition unavailable');e.category='DATA_UNAVAILABLE';DIAGNOSTICS.set(e,snapshot);return e;}
export function publicAcquisitionDiagnostic(error){return DIAGNOSTICS.get(error)?.()??null;}
export function workerStage(value){
 const extra=value?.status==='FAIL'?['error_class','safe_hint']:value?.phase==='ENCODE'&&value?.status==='COMPLETE'?['encoded_bytes']:[];
 exact(value,['schema','phase','status','method','cursor','elapsed_ms','utc',...extra]);
 need(value.schema==='kpxa-public-borsh-stage/v1'&&['SDK_LOAD','CONNECT','REQUEST','SDK_AWAIT','MATERIALIZE','ENCODE','STDOUT'].includes(value.phase)&&['START','COMPLETE','FAIL'].includes(value.status),'typed worker stage');
 need(['CONNECT','SDK_AWAIT','MATERIALIZE'].includes(value.phase)||['REQUEST','ENCODE','STDOUT'].includes(value.phase)&&value.status!=='START','producer phase and status');
 need((value.method===null||METHODS.includes(value.method))&&(value.cursor===null||typeof value.cursor==='string'&&/^[0-9a-f]{64}$/.test(value.cursor)),'typed worker request');
 need(Number.isFinite(value.elapsed_ms)&&value.elapsed_ms>=0&&typeof value.utc==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value.utc)&&Number.isFinite(Date.parse(value.utc)),'typed worker clock');
 need(new Date(value.utc).toISOString()===value.utc,'canonical worker clock');
 if(value.phase==='CONNECT')need(value.method===null&&value.cursor===null,'connect has no request');
 else if(value.phase==='REQUEST'&&value.status==='FAIL'&&value.method===null)need(value.cursor===null,'unparsed request has no cursor');
 else need(METHODS.includes(value.method)&&(value.method==='getVirtualChainFromBlockV2'?value.cursor!==null:value.cursor===null),'stage belongs to one read-only request');
 if(value.status==='FAIL')need(ERRORS.includes(value.error_class)&&HINTS.includes(value.safe_hint),'typed worker failure');
 if(extra.includes('encoded_bytes'))need(Number.isSafeInteger(value.encoded_bytes)&&value.encoded_bytes>0,'typed encoded bytes');
 return Object.freeze({schema:value.schema,phase:value.phase,status:value.status,method:value.method,cursor:value.cursor,elapsed_ms:value.elapsed_ms,utc:value.utc,...Object.fromEntries(extra.map(key=>[key,value[key]]))});
}
export function sourceSelection(row){
 exact(row,['path','sha256']);const selected=strictJson(guardedRead(row.path,row.sha256));need(Array.isArray(selected.source_members),'outer source members');
 const seen=new Set();for(const member of selected.source_members){need(typeof member.path==='string'&&!seen.has(member.path),'unique source path');seen.add(member.path);guardedRead(member.path,member.sha256);}
 for(const required of [OLD_WORKER,WORKER,SELF,SDK_MANIFEST_ROW.path])need(selected.source_members.some(r=>r.path===required),'missing read-only source');
 need(selected.source_members.some(r=>r.path===SDK_MANIFEST_ROW.path&&r.sha256===SDK_MANIFEST_ROW.sha256),'selected network SDK manifest');
 const sdk=strictJson(guardedRead(SDK_MANIFEST_ROW.path,SDK_MANIFEST_ROW.sha256));
 return {schema:'kpxa-readonly-borsh-acquisition-sources/v1',outer_profile_sha256:row.sha256,sdk_manifest:SDK_MANIFEST_ROW,sdk_files:sdk.files.map(x=>({path:path.join(sdk.directory,x.name),bytes:x.bytes,sha256:x.sha256})),request_timeout_ms:900000};
}
function requestMeta(id,method,params){return {call:id,method,cursor:typeof params?.startHash==='string'&&/^[0-9a-f]{64}$/.test(params.startHash)?params.startHash:null,address_count:Array.isArray(params?.addresses)?params.addresses.length:null};}
function counts(method,value){
 if(method==='getVirtualChainFromBlockV2')return {added_blocks:Array.isArray(value.addedChainBlockHashes)?value.addedChainBlockHashes.length:null,accepted_groups:Array.isArray(value.chainBlockAcceptedTransactions)?value.chainBlockAcceptedTransactions.length:null,accepted_transactions:Array.isArray(value.chainBlockAcceptedTransactions)&&value.chainBlockAcceptedTransactions.every(g=>Array.isArray(g?.acceptedTransactions))?value.chainBlockAcceptedTransactions.reduce((n,g)=>n+g.acceptedTransactions.length,0):null};
 if(method==='getUtxosByAddresses')return {utxo_entries:Array.isArray(value.entries)?value.entries.length:null};
 if(method==='getBlock')return {transactions:Array.isArray(value.block?.transactions)?value.block.transactions.length:null};
 return {};
}
export function ipcClient(child,record=()=>{}){
 const lines=createInterface({input:child.stdout,crlfDelay:Infinity}),stages=createInterface({input:child.stderr,crlfDelay:Infinity});let readyResolve,readyReject,pending=null,lastId=0,closed=false,failed=false,readySeen=false,closePromise;
 let firstFailure=null,lastWorkerStage=null,lastWorkerFailure=null,lastRequest=null,lastResponse=null,started=0,completed=0,replies=0,sequence=0,recorded=0,rejectedStderr=0,writeFailed=false,stdoutEof=false,stderrEof=false;
 let workerExit={observed:false,code:null,signal:null},childClose={observed:false,code:null,signal:null};
 const emit=(event,fields={})=>{const value={schema:'kpxa-public-borsh-observation/v1',sequence:++sequence,event,utc:new Date().toISOString(),...fields};try{record(value);recorded++;}catch{writeFailed=true;}};
 const snapshot=stage=>({schema:'kpxa-public-borsh-failure/v1',failure_stage:stage,first_failure_stage:firstFailure,last_request:lastRequest,last_response:lastResponse,requests_started:started,requests_completed:completed,replies_received:replies,last_worker_stage:lastWorkerStage,last_worker_failure:lastWorkerFailure,worker_exit:{...workerExit},child_close:{...childClose},stdout_eof:stdoutEof,stderr_eof:stderrEof,events_recorded:recorded,rejected_stderr_lines:rejectedStderr,diagnostic_write_failed:writeFailed});
 const failure=stage=>{firstFailure??=stage;emit('FAILURE',{stage});return unavailable(()=>snapshot(stage));};
 const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});ready.catch(()=>{});
 // Child close, unlike exit, follows both pipe closures and all typed stderr.
 const drained=new Promise(resolve=>child.once('close',(code,signal)=>{childClose={observed:true,code,signal};emit('CHILD_CLOSE',{code,signal});resolve();}));
 function fail(stage){failed=true;const e=failure(stage);readyReject(e);if(pending){pending.reject(e);pending=null;}if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');}
 child.once('error',()=>fail('WORKER_SPAWN'));child.once('exit',(code,signal)=>{workerExit={observed:true,code,signal};emit('WORKER_EXIT',{code,signal});if(!closed){const e=failure('WORKER_EXIT');readyReject(e);if(pending){pending.reject(e);pending=null;}}});
 child.stdin.on('error',()=>{if(!closed)fail('WORKER_STDIN');});
 lines.on('close',()=>{stdoutEof=true;emit('STDOUT_EOF',{controlled_close:closed});if(!closed)fail('WORKER_STDOUT_EOF');});
 stages.on('close',()=>{stderrEof=true;emit('STDERR_EOF',{controlled_close:closed});});
 stages.on('line',line=>{try{const value=workerStage(strictJson(line));lastWorkerStage=value;if(value.status==='FAIL')lastWorkerFailure=value;emit('WORKER_STAGE',{worker:value});}catch{rejectedStderr++;}});
 lines.on('line',line=>{
  let stage='PARENT_IPC_PARSE';
  try{const v=strictJson(line);stage='PARENT_IPC_SHAPE';
   if(!readySeen){exact(v,['ready','network_id','transport','rpc_deadline_seconds']);need(v.ready===true&&v.network_id==='testnet-10'&&v.transport==='TOR_SOCKS5H_TLS_BORSH'&&v.rpc_deadline_seconds===900,'worker ready');readySeen=true;emit('READY');readyResolve();return;}
   need(pending&&v.id===pending.id&&typeof v.ok==='boolean','worker response id');
   if(v.ok){exact(v,['id','ok','params']);need(v.params&&typeof v.params==='object'&&!Array.isArray(v.params),'worker result object');const p=pending;pending=null;replies++;completed++;lastResponse={...p.meta,ok:true,reply_bytes:Buffer.byteLength(line),...counts(p.meta.method,v.params)};emit('RESPONSE',lastResponse);p.resolve(v.params);}
   else{exact(v,['id','ok','error_class','category']);need(v.error_class==='ReadOnlyRpcFailure'&&v.category==='DATA_UNAVAILABLE','worker failure shape');const p=pending;pending=null;replies++;lastResponse={...p.meta,ok:false,reply_bytes:Buffer.byteLength(line)};emit('RESPONSE',lastResponse);p.reject(failure('WORKER_RPC_FAILURE'));}
  }catch{fail(stage);}
 });
 const rpc={};for(const method of METHODS)rpc[method]=async(params={})=>{
  await ready;try{need(!closed&&!failed&&child.exitCode===null,'worker closed');need(pending===null,'read-only singleflight');need(lastId<Number.MAX_SAFE_INTEGER,'request ids exhausted');}catch{throw failure('PARENT_REQUEST');}const id=++lastId;
  return new Promise((resolve,reject)=>{const meta=requestMeta(id,method,params);lastRequest=meta;started++;pending={id,resolve,reject,meta};emit('REQUEST',meta);try{child.stdin.write(JSON.stringify({id,method,params})+'\n');}catch{fail('PARENT_REQUEST_ENCODE');}});
 };
 const close=()=>closePromise??=(async()=>{closed=true;if(pending){pending.reject(failure('CONTROLLED_CLOSE'));pending=null;}child.stdin.end();let timer;await Promise.race([drained,new Promise(resolve=>{timer=setTimeout(resolve,5000);})]);clearTimeout(timer);if(!childClose.observed){if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');await drained;}lines.close();stages.close();})();
 return {ready,rpc,close};
}
// A retry is evidence-driven and applies only to these five read-only methods.
export function eligibleReadRetry(value,method,params){
 const cursor=typeof params?.startHash==='string'&&/^[0-9a-f]{64}$/.test(params.startHash)?params.startHash:null,f=value?.last_worker_failure,q=value?.last_request,r=value?.last_response;
 return METHODS.includes(method)&&value?.failure_stage==='WORKER_RPC_FAILURE'&&f?.status==='FAIL'&&f.phase==='SDK_AWAIT'&&f.safe_hint==='DISCONNECTED'&&f.method===method&&f.cursor===cursor&&q?.method===method&&q.cursor===cursor&&Number.isSafeInteger(q.call)&&q.call>0&&r?.ok===false&&r.call===q.call&&r.method===method&&r.cursor===cursor;
}
export async function connectReadOnlyBorsh(_oldFinancialSdk,upstream,outerSelectionRow,diagnosticPath){
 const u=new URL(upstream);need(u.protocol==='wss:'&&u.port===''&&['vector-10.kaspa.green','electron-10.kaspa.blue'].includes(u.hostname)&&u.pathname==='/kaspa/testnet-10/wrpc/borsh'&&!u.username&&!u.password&&!u.search&&!u.hash,'selected testnet Borsh peer');
 const acquisitionSources=sourceSelection(outerSelectionRow);need(typeof diagnosticPath==='string'&&path.isAbsolute(diagnosticPath),'explicit public diagnostic output');const fd=fs.openSync(diagnosticPath,'wx',0o400);
 let bridge,client,stopping,generation=0,logicalCall=0,activeCall=null,logicalPending=false,closed=false,closePromise,journalClosed=false,journalSequence=0,journalRecords=0,journalFailed=false,cleanupFailed=false;
 const write=value=>{fs.writeSync(fd,JSON.stringify({...value,sequence:++journalSequence})+'\n');journalRecords++;};
 const mark=(event,fields={})=>{try{write({schema:'kpxa-public-borsh-observation/v1',event,utc:new Date().toISOString(),generation,logical_call:activeCall,...fields});}catch{journalFailed=true;}};
 const closeJournal=()=>{if(!journalClosed){journalClosed=true;fs.closeSync(fd);}};
 const stop=()=>{if(stopping)return stopping;const c=client,b=bridge;client=null;bridge=null;return stopping=(async()=>{try{if(c)await c.close();}finally{if(b)await b.close();}})().finally(()=>{stopping=null;});};
 const open=async()=>{need(!closed,'connection closed');const ownGeneration=++generation,b=await startTorBridge({upstream:u.href});if(closed){await b.close();throw new Error('connection closed');}bridge=b;const child=spawn(NODE,[WORKER,'--url',loopback(bridge.url)],{env:{PATH:'/usr/bin:/bin'},stdio:['pipe','pipe','pipe']});client=ipcClient(child,value=>{const {sequence:worker_sequence,...fields}=value;try{write({...fields,generation:ownGeneration,logical_call:activeCall,worker_sequence});}catch{journalFailed=true;throw new Error('public diagnostic write failed');}});await client.ready;};
 const unknown=stage=>({schema:'kpxa-public-borsh-failure/v1',failure_stage:stage,last_worker_failure:null,worker_exit:{observed:false,code:null,signal:null},child_close:{observed:false,code:null,signal:null},stdout_eof:false,stderr_eof:false});
 const failure=(history,stage='PARENT_REQUEST')=>{const call=activeCall,failedGeneration=generation;return unavailable(()=>({...history.at(-1)?.diagnostic??unknown(stage),logical_call:call,generation:failedGeneration,read_retry:{maximum_retries:1,attempted:history.length===2,first_failure:history[0]??null,retry_failure:history[1]??null},cleanup_failed:cleanupFailed,journal_records:journalRecords,diagnostic_write_failed:journalFailed||history.some(row=>row.diagnostic.diagnostic_write_failed===true)}));};
 const close=()=>closePromise??=(async()=>{closed=true;try{await stop();}catch{cleanupFailed=true;mark('CLEANUP_FAILURE');throw failure([],'CLEANUP_FAILURE');}finally{closeJournal();}})();
 try{
  // An initial ready/handshake failure has no logical read to retry.
  await open();const rpc={};
  for(const method of METHODS)rpc[method]=async(params={})=>{
   if(closed||logicalPending||logicalCall>=Number.MAX_SAFE_INTEGER)throw failure([]);
   logicalPending=true;activeCall=++logicalCall;const call=activeCall,history=[];let stableParams;
   try{
    // One JSON snapshot prevents caller mutation from changing the second send.
    try{stableParams=JSON.parse(JSON.stringify(params));}catch{throw failure([],'PARENT_REQUEST_ENCODE');}
    mark('LOGICAL_REQUEST',requestMeta(call,method,stableParams));
    for(let attempt=0;attempt<2;attempt++){
     try{if(attempt===1)await open();const value=await client.rpc[method](stableParams);mark('LOGICAL_RETURN',{call,method,read_retries:attempt,...counts(method,value)});return value;}
     catch(error){const failedGeneration=generation;let stopped=true;try{await stop();}catch{stopped=false;cleanupFailed=true;mark('CLEANUP_FAILURE');}const diagnostic=publicAcquisitionDiagnostic(error)??unknown(attempt===1?'BRIDGE_CONNECT':'PARENT_REQUEST');history.push({generation:failedGeneration,diagnostic,cleanup_failed:!stopped});
      // Drain BOTH streams before examining the positive typed SDK failure.
      if(attempt===0&&stopped&&!closed&&eligibleReadRetry(diagnostic,method,stableParams)){mark('READ_RETRY',{call,method,cursor:requestMeta(call,method,stableParams).cursor,reason:'SDK_AWAIT_DISCONNECTED',next_generation:generation+1});continue;}
      throw failure(history);
     }
    }
   }finally{logicalPending=false;activeCall=null;}
  };
  return {rpc,transport:'TOR_SOCKS5H_TLS_BORSH',acquisitionSources,close};
 }catch(error){try{await close();}catch{}const original=publicAcquisitionDiagnostic(error);if(original&&!cleanupFailed)throw error;throw unavailable(()=>({...publicAcquisitionDiagnostic(error)??unknown('BRIDGE_CONNECT'),generation,logical_call:null,cleanup_failed:cleanupFailed,journal_records:journalRecords,diagnostic_write_failed:journalFailed}));}
}
