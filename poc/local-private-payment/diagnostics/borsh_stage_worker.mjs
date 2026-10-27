// NEW diagnostic only. Production worker and SDK stay unchanged.
import {createRequire} from 'node:module';
import path from 'node:path';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {performance} from 'node:perf_hooks';
import {guardedRead} from '../chain/public.mjs';
import {strictJson} from '../chain/json.mjs';
import {SDK_MANIFEST_ROW,loopback,requestLine,materialize,encode} from '../ingress/readonly_borsh_worker.mjs';
export function safeError(error){
 const type=error?.name,allowed=['Error','TypeError','RangeError','SyntaxError','ReferenceError','AggregateError','RuntimeError','DOMException'];
 const text=String(error?.message??error);
 const hints=[[/websocket.*disconnect|not connected|connection closed/i,'DISCONNECTED'],[/timed? ?out|timeout/i,'TIMEOUT'],[/out of memory|allocation/i,'MEMORY'],[/maximum call stack|stack overflow/i,'STACK'],[/invalid string length/i,'STRING_LENGTH'],[/unreachable|out of bounds/i,'WASM_RUNTIME'],[/duplicate-field|json-/i,'JSON_VALIDATION'],[/integer|range/i,'INTEGER_VALIDATION'],[/serialize|circular|BigInt/i,'SERIALIZATION']];
 return {error_class:allowed.includes(type)?type:typeof error,safe_hint:hints.find(([pattern])=>pattern.test(text))?.[1]??'UNCLASSIFIED_PUBLIC_ERROR'};
}
export async function main(argv){
 if(argv.length!==2||argv[0]!=='--url')throw new Error('closed arguments');const url=loopback(argv[1]);
 const started=performance.now();let method=null,cursor=null,phase='SDK_LOAD',rpc;
 const event=(status,extra={})=>process.stderr.write(JSON.stringify({schema:'kpxa-public-borsh-stage/v1',phase,status,method,cursor,elapsed_ms:performance.now()-started,utc:new Date().toISOString(),...extra})+'\n');
 for(const key of ['log','info','warn','error','debug'])console[key]=()=>{};
 const manifest=strictJson(guardedRead(SDK_MANIFEST_ROW.path,SDK_MANIFEST_ROW.sha256));
 if(manifest.request_timeout_ms!==900000||manifest.directory!=='/dev/shm/kpi-borsh-deadline-build-01/network-sdk')throw new Error('SDK identity');
 for(const row of manifest.files){const bytes=guardedRead(path.join(manifest.directory,row.name),row.sha256);if(bytes.length!==row.bytes)throw new Error('SDK size');}
 const k=createRequire(import.meta.url)(path.join(manifest.directory,'kaspa_rpc.js'));
 const send=async value=>{phase='ENCODE';const line=encode(value)+'\n';event('COMPLETE',{encoded_bytes:Buffer.byteLength(line)});phase='STDOUT';if(!process.stdout.write(line))await once(process.stdout,'drain');event('COMPLETE');};
 const lines=createInterface({input:process.stdin,crlfDelay:Infinity});let lastId=0;
 try{
  phase='CONNECT';event('START');rpc=new k.RpcClient({url,networkId:'testnet-10'});if(rpc.resolver!=null)throw new Error('resolver disabled');await rpc.connect({blockAsyncConnect:true,timeoutDuration:300000,strategy:'fallback'});if(new URL(rpc.url).href!==url)throw new Error('loopback changed');event('COMPLETE');
  phase='SDK_AWAIT';method='getBlockDagInfo';event('START');const dag=await rpc.getBlockDagInfo();if(dag.network!=='testnet-10')throw new Error('network identity');event('COMPLETE');
  await send({ready:true,network_id:'testnet-10',transport:'TOR_SOCKS5H_TLS_BORSH',rpc_deadline_seconds:900});
  for await(const line of lines){phase='REQUEST';method=null;cursor=null;const q=requestLine(line,lastId);lastId=q.id;method=q.method;cursor=q.params.startHash??null;event('COMPLETE');
   try{phase='SDK_AWAIT';event('START');const raw=await rpc[q.method](q.params);event('COMPLETE');phase='MATERIALIZE';event('START');const value=materialize(q.method,raw);event('COMPLETE');await send({id:q.id,ok:true,params:value});}
   catch(error){event('FAIL',safeError(error));await send({id:q.id,ok:false,error_class:'ReadOnlyRpcFailure',category:'DATA_UNAVAILABLE'});}
  }
 }catch(error){event('FAIL',safeError(error));throw new Error('diagnostic worker failed');}
 finally{lines.close();if(rpc)try{await rpc.disconnect();}catch{}}
}
if(process.argv[1]?.endsWith('/borsh_stage_worker.mjs'))main(process.argv.slice(2)).catch(()=>{process.exitCode=2;});
