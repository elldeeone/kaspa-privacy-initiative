// Separate network event loop; main-thread synchronous public guards cannot block it.
// The selected parent supplies the single-session Tor/SOCKS5h/TLS bridge.
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';
import {createInterface} from 'node:readline';
import {once} from 'node:events';
import {guardedRead} from '../chain/public.mjs';
import {strictJson} from '../chain/json.mjs';
import {plainHeader,point,pointKey,hex} from '../chain/wire.mjs';
import {entry as originalEntry} from '../chain/acquire.mjs';
export const METHODS=Object.freeze(['getServerInfo','getBlockDagInfo','getBlock','getUtxosByAddresses','getVirtualChainFromBlockV2']);
export const SDK_MANIFEST_ROW=Object.freeze({path:fileURLToPath(new URL('./BORSH-RPC-SDK-01.json',import.meta.url)),sha256:'4bb8ca2f39859b9b9809ccc34f4981e985bb2141624cf65f846c37f0e430dc62'});
const need=(condition,message)=>{if(!condition)throw new Error(message);};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function exact(value,names){need(object(value)&&Object.keys(value).sort().join(',')===[...names].sort().join(','),'closed object fields');}
export function loopback(value){
 need(typeof value==='string','loopback URL');const u=new URL(value);
 need(u.protocol==='ws:'&&u.hostname==='127.0.0.1'&&u.port&&Number(u.port)>0&&Number(u.port)<=65535&&u.pathname==='/'&&!u.username&&!u.password&&!u.search&&!u.hash,'exact loopback URL');return u.href;
}
export function request(value,lastId){
 exact(value,['id','method','params']);need(Number.isSafeInteger(value.id)&&value.id>0&&value.id===lastId+1,'monotonic request id');
 need(METHODS.includes(value.method)&&object(value.params),'read-only method');const p=value.params;
 if(['getServerInfo','getBlockDagInfo'].includes(value.method))exact(p,[]);
 else if(value.method==='getBlock'){exact(p,['hash','includeTransactions']);hex(p.hash,32);need(p.includeTransactions===false,'header-only block');}
 else if(value.method==='getUtxosByAddresses'){exact(p,['addresses']);need(Array.isArray(p.addresses)&&p.addresses.length>0&&p.addresses.every(a=>typeof a==='string'&&/^kaspatest:[a-z0-9]+$/.test(a)),'testnet addresses');}
 else{exact(p,['startHash','dataVerbosityLevel','minConfirmationCount']);hex(p.startHash,32);need(p.dataVerbosityLevel==='Full'&&p.minConfirmationCount===20,'exact Full depth20');}
 return value;
}
export function requestLine(line,lastId){return request(strictJson(line),lastId);}
export function materialize(method,value){
 need(object(value),'RPC response object');
 if(method==='getBlock'){
  const b=value.block;need(object(b)&&object(b.verboseData)&&Array.isArray(b.transactions),'block response shape');
  return {...value,block:{...b,header:plainHeader(b.header),transactions:b.transactions,verboseData:b.verboseData}};
 }
 if(method==='getVirtualChainFromBlockV2'){
  need(Array.isArray(value.addedChainBlockHashes)&&Array.isArray(value.removedChainBlockHashes)&&Array.isArray(value.chainBlockAcceptedTransactions),'Full response arrays');
  return {...value,chainBlockAcceptedTransactions:value.chainBlockAcceptedTransactions.map(g=>{
   need(object(g)&&Array.isArray(g.acceptedTransactions),'Full group shape');return {...g,chainBlockHeader:plainHeader(g.chainBlockHeader),acceptedTransactions:g.acceptedTransactions};
  })};
 }
 if(method==='getUtxosByAddresses'){
  need(Array.isArray(value.entries),'UTXO entries');return {...value,entries:value.entries.map(raw=>{
   const v=originalEntry(raw);
   if(raw.outpoint!==undefined)need(pointKey(point(raw.outpoint))===pointKey(v.outpoint),'UTXO outpoint aliases differ');
   const row={outpoint:v.outpoint,entry:{outpoint:v.outpoint,amount:v.amount_sompi,scriptPublicKey:v.script_public_key,blockDaaScore:v.block_daa_score,isCoinbase:v.is_coinbase,covenantId:v.covenant_id}};
   if(raw.address!==undefined&&raw.address!==null)row.address=String(raw.address);return row;
  })};
 }
 if(method==='getBlockDagInfo')need(value.network==='testnet-10','testnet identity');
 return value;
}
export function encode(value){return JSON.stringify(value,(_key,v)=>{if(typeof v==='bigint')return v.toString();if(typeof v==='number')need(Number.isFinite(v),'nonfinite RPC number');return v;});}
function selectedSdk(){
 const s=strictJson(guardedRead(SDK_MANIFEST_ROW.path,SDK_MANIFEST_ROW.sha256));
 need(s.schema==='kpxa-network-rpc-sdk-selection/v1'&&s.source_commit==='01b532e8b553523216471682649693af92f0fd16'&&s.request_timeout_ms===900000,'selected network SDK');
 need(s.directory==='/dev/shm/kpi-borsh-deadline-build-01/network-sdk'&&Array.isArray(s.files)&&s.files.map(x=>x.name).sort().join(',')==='kaspa_rpc.d.ts,kaspa_rpc.js,kaspa_rpc_bg.wasm','static SDK files');
 for(const row of s.files){const b=guardedRead(path.join(s.directory,row.name),row.sha256);need(b.length===row.bytes,'SDK file size');}
 return createRequire(import.meta.url)(path.join(s.directory,'kaspa_rpc.js'));
}
async function send(value){if(!process.stdout.write(encode(value)+'\n'))await once(process.stdout,'drain');}
export async function main(argv){
 need(argv.length===2&&argv[0]==='--url','closed worker arguments');const url=loopback(argv[1]);
 // Route SDK diagnostic calls away from the typed IPC and never log their args.
 for(const key of ['log','info','warn','error','debug'])console[key]=()=>process.stderr.write('readonly-borsh: SDK diagnostic\n');
 const k=selectedSdk();let rpc,lastId=0;const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
 try{
  rpc=new k.RpcClient({url,networkId:'testnet-10'});const resolver=rpc.resolver;
  if(resolver!==undefined&&resolver!==null){resolver.free?.();throw new Error('resolver disabled');}
  if(rpc.url!==undefined)need(new URL(rpc.url).href===url,'selected loopback URL');
  await rpc.connect({blockAsyncConnect:true,timeoutDuration:300000,strategy:'fallback'});need(new URL(rpc.url).href===url,'loopback URL changed');
  const dag=await rpc.getBlockDagInfo();need(dag.network==='testnet-10','testnet identity');
  await send({ready:true,network_id:'testnet-10',transport:'TOR_SOCKS5H_TLS_BORSH',rpc_deadline_seconds:900});
  // Exactly one awaited public request at a time; no retries or subscriptions.
  for await(const line of lines){const q=requestLine(line,lastId);lastId=q.id;
   try{const result=materialize(q.method,await rpc[q.method](q.params));await send({id:q.id,ok:true,params:result});}
   catch{await send({id:q.id,ok:false,error_class:'ReadOnlyRpcFailure',category:'DATA_UNAVAILABLE'});}
  }
 }finally{lines.close();if(rpc)try{await rpc.disconnect();}catch{}}
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)main(process.argv.slice(2)).catch(()=>{process.stderr.write('readonly-borsh: worker failed\n');process.exitCode=2;});
