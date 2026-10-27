// Separate public-only read diagnostic. No intent/sign/prove/submit API is used.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {queryInputs,makeTransaction} from '../chain/submit_pool.mjs';
import {connectTor} from '../chain/rpc.mjs';
import {DEFAULT_RPCS} from '../chain/fetch.mjs';
import {guardedRead} from '../chain/public.mjs';
import {GENESIS,loadSdk,sha,need} from '../chain/wire.mjs';
import {checkedPath,strictJson} from '../chain/selection.mjs';

const ROOT='/var/tmp/kpi-local-private-payment-01/campaign/trial-02';
const CANDIDATE=ROOT+'/run/action-0008/submission/pool-preflight/result/SDK-CANDIDATE.json';
const CANDIDATE_SHA='6b41caa4acec2f5bcc68e439ea9bf4f5be20e13a0a04ddf60bcfedfb758df0a5';
const TXID='35f828828e86fddd6eae3f64681a085b2d12a90bec832af83f1767c26ef00f5c';
const CASE_SHA='f4d2f7d6956668251f04cd04eac8bb97a34a1de9f49a1c8700b904f7364ad79c';
export const ENDPOINT='wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh';

export function readOnlyRpc(rpc){
 const allowed=new Set(['getServerInfo','getBlockDagInfo','getUtxosByAddresses']);
 return new Proxy(rpc,{get(target,name){
  if(!allowed.has(name))throw new Error('NON_READ_RPC_BLOCKED');
  return (...args)=>target[name](...args);
 }});
}

export function publicError(error){
 const text=String(error?.message??error??'');
 let category='UNCLASSIFIED_PUBLIC_QUERY_ERROR';
 if(/WebSocket disconnected/i.test(text))category='WEBSOCKET_DISCONNECTED';
 else if(/timeout|timed out/i.test(text))category='RPC_TIMEOUT';
 else if(error?.category==='INPUT')category='EXACT_INPUT_MISMATCH';
 else if(error?.category==='NODE_IDENTITY')category='NODE_IDENTITY_MISMATCH';
 else if(text==='NON_READ_RPC_BLOCKED')category='NON_READ_RPC_BLOCKED';
 const code=typeof error?.code==='string'&&/^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)?error.code:null;
 return {category,code}; // Never emit raw message, traceback, response or logs.
}

export async function diagnostic(output){
 output=checkedPath(output);
 need(output.startsWith(ROOT+'/control/first-submit8-recovery-01/')&&!fs.existsSync(output),
  'OUTPUT','fresh selected public diagnostic directory required');
 fs.mkdirSync(output,{mode:0o700});
 const result={schema:'kpxa-public-first-submit8-query-diagnostic/v1',selected_rpc:ENDPOINT,
  candidate_sha256:CANDIDATE_SHA,transaction_id:TXID,read_only:true,
  private_STATE_PLAN_Original_or_logs_read:false,intent_sign_prove_or_submit_called:false};
 let phase='PUBLIC_CANDIDATE',connection,tx;
 try{
  const raw=guardedRead(CANDIDATE,CANDIDATE_SHA),c=strictJson(raw);
  need(sha(raw)===CANDIDATE_SHA&&c.transaction.id===TXID&&c.case_sha256===CASE_SHA
   &&c.stage==='action-0008'&&c.network_id==='testnet-10'&&c.genesis_hash_hex===GENESIS
   &&c.actual_native_Full_passed===true&&c.broadcast_performed===false,'SCOPE','exact public candidate required');
  need(sha(guardedRead(process.execPath,c.node_pin))===c.node_pin,'NODE','selected Node binary required');
  need(DEFAULT_RPCS.includes(ENDPOINT),'ENDPOINT','existing explicitly selected endpoint required');
  phase='SDK_ROUNDTRIP';const k=loadSdk();tx=makeTransaction(k,c.transaction,c.contexts);
  phase='TOR_CONNECT';connection=await connectTor(k,ENDPOINT);
  const rpc=readOnlyRpc(connection.rpc);
  phase='PUBLIC_INPUT_QUERY_1';result.first_virtual_daa=await queryInputs(k,rpc,c.transaction,c.contexts);
  phase='PUBLIC_INPUT_QUERY_2';result.second_virtual_daa=await queryInputs(k,rpc,c.transaction,c.contexts);
  result.status='TWO_FRESH_EXACT_PUBLIC_INPUT_QUERIES_PASS';result.phase='COMPLETE';
 }catch(error){
  result.status='PUBLIC_QUERY_INCOMPLETE';result.phase=phase;result.error=publicError(error);
 }finally{
  if(tx)tx.free();
  if(connection){try{await connection.close();}catch(error){result.close_error=publicError(error);}}
 }
 fs.writeFileSync(path.join(output,'RESULT.json'),JSON.stringify(result)+'\n',{flag:'wx',mode:0o400});
 return result;
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  need(process.argv.length===4&&process.argv[2]==='--output','ARGUMENT','only exact public --output supported');
  const result=await diagnostic(process.argv[3]);process.stdout.write(JSON.stringify(result)+'\n');
  if(result.status!=='TWO_FRESH_EXACT_PUBLIC_INPUT_QUERIES_PASS')process.exitCode=2;
 }catch{process.stderr.write('public read-only query diagnostic refused; no submission\n');process.exitCode=2;}
}
