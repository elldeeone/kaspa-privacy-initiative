import {connectTor} from '../chain/rpc.mjs';
// Read-only exact ordinary self-output observation. Never submits a transaction.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS,integer,loadSdk,need,pointKey,stringify} from '../chain/wire.mjs';
import {readPublic,checkedPath} from '../chain/selection.mjs';
import {identity,entry,save} from '../chain/acquire.mjs';
import {DEFAULT_RPCS} from '../chain/fetch.mjs';
import {makeTransaction} from '../chain/submit.mjs';

export async function reconcile(candidate,output,url=DEFAULT_RPCS[0],k=loadSdk()){
 need(candidate.schema==='kpxa-public-submit-candidate/v1'&&candidate.mode==='consolidate'
  &&candidate.network_id==='testnet-10'&&candidate.genesis_hash_hex===GENESIS,
  'CANDIDATE','exact selected ordinary consolidation candidate required');
 const body=candidate.transaction;
 need(body.outputs.length===1&&/^000020[0-9a-f]{64}ac$/.test(body.outputs[0].scriptPublicKey),
  'CANDIDATE','single ordinary self-output required');
 const tx=makeTransaction(k,body,candidate.contexts);tx.free();
 const endpoint=new URL(url);need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password
  &&!endpoint.search&&!endpoint.hash,'ENDPOINT','credential-free testnet RPC required');
 const connection=await connectTor(k,endpoint.href),rpc=connection.rpc;
 try{
  
  const observed=await identity(rpc),current=integer(observed.dag.virtualDaaScore);
  const address=k.addressFromScriptPublicKey(body.outputs[0].scriptPublicKey,'testnet-10');
  let raw;try{raw=await rpc.getUtxosByAddresses({addresses:[address.toString()]});}finally{address.free();}
  need(Array.isArray(raw.entries),'UTXO','complete exact-address UTXO array required');
  const found=new Map();for(const value of raw.entries){const row=entry(value),key=pointKey(row.outpoint);
   need(!found.has(key),'UTXO','duplicate UTXO point');found.set(key,row);}
  const at={transactionId:body.id,index:0},actual=found.get(pointKey(at));
  if(!actual)return {schema:'kpxa-ordinary-output-readback/v1',status:'INCOMPLETE_QUERY_ONLY',
   trial_id:candidate.trial_id,transaction_id:body.id,output_not_yet_observed:true,
   automatic_resubmission_permitted:false};
  need(actual.amount_sompi===body.outputs[0].value
   &&actual.script_public_key===body.outputs[0].scriptPublicKey
   &&actual.is_coinbase===false&&actual.covenant_id===null,'UTXO','exact ordinary output differs');
  for(const input of body.inputs)need(!found.has(pointKey(input.previousOutpoint)),
   'UTXO','selected old coinbase input remains unspent');
  const birth=integer(actual.block_daa_score),depth=current-birth;
  const result={schema:'kpxa-ordinary-output-readback/v1',
   status:depth>=20n?'EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20':'INCOMPLETE_WAIT_FOR_DAA_DEPTH',
   network_id:'testnet-10',genesis_hash_hex:GENESIS,trial_id:candidate.trial_id,
   transaction_id:body.id,case_sha256:candidate.case_sha256,output:actual,
   virtual_daa_score:current.toString(),observed_daa_depth:depth.toString(),required_daa_depth:'20',
   all_selected_coinbase_inputs_absent:true,full_accepted_prefix_or_independent_consensus_proved:false,
   observation_scope:'SELECTED_VALIDATING_NODE_EXACT_UTXO_AND_DAA_DEPTH',
   signing_or_broadcast_performed:false,automatic_resubmission_permitted:false};
  return result;
 }finally{await connection.close();}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const [file,sha,output,url]=process.argv.slice(2);need(file&&sha&&output,'ARGUMENT','CANDIDATE SHA FRESH_OUTPUT [RPC]');
  const directory=checkedPath(output);need(!fs.existsSync(directory),'OUTPUT','fresh read-only result directory');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const result=await reconcile(JSON.parse(readPublic(file,sha)),directory,url??DEFAULT_RPCS[0]);
  save(path.join(directory,'RESULTS.json'),result);process.stdout.write(stringify(result)+'\n');
  if(result.status.startsWith('INCOMPLETE'))process.exitCode=2;
 }catch(error){process.stderr.write('ordinary output reconciliation incomplete; query only\n');process.exitCode=2;}
}
