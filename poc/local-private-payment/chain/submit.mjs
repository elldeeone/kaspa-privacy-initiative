import {connectTor} from './rpc.mjs';
import {guardedRead} from './public.mjs';
// Fixed native preflight -> fresh exact input query -> durable intent -> ONE RPC.
// An unknown result permits read-only reconciliation, never automatic rebroadcast.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {GENESIS,loadSdk,canonicalTransaction,integer,pointKey,sha,stringify,need} from './wire.mjs';
import {checkedPath,canonical,strictJson,readPublic} from './selection.mjs';
import {identity,entry} from './acquire.mjs';
import {DEFAULT_RPCS} from './fetch.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const PRIVATE='/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01';
const CLEAN={PATH:'/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC'};

const REQUIRED=['mode','stage','trial-id','selection','selection-sha256','case','case-sha256','output','journal'];
const OPTIONAL=['assets','assets-sha256','codec-sha256','parameters','parameters-sha256','sessions','sessions-sha256','source-pins','source-pins-sha256',
 'descriptor','descriptor-sha256','fetch','fetch-sha256','bundle-directory','codec','rpc',
 'crypto','node','native-validator','sdk-directory'];

export function options(argv){
 const result={'exclude-old-trial':[],'exclude-private-directory':[]};
 for(let i=0;i<argv.length;i++){
  const raw=argv[i];
  if(raw==='--execute'){need(!result.execute,'ARGUMENT','duplicate execute');result.execute=true;continue;}
  const name=raw.slice(2);need(raw.startsWith('--')&&[...REQUIRED,...OPTIONAL,'exclude-old-trial',
   'exclude-private-directory'].includes(name)&&argv[i+1],'ARGUMENT','closed complete argument required');
  if(Array.isArray(result[name]))result[name].push(argv[++i]);
  else{need(result[name]===undefined,'ARGUMENT','duplicate argument');result[name]=argv[++i];}
 }
 need(REQUIRED.every(name=>result[name])&&['consolidate','genesis','lifecycle'].includes(result.mode)
  ,
  'ARGUMENT','complete selected scope and exclusions required');
 need(/^[a-z][a-z0-9-]{0,63}$/.test(result.stage),'ARGUMENT','canonical stage label required');
 need(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(result['trial-id']),
  'ARGUMENT','canonical trial UUID required');
 return result;
}

export function makeTransaction(k,body,contexts){
 const tx=new k.Transaction({...body,inputs:body.inputs.map((input,index)=>({...input,
  sequence:BigInt(input.sequence),sigOpCount:0,utxo:{outpoint:input.previousOutpoint,
   amount:BigInt(contexts[index].amount_sompi),scriptPublicKey:contexts[index].script_public_key,
   blockDaaScore:BigInt(contexts[index].block_daa_score),isCoinbase:contexts[index].is_coinbase}})),
  outputs:body.outputs.map(output=>({value:BigInt(output.value),scriptPublicKey:output.scriptPublicKey})),
  lockTime:BigInt(body.lockTime),gas:BigInt(body.gas),storageMass:BigInt(body.storageMass)});
 try{tx.finalize();assert.deepEqual(canonicalTransaction(tx),body);return tx;}
 catch(error){tx.free();throw error;}
}

export async function queryInputs(k,rpc,body,contexts){
 const source=await identity(rpc),current=integer(source.dag.virtualDaaScore);
 need(body.inputs.length===contexts.length,'INPUT','complete native populated contexts required');
 const scripts=[...new Set(contexts.map(row=>row.script_public_key))];
 const addresses=scripts.map(script=>{const address=k.addressFromScriptPublicKey(script,'testnet-10');
  need(address,'INPUT','input script has no exact query address');
  try{return address.toString();}finally{address.free();}});
 const answer=await rpc.getUtxosByAddresses({addresses});
 need(Array.isArray(answer.entries),'INPUT','complete live UTXO response required');
 const found=new Map();
 for(const value of answer.entries){const row=entry(value),key=pointKey(row.outpoint);
  need(!found.has(key),'INPUT','duplicate current input UTXO');found.set(key,row);}
 for(let index=0;index<body.inputs.length;index++){
  const expected={outpoint:body.inputs[index].previousOutpoint,...contexts[index]};
  const actual=found.get(pointKey(body.inputs[index].previousOutpoint));
  need(canonical(actual)===canonical(expected),'INPUT','selected source changed or disappeared');
  need(expected.covenant_id===null&&typeof expected.is_coinbase==='boolean','INPUT','ordinary source flags');
  if(expected.is_coinbase)need(current>=integer(expected.block_daa_score)+1000n,
   'MATURITY','exact mined input must be mature before submission');
 }
 return current.toString();
}

export function reserveIntent(root,stage,record){
 root=checkedPath(root);
 need(root.startsWith(PRIVATE+'/')&&root.split(path.sep).includes('controller'),
  'INTENT','declared private submit-controller directory required');
 need(/^[a-z][a-z0-9-]{0,63}$/.test(stage),'INTENT','canonical stage label');
 need(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.trial_id)
  &&/^[0-9a-f]{64}$/.test(record.transaction_id),'INTENT','exact public trial/transaction identity');
 const registry=checkedPath(path.join(PRIVATE,'submission-intents',record.trial_id));
 const transactions=checkedPath(path.join(PRIVATE,'submission-transactions'));
 for(const directory of [path.dirname(registry),registry,transactions]){
  try{fs.mkdirSync(directory,{mode:0o700,recursive:false});}
  catch(error){if(error.code!=='EEXIST'||!fs.lstatSync(directory).isDirectory())throw error;}
  const parent=fs.openSync(path.dirname(directory),fs.constants.O_RDONLY);
  try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
 }
 const targets=[path.join(registry,'stage-'+stage+'.intent.json'),
  path.join(transactions,'tx-'+record.transaction_id+'.intent.json')];
 for(const target of targets){
  const fd=fs.openSync(target,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
  try{fs.writeFileSync(fd,stringify({...record,status:'RESERVED_NEVER_RESUBMIT'})+'\n');fs.fsyncSync(fd);}
  finally{fs.closeSync(fd);}
  const directory=fs.openSync(path.dirname(target),fs.constants.O_RDONLY);
  try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
 }
 // Both immutable reservations precede any network write. An interruption
 // between them only consumes the stage; no partial reservation can submit.
 return targets;
}

export async function transmitOnce(rpc,transaction,expectedId){
 try{const reply=await rpc.submitTransaction({transaction,allowOrphan:false});
  return reply.transactionId?.toString()===expectedId;}
 catch{return false;}
}

function preflightArgs(a,output){
 const names=['mode','stage','trial-id','selection','selection-sha256','case','case-sha256',
  ...OPTIONAL.filter(name=>name!=='rpc'&&a[name]!==undefined)];
 const args=names.flatMap(name=>['--'+name,a[name]]);
 for(const name of ['exclude-old-trial','exclude-private-directory'])
  for(const value of a[name])args.push('--'+name,value);
 return [...args,'--output',output];
}

export async function execute(a){
 const output=checkedPath(a.output);need(!fs.existsSync(output),'OUTPUT','fresh submission result directory');
 need(!output.startsWith(PRIVATE+'/'),'OUTPUT','public result must be outside private controller');
 fs.mkdirSync(output,{recursive:true,mode:0o700});
 const preflight=path.join(output,'preflight');
 const preflightProcess=spawnSync('/usr/bin/python3',['-B',path.join(HERE,'preflight.py'),...preflightArgs(a,preflight)],
  {env:CLEAN,input:undefined,encoding:'utf8',maxBuffer:16*1024*1024,stdio:['ignore','pipe','pipe']});
 need(!preflightProcess.error&&preflightProcess.status===0&&!preflightProcess.stderr,'PREFLIGHT','fixed native/accepted-history preflight incomplete');
 const summary=strictJson(Buffer.from(preflightProcess.stdout));
 const candidateRaw=readPublic(path.join(preflight,'SDK-CANDIDATE.json'),summary.candidate_sha256);
 need(sha(candidateRaw)===summary.candidate_sha256,'PREFLIGHT','fixed preflight candidate changed');
 const c=strictJson(candidateRaw);
 need(c.schema==='kpxa-public-submit-candidate/v1'&&c.network_id==='testnet-10'&&c.genesis_hash_hex===GENESIS
  &&c.trial_id===a['trial-id']&&c.stage===a.stage&&c.mode===a.mode
  &&c.case_sha256===a['case-sha256']&&c.selection_file_sha256===a['selection-sha256']
  &&c.broadcast_performed===false&&c.actual_native_Full_passed===true,
  'PREFLIGHT','exact fixed native candidate scope differs');
 const k=loadSdk(a['sdk-directory']),tx=makeTransaction(k,c.transaction,c.contexts);
 if(!a.execute){tx.free();return{status:'PREFLIGHT_ONLY_NO_SUBMISSION',candidate_sha256:summary.candidate_sha256};}
 need(sha(guardedRead(processExecPath(),c.node_pin))===c.node_pin,'NODE','selected Node binary required for live submission');
 const endpoint=new URL(a.rpc??DEFAULT_RPCS[0]);
 need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,
  'ENDPOINT','credential-free testnet TLS RPC required');
 const connection=await connectTor(k,endpoint.href),rpc=connection.rpc;
 let intended=false,attempted=false,acknowledged=false;
 try{
  
  const daa=await queryInputs(k,rpc,c.transaction,c.contexts);
  reserveIntent(a.journal,a.stage,{schema:'kpxa-once-only-native-intent/v1',trial_id:a['trial-id'],
   stage:a.stage,mode:a.mode,financial_profile_sha256:c.financial_profile_sha256,case_sha256:a['case-sha256'],
   candidate_sha256:summary.candidate_sha256,transaction_id:c.transaction.id,last_checked_virtual_daa:daa});
  intended=true;
  // One further query after durable bookkeeping; no proving or signing here.
  await queryInputs(k,rpc,c.transaction,c.contexts);
  attempted=true;acknowledged=await transmitOnce(rpc,tx,c.transaction.id);
  const result={schema:'kpxa-single-native-submission/v1',trial_id:a['trial-id'],stage:a.stage,
   transaction_id:c.transaction.id,case_sha256:a['case-sha256'],candidate_sha256:summary.candidate_sha256,
   status:acknowledged?'SUBMITTED_ACKNOWLEDGED_QUERY_ONLY':'RPC_UNKNOWN_QUERY_ONLY',
   durable_intent_reserved:true,submission_attempted:true,automatic_resubmission_permitted:false,
   confirmation_claimed:false,private_seed_key_or_proving_witness_read:false};
  fs.writeFileSync(path.join(output,'RESULTS.json'),stringify(result)+'\n',{flag:'wx',mode:0o400});return result;
 }catch(error){
  const result={schema:'kpxa-single-native-submission/v1',trial_id:a['trial-id'],stage:a.stage,
   transaction_id:c.transaction.id,status:'INCOMPLETE_QUERY_ONLY',durable_intent_reserved:intended,
   submission_attempted:attempted,automatic_resubmission_permitted:false,confirmation_claimed:false,
   stage_already_used:error.code==='EEXIST',
   category:error.code==='EEXIST'?'USED_STAGE_NEVER_RESUBMIT':error.category??'PUBLIC_RPC_OR_INTENT_UNAVAILABLE'};
  fs.writeFileSync(path.join(output,'INCOMPLETE.json'),stringify(result)+'\n',{flag:'wx',mode:0o400});return result;
 }finally{tx.free();await connection.close();}
}
function processExecPath(){return globalThis.process.execPath;}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const result=await execute(options(process.argv.slice(2)));process.stdout.write(stringify(result)+'\n');
  if(['RPC_UNKNOWN_QUERY_ONLY','INCOMPLETE_QUERY_ONLY'].includes(result.status))process.exitCode=2;}
 catch(error){process.stderr.write('native submission incomplete; reconcile read-only before any further action\n');process.exitCode=2;}
}
