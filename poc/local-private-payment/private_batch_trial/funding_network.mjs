// New-profile public Tor/RPC operations. No seed, signer, wallet or PK API.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {connectTor} from './funding_network_rpc.mjs';
import {identity as nodeIdentity, frontier, scan, entry} from '../chain/acquire.mjs';
import {validateHeader} from '../chain/wire.mjs';
import {IDS,RPCS,NODE_PIN,need,sha,stringify,canonical,strictJson,checkedPath,readPinned,
  loadSdk,identityDocument,checkAddresses,matureObservation,makeTransaction,durable,
  reservePhase,integer,point,pointKey,canonicalTransaction,script} from './funding_network_common.mjs';

const CLOSED = ['anchor','collect','submit-consolidation','reconcile-ordinary','submit-genesis','confirm'];

export function nativeGate(job, invoke=spawnSync) {
  const result=invoke('/usr/bin/python3',['-B','-S',fileURLToPath(new URL('./funding_network_gate.py',import.meta.url))],
    {env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC'},encoding:'utf8',maxBuffer:32*1024*1024,
      stdio:['ignore','pipe','pipe']});
  need(!result.error && result.status===0,'ACTUAL_NATIVE_GATE_REFUSED');
  const candidate=strictJson(Buffer.from(result.stdout));
  need(candidate.schema==='kpb-network-native-candidate/v1' && candidate.identity_sha256===job.identity_sha256
    && candidate.case_sha256===job.case_sha256 && candidate.case_mode===job.case_mode
    && candidate.owner_component===job.owner_component && candidate.network_or_broadcast===false,
    'FRESH_EXACT_NATIVE_GATE_OUTPUT');
  return candidate;
}

export async function queryInputs(k,rpc,candidate) {
  const observed=await nodeIdentity(rpc), current=integer(observed.dag.virtualDaaScore);
  const scripts=[...new Set(candidate.contexts.map(row=>row.script_public_key))];
  const addresses=scripts.map(spk=>{const address=k.addressFromScriptPublicKey(spk,'testnet-10');
    need(address,'CURRENT_INPUT_QUERY_ADDRESS'); try{return address.toString();}finally{address.free();}});
  const response=await rpc.getUtxosByAddresses({addresses});
  need(Array.isArray(response.entries),'CURRENT_INPUT_RESPONSE');
  const found=new Map();
  for (const raw of response.entries) {const row=entry(raw),key=pointKey(row.outpoint);
    need(!found.has(key),'DUPLICATE_CURRENT_INPUT');found.set(key,row);}
  candidate.transaction.inputs.forEach((input,index)=>{
    const expected={outpoint:input.previousOutpoint,...candidate.contexts[index]};
    need(canonical(found.get(pointKey(input.previousOutpoint)))===canonical(expected),'EXACT_CURRENT_SOURCE_CHANGED');
    need(expected.covenant_id===null && typeof expected.is_coinbase==='boolean','ORDINARY_CURRENT_SOURCE_FLAGS');
    if (expected.is_coinbase) need(current>=integer(expected.block_daa_score)+1000n,'COINBASE_NOT_MATURE');
  });
  return current;
}

export async function currentOutputs(k,rpc,candidate) {
  const observed=await nodeIdentity(rpc),current=integer(observed.dag.virtualDaaScore);
  const scripts=[...new Set([...candidate.contexts.map(row=>row.script_public_key),
    ...candidate.transaction.outputs.map(row=>row.scriptPublicKey)])];
  const addresses=scripts.map(spk=>{const address=k.addressFromScriptPublicKey(spk,'testnet-10');
    need(address,'OUTPUT_QUERY_ADDRESS');try{return address.toString();}finally{address.free();}});
  const response=await rpc.getUtxosByAddresses({addresses});need(Array.isArray(response.entries),'OUTPUT_QUERY_RESPONSE');
  const found=new Map();
  for (const raw of response.entries) {const row=entry(raw),key=pointKey(row.outpoint);
    need(!found.has(key),'DUPLICATE_OUTPUT_QUERY');found.set(key,row);}
  const outputs=candidate.transaction.outputs.map((output,index)=>{
    const at={transactionId:candidate.transaction.id,index},actual=found.get(pointKey(at))??null;
    if(actual) need(actual.amount_sompi===output.value && actual.script_public_key===output.scriptPublicKey
      && actual.is_coinbase===false && actual.covenant_id===null,'EXACT_OUTPUT_QUERY_SUBSTITUTION');
    return {outpoint:at,entry:actual,daa_depth:actual?(current-integer(actual.block_daa_score)).toString():null};
  });
  return {virtual_daa_score:current.toString(),outputs,all_inputs_absent:candidate.transaction.inputs.every(input=>!found.has(pointKey(input.previousOutpoint))),
    observed_at:new Date().toISOString(),independent_consensus_proved:false};
}

export async function submitOnce({k,rpc,identity,job,candidate,transaction,onSubmit=()=>{}}) {
  const stage=job.operation==='submit-genesis'?'genesis':'consolidate-'+job.owner_component;
  // Registry consumption precedes the first RPC, including read-only checks.
  // The caller invokes this before connecting; see execute() for that ordering.
  await queryInputs(k,rpc,candidate);
  let acknowledged=false;
  try {onSubmit();const reply=await rpc.submitTransaction({transaction,allowOrphan:false});
    acknowledged=reply.transactionId?.toString()===candidate.transaction.id;} catch { /* Query only, never resend. */ }
  let post=null;
  try {post=await currentOutputs(k,rpc,candidate);} catch { /* Retain unknown write outcome. */ }
  return {schema:'kpb-single-native-network-submission/v1',...IDS,trial_id:identity.trial_id,stage,
    transaction_id:candidate.transaction.id,case_sha256:job.case_sha256,identity_sha256:job.identity_sha256,
    status:acknowledged?'RPC_ACKNOWLEDGED_QUERY_ONLY':'RPC_UNKNOWN_QUERY_ONLY',submission_attempted:true,
    durable_phase_and_tx_reserved:true,automatic_resubmission_permitted:false,
    confirmation_claimed:false,post_query:post};
}

export async function collect(k,rpc,identity,output) {
  const observed=await nodeIdentity(rpc),current=integer(observed.dag.virtualDaaScore),owners=[];
  for (const owner of identity.owners) {
    const reply=await rpc.getUtxosByAddresses({addresses:[owner.address]});
    const value=matureObservation(identity,owner.owner_component,reply.entries,current);
    const file=path.join(output,'OWNER-'+owner.owner_component+'.json');durable(file,value.observation);
    owners.push({owner_component:owner.owner_component,mature_coinbase_sompi:value.total.toString(),
      immature_coinbase_sompi:value.immature.toString(),source_count:value.observation.sources.length,
      observation_file:file,observation_sha256:sha(readPinned(file)),
      sufficient_for_20_KAS_plus_1_KAS_headroom:value.total>=2100000000n});
  }
  return {schema:'kpb-three-owner-funding-observation/v1',...IDS,trial_id:identity.trial_id,
    virtual_daa_score:current.toString(),coinbase_maturity_daa_delta:1000,owners,
    status:owners.every(row=>row.sufficient_for_20_KAS_plus_1_KAS_headroom)?'MATURE_SOURCES_OBSERVED_PENDING_CONSOLIDATION':'INCOMPLETE_WAIT_FOR_REWARDS_OR_MATURITY',
    mining_signing_or_broadcast_performed:false,independent_consensus_proved:false};
}

export async function captureAnchor(k,rpc,identity) {
  const found=await frontier(k,rpc);
  return {schema:'kpb-GEN3-birth-anchor/v1',...IDS,trial_id:identity.trial_id,
    component_profile_sha256:identity.component_profile_sha256,native_tail_sha256:identity.native_tail_sha256,
    birth_start_hash:found.header.hash,birth_header:found.header,observed_sink:found.sink,
    min_confirmation_count:found.min_confirmation_count,server:found.source.server,
    observed_at:new Date().toISOString(),funding_or_currentness_or_readiness_claimed:false};
}

function acceptedContexts(raw,body) {
  need(Array.isArray(raw.inputs) && raw.inputs.length===body.inputs.length,'FULL_ACCEPTED_CONTEXT_COUNT');
  return raw.inputs.map((input,index)=>{const e=input.verboseData?.utxoEntry;
    need(e && typeof e.isCoinbase==='boolean' && (e.covenantId??null)===null,'FULL_ORDINARY_ACCEPTED_CONTEXT');
    return {outpoint:body.inputs[index].previousOutpoint,amount_sompi:integer(e.amount).toString(),
      script_public_key:script(e.scriptPublicKey),block_daa_score:integer(e.blockDaaScore).toString(),is_coinbase:e.isCoinbase,covenant_id:null};});
}
function decodedPage(output,record) {
  const file=checkedPath(path.join(output,record.path));
  need(file.startsWith(checkedPath(output)+path.sep),'FULL_PAGE_CANONICAL_PATH');
  const compressed=readPinned(file,record.gzip_sha256),raw=zlib.gunzipSync(compressed);
  need(sha(raw)===record.decoded_sha256 && raw.length===record.decoded_bytes,'FULL_PAGE_EXACT_DECODED_BYTES');
  return strictJson(raw);
}

export async function confirm(k,rpc,identity,job,candidate,output) {
  const anchor=strictJson(readPinned('/inputs/ANCHOR.json',job.anchor_sha256));
  need(anchor.schema==='kpb-GEN3-birth-anchor/v1' && Object.entries(IDS).every(([key,value])=>anchor[key]===value)
    && anchor.trial_id===identity.trial_id && anchor.component_profile_sha256===identity.component_profile_sha256
    && anchor.native_tail_sha256===identity.native_tail_sha256,'EXACT_NEW_BIRTH_ANCHOR');
  const boundary=await frontier(k,rpc);
  const descriptor={birth_start_hash:anchor.birth_start_hash,
    founding_outpoint:{transactionId:candidate.transaction.id,index:0}};
  // Generic scan/frontier helpers do not invoke the old profile/codec parser.
  const scanned=await scan(k,rpc,descriptor,boundary,output,true);
  const at=scanned.founding, page=decodedPage(output,scanned.pages[at.page]);
  const group=page.chainBlockAcceptedTransactions[at.group],raw=group.acceptedTransactions[at.transaction];
  const body=canonicalTransaction(raw),contexts=acceptedContexts(raw,body);
  const expected=candidate.contexts.map((row,index)=>({outpoint:candidate.transaction.inputs[index].previousOutpoint,...row}));
  need(canonical(body)===canonical(candidate.transaction) && canonical(contexts)===canonical(expected),
    'EXACT_ACCEPTED_WHOLE_CASE_WITNESS_BUDGET_CONTEXT');
  const tx=makeTransaction(k,body,contexts);tx.free();
  const current=await currentOutputs(k,rpc,candidate);
  const delta=await rpc.getVirtualChainFromBlockV2({startHash:boundary.header.hash,dataVerbosityLevel:'None',minConfirmationCount:boundary.min_confirmation_count});
  need(Array.isArray(delta.removedChainBlockHashes) && delta.removedChainBlockHashes.length===0,'POST_QUERY_REORG');
  const fixed=await rpc.getBlock({hash:boundary.header.hash,includeTransactions:false});
  validateHeader(k,fixed.block.header,boundary.header.hash);
  need(fixed.block.verboseData.isChainBlock===true,'POST_QUERY_FIXED_CHECKPOINT_NOT_CHAIN');
  const complete=!!current.outputs[0].entry && current.all_inputs_absent;
  const record={schema:'kpb-fresh-accepted-whole-CASE/v1',...IDS,trial_id:identity.trial_id,
    case_sha256:job.case_sha256,identity_sha256:job.identity_sha256,case_mode:job.case_mode,
    transaction_id:body.id,accepted_transaction:body,accepted_input_contexts:contexts,
    native_report_sha256:candidate.native_report_sha256,native_metrics_sha256:candidate.native_metrics_sha256,
    accepting_block_header:group.chainBlockHeader,frontier:boundary.header,sink:boundary.sink,
    min_confirmation_count:boundary.min_confirmation_count,source_pages:scanned.pages,
    post_query_delta:delta,requeried_checkpoint_header:fixed.block.header,
    current_view:current,status:complete?'EXACT_CASE_IN_FRESH_PREFIX_AND_CURRENT_OUTPUT':'ACCEPTED_CASE_CURRENTNESS_INCOMPLETE',
    confirmation_scope:'SELECTED_VALIDATING_NODE_FULL_PAGES_SDK_WHOLE_CASE_NATIVEFULL',
    independent_consensus_proved:false,signing_or_broadcast_performed:false,automatic_resubmission_permitted:false};
  if(job.case_mode==='genesis') need(complete && current.outputs[0].entry.amount_sompi==='6000000000','LIVE_EXACT60KAS_GEN3_HEAD_REQUIRED');
  return record;
}

export async function execute(operation) {
  need(CLOSED.includes(operation),'CLOSED_NEW_PUBLIC_NETWORK_OPERATION');
  need(!fs.existsSync('/etc/ssl/private') && !fs.existsSync('/original') && !fs.existsSync('/home/luke/.codex'), 'PUBLIC_NETWORK_NO_HOST_PRIVATE_MOUNTS');
  need(sha(readPinned(process.execPath))===NODE_PIN,'SELECTED_PUBLIC_NODE');
  const job=strictJson(readPinned('/NETWORK-JOB.json'));
  need(job.schema==='kpb-public-network-job/v1' && job.operation===operation,'EXACT_PUBLIC_NETWORK_JOB');
  if(operation==='submit-genesis') need(job.case_mode==='genesis' && job.owner_component===null,'EXACT_NEW_GEN3_OPERATION');
  if(['submit-consolidation','reconcile-ordinary'].includes(operation))
    need(job.case_mode==='consolidation' && Number.isSafeInteger(job.owner_component)
      && job.owner_component>=0 && job.owner_component<3,'EXACT_NEW_CONSOLIDATION_OPERATION');
  const identity=identityDocument(readPinned('/IDENTITY.json',job.identity_sha256));
  const marker=strictJson(readPinned('/NAMESPACE.json'));
  need(marker.schema==='kpb-public-network-namespace/v1' && marker.operation===operation
    && marker.network_id==='testnet-10' && marker.trial_id===identity.trial_id,'EXACT_NEW_NETWORK_NAMESPACE');
  for(const member of job.source_members) readPinned(member.path,member.sha256);
  need(Number.isSafeInteger(job.rpc_index) && job.rpc_index>=0 && job.rpc_index<RPCS.length,'SELECTED_TN10_RPC');
  const output='/out',k=loadSdk();checkAddresses(k,identity);
  let candidate=null,transaction=null;
  if(!['anchor','collect'].includes(operation)) {
    candidate=nativeGate(job);need(candidate.trial_id===identity.trial_id,'NATIVE_GATE_TRIAL');
    transaction=makeTransaction(k,candidate.transaction,candidate.contexts);
  }
  const submitting=operation.startsWith('submit-');
  if(submitting) reservePhase('/registry',identity,operation==='submit-genesis'?'genesis':'consolidate-'+job.owner_component,
    {identity_sha256:job.identity_sha256,case_sha256:job.case_sha256,transaction_id:candidate.transaction.id});
  let connection,submissionAttempted=false;
  try {
    connection=await connectTor(k,RPCS[job.rpc_index]);const rpc=connection.rpc;
    let result;
    if(operation==='anchor') result=await captureAnchor(k,rpc,identity);
    else if(operation==='collect') result=await collect(k,rpc,identity,output);
    else if(submitting) result=await submitOnce({k,rpc,identity,job,candidate,transaction,onSubmit:()=>{submissionAttempted=true;}});
    else if(operation==='confirm') result=await confirm(k,rpc,identity,job,candidate,output);
    else {const observed=await currentOutputs(k,rpc,candidate),first=observed.outputs[0];
      result={schema:'kpb-ordinary-output-readback/v1',...IDS,trial_id:identity.trial_id,case_sha256:job.case_sha256,
        transaction_id:candidate.transaction.id,current_view:observed,output:first.entry,
        status:first.entry && BigInt(first.daa_depth)>=20n && observed.all_inputs_absent?'EXACT_ORDINARY_OUTPUT_OBSERVED_DAA_DEPTH20':'INCOMPLETE_QUERY_ONLY',
        full_accepted_prefix_proved:false,automatic_resubmission_permitted:false};}
    durable(path.join(output,'RESULTS.json'),result);return result;
  } catch(error) {
    const result={schema:'kpb-public-network-incomplete/v1',...IDS,trial_id:identity.trial_id,operation,
      status:'INCOMPLETE_QUERY_ONLY',durable_phase_reserved:submitting,automatic_resubmission_permitted:false,
      submission_attempted:submissionAttempted,
      category:'PUBLIC_NETWORK_OR_ACCEPTED_CASE_INCOMPLETE'};
    if(!fs.existsSync(path.join(output,'INCOMPLETE.json'))) durable(path.join(output,'INCOMPLETE.json'),result);
    throw error;
  } finally {transaction?.free();if(connection)await connection.close();}
}

if(process.argv[1]===fileURLToPath(import.meta.url)) {
  try {const result=await execute(process.argv[2]);process.stdout.write(stringify({status:result.status??'PUBLIC_OBSERVATION_COMPLETE'})+'\n');
    if(['RPC_UNKNOWN_QUERY_ONLY','INCOMPLETE_QUERY_ONLY','INCOMPLETE_WAIT_FOR_REWARDS_OR_MATURITY','ACCEPTED_CASE_CURRENTNESS_INCOMPLETE'].includes(result.status))process.exitCode=2;}
  catch {process.stderr.write('new public network operation incomplete; reconcile read-only, never resend\n');process.exitCode=2;}
}
