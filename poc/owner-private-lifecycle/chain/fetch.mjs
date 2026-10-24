#!/usr/bin/env node
// Public GN3/W acquisition only. A successful fetch still requires semantic replay.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS, SDK_PINS, loadSdk, need, script, sha, stringify} from './wire.mjs';
import {checkedPath, readPublic, profile, descriptor, canonical} from './selection.mjs';
import {frontier, scan, discover, currentView, postQuery, save} from './acquire.mjs';

export const DEFAULT_RPCS = [
  'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
];

export async function fetchOne(k, rpc, selected, profileSha, d, descriptorSha, root) {
  const boundary = await frontier(k, rpc);
  const scanned = await scan(k, rpc, d, boundary, root);
  const found = discover(k, d, scanned, root, boundary);
  const initial = k.payToScriptHashScript(Buffer.from(d.initial_redeem_hex, 'hex'));
  try {
    need(script(initial) === found.rows[0].transaction.outputs[0].scriptPublicKey,
      'GN3', 'accepted funding output differs from selected initial W');
  } finally { initial.free(); }
  const view = await currentView(k, rpc, found);
  view.post_query_delta = await postQuery(k, rpc, d, boundary, found, root, view);
  // A newly accepted spend can still be inside the confirmation window and
  // absent from the confirmed delta. Requery the exact same points after it.
  const rechecked = await currentView(k,rpc,found);
  need(canonical(view.queries)===canonical(rechecked.queries),'STALE_CURRENT_VIEW',
    'an exact W/change/payout query changed during acquisition');
  view.final_requery=rechecked;
  return {schema:'kpx8-gn3-network-fetch/v1', status:'FETCHED_PENDING_REPLAY',
    network_id:'testnet-10', genesis_hash_hex:GENESIS,
    financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha, descriptor:d, descriptor_file_sha256:descriptorSha,
    descriptor_canonical_sha256:sha(canonical(d)),
    trust:'REMOTE_VALIDATING_NODE_AND_RETAINED_CHAIN_DATA', rpc_views_are_atomic:false,
    sdk_pins:SDK_PINS, transactions:found.rows, current_view:view,
    coverage:{start_hash:d.birth_start_hash, anchor_header:scanned.anchor,
      frontier:boundary.header, initial_sink:boundary.sink, end_cursor:scanned.cursor,
      complete:true, frontier_seen:true, removed_chain_block_hashes:[], missing:[], pruned:false,
      min_confirmation_count:boundary.min_confirmation_count,
      accepted_transaction_rows_scanned:scanned.accepted_transactions_scanned,
      scope:'FINITE_CONFIRMED_PREFIX_PENDING_GN3_W_SEMANTIC_REPLAY'},
    pages:scanned.pages, terminal_candidate_not_yet_replay_verified:found.terminal_candidate,
    public_parameter_blob_read:false, owner_backup_or_signing_key_read:false,
    accepted_backing_currentness_or_spend_authorized:false,
    observed_at:new Date().toISOString()};
}

export async function execute(profilePath, profileSha, descriptorPath, descriptorSha,
  output, urls=DEFAULT_RPCS, k=loadSdk()) {
  const selected=profile(readPublic(profilePath,profileSha),profileSha);
  const d=descriptor(readPublic(descriptorPath,descriptorSha),descriptorSha,selected,profileSha);
  output=checkedPath(output);
  need(!fs.existsSync(output),'OUTPUT_EXISTS','fresh public acquisition output required');
  fs.mkdirSync(output,{recursive:true,mode:0o700});
  const attempts=[];
  for(let index=0;index<urls.length;index++) {
    const endpoint=new URL(urls[index]);
    need((endpoint.protocol==='wss:' || endpoint.protocol==='ws:'
      && ['localhost','127.0.0.1','[::1]'].includes(endpoint.hostname))
      && !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash,
      'ENDPOINT','public TLS or loopback RPC without credentials required');
    const root=path.join(output,`attempt-${String(index+1).padStart(3,'0')}`);
    fs.mkdirSync(root,{mode:0o700});
    const rpc=new k.RpcClient({url:endpoint.href,networkId:'testnet-10'});
    try {
      await rpc.connect({blockAsyncConnect:true,timeoutDuration:60000,strategy:'fallback'});
      const fetched=await fetchOne(k,rpc,selected,profileSha,d,descriptorSha,root);
      fetched.source={rpc_url:endpoint.href,attempt:index+1,
        assertion_scope:'Distinct endpoint names do not establish independent administration or consensus'};
      fetched.attempts=attempts;
      fetched.pages.forEach(row=>{row.path=path.posix.join(path.basename(root),row.path);});
      fetched.current_view.post_query_delta.pages.forEach(row=>{
        row.path=path.posix.join(path.basename(root),row.path);
      });
      save(path.join(output,'fetch.json'),fetched);
      return fetched;
    } catch(error) {
      const failed={rpc_url:endpoint.href,status:'INCOMPLETE',category:error.category??'DATA_UNAVAILABLE',
        error:String(error.message??error),recorded_at:new Date().toISOString()};
      save(path.join(root,'INCOMPLETE.json'),failed);attempts.push(failed);
    } finally {await rpc.disconnect();}
  }
  const result={schema:'kpx8-gn3-network-fetch/v1',status:'INCOMPLETE',
    financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,descriptor_file_sha256:descriptorSha,
    attempts,balance_known:false,no_empty_balance_inference:true};
  save(path.join(output,'INCOMPLETE.json'),result);
  return result;
}

if(process.argv[1]===fileURLToPath(import.meta.url)) {
  try {
    const [profilePath,profileSha,descriptorPath,descriptorSha,output,...rest]=process.argv.slice(2);
    need(profilePath&&profileSha&&descriptorPath&&descriptorSha&&output,'ARGUMENT',
      'fetch.mjs PROFILE PROFILE_SHA DESCRIPTOR DESCRIPTOR_SHA FRESH_OUTPUT [--rpc URL ...] [--sdk-dir DIR]');
    const urls=[];let sdk;
    for(let i=0;i<rest.length;i+=2) {
      need(rest[i+1]&&['--rpc','--sdk-dir'].includes(rest[i]),'ARGUMENT','unknown option');
      if(rest[i]==='--rpc')urls.push(rest[i+1]);else {need(!sdk,'ARGUMENT','duplicate SDK directory');sdk=checkedPath(rest[i+1]);}
    }
    const result=await execute(profilePath,profileSha,descriptorPath,descriptorSha,output,
      urls.length?urls:DEFAULT_RPCS,loadSdk(sdk));
    process.stdout.write(stringify({status:result.status,output,
      transactions:result.transactions?.length,balance_known:false})+'\n');
    if(result.status==='INCOMPLETE')process.exitCode=2;
  } catch(error) {
    process.stderr.write(`GN3/W acquisition incomplete: ${error.category??'ERROR'}: ${error.message}\n`);
    process.exitCode=2;
  }
}
