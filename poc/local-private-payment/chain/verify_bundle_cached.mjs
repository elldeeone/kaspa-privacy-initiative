#!/usr/bin/env node
// Fresh offline public SDK/evidence checks. No RPC, owner key, PK or prover.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS, SDK_PINS, canonicalTransaction, contexts, hex, integer, loadSdk,
  need, plainHeader, point, pointKey, sha, stringify, validateHeader} from './wire.mjs';
import {checkedPath, readPublic, profile, descriptor, canonical, strictJson} from './selection.mjs';
import {discover, pageData} from './acquire.mjs';
import {cacheOptions,admitted,prepareBase,verifyCopied,row} from './cache.mjs';
let REUSE=null;

function equal(a,b,code) {need(canonical(a)===canonical(b),code,'public evidence differs');}
function canonicalAmount(value) {
  need(typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value),
    'AMOUNT','canonical decimal sompi string required');
  return integer(value);
}
function queryEntry(raw, expected) {
  equal(point(raw.outpoint),expected.outpoint,'UTXO_SUBSTITUTION');
  need(canonicalAmount(raw.amount_sompi)===canonicalAmount(expected.amount_sompi)
    && raw.script_public_key===expected.script_public_key
    && raw.is_coinbase===false && raw.covenant_id===null,
    'UTXO_SUBSTITUTION','current UTXO differs from exact expected output');
  canonicalAmount(raw.block_daa_score);
}

// Rebuild the selected graph from immutable Full page contents, not locator flags
// or txid alone: v1 txid omits witness and compute budget.
function retainedScan(k,d,boundary,pages,root,requireFounding=true) {
  need(Array.isArray(pages),'COVERAGE','retained Full pages required');
  let cursor=d.birth_start_hash,reached=cursor===boundary.header.hash,founding;
  const seen=new Set([cursor]),paths=new Set(),edges=new Map();let acceptedRows=0;
  let firstPage=0;
  if(requireFounding&&REUSE){
    const b=REUSE.base;firstPage=b.pages.length;
    equal(pages.slice(0,firstPage),REUSE.records,'CACHE_PREFIX');verifyCopied(root,REUSE.records);
    cursor=b.frontier.hash;reached=cursor===boundary.header.hash;seen.add(cursor);founding=b.founding;acceptedRows=b.accepted;
    for(const [key,values] of b.edges)edges.set(key,[...values]);
    REUSE.records.forEach(r=>paths.add(r.path));
  }
  for(let pageIndex=firstPage;pageIndex<pages.length;pageIndex++) {
    need(!reached,'COVERAGE','extra page after fixed frontier');
    const record=pages[pageIndex];
    need(!paths.has(record.path),'CACHE_INTEGRITY','duplicate page path');paths.add(record.path);
    equal(record.request,{startHash:cursor,dataVerbosityLevel:'Full',
      minConfirmationCount:boundary.min_confirmation_count},'COVERAGE');
    const data=pageData(root,record);
    need(Array.isArray(data.removedChainBlockHashes)&&data.removedChainBlockHashes.length===0,
      'REORG','retained removals invalidate prefix');
    need(Array.isArray(data.addedChainBlockHashes)&&Array.isArray(data.chainBlockAcceptedTransactions)
      &&data.addedChainBlockHashes.length===data.chainBlockAcceptedTransactions.length
      &&data.addedChainBlockHashes.length>0,'TRUNCATED_PAGE','retained Full groups incomplete');
    for(let groupIndex=0;groupIndex<data.chainBlockAcceptedTransactions.length;groupIndex++) {
      const group=data.chainBlockAcceptedTransactions[groupIndex],hash=hex(data.addedChainBlockHashes[groupIndex],32);
      need(!seen.has(hash),'CURSOR_CYCLE','duplicate retained accepted block');seen.add(hash);
      validateHeader(k,group.chainBlockHeader,hash);
      const header=plainHeader(group.chainBlockHeader);
      need(header.parentsByLevel[0]?.includes(cursor),'TRUNCATED_PAGE','retained chain skips predecessor');
      need(integer(boundary.sink.blueScore)-integer(header.blueScore)>BigInt(boundary.min_confirmation_count),
        'DEPTH','accepted block is outside fixed sink confirmation policy');
      need(Array.isArray(group.acceptedTransactions),'TRUNCATED_PAGE','Full accepted bodies missing');
      for(let txIndex=0;txIndex<group.acceptedTransactions.length;txIndex++) {
        const tx=group.acceptedTransactions[txIndex],id=hex(tx.verboseData?.transactionId??tx.id,32);
        acceptedRows++;
        const locator={page:pageIndex,group:groupIndex,transaction:txIndex,id};
        if(id===d.founding_outpoint.transactionId) {
          need(!founding,'DUPLICATE_TRANSACTION','retained GN3 repeated');founding=locator;
        }
        need(Array.isArray(tx.inputs),'TRUNCATED_PAGE','accepted transaction inputs missing');
        tx.inputs.forEach((input,inputIndex)=>{
          const key=pointKey(point(input.previousOutpoint)),tail=d.initial_redeem_hex?.slice(228);
          const candidate=d.watched_outpoints?d.watched_outpoints.has(key)
            :key===pointKey(d.founding_outpoint)||typeof input.signatureScript==='string'
              &&tail&&input.signatureScript.endsWith(tail);
          if(candidate) {
            const rows=edges.get(key)??[];rows.push({...locator,input_index:inputIndex});edges.set(key,rows);
          }
        });
      }
      cursor=hash;
      if(cursor===boundary.header.hash){reached=true;break;}
    }
  }
  need(reached&&(!requireFounding||founding),'COVERAGE','complete funding/frontier prefix required');
  return {cursor,pages,edges,founding,accepted_transactions_scanned:acceptedRows};
}

export function verify(rawProfile,profileSha,rawDescriptor,descriptorSha,rawBundle,root,k=loadSdk()) {
  const selected=profile(rawProfile,profileSha);
  const d=descriptor(rawDescriptor,descriptorSha,selected,profileSha);
  const value=strictJson(rawBundle);
  need(value.schema==='kpxa-gn3-network-fetch/v1'&&value.status==='FETCHED_PENDING_REPLAY'
    &&value.network_id==='testnet-10'&&value.genesis_hash_hex===GENESIS
    &&value.financial_profile_sha256===selected.financial_profile_sha256
    &&value.selection_file_sha256===profileSha
    &&value.descriptor_file_sha256===descriptorSha
    &&value.descriptor_canonical_sha256===sha(canonical(d))
    &&value.public_parameter_blob_read===false&&value.owner_backup_or_signing_key_read===false
    &&value.accepted_backing_currentness_or_spend_authorized===false,
    'BUNDLE','new public acquisition and exact independent selections required');
  equal(value.descriptor,d,'BUNDLE');equal(value.sdk_pins,SDK_PINS,'SDK_IDENTITY');
  const coverage=value.coverage,view=value.current_view,post=view.post_query_delta;
  need(coverage.complete===true&&coverage.frontier_seen===true&&coverage.pruned===false
    &&Array.isArray(coverage.missing)&&coverage.missing.length===0
    &&Array.isArray(coverage.removed_chain_block_hashes)&&coverage.removed_chain_block_hashes.length===0
    &&coverage.start_hash===d.birth_start_hash&&coverage.end_cursor===coverage.frontier.hash
    &&Number.isSafeInteger(coverage.min_confirmation_count)&&coverage.min_confirmation_count>=1,
    'COVERAGE','complete fixed confirmed prefix required');
  validateHeader(k,coverage.anchor_header,d.birth_start_hash);
  validateHeader(k,coverage.frontier,coverage.frontier.hash);
  validateHeader(k,coverage.initial_sink,coverage.initial_sink.hash);
  need(integer(coverage.anchor_header.blueScore)<integer(coverage.frontier.blueScore)
    &&integer(coverage.initial_sink.blueScore)-integer(coverage.frontier.blueScore)
      >BigInt(coverage.min_confirmation_count),'DEPTH','birth/frontier/sink bounds');
  const boundary={header:coverage.frontier,sink:coverage.initial_sink,
    min_confirmation_count:coverage.min_confirmation_count};
  const scanned=retainedScan(k,d,boundary,value.pages,root);
  need(scanned.accepted_transactions_scanned===coverage.accepted_transaction_rows_scanned,
    'COVERAGE','accepted transaction row count differs');
  const found=discover(k,d,scanned,root,boundary);
  equal(found.rows,value.transactions,'FULL_BODY_BINDING');
  need(found.terminal_candidate===value.terminal_candidate_not_yet_replay_verified,
    'BUNDLE','terminal candidate differs from retained accepted bodies');
  const expected=new Map(),consumed=new Set();
  for(const row of found.rows) {
    equal(canonicalTransaction(row.transaction),row.transaction,'SDK_BODY');
    for(const input of row.accepted_input_contexts) {
      expected.set(pointKey(input.outpoint),input);consumed.add(pointKey(input.outpoint));
    }
    row.transaction.outputs.forEach((out,index)=>{
      const at={transactionId:row.transaction.id,index};
      expected.set(pointKey(at),{outpoint:at,amount_sompi:out.value,script_public_key:out.scriptPublicKey});
    });
  }
  const queries=new Map();
  need(Array.isArray(view.queries),'CURRENT_VIEW','exact point queries required');
  for(const q of view.queries) {
    const key=pointKey(point(q.outpoint));
    need(!queries.has(key)&&q.queried===true&&expected.has(key),'CURRENT_VIEW','missing/duplicate/extra point query');
    const e=expected.get(key);
    need(canonicalAmount(q.amount_sompi)===canonicalAmount(e.amount_sompi)
      &&q.script_public_key===e.script_public_key,'UTXO_SUBSTITUTION','queried expected output differs');
    if(q.entry!==null)queryEntry(q.entry,e);
    if(consumed.has(key))need(q.entry===null,'CURRENT_VIEW','consumed input still reported unspent');
    queries.set(key,q);
  }
  need(queries.size===expected.size,'CURRENT_VIEW','not every exact expected point was queried');
  if(found.head)need(queries.get(pointKey(found.head))?.entry!==null,
    'MISSING_CURRENT_HEAD','actual nonterminal W head is not unspent');
  need(view.checkpoint?.network==='testnet-10'&&view.checkpoint?.expected_genesis===GENESIS,
    'CURRENT_VIEW','selected network checkpoint required');
  hex(view.checkpoint.observed_sink,32);
  const live=new Set([...queries.values()].filter(q=>q.entry!==null).map(q=>pointKey(q.outpoint)));
  need(post?.completed===true&&post.rpc_views_are_atomic===false
    &&post.start_hash===coverage.frontier.hash&&Array.isArray(post.removed_chain_block_hashes)
    &&post.removed_chain_block_hashes.length===0&&Array.isArray(post.related_transactions)
    &&post.related_transactions.length===0,'POST_QUERY','complete race/reorg reconciliation required');
  const watched=post.watched_outpoints?.map(x=>pointKey(point(x)));
  need(Array.isArray(watched)&&new Set(watched).size===watched.length
    &&watched.length===live.size&&watched.every(x=>live.has(x)),
    'POST_QUERY','every currently live W/change/payout point must be watched');
  validateHeader(k,post.frontier,post.frontier.hash);
  need(integer(post.frontier.blueScore)>=integer(coverage.frontier.blueScore),
    'POST_QUERY','post-query frontier moved backwards');
  validateHeader(k,post.initial_sink,post.initial_sink.hash);
  need(post.min_confirmation_count===coverage.min_confirmation_count
    &&integer(post.initial_sink.blueScore)-integer(post.frontier.blueScore)
      >BigInt(post.min_confirmation_count),'POST_QUERY','post-query confirmed frontier policy differs');
  const postBoundary={header:post.frontier,sink:post.initial_sink,
    min_confirmation_count:post.min_confirmation_count};
  const postD={birth_start_hash:coverage.frontier.hash,
    founding_outpoint:{transactionId:'00'.repeat(32),index:0},watched_outpoints:live};
  const delta=retainedScan(k,postD,postBoundary,post.pages,root,false);
  need(delta.edges.size===0,'STALE_FRONTIER','queried live point spent after original frontier');
  need(post.server?.networkId==='testnet-10'&&post.server?.serverVersion==='2.1.0'
    &&post.server?.isSynced===true&&post.server?.hasUtxoIndex===true,
    'NODE_IDENTITY','post-query node identity differs');
  need(view.final_requery?.checkpoint?.network==='testnet-10'
    &&view.final_requery?.checkpoint?.expected_genesis===GENESIS,
    'CURRENT_VIEW','final exact-point requery required');
  hex(view.final_requery.checkpoint.observed_sink,32);
  equal(view.final_requery.queries,view.queries,'STALE_CURRENT_VIEW');
  return {schema:'kpxa-gn3-public-sdk-verification/v1',status:'PUBLIC_EVIDENCE_CONSISTENCY_PASS',
    financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,descriptor_file_sha256:descriptorSha,
    fetch_file_sha256:sha(rawBundle),sdk_pins:SDK_PINS,
    selected_transaction_ids:found.rows.map(row=>row.transaction.id),
    discovered_head:found.head,terminal_candidate:found.terminal_candidate,
    transaction_ids_and_full_body_context_locators_recomputed:true,
    header_hashes_and_prefix_paths_recomputed:true,current_view_and_delta_consistent:true,
    chain_inclusion_pow_or_independent_consensus_verified:false,
    no_GN3_or_W_semantic_native_verification_in_this_SDK_stage:true};
}

export function verifyCached(rawP,ps,rawD,ds,rawBundle,root,k,a){
 const info=admitted(a,rawP,ps,rawD,ds,k),value=strictJson(rawBundle);
 const trusted=!!(a.trusted||a['trusted-local-cache']);
 if(!trusted||!value.cache_reuse&&sha(rawBundle)!==info.baseRow.sha256)return verify(rawP,ps,rawD,ds,rawBundle,root,k);
 const base=prepareBase(info,a);
 if(sha(rawBundle)===info.baseRow.sha256){
  // This path is only the controller's already confirmed prefix in preflight.
  return {schema:'kpxa-gn3-public-sdk-verification/v1',status:'PUBLIC_EVIDENCE_CONSISTENCY_PASS',
   fetch_file_sha256:sha(rawBundle),selected_transaction_ids:info.base.transactions.map(r=>r.transaction.id),
   local_prior_SDK_scan_reused:true,local_trust_scope:'trusted-controller-local-state-only',
   public_receipt_is_external_attestation:false,baseline_fetch:info.baseRow};
 }
 const c=value.cache_reuse;
 equal(c.baseline_fetch,info.baseRow,'CACHE_PREFIX');equal(c.admission,info.admissionRow,'CACHE_PREFIX');equal(c.runtime_sources,info.source,'CACHE_PREFIX');
 equal(c.baseline_cache,a['baseline-cache']?row(a,'baseline-cache'):null,'CACHE_PREFIX');
 need(c.trust_scope==='trusted-controller-local-state-only','CACHE_PREFIX','same explicit local provenance scope');
 need(c.prefix_fingerprint===base.fingerprint&&c.base_pages===base.pages.length&&c.base_accepted_rows===base.accepted&&c.external_attestation===false,'CACHE_PREFIX','exact derived admitted prefix');
 equal(c.base_frontier,base.frontier,'CACHE_PREFIX');
 const suffix=base.pages[0].path,first=value.pages[0]?.path;
 need(typeof first==='string'&&first.endsWith(suffix),'CACHE_PREFIX','rebased prefix path');
 const prefix=first.slice(0,first.length-suffix.length),records=base.pages.map(r=>({...r,path:prefix+r.path}));
 REUSE={base,records};
 try{const result=verify(rawP,ps,rawD,ds,rawBundle,root,k);return {...result,local_prior_SDK_scan_reused:true,
  local_trust_scope:'trusted-controller-local-state-only',public_receipt_is_external_attestation:false,baseline_fetch:info.baseRow};}
 finally{REUSE=null;}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const [pp,ps,dp,ds,bp,bs,root,output,sdkDirectory,...rest]=process.argv.slice(2);
  const result=verifyCached(readPublic(pp,ps),ps,readPublic(dp,ds),ds,readPublic(bp,bs),checkedPath(root),loadSdk(sdkDirectory),cacheOptions(rest));
  fs.writeFileSync(checkedPath(output),stringify(result)+'\n',{flag:'wx',mode:0o600});process.stdout.write(stringify({status:result.status,transactions:result.selected_transaction_ids.length})+'\n');
 }catch(error){process.stderr.write(`cached SDK verification incomplete: ${error.category??'ERROR'}: ${error.message}\n`);process.exitCode=2;}
}
