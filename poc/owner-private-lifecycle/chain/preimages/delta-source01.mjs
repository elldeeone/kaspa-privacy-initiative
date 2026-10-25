#!/usr/bin/env node
// Read-only transport optimization. Financial acceptance still requires the
// unchanged complete-prefix SDK/native replay, including all reused raw pages.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {GENESIS, SDK_PINS, hex, integer, loadSdk, need, plainHeader, point,
  pointKey, script, sha, stringify, validateHeader} from './wire.mjs';
import {canonical, checkedPath, descriptor, profile, readPublic, strictJson} from './selection.mjs';
import {currentView, discover, frontier, pageData, postQuery, save, scan} from './acquire.mjs';
import {DEFAULT_RPCS, fetchOne} from './fetch.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const SOURCE_NAMES=['delta.mjs','acquire.mjs','fetch.mjs','wire.mjs','selection.mjs','json.mjs'];
function equal(a,b,code) {need(canonical(a)===canonical(b),code,'public evidence differs');}
function count(value) {need(Number.isSafeInteger(value)&&value>=0,'CACHE_INTEGRITY','exact byte length required');return value;}

// Authenticate both encodings and lengths before interpreting cached bytes.
// readPublic also rejects symlinks, hardlinks and source replacement races.
export function authenticatedPage(root,record) {
  need(typeof record.path==='string'&&!path.isAbsolute(record.path)
    &&path.posix.normalize(record.path)===record.path
    &&!record.path.split('/').includes('..'),'CACHE_INTEGRITY','canonical relative page path');
  const base=checkedPath(root),file=checkedPath(path.join(base,record.path));
  need(file.startsWith(base+path.sep),'CACHE_INTEGRITY','page outside selected cache');
  const compressed=readPublic(file,record.gzip_sha256);
  need(compressed.length===count(record.gzip_bytes),'CACHE_INTEGRITY','gzip byte length differs');
  const raw=zlib.gunzipSync(compressed);
  need(raw.length===count(record.decoded_bytes)&&sha(raw)===record.decoded_sha256,
    'CACHE_INTEGRITY','decoded bytes differ');
  return {compressed,data:strictJson(raw)};
}

// Visit only the old confirmed prefix. A response containing groups beyond its
// frontier is never reused: its preceding whole-page cursor is our fresh seam.
// No cached post-query page is inspected or promoted into the main prefix.
export function cachePlan(k,d,old,root,retain=()=>{}) {
  const c=old.coverage;
  need(old.schema==='kpx8-gn3-network-fetch/v1'&&old.status==='FETCHED_PENDING_REPLAY'
    &&old.network_id==='testnet-10'&&old.genesis_hash_hex===GENESIS,
    'CACHE_SELECTION','prior selected Full acquisition required');
  equal(old.descriptor,d,'CACHE_SELECTION');
  need(c?.complete===true&&c.frontier_seen===true&&c.pruned===false
    &&c.start_hash===d.birth_start_hash&&c.end_cursor===c.frontier.hash
    &&c.removed_chain_block_hashes?.length===0&&c.missing?.length===0
    &&Number.isSafeInteger(c.min_confirmation_count)&&c.min_confirmation_count>=1,
    'CACHE_COVERAGE','prior complete confirmed prefix required');
  validateHeader(k,c.anchor_header,d.birth_start_hash);
  validateHeader(k,c.frontier,c.frontier.hash);validateHeader(k,c.initial_sink,c.initial_sink.hash);
  need(integer(c.anchor_header.blueScore)<integer(c.frontier.blueScore)
    &&integer(c.initial_sink.blueScore)-integer(c.frontier.blueScore)>BigInt(c.min_confirmation_count),
    'CACHE_COVERAGE','prior confirmation bounds differ');
  need(Array.isArray(old.pages)&&old.pages.length>0,'CACHE_COVERAGE','prior main pages required');
  let cursor=d.birth_start_hash,reached=false,acceptedRows=0,cachedRows=0,seamHeader=c.anchor_header;
  const seen=new Set([cursor]),paths=new Set(),pages=[],edges=new Map();let founding;
  for(let index=0;index<old.pages.length;index++) {
    need(!reached,'CACHE_COVERAGE','extra main page after old confirmed frontier');
    const record=old.pages[index];
    need(!paths.has(record.path),'CACHE_INTEGRITY','duplicate cached page');paths.add(record.path);
    equal(record.request,{startHash:cursor,dataVerbosityLevel:'Full',minConfirmationCount:c.min_confirmation_count},'CACHE_JOIN');
    const loaded=authenticatedPage(root,record),data=loaded.data;
    need(Array.isArray(data.removedChainBlockHashes)&&data.removedChainBlockHashes.length===0,
      'REORG','cached removals invalidate reuse');
    need(Array.isArray(data.addedChainBlockHashes)&&Array.isArray(data.chainBlockAcceptedTransactions)
      &&data.addedChainBlockHashes.length===data.chainBlockAcceptedTransactions.length
      &&data.addedChainBlockHashes.length>0,'CACHE_GAP','cached Full response incomplete');
    const localEdges=new Map(),beforeRows=acceptedRows;let localFounding,consumedGroups=0;
    for(let groupIndex=0;groupIndex<data.chainBlockAcceptedTransactions.length;groupIndex++) {
      const group=data.chainBlockAcceptedTransactions[groupIndex],hash=hex(data.addedChainBlockHashes[groupIndex],32);
      need(!seen.has(hash),'CACHE_JOIN','duplicate cached chain block');seen.add(hash);
      validateHeader(k,group.chainBlockHeader,hash);
      need(plainHeader(group.chainBlockHeader).parentsByLevel[0]?.includes(cursor),
        'CACHE_GAP','cached path skips its predecessor');
      need(integer(c.initial_sink.blueScore)-integer(group.chainBlockHeader.blueScore)>BigInt(c.min_confirmation_count),
        'CACHE_COVERAGE','cached group lacks old fixed depth');
      need(Array.isArray(group.acceptedTransactions),'CACHE_GAP','cached Full bodies missing');
      for(let txIndex=0;txIndex<group.acceptedTransactions.length;txIndex++) {
        const tx=group.acceptedTransactions[txIndex],id=hex(tx.verboseData?.transactionId??tx.id,32);
        acceptedRows++;const locator={page:pages.length,group:groupIndex,transaction:txIndex,id};
        if(id===d.founding_outpoint.transactionId) {
          need(!founding&&!localFounding,'CACHE_JOIN','duplicate founding transaction');localFounding=locator;
        }
        need(Array.isArray(tx.inputs),'CACHE_GAP','cached transaction inputs missing');
        tx.inputs.forEach((input,inputIndex)=>{
          const key=pointKey(point(input.previousOutpoint)),tail=d.initial_redeem_hex.slice(228);
          if(key===pointKey(d.founding_outpoint)||typeof input.signatureScript==='string'&&tail&&input.signatureScript.endsWith(tail)) {
            const rows=localEdges.get(key)??[];rows.push({...locator,input_index:inputIndex});localEdges.set(key,rows);
          }
        });
      }
      cursor=hash;
      consumedGroups++;
      if(cursor===c.frontier.hash) {
        equal(plainHeader(group.chainBlockHeader),c.frontier,'CACHE_JOIN');reached=true;
        // Whole response bytes after this group were never confirmed by the
        // prior fixed replay. Discard this whole page; reacquire the overlap.
        if(groupIndex!==data.addedChainBlockHashes.length-1)break;
      }
    }
    const whole=consumedGroups===data.addedChainBlockHashes.length;
    if(whole) {
      const selected=retain(record,loaded.compressed,index)??record;pages.push(selected);
      cachedRows+=acceptedRows-beforeRows;
      for(const [key,rows] of localEdges)edges.set(key,[...(edges.get(key)??[]),...rows]);
      if(localFounding)founding=localFounding;
      seamHeader=plainHeader(data.chainBlockAcceptedTransactions.at(-1).chainBlockHeader);
    }
  }
  need(reached&&acceptedRows===c.accepted_transaction_rows_scanned,'CACHE_COVERAGE','old frontier/row count differs');
  need(pages.length>0&&founding,'CACHE_MISS','no complete founding-containing cached prefix');
  return {pages,edges,founding,anchor:c.anchor_header,cursor:seamHeader.hash,seam_header:seamHeader,
    old_frontier:c.frontier,min_confirmation_count:c.min_confirmation_count,
    accepted_transactions_scanned:cachedRows};
}

function mergeScan(k,d,cached,delta,root,boundary) {
  const offset=cached.pages.length,pages=[...cached.pages,...delta.pages],edges=new Map(cached.edges);
  for(const [key,rows] of delta.edges)edges.set(key,[...(edges.get(key)??[]),...rows.map(row=>({...row,page:row.page+offset}))]);
  let oldSeen=cached.cursor===cached.old_frontier.hash;
  // cachePlan indexed all retained groups and scan indexed all fresh groups.
  // Inspect the fresh overlap; never count unconsumed final-response groups.
  let reached=false;
  for(const record of delta.pages) {
    const data=pageData(root,record);
    for(const group of data.chainBlockAcceptedTransactions) {
      if(group.chainBlockHeader.hash===cached.old_frontier.hash) {
        equal(plainHeader(group.chainBlockHeader),cached.old_frontier,'CACHE_JOIN');oldSeen=true;
      }
      if(group.chainBlockHeader.hash===boundary.header.hash){reached=true;break;}
    }
    if(reached)break;
  }
  need(oldSeen&&reached,'CACHE_JOIN','fresh overlap must include prior confirmed frontier');
  return {anchor:cached.anchor,cursor:delta.cursor,pages,edges,founding:cached.founding,
    accepted_transactions_scanned:cached.accepted_transactions_scanned+delta.accepted_transactions_scanned};
}

async function selectedAnchor(k,rpc,header,code) {
  const block=(await rpc.getBlock({hash:header.hash,includeTransactions:false})).block;
  validateHeader(k,block.header,header.hash);equal(plainHeader(block.header),header,code);
  need(block.verboseData.isChainBlock===true,code,'cached anchor no longer selected');
}

export async function fetchIncremental(k,rpc,selected,profileSha,d,descriptorSha,cache,root) {
  const boundary=await frontier(k,rpc);
  need(boundary.min_confirmation_count===cache.old.coverage.min_confirmation_count,
    'CACHE_SELECTION','confirmation policy changed');
  need(integer(boundary.header.blueScore)>integer(cache.old.coverage.frontier.blueScore),
    'STALE_FRONTIER','new confirmed frontier must advance');
  const cacheRoot=path.join(root,'cache');fs.mkdirSync(cacheRoot,{mode:0o700});
  const cached=cachePlan(k,d,cache.old,cache.root,(record,bytes)=>{
    const copy={...record,path:path.posix.join('cache',record.path)};
    save(path.join(root,copy.path),bytes);return copy;
  });
  await selectedAnchor(k,rpc,cached.anchor,'REORG');
  await selectedAnchor(k,rpc,cached.seam_header,'REORG');
  await selectedAnchor(k,rpc,cached.old_frontier,'REORG');
  const deltaRoot=path.join(root,'delta');fs.mkdirSync(deltaRoot,{mode:0o700});
  const delta=await scan(k,rpc,{...d,birth_start_hash:cached.cursor},boundary,deltaRoot,false);
  delta.pages=delta.pages.map(record=>({...record,path:path.posix.join('delta',record.path)}));
  const scanned=mergeScan(k,d,cached,delta,root,boundary),found=discover(k,d,scanned,root,boundary);
  const initial=k.payToScriptHashScript(Buffer.from(d.initial_redeem_hex,'hex'));
  try {need(script(initial)===found.rows[0].transaction.outputs[0].scriptPublicKey,'GN3','initial W differs');}
  finally {initial.free();}
  const view=await currentView(k,rpc,found);
  view.post_query_delta=await postQuery(k,rpc,d,boundary,found,root,view);
  const rechecked=await currentView(k,rpc,found);
  equal(view.queries,rechecked.queries,'STALE_CURRENT_VIEW');view.final_requery=rechecked;
  await selectedAnchor(k,rpc,cached.seam_header,'REORG');
  await selectedAnchor(k,rpc,cached.old_frontier,'REORG');
  return {schema:'kpx8-gn3-network-fetch/v1',status:'FETCHED_PENDING_REPLAY',network_id:'testnet-10',genesis_hash_hex:GENESIS,
    financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,
    descriptor:d,descriptor_file_sha256:descriptorSha,descriptor_canonical_sha256:sha(canonical(d)),
    trust:'REMOTE_VALIDATING_NODE_AND_RETAINED_CHAIN_DATA',rpc_views_are_atomic:false,sdk_pins:SDK_PINS,
    transactions:found.rows,current_view:view,coverage:{start_hash:d.birth_start_hash,anchor_header:scanned.anchor,
      frontier:boundary.header,initial_sink:boundary.sink,end_cursor:scanned.cursor,complete:true,frontier_seen:true,
      removed_chain_block_hashes:[],missing:[],pruned:false,min_confirmation_count:boundary.min_confirmation_count,
      accepted_transaction_rows_scanned:scanned.accepted_transactions_scanned,
      scope:'FINITE_CONFIRMED_PREFIX_PENDING_GN3_W_SEMANTIC_REPLAY'},pages:scanned.pages,
    terminal_candidate_not_yet_replay_verified:found.terminal_candidate,public_parameter_blob_read:false,
    owner_backup_or_signing_key_read:false,accepted_backing_currentness_or_spend_authorized:false,
    incremental_acquisition:{schema:'kpx8-whole-main-page-delta/v1',prior_handoff_sha256:cache.handoffSha,
      prior_fetch_sha256:cache.fetchSha,prior_confirmed_frontier:cached.old_frontier.hash,
      fresh_delta_start_hash:cached.cursor,reused_whole_main_pages:cached.pages.length,
      trailing_partial_main_page_refetched:cached.cursor!==cached.old_frontier.hash,
      prior_post_query_pages_reused:0,complete_prefix_replay_required:true},observed_at:new Date().toISOString()};
}

export function loadCache(handoffPath,handoffSha,profileSha,descriptorSha) {
  const handoff=strictJson(readPublic(handoffPath,handoffSha));
  need(handoff.schema==='kpx8-confirmed-transition-handoff/v1'
    &&handoff.status==='RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS'
    &&handoff.submission_performed===false,'CACHE_SELECTION','pinned prior confirmation handoff required');
  need(handoff.selectors?.selection?.sha256===profileSha&&handoff.selectors?.descriptor?.sha256===descriptorSha,
    'CACHE_SELECTION','cache selected identity differs');
  const f=handoff.selectors['fetch.json'],old=strictJson(readPublic(f.path,f.sha256));
  need(old.selection_file_sha256===profileSha&&old.descriptor_file_sha256===descriptorSha,
    'CACHE_SELECTION','old fetch selection differs');
  const listed=new Map(handoff.full_prefix_pages.map(row=>[checkedPath(row.path),row]));
  const root=path.dirname(checkedPath(f.path));
  for(const record of old.pages) {
    const row=listed.get(checkedPath(path.join(root,record.path)));
    need(row&&row.sha256===record.gzip_sha256&&row.bytes===record.gzip_bytes,
      'CACHE_SELECTION','old MAIN page not bound by confirmed handoff');
  }
  return {old,root,handoffSha,fetchSha:f.sha256};
}

export async function execute(pp,ps,dp,ds,hp,hs,output,urls=DEFAULT_RPCS,k=loadSdk()) {
  const selected=profile(readPublic(pp,ps),ps),d=descriptor(readPublic(dp,ds),ds,selected,ps);
  output=checkedPath(output);need(!fs.existsSync(output),'OUTPUT_EXISTS','fresh public output required');
  fs.mkdirSync(output,{recursive:true,mode:0o700});
  // New producer identity is explicit even when a full acquisition fallback wins.
  const producer={name:'whole-main-page-delta/v1',sources:Object.fromEntries(SOURCE_NAMES.map(name=>[name,sha(fs.readFileSync(path.join(HERE,name)))])),
    unchanged_verifiers:['verify_bundle.mjs','replay.py'],complete_prefix_replay_required:true};
  const attempts=[];
  for(let index=0;index<urls.length;index++) {
    const endpoint=new URL(urls[index]);
    need((endpoint.protocol==='wss:'||endpoint.protocol==='ws:'&&['localhost','127.0.0.1','[::1]'].includes(endpoint.hostname))
      &&!endpoint.username&&!endpoint.password&&!endpoint.search&&!endpoint.hash,'ENDPOINT','public TLS or loopback RPC required');
    const root=path.join(output,`attempt-${String(index+1).padStart(3,'0')}`);fs.mkdirSync(root,{mode:0o700});
    const rpc=new k.RpcClient({url:endpoint.href,networkId:'testnet-10'});
    try {
      await rpc.connect({blockAsyncConnect:true,timeoutDuration:60000,strategy:'fallback'});
      let fetched,mode='INCREMENTAL',fallback;
      try {const cache=loadCache(hp,hs,ps,ds);fetched=await fetchIncremental(k,rpc,selected,ps,d,ds,cache,root);}
      catch(error) {
        fallback={category:error.category??'CACHE_OR_DELTA_UNAVAILABLE',error:String(error.message??error)};
        save(path.join(root,'DELTA-FALLBACK.json'),fallback);mode='FULL_FALLBACK';
        const fullRoot=path.join(root,'full');fs.mkdirSync(fullRoot,{mode:0o700});
        fetched=await fetchOne(k,rpc,selected,ps,d,ds,fullRoot);
        fetched.pages=fetched.pages.map(row=>({...row,path:path.posix.join('full',row.path)}));
        fetched.current_view.post_query_delta.pages=fetched.current_view.post_query_delta.pages.map(row=>({...row,path:path.posix.join('full',row.path)}));
      }
      fetched.source={rpc_url:endpoint.href,attempt:index+1,collector:producer,acquisition_mode:mode,
        fallback:fallback??null,assertion_scope:'Distinct endpoint names do not establish independent administration or consensus'};
      fetched.attempts=attempts;
      fetched.pages=fetched.pages.map(row=>({...row,path:path.posix.join(path.basename(root),row.path)}));
      fetched.current_view.post_query_delta.pages=fetched.current_view.post_query_delta.pages.map(row=>({...row,path:path.posix.join(path.basename(root),row.path)}));
      save(path.join(output,'fetch.json'),fetched);return fetched;
    }catch(error) {
      const failed={rpc_url:endpoint.href,status:'INCOMPLETE',category:error.category??'DATA_UNAVAILABLE',error:String(error.message??error)};
      save(path.join(root,'INCOMPLETE.json'),failed);attempts.push(failed);
    }finally {await rpc.disconnect();}
  }
  const failed={schema:'kpx8-gn3-network-fetch/v1',status:'INCOMPLETE',attempts,balance_known:false,no_empty_balance_inference:true};
  save(path.join(output,'INCOMPLETE.json'),failed);return failed;
}

if(process.argv[1]===fileURLToPath(import.meta.url)) {
  try {
    const [pp,ps,dp,ds,hp,hs,output,...rest]=process.argv.slice(2),urls=[];let sdk;
    need(pp&&ps&&dp&&ds&&hp&&hs&&output,'ARGUMENT','delta.mjs PROFILE SHA DESCRIPTOR SHA PRIOR_HANDOFF SHA FRESH_OUTPUT [--rpc URL] [--sdk-dir DIR]');
    for(let i=0;i<rest.length;i+=2) {
      need(rest[i+1]&&['--rpc','--sdk-dir'].includes(rest[i]),'ARGUMENT','unknown option');
      if(rest[i]==='--rpc')urls.push(rest[i+1]);else {need(!sdk,'ARGUMENT','duplicate SDK directory');sdk=checkedPath(rest[i+1]);}
    }
    const result=await execute(pp,ps,dp,ds,hp,hs,output,urls.length?urls:DEFAULT_RPCS,loadSdk(sdk));
    process.stdout.write(stringify({status:result.status,output,transactions:result.transactions?.length,
      acquisition_mode:result.source?.acquisition_mode,balance_known:false})+'\n');
    if(result.status==='INCOMPLETE')process.exitCode=2;
  }catch(error) {process.stderr.write(`Full-prefix delta incomplete: ${error.category??'ERROR'}: ${error.message}\n`);process.exitCode=2;}
}
