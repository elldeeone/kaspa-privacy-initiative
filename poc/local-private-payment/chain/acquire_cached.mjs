// ADR0067 authenticated prefix + fixed-frontier delta; current queries stay live.
import fs from 'node:fs';
import path from 'node:path';
import {frontier,scan,discover,currentView,postQuery} from './acquire.mjs';
import {integer,need,script,validateHeader,SDK_PINS,sha} from './wire.mjs';
import {canonical} from './selection.mjs';
import {prepareBase,row} from './cache.mjs';
export async function fetchCachedOne(k,rpc,selected,profileSha,d,descriptorSha,root,info,a,prepared=null){
 // Production caller prepares before opening Tor/RPC. Optional fallback is for
 // small offline fake-RPC controls; no live connection should block on copies.
 const base=prepared??prepareBase(info,a,root);
 const boundary=await frontier(k,rpc),anchor=(await rpc.getBlock({hash:d.birth_start_hash,includeTransactions:false})).block;
 validateHeader(k,anchor.header,d.birth_start_hash);need(anchor.verboseData.isChainBlock===true,'CACHE_STALE','birth anchor left chain');
 const old=info.base.current_view.post_query_delta.frontier,checked=(await rpc.getBlock({hash:old.hash,includeTransactions:false})).block;
 validateHeader(k,checked.header,old.hash);need(checked.verboseData.isChainBlock===true&&integer(old.blueScore)<=integer(boundary.header.blueScore),'CACHE_STALE','old frontier stale');
 const deltaRoot=path.join(root,'delta');fs.mkdirSync(deltaRoot,{mode:0o700});
 const delta=old.hash===boundary.header.hash?{pages:[],edges:new Map(),cursor:old.hash,accepted_transactions_scanned:0}:await scan(k,rpc,{...d,birth_start_hash:old.hash},boundary,deltaRoot,false);
 const offset=base.pages.length,pages=[...base.pages,...delta.pages.map(r=>({...r,path:path.posix.join('delta',r.path)}))],edges=new Map([...base.edges].map(([key,v])=>[key,[...v]]));
 for(const [key,v]of delta.edges){const rows=edges.get(key)??[];rows.push(...v.map(r=>({...r,page:r.page+offset})));edges.set(key,rows);}
 const scanned={anchor:info.base.coverage.anchor_header,cursor:boundary.header.hash,pages,edges,founding:base.founding,accepted_transactions_scanned:base.accepted+delta.accepted_transactions_scanned};
 const found=discover(k,d,scanned,root,boundary),initial=k.payToScriptHashScript(Buffer.from(d.initial_redeem_hex,'hex'));
 try{need(script(initial)===found.rows[0].transaction.outputs[0].scriptPublicKey,'GN3','same actual founding policy');}finally{initial.free();}
 const view=await currentView(k,rpc,found);view.post_query_delta=await postQuery(k,rpc,d,boundary,found,root,view);
 const rechecked=await currentView(k,rpc,found);need(canonical(view.queries)===canonical(rechecked.queries),'STALE_CURRENT_VIEW','live points changed');view.final_requery=rechecked;
 return {schema:'kpxa-gn3-network-fetch/v1',status:'FETCHED_PENDING_REPLAY',network_id:'testnet-10',genesis_hash_hex:info.base.genesis_hash_hex,financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,descriptor:d,descriptor_file_sha256:descriptorSha,descriptor_canonical_sha256:sha(canonical(d)),trust:'REMOTE_VALIDATING_NODE_AND_RETAINED_CHAIN_DATA',rpc_views_are_atomic:false,sdk_pins:SDK_PINS,transactions:found.rows,current_view:view,pages,terminal_candidate_not_yet_replay_verified:found.terminal_candidate,
 coverage:{start_hash:d.birth_start_hash,anchor_header:info.base.coverage.anchor_header,frontier:boundary.header,initial_sink:boundary.sink,end_cursor:boundary.header.hash,complete:true,frontier_seen:true,removed_chain_block_hashes:[],missing:[],pruned:false,min_confirmation_count:boundary.min_confirmation_count,accepted_transaction_rows_scanned:scanned.accepted_transactions_scanned,scope:'FINITE_CONFIRMED_PREFIX_PENDING_GN3_W_SEMANTIC_REPLAY'},
 cache_reuse:{baseline_fetch:info.baseRow,baseline_cache:a['baseline-cache']?row(a,'baseline-cache'):null,admission:info.admissionRow,runtime_sources:info.source,prefix_fingerprint:base.fingerprint,base_pages:base.pages.length,base_frontier:base.frontier,base_accepted_rows:base.accepted,trust_scope:'trusted-controller-local-state-only',external_attestation:false},
 public_parameter_blob_read:false,owner_backup_or_signing_key_read:false,accepted_backing_currentness_or_spend_authorized:false,observed_at:new Date().toISOString()};
}
