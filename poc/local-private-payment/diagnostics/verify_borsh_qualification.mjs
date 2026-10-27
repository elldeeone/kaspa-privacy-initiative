// OFFLINE correction only. Reuse actual pinned capture; perform ZERO network operations.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {guardedRead} from '../chain/public.mjs';
import {strictJson} from '../chain/json.mjs';
import {loadSdk,plainHeader,validateHeader,canonicalTransaction,contexts,verifyTransactionId,integer,script,sha,stringify} from '../chain/wire.mjs';
import {entry as originalEntry} from '../chain/acquire.mjs';
import {nativeCaseJson} from './native_case_json.mjs';
const args={};for(let i=2;i<process.argv.length;i+=2){if(!['--selection','--selection-sha256','--qualification','--qualification-sha256','--output'].includes(process.argv[i])||!process.argv[i+1]||args[process.argv[i]])throw new Error('closed arguments');args[process.argv[i]]=process.argv[i+1];}
assert.equal(Object.keys(args).length,5);
const s=strictJson(guardedRead(args['--selection'],args['--selection-sha256']));assert.equal(s.schema,'kpxa-readonly-borsh-deadline-qualification-selection/v1');
for(const row of s.source_members)guardedRead(row.path,row.sha256);
const oldFetch=strictJson(guardedRead(s.baseline_fetch.path,s.baseline_fetch.sha256)),handoff=strictJson(guardedRead(s.baseline_handoff.path,s.baseline_handoff.sha256));
assert.equal(handoff.accepted_whole_CASE_equals_expected,true);assert.equal(handoff.selectors['fetch.json'].sha256,s.baseline_fetch.sha256);assert.equal(handoff.selectors['fetch.json'].path,s.baseline_fetch.path);
const selectedPage=oldFetch.pages[207];assert.equal(path.resolve(path.dirname(s.baseline_fetch.path),selectedPage.path),s.reference_page.path);assert.equal(selectedPage.gzip_sha256,s.reference_page.sha256);assert.deepEqual(selectedPage.request,s.reference_request);
const oldRaw=zlib.gunzipSync(guardedRead(s.reference_page.path,s.reference_page.sha256));assert.equal(sha(oldRaw),selectedPage.decoded_sha256);assert.equal(oldRaw.length,selectedPage.decoded_bytes);const oldPage=strictJson(oldRaw);
const case10=nativeCaseJson(guardedRead(s.case10.path,s.case10.sha256)),case11=nativeCaseJson(guardedRead(s.case11.path,s.case11.sha256));
const k=loadSdk(),output=path.resolve(args['--output']),parent='/dev/shm/kpi-local-private-payment-transport-01';
assert.equal(path.dirname(output),parent);assert(!fs.existsSync(output));const st=fs.lstatSync(parent);assert(st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700);fs.mkdirSync(output,{mode:0o700});
const result={schema:'kpxa-retained-borsh-offline-qualification/v1',selection_sha256:args['--selection-sha256'],status:'IN_PROGRESS',stage:'CONNECT',endpoint:s.upstream,rpc_deadline_seconds:900,outputs:{},calls:[],financial_action:false,full_financial_replay_or_confirmation:false,raw_decoded_byte_identity_claimed:false,synthetic_latency_control:false};
function save(name,value){const raw=stringify(value)+'\n',p=path.join(output,name+'.json');fs.writeFileSync(p,raw,{flag:'wx',mode:0o400});return {path:p,sha256:sha(raw),bytes:Buffer.byteLength(raw)};}
function semantic(v){if(typeof v==='number'){assert(Number.isSafeInteger(v));return String(v);}if(Array.isArray(v))return v.map(semantic);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(key=>[key,semantic(v[key])]));return v;}
function retained(v){return {removedChainBlockHashes:v.removedChainBlockHashes,addedChainBlockHashes:v.addedChainBlockHashes,chainBlockAcceptedTransactions:v.chainBlockAcceptedTransactions.map(g=>({chainBlockHeader:plainHeader(g.chainBlockHeader),acceptedTransactions:g.acceptedTransactions}))};}

const capture=strictJson(guardedRead(args['--qualification'],args['--qualification-sha256']));
assert.equal(capture.selection_sha256,args['--selection-sha256']);assert.equal(capture.status,'FAIL_PRESERVED');assert.equal(capture.stage,'CASE10_EXPECTATION');
assert.equal(capture.calls.length,6);assert(capture.calls.every(c=>c.status==='RETURNED'));
const received={};for(const name of ['server_info','dag_info','block','utxos','reference','failed_cursor']){const row=capture.outputs[name];received[name]=strictJson(guardedRead(row.path,row.sha256));}
Object.assign(result,{capture_sha256:args['--qualification-sha256'],original_capture_status:capture.status,original_capture_stage:capture.stage,network_operations_performed:0,uses_retained_network_responses:true,calls:capture.calls,outputs:capture.outputs,acquisition_sources:capture.acquisition_sources,correction:'Native CASE unsafe integer tokens retain original decimal lexemes; original old SDK/range/whole-body checks unchanged'});
try{
 result.stage='NETWORK_IDENTITY';assert.equal(received.dag_info.network,'testnet-10');assert.equal(received.server_info.isSynced,true);assert.equal(received.server_info.networkId,'testnet-10');assert.equal(received.server_info.serverVersion,'2.1.0');assert.equal(received.server_info.hasUtxoIndex,true);
 result.stage='SAME_CURSOR_SEMANTICS';assert.deepEqual(semantic(retained(received.reference)),semantic(retained(oldPage)),'same-cursor whole accepted groups differ');
 result.stage='CASE10_EXPECTATION';const expectedBody=canonicalTransaction(case10.transaction),expectedContexts=contexts({...case10.transaction,inputs:case10.transaction.inputs.map((input,i)=>({...input,verboseData:{utxoEntry:case10.entries[i]}}))},expectedBody);
 result.stage='OLD_SDK_HEADERS_AND_BODIES';let headers=0,transactions=0,poolBodies=0,inputContexts=0,wholeCase10=0;
 for(const [name,value]of [['reference',received.reference],['failed_cursor',received.failed_cursor]]){
  assert.equal(value.removedChainBlockHashes.length,0);assert.equal(value.addedChainBlockHashes.length,value.chainBlockAcceptedTransactions.length);assert(value.addedChainBlockHashes.length>0);
  for(let i=0;i<value.chainBlockAcceptedTransactions.length;i++){const group=value.chainBlockAcceptedTransactions[i];validateHeader(k,group.chainBlockHeader,value.addedChainBlockHashes[i]);headers++;
   for(const tx of group.acceptedTransactions){transactions++;integer(tx.version,16);if(typeof tx.payload==='string'&&tx.payload.startsWith('4b505841')){const body=canonicalTransaction(tx),entries=contexts(tx,body);verifyTransactionId(k,body,entries);poolBodies++;inputContexts+=entries.length;if(name==='reference'&&body.id===expectedBody.id){assert.deepEqual(body,expectedBody,'accepted whole CASE10 transaction differs');assert.deepEqual(entries,expectedContexts,'accepted whole CASE10 populated contexts differ');wholeCase10++;}}}
  }
 }
 result.stage='KNOWN_WHOLE_CASE10';assert.equal(wholeCase10,1,'nonvacuous known accepted native CASE10 required');validateHeader(k,received.block.block.header,s.block_hash);assert.equal(received.block.block.verboseData.isChainBlock,true);
 result.stage='CASE11_UTXO';const target=case11.transaction,paid=target.outputs.at(-1),index=target.outputs.length-1;
 const matches=received.utxos.entries.filter(raw=>raw.outpoint.transactionId===target.id&&raw.outpoint.index===index);assert.equal(matches.length,1);const payout=originalEntry(matches[0]);assert.equal(payout.amount_sompi,integer(paid.value).toString());assert.equal(payout.script_public_key,script(paid.scriptPublicKey));assert.equal(payout.is_coinbase,false);assert.equal(payout.covenant_id,null);
 Object.assign(result,{stage:'COMPLETE',status:'FUNCTIONAL_SAME_CURSOR_WHOLE_CASE_AND_OLD_SDK_CHECKS_PASS',headers,transactions,pool_bodies_checked:poolBodies,input_contexts_checked:inputContexts,whole_accepted_case10_matches:wholeCase10,exact_case11_payout_UTXO_observed:true,request_over_old_60s_observed:result.calls.some(r=>r.status==='RETURNED'&&r.wall_ms>60000),deadline_change_source_bound:true});
}catch{result.status='FAIL_PRESERVED';result.error_class='RetainedBorshOfflineQualificationFailure';}
const final=save('RESULTS',result);process.stdout.write(stringify({status:result.status,output,result_sha256:final.sha256,network_operations_performed:0}));if(result.status==='FAIL_PRESERVED')process.exitCode=2;
