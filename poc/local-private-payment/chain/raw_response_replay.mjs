// Optional, finite replay of authenticated LOCAL transport responses. No financial cache authority.
import zlib from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {guardedRead} from './public.mjs';
import {strictJson,canonical} from './json.mjs';
import {integer,hex,sha,plainHeader,validateHeader,Incomplete} from './wire.mjs';
import {METHODS,exact} from '../ingress/readonly_borsh_worker.mjs';
export const CAPTURE_SELECTOR_ROW=Object.freeze({path:fileURLToPath(new URL('../ingress/RAW-DELTA79-CAPTURE-01.json',import.meta.url)),sha256:'3fec5e9a0cddc49822c8feb969c495347a3d9df623f758ae15b6d23d4cf2e520'});
const DIRECTORY='/dev/shm/kpi-local-private-payment-transport-01/borsh-full-acquisition-01';
const ENDPOINT='wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh';
const SCOPE_KEYS=['endpoint','selection','descriptor','runtime_source','cache_admission','baseline_fetch','baseline_cache'];
const FALLBACKS=['CACHE_STALE','REORG','STALE_FRONTIER','STALE_CURRENT_VIEW'];
const need=(ok,message)=>{if(!ok)throw new Incomplete('CACHE_STALE',message);};
const same=(a,b)=>canonical(a)===canonical(b);
const closed=(value,names)=>{try{exact(value,names);}catch{need(false,'closed selected raw fields');}};
function selectedRow(row){closed(row,['path','sha256']);need(typeof row.path==='string'&&row.path.startsWith('/'),'absolute public selector');hex(row.sha256,32);}
export function validateManifest(s,scope){
 need(s?.schema==='kpxa-selected-raw-full-capture/v1'&&s.financial_cache_authority===false&&s.expected_base_pages===217,'transport-only finite capture');
 closed(scope,SCOPE_KEYS);closed(s.scope,SCOPE_KEYS);need(scope.endpoint===ENDPOINT&&same(scope,s.scope),'same exact original financial acquisition scope');
 for(const key of SCOPE_KEYS.filter(k=>k!=='endpoint'))selectedRow(scope[key]);
 need(s.capture_directory===DIRECTORY&&Array.isArray(s.pages)&&s.pages.length===79,'exact selected79 capture');
 for(const key of ['capture_selection','capture_results','origin_report','ancestry_report'])selectedRow(s[key]);
 let cursor=hex(s.initial_cursor,32);for(let i=0;i<s.pages.length;i++){
  const row=s.pages[i];need(row.page===i&&row.call===i+13,'exact captured order and call');
  closed(row.request,['startHash','dataVerbosityLevel','minConfirmationCount']);need(row.request.startHash===cursor&&row.first_parent===cursor&&row.request.dataVerbosityLevel==='Full'&&row.request.minConfirmationCount===20,'contiguous Full20 capture');
  need(row.gzip.path===`${DIRECTORY}/prefix/attempt-001/delta/pages/${String(i).padStart(5,'0')}.json.gz`,'finite public page path');
  for(const key of ['gzip','request_event','response_event']){const r=row[key];closed(r,['path','bytes','sha256']);hex(r.sha256,32);need(Number.isSafeInteger(r.bytes)&&r.bytes>0,'capture bytes');}
  for(const key of ['request_event','response_event'])need(row[key].path.startsWith(DIRECTORY+'/events/')&&/^\d{6}\.json$/.test(row[key].path.slice((DIRECTORY+'/events/').length)),'selected public event');
  hex(row.decoded_sha256,32);hex(row.ipc_sha256,32);need(Number.isSafeInteger(row.decoded_bytes)&&row.decoded_bytes>0&&Number.isSafeInteger(row.ipc_bytes)&&row.ipc_bytes>0&&Number.isSafeInteger(row.groups)&&row.groups>0,'decoded capture identity');cursor=hex(row.last_hash,32);
 }
 need(s.tail?.hash===cursor&&s.tail.header?.hash===cursor,'same selected retained tail');plainHeader(s.tail.header);return s;
}
export function validateEligibility(s,origin,ancestry){
 need(origin.status==='ALL79_EXACT_IPC_ORIGIN_AND_CURSOR_CONTINUITY_PASS'&&origin.pages_passed===79&&same(origin.page_identities,s.pages),'selected origin identities');
 need(origin.capture_selection_sha256===s.capture_selection.sha256&&origin.capture_results_sha256===s.capture_results.sha256&&same(origin.ancestry_report,s.ancestry_report),'origin capture/report links');
 need(ancestry.pages_completed===79&&ancestry.expected_pages===79&&ancestry.failure===null&&ancestry.capture_selection_sha256===s.capture_selection.sha256&&ancestry.baseline_fetch_sha256===s.scope.baseline_fetch.sha256&&ancestry.start_cursor===s.initial_cursor&&ancestry.last_valid_hash===s.tail.hash,'ancestry scope/selector links');
}
export function decodeCapturedPage(compressed,row){
 need(Buffer.isBuffer(compressed)&&compressed.length===row.gzip.bytes&&sha(compressed)===row.gzip.sha256,'raw gzip identity');
 const raw=zlib.gunzipSync(compressed);need(raw.length===row.decoded_bytes&&sha(raw)===row.decoded_sha256,'raw decoded identity');const page=strictJson(raw);
 closed(page,['removedChainBlockHashes','addedChainBlockHashes','chainBlockAcceptedTransactions']);need(Array.isArray(page.removedChainBlockHashes)&&page.removedChainBlockHashes.length===0&&Array.isArray(page.addedChainBlockHashes)&&Array.isArray(page.chainBlockAcceptedTransactions)&&page.addedChainBlockHashes.length===row.groups&&page.chainBlockAcceptedTransactions.length===row.groups&&row.groups>0,'complete nonremoved raw page');
 const line=JSON.stringify({id:row.call,ok:true,params:{addedChainBlockHashes:page.addedChainBlockHashes,removedChainBlockHashes:page.removedChainBlockHashes,chainBlockAcceptedTransactions:page.chainBlockAcceptedTransactions}});
 need(Buffer.byteLength(line)===row.ipc_bytes&&sha(line)===row.ipc_sha256,'exact captured IPC origin');
 let cursor=row.request.startHash;const seen=new Set([cursor]);for(let i=0;i<page.chainBlockAcceptedTransactions.length;i++){
  const group=page.chainBlockAcceptedTransactions[i];closed(group,['chainBlockHeader','acceptedTransactions']);need(Array.isArray(group.acceptedTransactions),'complete raw accepted list');
  const hash=hex(page.addedChainBlockHashes[i],32);need(group.chainBlockHeader?.hash===hash&&!seen.has(hash),'raw header identity/cycle');seen.add(hash);
  const header=plainHeader(group.chainBlockHeader);need(header.parentsByLevel[0]?.[0]===cursor,'strict first-parent route');cursor=hash;
 }
 need(cursor===row.last_hash,'captured last cursor');return page;
}
export function verifyLiveTail(k,block,tail){
 validateHeader(k,block.header,tail.hash);need(block.verboseData?.isChainBlock===true&&same(plainHeader(block.header),tail.header),'fresh live selected tail');
}
// Pure state machine, also exercised by synthetic controls. It cannot authorize KAS or return page bytes.
export class ReplayGate{
 constructor(selected){this.selected=selected;this.served=0;this.active=true;this.tailChecked=false;this.liveTailReturned=false;}
 disable(){this.active=false;}
 reject(message){this.disable();throw new Incomplete('CACHE_STALE',message);}
 beforeNonFull(){if(this.active&&this.served>0&&(this.served!==79||!this.liveTailReturned))this.reject('raw suffix requires complete primary live tail continuation');}
 beforeFull(params){
  if(!this.active)return null;try{closed(params,['startHash','dataVerbosityLevel','minConfirmationCount']);}catch{this.reject('closed raw Full20 request');}if(params.dataVerbosityLevel!=='Full'||params.minConfirmationCount!==20)this.reject('raw Full20 only');
  if(this.served<79){const row=this.selected.pages[this.served];if(!same(params,row.request))this.reject('raw cursor gap/overlap/wrong scope');return row;}
  if(!this.liveTailReturned&&params.startHash!==this.selected.tail.hash)this.reject('primary live continuation must begin at exact retained tail');return null;
 }
 markServed(){need(this.active&&this.tailChecked&&this.served<79,'fresh chain tail required before raw serve');this.served++;}
 markLiveReturned(params){if(this.active&&this.served===79&&!this.liveTailReturned){need(params.startHash===this.selected.tail.hash,'live tail return cursor');this.liveTailReturned=true;}}
 assertResult(value){try{
  need(value?.coverage?.complete===true&&value.coverage.frontier_seen===true&&value.coverage.end_cursor===value.coverage.frontier?.hash,'original complete fixed coverage required');
  need(value.network_id==='testnet-10'&&value.selection_file_sha256===this.selected.scope.selection.sha256&&value.descriptor_file_sha256===this.selected.scope.descriptor.sha256,'same result scope');
  if(!this.active){need(value.cache_reuse===undefined&&value.cache_fallback?.full_acquisition===true&&FALLBACKS.includes(value.cache_fallback.category),'disabled raw source requires ordinary full fallback');return;}
  need(this.served===79&&this.tailChecked&&this.liveTailReturned,'all79 and successful primary live Full required');
  need(same(value.cache_reuse?.baseline_fetch,this.selected.scope.baseline_fetch)&&same(value.cache_reuse?.runtime_sources,this.selected.scope.runtime_source)&&same(value.cache_reuse?.admission,this.selected.scope.cache_admission)&&same(value.cache_reuse?.baseline_cache,this.selected.scope.baseline_cache)&&value.cache_reuse?.base_pages===217,'old admitted prefix authority unchanged');
  need(value.coverage.frontier.hash!==this.selected.tail.hash&&integer(value.coverage.frontier.blueScore)>integer(this.selected.tail.header.blueScore),'actual returned fixed frontier strictly beyond retained tail');
 }catch(error){this.disable();throw error;}}
 summary(){return {scope:'local-transport-response-replay-only',financial_cache_authority:false,selector:CAPTURE_SELECTOR_ROW,active:this.active,raw_pages_served:this.served,fresh_tail_checked:this.tailChecked,primary_live_tail_full_returned:this.liveTailReturned};}
}
export function createRawResponseReplay(k,liveRpc,scope){
 const selected=validateManifest(strictJson(guardedRead(CAPTURE_SELECTOR_ROW.path,CAPTURE_SELECTOR_ROW.sha256)),scope);
 // The frozen eligibility reports bind origin and structural ancestry; acceptance still comes from original validators.
 const origin=strictJson(guardedRead(selected.origin_report.path,selected.origin_report.sha256)),ancestry=strictJson(guardedRead(selected.ancestry_report.path,selected.ancestry_report.sha256));
 validateEligibility(selected,origin,ancestry);
 const gate=new ReplayGate(selected),rpc={};let busy=false;
 async function checkLiveTail(){
  let block;try{block=(await liveRpc.getBlock({hash:selected.tail.hash,includeTransactions:false})).block;}catch(error){gate.disable();throw error;}
  try{verifyLiveTail(k,block,selected.tail);}catch{gate.reject('stale or unverifiable live selected tail');}gate.tailChecked=true;
 }
 for(const method of METHODS)rpc[method]=async(params={})=>{
  if(busy)gate.reject('raw read-only singleflight');busy=true;try{
  if(method!=='getVirtualChainFromBlockV2'){gate.beforeNonFull();return await liveRpc[method](params);}
  let row;try{row=gate.beforeFull(params);}catch(error){gate.disable();throw error;}
  if(row){if(!gate.tailChecked)await checkLiveTail();try{const page=decodeCapturedPage(guardedRead(row.gzip.path,row.gzip.sha256),row);gate.markServed();return page;}catch{gate.reject('selected raw response unavailable or ineligible');}}
  const value=await liveRpc[method](params);gate.markLiveReturned(params);return value;
  }finally{busy=false;}
 };
 return {rpc,disable:()=>gate.disable(),assertResult:value=>gate.assertResult(value),summary:()=>gate.summary()};
}
