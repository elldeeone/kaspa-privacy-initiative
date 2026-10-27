// NONLIVE: guarded source envelope, tiny public fixtures, fake RPC/SDK only.
// No project module imports, live network, Original, profile or financial acceptance.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {execFile,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const input=JSON.parse(fs.readFileSync(0,'utf8')),sources=input.sources,reports=[];
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const pins={
 shared:'7cc9d5a6e53114c086290bce50737b921dac63a8a3831abc77ac58e8b4bf563c',
 fetch:'f51957b0aa337ea8ccec80ae16a3ec82002157c16653796fefb3d58f22cdc078',
 confirm:'1c9ea1a8f262b00afbe24b4e88be4f1f63f55746a5a73313755f376715fdcaf3',
 caller:'dc8d13bab58e8792f4dcf7a437809e86fb650a2142de1c4ede854360cca0417f',
 parallel:'e63e74c320e9968ed78b34f0227c6e9ae27ec11bd955604fbfdc5af85dccfcc5',
 cache:'3a42869c445b3af7f74d37e71614041402ae554399cb279823a9966cf9800070',
 json:'59e7b579ddd3a62e5af404b38051376044e3ae1e26c25bdb6e6c6cfd969da1f7',
 selection:'4ee1531a25a34c3b511b36bbc4895221322cfcdd17e3b85d29deadbeb0328a1e',
 public:'1ca8c575ca7111a128f7fa1e64cfa9313b88e5f4b438909c0f88ff3b3221a5ad',
 acquire:'f5924a0242b144970dd52f7339401311ac7fb26ad57d96235f57469b295fd6f3',
 verify:'16d4fd910380e44b78d60dfd7300ab0aec5ddfaebf54384a58197e92a78be8bd'};
for(const [key,pin]of Object.entries(pins))assert.equal(hash(sources[key]),pin,'guarded exact source: '+key);
const strip=s=>s.replace(/^import .*;\r?\n/gm,'').replace(/^export /gm,'');
const segment=(s,a,b)=>{assert.equal(s.split(a).length,2);if(b)assert.equal(s.split(b).length,2);return s.slice(s.indexOf(a),b?s.indexOf(b):undefined);};
const sourceClone=(s,bindings,returns,url)=>Function(...Object.keys(bindings),strip(s).replaceAll('import.meta.url',JSON.stringify(url??'file:///pure/module.mjs'))+'\nreturn {'+returns+'};')(...Object.values(bindings));
const json=sourceClone(sources.json,{crypto},'canonical,strictJson');
const need=(ok,category,message)=>{if(!ok)throw Object.assign(Error(message??category),{category});};
const hx=(s,n)=>{need(typeof s==='string'&&s.length===2*n&&/^[0-9a-f]+$/.test(s),'HEX');return s;};
const pointKey=p=>p.transactionId+':'+p.index,integer=BigInt;
const H=n=>n.toString(16).padStart(64,'0'),SCRIPT='synthetic-script',HELPER='/var/tmp/kpi-root-guard-helper-09.py';
const BASE='/pure/local-private-payment',SRC='/pure/source',OUT='/pure/output';
const outer={path:'/pure/outer.json',sha256:'a'.repeat(64)},args={'runtime-source':'/pure/runtime','runtime-source-sha256':'b'.repeat(64),'cache-admission':'/pure/admission','cache-admission-sha256':'c'.repeat(64),'baseline-bundle-directory':SRC,trusted:true};
const descriptor={birth_start_hash:H(1),founding_outpoint:{transactionId:H(11),index:0},initial_redeem_hex:'00'.repeat(114)+'aa'};
const names=['ingress/readonly_borsh_worker.mjs','diagnostics/borsh_stage_worker.mjs','chain/readonly_borsh_observed_retry_strict_rpc.mjs','chain/fetch_borsh_shared_prefix.mjs','ingress/BORSH-RPC-SDK-01.json','chain/cache_prepare_parallel.mjs','chain/acquire_cached_shared.mjs'];
const selectedSources=names.map((name,i)=>({path:BASE+'/'+name,sha256:hash('synthetic selected public source '+i)})).sort((a,b)=>a.path.localeCompare(b.path));
const pristineManifest={schema:'kpxa-public-offline-pool-selection/v1',parent_runtime:{path:args['runtime-source'],sha256:args['runtime-source-sha256']},parent_admission:{path:args['cache-admission'],sha256:args['cache-admission-sha256']},source_members:[...selectedSources,{path:BASE+'/chain/confirm_pool_borsh_shared_prefix.py',sha256:hash('synthetic confirm')}]};
function memoryFs(){
 const entries=new Map(),fds=new Map();let ino=100,nextFd=10,failWrite=null,failChmod=false;
 const stat=e=>({dev:1,ino:e.ino,size:e.bytes?.length??0,nlink:e.nlink,mode:e.mode,mtimeNs:1,ctimeNs:1,isFile:()=>e.kind==='file',isDirectory:()=>e.kind==='dir',isSymbolicLink:()=>e.kind==='symlink'});
 const get=p=>{const e=entries.get(p);if(!e)throw Object.assign(Error('missing synthetic public file'),{code:'ENOENT'});return e;};
 const api={constants:fs.constants,existsSync:p=>p===HELPER||entries.has(p),lstatSync:p=>stat(get(p)),
 mkdirSync(p,o={}){if(entries.has(p)){if(o.recursive&&get(p).kind==='dir')return;throw Error('EEXIST');}if(o.recursive&&p!=='/')api.mkdirSync(path.dirname(p),{recursive:true,mode:o.mode});entries.set(p,{kind:'dir',mode:o.mode??0o700,nlink:2,ino:ino++});},
 writeFileSync(p,b,o={}){if(typeof p==='number'){get(fds.get(p)).bytes=Buffer.from(b);return;}if(failWrite?.(p))throw Object.assign(Error('synthetic write refusal'),{code:'ENOSPC'});if(o.flag==='wx'&&entries.has(p))throw Error('EEXIST');entries.set(p,{kind:'file',bytes:Buffer.from(b),mode:o.mode??0o600,nlink:1,ino:ino++});},
 chmodSync(p,m){if(failChmod)throw Object.assign(Error('synthetic finalization refusal'),{code:'EACCES'});get(p).mode=m;},
 openSync(p,flags,mode){if(flags==='wx'){api.writeFileSync(p,Buffer.alloc(0),{flag:'wx',mode});}else if(get(p).kind==='symlink')throw Error('NOFOLLOW');const fd=nextFd++;fds.set(fd,p);return fd;},
 fstatSync(fd,o){const e=get(fds.get(fd)),s=stat(e);if(o?.bigint)for(const k of ['dev','ino','size','nlink','mtimeNs','ctimeNs'])s[k]=BigInt(s[k]);return s;},
 readFileSync:fd=>Buffer.from(get(fds.get(fd)).bytes),closeSync:fd=>fds.delete(fd),fsyncSync:()=>{}};
 entries.set('/',{kind:'dir',mode:0o700,nlink:2,ino:ino++});
 return{api,entries,get,setWriteFailure:f=>{failWrite=f;},setChmodFailure:()=>{failChmod=true;}};
}
function checkedApi(f){
 return sourceClone(segment(sources.selection,'export function checkedPath(','export function readPublic('),{fs:f,path,need},'checkedPath').checkedPath;
}
function publicApi(f){
 const offlineFs={...f,existsSync:p=>p===HELPER?false:f.existsSync(p)};
 return sourceClone(sources.public,{fs:offlineFs,crypto,spawnSync:()=>{throw Error('real helper forbidden in virtual controls');}},'guardedRead').guardedRead;
}
function cacheApi(f,checkedPath,guardedRead){
 const prefixData=sourceClone(segment(sources.cache,'export function prefixData(','export function prepareBase('),{need},'prefixData').prefixData;
 const common={fs:f,path,zlib,need,sha:hash,pointKey,checkedPath,guardedRead,...json,prefixData};
 const serial=sourceClone(segment(sources.cache,'export function prepareBase(','export function verifyCopied('),common,'prepareBase').prepareBase;
 const verifyCopied=sourceClone(segment(sources.cache,'export function verifyCopied('),common,'verifyCopied').verifyCopied;
 const pageData=sourceClone(segment(sources.acquire,'export function pageData(','export async function scan('),common,'pageData').pageData;
 const save=sourceClone(segment(sources.acquire,'export function save(','export async function identity('),{fs:f,path,stringify:json.canonical,sha:hash},'save').save;
 return{...common,serial,verifyCopied,pageData,save};
}
function addPage(f,root,relative,from,to,txId,prior){
 const data={removedChainBlockHashes:[],addedChainBlockHashes:[to],chainBlockAcceptedTransactions:[{chainBlockHeader:{hash:to,parentsByLevel:[[from]],blueScore:'10'},acceptedTransactions:[{id:txId,inputs:prior?[{previousOutpoint:{transactionId:prior,index:0},signatureScript:'aa'}]:[]}]}]};
 const raw=Buffer.from(json.canonical(data)+'\n'),bytes=zlib.gzipSync(raw,{level:6});f.mkdirSync(path.dirname(path.join(root,relative)),{recursive:true,mode:0o700});f.writeFileSync(path.join(root,relative),bytes,{flag:'wx',mode:0o600});
 return{path:relative,request:{startHash:from,dataVerbosityLevel:'Full',minConfirmationCount:20},gzip_sha256:hash(bytes),gzip_bytes:bytes.length,decoded_sha256:hash(raw),decoded_bytes:raw.length,encoding:'public synthetic page'};
}
function fixture(m){
 m.api.mkdirSync(SRC,{recursive:true,mode:0o700});
 const primary=addPage(m.api,SRC,'primary/0.gz',H(1),H(2),H(11)),post=addPage(m.api,SRC,'post/0.gz',H(2),H(3),H(12),H(11));
 const tx=(id,page,prior)=>({transaction:{id,inputs:prior?[{previousOutpoint:{transactionId:prior,index:0}}]:[]},source_page_index:page,source_group_index:0,source_transaction_index:0});
 return{base:{genesis_hash_hex:H(99),pages:[primary],coverage:{frontier:{hash:H(2)},anchor_header:{hash:H(1)},accepted_transaction_rows_scanned:1},current_view:{post_query_delta:{pages:[post],frontier:{hash:H(3),blueScore:'10'}}},transactions:[tx(H(11),0),tx(H(12),1,H(11))]},baseRow:{path:'/pure/base-fetch',sha256:'d'.repeat(64)},admissionRow:pristineManifest.parent_admission,source:pristineManifest.parent_runtime};
}
function harness(options={}){
 const m=memoryFs(),f=m.api,checkedPath=checkedApi(f),guardedRead=publicApi(f),c=cacheApi(f,checkedPath,guardedRead),info=fixture(m);
 const h={m,f,c,info,manifest:structuredClone(pristineManifest),prepareCalls:0,connections:[],closed:[],saved:[],snapshots:[],current:null,prepared:null};
 const exec=(file,a,o,callback)=>{assert.equal(file,'/usr/bin/python3');assert.equal(a[3].startsWith(SRC+'/'),true);setImmediate(()=>{try{callback(null,guardedRead(a[3],a[4]));}catch(e){callback(e,Buffer.alloc(0));}});};
 const parallel=sourceClone(sources.parallel,{...c,fs:f,execFile:exec},'prepareBaseParallel').prepareBaseParallel;
 const prepare=async(...a)=>{h.prepareCalls++;const result=await parallel(...a);h.prepared=result;h.beforePrepared=structuredClone(result);h.beforeInfo=structuredClone(info);return result;};
 const boundary=rpc=>({header:{hash:options.empty?H(3):H(4),blueScore:'20'},sink:{blueScore:'100'},min_confirmation_count:20});
 const validateHeader=(_k,header,expected)=>assert.equal(header.hash,expected);
 const scan=async(_k,rpc,_d,_boundary,root)=>{
  const r=addPage(f,root,'pages/00000.json.gz',H(3),H(4),H(13),H(12));
  return{pages:options.missingDelta?[]:[r],edges:new Map([[pointKey({transactionId:H(12),index:0}),[{page:0,group:0,transaction:0,id:H(13),input_index:0}]]]),cursor:H(4),accepted_transactions_scanned:1};
 };
 const discover=(_k,_d,scanned,root)=>{
  for(const r of scanned.pages)c.pageData(root,r);
  if(!options.empty&&!options.missingDelta)assert.equal(scanned.edges.get(pointKey({transactionId:H(12),index:0}))[0].page,2);
  if(h.current?.fail){scanned.pages[0].request.contaminated=true;scanned.edges.values().next().value[0].id='contaminated';scanned.founding.page=900;throw Object.assign(Error('synthetic peer unavailable'),{category:'DATA_UNAVAILABLE'});}
  return{rows:[{transaction:{outputs:[{scriptPublicKey:SCRIPT}]}}],terminal_candidate:false};
 };
 const postQuery=async(_k,_rpc,_d,b,_found,root)=>{
  const pages=options.empty?[]:[addPage(f,root,'post-query/pages/00000.json.gz',b.header.hash,H(5),H(14))];
  return{pages,start_hash:b.header.hash,frontier:{hash:options.empty?H(3):H(5)},initial_sink:{blueScore:'100'},min_confirmation_count:20,completed:true};
 };
 const shared=sourceClone(sources.shared,{fs:f,path,...json,checkedPath,need,integer,script:()=>SCRIPT,validateHeader,SDK_PINS:{fixture:true},sha:hash,row:()=>{throw Error('unused baseline cache');},frontier:async(_k,rpc)=>boundary(rpc),scan,discover,currentView:async()=>({queries:[{fixture:'stable'}]}),postQuery},'fetchCachedOneShared').fetchCachedOneShared;
 const read=(file,pin)=>{if(file===outer.path){assert.equal(pin,outer.sha256);return json.canonical(h.manifest);}if(file==='/pure/profile')return'{}';if(file==='/pure/descriptor')return'{}';const row=selectedSources.find(r=>r.path===file);need(row&&row.sha256===pin,'ACQUISITION_SOURCE');return'pure selected source';};
 const connect=async(_k,url,_acq,journal)=>{
  const index=h.connections.length;h.connections.push(url);h.current={index,fail:options.failFirst&&index===0};
  c.save(journal,{synthetic_peer:index});
  return{rpc:{getBlock:async({hash})=>({block:{header:{hash},verboseData:{isChainBlock:true}}})},close:async()=>{h.closed.push(index);}};
 };
 const cached=async(...a)=>{if(options.fallback)throw Object.assign(Error('synthetic stale frontier'),{category:'CACHE_STALE'});return shared(...a);};
 const full=async(_k,_rpc,_p,_ps,_d,_ds,root)=>{
  const primary=addPage(f,root,'pages/00000.json.gz',H(1),H(4),H(11)),post=addPage(f,root,'post-query/pages/00000.json.gz',H(4),H(5),H(14));
  return{status:'FETCHED_PENDING_REPLAY',pages:[primary],current_view:{post_query_delta:{pages:[post],start_hash:H(4),frontier:{hash:H(5)},initial_sink:{blueScore:'100'},min_confirmation_count:20}},coverage:{frontier:{hash:H(4)},initial_sink:{blueScore:'100'},min_confirmation_count:20}};
 };
 const fetchText=sources.fetch.slice(0,sources.fetch.indexOf('\nif(process.argv[1]'));
 h.api=sourceClone(fetchText,{fs:f,path,fileURLToPath,connectReadOnlyBorsh:connect,publicAcquisitionDiagnostic:()=>null,DEFAULT_RPCS:[],fetchOne:full,loadSdk:()=>({}),need,stringify:json.canonical,checkedPath,readPublic:read,profile:()=>({financial_profile_sha256:'e'.repeat(64)}),descriptor:()=>structuredClone(descriptor),strictJson:json.strictJson,save:(p,v)=>{h.saved.push(p);return c.save(p,v);},cacheOptions:()=>{},admitted:()=>info,prepareBaseParallel:prepare,fetchCachedOneShared:cached},'execute,acquisitionSources','file://'+BASE+'/chain/fetch_borsh_shared_prefix.mjs');
 h.sdk={payToScriptHashScript:()=>({free(){}})};
 h.run=()=>h.api.execute('/pure/profile','1','/pure/descriptor','2',OUT,args,outer,['wss://one.example.invalid','wss://two.example.invalid'],h.sdk);
 h.shared=shared;
 h.verify=value=>{
  const retained=segment(sources.verify,'function retainedScan(','export function verify('),verify=segment(sources.verify,'export function verifyCached(','\nif(process.argv[1]');
  const inspect="function verify(rawP,ps,rawD,ds,rawBundle,root,k){const v=strictJson(rawBundle),b={header:v.coverage.frontier,sink:v.coverage.initial_sink,min_confirmation_count:v.coverage.min_confirmation_count};retainedScan(k,d,b,v.pages,root);const p=v.current_view.post_query_delta;retainedScan(k,{birth_start_hash:p.start_hash,founding_outpoint:{transactionId:'00'.repeat(32),index:0}},{header:p.frontier,sink:p.initial_sink,min_confirmation_count:p.min_confirmation_count},p.pages,root,false);return{status:'SYNTHETIC_PATH_CONSISTENCY_PASS'};}";
  const bindings={need,integer,hex:hx,point:x=>x,pointKey,plainHeader:x=>x,validateHeader,pageData:c.pageData,verifyCopied:c.verifyCopied,equal:(a,b)=>assert.deepEqual(a,b),...json,sha:hash,admitted:()=>info,prepareBase:c.serial,row:()=>{},d:descriptor};
  const fn=sourceClone('let REUSE=null;\n'+retained+strip(verify)+'\n'+inspect,bindings,'verifyCached').verifyCached;
  return fn('{}','1','{}','2',Buffer.from(json.canonical(value)),OUT,h.sdk,args);
 };
 return h;
}
const record=(id,name)=>reports.push({id,name,status:'PASS'});
const selectionBytes=h=>Buffer.from(h.m.get(OUT+'/INCOMPLETE.json').bytes);
const cachedSnapshot=h=>[...h.m.entries].filter(([p,e])=>p.startsWith(OUT+'/cached/')&&e.kind==='file').map(([p,e])=>({path:p,ino:e.ino,nlink:e.nlink,mode:e.mode,sha256:hash(e.bytes),bytes:e.bytes.length}));
const verifyPaths=(h,v)=>{for(const r of [...v.pages,...v.current_view.post_query_delta.pages])h.c.pageData(OUT,r);return h.verify(v);};

const two=harness({failFirst:true}),twoResult=await two.run();
assert.equal(twoResult.source.attempt,2);assert.equal(two.prepareCalls,1);assert.equal(two.connections.length,2);assert.equal(twoResult.attempts.length,1);
assert(two.m.entries.has(OUT+'/attempt-001/delta/pages/00000.json.gz'));assert(two.m.entries.has(OUT+'/attempt-001/INCOMPLETE.json'));
assert(two.m.entries.has(OUT+'/attempt-002/delta/pages/00000.json.gz'));assert(twoResult.pages.every(r=>!r.path.startsWith('attempt-001/')));
record('C01','one actual preparer invocation; failed first peer retains separate evidence; second succeeds');
assert.deepEqual(two.prepared,two.beforePrepared);assert.deepEqual(two.info,two.beforeInfo);
const snapshot=cachedSnapshot(two);assert.equal(snapshot.length,2);assert(snapshot.every(r=>r.mode===0o400&&r.nlink===1));
assert.equal(twoResult.cache_reuse.prefix_fingerprint,two.prepared.fingerprint);
record('C02','nested prepared state/provenance/fingerprint unchanged; virtual baseline has one ordinary copy');
assert.equal(verifyPaths(two,twoResult).status,'SYNTHETIC_PATH_CONSISTENCY_PASS');
assert.equal(twoResult.pages[0].path,'cached/00000.json.gz');assert.equal(twoResult.pages[2].path,'attempt-002/delta/pages/00000.json.gz');
assert.equal(twoResult.current_view.post_query_delta.pages[0].path,'attempt-002/post-query/pages/00000.json.gz');
record('C03','nonempty primary/post paths, locator offset and unchanged verifier prefix/export checks');

const empty=harness({empty:true}),emptyResult=await empty.run();assert.equal(emptyResult.pages.length,2);assert.equal(emptyResult.current_view.post_query_delta.pages.length,0);verifyPaths(empty,emptyResult);
const missing=harness({missingDelta:true}),missingResult=await missing.run();assert.throws(()=>missing.verify(missingResult));
record('C04','same-frontier empty delta/post passes; advanced frontier missing delta fails coverage');
const fallback=harness({fallback:true}),fallbackResult=await fallback.run();assert(fallbackResult.pages.every(r=>r.path.startsWith('attempt-001/full-fallback/')));assert(fallbackResult.current_view.post_query_delta.pages.every(r=>r.path.startsWith('attempt-001/full-fallback/')));assert(fallbackResult.pages.every(r=>!r.path.startsWith('cached/')));verifyPaths(fallback,fallbackResult);
record('C05','full fallback rebases both arrays exactly once and retains separate workspace');

const bad=harness();bad.info.base.pages[0].gzip_sha256='0'.repeat(64);const badResult=await bad.run();assert.equal(badResult.status,'INCOMPLETE');assert.equal(bad.connections.length,0);assert.deepEqual(badResult.attempts,[]);assert(badResult.local_preparation);assert(!bad.saved.some(p=>p.endsWith('/fetch.json')));
record('C06','bad admitted-source gzip checksum stops locally before any peer connection');
for(const finalize of [false,true]){
 const h=harness();if(finalize)h.m.setChmodFailure();else h.m.setWriteFailure(p=>p===OUT+'/cached/00001.json.gz');
 const result=await h.run();assert.equal(result.status,'INCOMPLETE');assert.equal(h.connections.length,0);assert.equal(h.prepareCalls,1);assert(cachedSnapshot(h).length>0);
 const first=selectionBytes(h);await assert.rejects(h.run(),e=>e.category==='OUTPUT_EXISTS');assert.deepEqual(selectionBytes(h),first);assert.equal(h.prepareCalls,1);
}
record('C07','copy/finalization refusal retains partial prefix and first global failure; reused output refused');
for(const invalid of ['../attempt-001','/attempt-001','.','cached','attempt-001/child']){
 await assert.rejects(two.shared(two.sdk,{}, {},'1',descriptor,'2',OUT,invalid,two.info,args,two.prepared));
}
const pathHarness=harness({empty:true});await pathHarness.run();pathHarness.m.entries.set(OUT+'/attempt-003',{kind:'symlink',mode:0o777,nlink:1,ino:900});
await assert.rejects(pathHarness.shared(pathHarness.sdk,{}, {},'1',descriptor,'2',OUT,'attempt-003',pathHarness.info,args,pathHarness.prepared));
const file=two.m.get(OUT+'/cached/00000.json.gz');file.nlink=2;assert.throws(()=>two.c.verifyCopied(OUT,two.prepared.pages));file.nlink=1;
record('C08','malformed/escaping attempt names, symlink paths and hardlinked public bytes rejected');

const tamper=Buffer.from(file.bytes);file.bytes=Buffer.from('changed shared gzip');assert.throws(()=>two.c.verifyCopied(OUT,two.prepared.pages));assert.throws(()=>two.verify(twoResult));file.bytes=tamper;
record('C09','changed shared gzip rejected by unchanged verifyCopied/export path');
const wrong=structuredClone(twoResult);wrong.cache_reuse.prefix_fingerprint='0'.repeat(64);assert.throws(()=>two.verify(wrong));
record('C10','unchanged verifier rejects wrong prefix fingerprint');
for(const mutate of [
 v=>v.pages.shift(),v=>v.pages[2].path='attempt-002/'+v.pages[2].path,
 v=>v.pages[2].path='../outside.gz',v=>v.current_view.post_query_delta.pages[0].path='attempt-002/'+v.current_view.post_query_delta.pages[0].path,
 v=>v.current_view.post_query_delta.pages[0].path='../outside.gz',v=>v.current_view.post_query_delta.pages=[]]){
 const changed=structuredClone(twoResult);mutate(changed);assert.throws(()=>two.verify(changed));
}
record('C11','missing/double-prefixed/escaping primary or post-query paths rejected');
for(const mutate of [
 m=>{m.source_members=m.source_members.filter(r=>!r.path.endsWith('/acquire_cached_shared.mjs'));},
 m=>{m.source_members.find(r=>r.path.endsWith('/acquire_cached_shared.mjs')).sha256='0'.repeat(64);}]){const h=harness();mutate(h.manifest);assert.throws(()=>h.api.acquisitionSources(outer,args));assert.equal(h.connections.length,0);}
const sidecar=JSON.parse(two.m.get(OUT+'/ACQUISITION-SOURCES.json').bytes);assert.equal(sidecar.source_members.length,7);assert.deepEqual(sidecar.source_members,selectedSources);assert.equal(sidecar.fetch.sha256,hash(two.m.get(OUT+'/fetch.json').bytes));
const python=[
'import ast,json,sys','from pathlib import Path','from types import SimpleNamespace',
'p=json.load(sys.stdin); tree=ast.parse(p["source"]); wanted={"acquisition_sources","verify_acquisition_sidecar"}',
'nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted or isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=="NETWORK_SOURCE_NAMES" for x in n.targets)]',
'def need(ok,*rest):\n if not ok: raise ValueError(rest)',
'def fields(v,ks,*rest): need(type(v)is dict and set(v)==set(ks))',
'def hx(v,n): need(type(v)is str and len(v)==2*n);return bytes.fromhex(v)',
'ns={"BASE":Path(p["base"]),"parse":json.loads,"need":need,"fields":fields,"hx":hx};exec(compile(ast.Module(body=nodes,type_ignores=[]),"<public-source-provenance>","exec"),ns)',
'm=p["manifest"];side=p["sidecar"];a=SimpleNamespace(pool_selection=Path(p["outer"]["path"]),pool_selection_sha256=p["outer"]["sha256"],runtime_source=Path(m["parent_runtime"]["path"]),runtime_source_sha256=m["parent_runtime"]["sha256"],cache_admission=Path(m["parent_admission"]["path"]),cache_admission_sha256=m["parent_admission"]["sha256"])',
'class Guard:\n def read(self,f,sha=None):\n  f=str(f)\n  if f==p["outer"]["path"]: need(sha==p["outer"]["sha256"]);return json.dumps(m).encode()\n  if f=="/pure/output/ACQUISITION-SOURCES.json":return json.dumps(side).encode()\n  row=next((r for r in m["source_members"] if r["path"]==f),None);need(row is not None and row["sha256"]==sha);return b"synthetic public source"',
'guard=Guard();selected=ns["acquisition_sources"](a,guard);need(selected==p["sources"]);ns["verify_acquisition_sidecar"](a,guard,Path("/pure/output"),p["fetch_sha"],selected)',
'for bad in ["source","fetch"]:\n side=json.loads(json.dumps(p["sidecar"]))\n if bad=="source": side["source_members"].pop()\n else: side["fetch"]["sha256"]="0"*64\n try:ns["verify_acquisition_sidecar"](a,guard,Path("/pure/output"),p["fetch_sha"],selected)\n except(ValueError,KeyError):pass\n else:raise AssertionError("changed sidecar accepted")',
'print(json.dumps({"status":"PASS","members":len(selected)}))'].join('\n');
const py=JSON.parse(execFileSync('/usr/bin/python3',['-B','-c',python],{input:JSON.stringify({source:sources.confirm,base:BASE,outer,manifest:pristineManifest,sidecar,sources:selectedSources,fetch_sha:sidecar.fetch.sha256}),encoding:'utf8',env:{PATH:'/usr/bin:/bin'}}));assert.equal(py.members,7);
record('C12','required shared helper and exact seven-member JS/Python source/fetch sidecar binding');

// One tiny real public ordinary-file preparation through the unchanged helper09.
// Source text was guarded by the outer caller; fixtures are new and public only.
const physicalRoot='/dev/shm/kpi-shared-prefix-controls-01-'+process.pid+'-'+Date.now();
fs.mkdirSync(physicalRoot,{mode:0o700});const realSource=path.join(physicalRoot,'source'),realOutput=path.join(physicalRoot,'output');
fs.mkdirSync(realSource,{mode:0o700});fs.mkdirSync(realOutput,{mode:0o700});
let realHelperCalls=0,realPrepareReaderCalls=0;
const realChecked=checkedApi(fs),readPublic=(p,pin)=>{realHelperCalls++;return execFileSync('/usr/bin/python3',['-B','-c',"import runpy,sys;sys.stdout.buffer.write(runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](sys.argv[1],sys.argv[2]))",p,pin],{env:{PATH:'/usr/bin:/bin'},maxBuffer:1024*1024});};
const realCache=cacheApi(fs,realChecked,readPublic),realInfo=structuredClone(two.info);
realInfo.base.pages=[addPage(fs,realSource,'primary/0.gz',H(1),H(2),H(11))];
realInfo.base.current_view.post_query_delta.pages=[addPage(fs,realSource,'post/0.gz',H(2),H(3),H(12),H(11))];
const realParallel=sourceClone(sources.parallel,{...realCache,fs,execFile:(...a)=>{realHelperCalls++;realPrepareReaderCalls++;return execFile(...a);}},'prepareBaseParallel').prepareBaseParallel;
let physical;
try{
 physical=await realParallel(realInfo,{...args,'baseline-bundle-directory':realSource},realOutput);
 for(const r of physical.pages){const p=path.join(realOutput,r.path);fs.chmodSync(p,0o400);const st=fs.lstatSync(p);assert(st.isFile()&&!st.isSymbolicLink());assert.equal(st.nlink,1);assert.equal(st.mode&0o777,0o400);assert.equal(hash(readPublic(p,r.gzip_sha256)),r.gzip_sha256);}
 assert.equal(realPrepareReaderCalls,2);assert.equal(fs.readdirSync(path.join(realOutput,'cached')).length,2);
 const serial=realCache.serial(realInfo,{...args,'baseline-bundle-directory':realSource});assert.equal(physical.fingerprint,serial.fingerprint);
}catch(error){process.stdout.write(JSON.stringify({status:'FAIL_PRESERVED',stage:'REAL_PUBLIC_HELPER_FIXTURE',virtualFamilies:reports,physicalRoot,prototypeHelperCalls:realHelperCalls,first_error_class:error.name})+'\n');throw error;}
assert.equal(reports.length,12);
process.stdout.write(JSON.stringify({schema:'shared-prefix-public-controls/v1',status:'PASS',families:reports,sourcePins:pins,
 virtual_scope:'exact source clones, actual path/hash/prefix verification, mocked public admission/RPC/SDK/discovery; no financial acceptance claim',
 physical_scope:'one unchanged e63 ordinary-file preparation with two tiny public pages through unchanged helper09; fingerprint matches unchanged serial preparation',
 physicalRoot,physicalPreparedPages:physical.pages.length,prototypeHelperCalls:realHelperCalls,realRpcCalls:0,originalJobs:0,profileMaterializations:0,launches:0})+'\n');
