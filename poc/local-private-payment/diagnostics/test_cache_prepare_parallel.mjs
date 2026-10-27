// Pure differential controls only. A guarded caller supplies source bytes on stdin.
// No real helper invocation, filesystem copy, benchmark, RPC or financial action.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const envelope=JSON.parse(fs.readFileSync(0,'utf8'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
for(const key of ['serial','parallel','json'])assert.equal(sha(envelope[key]),envelope.pins[key]);
assert.equal(envelope.pins.serial,'3a42869c445b3af7f74d37e71614041402ae554399cb279823a9966cf9800070');
assert.equal(envelope.pins.json,'59e7b579ddd3a62e5af404b38051376044e3ae1e26c25bdb6e6c6cfd969da1f7');
const strip=s=>s.replace(/^import .*;\r?\n/gm,'').replace(/^export /gm,'');
const json=Function('crypto',strip(envelope.json)+'\nreturn {canonical,strictJson};')(crypto);
const need=(ok,category,message)=>{if(!ok){const e=new Error(message??category);e.category=category;throw e;}};
function segment(start,end){
 assert.equal(envelope.serial.split(start).length,2);assert.equal(envelope.serial.split(end).length,2);
 return envelope.serial.slice(envelope.serial.indexOf(start),envelope.serial.indexOf(end));
}
const prefixData=Function('need',strip(segment('export function prefixData(', 'export function prepareBase('))+'\nreturn prefixData;')(need);
const serialBody=strip(segment('export function prepareBase(', 'export function verifyCopied('));
const SRC='/synthetic/source',OUT='/synthetic/output',HELPER='/var/tmp/kpi-root-guard-helper-09.py';
const helperCode="import runpy,sys;sys.stdout.buffer.write(runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](sys.argv[1],sys.argv[2] or None))";
const clone=v=>structuredClone(v),reports=[];
function fixture(){
 const input=new Map(),primary=[],post=[];
 function add(kind,index,rows){
  const tag=kind+index,data={removedChainBlockHashes:[],addedChainBlockHashes:[tag+'a',tag+'b',tag+'c'],
   chainBlockAcceptedTransactions:Array.from({length:3},(_,g)=>({acceptedTransactions:Array.from({length:index+g+1},(_,t)=>({id:tag+'-'+g+'-'+t}))}))};
  const raw=Buffer.from(JSON.stringify(data)+'\n'),gzip=zlib.gzipSync(raw,{level:6});
  const row={path:kind+'/'+index+'.gz',gzip_sha256:sha(gzip),gzip_bytes:gzip.length,decoded_sha256:sha(raw),decoded_bytes:raw.length,
   request:{startHash:tag,minConfirmationCount:20},encoding:'synthetic'};
  input.set(path.join(SRC,row.path),gzip);rows.push(row);
 }
 for(let i=0;i<9;i++)add('primary',i,primary);for(let i=0;i<3;i++)add('post',i,post);
 const tx=(id,page,prior)=>({transaction:{id,inputs:prior?[{previousOutpoint:{transactionId:prior,index:0}}]:[]},source_page_index:page,source_group_index:0,source_transaction_index:0});
 return {input,info:{base:{pages:primary,coverage:{frontier:{hash:'primary8b'},accepted_transaction_rows_scanned:400},
  current_view:{post_query_delta:{pages:post,frontier:{hash:'post2b'}}},transactions:[tx('founder',0),tx('next',5,'founder'),tx('last',10,'next')]}},args:{'baseline-bundle-directory':SRC}};
}
function harness(f,{failIndex=null,failAll=false,stringStdout=false,helperExists=true,collision=false}={}){
 const writes=new Map(),started=[],completed=[],stats={active:0,max:0};
 if(collision)writes.set(path.join(OUT,'cached/00000.json.gz'),Buffer.from('existing'));
 const fakeFs={existsSync:p=>p===HELPER&&helperExists,mkdirSync:()=>{},writeFileSync:(p,b,o)=>{
  assert.deepEqual(o,{flag:'wx',mode:0o600});if(writes.has(p))throw Object.assign(new Error('EEXIST'),{code:'EEXIST'});writes.set(p,Buffer.from(b));
 }};
 const read=p=>{assert(f.input.has(p),'synthetic source missing');return Buffer.from(f.input.get(p));};
 const execFile=(file,args,options,callback)=>{
  assert.equal(file,'/usr/bin/python3');assert.equal(args[0],'-B');assert.equal(args[1],'-c');assert.equal(args[2],helperCode);
  assert.deepEqual(options,{env:{PATH:'/usr/bin:/bin'},maxBuffer:512*1024*1024,encoding:'buffer'});
  const index=started.length;started.push({path:args[3],expected:args[4]});stats.active++;stats.max=Math.max(stats.max,stats.active);
  const delay=failIndex!==null?(index===failIndex?1:25):30-(index%6)*4;
  setTimeout(()=>{stats.active--;completed.push(index);
   if(failAll||index===failIndex)callback(new Error('DO_NOT_LEAK_PRIVATE_FILENAME'),Buffer.alloc(0));
   else callback(null,stringStdout?'not a Buffer':read(args[3]));
  },delay);
 };
 const names=['fs','path','zlib','need','sha','pointKey','checkedPath','canonical','strictJson','prefixData'];
 const values=[fakeFs,path,zlib,need,sha,p=>p.transactionId+':'+p.index,p=>path.resolve(p),json.canonical,json.strictJson,prefixData];
 const serial=Function(...names,'guardedRead',serialBody+'\nreturn prepareBase;')(...values,read);
 const parallel=Function(...names,'execFile',strip(envelope.parallel)+'\nreturn {prepareBaseParallel,readOpaque,PREPARE_GUARD_CONCURRENCY};')(...values,execFile);
 return {serial,parallel,writes,started,completed,stats};
}
async function equivalent(name,mutate=()=>{},output=OUT){
 const f=fixture();mutate(f);const before=clone(f.info),a=harness(f),b=harness(f);
 const old=a.serial(f.info,f.args,output),current=await b.parallel.prepareBaseParallel(f.info,f.args,output);
 assert.deepEqual(current,old);assert.equal(current.base,f.info.base);assert.equal(current.frontier,f.info.base.current_view.post_query_delta.frontier);
 assert.equal(current.pages[0].request,f.info.base.pages[0].request);assert.deepEqual(f.info,before);
 const sorted=m=>[...m].sort(([p],[q])=>p.localeCompare(q));
 assert.deepEqual(sorted(b.writes),sorted(a.writes));assert.equal(b.stats.active,0);assert.equal(b.stats.max,6);
 assert(b.completed.some((x,i)=>x!==i),'completion order must differ from page order');assert.equal(b.started.length,12);
 reports.push({name,status:'PASS',mockedReads:12,maxInFlight:b.stats.max});
}
async function rejection(name,mutate=()=>{},options={}){
 const f=fixture();mutate(f);const a=harness(f,options),b=harness(f,options);let old,current;
 try{a.serial(f.info,f.args,OUT);}catch(e){old=e;}try{await b.parallel.prepareBaseParallel(f.info,f.args,OUT);}catch(e){current=e;}
 assert(old&&current,'both paths must reject');assert.equal(current.message,old.message);assert.equal(b.stats.active,0);
 const size=b.writes.size;await new Promise(r=>setTimeout(r,35));assert.equal(b.writes.size,size,'no post-return background writes');
 reports.push({name,status:'PASS',bothRejected:true,allStartedSettled:true});
}
await equivalent('full bytes/records/fingerprint/Map/reference identities and forced out-of-order completion');
await equivalent('no output root returns identical data without copies',()=>{},null);
await equivalent('non-tail primary stays opaque',f=>{const r=f.info.base.pages[0],b=Buffer.from('opaque non-gzip primary');f.input.set(path.join(SRC,r.path),b);r.gzip_sha256=sha(b);r.gzip_bytes=b.length;r.decoded_sha256='not-decoded';});
await rejection('gzip checksum mismatch',f=>f.info.base.pages[0].gzip_sha256='0'.repeat(64));
await rejection('primary tail decoded checksum mismatch',f=>f.info.base.pages[8].decoded_sha256='0'.repeat(64));
await rejection('non-tail post decoded checksum mismatch',f=>f.info.base.current_view.post_query_delta.pages[0].decoded_sha256='0'.repeat(64));
await rejection('invalid gzip primary tail',f=>{const r=f.info.base.pages[8],b=Buffer.from('not gzip');f.input.set(path.join(SRC,r.path),b);r.gzip_sha256=sha(b);});
function changeTail(f,change){const r=f.info.base.pages[8],p=path.join(SRC,r.path),data=JSON.parse(zlib.gunzipSync(f.input.get(p)));change(data);
 const raw=Buffer.from(JSON.stringify(data)+'\n'),gzip=zlib.gzipSync(raw,{level:6});f.input.set(p,gzip);r.gzip_sha256=sha(gzip);r.decoded_sha256=sha(raw);}
await rejection('removed chain rows reject',f=>changeTail(f,d=>d.removedChainBlockHashes.push('removed')));
await rejection('hash/group count mismatch rejects',f=>changeTail(f,d=>d.chainBlockAcceptedTransactions.pop()));
await rejection('missing primary tail boundary',f=>f.info.base.coverage.frontier.hash='absent');
await rejection('missing post tail boundary',f=>f.info.base.current_view.post_query_delta.frontier.hash='absent');
await rejection('absolute source path',f=>f.info.base.pages[0].path='/elsewhere');
await rejection('source traversal',f=>f.info.base.pages[0].path='../elsewhere');
await rejection('exclusive output collision',()=>{},{collision:true});
{
 const f=fixture(),h=harness(f,{failIndex:0});let error;
 try{await h.parallel.prepareBaseParallel(f.info,f.args,OUT);}catch(e){error=e;}
 assert.equal(error?.message,'selected public read refused');assert.equal(h.started.length,6);assert.equal(h.stats.active,0);
 const count=h.writes.size;await new Promise(r=>setTimeout(r,35));assert.equal(h.writes.size,count);
 reports.push({name:'first read failure stops queue and settles every started helper',status:'PASS',started:6,maxInFlight:h.stats.max,activeAfterReturn:0});
}
for(const [name,options]of [['non-Buffer stdout rejects',{stringStdout:true}],['helper error masks private diagnostic',{failAll:true}],['missing helper has no fallback',{helperExists:false}]]){
 const h=harness(fixture(),options);await assert.rejects(h.parallel.readOpaque('/synthetic/source/primary/0.gz','known'),{message:'selected public read refused'});
 assert.equal(h.stats.active,0);reports.push({name,status:'PASS'});
}
const empty=fixture();empty.info.base.pages=[];empty.info.base.current_view.post_query_delta.pages=[];
const a=harness(empty),b=harness(empty);assert.throws(()=>a.serial(empty.info,empty.args,OUT));await assert.rejects(b.parallel.prepareBaseParallel(empty.info,empty.args,OUT));assert.equal(b.started.length,0);
reports.push({name:'empty prefix rejects without reader calls',status:'PASS'});
process.stdout.write(JSON.stringify({schema:'cache-prepare-parallel-pure-controls/v1',status:'PASS',controls:reports.length,sourcePins:envelope.pins,reports,
 scope:'guarded outer source admission, then test-only source clones and mocked opaque reader/copy environment; actual old canonical/strictJson/prefixData; no prototype guard invocation or throughput claim',
 prototypeHelperInvocations:0,realFilesystemCopies:0,rpcCalls:0,benchmarkExecuted:false})+'\n');
