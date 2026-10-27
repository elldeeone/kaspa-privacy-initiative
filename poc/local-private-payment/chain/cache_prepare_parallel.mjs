// Prospective pre-connect preparation only; old cache admission remains authoritative.
// Six independent invocations of the unchanged helper09, never a guard override.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {execFile} from 'node:child_process';
import {need,sha,pointKey} from './wire.mjs';
import {checkedPath,canonical,strictJson} from './selection.mjs';
import {prefixData} from './cache.mjs';

export const PREPARE_GUARD_CONCURRENCY=6;
const HELPER='/var/tmp/kpi-root-guard-helper-09.py';

function readOpaque(file,expected){
 if(!fs.existsSync(HELPER))return Promise.reject(new Error('selected public read refused'));
 const args=['-B','-c',"import runpy,sys;sys.stdout.buffer.write(runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](sys.argv[1],sys.argv[2] or None))",file,expected??''];
 return new Promise((resolve,reject)=>{
  execFile('/usr/bin/python3',args,{env:{PATH:'/usr/bin:/bin'},maxBuffer:512*1024*1024,encoding:'buffer'},(error,stdout)=>{
   // Preserve the old public.mjs masking; helper errors may contain private paths.
   if(error||!Buffer.isBuffer(stdout))reject(new Error('selected public read refused'));
   else resolve(stdout);
  });
 });
}

export async function prepareBaseParallel(info,a,outputRoot=null){
 const b=info.base,sourceRoot=checkedPath(a['baseline-bundle-directory']),pages=[];let postRows=0;
 const post=b.current_view.post_query_delta;
 const segments=[{rows:b.pages,target:b.coverage.frontier.hash,post:false}, {rows:post.pages,target:post.frontier.hash,post:true}];
 // Fixed flattened indices preserve the serial page order even when reads finish out of order.
 const jobs=[];for(const segment of segments)for(let i=0;i<segment.rows.length;i++)jobs.push({segment,i,old:segment.rows[i],index:jobs.length});
 const counts=new Array(jobs.length).fill(0);let next=0,firstError=null;
 async function worker(){
  while(firstError===null&&next<jobs.length){
   const {segment,i,old,index}=jobs[next++];
   try{
    need(!path.isAbsolute(old.path)&&!old.path.split('/').includes('..'),'CACHE_PREFIX','relative source page');
    const source=checkedPath(path.join(sourceRoot,old.path));need(source.startsWith(sourceRoot+path.sep),'CACHE_PREFIX','bounded source');
    let compressed=await readOpaque(source,old.gzip_sha256),record={...old,path:`cached/${String(index).padStart(5,'0')}.json.gz`};need(sha(compressed)===old.gzip_sha256,'CACHE_PREFIX','source gzip bytes');
    if(i===segment.rows.length-1||segment.post){
     const raw=zlib.gunzipSync(compressed);need(sha(raw)===old.decoded_sha256,'CACHE_PREFIX','source decoded bytes');let data=strictJson(raw);
     if(i===segment.rows.length-1){data=prefixData(data,segment.target);const changed=Buffer.from(canonical(data)+'\n');compressed=zlib.gzipSync(changed,{level:6});record={...record,decoded_sha256:sha(changed),decoded_bytes:changed.length,gzip_sha256:sha(compressed),gzip_bytes:compressed.length};}
     if(segment.post)counts[index]=data.chainBlockAcceptedTransactions.reduce((n,g)=>n+g.acceptedTransactions.length,0);
    }
    if(outputRoot){const target=path.join(outputRoot,record.path);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});fs.writeFileSync(target,compressed,{flag:'wx',mode:0o600});}
    pages[index]=record;
   }catch(error){if(firstError===null)firstError=error instanceof Error?error:new Error(String(error));}
  }
 }
 // On failure, stop scheduling and settle every started helper before reporting it.
 await Promise.all(Array.from({length:Math.min(PREPARE_GUARD_CONCURRENCY,jobs.length)},()=>worker()));
 if(firstError!==null)throw firstError;
 for(const count of counts)postRows+=count;
 need(pages.length>0,'CACHE_PREFIX','nonempty admitted complete prefix');
 const frontier=post.frontier,accepted=b.coverage.accepted_transaction_rows_scanned+postRows;
 const edges=new Map();for(let index=1;index<b.transactions.length;index++){
  const r=b.transactions[index],input=r.transaction.inputs[0].previousOutpoint,key=pointKey(input);
  edges.set(key,[{page:r.source_page_index,group:r.source_group_index,transaction:r.source_transaction_index,id:r.transaction.id,input_index:0}]);
 }
 const g=b.transactions[0],founding={page:g.source_page_index,group:g.source_group_index,transaction:g.source_transaction_index,id:g.transaction.id};
 return {pages,frontier,accepted,edges,founding,fingerprint:sha(canonical({pages,frontier,accepted})),base:b};
}
