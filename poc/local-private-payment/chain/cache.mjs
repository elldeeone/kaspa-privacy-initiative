// ADR0067: integrity of STATE-held selectors is a LOCAL controller assumption.
// A public receipt/boolean is not an external attestation. Untrusted callers use full SDK validation.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {guardedRead} from './public.mjs';
import {need,sha,SDK_PINS,pointKey} from './wire.mjs';
import {checkedPath,canonical,strictJson,readPublic,CHILD_DOMAIN} from './selection.mjs';
import {verify as fullVerify} from './verify_bundle.mjs';
const HERE=path.dirname(fileURLToPath(import.meta.url));
export const SOURCE57='29163ae54005653c12d6c9644c82a6de999a70be360d516f35099cbf8b08b4a3';
export const ROOT_HANDOFF='73ee6f11fed5864ea7d6b692ab8b01d9831eb018dd3e52a966e5e69fe4d85ba5';
export const SCOPE='trusted-controller-local-state-only';
export const cacheNames=['runtime-source','cache-admission','baseline-fetch','baseline-bundle-directory','baseline-cache'];
export function cacheOptions(argv){
 const a={};for(let i=0;i<argv.length;i++){
  if(argv[i]==='--trusted-local-cache'){need(!a.trusted,'CACHE_ARGUMENT','duplicate trust flag');a.trusted=true;continue;}
  const key=argv[i].slice(2);need(argv[i].startsWith('--')&&[...cacheNames,...cacheNames.filter(x=>x!=='baseline-bundle-directory').map(x=>x+'-sha256')].includes(key)&&argv[i+1]&&!a[key],'CACHE_ARGUMENT','closed cache arguments');a[key]=argv[++i];
 }return a;
}
export function cacheArgs(a){const out=[];for(const name of cacheNames){if(a[name]!==undefined){out.push('--'+name,a[name]);if(name!=='baseline-bundle-directory')out.push('--'+name+'-sha256',a[name+'-sha256']);}}if(a.trusted||a['trusted-local-cache'])out.push('--trusted-local-cache');return out;}
export function row(a,name){return {path:a[name],sha256:a[name+'-sha256']};}
export function runtime(a){
 const selected=row(a,'runtime-source'),m=strictJson(readPublic(selected.path,selected.sha256));
 need(m.schema==='kpxa-local-cached-chain-runtime/v1'&&m.frozen_sources.sha256===SOURCE57,'CACHE_SOURCE','original source57 required');
 const old=strictJson(readPublic(m.frozen_sources.path,SOURCE57)),members=new Map(m.source_members.map(r=>[r.path,r.sha256]));
 need(members.size===m.source_members.length,'CACHE_SOURCE','unique source closure');
 const repo=path.resolve(HERE,'../../..');for(const r of old.source_members)need(members.get(path.join(repo,r.path))===r.sha256,'CACHE_SOURCE','old57 mutation');
 for(const name of ['cache_common.py','cache.mjs','acquire_cached.mjs','fetch_cached.mjs','verify_bundle_cached.mjs','replay_cached.py','confirm_cached.py','preflight_cached.py','submit_cached.mjs'])need(members.has(path.join(HERE,name)),'CACHE_SOURCE','missing cached sibling');
 for(const [file,pin] of members)readPublic(file,pin);
 return selected;
}
export function admitted(a,rawProfile,profileSha,rawDescriptor,descriptorSha,k){
 const source=runtime(a),admissionRow=row(a,'cache-admission'),admission=strictJson(readPublic(admissionRow.path,admissionRow.sha256));
 need(admission.schema==='kpxa-local-verified-prefix-admission/v1'&&admission.scope===SCOPE&&canonical(admission.runtime_sources)===canonical(source)&&admission.initial_handoff.sha256===ROOT_HANDOFF&&admission.domain_hex32===CHILD_DOMAIN,'CACHE_ADMISSION','explicit root local admission');
 need(admission.selection.sha256===profileSha&&admission.descriptor.sha256===descriptorSha,'CACHE_ADMISSION','same descriptor/profile');
 const initial=strictJson(readPublic(admission.initial_handoff.path,ROOT_HANDOFF));
 need(initial.accepted_transactions===2&&initial.accepted_whole_CASE_equals_expected===true,'CACHE_ADMISSION','full verified seed handoff');
 const baseRow=row(a,'baseline-fetch'),base=strictJson(readPublic(baseRow.path,baseRow.sha256));
 need(base.descriptor_file_sha256===descriptorSha&&base.selection_file_sha256===profileSha&&canonical(base.sdk_pins)===canonical(SDK_PINS),'CACHE_ADMISSION','baseline source/domain selection');
 need(canonical(base.descriptor)===canonical(strictJson(rawDescriptor))&&base.descriptor.trial_id===admission.trial_id,'CACHE_ADMISSION','baseline trial/domain');
 let prior=null;
 if(a.trusted||a['trusted-local-cache']){
  if(a['baseline-cache']){
   prior=strictJson(readPublic(a['baseline-cache'],a['baseline-cache-sha256']));
   need(prior.schema==='kpxa-local-verified-prefix-cache/v1'&&prior.scope===SCOPE&&canonical(prior.runtime_sources)===canonical(source)&&canonical(prior.admission)===canonical(admissionRow)&&canonical(prior.initial_handoff)===canonical(admission.initial_handoff)&&canonical(prior.fetch)===canonical(baseRow)&&canonical(prior.selection)===canonical(admission.selection)&&canonical(prior.descriptor)===canonical(admission.descriptor)&&prior.all_selected_pool_native_financial_history_replayed===true&&prior.public_receipt_is_external_attestation===false,'CACHE_ADMISSION','STATE-held verified local selector required');
  }else need(canonical(initial.selectors['fetch.json'])===canonical(baseRow),'CACHE_ADMISSION','only explicitly admitted initial base without local receipt');
 }else fullVerify(rawProfile,profileSha,rawDescriptor,descriptorSha,readPublic(baseRow.path,baseRow.sha256),a['baseline-bundle-directory'],k);
 return {base,baseRow,admission,admissionRow,source,prior};
}
export function prefixData(data,target){
 need(Array.isArray(data.removedChainBlockHashes)&&data.removedChainBlockHashes.length===0&&data.addedChainBlockHashes.length===data.chainBlockAcceptedTransactions.length,'CACHE_PREFIX','complete nonremoved source page');
 const at=data.addedChainBlockHashes.indexOf(target);need(at>=0,'CACHE_PREFIX','verified boundary missing from final source page');
 return {removedChainBlockHashes:[],addedChainBlockHashes:data.addedChainBlockHashes.slice(0,at+1),chainBlockAcceptedTransactions:data.chainBlockAcceptedTransactions.slice(0,at+1)};
}
export function prepareBase(info,a,outputRoot=null){
 const b=info.base,sourceRoot=checkedPath(a['baseline-bundle-directory']),pages=[];let postRows=0;
 const post=b.current_view.post_query_delta;
 const segments=[{rows:b.pages,target:b.coverage.frontier.hash,post:false}, {rows:post.pages,target:post.frontier.hash,post:true}];
 for(const segment of segments)for(let i=0;i<segment.rows.length;i++){
  const old=segment.rows[i];need(!path.isAbsolute(old.path)&&!old.path.split('/').includes('..'),'CACHE_PREFIX','relative source page');
  const source=checkedPath(path.join(sourceRoot,old.path));need(source.startsWith(sourceRoot+path.sep),'CACHE_PREFIX','bounded source');
  let compressed=guardedRead(source,old.gzip_sha256),record={...old,path:`cached/${String(pages.length).padStart(5,'0')}.json.gz`};need(sha(compressed)===old.gzip_sha256,'CACHE_PREFIX','source gzip bytes');
  if(i===segment.rows.length-1||segment.post){
   const raw=zlib.gunzipSync(compressed);need(sha(raw)===old.decoded_sha256,'CACHE_PREFIX','source decoded bytes');let data=strictJson(raw);
   if(i===segment.rows.length-1){data=prefixData(data,segment.target);const changed=Buffer.from(canonical(data)+'\n');compressed=zlib.gzipSync(changed,{level:6});record={...record,decoded_sha256:sha(changed),decoded_bytes:changed.length,gzip_sha256:sha(compressed),gzip_bytes:compressed.length};}
   if(segment.post)postRows+=data.chainBlockAcceptedTransactions.reduce((n,g)=>n+g.acceptedTransactions.length,0);
  }
  if(outputRoot){const target=path.join(outputRoot,record.path);fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});fs.writeFileSync(target,compressed,{flag:'wx',mode:0o600});}
  pages.push(record);
 }
 need(pages.length>0,'CACHE_PREFIX','nonempty admitted complete prefix');
 const frontier=post.frontier,accepted=b.coverage.accepted_transaction_rows_scanned+postRows;
 const edges=new Map();for(let index=1;index<b.transactions.length;index++){
  const r=b.transactions[index],input=r.transaction.inputs[0].previousOutpoint,key=pointKey(input);
  edges.set(key,[{page:r.source_page_index,group:r.source_group_index,transaction:r.source_transaction_index,id:r.transaction.id,input_index:0}]);
 }
 const g=b.transactions[0],founding={page:g.source_page_index,group:g.source_group_index,transaction:g.source_transaction_index,id:g.transaction.id};
 return {pages,frontier,accepted,edges,founding,fingerprint:sha(canonical({pages,frontier,accepted})),base: b};
}
export function verifyCopied(root,records){const base=checkedPath(root);for(const r of records){need(typeof r.path==='string'&&!path.isAbsolute(r.path)&&!r.path.split('/').includes('..')&&path.posix.normalize(r.path)===r.path,'CACHE_PREFIX','canonical relative copied page');const target=checkedPath(path.join(base,r.path));need(target.startsWith(base+path.sep),'CACHE_PREFIX','copied page outside bundle');const b=guardedRead(target,r.gzip_sha256);need(sha(b)===r.gzip_sha256,'CACHE_PREFIX','copied admitted prefix changed');}}
