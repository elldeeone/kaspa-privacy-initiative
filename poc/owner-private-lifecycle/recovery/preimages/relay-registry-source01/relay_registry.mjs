// Durable replacement-relay intentions only. This module never sends an RPC.
// Reuses the fixed downloaded JSON parser; preserve the relative source tree.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {canonical,strictJson} from '../chain/json.mjs';

const DOMAIN='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480';
const PROFILE='69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f';
const PRIOR_STAGES=['consolidate-0','consolidate-1','consolidate-2','genesis','round-01','round-02'];
const DIRECTORIES=['predecessors','transactions','stages'];
const ROOT_NAMES=['INITIALIZING','HANDOVER.json','SEALED',...DIRECTORIES].sort();
const RECORD_FIELDS=['trial_id','transaction_id','previous_outpoint_hex36','case_sha256',
  'candidate_sha256','last_checked_virtual_daa'];
const SHA=/^[0-9a-f]{64}$/,STAGE=/^[a-z][a-z0-9-]{0,63}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hash=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const need=(ok,message)=>{if(!ok)throw new Error('replacement-registry:'+message);};
const hex32=value=>typeof value==='string'&&SHA.test(value);
const nonzero32=value=>hex32(value)&&value!=='0'.repeat(64);
const exact=(value,fields)=>value!==null&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===[...fields].sort().join(',');
const raw=value=>Buffer.from(canonical(value)+'\n');

function checked(value){
  need(typeof value==='string'&&path.isAbsolute(value)&&path.resolve(value)===value,
    'canonical-absolute-registry-path');
  for(let current=value;;current=path.dirname(current)){
    try{need(!fs.lstatSync(current).isSymbolicLink(),'symlink-registry-path');}
    catch(error){if(error.code!=='ENOENT')throw error;}
    if(path.dirname(current)===current)break;
  }
  return value;
}

function directory(value){
  checked(value);const info=fs.lstatSync(value);
  need(info.isDirectory()&&(info.mode&0o7777)===0o700,'registry-directory-mode');
}

function syncDirectory(value){
  const fd=fs.openSync(checked(value),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}

function writeExclusive(file,bytes){
  checked(file);
  const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
  try{
    fs.fchmodSync(fd,0o400);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);
    const info=fs.fstatSync(fd);need(info.isFile()&&info.nlink===1&&(info.mode&0o7777)===0o400,
      'new-single-link-readonly-marker');
  }finally{fs.closeSync(fd);}
  syncDirectory(path.dirname(file));
}

function readImmutable(file){
  checked(file);const before=fs.lstatSync(file,{bigint:true});
  need(before.isFile()&&before.nlink===1n&&(before.mode&0o7777n)===0o400n,
    'single-link-readonly-registry-file');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  const same=info=>['dev','ino','size','mtimeNs','ctimeNs'].every(key=>info[key]===before[key]);
  try{
    need(same(fs.fstatSync(fd,{bigint:true})),'registry-file-swapped');
    const bytes=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true});
    need(same(after)&&same(fs.lstatSync(file,{bigint:true}))&&after.nlink===1n
      &&BigInt(bytes.length)===before.size,'registry-file-changed');
    // An identical initializer must not return before its own durability check.
    fs.fsyncSync(fd);return bytes;
  }finally{fs.closeSync(fd);}
}

function handover(rawHandover,expectedSHA){
  need(Buffer.isBuffer(rawHandover)&&hex32(expectedSHA)&&hash(rawHandover)===expectedSHA,
    'externally-pinned-whole-handover');
  const value=strictJson(rawHandover);
  need(exact(value,['schema','domain_hex32','financial_profile_sha256','trial_id','selection_sha256',
    'descriptor_sha256','history_sha256','checkpoint_sha256','accepted_pool_prefix_txids','used_submissions',
    'all_prior_pool_submissions_resolved','original_coordinator_prover_and_writers_stopped'])
    &&value.schema==='kpx8-replacement-relay-handover/v1'&&value.domain_hex32===DOMAIN
    &&value.financial_profile_sha256===PROFILE&&typeof value.trial_id==='string'&&UUID.test(value.trial_id)
    &&['selection_sha256','descriptor_sha256','history_sha256','checkpoint_sha256'].every(key=>hex32(value[key]))
    &&value.all_prior_pool_submissions_resolved===true
    &&value.original_coordinator_prover_and_writers_stopped===true,'exact-complete-handover');
  need(Array.isArray(value.used_submissions)&&value.used_submissions.length===6
    &&Array.isArray(value.accepted_pool_prefix_txids)&&value.accepted_pool_prefix_txids.length===3,
    'complete-six-stage-three-pool-handover');
  const stages=new Map(),txids=new Set();
  for(const item of value.used_submissions){
    need(exact(item,['stage','transaction_id','status'])&&PRIOR_STAGES.includes(item.stage)
      &&nonzero32(item.transaction_id)&&item.status==='CONFIRMED'
      &&!stages.has(item.stage)&&!txids.has(item.transaction_id),'distinct-confirmed-prior-submission');
    stages.set(item.stage,item.transaction_id);txids.add(item.transaction_id);
  }
  need(PRIOR_STAGES.every(stage=>stages.has(stage))
    &&canonical(value.accepted_pool_prefix_txids)===canonical(['genesis','round-01','round-02'].map(stage=>stages.get(stage))),
    'exact-accepted-pool-prefix-order');
  return value;
}

function validateRecord(record,trial){
  need(exact(record,RECORD_FIELDS)&&record.trial_id===trial&&nonzero32(record.transaction_id)
    &&typeof record.previous_outpoint_hex36==='string'&&/^[0-9a-f]{72}$/.test(record.previous_outpoint_hex36)
    &&record.previous_outpoint_hex36.slice(0,64)!=='0'.repeat(64)
    &&hex32(record.case_sha256)&&hex32(record.candidate_sha256)
    &&typeof record.last_checked_virtual_daa==='string'&&/^(0|[1-9][0-9]*)$/.test(record.last_checked_virtual_daa)
    &&BigInt(record.last_checked_virtual_daa)<(1n<<64n),'exact-canonical-reservation-record');
}

function sealed(root,expectedSHA){
  directory(root);
  need(fs.readdirSync(root).sort().join(',')===ROOT_NAMES.join(','),'incomplete-or-ambiguous-registry-seal');
  const pin=Buffer.from(expectedSHA+'\n');
  need(readImmutable(path.join(root,'INITIALIZING')).equals(pin)
    &&readImmutable(path.join(root,'SEALED')).equals(pin),'different-or-partial-handover-seal');
  const value=handover(readImmutable(path.join(root,'HANDOVER.json')),expectedSHA);
  for(const name of DIRECTORIES)directory(path.join(root,name));
  syncDirectory(root);return value;
}

export function initialize(root,rawHandover,expectedSHA){
  root=checked(root);const value=handover(rawHandover,expectedSHA);
  if(!fs.existsSync(root)){
    fs.mkdirSync(root,{mode:0o700});syncDirectory(path.dirname(root));
  }
  directory(root);
  if(fs.readdirSync(root).length){
    const existing=sealed(root,expectedSHA);
    need(readImmutable(path.join(root,'HANDOVER.json')).equals(rawHandover),'different-handover-bytes');
    syncDirectory(root);return existing;
  }
  // INITIALIZING remains forever. A crash before SEALED consumes this root;
  // another initializer cannot reinterpret partial state as a fresh registry.
  writeExclusive(path.join(root,'INITIALIZING'),Buffer.from(expectedSHA+'\n'));
  writeExclusive(path.join(root,'HANDOVER.json'),rawHandover);
  for(const name of DIRECTORIES){fs.mkdirSync(path.join(root,name),{mode:0o700});syncDirectory(root);}
  writeExclusive(path.join(root,'SEALED'),Buffer.from(expectedSHA+'\n'));
  return sealed(root,expectedSHA);
}

function consumed(root,expectedSHA,trial){
  const records=[];
  for(const category of DIRECTORIES){
    const folder=path.join(root,category);directory(folder);
    for(const name of fs.readdirSync(folder)){
      const value=strictJson(readImmutable(path.join(folder,name)));
      need(exact(value,['schema','handover_sha256','stage','record','status'])
        &&value.schema==='kpx8-replacement-relay-intent/v1'&&value.handover_sha256===expectedSHA
        &&typeof value.stage==='string'&&STAGE.test(value.stage)
        &&value.status==='RESERVED_NEVER_RESUBMIT','exact-immutable-reservation');
      validateRecord(value.record,trial);
      const id=category==='predecessors'?value.record.previous_outpoint_hex36:
        category==='transactions'?value.record.transaction_id:value.stage;
      need(name===id+'.intent.json','reservation-filename-identity');
      records.push(value);
    }
  }
  // Any one durable marker consumes all three identities, including a partial
  // attempt. Never infer permission to resend from a missing sibling marker.
  return records;
}

export function reserve(root,handoverSHA,stage,record){
  root=checked(root);need(hex32(handoverSHA)&&typeof stage==='string'&&STAGE.test(stage),
    'canonical-reservation-scope');
  const value=sealed(root,handoverSHA);validateRecord(record,value.trial_id);
  const prior=value.used_submissions;
  need(!prior.some(item=>item.stage===stage||item.transaction_id===record.transaction_id),
    'prior-submission-never-resubmit');
  const previous=consumed(root,handoverSHA,value.trial_id);
  need(!previous.some(item=>item.stage===stage||item.record.transaction_id===record.transaction_id
    ||item.record.previous_outpoint_hex36===record.previous_outpoint_hex36),
    'used-stage-transaction-or-predecessor');
  const bytes=raw({schema:'kpx8-replacement-relay-intent/v1',handover_sha256:handoverSHA,
    stage,record,status:'RESERVED_NEVER_RESUBMIT'});
  const targets=[path.join(root,'predecessors',record.previous_outpoint_hex36+'.intent.json'),
    path.join(root,'transactions',record.transaction_id+'.intent.json'),
    path.join(root,'stages',stage+'.intent.json')];
  // The predecessor marker is first: two competing spends cannot both return.
  // A later collision deliberately consumes the earlier markers; no rollback.
  for(const file of targets)writeExclusive(file,bytes);
  return targets;
}
