// Synthetic page framing + real pinned SDK header hashes; never chain authority.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import {retainedScan} from './acquire.mjs';
import {loadSdk,headerHash,sha,stringify} from '../../../chain/wire.mjs';

const k=loadSdk(),root=fs.mkdtempSync(path.join(os.tmpdir(),'kpb-public-page-controls-'));
const H=text=>sha(Buffer.from(text));let serial=0,passed=0;
function header(parent,score){
  const raw={hash:'00'.repeat(32),version:0,parentsByLevel:[[parent]],hashMerkleRoot:H('transactions'),
    acceptedIdMerkleRoot:H('accepted IDs'),utxoCommitment:H('UTXO'),timestamp:'1',bits:0,nonce:'0',
    daaScore:String(score),blueScore:String(score),blueWork:'00'.repeat(24),pruningPoint:H('pruning')};
  raw.hash=headerHash(k,raw);return raw;
}
const anchor=header(H('parent'),1),frontier=header(anchor.hash,2),producer=H('synthetic producer');
const r={birth_start_hash:anchor.hash,head:{outpoint:{transactionId:producer,index:0}},immutable_tail_hex:'deadbeef'};
function fixture(){return {removedChainBlockHashes:[],addedChainBlockHashes:[frontier.hash],
  chainBlockAcceptedTransactions:[{chainBlockHeader:structuredClone(frontier),
    acceptedTransactions:[{id:producer,inputs:[]}]}]};}
function record(data){
  const raw=Buffer.from(stringify(data)+'\n'),gzip=zlib.gzipSync(raw),relative=`${serial++}.json.gz`;
  fs.writeFileSync(path.join(root,relative),gzip,{flag:'wx'});
  return {path:relative,request:{startHash:anchor.hash,dataVerbosityLevel:'Full',minConfirmationCount:20},
    decoded_sha256:sha(raw),decoded_bytes:raw.length,gzip_sha256:sha(gzip),gzip_bytes:gzip.length};
}
function boundary(){return {header:frontier,sink:{blueScore:'100'},min_confirmation_count:20};}
function control(name,body){body();passed++;process.stdout.write(name+' PASS\n');}
try{
  control('structural-prefix-with-real-SDK-header-hashes',()=>{
    const result=retainedScan(k,r,boundary(),[record(fixture())],root);assert.equal(result.founding.id,producer);
  });
  control('removed-selected-block',()=>{const data=fixture();data.removedChainBlockHashes=[H('removed')];assert.throws(()=>retainedScan(k,r,boundary(),[record(data)],root),e=>e.category==='REORG');});
  control('changed-complete-header',()=>{const data=fixture();data.chainBlockAcceptedTransactions[0].chainBlockHeader.nonce='1';assert.throws(()=>retainedScan(k,r,boundary(),[record(data)],root),e=>e.category==='HEADER');});
  control('missing-selected-predecessor',()=>{const data=fixture(),changed=header(H('unrelated parent'),2);data.addedChainBlockHashes=[changed.hash];data.chainBlockAcceptedTransactions[0].chainBlockHeader=changed;const b=boundary();b.header=changed;assert.throws(()=>retainedScan(k,r,b,[record(data)],root),e=>e.category==='COVERAGE');});
  control('insufficient-fixed-sink-depth',()=>{const b=boundary();b.sink.blueScore='22';assert.throws(()=>retainedScan(k,r,b,[record(fixture())],root),e=>e.category==='DEPTH');});
  control('missing-frontier',()=>{const b=boundary();b.header={...frontier,hash:H('missing frontier')};assert.throws(()=>retainedScan(k,r,b,[record(fixture())],root),e=>e.category==='COVERAGE');});
  control('extra-page-after-frontier',()=>{const row=record(fixture());assert.throws(()=>retainedScan(k,r,boundary(),[row,row],root),e=>e.category==='COVERAGE');});
  control('missing-admitted-head-producer',()=>{const data=fixture();data.chainBlockAcceptedTransactions[0].acceptedTransactions[0].id=H('another producer');assert.throws(()=>retainedScan(k,r,boundary(),[record(data)],root),e=>e.category==='COVERAGE');});
  control('changed-gzip',()=>{const row=record(fixture());fs.appendFileSync(path.join(root,row.path),'x');assert.throws(()=>retainedScan(k,r,boundary(),[row],root));});
  control('changed-decoded-page',()=>{const row=record(fixture());row.decoded_sha256=H('wrong decoded page');assert.throws(()=>retainedScan(k,r,boundary(),[row],root),e=>e.category==='CACHE_INTEGRITY');});
  process.stdout.write(JSON.stringify({schema:'kpb-public-retained-page-controls/v1',passed,
    real_pinned_SDK_header_hashing:true,live_RPC_or_financial_proof_or_settlement:false})+'\n');
}finally{fs.rmSync(root,{recursive:true,force:true});}
