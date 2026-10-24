// SYNTHETIC accepted assignments only. No Native Full, proof, funding or live pool.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadSdk, headerHash, canonicalTransaction, sha, stringify, GENESIS} from './wire.mjs';
import {canonical, CHILD_DOMAIN, profile, strictJson} from './selection.mjs';
import {execute} from './fetch.mjs';
import {verify} from './verify_bundle.mjs';

const real=loadSdk(), H=c=>c.repeat(64), clone=v=>JSON.parse(JSON.stringify(v));
const raw=v=>Buffer.from(canonical(v)+'\n');
const trial='cfec7af9-5614-4af0-bf30-de1d24de7595';
const financialSha=H('e');
const Wtail=Buffer.from('51','hex'); // Deliberately dummy reserve policy.
const selected={schema:'kpx8-GN3-selection/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
  domain_hex32:CHILD_DOMAIN,state_magic_hex8:Buffer.from('KPX8ST01').toString('hex'),
  financial_profile_sha256:financialSha,native_tail_hex:Wtail.toString('hex'),native_tail_sha256:sha(Wtail)};
const profileRaw=raw(selected),profileSha=sha(profileRaw);
const state=Buffer.concat([Buffer.from('KPX8ST01'),Buffer.from(CHILD_DOMAIN,'hex'),
  Buffer.from(H('3'),'hex'),Buffer.from('03000000','hex'),Buffer.from(H('4'),'hex'),Buffer.from('01000000','hex')]);
const redeem=Buffer.concat([Buffer.from('4c70','hex'),state,Wtail]);
function spk(script) {
  const value=real.payToScriptHashScript(script);
  try{return value.version.toString(16).padStart(4,'0')+value.script;}finally{value.free();}
}
const sourceSpks=['000020'+H('5')+'ac','000020'+H('6')+'ac','000020'+H('a')+'ac'];
const sourcePoints=[{transactionId:H('7'),index:0},{transactionId:H('8'),index:1},{transactionId:H('9'),index:2}];
const fundingContexts=sourcePoints.map((at,i)=>({outpoint:at,amount_sompi:'2010000000',
  script_public_key:sourceSpks[i],block_daa_score:'123',is_coinbase:false,covenant_id:null}));
function finalize(value,entries) {
  const tx=new real.Transaction({...value,
    inputs:value.inputs.map((item,i)=>({...item,sequence:BigInt(item.sequence),sigOpCount:0,
      utxo:{outpoint:item.previousOutpoint,amount:BigInt(entries[i].amount_sompi),
        scriptPublicKey:entries[i].script_public_key,blockDaaScore:BigInt(entries[i].block_daa_score),isCoinbase:false}})),
    outputs:value.outputs.map(item=>({value:BigInt(item.value),scriptPublicKey:item.scriptPublicKey})),
    lockTime:BigInt(value.lockTime),gas:BigInt(value.gas),storageMass:BigInt(value.storageMass)});
  try{tx.finalize();return canonicalTransaction(tx);}finally{tx.free();}
}
const payload=Buffer.concat([Buffer.from('KPX8GN01'),Buffer.from(financialSha,'hex'),
  Buffer.from(CHILD_DOMAIN,'hex'),Buffer.from(trial.replaceAll('-',''),'hex'),Buffer.alloc(1488,0x22)]);
const founding=finalize({version:1,id:H('0'),inputs:sourcePoints.map(at=>({previousOutpoint:at,
  signatureScript:'41'+'11'.repeat(64)+'01',sequence:'18446744073709551615',computeBudget:10})),
  outputs:[{value:'6000000000',scriptPublicKey:spk(redeem),covenant:null},
    ...sourceSpks.map(s=>({value:'9990000',scriptPublicKey:s,covenant:null}))],
  lockTime:'0',subnetworkId:'00'.repeat(20),gas:'0',payload:payload.toString('hex'),storageMass:'0'},fundingContexts);
const wPoint={transactionId:founding.id,index:0};
const wContext=[{outpoint:wPoint,amount_sompi:'6000000000',script_public_key:spk(redeem),
  block_daa_score:'130',is_coinbase:false,covenant_id:null}];
function terminal(destination=H('9')) {
  const payload=Buffer.alloc(1632);Buffer.from('KPX8XB01').copy(payload);
  Buffer.from([1,0,1,0,0,0,1,0]).copy(payload,8);Buffer.from(CHILD_DOMAIN,'hex').copy(payload,16);
  state.copy(payload,148);state.copy(payload,268);payload.writeBigUInt64LE(6000000000n,260);
  payload.writeBigUInt64LE(10000000n,388);payload.writeBigUInt64LE(5990000000n,396);
  Buffer.from('000020'+destination+'ac','hex').copy(payload,404);
  const frame=Buffer.concat([Buffer.from([65]),Buffer.alloc(65),Buffer.from([0x4c,128]),
    Buffer.alloc(128),Buffer.from([0x4d,redeem.length&255,redeem.length>>8]),redeem]);
  return finalize({version:1,id:H('0'),inputs:[{previousOutpoint:wPoint,signatureScript:frame.toString('hex'),
    sequence:'18446744073709551615',computeBudget:1500}],outputs:[{value:'5990000000',
      scriptPublicKey:'000020'+destination+'ac',covenant:null}],lockTime:'0',subnetworkId:'00'.repeat(20),
    gas:'0',payload:payload.toString('hex'),storageMass:'0'},wContext);
}
function rawBody(tx,entries) {
  const result=clone(tx);result.verboseData={transactionId:tx.id};
  result.inputs.forEach((item,i)=>{const c=entries[i];item.verboseData={utxoEntry:{amount:c.amount_sompi,
    scriptPublicKey:c.script_public_key,blockDaaScore:c.block_daa_score,isCoinbase:false,covenantId:null}};});
  return result;
}
function header(parent,score) {
  const value={hash:H('0'),version:2,parentsByLevel:[[parent]],hashMerkleRoot:H('a'),
    acceptedIdMerkleRoot:H('b'),utxoCommitment:H('c'),timestamp:'1',bits:1,nonce:String(score),
    daaScore:String(score),blueScore:String(score),blueWork:BigInt(score).toString(16).padStart(48,'0'),pruningPoint:H('d')};
  value.hash=headerHash(real,value);return value;
}

const anchor=header(H('0'),10),first=header(anchor.hash,11),front=header(first.hash,79),sink=header(front.hash,100);
const newFront=header(front.hash,179),newSink=header(newFront.hash,200);
const d={schema:'kpx8-gn3-network-descriptor/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
  financial_profile_sha256:financialSha,trial_id:trial,founding_outpoint:wPoint,birth_start_hash:anchor.hash,
  initial_redeem_hex:redeem.toString('hex'),initial_redeem_sha256:sha(redeem)};
const descriptorRaw=raw(d),descriptorSha=sha(descriptorRaw);
const page=groups=>({removedChainBlockHashes:[],addedChainBlockHashes:groups.map(g=>g.chainBlockHeader.hash),
  chainBlockAcceptedTransactions:groups});

function mocked(modes,calls) {
 return {...real,RpcClient:class {
  constructor({url}){this.mode=modes[url];this.pages=0;this.identities=0;this.utxoCalls=0;calls.push(url);}
  async connect(){if(this.mode==='down')throw Error('injected offline endpoint');}
  async disconnect(){}
  async getServerInfo(){return {networkId:this.mode==='mainnet'?'mainnet':'testnet-10',
    serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true};}
  async getBlockDagInfo(){this.identities++;return {network:'testnet-10',
    sink:this.mode==='payout-race'&&this.identities>=3?newSink.hash:sink.hash};}
  async getBlock({hash}){
   if(hash===anchor.hash&&this.mode==='pruned')throw Error('injected pruned birth anchor');
   const h=[anchor,first,front,sink,newFront,newSink].find(h=>h.hash===hash);
   assert(h,'unexpected mock header');
   return {block:{header:clone(h),verboseData:{isChainBlock:!(this.mode==='anchor-reorg'&&this.identities>=4&&hash===anchor.hash),
     selectedParentHash:h.parentsByLevel[0][0]}}};
  }
  async getVirtualChainFromBlockV2({startHash}){
   if(startHash===front.hash&&this.mode==='payout-race'){
    const payout={transactionId:terminal().id,index:0};
    return page([{chainBlockHeader:newFront,acceptedTransactions:[{id:H('f'),
      inputs:[{previousOutpoint:payout,signatureScript:''}]}]}]);
   }
   if(this.mode==='partial'&&this.pages++)return page([]);
   const funding=rawBody(founding,fundingContexts);
   if(this.mode==='missing-context')delete funding.inputs[1].verboseData;
   const group1={chainBlockHeader:clone(first),acceptedTransactions:this.mode==='missing-funding'?[]:[funding]};
   const terminalMode=['terminal','payout-race','prior-payout-spent','duplicate-utxo','conflict','near-tip-race'].includes(this.mode);
   const exits=terminalMode?[rawBody(terminal(),wContext)]:[];
   if(this.mode==='conflict')exits.push(rawBody(terminal(H('e')),wContext));
   const group2={chainBlockHeader:clone(front),acceptedTransactions:exits};
   if(this.mode==='duplicate-funding')group2.acceptedTransactions.push(funding);
   const result=page(this.mode==='partial'?[group1]:[group1,group2]);
   if(this.mode==='removed')result.removedChainBlockHashes=[H('e')];
   if(this.mode==='truncated')result.addedChainBlockHashes.pop();
   if(this.mode==='bad-header')result.chainBlockAcceptedTransactions[0].chainBlockHeader.nonce='99';
   return result;
  }
  async getUtxosByAddresses(){
   this.utxoCalls++;
   const terminalMode=['terminal','payout-race','prior-payout-spent','duplicate-utxo','conflict','near-tip-race'].includes(this.mode);
   let entries=founding.outputs.slice(1).map((o,i)=>({outpoint:{transactionId:founding.id,index:i+1},
     amount:o.value,scriptPublicKey:o.scriptPublicKey,blockDaaScore:'130',isCoinbase:false,covenantId:null}));
   if(terminalMode&&this.mode!=='prior-payout-spent')entries.push({outpoint:{transactionId:terminal().id,index:0},
     amount:'5990000000',scriptPublicKey:terminal().outputs[0].scriptPublicKey,
     blockDaaScore:'140',isCoinbase:false,covenantId:null});
   if(!terminalMode&&this.mode!=='head-missing')entries.push({outpoint:wPoint,amount:'6000000000',
     scriptPublicKey:spk(redeem),blockDaaScore:'130',isCoinbase:false,covenantId:null});
   if(this.mode==='near-tip-race'&&this.utxoCalls>1)entries=entries.filter(x=>x.outpoint.transactionId!==terminal().id);
   if(this.mode==='ordinary-change-prior'||this.mode==='ordinary-change-race'&&this.utxoCalls>1)
     entries=entries.filter(x=>!(x.outpoint.transactionId===founding.id&&x.outpoint.index===1));
   if(this.mode==='duplicate-utxo')entries.push(entries[0]);
   return {entries};
  }
 }};
}
const A='wss://primary.invalid/',B='wss://secondary.invalid/';
async function run(modes,inspect) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'owner-private-chain-test-')),calls=[];
 try{
  fs.writeFileSync(path.join(root,'profile.json'),profileRaw);fs.writeFileSync(path.join(root,'descriptor.json'),descriptorRaw);
  const result=await execute(path.join(root,'profile.json'),profileSha,path.join(root,'descriptor.json'),descriptorSha,
    path.join(root,'fetch'),Object.keys(modes),mocked(modes,calls));
  if(inspect)return await inspect({root: path.join(root,'fetch'),result,calls});
  return {result,calls};
 }finally{fs.rmSync(root,{recursive:true,force:true});}
}
const verifyResult=(result,root)=>verify(profileRaw,profileSha,descriptorRaw,descriptorSha,raw(result),root,real);

test('externally pinned profile and strict UTF8/duplicate JSON',()=>{
 assert.equal(profile(profileRaw,profileSha).financial_profile_sha256,financialSha);
 assert.throws(()=>profile(profileRaw,H('0')));
 const wrong=clone(selected);wrong.domain_hex32=H('0');const bytes=raw(wrong);
 assert.throws(()=>profile(bytes,sha(bytes)));
 assert.throws(()=>strictJson('{"x":{"a":1,"a":2}}'));
 assert.throws(()=>strictJson(Buffer.from([123,34,97,34,58,34,255,34,125])));
});
test('complete funding acquisition is pending financial replay and retains actual DAA',async()=>{
 await run({[A]:'funded'},({root,result})=>{
  assert.equal(result.status,'FETCHED_PENDING_REPLAY');assert.equal(result.transactions.length,1);
  assert.equal(result.transactions[0].accepted_input_contexts[1].block_daa_score,'123');
  const checked=verifyResult(result,root);assert.deepEqual(checked.discovered_head,wPoint);
  assert.equal(checked.no_GN3_or_W_semantic_native_verification_in_this_SDK_stage,true);
 });
});
test('direct private fallback may be first W spend and valid historical payout may already be spent',async()=>{
 for(const mode of ['terminal','prior-payout-spent'])await run({[A]:mode},({root,result})=>{
  const checked=verifyResult(result,root);assert.equal(checked.terminal_candidate,true);
  assert.equal(checked.discovered_head,null);assert.equal(result.transactions.length,2);
 });
});
test('fresh fallback endpoint, and unknown balance if all endpoints fail',async()=>{
 const value=await run({[A]:'down',[B]:'funded'});assert.deepEqual(value.calls,[A,B]);
 assert.equal(value.result.source.attempt,2);
 const none=await run({[A]:'down',[B]:'down'});assert.equal(none.result.status,'INCOMPLETE');
 assert.equal(none.result.balance_known,false);
});
test('wrong network/pruned/partial/removed/truncated/missing data do not produce a balance',async()=>{
 for(const mode of ['mainnet','pruned','partial','removed','truncated','missing-funding','missing-context','bad-header',
   'head-missing','anchor-reorg','duplicate-funding','duplicate-utxo','conflict','payout-race']){
  const {result}=await run({[A]:mode});assert.equal(result.status,'INCOMPLETE',mode);
  assert.equal(result.balance_known,false,mode);
 }
});
test('near-tip payout or ordinary-change spends cannot hide inside confirmation depth',async()=>{
 for(const mode of ['near-tip-race','ordinary-change-race']) {
  const {result}=await run({[A]:mode});assert.equal(result.status,'INCOMPLETE',mode);
 }
 await run({[A]:'ordinary-change-prior'},({root,result})=>{
  assert.equal(verifyResult(result,root).status,'PUBLIC_EVIDENCE_CONSISTENCY_PASS');
 });
});
test('complete Full-page body/context joins reject same-txid budget and witness substitution',async()=>{
 await run({[A]:'funded'},({root,result})=>{
  for(const field of ['budget','witness','context']){
   const changed=clone(result);
   if(field==='budget')changed.transactions[0].transaction.inputs[0].computeBudget++;
   if(field==='witness')changed.transactions[0].transaction.inputs[0].signatureScript='41'+'22'.repeat(64)+'01';
   if(field==='context')changed.transactions[0].accepted_input_contexts[0].block_daa_score='999';
   if(field!=='context')assert.equal(finalize(changed.transactions[0].transaction,fundingContexts).id,founding.id);
   assert.throws(()=>verifyResult(changed,root),field);
  }
 });
});
test('exact post-query live point coverage and canonical amount boundary are mandatory',async()=>{
 await run({[A]:'terminal'},({root,result})=>{
  const omitted=clone(result);omitted.current_view.post_query_delta.watched_outpoints.pop();
  assert.throws(()=>verifyResult(omitted,root));
  const amount=clone(result);amount.current_view.queries[0].amount_sompi=2010000000;
  assert.throws(()=>verifyResult(amount,root));
  const missing=clone(result);missing.current_view.queries.pop();assert.throws(()=>verifyResult(missing,root));
 });
});
test('retained page traversal and symlink aliases reject before external reads',async()=>{
 await run({[A]:'funded'},({root,result})=>{
  const escaped=clone(result);escaped.pages[0].path='../private-canary';
  assert.throws(()=>verifyResult(escaped,root));
  const actual=path.join(root,result.pages[0].path),target=path.join(path.dirname(root),'private-canary');
  fs.writeFileSync(target,'UNREAD_SYNTHETIC_CANARY');fs.unlinkSync(actual);fs.symlinkSync(target,actual);
  let reads=0;const original=fs.readFileSync;
  fs.readFileSync=function(file,...rest){if(path.resolve(String(file))===target)reads++;return original.call(this,file,...rest);};
  try{assert.throws(()=>verifyResult(result,root));assert.equal(reads,0);}finally{fs.readFileSync=original;}
 });
});
