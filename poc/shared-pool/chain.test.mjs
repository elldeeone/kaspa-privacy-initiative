import test from 'node:test';
import assert from 'node:assert/strict';
import {acceptedSnapshot,successor,canonicalRpcTx,submissionFailure} from './chain.mjs';

function row(id,previous,index=0){return {transaction:{inputs:[{previousOutpoint:{transactionId:previous,index}}],verboseData:{transactionId:id}},header:{hash:'header-'+id}};}
function page(added,rows=[],removed=[]){return {addedChainBlockHashes:added,removedChainBlockHashes:removed,chainBlockAcceptedTransactions:rows.map(r=>({chainBlockHeader:r.header,acceptedTransactions:[r.transaction]}))};}
test('find successor from public outpoint without a wanted transaction list',()=>{
  const a=row('unrelated','other'),b=row('winner','reserve'),c=row('wrong-index','reserve',1);
  assert.equal(successor({transactions:[a,c,b]},{txid:'reserve',index:0}),b);
  assert.equal(successor({transactions:[a,c]},{txid:'reserve',index:0}),undefined);
  assert.equal(successor({transactions:[b,b]},{txid:'reserve',index:0}),b);
  assert.throws(()=>successor({transactions:[b,row('second','reserve')]},{txid:'reserve',index:0}),/competing accepted/);
});
test('pagination stops at captured target despite continued block production',async()=>{
  const calls=[];const pages=[page(['middle'],[row('a','source')]),page(['target','newer'],[row('b','a')])];
  const rpc={getBlockDagInfo:async()=>({sink:'target'}),getVirtualChainFromBlockV2:async q=>{calls.push(q);assert.ok(pages.length);return pages.shift();}};
  const snapshot=await acceptedSnapshot(rpc,'anchor');
  assert.deepEqual(calls.map(c=>c.startHash),['anchor','middle']);
  assert.ok(calls.every(c=>c.dataVerbosityLevel==='Full'));
  assert.equal(snapshot.transactions.length,2);
});
test('discard removed intermediate chain rather than append conflicting views',async()=>{
  const calls=[];const pages=[page(['middle'],[row('old','r')]),page(['replacement'],[],['middle']),page(['target'],[row('new','r')])];
  const rpc={getBlockDagInfo:async()=>({sink:'target'}),getVirtualChainFromBlockV2:async q=>{calls.push(q.startHash);return pages.shift();}};
  const snapshot=await acceptedSnapshot(rpc,'anchor');
  assert.deepEqual(calls,['anchor','middle','anchor']);
  assert.equal(snapshot.transactions.length,1);assert.equal(snapshot.transactions[0].transaction.verboseData.transactionId,'new');
});
test('canonical RPC decoding preserves integer sompi and input authorization fields',()=>{
  const t={version:1,inputs:[{previousOutpoint:{transactionId:'a',index:0},signatureScript:'1234',sequence:18446744073709551615n,sigOpCount:0,computeBudget:1600}],outputs:[{value:26713000n,scriptPublicKey:{version:0,script:'aabb'},covenant:null}],lockTime:0n,subnetworkId:'00',gas:0n,payload:'abcd',storageMass:137434n,verboseData:{transactionId:'id'}};
  const raw=canonicalRpcTx(t);assert.equal(raw.outputs[0].value,'26713000');assert.equal(raw.inputs[0].sequence,'18446744073709551615');assert.equal(raw.inputs[0].computeBudget,1600);assert.equal(raw.storageMass,'137434');assert.equal(raw.outputs[0].scriptPublicKey,'0000aabb');
});
test('only the initial conflict is expected; transport errors remain unknown',()=>{
  const rejection='Rejected transaction '+ 'a'.repeat(64)+': ';
  for(const cause of ['output a:0 already spent by transaction b in the mempool','at least one outpoint of the transaction is lacking a matching UTXO entry','transaction a is an orphan where orphan is disallowed']){
    assert.equal(submissionFailure(rejection+cause,0).classification,'initial-conflict');
    assert.equal(submissionFailure(rejection+cause,1).classification,'unexpected-rejection');
  }
  assert.equal(submissionFailure(rejection+'transaction is not standard: fee too low',1).classification,'unexpected-rejection');
  assert.equal(submissionFailure('WebSocket disconnected',1).accepted,null);
  assert.equal(submissionFailure('WebSocket disconnected',1).classification,'ambiguous-transport');
  assert.equal(submissionFailure(new Error('assertion failed'),0).classification,'unexpected-error');
});
