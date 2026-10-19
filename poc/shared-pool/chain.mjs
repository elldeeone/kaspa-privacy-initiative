// Public accepted-chain transport. Selection is by reserve outpoint, never a
// coordinator's list of future transaction IDs. Full-node view is an assumption.
import assert from 'node:assert/strict';
import {address,utxos,spk} from './runtime.mjs';

export const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export const outpoint=u=>`${u.txid}:${u.index}`;
export function outputUtxo(tx,index){
  const o=tx.outputs[index];
  return {txid:tx.id,index,amount:o.value,spk:o.scriptPublicKey,daa:'0',is_coinbase:false};
}
export async function exactUtxo(rpc,expected){
  const rows=await utxos(rpc,address(expected.spk));
  const found=rows.find(u=>outpoint(u)===outpoint(expected));
  if(found){assert.equal(found.amount,expected.amount);assert.equal(found.spk,expected.spk);assert.equal(found.is_coinbase,false);}
  return found;
}
export async function confirm(rpc,raw){
  for(;;){
    const found=await Promise.all(raw.outputs.map((_,i)=>exactUtxo(rpc,outputUtxo(raw,i))));
    if(found.every(Boolean))return found;
    await sleep(1000);
  }
}
export function canonicalRpcTx(t){
  assert.ok(t.verboseData?.transactionId);
  return {version:t.version,id:t.verboseData.transactionId,
    inputs:t.inputs.map(i=>({previousOutpoint:i.previousOutpoint,signatureScript:i.signatureScript??'',sequence:i.sequence.toString(),sigOpCount:i.sigOpCount,computeBudget:i.computeBudget})),
    outputs:t.outputs.map(o=>({value:o.value.toString(),scriptPublicKey:typeof o.scriptPublicKey==='string'?o.scriptPublicKey:spk(o.scriptPublicKey),covenant:o.covenant??null})),
    lockTime:t.lockTime.toString(),subnetworkId:t.subnetworkId,gas:t.gas.toString(),payload:t.payload,storageMass:t.storageMass.toString()};
}
export async function acceptedSnapshot(rpc,anchor){
  // Restart read-only pagination if its retained chain prefix is removed.
  // This does not implement rollback of an already adopted wallet history.
  for(;;){
    const target=(await rpc.getBlockDagInfo()).sink;
    let cursor=anchor;const transactions=[],pages=[],retained=new Set();let restart=false;
    for(;;){
      const page=await rpc.getVirtualChainFromBlockV2({startHash:cursor,dataVerbosityLevel:'Full'});
      if(page.removedChainBlockHashes.some(h=>retained.has(h)||h===target)){restart=true;break;}
      for(const h of page.addedChainBlockHashes)retained.add(h);
      for(const group of page.chainBlockAcceptedTransactions){
        for(const transaction of group.acceptedTransactions)transactions.push({transaction,header:group.chainBlockHeader});
      }
      pages.push({start:cursor,removed:page.removedChainBlockHashes,added:page.addedChainBlockHashes.length});
      if(cursor===target||page.addedChainBlockHashes.includes(target))return {transactions,pages,observedAt:new Date().toISOString()};
      const next=page.addedChainBlockHashes.at(-1);
      if(!next||next===cursor)return {transactions,pages,observedAt:new Date().toISOString()};
      cursor=next;
    }
    if(restart)await sleep(1000);
  }
}
export function successor(snapshot,reserve){
  const matches=new Map();
  for(const row of snapshot.transactions){
    const i=row.transaction.inputs[0]?.previousOutpoint;
    if(i?.transactionId===reserve.txid&&i.index===reserve.index){
      matches.set(row.transaction.verboseData.transactionId,row);
    }
  }
  assert.ok(matches.size<=1,'full node reports competing accepted spends of one reserve');
  return matches.values().next().value;
}

export function submissionFailure(error,attempt){
  const message=String(error);
  // Match the pinned native RpcError::RejectedTransaction and mempool errors.
  // A transport failure is an unknown outcome, never permission to rebroadcast.
  if(/Rejected transaction [0-9a-f]{64}:/i.test(message)){
    const conflict=/already spent by transaction|lacking a matching UTXO entry|is an orphan where orphan is disallowed/i.test(message);
    return {accepted:false,error:message,classification:attempt===0&&conflict?'initial-conflict':'unexpected-rejection'};
  }
  if(/timeout|timed out|disconnect|connection|websocket|socket|transport/i.test(message))return {accepted:null,error:message,classification:'ambiguous-transport'};
  return {accepted:null,error:message,classification:'unexpected-error'};
}
