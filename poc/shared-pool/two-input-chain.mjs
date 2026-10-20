// v6 public chain discovery. The RPC node's accepted-chain view is a trust
// assumption; no experiment controller provides the current reserve/state.
import assert from 'node:assert/strict';
import {acceptedSnapshot,canonicalRpcTx,outputUtxo,exactUtxo,sleep} from './chain.mjs';

export function reserveAfter(raw){
  if(!raw.payload)return outputUtxo(raw,0);
  const p=Buffer.from(raw.payload,'hex');
  assert.equal(p.length,5228);assert.equal(p.subarray(0,8).toString(),'KPICR06\0');
  // Counts include zero outputs and padded NFs. C==N is NOT a drain rule.
  if(p.subarray(755,860).every(x=>x===0)){
    assert.equal(p[212],2);assert.equal(raw.outputs.length,1);return null;
  }
  assert.equal(p[755],6);return outputUtxo(raw,0);
}
export async function acceptedHistory(rpc,d){
  for(;;){
    const snapshot=await acceptedSnapshot(rpc,d.start_hash);
    const byId=new Map(snapshot.transactions.map(r=>{const t=canonicalRpcTx(r.transaction);return [t.id,t];}));
    for(const u of d.sources){
      const parent=byId.get(u.txid);assert.ok(parent,'accepted funding parent unavailable');
      const actual=outputUtxo(parent,u.index);
      assert.equal(actual.amount,u.amount);assert.equal(actual.spk,u.spk);
    }
    const first=byId.get(d.funding_txid);if(!first){await sleep(1000);continue;}
    const history=[first],seen=new Set([first.id]);let current=reserveAfter(first);
    while(current){
      const next=[...byId.values()].filter(t=>t.inputs[0]?.previousOutpoint.transactionId===current.txid&&t.inputs[0]?.previousOutpoint.index===current.index);
      assert.ok(next.length<=1,'competing accepted reserve spends');if(!next.length)break;
      assert.ok(!seen.has(next[0].id));seen.add(next[0].id);history.push(next[0]);current=reserveAfter(next[0]);
    }
    if(current&&!await exactUtxo(rpc,current)){await sleep(1000);continue;}
    return {history,current,pages:snapshot.pages,observedAt:snapshot.observedAt};
  }
}
