import {connectTor} from './rpc.mjs';
// Read-only validating-node identity/maturity and optional public funding queries.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {GENESIS,loadSdk,need,stringify,script,integer,point} from './wire.mjs';
import {DEFAULT_RPCS} from './fetch.mjs';
import {identity} from './acquire.mjs';

export async function probe(urls=DEFAULT_RPCS,addresses=[],k=loadSdk()){
 const rows=[];
 for(const endpoint of urls){
  const url=new URL(endpoint);
  need(url.protocol==='wss:'&&!url.username&&!url.password&&!url.search&&!url.hash,
   'ENDPOINT','credential-free testnet TLS RPC required');
  let connection,rpc;
  try{
      connection=await connectTor(k,url.href);rpc=connection.rpc;
   
   const {server,dag}=await identity(rpc),current=integer(dag.virtualDaaScore);
   const entries=addresses.length?(await rpc.getUtxosByAddresses({addresses})).entries:[];
   const seen=new Set();
   const outputs=entries.map(raw=>{
    const e=raw.entry??raw,at=point(e.outpoint),key=at.transactionId+':'+at.index;
    need(!seen.has(key),'UTXO','duplicate exact funding point');seen.add(key);
    const born=integer(e.blockDaaScore),coinbase=e.isCoinbase;
    need(typeof coinbase==='boolean'&&(e.covenantId??null)===null,'UTXO','ordinary funding context required');
    return {outpoint:at,amount_sompi:integer(e.amount).toString(),script_public_key:script(e.scriptPublicKey),
      block_daa_score:born.toString(),is_coinbase:coinbase,covenant_id:null,
      mature_at_observation:!coinbase||current>=born+1000n};
   });
   rows.push({rpc_url:url.href,status:'READ_ONLY_TN10_NODE_OBSERVED',server,
    virtual_daa_score:current.toString(),sink:dag.sink,entries:outputs});
  }catch(error){rows.push({rpc_url:url.href,status:'INCOMPLETE',category:error.category??'RPC_UNAVAILABLE'});}
  finally{if(connection)await connection.close();}
 }
 return {schema:'kpxa-public-TN10-funding-probe/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
  coinbase_maturity_daa_delta:1000,observations:rows,observed_at:new Date().toISOString(),
  wallet_secret_key_or_PK_read:false,mining_funding_or_broadcast_performed:false,
  independent_administration_or_consensus_established:false};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const addresses=process.argv.slice(2);need(addresses.every(x=>x.startsWith('kaspatest:')),
    'ADDRESS','only public testnet addresses permitted');
  process.stdout.write(stringify(await probe(DEFAULT_RPCS,addresses))+'\n');
 }catch(error){process.stderr.write('read-only TN10 probe incomplete\n');process.exitCode=2;}
}
