// Read-only own coinbase maturity acquisition; no key, signer or submit API.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {GENESIS,loadSdk,need,script,integer,point,stringify} from '../chain/wire.mjs';
import {readPublic,checkedPath} from '../chain/selection.mjs';
import {identity,save} from '../chain/acquire.mjs';
import {DEFAULT_RPCS} from '../chain/fetch.mjs';

export async function collect(identityRaw,output,url=DEFAULT_RPCS[0],k=loadSdk()){
 const value=JSON.parse(identityRaw);
 need(value.schema==='kpx8-three-owner-funding-identity/v1'&&value.network_id==='testnet-10'
  &&value.genesis_hash_hex===GENESIS&&value.domain_hex32==='be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
  &&Array.isArray(value.funding_wallets)&&value.funding_wallets.length===3,
  'IDENTITY','selected new three-owner funding identity required');
 const endpoint=new URL(url);need(endpoint.protocol==='wss:'&&!endpoint.username&&!endpoint.password
  &&!endpoint.search&&!endpoint.hash,'ENDPOINT','credential-free testnet TLS RPC required');
 output=checkedPath(output);need(!fs.existsSync(output),'OUTPUT','fresh public funding observation directory');
 fs.mkdirSync(output,{recursive:true,mode:0o700});
 const rpc=new k.RpcClient({url:endpoint.href,networkId:'testnet-10'});
 try{
  await rpc.connect({blockAsyncConnect:true,timeoutDuration:60000,strategy:'fallback'});
  const observed=await identity(rpc),current=integer(observed.dag.virtualDaaScore),results=[];
  for(const owner of value.funding_wallets){
   need(['0','1','2'].includes(owner.role)&&/^000020[0-9a-f]{64}ac$/.test(owner.script_public_key),
    'IDENTITY','ordinary selected public funding key');
   const address=k.addressFromScriptPublicKey(owner.script_public_key,'testnet-10');
   try{need(address.toString()===owner.address,'IDENTITY','SDK funding address/script mismatch');}
   finally{address.free();}
   const answer=await rpc.getUtxosByAddresses({addresses:[owner.address]});
   need(Array.isArray(answer.entries),'UTXO','complete own funding UTXO array required');
   let total=0n,immature=0n;const sources=[],seen=new Set();
   for(const raw of answer.entries){
    const e=raw.entry??raw,at=point(e.outpoint),key=at.transactionId+':'+at.index;
    need(!seen.has(key),'UTXO','duplicate funding source');seen.add(key);
    need(script(e.scriptPublicKey)===owner.script_public_key&&(e.covenantId??null)===null,
     'UTXO','exact own ordinary funding script required');
    if(e.isCoinbase!==true)continue;
    const amount=integer(e.amount),birth=integer(e.blockDaaScore);
    need(amount>0n&&amount<=2870000000000000000n,'UTXO','positive bounded coinbase sompi');
    if(current<birth+1000n){immature+=amount;continue;}
    total+=amount;
    sources.push({outpoint:at,entry:{amount:amount.toString(),scriptPublicKey:owner.script_public_key,
      blockDaaScore:birth.toString(),isCoinbase:true,covenantId:null}});
   }
   sources.sort((a,b)=>a.outpoint.transactionId.localeCompare(b.outpoint.transactionId)
    ||a.outpoint.index-b.outpoint.index);
   const observation={schema:'kpx8-own-mature-coinbase-observation/v1',network_id:'testnet-10',
    genesis_hash_hex:GENESIS,domain_hex32:value.domain_hex32,trial_id:value.trial_id,
    participant_id_hex32:owner.participant_id_hex32,funding_script_public_key:owner.script_public_key,
    virtual_daa_score:current.toString(),sources};
   const member=save(path.join(output,'OWNER-'+owner.role+'.json'),observation);
   results.push({role:owner.role,mature_coinbase_sompi:total.toString(),immature_coinbase_sompi:immature.toString(),
    source_count:sources.length,observation_sha256:member.sha256,
    sufficient_for_20_KAS_plus_1_KAS_headroom:total>=2100000000n});
  }
  const result={schema:'kpx8-three-owner-funding-observation/v1',network_id:'testnet-10',
   genesis_hash_hex:GENESIS,trial_id:value.trial_id,rpc_url:endpoint.href,
   virtual_daa_score:current.toString(),coinbase_maturity_daa_delta:1000,owners:results,
   status:results.every(row=>row.sufficient_for_20_KAS_plus_1_KAS_headroom)?'MATURE_SOURCES_OBSERVED_PENDING_CONSOLIDATION':'INCOMPLETE_WAIT_FOR_FREE_REWARDS_OR_MATURITY',
   mining_signing_or_broadcast_performed:false,independent_consensus_proved:false};
  save(path.join(output,'RESULTS.json'),result);return result;
 }finally{await rpc.disconnect();}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const [file,sha,output,url]=process.argv.slice(2);need(file&&sha&&output,'ARGUMENT','IDENTITY SHA FRESH_OUTPUT [RPC]');
  process.stdout.write(stringify(await collect(readPublic(file,sha),output,url??DEFAULT_RPCS[0]))+'\n');}
 catch(error){process.stderr.write('read-only mature funding acquisition incomplete\n');process.exitCode=2;}
}
