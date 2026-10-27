// Public retained Full pages only. No RPC, key, wallet or submission interface.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {verify} from '../chain/verify_bundle.mjs';
import {pageData} from '../chain/acquire.mjs';
import {canonicalTransaction,integer,loadSdk,need,point,script,stringify} from '../chain/wire.mjs';
import {checkedPath,readPublic,strictJson} from '../chain/selection.mjs';
import {makeTransaction} from '../chain/submit.mjs';

export function extract(rawSelection,selectionSha,rawDescriptor,descriptorSha,rawFetch,root,k){
 const sdk=verify(rawSelection,selectionSha,rawDescriptor,descriptorSha,rawFetch,root,k);
 const fetch=strictJson(rawFetch),pool=fetch.transactions;
 need(pool.length>=1&&pool[0].transaction.inputs.length===3,'FUNDING','three actual genesis funding inputs');
 const wanted=new Set(pool[0].transaction.inputs.map(i=>i.previousOutpoint.transactionId));
 need(wanted.size===3&&pool[0].transaction.inputs.every(i=>i.previousOutpoint.index===0),'FUNDING','distinct actual ordinary self-output zero points');
 const found=new Map();
 for(let pageIndex=0;pageIndex<fetch.pages.length;pageIndex++){
  const data=pageData(root,fetch.pages[pageIndex]);
  for(let groupIndex=0;groupIndex<data.chainBlockAcceptedTransactions.length;groupIndex++){
   const group=data.chainBlockAcceptedTransactions[groupIndex];
   for(let transactionIndex=0;transactionIndex<group.acceptedTransactions.length;transactionIndex++){
    const raw=group.acceptedTransactions[transactionIndex],id=raw.verboseData?.transactionId??raw.id;
    if(!wanted.has(id))continue;
    need(!found.has(id),'FUNDING','ordinary accepted transaction appears more than once');
    const transaction=canonicalTransaction(raw);
    const contexts=raw.inputs.map((input,index)=>{
     const e=input.verboseData?.utxoEntry;
     need(e&&e.isCoinbase===true&&(e.covenantId??null)===null,'FUNDING','complete mature coinbase populated contexts');
     return {outpoint:point(transaction.inputs[index].previousOutpoint),amount_sompi:integer(e.amount).toString(),
      script_public_key:script(e.scriptPublicKey),block_daa_score:integer(e.blockDaaScore).toString(),
      is_coinbase:true,covenant_id:null};
    });
    const tx=makeTransaction(k,transaction,contexts);tx.free();
    found.set(id,{transaction,accepted_input_contexts:contexts,accepting_block_header:group.chainBlockHeader,
     source_page_index:pageIndex,source_group_index:groupIndex,source_transaction_index:transactionIndex});
   }
  }
 }
 need(found.size===3,'FUNDING','all three actual ordinary funding bodies must be retained');
 return {schema:'kpxa-public-accepted-case-extraction/v1',sdk_verification:sdk,
  ordinary_transactions:pool[0].transaction.inputs.map(i=>found.get(i.previousOutpoint.transactionId)),
  pool_transactions:pool,network_or_submission_performed:false};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const [sp,ss,dp,ds,fp,fsum,root,output,sdkDir]=process.argv.slice(2);
  need(sp&&ss&&dp&&ds&&fp&&fsum&&root&&output,'ARGUMENT','selected public inputs required');
  const result=extract(readPublic(sp,ss),ss,readPublic(dp,ds),ds,readPublic(fp,fsum),checkedPath(root),loadSdk(sdkDir));
  fs.writeFileSync(checkedPath(output),stringify(result)+'\n',{flag:'wx',mode:0o400});
  process.stdout.write(stringify({ordinary_transactions:3,pool_transactions:result.pool_transactions.length,network_or_submission_performed:false})+'\n');
 }catch(error){process.stderr.write('public accepted-case extraction incomplete\n');process.exitCode=2;}
}
