// Fresh new-profile transition acquisition. No genesis codec, signer or submit.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {frontier, scan, pageData, currentView, postQuery, save} from '../../../chain/acquire.mjs';
import {connectReadOnlyBorsh} from '../../../chain/readonly_borsh_observed_retry_strict_rpc.mjs';
import {canonical, strictJson, readPublic, checkedPath} from '../../../chain/selection.mjs';
import {GENESIS, SDK_PINS, canonicalTransaction, contexts, point, pointKey, script,
  verifyTransactionId, integer, hex, need, sha, stringify, loadSdk, validateHeader,
  plainHeader} from '../../../chain/wire.mjs';

function equal(left, right, code) {need(canonical(left) === canonical(right), code, 'public bytes differ');}
function exact(value, keys) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(','), 'REQUEST', 'exact request fields');
}
export function request(raw) {
  const r = strictJson(raw);
  exact(r, ['schema','nonce_hex32','request_sha256','selection_sha256','birth_start_hash',
    'head','context','immutable_tail_hex','candidate_transaction_id']);
  need(r.schema === 'kpb-settlement-acquisition-request/v1', 'REQUEST', 'new-profile request');
  for (const key of ['nonce_hex32','request_sha256','selection_sha256','birth_start_hash','candidate_transaction_id']) hex(r[key],32);
  exact(r.head, ['outpoint','state_hex112','reserve_sompi']);point(r.head.outpoint);hex(r.head.state_hex112,112);integer(r.head.reserve_sompi);
  exact(r.context, ['chain_hex32','pool_hex32','profile_hex32','domain_hex32','service_hex32','epoch_hex32']);
  Object.values(r.context).forEach(value=>hex(value,32));hex(r.immutable_tail_hex);
  need(r.context.chain_hex32 === GENESIS && r.immutable_tail_hex.length > 0, 'REQUEST', 'selected context');
  return r;
}
function state(payload, next, payment) {
  const [cm,n,nf,m] = !next ? [204,268,236,272]
    : payment ? [284,348,316,352] : [204,268,316,348];
  return Buffer.concat([Buffer.from('KPBAST01'),payload.subarray(104,136),
    payload.subarray(cm,cm+32),payload.subarray(n,n+4),payload.subarray(nf,nf+32),payload.subarray(m,m+4)]);
}
function acceptedAt(k,scanned,locator,root,boundary) {
  const page=pageData(root,scanned.pages[locator.page]),group=page.chainBlockAcceptedTransactions[locator.group];
  const raw=group.acceptedTransactions[locator.transaction],transaction=canonicalTransaction(raw),entries=contexts(raw,transaction);
  need(transaction.id===locator.id,'PRODUCER','accepted locator differs');verifyTransactionId(k,transaction,entries);
  return {transaction,accepted_input_contexts:entries,accepting_block_header:group.chainBlockHeader,
    source_page_index:locator.page,source_group_index:locator.group,source_transaction_index:locator.transaction,
    confirmation_policy:{min_confirmation_count:20,actual_blue_score_distance:(integer(boundary.sink.blueScore)-integer(group.chainBlockHeader.blueScore)).toString()}};
}
export function discover(k, r, scanned, root, boundary) {
  const rows = [], seen = new Set();
  let head = point(r.head.outpoint), previousState = r.head.state_hex112, reserve = integer(r.head.reserve_sompi);
  let previousLocator = scanned.founding;
  need(previousLocator, 'PRODUCER', 'accepted locked-head producer required');
  const tail = Buffer.from(r.immutable_tail_hex,'hex');
  while (head) {
    const candidates = scanned.edges.get(pointKey(head)) ?? [];
    need(candidates.length <= 1, 'CONFLICTING_SPEND', 'multiple accepted spends of the exact head');
    if (!candidates.length) break;
    const locator = candidates[0];need(locator.input_index === 0, 'POOL_GRAPH', 'selected input index');
    // An accepting block may include dependencies from several merged blocks.
    // Their raw transaction order need not be topological; block order must be.
    need(locator.page > previousLocator.page || locator.page === previousLocator.page
      && locator.group >= previousLocator.group, 'POOL_GRAPH', 'spend precedes accepted producer');
    previousLocator = locator;
    const page = pageData(root, scanned.pages[locator.page]);
    const group = page.chainBlockAcceptedTransactions[locator.group], raw = group.acceptedTransactions[locator.transaction];
    const transaction = canonicalTransaction(raw), entries = contexts(raw, transaction);
    need(transaction.id === locator.id && !seen.has(transaction.id), 'POOL_GRAPH', 'cycle or substituted transaction');
    seen.add(transaction.id);verifyTransactionId(k,transaction,entries);
    need(transaction.inputs.length === 1 && entries.length === 1
      && pointKey(transaction.inputs[0].previousOutpoint) === pointKey(head), 'POOL_GRAPH', 'exact consumed head');
    if (!rows.length) need(transaction.id === r.candidate_transaction_id, 'CANDIDATE', 'another transition won the head');
    const payload = Buffer.from(transaction.payload,'hex');
    const payment = payload.subarray(0,8).equals(Buffer.from('KPBAEF01'));
    need(payment ? payload.length === 10492
      : payload.length === 1604 && payload.subarray(0,8).equals(Buffer.from('KPBXEF01')), 'BODY', 'new-profile body only');
    for (const [offset,key] of [[8,'chain_hex32'],[40,'pool_hex32'],[72,'profile_hex32'],[104,'domain_hex32'],[136,'service_hex32']])
      need(payload.subarray(offset,offset+32).toString('hex') === r.context[key], 'BODY', 'selected context differs');
    need(state(payload,false,payment).toString('hex') === previousState
      && payload.readBigUInt64LE(276) === reserve && integer(entries[0].amount_sompi) === reserve,
      'POOL_GRAPH', 'old state or actual reserve differs');
    const frame = Buffer.from(transaction.inputs[0].signatureScript,'hex');
    need(frame.length >= 247 && frame[0] === 0x4c && frame[1] === 128 && frame[130] === 0x4d
      && frame.length === 133 + frame.readUInt16LE(131), 'WITNESS', 'canonical proof128/redeem framing');
    const redeem = Buffer.concat([Buffer.from('4c70','hex'),Buffer.from(previousState,'hex'),tail]);
    need(frame.subarray(133).equals(redeem), 'WITNESS', 'same exact immutable policy');
    const oldSpk = k.payToScriptHashScript(redeem);
    try {need(script(oldSpk) === entries[0].script_public_key,'POOL_GRAPH','actual input script differs');}
    finally {oldSpk.free();}
    const nextState = state(payload,true,payment), remaining = payload.readBigUInt64LE(payment ? 356 : 352);
    need(transaction.outputs.length === (payment || remaining === 0n ? 1 : 2), 'POOL_GRAPH', 'output count');
    if (remaining) {
      need(integer(transaction.outputs[0].value) === remaining, 'POOL_GRAPH', 'reserve output value');
      const successor = k.payToScriptHashScript(Buffer.concat([Buffer.from('4c70','hex'),nextState,tail]));
      try {need(script(successor) === transaction.outputs[0].scriptPublicKey,'POOL_GRAPH','successor state/policy');}
      finally {successor.free();}
      head = {transactionId:transaction.id,index:0};
    } else {
      need(!payment,'POOL_GRAPH','payment cannot terminate reserve');head = null;
    }
    const distance = integer(boundary.sink.blueScore)-integer(group.chainBlockHeader.blueScore);
    rows.push({transaction,accepted_input_contexts:entries,accepting_block_header:group.chainBlockHeader,
      source_page_index:locator.page,source_group_index:locator.group,source_transaction_index:locator.transaction,
      confirmation_policy:{min_confirmation_count:20,actual_blue_score_distance:distance.toString()},
      mode:payment?'payment':'exit'});
    previousState = nextState.toString('hex');reserve = remaining;
  }
  need(rows.length > 0 && rows[0].transaction.id === r.candidate_transaction_id,'CANDIDATE','exact candidate absent');
  return {rows,head,state_hex112:previousState,reserve_sompi:reserve.toString(),terminal_candidate:head===null};
}
function descriptor(r) {return {birth_start_hash:r.birth_start_hash,founding_outpoint:r.head.outpoint,
  initial_redeem_hex:'4c70'+r.head.state_hex112+r.immutable_tail_hex};}

// Rebuild the retained graph independently; locator booleans are not authority.
export function retainedScan(k,r,boundary,pages,root) {
  need(Array.isArray(pages),'COVERAGE','retained pages');
  let cursor=r.birth_start_hash,reached=false,accepted=0,founding;
  const seen=new Set([cursor]), paths=new Set(), edges=new Map(), d=descriptor(r);
  for(let pageIndex=0;pageIndex<pages.length;pageIndex++) {
    need(!reached,'COVERAGE','extra page after fixed frontier');const record=pages[pageIndex];
    need(!paths.has(record.path),'COVERAGE','duplicate page path');paths.add(record.path);
    equal(record.request,{startHash:cursor,dataVerbosityLevel:'Full',minConfirmationCount:20},'COVERAGE');
    const data=pageData(root,record);
    need(Array.isArray(data.removedChainBlockHashes)&&data.removedChainBlockHashes.length===0,'REORG','removed selected blocks');
    need(Array.isArray(data.addedChainBlockHashes)&&Array.isArray(data.chainBlockAcceptedTransactions)
      &&data.addedChainBlockHashes.length===data.chainBlockAcceptedTransactions.length&&data.addedChainBlockHashes.length>0,
      'COVERAGE','complete Full groups');
    for(let gi=0;gi<data.chainBlockAcceptedTransactions.length;gi++) {
      const group=data.chainBlockAcceptedTransactions[gi],hash=hex(data.addedChainBlockHashes[gi],32);
      need(!seen.has(hash),'COVERAGE','duplicate selected block');seen.add(hash);validateHeader(k,group.chainBlockHeader,hash);
      const header=plainHeader(group.chainBlockHeader);
      need(header.parentsByLevel[0]?.includes(cursor),'COVERAGE','missing selected predecessor');
      need(integer(boundary.sink.blueScore)-integer(header.blueScore)>20n,'DEPTH','fixed-sink confirmation depth');
      need(Array.isArray(group.acceptedTransactions),'COVERAGE','Full bodies');
      group.acceptedTransactions.forEach((tx,ti)=>{
        const id=hex(tx.verboseData?.transactionId??tx.id,32);accepted++;
        if(id===r.head.outpoint.transactionId){need(!founding,'PRODUCER','duplicate head producer');founding={page:pageIndex,group:gi,transaction:ti,id};}
        need(Array.isArray(tx.inputs),'COVERAGE','Full inputs');
        tx.inputs.forEach((input,ii)=>{
          const key=pointKey(point(input.previousOutpoint));
          if(key===pointKey(d.founding_outpoint)||typeof input.signatureScript==='string'&&input.signatureScript.endsWith(r.immutable_tail_hex)) {
            const rows=edges.get(key)??[];rows.push({page:pageIndex,group:gi,transaction:ti,id,input_index:ii});edges.set(key,rows);
          }
        });
      });
      cursor=hash;if(cursor===boundary.header.hash){reached=true;break;}
    }
  }
  need(reached&&founding,'COVERAGE','finite frontier and accepted head producer required');return {cursor,pages,edges,founding,accepted_transactions_scanned:accepted};
}
export function verifyRetained(k,r,value,root) {
  need(value.schema==='kpb-live-settlement-acquisition/v1'&&value.request_sha256===r.request_sha256
    &&value.selection_sha256===r.selection_sha256&&value.nonce_hex32===r.nonce_hex32
    &&value.network_id==='testnet-10'&&value.genesis_hash_hex===GENESIS,'BUNDLE','exact live request');
  equal(value.sdk_pins,SDK_PINS,'SDK');const c=value.coverage;
  need(c.start_hash===r.birth_start_hash&&c.end_cursor===c.frontier.hash&&c.complete===true&&c.min_confirmation_count===20,'COVERAGE','fixed complete prefix');
  for(const h of [c.anchor_header,c.frontier,c.initial_sink])validateHeader(k,h,h.hash);
  need(c.anchor_header.hash===r.birth_start_hash&&integer(c.anchor_header.blueScore)<integer(c.frontier.blueScore)
    &&integer(c.initial_sink.blueScore)-integer(c.frontier.blueScore)>20n,'DEPTH','anchor/frontier/sink');
  const boundary={header:c.frontier,sink:c.initial_sink,min_confirmation_count:20};
  const rebuilt=retainedScan(k,r,boundary,value.pages,root),found=discover(k,r,rebuilt,root,boundary);
  equal(acceptedAt(k,rebuilt,rebuilt.founding,root,boundary),value.locked_head_producer,'EXACT_HEAD_PRODUCER');
  equal(found.rows,value.transactions,'EXACT_FULL_ROWS');equal(found.head,value.head,'EXACT_HEAD');
  need(found.state_hex112===value.state_hex112&&found.reserve_sompi===value.reserve_sompi,'EXACT_HEAD','state/reserve');
  equal(value.current_view.queries,value.current_view.final_requery.queries,'CURRENT_VIEW');
  for(const view of [value.current_view,value.current_view.final_requery])
    need(view.checkpoint?.network==='testnet-10'&&view.checkpoint?.expected_genesis===GENESIS,
      'CURRENT_VIEW','selected testnet checkpoint');
  const expected=new Map(),consumed=new Set();
  for(const row of found.rows) {
    for(const item of row.accepted_input_contexts){expected.set(pointKey(item.outpoint),item);consumed.add(pointKey(item.outpoint));}
    row.transaction.outputs.forEach((out,index)=>{const at={transactionId:row.transaction.id,index};expected.set(pointKey(at),{outpoint:at,amount_sompi:out.value,script_public_key:out.scriptPublicKey});});
  }
  const queries=new Map();
  for(const q of value.current_view.queries) {
    const key=pointKey(point(q.outpoint)),want=expected.get(key);need(want&&!queries.has(key)&&q.queried===true,'CURRENT_VIEW','exact unique query');
    need(integer(q.amount_sompi)===integer(want.amount_sompi)&&q.script_public_key===want.script_public_key,'CURRENT_VIEW','expected output');
    if(q.entry!==null)need(pointKey(point(q.entry.outpoint))===key&&integer(q.entry.amount_sompi)===integer(want.amount_sompi)
      &&q.entry.script_public_key===want.script_public_key&&q.entry.is_coinbase===false&&q.entry.covenant_id===null,'CURRENT_VIEW','actual UTXO');
    if(q.entry!==null)integer(q.entry.block_daa_score);
    if(consumed.has(key))need(q.entry===null,'CURRENT_VIEW','consumed point still unspent');queries.set(key,q);
  }
  need(queries.size===expected.size&&(!found.head||queries.get(pointKey(found.head))?.entry!==null),'CURRENT_VIEW','complete actual current head');
  const post=value.current_view.post_query_delta,live=new Set([...queries.values()].filter(q=>q.entry!==null).map(q=>pointKey(q.outpoint)));
  need(post.completed===true&&post.start_hash===c.frontier.hash&&post.min_confirmation_count===20
    &&post.removed_chain_block_hashes.length===0&&post.related_transactions.length===0&&post.rpc_views_are_atomic===false,'POST_QUERY','complete race/reorg check');
  need(post.server?.networkId==='testnet-10'&&post.server?.serverVersion==='2.1.0'
    &&post.server?.isSynced===true&&post.server?.hasUtxoIndex===true,'POST_QUERY','selected validating node');
  equal([...post.watched_outpoints.map(pointKey)].sort(),[...live].sort(),'POST_QUERY');
  validateHeader(k,post.frontier,post.frontier.hash);validateHeader(k,post.initial_sink,post.initial_sink.hash);
  need(integer(post.frontier.blueScore)>=integer(c.frontier.blueScore)
    &&integer(post.initial_sink.blueScore)-integer(post.frontier.blueScore)>20n,'POST_QUERY','fresh fixed frontier');
  // The maintained postQuery scanner checks all live points, not new-profile
  // body tags. Replay its retained delta with the same generic scan rules.
  if(post.frontier.hash!==c.frontier.hash) {
    const d={birth_start_hash:c.frontier.hash,watched_outpoints:live};let cursor=d.birth_start_hash,reached=false;
    const seen=new Set([cursor]);
    for(const record of post.pages) {
      need(!reached,'POST_QUERY','extra delta page');equal(record.request,{startHash:cursor,dataVerbosityLevel:'Full',minConfirmationCount:20},'POST_QUERY');
      const data=pageData(root,record);need(data.removedChainBlockHashes.length===0&&data.addedChainBlockHashes.length===data.chainBlockAcceptedTransactions.length&&data.addedChainBlockHashes.length>0,'POST_QUERY','complete delta');
      for(let gi=0;gi<data.chainBlockAcceptedTransactions.length;gi++) {
        const g=data.chainBlockAcceptedTransactions[gi],hash=hex(data.addedChainBlockHashes[gi],32);need(!seen.has(hash),'POST_QUERY','delta cycle');seen.add(hash);validateHeader(k,g.chainBlockHeader,hash);
        need(plainHeader(g.chainBlockHeader).parentsByLevel[0]?.includes(cursor)&&integer(post.initial_sink.blueScore)-integer(g.chainBlockHeader.blueScore)>20n,'POST_QUERY','delta predecessor/depth');
        for(const tx of g.acceptedTransactions)for(const input of tx.inputs)need(!live.has(pointKey(point(input.previousOutpoint))),'POST_QUERY','live point spent after first query');
        cursor=hash;if(cursor===post.frontier.hash){reached=true;break;}
      }
    }
    need(reached,'POST_QUERY','delta frontier absent');
  } else need(post.pages.length===0,'POST_QUERY','unexpected delta pages');
  return found;
}
async function main(argv) {
  need(fs.existsSync('/kpb-public-only'),'NAMESPACE','public role required');
  const offline=argv[0]==='--verify-retained';if(offline)argv=argv.slice(1);
  need(argv.length===(offline?12:10)&&argv[0]==='--selection'&&argv[2]==='--selection-sha256'
    &&argv[4]==='--request'&&argv[6]==='--request-sha256'&&argv[8]==='--output'
    &&(!offline||argv[10]==='--acquisition-sha256'),'ARGUMENT','closed acquisition arguments');
  const [,_selection,,selectionSha,,requestFile,,requestSha,,output,,acquisitionSha]=argv;
  const selected=strictJson(readPublic(_selection,selectionSha));
  need(selected.schema==='kpb-live-settlement-selection/v1'&&selected.selected===true,'SELECTION','selected adapter');
  const r=request(readPublic(requestFile,requestSha)),k=loadSdk(selected.sdk_directory);checkedPath(output);
  if(offline) {
    const value=strictJson(readPublic(path.join(output,'ACQUISITION.json'),acquisitionSha));
    verifyRetained(k,r,value,output);
    process.stdout.write(stringify({schema:'kpb-retained-settlement-evidence-check/v1',
      acquisition_sha256:acquisitionSha,request_sha256:r.request_sha256,
      financial_settlement_authority:false})+'\n');return;
  }
  need(!fs.existsSync(output),'OUTPUT','fresh acquisition');fs.mkdirSync(output,{mode:0o700});
  const connection=await connectReadOnlyBorsh(k,selected.rpc_url,{path:_selection,sha256:selectionSha},path.join(output,'PUBLIC-BORSH-EVENTS.jsonl'));
  try {
    const boundary=await frontier(k,connection.rpc),d=descriptor(r);
    const scanned=await scan(k,connection.rpc,d,boundary,output,true),found=discover(k,r,scanned,output,boundary);
    const view=await currentView(k,connection.rpc,found);view.post_query_delta=await postQuery(k,connection.rpc,d,boundary,found,output,view);
    view.final_requery=await currentView(k,connection.rpc,found);equal(view.queries,view.final_requery.queries,'CURRENT_VIEW');
    const value={schema:'kpb-live-settlement-acquisition/v1',nonce_hex32:r.nonce_hex32,request_sha256:r.request_sha256,selection_sha256:r.selection_sha256,
      network_id:'testnet-10',genesis_hash_hex:GENESIS,sdk_pins:SDK_PINS,transactions:found.rows,head:found.head,state_hex112:found.state_hex112,reserve_sompi:found.reserve_sompi,
      locked_head_producer:acceptedAt(k,scanned,scanned.founding,output,boundary),
      coverage:{start_hash:r.birth_start_hash,anchor_header:scanned.anchor,frontier:boundary.header,initial_sink:boundary.sink,end_cursor:scanned.cursor,complete:true,min_confirmation_count:20},
      pages:scanned.pages,current_view:view,observed_at:new Date().toISOString(),trust:'SELECTED_VALIDATING_NODE_FINITE_PREFIX',rpc_views_are_atomic:false};
    verifyRetained(k,r,value,output);save(path.join(output,'ACQUISITION.json'),value);
    process.stdout.write(stringify({schema:'kpb-live-acquisition-complete/v1',request_sha256:r.request_sha256,acquisition_sha256:sha(fs.readFileSync(path.join(output,'ACQUISITION.json'))),retained_replay_performed:true})+'\n');
  } finally {await connection.close();}
}
if(process.argv[1]===fileURLToPath(import.meta.url))main(process.argv.slice(2)).catch(()=>{process.stderr.write('kpb-settlement-acquisition: incomplete\n');process.exitCode=2;});
