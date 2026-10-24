// ADR0064 accepted-prefix acquisition. No owner keys, PK, signer or submit API.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {GENESIS, canonicalTransaction, contexts, integer, hex, need, point,
  pointKey, script, stringify, sha, plainHeader, validateHeader, verifyTransactionId} from './wire.mjs';
import {CHILD_DOMAIN, checkedPath, strictJson} from './selection.mjs';
export function save(file, value) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(stringify(value) + '\n');
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, raw); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return {sha256: sha(raw), bytes: raw.length};
}
export async function identity(rpc) {
  const server = await rpc.getServerInfo(), dag = await rpc.getBlockDagInfo();
  need(server.networkId === 'testnet-10' && dag.network === 'testnet-10'
    && server.serverVersion === '2.1.0' && server.isSynced === true && server.hasUtxoIndex === true,
    'NODE_IDENTITY', 'expected synced indexed TN10 version2.1.0');
  return {server, dag};
}
export async function frontier(k, rpc, min = 20) {
  const source = await identity(rpc);
  const sink = (await rpc.getBlock({hash: source.dag.sink, includeTransactions: false})).block;
  validateHeader(k, sink.header, source.dag.sink);
  let block = sink;
  const seen = new Set();
  while (integer(sink.header.blueScore) - integer(block.header.blueScore) <= BigInt(min)) {
    need(!seen.has(block.header.hash), 'HEADER', 'selected-parent cycle');
    seen.add(block.header.hash);
    const next = hex(block.verboseData.selectedParentHash, 32);
    block = (await rpc.getBlock({hash: next, includeTransactions: false})).block;
    validateHeader(k, block.header, next);
  }
  need(block.verboseData.isChainBlock === true, 'HEADER', 'frontier is not a chain block');
  return {source, sink: plainHeader(sink.header), header: plainHeader(block.header), min_confirmation_count: min};
}
function pageRecord(root, number, request, response) {
  const retained = {removedChainBlockHashes: response.removedChainBlockHashes,
    addedChainBlockHashes: response.addedChainBlockHashes,
    chainBlockAcceptedTransactions: response.chainBlockAcceptedTransactions.map(group => ({
      chainBlockHeader: plainHeader(group.chainBlockHeader), acceptedTransactions: group.acceptedTransactions}))};
  const raw = Buffer.from(stringify(retained) + '\n'), compressed = zlib.gzipSync(raw, {level: 6});
  const relative = `pages/${String(number).padStart(5, '0')}.json.gz`;
  const stored = save(path.join(root, relative), compressed);
  return {path: relative, request, decoded_sha256: sha(raw), decoded_bytes: raw.length,
    gzip_sha256: stored.sha256, gzip_bytes: stored.bytes,
    encoding: 'Decoded Full RPC with explicitly expanded parents and decimal integer strings; not wire Borsh bytes'};
}
export function pageData(root, record) {
  need(typeof record.path === 'string' && !path.isAbsolute(record.path)
    && !record.path.split('/').includes('..') && path.posix.normalize(record.path) === record.path,
    'CACHE_INTEGRITY', 'canonical relative page path required');
  const resolvedRoot = checkedPath(root), resolved = checkedPath(path.join(resolvedRoot, record.path));
  need(resolved.startsWith(resolvedRoot + path.sep), 'CACHE_INTEGRITY', 'page outside public output');
  const compressed = fs.readFileSync(resolved);
  need(sha(compressed) === record.gzip_sha256, 'CACHE_INTEGRITY', 'raw page gzip changed');
  const raw = zlib.gunzipSync(compressed);
  need(sha(raw) === record.decoded_sha256, 'CACHE_INTEGRITY', 'raw page decoded bytes changed');
  return strictJson(raw);
}
export async function scan(k, rpc, d, boundary, root, requireFounding = true) {
  const anchor = (await rpc.getBlock({hash: d.birth_start_hash, includeTransactions: false})).block;
  validateHeader(k, anchor.header, d.birth_start_hash);
  need(anchor.verboseData.isChainBlock === true, 'ANCHOR', 'birth anchor is not on selected chain');
  need(integer(anchor.header.blueScore) < integer(boundary.header.blueScore), 'ANCHOR', 'anchor must precede frontier');
  let cursor = d.birth_start_hash, reached = false;
  const seenBlocks = new Set([cursor]), pages = [], edges = new Map();
  let acceptedRows = 0;
  let founding;
  while (!reached) {
    const request = {startHash: cursor, dataVerbosityLevel: 'Full', minConfirmationCount: boundary.min_confirmation_count};
    const response = await rpc.getVirtualChainFromBlockV2(request);
    need(response && Array.isArray(response.removedChainBlockHashes)
      && Array.isArray(response.addedChainBlockHashes) && Array.isArray(response.chainBlockAcceptedTransactions),
      'TRUNCATED_PAGE', 'Full response arrays required');
    const record = pageRecord(root, pages.length, request, response); pages.push(record);
    need(Array.isArray(response.removedChainBlockHashes) && response.removedChainBlockHashes.length === 0,
      'REORG', 'removed chain blocks invalidate the scan');
    need(response.addedChainBlockHashes.length === response.chainBlockAcceptedTransactions.length,
      'TRUNCATED_PAGE', 'hash/group count mismatch');
    need(response.addedChainBlockHashes.length > 0, 'PREMATURE_END', 'finite frontier was not reached');
    for (let groupIndex = 0; groupIndex < response.chainBlockAcceptedTransactions.length; groupIndex++) {
      const group = response.chainBlockAcceptedTransactions[groupIndex];
      const hash = response.addedChainBlockHashes[groupIndex];
      need(!seenBlocks.has(hash), 'CURSOR_CYCLE', 'duplicate accepted chain block'); seenBlocks.add(hash);
      validateHeader(k, group.chainBlockHeader, hash);
      const expanded = plainHeader(group.chainBlockHeader);
      need(expanded.parentsByLevel[0]?.includes(cursor), 'TRUNCATED_PAGE', 'accepted selected-chain path skips a predecessor');
      need(Array.isArray(group.acceptedTransactions), 'TRUNCATED_PAGE', 'Full accepted transactions missing');
      const distance = integer(boundary.sink.blueScore) - integer(group.chainBlockHeader.blueScore);
      need(distance > BigInt(boundary.min_confirmation_count), 'DEPTH', 'insufficient fixed-sink depth');
      for (let txIndex = 0; txIndex < group.acceptedTransactions.length; txIndex++) {
        const tx = group.acceptedTransactions[txIndex], id = hex(tx.verboseData?.transactionId ?? tx.id, 32);
        acceptedRows++;
        const locator = {page: pages.length - 1, group: groupIndex, transaction: txIndex, id};
        if (id === d.founding_outpoint.transactionId) {
          need(!founding, 'DUPLICATE_TRANSACTION', 'accepted founding transaction repeated'); founding = locator;
        }
        for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
          const input = tx.inputs[inputIndex], key = pointKey(point(input.previousOutpoint));
          // Native W fixes witness length/push framing and the literal final redeem.
          // Index only this selected tail (or exact post-query watch points), not
          // every unrelated network spend; the full public pages are still retained.
          const tail = d.initial_redeem_hex?.slice(228);
          const candidate = d.watched_outpoints ? d.watched_outpoints.has(key)
            : key === pointKey(d.founding_outpoint) || typeof input.signatureScript === 'string'
              && tail && input.signatureScript.endsWith(tail);
          if (candidate) {
            const rows = edges.get(key) ?? []; rows.push({...locator, input_index: inputIndex}); edges.set(key, rows);
          }
        }
      }
      cursor = hash;
      if (hash === boundary.header.hash) { reached = true; break; }
    }
  }
  need(!requireFounding || founding, 'MISSING_FOUNDING', 'founding transaction absent from complete prefix');
  return {anchor: plainHeader(anchor.header), cursor, pages, edges, founding, accepted_transactions_scanned: acceptedRows};
}
export function discover(k, d, scanned, root, boundary) {
  const rows = [], seen = new Set();
  function read(locator) {
    const page = pageData(root, scanned.pages[locator.page]);
    const group = page.chainBlockAcceptedTransactions[locator.group];
    const raw = group.acceptedTransactions[locator.transaction], transaction = canonicalTransaction(raw);
    need(transaction.id === locator.id && !seen.has(transaction.id), 'POOL_GRAPH', 'pool transaction cycle/substitution');
    seen.add(transaction.id);
    const entries = contexts(raw, transaction); verifyTransactionId(k, transaction, entries);
    const distance = integer(boundary.sink.blueScore) - integer(group.chainBlockHeader.blueScore);
    const result = {transaction, accepted_input_contexts: entries, accepting_block_header: group.chainBlockHeader,
      confirmation_policy: {min_confirmation_count: boundary.min_confirmation_count,
        accepting_blue_score: group.chainBlockHeader.blueScore.toString(), sink_blue_score: boundary.sink.blueScore.toString(),
        actual_blue_score_distance: distance.toString(), passes: true}, network_id: 'testnet-10', genesis_hash_hex: GENESIS,
      sdk_transaction_id_recomputed: true, source_page_index: locator.page,
      source_group_index: locator.group, source_transaction_index: locator.transaction};
    rows.push(result); return result;
  }
  need(scanned.founding, 'MISSING_FOUNDING', 'GN3 funding absent');
  let current = read(scanned.founding), head = d.founding_outpoint, terminalCandidate = false;
  const genesis = Buffer.from(current.transaction.payload, 'hex');
  need(current.transaction.inputs.length === 3 && current.transaction.outputs.length >= 1
    && genesis.length === 1576 && genesis.subarray(0,8).equals(Buffer.from('KPX8GN01'))
    && genesis.subarray(8,40).toString('hex') === d.financial_profile_sha256
    && genesis.subarray(40,72).toString('hex') === CHILD_DOMAIN
    && genesis.subarray(72,88).toString('hex') === d.trial_id.replaceAll('-', ''),
    'GN3', 'accepted funding body does not match selected GN3 identity');
  for (;;) {
    const next = scanned.edges.get(pointKey(head)) ?? [];
    need(next.length <= 1, 'CONFLICTING_SPEND', 'multiple accepted spends of actual W head');
    if (!next.length) break;
    need(next[0].input_index === 0, 'UNSUPPORTED_POOL_INPUT', 'W input must be first');
    current = read(next[0]);
    need(current.transaction.inputs.length === 1, 'UNSUPPORTED_POOL_INPUT', 'W spends have one input');
    const payload = Buffer.from(current.transaction.payload, 'hex');
    const first = current.transaction.outputs[0];
    need(first, 'POOL_GRAPH', 'W successor/payout missing');
    need(payload.length >= 404 && payload.subarray(16,48).toString('hex') === CHILD_DOMAIN,
      'UNSUPPORTED_BODY', 'selected lifecycle domain required');
    const remaining = payload.readBigUInt64LE(380), payout = payload.readBigUInt64LE(396);
    if (payload.subarray(0,8).equals(Buffer.from('KPX8PB01'))) {
      need(payload.length === 10780 && payload.subarray(8,16).equals(Buffer.from([1,0,3,0,6,0,0,0]))
        && remaining > 0n && payout === 0n && current.transaction.outputs.length === 1,
        'UNSUPPORTED_BODY', 'exact three-spend/six-output mixed continuation required');
    } else {
      need(payload.length === 1632 && payload.subarray(0,8).equals(Buffer.from('KPX8XB01'))
        && payload.subarray(8,16).equals(Buffer.from([1,0,1,0,0,0,1,0])) && payout > 0n,
        'UNSUPPORTED_BODY', 'exact one-note direct exit required');
      const destination = payload.subarray(404,440).toString('hex');
      const paid = current.transaction.outputs.at(-1);
      need(paid.value === payout.toString() && paid.scriptPublicKey === destination
        && current.transaction.outputs.length === (remaining === 0n ? 1 : 2),
        'UNSUPPORTED_BODY', 'exit payout/output layout differs');
      if (remaining === 0n) { terminalCandidate = true; head = null; break; }
    }
    need(first.value === remaining.toString(), 'POOL_GRAPH', 'remaining reserve differs');
    const nextRedeem = Buffer.concat([Buffer.from('4c70','hex'),payload.subarray(268,380),
      Buffer.from(d.initial_redeem_hex.slice(228),'hex')]);
    const nextScript = k.payToScriptHashScript(nextRedeem);
    try { need(script(nextScript) === first.scriptPublicKey, 'POOL_GRAPH',
      'selected next state and immutable policy do not match continuing reserve'); }
    finally { nextScript.free(); }
    head = {transactionId: current.transaction.id, index: 0};
  }
  return {rows, head, terminal_candidate: terminalCandidate};
}
export function entry(raw) {
  const value = raw.entry ?? raw;
  return {outpoint: point(value.outpoint), amount_sompi: integer(value.amount).toString(),
    script_public_key: script(value.scriptPublicKey), block_daa_score: integer(value.blockDaaScore).toString(),
    is_coinbase: value.isCoinbase, covenant_id: value.covenantId?.toString() ?? null};
}
export async function currentView(k, rpc, discovered) {
  const source = await identity(rpc);
  const checkpoint = {network: 'testnet-10', expected_genesis: GENESIS,
    observed_at: new Date().toISOString(), observed_sink: source.dag.sink};
  const expected = new Map();
  for (const row of discovered.rows) {
    for (const input of row.accepted_input_contexts) expected.set(pointKey(input.outpoint), input);
    row.transaction.outputs.forEach((output, index) => {
      const outpoint = {transactionId: row.transaction.id, index};
      expected.set(pointKey(outpoint), {outpoint, amount_sompi: output.value, script_public_key: output.scriptPublicKey});
    });
  }
  const scripts = [...new Set([...expected.values()].map(item => item.script_public_key))], entries = [];
  for (let start = 0; start < scripts.length; start += 128) {
    const addresses = scripts.slice(start, start + 128).map(spk => {
      const address = k.addressFromScriptPublicKey(spk, 'testnet-10');
      need(address, 'UNSUPPORTED_SCRIPT_QUERY', 'no address for exact script');
      try { return address.toString(); } finally { address.free(); }
    });
    const result = await rpc.getUtxosByAddresses({addresses}); entries.push(...result.entries.map(entry));
  }
  const byPoint = new Map();
  for (const value of entries) {
    const key = pointKey(value.outpoint);
    need(!byPoint.has(key), 'DUPLICATE_UTXO', 'UTXO response duplicates an outpoint'); byPoint.set(key, value);
  }
  const queries = [...expected.values()].map(value => {
    const actual = byPoint.get(pointKey(value.outpoint)) ?? null;
    if (actual) need(actual.amount_sompi === value.amount_sompi && actual.script_public_key === value.script_public_key
      && actual.is_coinbase === false && actual.covenant_id === null, 'UTXO_SUBSTITUTION', 'current UTXO differs');
    return {outpoint: value.outpoint, amount_sompi: value.amount_sompi,
      script_public_key: value.script_public_key, queried: true, entry: actual};
  });
  if (discovered.head) need(byPoint.has(pointKey(discovered.head)), 'MISSING_CURRENT_HEAD',
    'nonterminal pool head is not currently unspent');
  return {checkpoint, queries, observed_at: new Date().toISOString()};
}
export async function postQuery(k, rpc, d, boundary, discovered, root, view) {
  const next = await frontier(k, rpc), related = [];
  let pages = [];
  if (next.header.hash !== boundary.header.hash) {
    const postRoot = path.join(root, 'post-query'); fs.mkdirSync(postRoot, {mode: 0o700});
    const scanned = await scan(k, rpc, {birth_start_hash: boundary.header.hash,
      founding_outpoint: {transactionId: '00'.repeat(32), index: 0},
      watched_outpoints: new Set(view.queries.filter(query => query.entry !== null).map(query => pointKey(query.outpoint)))}, next, postRoot, false);
    pages = scanned.pages.map(record => ({...record, path: path.posix.join('post-query', record.path)}));
    // Every queried live point matters, including payouts after terminal exit.
    for (const query of view.queries.filter(query => query.entry !== null))
      related.push(...(scanned.edges.get(pointKey(query.outpoint)) ?? []).map(row => row.id));
  }
  need(related.length === 0, 'STALE_FRONTIER', 'pool advanced after fixed recovery frontier');
  const fresh = await identity(rpc);
  const anchor = (await rpc.getBlock({hash: boundary.header.hash, includeTransactions: false})).block;
  validateHeader(k, anchor.header, boundary.header.hash);
  need(anchor.verboseData.isChainBlock === true, 'REORG', 'frontier no longer selected');
  const birth = (await rpc.getBlock({hash:d.birth_start_hash, includeTransactions:false})).block;
  validateHeader(k, birth.header, d.birth_start_hash);
  need(birth.verboseData.isChainBlock === true, 'REORG', 'birth anchor no longer selected');
  return {removed_chain_block_hashes: [], related_transactions: related, pages,
    start_hash: boundary.header.hash, frontier: next.header, initial_sink: next.sink,
    min_confirmation_count: next.min_confirmation_count, completed: true,
    watched_outpoints: view.queries.filter(query => query.entry !== null).map(query => query.outpoint),
    observed_sink: fresh.dag.sink, server: fresh.server,
    checked_at: new Date().toISOString(), rpc_views_are_atomic: false};
}
