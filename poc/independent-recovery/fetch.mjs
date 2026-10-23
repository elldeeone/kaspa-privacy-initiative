#!/usr/bin/env node
// Read-only KPX2 chain discovery. No wallet, signer, PK or submission API.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

export const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
export const SDK_PINS = {
  'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
};
const SDK_DIRECTORY = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const POLICY_MANIFEST_SHA256 = '5f8e5354565c0545cfd6e6455958cbf955daa14d7982ac5c338673cc5a5a19bf';
const POLICY_TEMPLATE_SHA256 = '8b0e6dd802b58400fdfd9fcc11cff2ef6e4a27659c973ff3d0b1bf946fcfda46';
const DEFAULT_RPCS = [
  'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh',
];
export const DESCRIPTOR_FIELDS = ['schema', 'network_id', 'genesis_hash_hex', 'domain_hex32',
  'founding_outpoint', 'birth_start_hash', 'initial_redeem_hex', 'vk_hex328', 'immutable_policy_sha256'];
export const stringify = value => JSON.stringify(value, (_, x) => typeof x === 'bigint' ? x.toString() : x);
export const sha = value => crypto.createHash('sha256').update(value).digest('hex');
export const pointKey = point => `${point.transactionId}:${point.index}`;
export class Incomplete extends Error {
  constructor(category, message) { super(message); this.category = category; }
}
function need(ok, category, message) { if (!ok) throw new Incomplete(category, message); }
export function canonicalDescriptor(value) {
  const ordered = x => Array.isArray(x) ? x.map(ordered) : x && typeof x === 'object'
    ? Object.fromEntries(Object.keys(x).sort().map(key => [key, ordered(x[key])])) : x;
  return stringify(ordered(value));
}
export function hex(value, bytes) {
  need(typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value)
    && (bytes === undefined || value.length === bytes * 2), 'MALFORMED', 'noncanonical hex');
  return value;
}
export function integer(value, bits = 64) {
  need((typeof value === 'bigint' || typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
    || typeof value === 'number' && Number.isSafeInteger(value)), 'MALFORMED', 'integer encoding');
  const result = BigInt(value);
  need(result >= 0n && result < (1n << BigInt(bits)), 'MALFORMED', 'integer range');
  return result;
}
export function script(value) {
  const result = typeof value === 'string' ? value
    : Number(integer(value.version, 16)).toString(16).padStart(4, '0') + value.script;
  hex(result);
  need(result.startsWith('0000'), 'UNSUPPORTED_SCRIPT_VERSION', 'script version must be zero');
  return result;
}
function point(value) {
  // Pinned SDK classes store fields behind WASM getters; their explicit
  // serializer returns the same two canonical public fields as plain RPC JSON.
  if (value && typeof value.toJSON === 'function') value = value.toJSON();
  need(value && Object.keys(value).sort().join(',') === 'index,transactionId', 'MALFORMED', 'outpoint fields');
  return {transactionId: hex(value.transactionId, 32), index: Number(integer(value.index, 32))};
}
export function descriptor(value) {
  need(value && Object.keys(value).sort().join(',') === [...DESCRIPTOR_FIELDS].sort().join(','),
    'DESCRIPTOR', 'descriptor fields');
  need(value.schema === 'kpx2-recovery-descriptor/v1' && value.network_id === 'testnet-10'
    && value.genesis_hash_hex === GENESIS, 'DESCRIPTOR', 'TN10 descriptor required');
  hex(value.domain_hex32, 32); hex(value.birth_start_hash, 32); hex(value.vk_hex328, 328);
  hex(value.immutable_policy_sha256, 32); hex(value.initial_redeem_hex);
  point(value.founding_outpoint);
  need(value.founding_outpoint.index === 0, 'DESCRIPTOR', 'pool founding output must be zero');
  const redeem = Buffer.from(value.initial_redeem_hex, 'hex');
  need(redeem.length > 114 && redeem.subarray(0, 10).toString('hex') === '4c704b50583253543031'
    && redeem.subarray(10, 42).toString('hex') === value.domain_hex32,
    'DESCRIPTOR', 'initial State112/domain framing');
  need(sha(redeem.subarray(114)) === value.immutable_policy_sha256,
    'DESCRIPTOR', 'immutable policy hash mismatch');
  approvedPolicy(value);
  return value;
}
export function approvedPolicy(value) {
  const raw = fs.readFileSync(path.join(HERE, 'kpx2-policy-template.json'));
  need(sha(raw) === POLICY_MANIFEST_SHA256, 'POLICY_IDENTITY', 'approved policy manifest changed');
  const manifest = JSON.parse(raw), template = fs.readFileSync(path.join(HERE, 'kpx2-policy-template.bin'));
  need(template.length === 22274 && sha(template) === POLICY_TEMPLATE_SHA256,
    'POLICY_IDENTITY', 'approved policy template changed');
  for (const slot of manifest.patch_slots) {
    const replacement = Buffer.from(slot.kind === 'domain' ? value.domain_hex32 : value.vk_hex328, 'hex');
    need(replacement.length === slot.bytes
      && template.subarray(slot.data_offset, slot.data_offset + slot.bytes).every(x => x === 0),
      'POLICY_IDENTITY', 'invalid canonical template patch');
    replacement.copy(template, slot.data_offset);
  }
  need(template.equals(Buffer.from(value.initial_redeem_hex, 'hex').subarray(114))
    && sha(template) === value.immutable_policy_sha256, 'UNAPPROVED_POLICY', 'policy differs from approved full template');
}
export function loadSdk(directory = SDK_DIRECTORY) {
  for (const [name, hash] of Object.entries(SDK_PINS))
    need(sha(fs.readFileSync(path.join(directory, name))) === hash, 'SDK_IDENTITY', `SDK pin ${name}`);
  return createRequire(import.meta.url)(path.join(directory, 'kaspa.js'));
}
export function plainHeader(raw) {
  const parents = raw.parentsByLevel;
  let expanded;
  if (Array.isArray(parents)) expanded = parents;
  else if (parents && typeof parents.toExpanded === 'function') {
    try { expanded = parents.toExpanded(); } finally { parents.free(); }
  }
  need(Array.isArray(expanded) && expanded.every(Array.isArray), 'HEADER_ENCODING',
    'full expanded header parents required; lossy historical {} is not reconstructible');
  const work = typeof raw.blueWork === 'bigint' ? integer(raw.blueWork, 192)
    : typeof raw.blueWork === 'string' && /^[0-9a-f]{48}$/.test(raw.blueWork)
      ? BigInt('0x' + raw.blueWork) : null;
  need(work !== null, 'HEADER_ENCODING', 'blue work must be SDK bigint or native fixed-width hex');
  return {hash: hex(raw.hash, 32), version: Number(integer(raw.version, 16)),
    parentsByLevel: expanded.map(level => level.map(hash => hex(hash, 32))),
    hashMerkleRoot: hex(raw.hashMerkleRoot, 32), acceptedIdMerkleRoot: hex(raw.acceptedIdMerkleRoot, 32),
    utxoCommitment: hex(raw.utxoCommitment, 32), timestamp: integer(raw.timestamp).toString(),
    bits: Number(integer(raw.bits, 32)), nonce: integer(raw.nonce).toString(),
    daaScore: integer(raw.daaScore).toString(), blueScore: integer(raw.blueScore).toString(),
    blueWork: work.toString(16).padStart(48, '0'), pruningPoint: hex(raw.pruningPoint, 32)};
}
export function headerHash(k, raw) {
  const restored = plainHeader(raw);
  // Deliberately discard the RPC's cached identity before official finalize.
  restored.hash = '00'.repeat(32);
  for (const name of ['timestamp', 'nonce', 'daaScore', 'blueScore']) restored[name] = integer(raw[name]);
  restored.blueWork = BigInt('0x' + restored.blueWork);
  const header = new k.Header(restored);
  try { return header.finalize(); } finally { header.free(); }
}
function validateHeader(k, raw, expected) {
  hex(raw.hash, 32);
  need(raw.hash === expected && headerHash(k, raw) === expected, 'HEADER', 'header hash mismatch');
  integer(raw.blueScore);
}
export function canonicalTransaction(t) {
  need(t.version === 1, 'UNSUPPORTED_TRANSACTION', 'pool transaction version must be one');
  if (t.mass !== undefined && t.storageMass !== undefined)
    need(integer(t.mass) === integer(t.storageMass), 'MALFORMED', 'mass aliases differ');
  return {version: 1, id: hex(t.verboseData?.transactionId ?? t.id, 32),
    inputs: t.inputs.map(input => {
      need(input.computeBudget !== undefined, 'MALFORMED', 'missing compute budget');
      if (input.sigOpCount !== undefined && input.sigOpCount !== null)
        need(input.sigOpCount === 0, 'MALFORMED', 'version-one sigOpCount');
      return {previousOutpoint: point(input.previousOutpoint), signatureScript: hex(input.signatureScript),
        sequence: integer(input.sequence).toString(), computeBudget: Number(integer(input.computeBudget, 16))};
    }),
    outputs: t.outputs.map(output => {
      need((output.covenant ?? null) === null, 'UNSUPPORTED_COVENANT', 'KPX2 output covenant must be absent');
      return {value: integer(output.value).toString(), scriptPublicKey: script(output.scriptPublicKey), covenant: null};
    }),
    lockTime: integer(t.lockTime).toString(), subnetworkId: hex(t.subnetworkId, 20),
    gas: integer(t.gas).toString(), payload: hex(t.payload), storageMass: integer(t.storageMass ?? t.mass).toString()};
}
export function contexts(raw, transaction) {
  need(raw.inputs.length === transaction.inputs.length, 'MALFORMED', 'input context count');
  return raw.inputs.map((input, index) => {
    const entry = input.verboseData?.utxoEntry;
    need(entry && entry.isCoinbase === false && (entry.covenantId ?? null) === null,
      'INPUT_CONTEXT', 'Full populated noncoinbase input context required');
    return {outpoint: transaction.inputs[index].previousOutpoint,
      amount_sompi: integer(entry.amount).toString(), script_public_key: script(entry.scriptPublicKey),
      block_daa_score: integer(entry.blockDaaScore).toString(), is_coinbase: false, covenant_id: null};
  });
}
export function verifyTransactionId(k, transaction, entries) {
  const tx = new k.Transaction({...transaction,
    inputs: transaction.inputs.map((input, index) => ({...input, sequence: BigInt(input.sequence), sigOpCount: 0,
      utxo: {outpoint: input.previousOutpoint, amount: BigInt(entries[index].amount_sompi),
        scriptPublicKey: entries[index].script_public_key, blockDaaScore: BigInt(entries[index].block_daa_score),
        isCoinbase: false}})),
    outputs: transaction.outputs.map(output => ({value: BigInt(output.value), scriptPublicKey: output.scriptPublicKey})),
    lockTime: BigInt(transaction.lockTime), gas: BigInt(transaction.gas), storageMass: BigInt(transaction.storageMass)});
  try { tx.finalize(); assert.deepEqual(canonicalTransaction(tx), transaction, 'SDK body/ID mismatch'); }
  finally { tx.free(); }
}
function save(file, value) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(stringify(value) + '\n');
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, raw); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return {sha256: sha(raw), bytes: raw.length};
}
async function identity(rpc) {
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
function pageData(root, record) {
  const compressed = fs.readFileSync(path.join(root, record.path));
  need(sha(compressed) === record.gzip_sha256, 'CACHE_INTEGRITY', 'raw page gzip changed');
  const raw = zlib.gunzipSync(compressed);
  need(sha(raw) === record.decoded_sha256, 'CACHE_INTEGRITY', 'raw page decoded bytes changed');
  return JSON.parse(raw);
}
export async function scan(k, rpc, d, boundary, root, requireFounding = true) {
  const anchor = (await rpc.getBlock({hash: d.birth_start_hash, includeTransactions: false})).block;
  validateHeader(k, anchor.header, d.birth_start_hash);
  need(anchor.verboseData.isChainBlock === true, 'ANCHOR', 'birth anchor is not on selected chain');
  need(integer(anchor.header.blueScore) < integer(boundary.header.blueScore), 'ANCHOR', 'anchor must precede frontier');
  let cursor = d.birth_start_hash, reached = false;
  const seenBlocks = new Set([cursor]), seenTransactions = new Set(), pages = [], edges = new Map();
  let founding;
  while (!reached) {
    const request = {startHash: cursor, dataVerbosityLevel: 'Full', minConfirmationCount: boundary.min_confirmation_count};
    const response = await rpc.getVirtualChainFromBlockV2(request);
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
      const distance = integer(boundary.sink.blueScore) - integer(group.chainBlockHeader.blueScore);
      need(distance > BigInt(boundary.min_confirmation_count), 'DEPTH', 'insufficient fixed-sink depth');
      for (let txIndex = 0; txIndex < group.acceptedTransactions.length; txIndex++) {
        const tx = group.acceptedTransactions[txIndex], id = hex(tx.verboseData?.transactionId ?? tx.id, 32);
        seenTransactions.add(id);
        const locator = {page: pages.length - 1, group: groupIndex, transaction: txIndex, id};
        if (id === d.founding_outpoint.transactionId) {
          need(!founding, 'DUPLICATE_TRANSACTION', 'accepted founding transaction repeated'); founding = locator;
        }
        for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
          const key = pointKey(point(tx.inputs[inputIndex].previousOutpoint));
          const rows = edges.get(key) ?? []; rows.push({...locator, input_index: inputIndex}); edges.set(key, rows);
        }
      }
      cursor = hash;
      if (hash === boundary.header.hash) { reached = true; break; }
    }
  }
  need(!requireFounding || founding, 'MISSING_FOUNDING', 'founding transaction absent from complete prefix');
  return {anchor: plainHeader(anchor.header), cursor, pages, edges, founding, accepted_transactions_scanned: seenTransactions.size};
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
      sdk_transaction_id_recomputed: true, source_page_index: locator.page};
    rows.push(result); return result;
  }
  let current = read(scanned.founding), head = d.founding_outpoint, terminalCandidate = false;
  need(current.transaction.outputs[head.index], 'POOL_GRAPH', 'founding output missing');
  for (;;) {
    const next = scanned.edges.get(pointKey(head)) ?? [];
    need(next.length <= 1, 'CONFLICTING_SPEND', 'multiple accepted spends of pool head');
    if (!next.length) break;
    need(next[0].input_index === 0, 'UNSUPPORTED_POOL_INPUT', 'pool input must be first');
    current = read(next[0]);
    const first = current.transaction.outputs[0];
    need(first, 'POOL_GRAPH', 'pool successor/payout missing');
    if (!/^0000aa20[0-9a-f]{64}87$/.test(first.scriptPublicKey)) {
      need(current.transaction.payload.startsWith(Buffer.from('KPX2RV01').toString('hex')),
        'UNSUPPORTED_TERMINAL', 'unrecognized terminal candidate');
      terminalCandidate = true; head = null; break;
    }
    head = {transactionId: current.transaction.id, index: 0};
  }
  return {rows, head, terminal_candidate: terminalCandidate};
}
function entry(raw) {
  const value = raw.entry ?? raw;
  return {outpoint: point(value.outpoint), amount_sompi: integer(value.amount).toString(),
    script_public_key: script(value.scriptPublicKey), block_daa_score: integer(value.blockDaaScore).toString(),
    is_coinbase: value.isCoinbase, covenant_id: value.covenantId?.toString() ?? null};
}
async function currentView(k, rpc, discovered) {
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
async function postQuery(k, rpc, boundary, discovered, root) {
  const next = await frontier(k, rpc), related = [];
  let pages = [];
  if (next.header.hash !== boundary.header.hash) {
    const postRoot = path.join(root, 'post-query'); fs.mkdirSync(postRoot, {mode: 0o700});
    const scanned = await scan(k, rpc, {birth_start_hash: boundary.header.hash,
      founding_outpoint: {transactionId: '00'.repeat(32), index: 0}}, next, postRoot, false);
    pages = scanned.pages.map(record => ({...record, path: path.posix.join('post-query', record.path)}));
    if (discovered.head) related.push(...(scanned.edges.get(pointKey(discovered.head)) ?? []).map(row => row.id));
  }
  need(related.length === 0, 'STALE_FRONTIER', 'pool advanced after fixed recovery frontier');
  const fresh = await identity(rpc);
  const anchor = (await rpc.getBlock({hash: boundary.header.hash, includeTransactions: false})).block;
  validateHeader(k, anchor.header, boundary.header.hash);
  need(anchor.verboseData.isChainBlock === true, 'REORG', 'frontier no longer selected');
  return {removed_chain_block_hashes: [], related_transactions: related, pages,
    start_hash: boundary.header.hash, frontier: next.header, completed: true,
    observed_sink: fresh.dag.sink, server: fresh.server,
    checked_at: new Date().toISOString(), rpc_views_are_atomic: false};
}
export async function fetchOne(k, rpc, d, root) {
  const boundary = await frontier(k, rpc);
  const scanned = await scan(k, rpc, d, boundary, root);
  const found = discover(k, d, scanned, root, boundary);
  const view = await currentView(k, rpc, found), after = await postQuery(k, rpc, boundary, found, root);
  view.post_query_delta = after;
  const genesisScript = k.payToScriptHashScript(Buffer.from(d.initial_redeem_hex, 'hex'));
  try { need(script(genesisScript) === found.rows[0].transaction.outputs[d.founding_outpoint.index].scriptPublicKey,
    'DESCRIPTOR', 'founding output does not match pinned initial redeem'); }
  finally { genesisScript.free(); }
  return {schema: 'kpx2-network-fetch/v1', network_id: 'testnet-10', genesis_hash_hex: GENESIS,
    descriptor: d, descriptor_sha256: sha(canonicalDescriptor(d)),
    trust: 'REMOTE_VALIDATING_NODE_AND_RETAINED_CHAIN_DATA', sdk_pins: SDK_PINS,
    transactions: found.rows, current_view: view,
    coverage: {start_hash: d.birth_start_hash, anchor_header: scanned.anchor,
      frontier: boundary.header, initial_sink: boundary.sink, end_cursor: scanned.cursor,
      complete: true, frontier_seen: true, removed_chain_block_hashes: [], missing: [], pruned: false,
      min_confirmation_count: 20,
      accepted_transactions_scanned: scanned.accepted_transactions_scanned,
      scope: 'FINITE_CONFIRMED_PREFIX; sustained-active-pool catch-up not qualified'},
    pages: scanned.pages,
    terminal_candidate_not_yet_replay_verified: found.terminal_candidate,
    approved_policy_template_checked: true, observed_at: new Date().toISOString()};
}
export async function execute(descriptorPath, output, urls = DEFAULT_RPCS, k = loadSdk()) {
  need(!fs.existsSync(output), 'OUTPUT_EXISTS', 'fresh output directory required');
  const raw = fs.readFileSync(descriptorPath), d = descriptor(JSON.parse(raw));
  fs.mkdirSync(output, {recursive: true, mode: 0o700});
  const attempts = [];
  for (let index = 0; index < urls.length; index++) {
    const endpoint = new URL(urls[index]);
    need(['ws:', 'wss:'].includes(endpoint.protocol) && !endpoint.username && !endpoint.password,
      'ENDPOINT', 'unauthenticated ws/wss endpoint required');
    const root = path.join(output, `attempt-${String(index + 1).padStart(3, '0')}`);
    fs.mkdirSync(root, {mode: 0o700});
    const rpc = new k.RpcClient({url: endpoint.href, networkId: 'testnet-10'});
    try {
      await rpc.connect({blockAsyncConnect: true, timeoutDuration: 60000, strategy: 'fallback'});
      const fetched = await fetchOne(k, rpc, d, root);
      fetched.source = {rpc_url: endpoint.href, attempt: index + 1,
        assertion_scope: 'Distinct endpoints do not prove independently operated providers or consensus'};
      fetched.descriptor_file_sha256 = sha(raw); fetched.attempts = attempts;
      fetched.pages.forEach(record => { record.path = path.posix.join(path.basename(root), record.path); });
      fetched.current_view.post_query_delta.pages.forEach(record => {
        record.path = path.posix.join(path.basename(root), record.path);
      });
      save(path.join(output, 'fetch.json'), fetched); return fetched;
    } catch (error) {
      const failed = {rpc_url: endpoint.href, status: 'INCOMPLETE',
        category: error.category ?? 'DATA_UNAVAILABLE', error: String(error.message ?? error),
        recorded_at: new Date().toISOString()};
      save(path.join(root, 'INCOMPLETE.json'), failed); attempts.push(failed);
    } finally { await rpc.disconnect(); }
  }
  const result = {schema: 'kpx2-network-fetch/v1', status: 'INCOMPLETE', descriptor_sha256: sha(canonicalDescriptor(d)),
    attempts, balance_known: false, no_empty_balance_inference: true};
  save(path.join(output, 'INCOMPLETE.json'), result); return result;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [descriptorPath, output, ...rest] = process.argv.slice(2);
  try {
    need(descriptorPath && output, 'ARGUMENT', 'usage: fetch.mjs DESCRIPTOR NEW_OUTPUT [--rpc URL ...]');
    const urls = [];
    for (let i = 0; i < rest.length; i += 2) {
      need(rest[i] === '--rpc' && rest[i + 1], 'ARGUMENT', 'only --rpc URL is supported'); urls.push(rest[i + 1]);
    }
    const result = await execute(descriptorPath, path.resolve(output), urls.length ? urls : DEFAULT_RPCS);
    process.stdout.write(stringify({status: result.status ?? 'FETCHED_PENDING_REPLAY', output,
      transactions: result.transactions?.length, source: result.source?.rpc_url, balance_known: false}) + '\n');
    if (result.status === 'INCOMPLETE') process.exitCode = 2;
  } catch (error) {
    process.stderr.write(`independent fetch incomplete: ${error.category ?? 'ERROR'}: ${error.message}\n`); process.exitCode = 2;
  }
}
