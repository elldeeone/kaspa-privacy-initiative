import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {descriptor, canonicalDescriptor, canonicalTransaction, contexts, verifyTransactionId,
  headerHash, integer, script, loadSdk, scan, Incomplete} from './fetch.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PUBLIC = path.join(ROOT, 'research/next-session/testnet-rehearsal/accepted-01');
const valid = JSON.parse(fs.readFileSync(path.join(ROOT,
  'research/next-session/privacy-recovery/fetch/descriptor-v1.json')));
const copy = value => JSON.parse(JSON.stringify(value));
const category = wanted => error => error instanceof Incomplete && error.category === wanted;

test('descriptor is exact public bootstrap, canonical across key order', () => {
  assert.equal(descriptor(copy(valid)).schema, 'kpx2-recovery-descriptor/v1');
  const reversed = Object.fromEntries(Object.entries(valid).reverse());
  reversed.founding_outpoint = {index: 0, transactionId: valid.founding_outpoint.transactionId};
  assert.equal(canonicalDescriptor(valid), canonicalDescriptor(reversed));
});
test('descriptor rejects archive, owner and stage fields', () => {
  for (const name of ['snapshots', 'expected_payments_sompi', 'profile_path', 'operations', 'seed_hex32']) {
    assert.throws(() => descriptor({...valid, [name]: {}}), category('DESCRIPTOR'));
  }
});
test('descriptor rejects wrong network, genesis and founding index', () => {
  for (const value of [{...valid, network_id: 'mainnet'}, {...valid, genesis_hash_hex: '00'.repeat(32)},
    {...valid, founding_outpoint: {...valid.founding_outpoint, index: 1}}])
    assert.throws(() => descriptor(value), category('DESCRIPTOR'));
});
test('descriptor rejects arbitrary policy even with matching self-selected hash', () => {
  const value = copy(valid), raw = Buffer.from(value.initial_redeem_hex, 'hex');
  raw[200] ^= 1; value.initial_redeem_hex = raw.toString('hex');
  // Honest self-hash still cannot select new semantics into the approved app.
  return import('node:crypto').then(({default: crypto}) => {
    value.immutable_policy_sha256 = crypto.createHash('sha256').update(raw.subarray(114)).digest('hex');
    assert.throws(() => descriptor(value), category('UNAPPROVED_POLICY'));
  });
});
test('descriptor binds full domain and VK substitutions', () => {
  const wrongVk = {...valid, vk_hex328: '00'.repeat(328)};
  assert.throws(() => descriptor(wrongVk), category('UNAPPROVED_POLICY'));
  const wrongDomain = copy(valid), raw = Buffer.from(wrongDomain.initial_redeem_hex, 'hex');
  wrongDomain.domain_hex32 = '11'.repeat(32); Buffer.from(wrongDomain.domain_hex32, 'hex').copy(raw, 10);
  wrongDomain.initial_redeem_hex = raw.toString('hex');
  assert.throws(() => descriptor(wrongDomain), category('UNAPPROVED_POLICY'));
});
test('integer and SPK encoding reject lossy u64 and unknown script versions', () => {
  assert.equal(integer('18446744073709551615'), 18446744073709551615n);
  for (const bad of [true, -1, '01', 18446744073709551615, '18446744073709551616'])
    assert.throws(() => integer(bad), category('MALFORMED'));
  assert.throws(() => script('00012000'), category('UNSUPPORTED_SCRIPT_VERSION'));
});
test('actual public accepted body and ID roundtrip use pinned SDK', () => {
  const k = loadSdk(), observed = JSON.parse(fs.readFileSync(path.join(PUBLIC,
    'chain-public/observations/private.json')));
  const tx = canonicalTransaction(observed.accepted_body);
  verifyTransactionId(k, tx, observed.accepted_input_contexts);
  assert.equal(tx.inputs[0].sequence, '18446744073709551615');
  assert.throws(() => verifyTransactionId(k, {...tx, id: '00'.repeat(32)}, observed.accepted_input_contexts));
});
test('historical lossy parent serialization fails closed', () => {
  const k = loadSdk(), observed = JSON.parse(fs.readFileSync(path.join(PUBLIC,
    'chain-public/observations/private.json')));
  assert.deepEqual(observed.accepting_block_header.parentsByLevel, {});
  assert.throws(() => headerHash(k, observed.accepting_block_header), category('HEADER_ENCODING'));
});
test('fresh expanded network header recomputes after JSON roundtrip', () => {
  const k = loadSdk(), control = JSON.parse(fs.readFileSync(path.join(ROOT,
    'research/next-session/privacy-recovery/fetch/HEADER-CODEC-CONTROL.json')));
  assert.equal(headerHash(k, control.header), control.header_hash_recomputed);
  const corrupt = {...control.header, nonce: (BigInt(control.header.nonce) + 1n).toString()};
  assert.notEqual(headerHash(k, corrupt), control.header_hash_recomputed);
});
test('Full context absence and coinbase substitution reject', () => {
  const body = JSON.parse(fs.readFileSync(path.join(PUBLIC, 'chain-public/bodies/admit.json')));
  assert.throws(() => contexts(body, body), category('INPUT_CONTEXT'));
});

const H = byte => byte.repeat(64);
const header = (hash, score) => ({hash, blueScore: String(score), timestamp: '1', nonce: '1', daaScore: '1',
  blueWork: '0'.repeat(47) + '1', version: 2, bits: 1, parentsByLevel: [], hashMerkleRoot: hash,
  acceptedIdMerkleRoot: '00'.repeat(32), utxoCommitment: '00'.repeat(32), pruningPoint: '00'.repeat(32)});
const mockK = {Header: class {
  constructor(raw) { this.raw = raw; }
  finalize() { return this.raw.hashMerkleRoot; }
  free() {}
}};
const boundary = {header: header(H('3'), 50), sink: header(H('9'), 100), min_confirmation_count: 20};
const mockedDescriptor = {birth_start_hash: H('1'), founding_outpoint: {transactionId: H('a'), index: 0}};
const group = (hash, score, ids = []) => ({chainBlockHeader: header(hash, score),
  acceptedTransactions: ids.map(id => ({id, inputs: []}))});
const page = groups => ({removedChainBlockHashes: [], addedChainBlockHashes: groups.map(x => x.chainBlockHeader.hash),
  chainBlockAcceptedTransactions: groups});
async function runScan(pages) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kpx2-fetch-test-'));
  let index = 0;
  const rpc = {getBlock: async () => ({block: {header: header(H('1'), 10), verboseData: {isChainBlock: true}}}),
    getVirtualChainFromBlockV2: async () => pages[index++] ?? page([])};
  try { return await scan(mockK, rpc, mockedDescriptor, boundary, root); }
  finally { fs.rmSync(root, {recursive: true, force: true}); }
}
test('finite scan follows pagination to the exact fixed frontier and stops', async () => {
  const result = await runScan([page([group(H('2'), 20, [H('a')])]),
    page([group(H('3'), 50), group(H('4'), 70)])]);
  assert.equal(result.cursor, H('3')); assert.equal(result.pages.length, 2);
  assert.equal(result.founding.id, H('a'));
});
test('empty page before fixed frontier is incomplete, never complete zero', async () => {
  await assert.rejects(runScan([page([])]), category('PREMATURE_END'));
});
test('truncated hash/group response rejects', async () => {
  const broken = page([group(H('3'), 50, [H('a')])]); broken.addedChainBlockHashes = [];
  await assert.rejects(runScan([broken]), category('TRUNCATED_PAGE'));
});
test('removal invalidates the finite scan', async () => {
  const broken = page([group(H('3'), 50, [H('a')])]); broken.removedChainBlockHashes = [H('5')];
  await assert.rejects(runScan([broken]), category('REORG'));
});
test('cursor cycle rejects without silently advancing to current sink', async () => {
  await assert.rejects(runScan([page([group(H('2'), 20, [H('a')])]), page([group(H('2'), 20)])]),
    category('CURSOR_CYCLE'));
});
test('missing founding after a complete frontier is incomplete', async () => {
  await assert.rejects(runScan([page([group(H('3'), 50)])]), category('MISSING_FOUNDING'));
});
test('unrelated coinbase-like IDs do not impose a new global uniqueness rule', async () => {
  const result = await runScan([page([group(H('2'), 20, [H('a'), H('b')]), group(H('3'), 50, [H('b')])])]);
  assert.equal(result.founding.id, H('a'));
});
test('duplicate selected founding identity still rejects', async () => {
  await assert.rejects(runScan([page([group(H('2'), 20, [H('a')]),
    group(H('3'), 50, [H('a')])])]), category('DUPLICATE_TRANSACTION'));
});
test('header hash recomputation rejects a substituted accepting header', async () => {
  const broken = page([group(H('3'), 50, [H('a')])]);
  broken.chainBlockAcceptedTransactions[0].chainBlockHeader.hashMerkleRoot = H('5');
  await assert.rejects(runScan([broken]), category('HEADER'));
});
test('fixed-sink confirmation depth rejects shallow accepted rows', async () => {
  await assert.rejects(runScan([page([group(H('2'), 85, [H('a')]), group(H('3'), 50)])]), category('DEPTH'));
});
