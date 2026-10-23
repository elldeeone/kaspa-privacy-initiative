// Mock transport claims are NOT chain evidence. Real SDK body IDs still execute.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {descriptor, execute, loadSdk, Incomplete} from './fetch.mjs';
import {canonical, strictJson, validateManifest} from './parameter_manifest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FIXTURE = path.join(ROOT, 'research/next-session/private-service-loss/network/controls-fixtures-01');
const INPUT = path.join(FIXTURE, 'descriptor.json'), MANIFEST = path.join(FIXTURE, 'public-manifest.json');
const d = strictJson(fs.readFileSync(INPUT)), m = strictJson(fs.readFileSync(MANIFEST));
const bundle = strictJson(fs.readFileSync(path.join(FIXTURE, 'network-claims.json')));
const copied = value => JSON.parse(JSON.stringify(value));
const H = digit => digit.repeat(64);
const completeHeader = (hash, score) => ({hash, blueScore: String(score), timestamp: '1', nonce: '1', daaScore: '1',
  blueWork: '0'.repeat(47) + '1', version: 2, bits: 1, parentsByLevel: [], hashMerkleRoot: hash,
  acceptedIdMerkleRoot: H('0'), utxoCommitment: H('0'), pruningPoint: H('0')});
function rawBody(row) {
  const value = copied(row.transaction); value.verboseData = {transactionId: value.id};
  value.inputs.forEach((input, index) => {
    const entry = row.accepted_input_contexts[index];
    input.verboseData = {utxoEntry: {amount: entry.amount_sompi, scriptPublicKey: entry.script_public_key,
      blockDaaScore: entry.block_daa_score, isCoinbase: false, covenantId: null}};
  }); return value;
}
const page = groups => ({removedChainBlockHashes: [], addedChainBlockHashes: groups.map(x => x.chainBlockHeader.hash), chainBlockAcceptedTransactions: groups});
const group = (hash, score, transactions = []) => ({chainBlockHeader: completeHeader(hash, score), acceptedTransactions: transactions});
const founding = bundle.transactions.find(row => row.transaction.id === d.founding_outpoint.transactionId);
const live = bundle.current_view.queries.filter(q => q.entry !== null);

function mockedSdk(modes, calls) {
  const real = loadSdk();
  return {...real, Header: class {
    constructor(raw) { this.value = raw; }
    finalize() { return this.value.hashMerkleRoot; }
    free() {}
  }, RpcClient: class {
    constructor({url}) { this.mode = modes[url]; this.pages = 0; this.identities = 0; calls.push(url); }
    async connect() { if (this.mode === 'unavailable') throw Error('injected unavailable endpoint'); }
    async disconnect() {}
    async getServerInfo() { return {networkId: this.mode === 'wrong-network' ? 'mainnet' : 'testnet-10',
      serverVersion: '2.1.0', isSynced: true, hasUtxoIndex: true}; }
    async getBlockDagInfo() {
      this.identities++;
      return {network: this.mode === 'wrong-network' ? 'mainnet' : 'testnet-10',
        sink: this.mode === 'payout-race' && this.identities >= 3 ? H('7') : H('9')};
    }
    async getBlock({hash}) {
      if (hash === d.birth_start_hash && this.mode === 'pruned') throw Error('injected pruned anchor');
      const score = hash === H('9') ? 100 : hash === H('8') ? 79 : hash === H('7') ? 200 : hash === H('6') ? 179 : 10;
      return {block: {header: completeHeader(hash, score), verboseData: {isChainBlock: true,
        selectedParentHash: hash === H('9') ? H('8') : hash === H('7') ? H('6') : d.birth_start_hash}}};
    }
    async getVirtualChainFromBlockV2({startHash}) {
      if (this.mode === 'partial' && this.pages++) throw Error('injected lost partial source');
      if (this.mode === 'partial') return page([group(H('2'), 20, [rawBody(founding)])]);
      if (this.mode === 'missing-founding') return page([group(H('8'), 79)]);
      if (this.mode === 'empty') return page([]);
      if (this.mode === 'payout-race' && startHash === H('8'))
        return page([group(H('6'), 179, [{id: H('f'), inputs: [{previousOutpoint: live.at(-1).outpoint}]}])]);
      let rows = ['terminal', 'payout-race', 'open-missing-head'].includes(this.mode) ? bundle.transactions : [founding];
      if (this.mode === 'open-missing-head') rows = rows.slice(0, -1);
      const response = page([group(H('2'), 20, rows.map(rawBody)), group(H('8'), 79)]);
      if (this.mode === 'removal') response.removedChainBlockHashes = [H('e')];
      if (this.mode === 'truncated') response.addedChainBlockHashes.pop();
      return response;
    }
    async getUtxosByAddresses() {
      const values = ['terminal', 'payout-race', 'open-missing-head'].includes(this.mode) ? live
        : [{outpoint: d.founding_outpoint, amount_sompi: founding.transaction.outputs[0].value,
            script_public_key: founding.transaction.outputs[0].scriptPublicKey}];
      return {entries: values.map(value => ({outpoint: value.outpoint, amount: value.amount_sompi,
        scriptPublicKey: value.script_public_key, blockDaaScore: '1', isCoinbase: false, covenantId: null}))};
    }
  }};
}
async function run(modes) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kpx3-fetch-mock-')), calls = [];
  try {
    const result = await execute(INPUT, MANIFEST, path.join(root, 'out'), Object.keys(modes), mockedSdk(modes, calls));
    return {result, calls, hasFetch: fs.existsSync(path.join(root, 'out/fetch.json'))};
  } finally { fs.rmSync(root, {recursive: true, force: true}); }
}
const A = 'wss://primary.invalid/', B = 'wss://secondary.invalid/';
test('strict10 descriptor and full Auth528 policy template', () => {
  assert.equal(descriptor(copied(d)).schema, 'kpx3-private-network-descriptor/v1');
  assert.throws(() => descriptor({...d, schema: 'kpx3-recovery-descriptor/v1'}));
  const missing = {...d}; delete missing.public_params_manifest_sha256; assert.throws(() => descriptor(missing));
  assert.throws(() => descriptor({...d, operator_tree: 'forbidden'}));
});
test('public manifest requires exact canonical bytes and8source identities', () => {
  assert.equal(validateManifest(Buffer.from(canonical(m)), d).domain_hex32, d.domain_hex32);
  assert.throws(() => validateManifest(Buffer.from(canonical(m) + '\n'), d));
  assert.throws(() => strictJson('{"x":{"a":1,"a":2}}'));
  const wrong = copied(m); wrong.vk_hex328 = '00'.repeat(328);
  assert.throws(() => validateManifest(Buffer.from(canonical(wrong)), d));
});
test('preferred source failure uses a fresh secondary', async () => {
  const {result, calls} = await run({[A]: 'unavailable', [B]: 'complete'});
  assert.deepEqual(calls, [A, B]); assert.equal(result.source.attempt, 2); assert.equal(result.transactions.length, 1);
});
test('both sources down is incomplete with unknown balance', async () => {
  const {result, hasFetch} = await run({[A]: 'unavailable', [B]: 'unavailable'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(result.balance_known, false); assert.equal(hasFetch, false);
});
test('wrong network and pruned history fail before acceptance', async () => {
  assert.equal((await run({[A]: 'wrong-network'})).result.status, 'INCOMPLETE');
  assert.equal((await run({[A]: 'pruned'})).result.status, 'INCOMPLETE');
});
test('a partial source is never spliced into another source', async () => {
  const {result, hasFetch} = await run({[A]: 'partial', [B]: 'missing-founding'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(hasFetch, false);
  assert.equal(result.attempts[1].category, 'MISSING_FOUNDING');
});
test('Auth528 terminal is discovered through exact outpoint graph', async () => {
  const {result} = await run({[A]: 'terminal'});
  assert.equal(result.terminal_candidate_not_yet_replay_verified, true);
  assert.equal(result.transactions.at(-1).transaction.payload.slice(0, 16), Buffer.from('KPX3AU01').toString('hex'));
  assert.deepEqual(result.current_view.post_query_delta.watched_outpoints,
    result.current_view.queries.filter(query => query.entry !== null).map(query => query.outpoint));
});
test('postquery confirmed payout spend invalidates even terminal snapshot', async () => {
  const {result, hasFetch} = await run({[A]: 'payout-race'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(result.attempts[0].category, 'STALE_FRONTIER'); assert.equal(hasFetch, false);
});
test('missing current open head cannot become zero', async () => {
  const {result} = await run({[A]: 'open-missing-head'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(result.attempts[0].category, 'MISSING_CURRENT_HEAD');
});
test('empty, truncated or removed finite prefix fails incomplete', async () => {
  for (const mode of ['empty', 'truncated', 'removal']) {
    const {result, hasFetch} = await run({[A]: mode});
    assert.equal(result.status, 'INCOMPLETE'); assert.equal(hasFetch, false);
  }
});
