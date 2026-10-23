// Network-off transport controls. Mock node assertions are NOT chain evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execute, loadSdk} from './fetch.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const INPUT = path.join(ROOT, 'research/next-session/privacy-recovery/fetch/descriptor-v1.json');
const d = JSON.parse(fs.readFileSync(INPUT));
const PUBLIC = path.join(ROOT, 'research/next-session/testnet-rehearsal/accepted-01');
const body = JSON.parse(fs.readFileSync(path.join(PUBLIC, 'chain-public/bodies/founding.json')));
const observation = JSON.parse(fs.readFileSync(path.join(PUBLIC, 'chain-public/observations/founding.json')));
const H = digit => digit.repeat(64);
const completeHeader = (hash, score) => ({hash, blueScore: String(score), timestamp: '1', nonce: '1', daaScore: '1',
  blueWork: '0'.repeat(47) + '1', version: 2, bits: 1, parentsByLevel: [], hashMerkleRoot: hash,
  acceptedIdMerkleRoot: H('0'), utxoCommitment: H('0'), pruningPoint: H('0')});
const copied = value => JSON.parse(JSON.stringify(value));
function rawBody() {
  const value = copied(body);
  value.verboseData = {transactionId: body.id};
  value.inputs.forEach((input, index) => {
    const entry = observation.accepted_input_contexts[index];
    input.verboseData = {utxoEntry: {amount: entry.amount_sompi, scriptPublicKey: entry.script_public_key,
      blockDaaScore: entry.block_daa_score, isCoinbase: false, covenantId: null}};
  });
  return value;
}
function page(groups) {
  return {removedChainBlockHashes: [], addedChainBlockHashes: groups.map(group => group.chainBlockHeader.hash),
    chainBlockAcceptedTransactions: groups};
}
const group = (hash, score, transactions = []) => ({chainBlockHeader: completeHeader(hash, score),
  acceptedTransactions: transactions});

function mockedSdk(modes, calls) {
  const real = loadSdk();
  return {...real,
    // Synthetic headers isolate transport state transitions. Actual header
    // hashing/encoding is separately tested against the pinned live header.
    Header: class {
      constructor(raw) { this.value = raw; }
      finalize() { return this.value.hashMerkleRoot; }
      free() {}
    },
    RpcClient: class {
      constructor({url}) { this.url = url; this.mode = modes[url]; this.pages = 0; calls.push(url); }
      async connect() { if (this.mode === 'unavailable') throw Error('injected unavailable endpoint'); }
      async disconnect() {}
      async getServerInfo() {
        return {networkId: this.mode === 'wrong-network' ? 'mainnet' : 'testnet-10', serverVersion: '2.1.0',
          isSynced: true, hasUtxoIndex: true, virtualDaaScore: '1'};
      }
      async getBlockDagInfo() { return {network: this.mode === 'wrong-network' ? 'mainnet' : 'testnet-10', sink: H('9')}; }
      async getBlock({hash}) {
        if (hash === d.birth_start_hash && this.mode === 'pruned') throw Error('injected anchor outside retention root');
        const score = hash === H('9') ? 100 : hash === H('8') ? 79 : 10;
        return {block: {header: completeHeader(hash, score), verboseData: {isChainBlock: true,
          selectedParentHash: hash === H('9') ? H('8') : d.birth_start_hash}}};
      }
      async getVirtualChainFromBlockV2() {
        if (this.mode === 'partial' && this.pages++) throw Error('injected connection lost after one page');
        if (this.mode === 'partial') return page([group(H('2'), 20, [rawBody()])]);
        if (this.mode === 'missing-founding') return page([group(H('8'), 79)]);
        return page([group(H('2'), 20, [rawBody()]), group(H('8'), 79)]);
      }
      async getUtxosByAddresses() {
        return {entries: [{outpoint: d.founding_outpoint, amount: body.outputs[0].value,
          scriptPublicKey: body.outputs[0].scriptPublicKey, blockDaaScore: '0', isCoinbase: false, covenantId: null}]};
      }
    }};
}
async function run(modes) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kpx2-fetch-fault-')), calls = [];
  try {
    const result = await execute(INPUT, path.join(root, 'out'), Object.keys(modes), mockedSdk(modes, calls));
    return {result, calls, hasFetch: fs.existsSync(path.join(root, 'out/fetch.json')),
      hasIncomplete: fs.existsSync(path.join(root, 'out/INCOMPLETE.json'))};
  } finally { fs.rmSync(root, {recursive: true, force: true}); }
}
const A = 'wss://primary.invalid/', B = 'wss://secondary.invalid/';
test('mock unavailable preferred source falls back to a fresh successful secondary', async () => {
  const {result, calls, hasFetch} = await run({[A]: 'unavailable', [B]: 'complete'});
  assert.deepEqual(calls, [A, B]); assert.equal(hasFetch, true);
  assert.equal(result.source.attempt, 2); assert.equal(result.transactions.length, 1);
  assert.equal(result.attempts[0].status, 'INCOMPLETE');
});
test('both unavailable sources return incomplete without balance knowledge', async () => {
  const {result, hasFetch, hasIncomplete} = await run({[A]: 'unavailable', [B]: 'unavailable'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(result.balance_known, false);
  assert.equal(result.attempts.length, 2); assert.equal(hasFetch, false); assert.equal(hasIncomplete, true);
});
test('wrong network is rejected before the next source is tried', async () => {
  const {result, calls} = await run({[A]: 'wrong-network', [B]: 'complete'});
  assert.deepEqual(calls, [A, B]); assert.equal(result.source.attempt, 2);
  assert.equal(result.attempts[0].category, 'NODE_IDENTITY');
});
test('pruned birth anchor cannot become terminal zero', async () => {
  const {result, hasFetch} = await run({[A]: 'pruned'});
  assert.equal(result.status, 'INCOMPLETE'); assert.equal(result.balance_known, false);
  assert.equal(hasFetch, false); assert.match(result.attempts[0].error, /retention root/);
});
test('partial first-source founding is never spliced into a second-source prefix', async () => {
  const {result, calls, hasFetch} = await run({[A]: 'partial', [B]: 'missing-founding'});
  assert.deepEqual(calls, [A, B]); assert.equal(hasFetch, false); assert.equal(result.status, 'INCOMPLETE');
  assert.equal(result.attempts[1].category, 'MISSING_FOUNDING');
});
