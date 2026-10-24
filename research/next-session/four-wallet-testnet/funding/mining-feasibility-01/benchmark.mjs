// Local SDK PoW throughput only: no RPC, miner, wallet, signer or submission.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {isMainThread, parentPort, Worker, workerData} from 'node:worker_threads';
import {performance} from 'node:perf_hooks';

const PINS = {
  'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
};
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function need(value, reason) { if (!value) throw Error(reason); }
function load() {
  for (const [name, expected] of Object.entries(PINS))
    need(sha(fs.readFileSync('/sdk/' + name)) === expected, 'fixed SDK member');
  return createRequire(import.meta.url)('/sdk/kaspa.js');
}
function state(k, raw) {
  const value = {...raw, hash: '00'.repeat(32)};
  for (const name of ['timestamp', 'nonce', 'daaScore', 'blueScore']) value[name] = BigInt(raw[name]);
  value.blueWork = BigInt('0x' + raw.blueWork);
  const header = new k.Header(value);
  need(header.finalize() === raw.hash, 'known accepted public header identity');
  const pow = new k.PoW(header);
  need(pow.checkWork(BigInt(raw.nonce))[0] === true, 'known accepted nonce positive control');
  const target = BigInt(raw.bits & 0x7fffff) << BigInt(8 * ((raw.bits >>> 24) - 3));
  need(pow.target === target, 'independent compact target decoding');
  header.free();
  return pow;
}

if (!isMainThread) {
  const k = load(), pow = state(k, workerData.header);
  parentPort.postMessage({ready: true});
  parentPort.once('message', message => {
    need(message === 'START', 'fixed benchmark start');
    const start = performance.now();
    let nonce = BigInt(workerData.index), matches = 0;
    const stride = BigInt(workerData.workers);
    for (let i = 0; i < workerData.count; i++, nonce += stride) {
      const result = pow.checkWork(nonce);
      need(typeof result[0] === 'boolean' && typeof result[1] === 'bigint', 'official PoW result types');
      matches += Number(result[0]);
    }
    const elapsed = performance.now() - start;
    pow.free();
    parentPort.postMessage({hashes: workerData.count, elapsed_ms: elapsed,
      matching_nonce_count: matches, winning_nonce_or_hash_exported: false});
    parentPort.close();
  });
} else {
  const raw = fs.readFileSync('/header.json');
  const header = JSON.parse(raw);
  const k = load(), control = state(k, header); control.free();
  const cases = [];
  for (const workers of [1, 14]) {
    const count = 100_000, nodes = [], ready = [], done = [], exits = [];
    for (let index = 0; index < workers; index++) {
      const node = new Worker(new URL(import.meta.url), {workerData: {header, index, workers, count}});
      nodes.push(node);
      ready.push(new Promise((resolve, reject) => {
        const receive = message => { if (message.ready) { node.off('message', receive); resolve(); } };
        node.on('message', receive); node.once('error', reject);
      }));
      done.push(new Promise((resolve, reject) => {
        const receive = message => { if (message.hashes !== undefined) { node.off('message', receive); resolve(message); } };
        node.on('message', receive); node.once('error', reject);
      }));
      exits.push(new Promise((resolve, reject) => {
        node.once('exit', code => code === 0 ? resolve() : reject(Error('worker failed')));
      }));
    }
    await Promise.all(ready);
    const started = performance.now();
    for (const node of nodes) node.postMessage('START');
    const results = await Promise.all(done);
    const elapsed = performance.now() - started;
    await Promise.all(exits);
    cases.push({workers, hashes_per_worker: count, total_hashes: count * workers,
      wall_seconds_excluding_load_and_matrix_setup: elapsed / 1000,
      aggregate_hashes_per_second: count * workers / (elapsed / 1000),
      worker_results: results, all_worker_exits_zero: true});
  }
  const result = {schema: 'kpx6-local-SDK-PoW-benchmark/v1',
    header_sha256: sha(raw), known_header_hash: header.hash,
    known_accepted_nonce_passed: true, target_decode_matches_SDK: true,
    node_version: process.version, SDK_pins: PINS, cases,
    no_RPC_or_network_mining_signing_or_submission_interface: true,
    original_backup_or_private_key_or_wallet_read: false,
    scope: 'LOCAL_KNOWN_PUBLIC_HEADER_THROUGHPUT_NOT_ACCEPTED_MINING_REWARD'};
  fs.writeFileSync('/out/RESULTS.json', JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o400});
  process.stdout.write(JSON.stringify({status: 'LOCAL_BENCHMARK_COMPLETE', cases:
    cases.map(value => ({workers: value.workers, hashes: value.total_hashes,
      seconds: value.wall_seconds_excluding_load_and_matrix_setup,
      hashes_per_second: value.aggregate_hashes_per_second}))}) + '\n');
}
