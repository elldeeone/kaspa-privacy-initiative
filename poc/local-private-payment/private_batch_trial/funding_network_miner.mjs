import {connectTor} from './funding_network_rpc.mjs';
import {MiningJobs} from '../bootstrap/mining_jobs.mjs';
import {identityDocument as newIdentity, checkAddresses, reservePhase, IDS, readPinned, strictJson} from './funding_network_common.mjs';
// Ordinary TN10 mining with the existing SDK. Default is read-only planning.
// No private-key, wallet-signing, transaction submission or pool interface.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {isMainThread, parentPort, Worker} from 'node:worker_threads';
import {performance} from 'node:perf_hooks';

const SDK = {
  'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
};
const NODE = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c';
const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const URLS = ['wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh',
  'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh'];
const MAX64 = (1n << 64n) - 1n;
const need = (value, reason) => { if (!value) throw Error(reason); };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item);
function canonical(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
function bodyIdentity(block) {
  const copy = structuredClone(block); copy.header.nonce = 0n;
  return sha(json(canonical(copy)));
}
function load() {
  for (const [name, pin] of Object.entries(SDK)) need(sha(fs.readFileSync('/sdk/' + name)) === pin, 'SDK pin');
  return createRequire(import.meta.url)('/sdk/kaspa.js');
}
function durable(file, value) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o400);
  try { fs.writeFileSync(fd, json(value) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  const directory = fs.openSync(file.slice(0, file.lastIndexOf('/')), fs.constants.O_RDONLY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}
function script(value) {
  if (typeof value === 'string') return value;
  return Number(value.version).toString(16).padStart(4, '0') + value.script;
}
function payloadCheck(block, ownScript) {
  need(block.header.version === 2 && Array.isArray(block.transactions) && block.transactions.length > 0,
    'current v2 raw template');
  const raw = Buffer.from(block.transactions[0].payload, 'hex');
  need(raw.length >= 19 && raw.length >= 19 + raw[18], 'coinbase payload frame');
  const actual = raw.readUInt16LE(16).toString(16).padStart(4, '0') + raw.subarray(19, 19 + raw[18]).toString('hex');
  need(actual === ownScript && raw.readBigUInt64LE(8) > 0n, 'own future reward script/subsidy');
  return raw.readBigUInt64LE(8);
}

if (!isMainThread) {
  const k = load(); let active = null, scheduled = false;
  parentPort.on('message', message => {
    if (message.op === 'stop-job') { active?.pow.free(); active = null; return; }
    need(message.op === 'job' && /^[0-9a-f]{64}$/.test(message.id), 'fixed job message');
    active?.pow.free();
    active = {id: message.id, pow: k.PoW.fromRaw(message.pre, BigInt(message.time), message.bits),
      nonce: BigInt(message.index), stride: BigInt(message.workers)};
    if (!scheduled) { scheduled = true; setImmediate(step); }
  });
  function step() {
    if (!active) { scheduled = false; return; }
    const job = active;
    for (let i = 0; i < 2000; i++, job.nonce += job.stride) {
      need(job.nonce <= MAX64, 'nonce range exhausted');
      if (job.pow.checkWork(job.nonce)[0]) {
        parentPort.postMessage({id: job.id, nonce: job.nonce.toString()});
        job.pow.free(); active = null; scheduled = false; return;
      }
    }
    setImmediate(step);
  }
  parentPort.postMessage({ready: true});
} else {
  const options = new Map();
  for (let i = 2; i < process.argv.length; i++) {
    const key = process.argv[i];
    need(['--mode', '--role', '--rpc-index', '--execute', '--wallet-sha256', '--workers', '--target-sompi'].includes(key) && !options.has(key), 'closed option');
    options.set(key, key === '--execute' ? true : process.argv[++i]);
  }
  const mode = options.get('--mode') ?? 'plan', role = options.get('--role') ?? '0';
  const index = Number(options.get('--rpc-index') ?? 0);
  need(['plan', 'mine'].includes(mode) && ['0', '1', '2'].includes(role) && [0, 1].includes(index), 'fixed scope');
  need(mode === 'mine' ? options.get('--execute') === true : !options.has('--execute'), 'explicit mining execute');
  need(sha(fs.readFileSync(process.execPath)) === NODE, 'selected Node');
  const bytes = fs.readFileSync('/wallet.json'); need(/^[0-9a-f]{64}$/.test(options.get('--wallet-sha256'))
    && sha(bytes) === options.get('--wallet-sha256'), 'selected fresh public wallets');
  const identityDocument = newIdentity(bytes);
  const wallet = identityDocument.owners[Number(role)];
  const workers = Number(options.get('--workers') ?? 2);
  const targetText = options.get('--target-sompi') ?? '3100000000';
  need(Number.isSafeInteger(workers) && workers >= 1 && workers <= 256, 'selected CPU worker count');
  need(/^[1-9][0-9]*$/.test(targetText), 'canonical target sompi');
  const target = BigInt(targetText);
  need(target >= 2100000000n && target <= 2870000000000000000n, 'ordinary testnet funding target');
  need(wallet && wallet.address.startsWith('kaspatest:'), 'selected ordinary test wallet');
  const k = load(), addr = k.addressFromScriptPublicKey(wallet.funding_spk_hex36, 'testnet-10');
  try { need(addr.toString() === wallet.address, 'SDK address/script equality'); } finally { addr.free(); }
  checkAddresses(k, identityDocument);
  const marker = JSON.parse(fs.readFileSync('/NAMESPACE.json','utf8'));
  need(marker.schema === 'kpb-public-network-namespace/v1' && marker.operation === (mode === 'mine' ? 'mine' : 'plan-mining')
    && marker.network_id === 'testnet-10' && marker.trial_id === identityDocument.trial_id, 'new public mining namespace');
  need(!fs.existsSync('/etc/ssl/private') && !fs.existsSync('/home/luke/.codex') && !fs.existsSync('/original'), 'public namespace has no host secrets');
  const jobDocument = strictJson(readPinned('/NETWORK-JOB.json'));
  need(jobDocument.identity_sha256 === options.get('--wallet-sha256') && jobDocument.owner_component === Number(role), 'exact public mining job');
  for (const member of jobDocument.source_members) readPinned(member.path, member.sha256);
  if (mode === 'mine') reservePhase('/registry',identityDocument,'mine-'+role,{identity_sha256:options.get('--wallet-sha256'),owner_component:Number(role)});
  const connection=await connectTor(k,URLS[index]),rpc=connection.rpc;
  const nodes = [], jobs=new MiningJobs(); let fatal = null, stop = false, job = null, lastJob = null;
  let refresh = 0, observe = 0, attempts = 0, acknowledgements = 0, observedPresent = 0;
  let reward = 0n, mature = 0n, virtualDaa = 0n,foundMessages=0;
  const began = performance.now();
  process.on('SIGTERM', () => { stop = true; }); process.on('SIGINT', () => { stop = true; });
  async function identity() {
    const server = await rpc.getServerInfo(), dag = await rpc.getBlockDagInfo();
    need(server.networkId === 'testnet-10' && dag.network === 'testnet-10' && server.serverVersion === '2.1.0'
      && server.isSynced === true && server.hasUtxoIndex === true, 'selected synced TN10 2.1 node');
    virtualDaa = BigInt(dag.virtualDaaScore);
  }
  async function rewards() {
    await identity();
    const answer = await rpc.getUtxosByAddresses({addresses: [wallet.address]});
    need(Array.isArray(answer.entries), 'complete own UTXO entries'); reward = mature = 0n;
    const seen = new Set();
    for (const raw of answer.entries) {
      const entry = raw.entry ?? raw;
      need(script(entry.scriptPublicKey) === wallet.funding_spk_hex36 && (entry.covenantId ?? null) === null,
        'exact own ordinary reward script/context');
      const point = entry.outpoint.toJSON ? entry.outpoint.toJSON() : entry.outpoint;
      const id = point.transactionId + ':' + point.index; need(!seen.has(id), 'unique current UTXO'); seen.add(id);
      if (entry.isCoinbase !== true) continue;
      const amount = BigInt(entry.amount), score = BigInt(entry.blockDaaScore);
      need(amount > 0n && amount <= MAX64 && score >= 0n && score <= MAX64, 'canonical reward value/DAA');
      reward += amount; if (virtualDaa >= score + 1000n) mature += amount;
    }
    durable('/out/observation-' + Date.now() + '.json', {...IDS, trial_id:identityDocument.trial_id, owner_component:Number(role), network: 'testnet-10', expected_genesis: GENESIS,
      selected_validating_node_assumption: true, independent_genesis_or_consensus_proof: false,
      virtual_daa: virtualDaa, coinbase_sompi: reward, mature_coinbase_sompi: mature,
      maturity_daa_delta:1000,ordinary_consolidation_still_required:true,
      found_nonce_messages:foundMessages,submitted_unique_hashes:attempts,RPC_acknowledgements_only:acknowledgements,
      unknown_response_hash_observations:observedPresent,pending_found_work_count:jobs.queued.length,retained_public_job_count:jobs.jobs.size});
  }
  async function template() {
    await identity();
    const answer = await rpc.getBlockTemplate({payAddress: wallet.address, extraData: 'testnet-rehearsal'});
    need(answer.isSynced === undefined || answer.isSynced === true, 'synced template');
    const block = answer.block; payloadCheck(block, wallet.funding_spk_hex36);
    need(Object.getPrototypeOf(block) === Object.prototype && Object.getPrototypeOf(block.header) === Object.prototype,
      'raw structured template required');
    if (mode === 'plan') return block;
    const pow = new k.PoW(block.header);
    const pre = pow.prePoWHash, time = BigInt(block.header.timestamp), bits = block.header.bits;
    need(pow.target > 0n && pow.target < (1n << 256n), 'nonzero ordinary PoW target'); pow.free();
    const id = sha(pre + ':' + time + ':' + bits);
    if (id === lastJob) return block;
    lastJob = id; job=jobs.retain({id,block,used:false,identity:bodyIdentity(block)});
    nodes.forEach((node, i) => node.postMessage({op: 'job', id, pre, time: time.toString(), bits,
      index: i, workers: nodes.length}));
    return block;
  }
  async function found(message,job) {
    if (!job || message.id !== job.id || job.used) return;
    const nonce = BigInt(message.nonce); need(nonce >= 0n && nonce <= MAX64, 'canonical found nonce');
    const proof = new k.PoW(job.block.header);
    try { need(proof.checkWork(nonce)[0] === true, 'independent found-work recheck'); } finally { proof.free(); }
    const block = structuredClone(job.block); block.header.nonce = nonce;
    need(bodyIdentity(block) === job.identity, 'only nonce changed; complete raw body/header preserved');
    payloadCheck(block, wallet.funding_spk_hex36);
    const header = new k.Header(block.header); const hash = header.finalize(); header.free();
    need(/^[0-9a-f]{64}$/.test(hash), 'canonical block identity');
    job.used = true; for (const node of nodes) node.postMessage({op: 'stop-job'});
    const intent = '/journal/' + hash + '.intent.json';
    if (fs.existsSync(intent)) return; // Immutable earlier attempt is never sent again.
    durable(intent, {schema: 'kpb-once-only-TN10-block-intent/v1', ...IDS, trial_id:identityDocument.trial_id, owner_component:Number(role), block_hash: hash,
      network: 'testnet-10', expected_genesis: GENESIS, raw_block_sha256: sha(json(canonical(block))),
      block, automatic_resubmission_permitted: false});
    attempts++;
    let response = null, error = null, present = false;
    try { response = await rpc.submitBlock({block, allowNonDAABlocks: false}); }
    catch (problem) { error = String(problem); }
    if (response?.report?.type === 'success') acknowledgements++;
    else {
      try {
        const answer = await rpc.getBlock({hash, includeTransactions: false});
        const checked = new k.Header(answer.block.header);
        try { present = checked.finalize() === hash; } finally { checked.free(); }
      } catch { /* Retain UNKNOWN; no resend. */ }
    }
    observedPresent += Number(present);
    durable('/journal/' + hash + '.response.json', {block_hash: hash, response, error,
      observed_by_hash: present, accepted_reward_or_confirmation_claimed: false,
      automatic_resubmission_permitted: false});
    refresh = 0;
  }
  try {
    
    if (mode === 'plan') {
      const block = await template();
      const result = {schema:'kpb-readonly-TN10-mining-template/v1', ...IDS,
        trial_id:identityDocument.trial_id,owner_component:Number(role),
        mode, network: 'testnet-10', expected_genesis: GENESIS,
        server_assumption: true, bits: block.header.bits, daa_score: block.header.daaScore,
        own_reward_script_verified: true, subsidy_sompi: payloadCheck(block, wallet.funding_spk_hex36),
        workers_proposed: workers, target_observed_coinbase_sompi: target.toString(),
        mining_or_submission_executed: false};
      durable('/out/RESULTS.json',result); process.stdout.write(json(result) + '\n');
    } else {
      for (let i = 0; i < workers; i++) {
        const node = new Worker(new URL(import.meta.url)); nodes.push(node);
        node.on('message', message => { if (message.nonce !== undefined){foundMessages++;jobs.offer(message);} });
        node.on('error', error => { fatal = error; });
      }
      while (!stop && reward < target) {
        if (fatal) throw fatal;
        await jobs.drain(found);
        if (performance.now() >= refresh) {
          await jobs.during(async()=>{await template();refresh=performance.now()+1000;},found);
        }
        if (performance.now() >= observe) {
          await jobs.during(async()=>{await rewards();observe=performance.now()+1500;},found);
        }
        await new Promise(resolve => setTimeout(resolve, 20));
      }
      durable('/out/RESULTS.json', {schema: 'kpb-ordinary-TN10-mining-result/v1', ...IDS, trial_id:identityDocument.trial_id, owner_component:Number(role),
        status: reward >= target ? 'OWN_REWARDS_OBSERVED_AWAIT_MATURITY_AND_CONSOLIDATION' : 'INCOMPLETE',
        submitted_unique_hashes: attempts, RPC_acknowledgements_only: acknowledgements,
        unknown_response_hash_observations: observedPresent, coinbase_sompi: reward,
        mature_coinbase_sompi: mature, last_observed_virtual_daa: virtualDaa,
        elapsed_seconds: (performance.now() - began) / 1000, ordinary_consolidation_required: true,
        privacy_trial_funding_or_payout_confirmation_claimed: false, private_key_or_wallet_read: false});
    }
  } finally {
    for (const node of nodes) node.postMessage({op: 'stop-job'});
    await Promise.allSettled(nodes.map(node => node.terminate()));
    await connection.close();
  }
}
