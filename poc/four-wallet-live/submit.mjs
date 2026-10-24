// Fixed public preflight -> fresh exact-input query -> durable intent -> ONE RPC.
// Unknown responses permit read-only reconciliation, never an automatic retry.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {GENESIS, SDK_PINS, canonicalTransaction, loadSdk, need, pointKey, sha} from '../four-wallet-chain/wire.mjs';
import {checkedPath, canonical, strictJson, profile, descriptor} from '../four-wallet-chain/selection.mjs';
import {entry, identity} from '../four-wallet-chain/acquire.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLEAN = {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', HOME: '/nonexistent'};
const ENDPOINT = 'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh';
const STAGES = ['funding', 'settlement', 'owner-exit', 'exit-01', 'exit-02', 'exit-03', 'exit-04', 'fallback-01', 'fallback-02'];
const REQUIRED = ['stage', 'trial-directory', 'trial-id', 'financial-profile', 'financial-sha256',
  'descriptor', 'descriptor-sha256', 'case', 'case-sha256', 'software-root', 'inventory',
  'inventory-sha256', 'output'];
const OPTIONAL = ['journal', 'owner-attempt', 'fetch', 'fetch-sha256', 'bundle-directory', 'fee-rate', 'rpc'];

function options(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i];
    if (name === '--execute') { need(!result.execute, 'ARGUMENT', 'duplicate execute'); result.execute = true; continue; }
    need(name.startsWith('--') && [...REQUIRED, ...OPTIONAL].includes(name.slice(2))
      && argv[i + 1] && !Object.hasOwn(result, name.slice(2)), 'ARGUMENT', 'closed option required');
    result[name.slice(2)] = argv[++i];
  }
  need(REQUIRED.every(name => result[name]) && STAGES.includes(result.stage)
    && result.execute === true, 'ARGUMENT', 'explicit execute and complete fixed inputs required');
  need(result.stage === 'owner-exit' ? result['owner-attempt'] && !result.journal
    : result.journal && !result['owner-attempt'], 'ARGUMENT', 'one matching attempt journal required');
  return result;
}

function privateIdentities(trialDirectory) {
  const root = checkedPath(trialDirectory), result = new Set();
  for (const role of ['A', 'B', 'C', 'D']) {
    const file = path.join(root, 'owners', role, 'backup.json');
    if (fs.existsSync(file)) {
      const info = fs.lstatSync(file, {bigint: true});
      need(info.isFile(), 'PUBLIC_PATH', 'regular backup metadata required');
      result.add(`${info.dev}:${info.ino}`);
    }
  }
  return result;
}

export function stablePublic(file, trialDirectory, expected) {
  const resolved = checkedPath(file), root = checkedPath(trialDirectory);
  for (const role of ['A', 'B', 'C', 'D']) {
    const folder = path.join(root, 'owners', role);
    need(resolved !== folder && !resolved.startsWith(folder + path.sep),
      'PUBLIC_PATH', 'owner directory is not public input');
  }
  const forbidden = privateIdentities(root), before = fs.lstatSync(resolved, {bigint: true});
  need(before.isFile() && !forbidden.has(`${before.dev}:${before.ino}`), 'PUBLIC_PATH', 'public backup alias');
  const fd = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, {bigint: true});
    need(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino
      && !forbidden.has(`${opened.dev}:${opened.ino}`), 'PUBLIC_PATH', 'public source swapped before first byte');
    const raw = fs.readFileSync(fd), after = fs.fstatSync(fd, {bigint: true});
    need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => before[key] === after[key])
      && BigInt(raw.length) === before.size, 'PUBLIC_PATH', 'public source changed');
    if (expected !== undefined) need(/^[0-9a-f]{64}$/.test(expected) && sha(raw) === expected,
      'PUBLIC_IDENTITY', 'public whole-file SHA mismatch');
    return raw;
  } finally { fs.closeSync(fd); }
}

function python(file, args) {
  const result = spawnSync('/usr/bin/python3', ['-B', file, ...args], {
    env: CLEAN, input: undefined, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']});
  need(!result.error && result.status === 0 && !result.stderr, 'FIXED_PUBLIC_HELPER', 'fixed public helper incomplete');
  return strictJson(Buffer.from(result.stdout));
}

function preflightArgs(a, output) {
  const names = REQUIRED.filter(name => name !== 'output');
  for (const name of ['fetch', 'fetch-sha256', 'bundle-directory', 'fee-rate']) if (a[name]) names.push(name);
  return [...names.flatMap(name => ['--' + name, a[name]]), '--output', output];
}

function journalArgs(a, candidatePath, candidateSha, operation, acknowledged) {
  const names = ['trial-directory', 'trial-id', 'financial-sha256', 'descriptor-sha256', 'stage', 'case', 'case-sha256'];
  const args = [operation, ...names.flatMap(name => ['--' + name, a[name]]),
    '--sdk-candidate', candidatePath, '--sdk-candidate-sha256', candidateSha];
  for (const name of ['journal', 'owner-attempt']) if (a[name]) args.push('--' + name, a[name]);
  if (operation === 'reserve') args.push('--submit-source-sha256', sha(stablePublic(path.join(HERE, 'submit.mjs'), a['trial-directory'])));
  else args.push('--acknowledged', String(acknowledged));
  return args;
}

export function makeTransaction(k, body, contexts) {
  const tx = new k.Transaction({...body,
    inputs: body.inputs.map((input, index) => ({...input, sequence: BigInt(input.sequence), sigOpCount: 0,
      utxo: {outpoint: input.previousOutpoint, amount: BigInt(contexts[index].amount_sompi),
        scriptPublicKey: contexts[index].script_public_key,
        blockDaaScore: BigInt(contexts[index].block_daa_score), isCoinbase: false}})),
    outputs: body.outputs.map(output => ({value: BigInt(output.value), scriptPublicKey: output.scriptPublicKey})),
    lockTime: BigInt(body.lockTime), gas: BigInt(body.gas), storageMass: BigInt(body.storageMass)});
  try { tx.finalize(); assert.deepEqual(canonicalTransaction(tx), body); return tx; }
  catch (error) { tx.free(); throw error; }
}

export async function queryInputs(k, rpc, body, contexts) {
  await identity(rpc);
  const scripts = [...new Set(contexts.map(row => row.script_public_key))];
  const addresses = scripts.map(script => {
    const address = k.addressFromScriptPublicKey(script, 'testnet-10');
    need(address, 'INPUT_QUERY', 'input has no exact query address');
    try { return address.toString(); } finally { address.free(); }
  });
  const response = await rpc.getUtxosByAddresses({addresses}), found = new Map();
  need(Array.isArray(response.entries), 'INPUT_QUERY', 'complete UTXO entries required');
  for (const raw of response.entries) {
    const row = entry(raw), key = pointKey(row.outpoint);
    need(!found.has(key), 'INPUT_QUERY', 'duplicate live UTXO'); found.set(key, row);
  }
  body.inputs.forEach((input, index) => {
    const expected = {outpoint: input.previousOutpoint, ...contexts[index]};
    need(canonical(found.get(pointKey(input.previousOutpoint))) === canonical(expected),
      'INPUT_QUERY', 'exact selected source is no longer current');
  });
}

export async function transmitOnce(rpc, tx, expectedId) {
  // The caller must already have committed the immutable intent. This function
  // makes one request even when the peer returns an error or an unexpected ID.
  try {
    const response = await rpc.submitTransaction({transaction: tx, allowOrphan: false});
    return response.transactionId === expectedId;
  } catch { return false; }
}

export async function execute(a) {
  const root = checkedPath(a.output);
  need(!fs.existsSync(root), 'OUTPUT', 'fresh public submit output required');
  fs.mkdirSync(root, {recursive: true, mode: 0o700});
  const preflight = path.join(root, 'preflight');
  python(path.join(HERE, 'preflight.py'), preflightArgs(a, preflight));
  const candidatePath = path.join(preflight, 'SDK-CANDIDATE.json');
  const candidateRaw = stablePublic(candidatePath, a['trial-directory']), candidateSha = sha(candidateRaw);
  const candidate = strictJson(candidateRaw);
  need(candidate.schema === 'kpx6-four-wallet-public-SDK-candidate/v1'
    && candidate.network_id === 'testnet-10' && candidate.genesis_hash_hex === GENESIS
    && candidate.trial_id === a['trial-id'] && candidate.stage === a.stage
    && candidate.financial_profile_sha256 === a['financial-sha256']
    && candidate.descriptor_sha256 === a['descriptor-sha256']
    && candidate.case_file_sha256 === a['case-sha256'] && candidate.submitting_or_accepted === false,
    'PREFLIGHT', 'candidate identity mismatch');
  const selected = profile(stablePublic(a['financial-profile'], a['trial-directory'], a['financial-sha256']), a['financial-sha256']);
  const d = descriptor(stablePublic(a.descriptor, a['trial-directory'], a['descriptor-sha256']),
    a['descriptor-sha256'], selected, a['financial-sha256']);
  need(d.trial_id === a['trial-id'], 'PREFLIGHT', 'descriptor trial mismatch');
  const nodeRaw = stablePublic(process.execPath, a['trial-directory'], selected.executables.node.sha256);
  need(nodeRaw.length === selected.executables.node.bytes, 'NODE_IDENTITY', 'selected Node executable required');
  const sdkDirectory = path.join(root, 'public-sdk'); fs.mkdirSync(sdkDirectory, {mode: 0o700});
  for (const [name, expected] of Object.entries(SDK_PINS)) {
    const raw = stablePublic(path.join(a['software-root'], 'runtime-sdk', name), a['trial-directory'], expected);
    fs.writeFileSync(path.join(sdkDirectory, name), raw, {flag: 'wx', mode: 0o400});
  }
  const k = loadSdk(sdkDirectory), tx = makeTransaction(k, candidate.transaction, candidate.contexts);
  const endpoint = new URL(a.rpc ?? ENDPOINT);
  need(endpoint.protocol === 'wss:' && !endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash,
    'ENDPOINT', 'credential-free public WSS required');
  const rpc = new k.RpcClient({url: endpoint.href, networkId: 'testnet-10'});
  let reserved = false, attempted = false, acknowledged = false;
  try {
    await rpc.connect({blockAsyncConnect: true, timeoutDuration: 60000, strategy: 'fallback'});
    await queryInputs(k, rpc, candidate.transaction, candidate.contexts);
    // Connection stays open. No proof generation or external command is allowed
    // between the immediate source query and this fixed durable bookkeeping.
    const intent = python(path.join(HERE, 'journal_cli.py'), journalArgs(a, candidatePath, candidateSha, 'reserve'));
    need(intent.transaction_id === candidate.transaction.id && intent.status === 'RESERVED_NEVER_RESUBMIT',
      'INTENT', 'durable exact intent required'); reserved = true;
    attempted = true;
    acknowledged = await transmitOnce(rpc, tx, candidate.transaction.id);
    python(path.join(HERE, 'journal_cli.py'), journalArgs(a, candidatePath, candidateSha, 'response', acknowledged));
    return {status: acknowledged ? 'RPC_ACK_ONLY' : 'RECONCILE_READ_ONLY',
      transaction_id: candidate.transaction.id, submission_attempted: attempted,
      accepted_or_confirmed: false, automatic_resubmission_permitted: false};
  } finally {
    tx.free(); await rpc.disconnect();
    // A crash after reservation also remains reserved. There is no finally-send.
    void reserved;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(JSON.stringify(await execute(options(process.argv.slice(2)))) + '\n'); }
  catch (error) {
    process.stderr.write(`four-wallet submission incomplete: ${error.category ?? 'FIXED_PIPELINE_REFUSED'}; query only if intent exists\n`);
    process.exitCode = 2;
  }
}
