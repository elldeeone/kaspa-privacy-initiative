// Finite Auth528 TN10 transport fork. Root-only durable once-only submission.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const OLD_DOMAIN = '9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c';
const AA_DOMAIN = 'aa39ad5d2da85dfd1695cc74ce3e0f23e713f315d6e5341bccc8a060111354c2';
const SDK = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const PINS = {'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'};
export const stringify = v => JSON.stringify(v, (_, x) => typeof x === 'bigint' ? x.toString() : x);
export const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const read = p => JSON.parse(fs.readFileSync(p, 'utf8'));
const outpoint = p => `${p.transactionId}:${p.index}`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function save(p, value) {
  const fd = fs.openSync(p, 'wx', 0o600);
  try { fs.writeFileSync(fd, stringify(value) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  const d = fs.openSync(path.dirname(p), 'r');
  try { fs.fsyncSync(d); } finally { fs.closeSync(d); }
}
export function spk(s) {
  const value = typeof s === 'string' ? s : s.version.toString(16).padStart(4, '0') + s.script;
  assert.match(value, /^0000(?:[0-9a-f]{2})*$/, 'script public key version must be zero');
  return value;
}
export function canonical(t) {
  assert.equal(t.version, 1, 'transaction version must be one');
  if (t.mass !== undefined && t.storageMass !== undefined)
    assert.equal(BigInt(t.mass), BigInt(t.storageMass), 'conflicting mass aliases');
  const inputs = t.inputs.map(i => {
    assert.ok(i.computeBudget !== undefined && i.computeBudget !== null, 'missing v1 compute commitment');
    // RPC Full exposes deprecated sigOpCount=0 even though native v1 serde omits it.
    if (i.sigOpCount !== undefined && i.sigOpCount !== null) assert.equal(i.sigOpCount, 0);
    return {previousOutpoint:{transactionId:i.previousOutpoint.transactionId, index:i.previousOutpoint.index},
      signatureScript:i.signatureScript ?? '', sequence:i.sequence.toString(), computeBudget:i.computeBudget};
  });
  return {version:t.version, id:t.verboseData?.transactionId ?? t.id, inputs,
    outputs:t.outputs.map(o => { assert.equal(o.covenant ?? null, null); return {
      value:o.value.toString(), scriptPublicKey:spk(o.scriptPublicKey), covenant:null}; }),
    lockTime:t.lockTime.toString(), subnetworkId:t.subnetworkId, gas:t.gas.toString(), payload:t.payload,
    storageMass:(t.storageMass ?? t.mass).toString()};
}
function sdk(request) {
  const configured = request.sdk_path ?? SDK;
  const directory = configured.endsWith('.js') ? path.dirname(configured) : configured;
  for (const [name, hash] of Object.entries(PINS))
    assert.equal(sha(fs.readFileSync(path.join(directory, name))), hash, `SDK pin ${name}`);
  return createRequire(import.meta.url)(path.join(directory, 'kaspa.js'));
}
function nativeBody(file) {
  return JSON.parse(execFileSync('/usr/bin/python3', [path.join(HERE, 'native_safe.py'), file],
    {encoding:'utf8', maxBuffer:16*1024*1024}));
}
function nativeInputs(p, raw) {
  const file = p.context_path ?? path.join(path.dirname(p.body_path), 'supplied-context.json');
  const entries = JSON.parse(execFileSync('/usr/bin/python3', [path.join(HERE, 'native_safe.py'), '--context', file],
    {encoding:'utf8', maxBuffer:16*1024*1024}));
  assert.equal(entries.length, raw.inputs.length);
  return entries.map((e, i) => ({...e, outpoint:raw.inputs[i].previousOutpoint}));
}
export function roundtrip(k, raw, contexts) {
  assert.equal(contexts.length, raw.inputs.length);
  const tx = new k.Transaction({...raw,
    // The SDK constructor requires the deprecated field even for v1. It is
    // zero, as returned by official RPC Full, and is absent from native v1 serde.
    inputs:raw.inputs.map((i, index) => ({...i, sequence:BigInt(i.sequence), sigOpCount:0,
      utxo:{outpoint:i.previousOutpoint, amount:BigInt(contexts[index].amount_sompi),
        scriptPublicKey:spk(contexts[index].script_public_key),
        blockDaaScore:BigInt(contexts[index].block_daa_score),
        isCoinbase:contexts[index].is_coinbase}})),
    outputs:raw.outputs.map(o => ({value:BigInt(o.value), scriptPublicKey:o.scriptPublicKey})),
    lockTime:BigInt(raw.lockTime), gas:BigInt(raw.gas), storageMass:BigInt(raw.storageMass)});
  tx.finalize(); assert.deepEqual(canonical(tx), raw, 'SDK changed native body/id');
  const safe = k.Transaction.deserializeFromSafeJSON(tx.serializeToSafeJSON());
  try { safe.finalize(); assert.deepEqual(canonical(safe), raw, 'SDK safe roundtrip changed body'); }
  finally { safe.free(); }
  return tx;
}
function address(k, script) {
  const a = k.addressFromScriptPublicKey(spk(script), 'testnet-10'); assert.ok(a);
  try { return a.toString(); } finally { a.free(); }
}
async function utxos(k, rpc, scripts) {
  if (!scripts.length) return [];
  const response = await rpc.getUtxosByAddresses({addresses:[...new Set(scripts.map(s => address(k, s)))]});
  return response.entries.map(row => { const e = row.entry ?? row; return {
    outpoint:{transactionId:e.outpoint.transactionId, index:e.outpoint.index},
    amount_sompi:e.amount.toString(), script_public_key:spk(e.scriptPublicKey),
    block_daa_score:e.blockDaaScore.toString(), is_coinbase:e.isCoinbase,
    covenant_id:e.covenantId?.toString() ?? null}; });
}
async function identity(rpc) {
  const info = await rpc.getServerInfo(), dag = await rpc.getBlockDagInfo();
  assert.equal(info.networkId, 'testnet-10'); assert.equal(dag.network, 'testnet-10');
  assert.equal(info.isSynced, true); assert.equal(info.hasUtxoIndex, true);
  return {server:info, dag};
}
async function checkpoint(rpc, depth=64) {
  const info = await identity(rpc); let hash = info.dag.sink, block;
  for (let n=0; n<=depth; n++) {
    block = (await rpc.getBlock({hash, includeTransactions:false})).block;
    assert.equal(block.header.hash, hash);
    if (n === depth) break;
    hash = block.verboseData.selectedParentHash;
  }
  assert.equal(block.verboseData.isChainBlock, true);
  return {start_hash:hash, header:block.header, reference_sink:info.dag.sink,
    selected_parent_depth:depth, observed_at:new Date().toISOString()};
}
async function accepted(rpc, start, min) {
  let cursor = start; const rows = [], pages = [];
  for (;;) {
    const page = await rpc.getVirtualChainFromBlockV2({startHash:cursor,
      dataVerbosityLevel:'Full', minConfirmationCount:min});
    assert.equal(page.removedChainBlockHashes.length, 0, 'retained trial prefix removed: reconcile reorg');
    assert.equal(page.addedChainBlockHashes.length, page.chainBlockAcceptedTransactions.length);
    pages.push({start_hash:cursor, response:page});
    page.chainBlockAcceptedTransactions.forEach((group, index) => {
      assert.equal(group.chainBlockHeader.hash, page.addedChainBlockHashes[index], 'accepting header mismatch');
      for (const tx of group.acceptedTransactions) rows.push({tx, header:group.chainBlockHeader});
    });
    const next = page.addedChainBlockHashes.at(-1);
    if (!next || next === cursor) return {rows, pages, cursor};
    cursor = next;
  }
}
function freshProfile(p) {
  const identityPath = fs.realpathSync(p.profile_path);
  const trial = path.dirname(path.dirname(identityPath));
  assert.equal(identityPath, path.join(trial, 'public', 'identity.json'), 'canonical public identity location');
  const bytes = fs.readFileSync(identityPath), profile = JSON.parse(bytes);
  assert.equal(profile.schema, 'kpx3-tn10-private-trial/v1');
  assert.equal(profile.classification, 'PRIVATE_TN10_TEST_KAS_ONLY');
  assert.equal(profile.program_label, 'AUTH528_PRIVATE_CASHOUT/v1');
  assert.equal(profile.network_id, 'testnet-10'); assert.equal(profile.genesis_hash_hex, GENESIS);
  assert.equal(Object.hasOwn(profile, 'secrets'), false, 'adapter requires public/identity.json');
  assert.match(profile.domain_hex32, /^[0-9a-f]{64}$/); assert.notEqual(profile.domain_hex32, OLD_DOMAIN); assert.notEqual(profile.domain_hex32, AA_DOMAIN);
  assert.match(profile.domain_nonce_hex32, /^[0-9a-f]{64}$/);
  assert.equal(profile.domain_hex32, sha(Buffer.concat([Buffer.from('KPX3/TN10/PRIVATE-RECOVERY/v1\0'),
    Buffer.from(GENESIS, 'hex'), Buffer.from(profile.domain_nonce_hex32, 'hex')])));
  return {profile, hash:sha(bytes), trial};
}
function approvedRedeem(redeem, domain) {
  assert.equal(redeem.length, 24417, 'approved whole program length');
  const directory=path.resolve(HERE,'../private-exit-recovery');
  const meta=fs.readFileSync(path.join(directory,'kpx3-policy-template.json'));
  const template=fs.readFileSync(path.join(directory,'kpx3-policy-template.bin'));
  assert.equal(sha(meta),'6f9b71043db6cbea271585b9c2853125b601b71ad2eccad9d65ddc35db7e49c7');
  assert.equal(sha(template),'731eb10da7a96a3f1f67b3c3fb0da6d45294820c8c610dc9d7d0d0fd1dd10556');
  const manifest=JSON.parse(meta), expected=Buffer.from(template);
  let domains=0, keys=0;
  for(const slot of manifest.patch_slots) {
    const value=slot.kind==='domain'?Buffer.from(domain,'hex'):redeem.subarray(114+slot.data_offset,114+slot.data_offset+328);
    if(slot.kind==='domain')domains++;else {assert.equal(slot.kind,'vk');keys++;}
    assert.equal(value.length,slot.bytes);
    value.copy(expected,slot.data_offset);
  }
  assert.equal(domains,10);assert.equal(keys,1);
  assert.deepEqual(redeem.subarray(114),expected,'unapproved immutable program');
}
export function bodyDomain(k, raw, profile, stage, checked) {
  const payload = Buffer.from(raw.payload, 'hex'), magic = payload.subarray(0, 8).toString();
  const selectors = {founding:'KPX2GN01', 'private-payment':'KPX3AU01',
    'bob-private-exit':'KPX3AU01', 'charlie-private-exit':'KPX3AU01'};
  assert.ok(Object.hasOwn(selectors, stage), 'unknown finite stage');
  assert.equal(magic, selectors[stage], 'stage/payload mismatch');
  assert.equal(payload.subarray(8, 40).toString('hex'), profile.domain_hex32, 'body domain mismatch');
  if (stage !== 'founding') {
    assert.equal(payload.length, 4400, 'Auth528 payload size');
    const remaining = payload.readBigUInt64LE(476), payout = payload.readBigUInt64LE(484);
    if (stage === 'private-payment') { assert.equal(payout, 0n, 'P0 payment'); assert.ok(remaining > 0n, 'continuing payment'); }
    if (stage === 'bob-private-exit') { assert.ok(payout > 0n, 'private payout'); assert.ok(remaining > 0n, 'continuing private exit'); }
    if (stage === 'charlie-private-exit') { assert.ok(payout > 0n, 'private payout'); assert.equal(remaining, 0n, 'terminal private exit'); }
  }
  let redeem;
  if (stage === 'founding') {
    assert.match(checked.output0_redeem_hex, /^(?:[0-9a-f]{2})+$/);
    redeem = Buffer.from(checked.output0_redeem_hex, 'hex');
    const script = k.payToScriptHashScript(redeem);
    try { assert.equal(spk(script), raw.outputs[0].scriptPublicKey, 'founding immutable pool SPK'); }
    finally { script.free(); }
  } else if (['private-payment','bob-private-exit','charlie-private-exit'].includes(stage)) {
    redeem = Buffer.from(raw.inputs[0].signatureScript, 'hex').subarray(199);
    const script = k.payToScriptHashScript(redeem);
    try { assert.equal(spk(script), checked.inputs[0].script_public_key, 'pool input SPK'); }
    finally { script.free(); }
  }
  if (redeem) {
    approvedRedeem(redeem,profile.domain_hex32);
    assert.equal(redeem.subarray(0, 2).toString('hex'), '4c70');
    assert.equal(redeem.subarray(2, 10).toString(), 'KPX2ST01');
    assert.equal(redeem.subarray(10, 42).toString('hex'), profile.domain_hex32, 'immutable policy domain mismatch');
  }
}
function localCheck(p, raw, profileHash) {
  const checked = read(p.local_check_path);
  assert.equal(checked.body_sha256, sha(fs.readFileSync(p.body_path)));
  assert.equal(checked.transaction_id, raw.id); assert.equal(checked.profile_sha256, profileHash);
  assert.equal(checked.native_full_accepted, true); assert.equal(checked.all_input_engines_accepted, true);
  assert.match(checked.native_binary_sha256, /^[0-9a-f]{64}$/);
  assert.equal(checked.inputs.length, raw.inputs.length);
  checked.inputs.forEach((input, index) => {
    assert.deepEqual(input.outpoint, raw.inputs[index].previousOutpoint);
    assert.match(input.amount_sompi, /^(0|[1-9][0-9]*)$/); spk(input.script_public_key);
    assert.match(input.block_daa_score, /^(0|[1-9][0-9]*)$/);
    assert.equal(input.is_coinbase, false); assert.equal(input.covenant_id, null);
  });
  return checked;
}
function exactEntry(actual, expected) {
  assert.ok(actual, 'exact current UTXO absent');
  assert.deepEqual(actual.outpoint, expected.outpoint);
  assert.equal(actual.amount_sompi, expected.amount_sompi);
  assert.equal(actual.script_public_key, spk(expected.script_public_key));
  if (expected.block_daa_score !== undefined)
    assert.equal(actual.block_daa_score, expected.block_daa_score, 'actual input DAA context changed');
  assert.equal(actual.is_coinbase, false); assert.equal(actual.covenant_id, null);
}
function inputContexts(row, checked) {
  return row.tx.inputs.map((input, index) => {
    const entry = input.verboseData?.utxoEntry;
    assert.ok(entry, 'Full accepted input UTXO context missing');
    const expected = checked.inputs[index];
    const actual = {outpoint:input.previousOutpoint, amount_sompi:entry.amount.toString(),
      script_public_key:spk(entry.scriptPublicKey), is_coinbase:entry.isCoinbase,
      block_daa_score:entry.blockDaaScore.toString(), covenant_id:entry.covenantId?.toString() ?? null};
    exactEntry(actual, expected); return actual;
  });
}
export async function observe(k, rpc, p, raw, checked) {
  const min = p.min_confirmations ?? 20; assert.ok(Number.isInteger(min) && min >= 20);
  assert.match(p.start_hash, /^[0-9a-f]{64}$/);
  const requested = p.expected_unspent_output_indices ?? raw.outputs.map((_, i) => i);
  assert.equal(new Set(requested).size, requested.length);
  for (const index of requested) assert.ok(Number.isInteger(index) && index>=0 && index<raw.outputs.length);
  for (;;) {
    const view = await accepted(rpc, p.start_hash, min);
    const row = view.rows.find(r => (r.tx.verboseData?.transactionId ?? r.tx.id) === raw.id);
    if (!row) { await delay(p.poll_ms ?? 1500); continue; }
    const actual = canonical(row.tx); assert.deepEqual(actual, raw, 'accepted body substitution');
    const inputs = inputContexts(row, checked);
    const queryStarted = new Date().toISOString();
    const all = await utxos(k, rpc, [...raw.outputs.map(o => o.scriptPublicKey),
      ...checked.inputs.map(i => i.script_public_key)]);
    const outputs = requested.map(index => {
      const expected = raw.outputs[index], point = {transactionId:raw.id, index};
      const entry = all.find(e => outpoint(e.outpoint) === outpoint(point));
      exactEntry(entry, {outpoint:point, amount_sompi:expected.value, script_public_key:expected.scriptPublicKey});
      return {index, outpoint:point, amount_sompi:expected.value, script_public_key:expected.scriptPublicKey, utxo:entry};
    });
    const spent = checked.inputs.map(input => ({outpoint:input.outpoint,
      script_public_key:input.script_public_key, queried:true,
      unspent:all.some(e => outpoint(e.outpoint) === outpoint(input.outpoint))}));
    assert.ok(spent.every(x => !x.unspent), 'accepted consumed input still present');
    // Reconcile a second chain delta AFTER querying current outputs. No view is atomic.
    const after = await accepted(rpc, view.cursor, min);
    const tracked = new Set([...checked.inputs.map(i=>outpoint(i.outpoint)),
      ...requested.map(index=>outpoint({transactionId:raw.id,index}))]);
    assert.ok(after.rows.every(next=>next.tx.inputs.every(input=>!tracked.has(outpoint(input.previousOutpoint)))),
      'post-query related spend; refetch a fresh view');
    const fresh = await identity(rpc);
    const anchor = (await rpc.getBlock({hash:row.header.hash, includeTransactions:false})).block;
    assert.equal(anchor.verboseData.isChainBlock, true, 'accepting block removed');
    const sink = (await rpc.getBlock({hash:fresh.dag.sink, includeTransactions:false})).block;
    const distance = BigInt(sink.header.blueScore) - BigInt(row.header.blueScore);
    assert.ok(distance > BigInt(min), 'accepting block has insufficient blue-score depth');
    return {transaction_id:raw.id, accepted_body:actual, accepted_body_sha256:sha(stringify(actual)),
      accepted_input_contexts:inputs, accepting_block_header:row.header,
      observed_sink:sink.header.hash, virtual_daa_score:fresh.server.virtualDaaScore.toString(),
      start_hash:p.start_hash, final_cursor:after.cursor,
      confirmation_policy:{min_confirmation_count:min, comparison:'sinkBlueScore-acceptingBlueScore > min',
        accepting_blue_score:row.header.blueScore.toString(), sink_blue_score:sink.header.blueScore.toString(),
        actual_blue_score_distance:distance.toString(), passes:true, immutable_finality:false},
      current_outputs:outputs, spent_inputs:spent, chain_delta_removed:[],post_query_related_spend_check:true,
      pages:[...view.pages, ...after.pages], utxo_query_started_at:queryStarted,
      observed_at:new Date().toISOString(), network:'testnet-10', expected_genesis:GENESIS,
      trust:'VALIDATING_NODE_AND_PUBLIC_ARCHIVE_ORACLE', server:fresh.server};
  }
}
export async function execute(p) {
  const k = sdk(p);
  if (p.op === 'roundtrip') {
    const raw = nativeBody(p.body_path), tx = roundtrip(k, raw, nativeInputs(p, raw)); tx.free();
    return {transaction:raw, SDK_PINS:PINS, lossless_native_roundtrip:true};
  }
  const url = new URL(p.rpc_url);
  assert.ok(['ws:','wss:'].includes(url.protocol)); assert.equal(url.username, ''); assert.equal(url.password, '');
  const rpc = new k.RpcClient({url:p.rpc_url, networkId:'testnet-10'});
  try {
    await rpc.connect({blockAsyncConnect:true, timeoutDuration:120000, strategy:'fallback'});
    const current = await identity(rpc);
    if (p.op === 'network') {
      let genesis;
      try { genesis = (await rpc.getBlock({hash:GENESIS, includeTransactions:false})).block.header; }
      catch { genesis = {retained:false, expected_genesis:GENESIS,
        source:'pinned TESTNET_PARAMS; remote network assertion remains trusted'}; }
      const cp = await checkpoint(rpc, 32);
      const page = await rpc.getVirtualChainFromBlockV2({startHash:cp.start_hash,
        dataVerbosityLevel:'Full', minConfirmationCount:20});
      return {read_only:true, ...current, genesis, checkpoint:cp,
        full_history:{supported:true, groups:page.chainBlockAcceptedTransactions.length,
          removed:page.removedChainBlockHashes}, fee_estimate:await rpc.getFeeEstimate(),
        observed_at:new Date().toISOString(), SDK_PINS:PINS};
    }
    assert.equal(current.server.serverVersion, '2.1.0', 'primary runtime must match pinned native2.1.0');
    if (p.op === 'checkpoint') return {...await checkpoint(rpc), network:'testnet-10', expected_genesis:GENESIS};
    if (p.op === 'utxos') return {network:'testnet-10', expected_genesis:GENESIS,
      observed_at:new Date().toISOString(), observed_sink:current.dag.sink,
      entries:await utxos(k, rpc, p.scripts),
      confirmation:'virtual-consensus UTXO view; observe accepted history for depth'};
    const raw = nativeBody(p.body_path), f = freshProfile(p), checked = localCheck(p, raw, f.hash);
    const tx = roundtrip(k, raw, checked.inputs); tx.free();
    bodyDomain(k, raw, f.profile, p.stage, checked);
    if (p.op === 'observe') return await observe(k, rpc, p, raw, checked);
    if (p.op !== 'submit-once') throw Error('unsupported finite adapter operation');
    const releaseBytes = fs.readFileSync(p.release_path);
    assert.equal(sha(releaseBytes), p.release_sha256); const release = JSON.parse(releaseBytes);
    assert.equal(release.authorization, 'TN10_FRESH_TRIAL_REHEARSAL');
    assert.equal(release.profile_sha256, f.hash); assert.equal(release.network, 'testnet-10');
    assert.equal(release.genesis, GENESIS); assert.equal(release.rpc_url, p.rpc_url);
    assert.equal(release.trial_directory, f.trial, 'released once-only identity directory');
    assert.ok(release.allowed_stages.includes(p.stage));
    assert.equal(release.adapter_sha256, sha(fs.readFileSync(fileURLToPath(import.meta.url))));
    assert.equal(release.native_safe_sha256, sha(fs.readFileSync(path.join(HERE, 'native_safe.py'))));
    assert.equal(checked.native_binary_sha256, release.native_binary_sha256);
    assert.deepEqual(release.bodies[p.stage], {transaction_id:raw.id, body_sha256:checked.body_sha256,
      local_check_sha256:sha(fs.readFileSync(p.local_check_path))});
    const live = await utxos(k, rpc, checked.inputs.map(i => i.script_public_key));
    for (const expected of checked.inputs)
      exactEntry(live.find(e => outpoint(e.outpoint) === outpoint(expected.outpoint)), expected);
    const trial = f.trial;
    assert.equal(fs.realpathSync(p.trial_dir), trial, 'once-only marker directory must belong to identity');
    assert.ok(fs.realpathSync(p.body_path).startsWith(trial + path.sep));
    assert.equal(fs.statSync(trial).mode & 0o777, 0o700);
    assert.match(p.start_hash, /^[0-9a-f]{64}$/);
    const dir = path.join(trial, 'chain'); fs.mkdirSync(dir, {recursive:true, mode:0o700});
    const intentData = {transaction_id:raw.id, body_sha256:checked.body_sha256,
      profile_sha256:f.hash, stage:p.stage, rpc_url:p.rpc_url,
      release_sha256:p.release_sha256, start_hash:p.start_hash, created_at:new Date().toISOString()};
    // Both markers are exclusive and durable BEFORE the only network submission.
    save(path.join(dir, `${p.stage}.submission-intent.json`), intentData);
    save(path.join(dir, `${raw.id}.submission-intent.json`), intentData);
    const native = roundtrip(k, raw, checked.inputs); let response;
    try {
      response = await rpc.submitTransaction({transaction:native, allowOrphan:false});
      assert.equal(response.transactionId, raw.id);
    } catch {
      const result = {transaction_id:raw.id, status:'RECONCILE_READ_ONLY', submission_attempted:true};
      save(path.join(dir, `${p.stage}.submission-result.json`), result); return result;
    } finally { native.free(); }
    const result = {transaction_id:raw.id, status:'RPC_ACK_ONLY', response, submission_attempted:true};
    save(path.join(dir, `${p.stage}.submission-result.json`), result); return result;
  } finally { await rpc.disconnect(); }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { const p = JSON.parse(fs.readFileSync(0, 'utf8')); process.stdout.write(stringify(await execute(p)) + '\n'); }
  catch (error) {
    process.stderr.write(`new Auth528 TN10 adapter rejected: ${String(error.message).replace(/(?:ws|wss):\/\/\S+/g, '[endpoint]')}\n`);
    process.exitCode = 1;
  }
}
