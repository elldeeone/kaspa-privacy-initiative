#!/usr/bin/env node
// Public ordinary funding only. No secret/signing or caller-command API.
import readline from 'node:readline';
import {isDeepStrictEqual} from 'node:util';
import {loadSelectedSdk, selectedIdentity, validateRequest, makeTransaction,
  canonicalTransaction} from './ordinary_sdk.mjs';

const NET = 'testnet-10', GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const PROFILE = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a';
function need(value, category) { if (!value) throw new Error(category); }
function number(value, bits = 64) {
  if (typeof value === 'number') need(Number.isSafeInteger(value), 'unsafe-RPC-number');
  const text = String(value);
  need(/^(0|[1-9][0-9]*)$/.test(text), 'RPC-u64-decimal');
  const parsed = BigInt(text); need(parsed < (1n << BigInt(bits)), 'RPC-u64-range'); return text;
}
function point(value) {
  if (typeof value?.toJSON === 'function') value = value.toJSON();
  need(value && Object.keys(value).sort().join(',') === 'index,transactionId'
    && /^[a-f0-9]{64}$/.test(value.transactionId), 'RPC-outpoint');
  return {transactionId: value.transactionId, index: Number(number(value.index, 32))};
}
function entry(raw) {
  const value = raw.entry ?? raw;
  const spk = typeof value.scriptPublicKey === 'string' ? value.scriptPublicKey
    : Number(number(value.scriptPublicKey.version, 16)).toString(16).padStart(4, '0') + value.scriptPublicKey.script;
  need(/^000020[a-f0-9]{64}ac$/.test(spk), 'ordinary-P2PK-entry');
  return {outpoint: point(value.outpoint), entry: {amount_sompi: number(value.amount),
    script_public_key: spk, block_daa_score: number(value.blockDaaScore),
    is_coinbase: value.isCoinbase, covenant_id: value.covenantId?.toString() ?? null}};
}
const key = p => p.transactionId + ':' + p.index;
const emit = value => process.stdout.write(JSON.stringify(value) + '\n');
async function identity(rpc) {
  const server = await rpc.getServerInfo({});
  need(server.networkId === NET && server.isSynced === true, 'synced-testnet10-RPC-required');
  const dag = await rpc.getBlockDagInfo({});
  need(dag.network === NET || dag.networkId === NET, 'testnet10-DAG-required');
  return number(dag.virtualDaaScore);
}
async function allEntries(rpc, addresses) {
  const result = await rpc.getUtxosByAddresses({addresses});
  need(Array.isArray(result.entries), 'complete-RPC-UTXO-array');
  const found = new Map();
  for (const raw of result.entries) {
    const row = entry(raw), id = key(row.outpoint);
    need(!found.has(id), 'duplicate-RPC-UTXO'); found.set(id, row);
  }
  return found;
}
async function freshInputs(rpc, chosen, body, contexts) {
  const daa = await identity(rpc);
  const found = await allEntries(rpc, [chosen.A.address]);
  body.inputs.forEach((input, index) => {
    const actual = found.get(key(input.previousOutpoint));
    const expected = {outpoint: input.previousOutpoint, entry: contexts[index]};
    need(isDeepStrictEqual(actual, expected), 'exact-selected-mined-input-no-longer-current');
    need(actual.entry.is_coinbase === true && actual.entry.covenant_id === null
      && actual.entry.script_public_key === chosen.A.script_public_key
      && BigInt(daa) >= BigInt(actual.entry.block_daa_score) + 1000n,
      'actual-coinbase-maturity1000-before-intent-and-submit');
  });
  return daa;
}

export async function run(request, nextLine, sdkDirectory) {
  need(request && ['collect', 'submit', 'reconcile'].includes(request.action)
    && request.sdk_request && !('funding_secret_hex32' in request.sdk_request)
    && request.sdk_request.operation !== 'sign-input', 'public-fixed-funding-operation-only');
  const chosen = selectedIdentity(request.sdk_request), k = loadSelectedSdk(sdkDirectory);
  const rpc = new k.RpcClient({url: request.rpc_url, networkId: NET});
  let tx;
  try {
    await rpc.connect();
    if (request.action === 'collect') {
      const daa = await identity(rpc), found = await allEntries(rpc, [chosen.A.address]);
      const sources = [...found.values()].filter(row => row.entry.is_coinbase === true
        && row.entry.covenant_id === null && row.entry.script_public_key === chosen.A.script_public_key
        && BigInt(daa) >= BigInt(row.entry.block_daa_score) + 1000n)
        .sort((a, b) => a.outpoint.transactionId.localeCompare(b.outpoint.transactionId)
          || a.outpoint.index - b.outpoint.index);
      return {schema: 'kpx6-ordinary-mined-funding-observation/v1', network_id: NET,
        genesis_hash_hex: GENESIS, financial_profile_sha256: PROFILE,
        funding_identity_sha256: chosen.funding_identity_sha256, trial_id: chosen.trial_id,
        virtual_daa_score: daa, sources};
    }
    need(request.sdk_request.operation === 'roundtrip', 'public-roundtrip-only');
    const validated = validateRequest(request.sdk_request);
    tx = makeTransaction(k, validated.body, validated.contexts);
    need(isDeepStrictEqual(canonicalTransaction(tx), validated.body), 'exact-SDK-intended-body');
    if (request.action === 'reconcile') {
      const daa = await identity(rpc), found = await allEntries(rpc, [chosen.A.address, chosen.C.address]);
      const outputs = validated.body.outputs.map((output, index) => {
        const expected = {outpoint: {transactionId: validated.body.id, index}, entry: {
          amount_sompi: output.value, script_public_key: output.scriptPublicKey,
          is_coinbase: false, covenant_id: null}};
        const actual = found.get(key(expected.outpoint));
        need(actual && actual.entry.amount_sompi === expected.entry.amount_sompi
          && actual.entry.script_public_key === expected.entry.script_public_key
          && actual.entry.is_coinbase === false && actual.entry.covenant_id === null
          && BigInt(daa) >= BigInt(actual.entry.block_daa_score), 'ordinary-exact-output-not-yet-current');
        return actual;
      });
      return {schema: 'kpx6-ordinary-funding-output-observation/v1',
        status: 'EXACT_ORDINARY_OUTPUTS_OBSERVED_AT_TRUSTED_NODE', virtual_daa_score: daa,
        outputs, full_accepted_history_proof: false, no_resubmission: true};
    }
    await freshInputs(rpc, chosen, validated.body, validated.contexts);
    need(/^[a-f0-9]{64}$/.test(request.case_sha256), 'exact-case-audit-hash');
    emit({status: 'FRESH_INPUTS_CHECKED_AWAITING_DURABLE_INTENT',
      transaction_id: validated.body.id, case_sha256: request.case_sha256});
    const ack = JSON.parse(await nextLine());
    need(Object.keys(ack).sort().join(',') === 'case_sha256,intent_reserved,transaction_id'
      && ack.intent_reserved === true && ack.case_sha256 === request.case_sha256
      && ack.transaction_id === validated.body.id, 'host-durable-once-intent-required');
    // A second exact query after the durable intent closes the preparation gap.
    await freshInputs(rpc, chosen, validated.body, validated.contexts);
    try {
      const response = await rpc.submitTransaction({transaction: tx, allowOrphan: false});
      const id = response.transactionId?.toString();
      return {status: id === validated.body.id ? 'SUBMITTED_ACKNOWLEDGED_QUERY_ONLY'
        : 'RPC_UNKNOWN_QUERY_ONLY', no_resubmission: true};
    } catch {
      return {status: 'RPC_UNKNOWN_QUERY_ONLY', no_resubmission: true};
    }
  } finally {
    tx?.free();
    try { await rpc.disconnect(); } catch { /* query-only after an unknown response */ }
    rpc.free?.();
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const lines = readline.createInterface({input: process.stdin, crlfDelay: Infinity})[Symbol.asyncIterator]();
  const next = async () => { const line = await lines.next(); need(!line.done, 'request-or-intent-ack-required'); return line.value; };
  try {
    need(process.argv.length === 4 && process.argv[2] === '--sdk-dir', 'fixed-staged-SDK-argument');
    const request = JSON.parse(await next());
    emit(await run(request, next, process.argv[3]));
  } catch {
    emit({status: 'REFUSED_OR_UNKNOWN_QUERY_ONLY', no_resubmission: true});
    process.exitCode = 1;
  }
}
