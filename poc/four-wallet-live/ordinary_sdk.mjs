// Fixed offline ordinary-coinbase SDK boundary. No RPC, backup or file-key API.
// The closed launcher must exclude all eight original owner files/directories
// before staging exact selected SDK/public inputs. A sign request is private
// owner-worker stdin only; never retain it as a public request or log.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

export const SDK_PINS = Object.freeze({
  'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0',
});
export const FINANCIAL_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a';
export const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const MAX = 2870000000000000000n;
const P2PK = /^000020[0-9a-f]{64}ac$/;
const PLACEHOLDER = '41' + '00'.repeat(64) + '01';
const sha = raw => crypto.createHash('sha256').update(raw).digest('hex');
const need = (ok, code) => { if (!ok) throw new Error('ordinary-sdk:' + code); };

function exact(value, names, code) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...names].sort().join(','), code);
}
function hex(value, bytes) {
  need(typeof value === 'string' && new RegExp('^[0-9a-f]{' + 2 * bytes + '}$').test(value), 'hex');
  return value;
}
export function decimal(value, bits = 64) {
  need(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), 'decimal-string');
  const parsed = BigInt(value);
  need(parsed >= 0n && parsed < (1n << BigInt(bits)), 'integer-range');
  return parsed;
}
function amount(value, positive = true) {
  const parsed = decimal(value);
  need(parsed <= MAX && (!positive || parsed > 0n), 'sompi-range');
  return parsed;
}
function point(value) {
  if (value && typeof value.toJSON === 'function') value = value.toJSON();
  exact(value, ['transactionId', 'index'], 'outpoint-fields');
  hex(value.transactionId, 32);
  need(Number.isInteger(value.index) && value.index >= 0 && value.index < 2 ** 32, 'outpoint-index');
  return {transactionId: value.transactionId, index: value.index};
}
function script(value) {
  if (typeof value === 'string') return value;
  need(value && value.version === 0 && typeof value.script === 'string', 'script-version');
  return '0000' + value.script;
}
function finalized(tx) {
  const id = tx.finalize();
  // Selected SDK2.1 returns a WASM Hash handle, not a string.
  id?.free?.();
}

export function canonicalTransaction(tx) {
  return {version: tx.version, id: tx.id,
    inputs: tx.inputs.map(row => {
      need(row.sigOpCount === 0 && Number.isInteger(row.computeBudget), 'SDK-v1-input');
      return {previousOutpoint: point(row.previousOutpoint), signatureScript: row.signatureScript,
        sequence: row.sequence.toString(), computeBudget: row.computeBudget};
    }),
    outputs: tx.outputs.map(row => {
      need((row.covenant ?? null) === null, 'SDK-output-covenant');
      return {value: row.value.toString(), scriptPublicKey: script(row.scriptPublicKey), covenant: null};
    }),
    lockTime: tx.lockTime.toString(), subnetworkId: tx.subnetworkId,
    gas: tx.gas.toString(), payload: tx.payload, storageMass: tx.storageMass.toString()};
}

export function loadSelectedSdk(sdkDirectory = '/runtime/sdk') {
  need(typeof sdkDirectory === 'string' && !sdkDirectory.split(/[\\/]/).includes('..'), 'SDK-directory');
  const root = path.resolve(sdkDirectory);
  for (let part = root;; part = path.dirname(part)) {
    need(!fs.lstatSync(part).isSymbolicLink(), 'SDK-symlink');
    if (part === path.dirname(part)) break;
  }
  const entries = Object.entries(SDK_PINS).map(([name, pin]) => {
    const file = path.join(root, name), before = fs.lstatSync(file, {bigint: true});
    need(before.isFile() && (before.mode & 0o777n) === 0o400n, 'SDK-readonly-member');
    return {file, pin, before};
  });
  // Every SDK member's metadata precedes the first SDK member byte read.
  for (const {file, pin, before} of entries) {
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const opened = fs.fstatSync(fd, {bigint: true});
      need(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino, 'SDK-opened-member');
      const raw = fs.readFileSync(fd), after = fs.fstatSync(fd, {bigint: true});
      need(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => before[key] === after[key])
        && BigInt(raw.length) === before.size && sha(raw) === pin, 'SDK-selected-stable-bytes');
    } finally { fs.closeSync(fd); }
  }
  // The selected read-only installation and host remain trusted during use.
  return createRequire(import.meta.url)(path.join(root, 'kaspa.js'));
}

export function selectedIdentity(request) {
  // Root selects this receipt digest as explicit command metadata. A failed
  // trial can use a fresh identity without changing code or financial setup.
  hex(request.funding_identity_sha256, 32);
  need(typeof request.funding_identity_raw_utf8 === 'string'
    && sha(Buffer.from(request.funding_identity_raw_utf8, 'utf8')) === request.funding_identity_sha256,
    'externally-selected-fresh-funding-identity');
  need(typeof request.financial_profile_raw_utf8 === 'string'
    && sha(Buffer.from(request.financial_profile_raw_utf8, 'utf8')) === FINANCIAL_SHA,
    'fixed-financial-profile');
  // These exact pinned files include diagnostic metadata such as elapsed
  // seconds. Protocol amounts below still require canonical decimal strings.
  const receipt = JSON.parse(request.funding_identity_raw_utf8);
  const profile = JSON.parse(request.financial_profile_raw_utf8);
  exact(receipt, ['SDK21_address_and_source_script_binding_checked_inside_own_owner_process',
    'backup_or_private_scalar_hashes_exported', 'classification', 'constructor_source_sha256',
    'constructor_wall_seconds', 'coordinator_backup_or_private_key_contents_read', 'domain_hex32',
    'financial_profile_id', 'four_owner_processes_succeeded',
    'funding_GN2_signing_setup_proving_or_broadcast_performed', 'funding_wallets',
    'profile_identity_sha256', 'reviewed_public_source_preimages', 'schema', 'trial_id'],
    'fixed-funding-receipt-fields');
  need(profile.schema === 'kpx6-four-wallet-financial-profile/v1'
    && profile.network_id === 'testnet-10' && profile.genesis_hash_hex === GENESIS
    && receipt.financial_profile_id === profile.financial_profile_id
    && receipt.domain_hex32 === profile.child_domain_hex32
    && typeof request.trial_id === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.trial_id)
    && request.trial_id === receipt.trial_id, 'receipt-profile-trial-domain-binding');
  need(receipt.SDK21_address_and_source_script_binding_checked_inside_own_owner_process === true
    && receipt.four_owner_processes_succeeded === true
    && receipt.backup_or_private_scalar_hashes_exported === false
    && receipt.coordinator_backup_or_private_key_contents_read === false
    && receipt.funding_GN2_signing_setup_proving_or_broadcast_performed === false,
    'fixed-funding-identity-only-scope');
  need(Array.isArray(receipt.funding_wallets) && receipt.funding_wallets.length === 2,
    'two-fresh-funding-wallets');
  const byRole = {};
  for (const row of receipt.funding_wallets) {
    exact(row, ['address', 'role', 'script_public_key', 'xonly_hex32'], 'fixed-funding-wallet-fields');
    need(['A', 'C'].includes(row.role) && !Object.hasOwn(byRole, row.role), 'distinct-A-C-funding-roles');
    hex(row.xonly_hex32, 32);
    need(row.script_public_key === '000020' + row.xonly_hex32 + 'ac'
      && typeof row.address === 'string' && row.address.startsWith('kaspatest:'), 'fresh-funding-P2PK');
    byRole[row.role] = {...row};
  }
  need(byRole.A.script_public_key !== byRole.C.script_public_key, 'distinct-fresh-A-C-targets');
  return {A: byRole.A, C: byRole.C, trial_id: receipt.trial_id,
    funding_identity_sha256: request.funding_identity_sha256};
}

export function validateRequest(request) {
  need(request && ['build', 'roundtrip', 'sign-input'].includes(request.operation), 'closed-operation');
  const names = ['schema', 'operation', 'network_id', 'trial_id', 'funding_identity_raw_utf8', 'funding_identity_sha256',
    'financial_profile_raw_utf8', 'transaction', 'contexts', 'observed_daa_score'];
  if (request.operation !== 'build') names.push('reference_mining_mass');
  if (request.operation === 'sign-input') names.push('input_index', 'funding_secret_hex32');
  exact(request, names, 'closed-request-fields');
  need(request.schema === 'kpx6-ordinary-coinbase-sdk/v1' && request.network_id === 'testnet-10',
    'TN10-ordinary-coinbase-request');
  const selected = selectedIdentity(request);
  const targets = {A: selected.A.script_public_key, C: selected.C.script_public_key};
  const body = request.transaction, contexts = request.contexts;
  exact(body, ['version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId', 'gas', 'payload',
    'storageMass'], 'SDK-body-fields');
  need(body.version === 1 && body.lockTime === '0' && body.gas === '0'
    && body.subnetworkId === '00'.repeat(20) && body.payload === '', 'fixed-native-V1-header');
  hex(body.id, 32); decimal(body.storageMass);
  need(request.operation !== 'build' || body.id === '00'.repeat(32), 'build-derived-ID-only');
  need(Array.isArray(body.inputs) && body.inputs.length > 0 && Array.isArray(contexts)
    && contexts.length === body.inputs.length, 'all-input-contexts');
  const observed = decimal(request.observed_daa_score), points = new Set();
  let incoming = 0n;
  body.inputs.forEach((row, index) => {
    exact(row, ['previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'], 'input-fields');
    const at = point(row.previousOutpoint), key = at.transactionId + ':' + at.index;
    need(!points.has(key), 'distinct-ordinary-inputs'); points.add(key);
    need(row.computeBudget === 10 && row.sequence === '18446744073709551615', 'budget10-and-sequence');
    need(typeof row.signatureScript === 'string' && /^41[0-9a-f]{128}01$/.test(row.signatureScript)
      && (request.operation !== 'build' || row.signatureScript === PLACEHOLDER), 'fixed66-ALL-script-shape');
    const context = contexts[index];
    exact(context, ['amount_sompi', 'script_public_key', 'block_daa_score', 'is_coinbase', 'covenant_id'],
      'ordinary-coinbase-context-fields');
    need(context.is_coinbase === true && context.covenant_id === null
      && P2PK.test(context.script_public_key) && context.script_public_key === targets.A,
      'all-original-A-P2PK-coinbases');
    const daa = decimal(context.block_daa_score);
    need(observed >= daa && observed - daa >= 1000n, 'actual-observed-coinbase-maturity1000');
    incoming += amount(context.amount_sompi);
    need(incoming <= MAX, 'source-sum-range');
  });
  need(Array.isArray(body.outputs) && [2, 3].includes(body.outputs.length), 'two-targets-optional-A-refund');
  let outgoing = 0n;
  body.outputs.forEach((row, index) => {
    exact(row, ['value', 'scriptPublicKey', 'covenant'], 'output-fields');
    const value = amount(row.value), wanted = index === 1 ? targets.C : targets.A;
    need(row.covenant === null && row.scriptPublicKey === wanted
      && (index > 1 || value === 2100000000n), 'exact-fresh-A21-C21-protected-A-refund');
    outgoing += value;
    need(outgoing <= MAX, 'output-sum-range');
  });
  need(incoming > outgoing, 'positive-ordinary-fee');
  const fee = incoming - outgoing;
  if (request.operation !== 'build') {
    const mass = decimal(request.reference_mining_mass);
    need(mass > 0n && fee === 100n * mass, 'exact-selected-Native-ref100-fee');
  }
  if (request.operation === 'sign-input') {
    need(Number.isInteger(request.input_index) && request.input_index >= 0
      && request.input_index < body.inputs.length, 'one-valid-input-index');
    hex(request.funding_secret_hex32, 32);
  }
  return {body, contexts, source_script_public_key: targets.A,
    fee_sompi: fee.toString(), observed_daa_score: observed.toString(),
    supplied_observation_or_Native_metrics_independently_verified: false};
}

export function makeTransaction(k, body, contexts) {
  const tx = new k.Transaction({...body,
    inputs: body.inputs.map((row, index) => ({...row, sequence: BigInt(row.sequence), sigOpCount: 0,
      utxo: {outpoint: row.previousOutpoint, amount: BigInt(contexts[index].amount_sompi),
        scriptPublicKey: contexts[index].script_public_key,
        blockDaaScore: BigInt(contexts[index].block_daa_score), isCoinbase: true}})),
    outputs: body.outputs.map(row => ({value: BigInt(row.value), scriptPublicKey: row.scriptPublicKey})),
    lockTime: BigInt(body.lockTime), gas: BigInt(body.gas), storageMass: BigInt(body.storageMass)});
  try { finalized(tx); return tx; } catch (error) { tx.free(); throw error; }
}

export function run(request, sdkDirectory = '/runtime/sdk') {
  const selected = validateRequest(request), k = loadSelectedSdk(sdkDirectory);
  let tx, key;
  try {
    tx = makeTransaction(k, selected.body, selected.contexts);
    const actual = canonicalTransaction(tx);
    const expected = structuredClone(selected.body);
    if (request.operation === 'build') expected.id = actual.id;
    assert.deepEqual(actual, expected, 'ordinary SDK complete body/ID mismatch');
    const safe = k.Transaction.deserializeFromSafeJSON(tx.serializeToSafeJSON());
    try { finalized(safe); assert.deepEqual(canonicalTransaction(safe), actual); }
    finally { safe.free(); }
    if (request.operation === 'sign-input') {
      key = new k.PrivateKey(request.funding_secret_hex32);
      const address = key.toAddress('testnet-10'), source = k.payToAddressScript(address);
      try { need(script(source) === selected.source_script_public_key, 'own-A-ordinary-key-control'); }
      finally { source.free(); address.free(); }
      const signature = k.createInputSignature(tx, request.input_index, key, k.SighashType.All);
      need(typeof signature === 'string' && /^41[0-9a-f]{128}01$/.test(signature), 'one-ordinary-ALL-signature');
      assert.deepEqual(canonicalTransaction(tx), actual, 'sign-input must not mutate transaction');
      return {input_index: request.input_index, signature_script_hex66: signature,
        network_or_broadcast: false, secret_material_emitted: false};
    }
    return {transaction: actual, lossless_safe_roundtrip: true,
      provisional_no_Native_fee_approval: request.operation === 'build',
      Native_consensus_currentness_or_metrics_verified: false,
      network_or_broadcast: false, secret_material_emitted: false};
  } finally { key?.free(); tx?.free(); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    need(process.argv.length === 2 || process.argv.length === 4 && process.argv[2] === '--sdk-dir', 'closed-CLI');
    const request = JSON.parse(fs.readFileSync(0, 'utf8'));
    process.stdout.write(JSON.stringify(run(request, process.argv[3] ?? '/runtime/sdk')) + '\n');
  } catch {
    // Never echo request contents, private scalar, input body or exception data.
    process.stderr.write('offline ordinary SDK refused\n'); process.exitCode = 2;
  }
}
