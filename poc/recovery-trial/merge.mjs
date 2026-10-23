// Ordinary test-KAS funding only. No RPC, pool state, prover or broadcast API.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {canonical, spk, stringify} from '../future-native-chain/adapter.mjs';

const SDK = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa';
const PINS = {'kaspa.js':'6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
  'kaspa_bg.wasm':'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
  'package.json':'8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'};
const GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
const MAX = 2870000000000000000n;
const digest = b => crypto.createHash('sha256').update(b).digest('hex');

export function sdk() {
  for (const [name, hash] of Object.entries(PINS))
    assert.equal(digest(fs.readFileSync(path.join(SDK, name))), hash, 'SDK identity');
  return createRequire(import.meta.url)(path.join(SDK, 'kaspa.js'));
}

function amount(value) {
  assert.equal(typeof value, 'string'); assert.match(value, /^(0|[1-9][0-9]*)$/);
  const n = BigInt(value); assert.ok(n > 0n && n <= MAX); return n;
}

export function build(k, request) {
  assert.equal(request.schema, 'kpi-tn10-ordinary-merge/v1');
  assert.equal(request.network_id, 'testnet-10'); assert.equal(request.genesis_hash_hex, GENESIS);
  assert.deepEqual(Object.keys(request).sort(), ['schema','network_id','genesis_hash_hex','inputs',
    'destination_spk','fee_sompi','storage_mass'].sort());
  assert.ok(Array.isArray(request.inputs) && request.inputs.length >= 1 && request.inputs.length <= 8);
  assert.match(request.destination_spk, /^000020[0-9a-f]{64}ac$/);
  const destination = new k.XOnlyPublicKey(request.destination_spk.slice(6, 70));
  destination.free();
  const fee = amount(request.fee_sompi), keys = [], contexts = [], seen = new Set();
  let total = 0n, tx, signed;
  try {
    const inputs = request.inputs.map(row => {
      assert.deepEqual(Object.keys(row).sort(), ['outpoint','amount_sompi','script_public_key',
        'block_daa_score','is_coinbase','covenant_id','private_key_hex32'].sort());
      assert.deepEqual(Object.keys(row.outpoint).sort(), ['index','transactionId']);
      assert.match(row.outpoint.transactionId, /^[0-9a-f]{64}$/);
      assert.ok(Number.isInteger(row.outpoint.index) && row.outpoint.index >= 0 && row.outpoint.index <= 0xffffffff);
      const point = row.outpoint.transactionId + ':' + row.outpoint.index;
      assert.ok(!seen.has(point), 'duplicate input'); seen.add(point);
      assert.equal(row.is_coinbase, false); assert.equal(row.covenant_id, null);
      assert.match(row.script_public_key, /^000020[0-9a-f]{64}ac$/);
      assert.match(row.private_key_hex32, /^[0-9a-f]{64}$/);
      assert.match(row.block_daa_score, /^(0|[1-9][0-9]*)$/);
      assert.ok(BigInt(row.block_daa_score) <= 0xffffffffffffffffn);
      const value = amount(row.amount_sompi); total += value; assert.ok(total <= MAX);
      const key = new k.PrivateKey(row.private_key_hex32); keys.push(key);
      const address = key.toAddress('testnet-10'), script = k.payToAddressScript(address);
      try { assert.equal(spk(script), row.script_public_key, 'source key mismatch'); }
      finally { script.free(); address.free(); }
      contexts.push(Object.fromEntries(Object.entries(row).filter(([name]) => name !== 'private_key_hex32')));
      return {previousOutpoint:row.outpoint, signatureScript:'', sequence:0xffffffffffffffffn,
        computeBudget:10, sigOpCount:0, utxo:{outpoint:row.outpoint, amount:value,
          scriptPublicKey:row.script_public_key, blockDaaScore:BigInt(row.block_daa_score), isCoinbase:false}};
    });
    assert.ok(total > fee, 'no positive output');
    assert.match(request.storage_mass, /^(0|[1-9][0-9]*)$/);
    assert.ok(BigInt(request.storage_mass) <= 0xffffffffffffffffn);
    tx = new k.Transaction({version:1, inputs, outputs:[{value:total-fee,
      scriptPublicKey:request.destination_spk}], lockTime:0n,
      subnetworkId:'0000000000000000000000000000000000000000', gas:0n, payload:'',
      storageMass:BigInt(request.storage_mass)});
    tx.finalize(); signed = k.signTransaction(tx, keys, true); signed.finalize();
    const transaction = canonical(signed);
    for (const input of transaction.inputs)
      assert.match(input.signatureScript, /^41[0-9a-f]{128}01$/, 'SIG_HASH_ALL P2PK frame');
    assert.equal(transaction.outputs.length, 1);
    assert.equal(transaction.outputs[0].scriptPublicKey, request.destination_spk);
    assert.equal(BigInt(transaction.outputs[0].value) + fee, total);
    return {schema:'kpi-tn10-ordinary-merge-body/v1', network_id:'testnet-10',
      transaction, inputs:contexts, fee_sompi:fee.toString(), secret_material_emitted:false};
  } finally {
    for (const key of keys) key.free();
    if (signed && signed !== tx) signed.free();
    if (tx) tx.free();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(stringify(build(sdk(), JSON.parse(fs.readFileSync(0, 'utf8')))) + '\n'); }
  catch { process.stderr.write('ordinary TN10 merge refused\n'); process.exitCode = 1; }
}
