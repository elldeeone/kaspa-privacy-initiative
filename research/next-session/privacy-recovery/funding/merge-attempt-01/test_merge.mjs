import {test} from 'node:test';
import assert from 'node:assert/strict';
import {build, sdk} from './merge.mjs';
import {spk} from '../future-native-chain/adapter.mjs';

const k = sdk();
function script(secret) {
  const key = new k.PrivateKey(secret), address = key.toAddress('testnet-10');
  const pub = k.payToAddressScript(address);
  try { return spk(pub); } finally { pub.free(); address.free(); key.free(); }
}
export function fixture() {
  const secret = ['01'.repeat(32), '02'.repeat(32)];
  return {schema:'kpi-tn10-ordinary-merge/v1', network_id:'testnet-10',
    genesis_hash_hex:'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
    inputs:secret.map((value, index) => ({outpoint:{transactionId:(index ? '22':'11').repeat(32), index:0},
      amount_sompi:index ? '600000000':'500000000', script_public_key:script(value),
      block_daa_score:'0', is_coinbase:false, covenant_id:null, private_key_hex32:value})),
    destination_spk:script('03'.repeat(32)), fee_sompi:'500000', storage_mass:'0'};
}
test('two ordinary owners authorize one exact output with ALL and no secret fields', () => {
  const request = fixture(), result = build(k, request), body = result.transaction;
  assert.equal(body.outputs[0].value, '1099500000');
  assert.equal(body.outputs[0].scriptPublicKey, request.destination_spk);
  assert.equal(body.inputs.length, 2);
  assert.equal(body.storageMass, '0');
  assert.equal(JSON.stringify(result).includes('private_key_hex32'), false);
  assert.equal(JSON.stringify(result).includes(request.inputs[0].private_key_hex32), false);
});
test('wrong source key is rejected before signing', () => {
  const request = fixture(); request.inputs[0].private_key_hex32 = '04'.repeat(32);
  assert.throws(() => build(k, request), /source key mismatch/);
});
test('duplicate, nonordinary, mainnet and imprecise amount inputs are rejected', () => {
  const changes = [r => {r.inputs[1].outpoint = {...r.inputs[0].outpoint};},
    r => {r.inputs[0].covenant_id = '00'.repeat(32);},
    r => {r.network_id = 'mainnet';}, r => {r.inputs[0].amount_sompi = 500000000;}];
  for (const change of changes) { const request = fixture(); change(request); assert.throws(() => build(k, request)); }
});
test('invalid destination point and overspend are rejected', () => {
  const request = fixture(); request.destination_spk = '000020' + 'ff'.repeat(32) + 'ac';
  assert.throws(() => build(k, request));
  const overspend = fixture(); overspend.fee_sompi = '1100000000';
  assert.throws(() => build(k, overspend), /no positive output/);
});
