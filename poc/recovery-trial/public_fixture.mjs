// PUBLIC_SYNTHETIC_DO_NOT_FUND. These fixed private scalars are public test data.
import {spk} from '../future-native-chain/adapter.mjs';
export function publicFixture(k) {
  function script(secret) {
    const key = new k.PrivateKey(secret), address = key.toAddress('testnet-10');
    const pub = k.payToAddressScript(address);
    try { return spk(pub); } finally { pub.free(); address.free(); key.free(); }
  }
  const secret = ['01'.repeat(32), '02'.repeat(32)];
  return {schema:'kpi-tn10-ordinary-merge/v1', network_id:'testnet-10',
    genesis_hash_hex:'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
    inputs:secret.map((value, index) => ({outpoint:{transactionId:(index ? '22':'11').repeat(32), index:0},
      amount_sompi:index ? '600000000':'500000000', script_public_key:script(value),
      block_daa_score:'0', is_coinbase:false, covenant_id:null, private_key_hex32:value})),
    destination_spk:script('03'.repeat(32)), fee_sompi:'500000', storage_mass:'0'};
}
