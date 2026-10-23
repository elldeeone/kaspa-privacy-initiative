const fs=require('fs');const k=require('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js');
const url='wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh';
const address='kaspatest:qq3xehkenww2q3muvda58xmrw8ucqghp69ac7vgxh8gypg6uum4pclvfektpe';
const stringify=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x,2);
const r=new k.RpcClient({url,networkId:'testnet-10'});
(async()=>{try{await r.connect({timeoutDuration:15000});const info=await r.getServerInfo();if(info.networkId!=='testnet-10'||!info.isSynced||!info.hasUtxoIndex)throw Error('network/sync/index check failed');const [dag,utxos]=await Promise.all([r.getBlockDagInfo(),r.getUtxosByAddresses({addresses:[address]})]);const o={schema:'kpi-new-trial-readonly-funding/v1',observed_utc:new Date().toISOString(),scope:'read-only RPC; no key read, signatures, funding or broadcast',url,address,server_info:info,dag,utxos};fs.writeFileSync('research/next-session/testnet-rehearsal/funding/STAGING-UTXOS-WRPC-01.json',stringify(o)+'\n',{flag:'wx'});console.log(stringify(o));}finally{await r.disconnect();}})().then(()=>process.exit(0)).catch(e=>{console.error(e);process.exit(1)});
