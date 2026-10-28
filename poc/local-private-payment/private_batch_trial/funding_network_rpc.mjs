// Every official SDK client connects only to a fresh single-session Tor bridge.
import {startTorBridge} from './funding_network_bridge.mjs';
export async function connectTor(k,upstream) {
  const bridge=await startTorBridge({upstream});
  let rpc;
  try {
    rpc=new k.RpcClient({url:bridge.url,networkId:'testnet-10'});
    const resolver=rpc.resolver;
    if(resolver!==undefined&&resolver!==null){resolver.free?.();throw new Error('SDK resolver must be disabled');}
    if(rpc.url!==undefined&&new URL(rpc.url).href!==new URL(bridge.url).href)throw new Error('SDK must use exact loopback bridge URL');
    await rpc.connect({blockAsyncConnect:true,timeoutDuration:300000,strategy:'fallback'});
    if(new URL(rpc.url).href!==new URL(bridge.url).href)throw new Error('SDK transport URL changed');
    const dag=await rpc.getBlockDagInfo();
    if(dag.network!=='testnet-10')throw new Error('testnet-10 identity required');
    return {rpc,transport:'TOR_SOCKS5H_TLS',close:async()=>{try{await rpc.disconnect();}finally{await bridge.close();}}};
  }catch(error){try{if(rpc)await rpc.disconnect();}finally{await bridge.close();}throw error;}
}
