#!/usr/bin/env node
// Select a recent confirmed birth anchor before funding; no transaction input.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {GENESIS, loadSdk, need, stringify} from './wire.mjs';
import {checkedPath, readPublic, profile} from './selection.mjs';
import {frontier, save} from './acquire.mjs';
import {DEFAULT_RPCS} from './fetch.mjs';

export async function capture(profilePath,profileSha,output,urls=DEFAULT_RPCS,k=loadSdk()) {
  const selected=profile(readPublic(profilePath,profileSha),profileSha);
  output=checkedPath(output);need(!fs.existsSync(output),'OUTPUT_EXISTS','fresh public anchor output required');
  const attempts=[];
  for(const endpoint of urls) {
    const url=new URL(endpoint);
    need(url.protocol==='wss:'&&!url.username&&!url.password&&!url.search&&!url.hash,
      'ENDPOINT','public TLS endpoint required');
    const rpc=new k.RpcClient({url:url.href,networkId:'testnet-10'});
    try {
      await rpc.connect({blockAsyncConnect:true,timeoutDuration:60000,strategy:'fallback'});
      const found=await frontier(k,rpc);
      const value={schema:'kpx8-gn3-birth-anchor/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
        financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,birth_start_hash:found.header.hash,
        birth_header:found.header,observed_sink:found.sink,min_confirmation_count:found.min_confirmation_count,
        server:found.source.server,rpc_url:url.href,attempts,observed_at:new Date().toISOString(),
        trial_created_or_funding_currentness_or_readiness_claimed:false};
      save(output,value);return value;
    } catch(error) {
      attempts.push({rpc_url:url.href,status:'INCOMPLETE',category:error.category??'DATA_UNAVAILABLE',
        error:String(error.message??error)});
    } finally {await rpc.disconnect();}
  }
  const result={schema:'kpx8-gn3-birth-anchor/v1',status:'INCOMPLETE',attempts,
    financial_profile_sha256:selected.financial_profile_sha256,selection_file_sha256:profileSha,funding_authorized:false};
  save(output,result);return result;
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
  try {
    const [pp,ps,output,...rest]=process.argv.slice(2),urls=[];let sdk;
    need(pp&&ps&&output,'ARGUMENT','anchor.mjs PROFILE SHA FRESH_OUTPUT [--rpc URL] [--sdk-dir DIR]');
    for(let i=0;i<rest.length;i+=2) {
      need(rest[i+1]&&['--rpc','--sdk-dir'].includes(rest[i]),'ARGUMENT','unknown option');
      if(rest[i]==='--rpc')urls.push(rest[i+1]);else {need(!sdk,'ARGUMENT','duplicate SDK directory');sdk=checkedPath(rest[i+1]);}
    }
    const value=await capture(pp,ps,output,urls.length?urls:DEFAULT_RPCS,loadSdk(sdk));
    process.stdout.write(stringify({status:value.status??'RECENT_ANCHOR_OBSERVED',
      output,birth_start_hash:value.birth_start_hash})+'\n');
    if(value.status==='INCOMPLETE')process.exitCode=2;
  } catch(error) {
    process.stderr.write(`GN3 birth anchor incomplete: ${error.category??'ERROR'}: ${error.message}\n`);
    process.exitCode=2;
  }
}
