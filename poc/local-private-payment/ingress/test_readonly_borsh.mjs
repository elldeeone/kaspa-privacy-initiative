import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {spawn} from 'node:child_process';
import {METHODS,request,requestLine,loopback,materialize,encode} from './readonly_borsh_worker.mjs';
import {ipcClient,connectReadOnlyBorsh} from '../chain/readonly_borsh_rpc.mjs';
import {entry as originalEntry} from '../chain/acquire.mjs';
const HASH='a'.repeat(64),POINT={transactionId:HASH,index:1},MAX=(1n<<64n)-1n;
const q=(method,params,id=1)=>({id,method,params});
function header(){let freed=false;return {raw:{hash:HASH,version:1,parentsByLevel:{toExpanded:()=>[[HASH]],free:()=>{freed=true;}},hashMerkleRoot:HASH,acceptedIdMerkleRoot:HASH,utxoCommitment:HASH,timestamp:MAX,bits:1,nonce:MAX,daaScore:4n,blueScore:3n,blueWork:5n,pruningPoint:HASH},freed:()=>freed};}
class OpaquePoint {toJSON(){return POINT;}}
function utxo(){return {outpoint:new OpaquePoint(),entry:{outpoint:new OpaquePoint(),amount:MAX,scriptPublicKey:{version:0,script:'51'},blockDaaScore:6n,isCoinbase:false,covenantId:null}};}
test('five read-only request shapes and monotonic ids',()=>{
 const rows=[['getServerInfo',{}],['getBlockDagInfo',{}],['getBlock',{hash:HASH,includeTransactions:false}],['getUtxosByAddresses',{addresses:['kaspatest:qqqq']}],['getVirtualChainFromBlockV2',{startHash:HASH,dataVerbosityLevel:'Full',minConfirmationCount:20}]];
 assert.equal(rows.length,METHODS.length);rows.forEach(([m,p],i)=>assert.equal(request(q(m,p,i+1),i).id,i+1));
});
test('unknown/financial methods, malformed ids and duplicate fields reject',()=>{
 for(const m of ['submitTransaction','constructor','__proto__'])assert.throws(()=>request(q(m,{}),0));
 for(const id of [0,-1,1.1,Number.MAX_SAFE_INTEGER+1,2])assert.throws(()=>request(q('getServerInfo',{},id),0));
 assert.throws(()=>request(q('getServerInfo',{},1),1));assert.throws(()=>request({...q('getServerInfo',{}),extra:true},0));
 assert.throws(()=>requestLine('{"id":1,"id":1,"method":"getServerInfo","params":{}}',0));
 assert.throws(()=>requestLine('{"id":1,"method":"getServerInfo","params":{"a":1,"a":2}}',0));
});
test('header-only block, Full depth20 and testnet address policy',()=>{
 assert.throws(()=>request(q('getBlock',{hash:HASH,includeTransactions:true}),0));
 for(const n of [0,19,21,'20'])assert.throws(()=>request(q('getVirtualChainFromBlockV2',{startHash:HASH,dataVerbosityLevel:'Full',minConfirmationCount:n}),0));
 assert.throws(()=>request(q('getVirtualChainFromBlockV2',{startHash:HASH,dataVerbosityLevel:'Ids',minConfirmationCount:20}),0));
 assert.throws(()=>request(q('getUtxosByAddresses',{addresses:['kaspa:qqqq']}),0));
});
test('only IPv4 ws loopback; upstream peer ports reject before source/RPC',async()=>{
 assert.equal(loopback('ws://127.0.0.1:1234'),'ws://127.0.0.1:1234/');
 for(const u of ['wss://127.0.0.1:1234/','ws://localhost:1234/','ws://10.0.0.1:1234/','ws://127.0.0.1:1234/private','ws://u:p@127.0.0.1:1234/','ws://127.0.0.1:1234/?x=1'])assert.throws(()=>loopback(u));
 await assert.rejects(connectReadOnlyBorsh(null,'wss://electron-10.kaspa.blue:8888/kaspa/testnet-10/wrpc/borsh',{}),/selected testnet/);
});
test('opaque parents expand/free; uint64 and BOOL survive response encoding',()=>{
 const h=header(),v=JSON.parse(encode(materialize('getVirtualChainFromBlockV2',{removedChainBlockHashes:[],addedChainBlockHashes:[HASH],chainBlockAcceptedTransactions:[{chainBlockHeader:h.raw,acceptedTransactions:[{version:1,value:MAX,flag:false}]}]})));
 assert(h.freed());assert.deepEqual(v.chainBlockAcceptedTransactions[0].chainBlockHeader.parentsByLevel,[[HASH]]);assert.equal(v.chainBlockAcceptedTransactions[0].chainBlockHeader.nonce,MAX.toString());assert.equal(v.chainBlockAcceptedTransactions[0].acceptedTransactions[0].value,MAX.toString());assert.equal(v.chainBlockAcceptedTransactions[0].acceptedTransactions[0].flag,false);
 const h2=header();assert.equal(materialize('getBlock',{block:{header:h2.raw,transactions:[],verboseData:{isChainBlock:true,selectedParentHash:HASH}}}).block.header.timestamp,MAX.toString());assert(h2.freed());
});
test('opaque outpoints and SDK UTXOs use old semantic entry validator',()=>{
 const parsed=JSON.parse(encode(materialize('getUtxosByAddresses',{entries:[utxo()]})));assert.deepEqual(parsed.entries[0].outpoint,POINT);
 const c=originalEntry(parsed.entries[0]);assert.equal(c.amount_sompi,MAX.toString());assert.equal(c.script_public_key,'000051');assert.equal(c.is_coinbase,false);assert.equal(c.covenant_id,null);
 const bad=utxo();bad.outpoint={transactionId:'b'.repeat(64),index:1};assert.throws(()=>materialize('getUtxosByAddresses',{entries:[bad]}));
 for(const amount of [Number(MAX),MAX+1n]){const bad=utxo();bad.entry.amount=amount;assert.throws(()=>materialize('getUtxosByAddresses',{entries:[bad]}));}
});
test('nonfinite rejects; finite difficulty, BOOL and wide integers retain types',()=>{
 assert.throws(()=>encode({v:NaN}));assert.throws(()=>encode({v:Infinity}));assert.deepEqual(JSON.parse(encode({flag:true,difficulty:0.5,value:9007199254740993n})),{flag:true,difficulty:0.5,value:'9007199254740993'});
});
class Child extends EventEmitter {
 constructor(){super();this.exitCode=null;this.stdout=new PassThrough();this.stderr=new PassThrough();this.stdin=new PassThrough();this.requests=[];this.stdin.on('data',b=>this.requests.push(JSON.parse(String(b))));this.stdin.once('finish',()=>queueMicrotask(()=>this.kill()));}
 kill(){if(this.exitCode!==null)return false;this.exitCode=0;this.emit('exit',0);this.emit('close',0);return true;}
 ready(){this.stdout.write(JSON.stringify({ready:true,network_id:'testnet-10',transport:'TOR_SOCKS5H_TLS_BORSH',rpc_deadline_seconds:900})+'\n');}
 reply(v){this.stdout.write(JSON.stringify(v)+'\n');}
}
test('parent singleflight and correlated response',async()=>{
 const c=new Child(),p=ipcClient(c);c.ready();await p.ready;const first=p.rpc.getServerInfo();await new Promise(setImmediate);await assert.rejects(p.rpc.getBlockDagInfo(),/singleflight/);assert.equal(c.requests.length,1);c.reply({id:1,ok:true,params:{isSynced:true}});assert.deepEqual(await first,{isSynced:true});await p.close();
});
test('wrong id, duplicate reply fields and early EOF fail closed',async()=>{
 for(const variant of ['wrong','duplicate','EOF']){const c=new Child(),p=ipcClient(c);c.ready();await p.ready;const call=p.rpc.getServerInfo();await new Promise(setImmediate);
  if(variant==='wrong')c.reply({id:2,ok:true,params:{}});else if(variant==='duplicate')c.stdout.write('{"id":1,"ok":true,"params":{},"params":{}}\n');else c.stdout.end();
  await assert.rejects(call,/unavailable/);await assert.rejects(p.rpc.getServerInfo(),/closed/);await p.close();}
});
test('real spawn ENOENT without exit event closes promptly',async()=>{
 const c=spawn('/kpi-absent-readonly-worker-test',[],{stdio:['pipe','pipe','pipe']}),p=ipcClient(c);await assert.rejects(p.ready,/unavailable/);let timer;await Promise.race([p.close(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('spawn cleanup hung')),1000);})]);clearTimeout(timer);
});
