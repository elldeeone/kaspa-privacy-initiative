import assert from 'node:assert/strict';
import {prefixData,verifyCopied} from './cache.mjs';
const groups=[0,1,2].map(i=>({chainBlockHeader:{hash:String(i)},acceptedTransactions:[{id:'tx'+i}]}));
const page={removedChainBlockHashes:[],addedChainBlockHashes:['0','1','2'],chainBlockAcceptedTransactions:groups};
let passed=0;
function test(name,work){work();passed++;process.stdout.write(name+' PASS\n');}
test('processed prefix cuts after exact midpage frontier',()=>{const p=prefixData(page,'1');assert.deepEqual(p.addedChainBlockHashes,['0','1']);assert.deepEqual(p.chainBlockAcceptedTransactions,groups.slice(0,2));assert.equal(page.chainBlockAcceptedTransactions.length,3);});
test('end boundary retains all actual rows',()=>assert.deepEqual(prefixData(page,'2'),page));
test('missing boundary never infers empty delta',()=>assert.throws(()=>prefixData(page,'missing')));
test('removed chain invalidates admitted prefix',()=>assert.throws(()=>prefixData({...page,removedChainBlockHashes:['x']},'1')));
test('truncated group arrays rejected',()=>assert.throws(()=>prefixData({...page,chainBlockAcceptedTransactions:groups.slice(1)},'1')));
test('absolute copied cache path rejected before read',()=>assert.throws(()=>verifyCopied('/var/tmp/kpi-local-private-payment-01',[{path:'/public/x',gzip_sha256:'00'.repeat(32)}])));
test('parent traversal rejected before read',()=>assert.throws(()=>verifyCopied('/var/tmp/kpi-local-private-payment-01',[{path:'../x',gzip_sha256:'00'.repeat(32)}])));
test('noncanonical copied path rejected before read',()=>assert.throws(()=>verifyCopied('/var/tmp/kpi-local-private-payment-01',[{path:'a//b',gzip_sha256:'00'.repeat(32)}])));
process.stdout.write(JSON.stringify({schema:'kpxa-cached-prefix-structural-controls/v1',passed,financial_or_chain_acceptance:false})+'\n');
