import assert from 'node:assert/strict';
import {test} from 'node:test';
import {MiningJobs} from './mining_jobs.mjs';
const job=id=>({id,identity:'public-body-'+id,used:false});
test('slow RPC replacement preserves queued work against its original exact template',async()=>{
 const jobs=new MiningJobs(),first=jobs.retain(job('old')),events=[];
 const consume=async(message,retained)=>{events.push(['consumed',retained.id,message.nonce]);retained.used=true;};
 await jobs.during(async()=>{
   events.push(['RPC-start']);
   setTimeout(()=>jobs.offer({id:'old',nonce:'7'}),10);
   await new Promise(resolve=>setTimeout(resolve,50));
   jobs.retain(job('new'));events.push(['RPC-end']);
 },consume);
 assert.deepEqual(events,[['RPC-start'],['RPC-end'],['consumed','old','7']]);
 assert.equal(first.used,true);
});
test('pending found work drains before another remote request starts',async()=>{
 const jobs=new MiningJobs();jobs.retain(job('a'));jobs.offer({id:'a',nonce:'1'});const events=[];
 await jobs.during(async()=>events.push('request'),async(m,j)=>{events.push('found');j.used=true;});
 assert.deepEqual(events,['found','request']);
});
test('duplicate candidate and repeated template identity cannot reset consumed work',async()=>{
 const jobs=new MiningJobs();const first=jobs.retain(job('a'));let submitted=0;
 jobs.offer({id:'a',nonce:'1'});jobs.offer({id:'a',nonce:'1'});
 await jobs.drain(async(m,j)=>{j.used=true;submitted++;});
 assert.equal(jobs.retain(job('a')),first);jobs.offer({id:'a',nonce:'2'});
 await jobs.drain(async()=>{submitted++;});assert.equal(submitted,1);
 assert.throws(()=>jobs.retain({id:'a',identity:'different-body',used:false}));
});
