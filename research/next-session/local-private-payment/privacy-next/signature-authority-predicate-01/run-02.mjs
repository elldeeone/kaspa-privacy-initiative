// PROSPECTIVE run-02 only: official C++ witness generation; original R1CS authority.
// Failed run-01 is immutable. No setup/proving/native/network API.
// Do not execute any mode before Root's frozen-source execution review.
import {createHash, randomBytes} from 'node:crypto';
import {spawn, spawnSync, execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {resolve, join, dirname, sep} from 'node:path';
import {mkdir, writeFile, stat, readdir, unlink, access} from 'node:fs/promises';

const HERE = dirname(fileURLToPath(import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const NODE = '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node';
const GUARD = '/var/tmp/kpi-root-guard-helper-09.py';
const SCRATCH = '/dev/shm/kpi-signature-predicate-scratch-01';
const RUN02_HANDOFF_SHA = '284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218';
const ORIGINAL_AUTHORITY_R1CS = SCRATCH+'/run-01/build/authority.r1cs';
const ORIGINAL_AUTHORITY_R1CS_SHA = 'ec0a3bedc3a64f8ae25096743e24f2be07ac2a623cea1b77114067483d12783d';
const REUSED_ASSET_SHAS = {authorityR1cs:ORIGINAL_AUTHORITY_R1CS_SHA,
  authorityWasm:'2a76b28b8b076c91027d84a3125172a2da6f3dd4aa5e7b2e3bc4c549c025607b',
  hashGoldenR1cs:'93046cde576bc2ceb518e8cf14628b0eed9f83862865678a527a8544c651fa2a',
  hashGoldenWasm:'c8e1842074f3ef494c4be8e32ac0df3e024718fa124a5b767f883c6f9f35a37b'};
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const TAG = Buffer.from('KPIAUT01', 'ascii');
const FIXTURE_RECIPE_SHA='e3a8e3d0fa1b5c0f265657d027aaed4b6694ed8bbe9ff6ab3caaea8fa3414093';
let RECIPE,RECIPE_SHA;
const COMPILED_PINS={};
const INPUT_FIELDS = ['anchor','nf','commitmentsOut','evaluationHeight','testTag','chainId',
  'poolId','profileId','roleId','assetTag','publicKeyBytes','signatureR8Bytes',
  'signatureSBytes','nullifyingKey','inputRandom','inputSompi','leafIndex','siblingCM',
  'outputNPK','valueOut','feeSompi','nonce','validFrom','validUntil','outputTuple'];
const requireTools = createRequire(join(HERE, 'tools', 'package.json'));
const json = (v) => JSON.stringify(v, (_k,x) => typeof x === 'bigint' ? x.toString() : x, 2) + '\n';
const plain = (v) => JSON.parse(json(v));
const clone = (v) => structuredClone(v);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const fail = (s) => {throw new Error(s);};
const need = (ok,s) => {if (!ok) fail(s);};
const le = (b) => {let x=0n; for(let k=b.length-1;k>=0;k--) x=(x<<8n)+BigInt(b[k]); return x;};
const bytes32 = (x) => {x=BigInt(x); need(x>=0n && x<1n<<256n,'u256');
  return Array.from({length:32},()=>{const b=Number(x&255n);x>>=8n;return b;});};
const packPoint = (p,F) => p.map(x=>bytes32(F.toObject(x)));
const unpackPoint = (b,F) => b.map(x=>F.e(le(x)));

function guardRead(path, expected='') {
  need(resolve(path)===path,'absolute_guard_path');
  const code='import runpy,sys; h=runpy.run_path(sys.argv[1]); b=h["read"](sys.argv[2],sys.argv[3] or None); sys.stdout.buffer.write(b)';
  return execFileSync('python3',['-c',code,GUARD,path,expected], {maxBuffer:256*1024*1024});
}
function loadRecipe() {
  const b=guardRead(join(HERE,'FIXTURE-RECIPE-01.json'),FIXTURE_RECIPE_SHA);
  RECIPE=JSON.parse(b);RECIPE_SHA=sha(b);
  need(RECIPE.schema==='signature-authority-finite-fixture-recipe/v1','recipe_schema');
  need(RECIPE.staticInputs.outputTagASCII==='KPIAUT01','recipe_output_tag');
}
function guardPin(path) {
  const code='import runpy,sys,hashlib,json; h=runpy.run_path(sys.argv[1]); b=h["read"](sys.argv[2]); print(json.dumps({"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}))';
  return JSON.parse(execFileSync('python3',['-c',code,GUARD,path],{maxBuffer:65536}));
}
function runPath(arg) {
  const p=resolve(arg||'');
  need(p===join(SCRATCH,'run-02'),'exact_new_run02_required');
  return p;
}
async function save(path,value) {await writeFile(path,json(value),{flag:'wx',mode:0o600});}
async function absent(path) {try {await access(path); fail('artifact_already_exists:'+path);} catch(e) {
  if(e.code!=='ENOENT') throw e;
}}
async function usedBytes(path) {let n=0;for(const ent of await readdir(path,{withFileTypes:true})) {
  const q=join(path,ent.name); need(!ent.isSymbolicLink(),'scratch_symlink');
  n+=ent.isDirectory()?await usedBytes(q):(await stat(q)).size;
}return n;}
async function resources(path,enforce=true) {
  const u=process.resourceUsage();
  const v={cpuMicros:u.userCPUTime+u.systemCPUTime,maxRSSKiB:u.maxRSS,
    rssBytes:process.memoryUsage().rss,scratchBytes:await usedBytes(path)};
  if(enforce) {
    need(v.cpuMicros<=30*60*1e6,'RESOURCE_CPU_30MIN');
    need(v.rssBytes<=4*1024**3,'RESOURCE_RAM_4GIB');
    need(v.scratchBytes<=2*1024**3,'RESOURCE_SCRATCH_2GIB');
  }
  return v;
}
async function math() {
  const {buildPoseidon,buildBabyjub}=requireTools('circomlibjs');
  const poseidon=await buildPoseidon(), baby=await buildBabyjub();
  const h=(v)=>BigInt(poseidon.F.toObject(poseidon(v.map(BigInt))));
  return {h,baby};
}
function tuple(i,j,cm) {
  const [a,b,c]=RECIPE.staticInputs.tupleLinearCoefficients;
  const out=Array.from({length:520},(_x,k)=>(a*k+b*j+c*i)%256);
  out.splice(0,32,...bytes32(cm));return out;
}
function refreshOutputs(input,h) {
  input.commitmentsOut=input.outputNPK.map((npk,j)=>h([npk,input.assetTag,input.valueOut[j]]).toString());
  input.outputTuple.forEach((t,j)=>t.splice(0,32,...bytes32(input.commitmentsOut[j])));
}
function message(input,h) {
  const bytes=Buffer.concat([TAG,...input.outputTuple.map(x=>{
    need(x.length===520 && x.every(b=>Number.isInteger(b)&&b>=0&&b<256),'host_tuple_bytes');
    return Buffer.from(x);
  })]);
  const digest=createHash('sha256').update(bytes).digest();
  const limbs=[le(digest.subarray(0,16)),le(digest.subarray(16,32))];
  const bound=h([input.testTag,input.chainId,input.poolId,input.profileId,input.roleId,
    input.nonce,input.validFrom,input.validUntil,input.feeSompi,...limbs,2]);
  return {digestHex:digest.toString('hex'),digestBytes:Array.from(digest),limbs,
    M:h([input.anchor,bound,input.nf,...input.commitmentsOut])};
}
function record(i,pk,anchor,sibling,h) {
  const f=RECIPE.staticInputs,nk=BigInt(f.nullifyingKeyBase)+BigInt(i);
  const r={anchor:String(anchor),nf:h([nk,i]).toString(),commitmentsOut:['0','0'],
    evaluationHeight:f.evaluationHeight,...f.tags,publicKeyBytes:clone(pk),
    signatureR8Bytes:[bytes32(0n),bytes32(0n)],signatureSBytes:bytes32(0n),
    nullifyingKey:nk.toString(),inputRandom:(BigInt(f.inputRandomBase)+BigInt(i)).toString(),inputSompi:f.inputSompi,
    leafIndex:String(i),siblingCM:String(sibling),outputNPK:[0,1].map(j=>(BigInt(f.outputNPKBase)+BigInt(2*i+j)).toString()),
    valueOut:clone(f.outputSompi),feeSompi:f.feeSompi,nonce:(BigInt(f.nonceBase)+BigInt(i)).toString(),
    validFrom:f.validFrom,validUntil:f.validUntil,outputTuple:[tuple(i,0,0n),tuple(i,1,0n)]};
  refreshOutputs(r,h);return r;
}
function inputCM(i,pk,h) {
  const f=RECIPE.staticInputs;
  const mpk=h([le(pk[0]),le(pk[1]),BigInt(f.nullifyingKeyBase)+BigInt(i)]);
  return h([h([mpk,BigInt(f.inputRandomBase)+BigInt(i)]),f.tags.assetTag,f.inputSompi]);
}
function exactInput(r) {
  need(Object.keys(r).sort().join('|')===INPUT_FIELDS.slice().sort().join('|'),'exact_input_fields');
  return plain(r);
}
function exactFields(value,fields,label) {
  need(value && Object.keys(value).sort().join('|')===fields.slice().sort().join('|'),label);
}
function rejectSecrets(value) {
  if(!value || typeof value!=='object') return;
  for(const [k,v] of Object.entries(value)) {
    need(!/^(seed|privateSeed|privateKey|signingKey|spendSigningKey|ownerSpendSigningKey)$/i.test(k),'forbidden_secret_handoff');
    rejectSecrets(v);
  }
}
const BUNDLE_FIELDS=['kind','ownerIndex','publicKeyBytes','inputCM','baseline','alternative',
  'nullifierKeyControl','replacementForPeer','usage'];
function validateBundle(m,i) {
  exactFields(m,BUNDLE_FIELDS,'owner_handoff_allowlist');
  need(m.kind==='signed-fixed-records'&&m.ownerIndex===i,'owner_handoff');
  exactFields(m.usage,['cpuMicros','maxRSSKiB'],'owner_usage_allowlist');
  for(const k of ['baseline','alternative','nullifierKeyControl','replacementForPeer']) exactInput(m[k]);
  rejectSecrets(m);
}

// Only this child mode holds a signing secret. IPC accepts a single fixed
// anchor/sibling request, not arbitrary messages or arbitrary signing requests.
async function ownerMode(i) {
  need(process.send && (i===0||i===1),'owner_ipc_only');
  const {buildEddsa}=requireTools('circomlibjs');
  const eddsa=await buildEddsa(), F=eddsa.babyJub.F;
  const h=(v)=>BigInt(eddsa.poseidon.F.toObject(eddsa.poseidon(v.map(BigInt))));
  const privateSeed=randomBytes(32), pk=packPoint(eddsa.prv2pub(privateSeed),F);
  const cm=inputCM(i,pk,h);
  process.send({kind:'ready',ownerIndex:i,publicKeyBytes:pk,inputCM:cm.toString()});
  process.once('message',async request=>{
    try {
      need(request && Object.keys(request).sort().join('|')==='anchor|kind|peerInputCM','fixed_owner_request');
      need(request.kind==='sign-fixed-records','fixed_owner_request_kind');
      const peer=BigInt(request.peerInputCM), anchor=BigInt(request.anchor);
      need(anchor===h(i===0?[cm,peer]:[peer,cm]),'owner_checks_common_anchor');
      const sign=r=>{
        const m=message(r,h), sig=eddsa.signPoseidon(privateSeed,F.e(m.M));
        r.signatureR8Bytes=packPoint(sig.R8,F);r.signatureSBytes=bytes32(sig.S);
        return exactInput(r);
      };
      const baseline=sign(record(i,pk,anchor,peer,h));
      const alternative=clone(baseline);
      alternative.outputNPK[0]=(BigInt(alternative.outputNPK[0])+10000n).toString();
      refreshOutputs(alternative,h);alternative.outputTuple[0][96]^=1;
      sign(alternative);
      const nullifierKeyControl=clone(baseline);
      nullifierKeyControl.nullifyingKey=(BigInt(baseline.nullifyingKey)+1n).toString();
      nullifierKeyControl.nf=h([nullifierKeyControl.nullifyingKey,i]).toString();
      sign(nullifierKeyControl);
      // Sign the other fixture owner's exact context using THIS owner's PK.
      // Root membership still refers to the original leaves: rejection tests
      // key-to-note binding even though the replacement signature is valid.
      const replacementForPeer=sign(record(1-i,pk,anchor,cm,h));
      const usage=process.resourceUsage();
      const publicBundle={kind:'signed-fixed-records',ownerIndex:i,publicKeyBytes:pk,
        inputCM:cm.toString(),baseline,alternative,nullifierKeyControl,replacementForPeer,
        usage:{cpuMicros:usage.userCPUTime+usage.systemCPUTime,maxRSSKiB:usage.maxRSS}};
      rejectSecrets(publicBundle);
      privateSeed.fill(0); // Best effort only; no host-memory erasure claim.
      await new Promise((ok,no)=>process.send(plain(publicBundle),e=>e?no(e):ok()));
      process.disconnect();process.exit(0);
    } catch(_e) {privateSeed.fill(0);process.send({kind:'owner-error',error:'OWNER_PHASE_FAILED'},()=>process.exit(1));}
  });
}
function startOwner(i) {
  need(process.execPath===NODE,'explicit_selected_node_required');
  const c=spawn(NODE,[SELF,'owner',String(i)],{stdio:['ignore','ignore','ignore','ipc'],
    env:{PATH:'/usr/bin:/bin',HOME:process.env.HOME,LANG:'C',NODE_OPTIONS:'--max-old-space-size=3072'}});
  const messages=[];let waiter;
  c.on('message',m=>{if(waiter){const w=waiter;waiter=null;w(m);}else messages.push(m);});
  const next=()=>messages.length?Promise.resolve(messages.shift()):new Promise(ok=>{waiter=ok;});
  const exit=new Promise((ok,no)=>{c.on('error',no);c.on('exit',(code,signal)=>{
    if(waiter){const w=waiter;waiter=null;w({kind:'unexpected-exit'});}
    ok({code,signal});
  });});
  return {c,next,exit};
}
async function prepare(dir) {
  await mkdir(dir,{recursive:false,mode:0o700});
  const owners=[];
  try {
    const a=startOwner(0);owners.push(a);const ar=await a.next();
    const b=startOwner(1);owners.push(b);const br=await b.next();
    for(const [i,r] of [ar,br].entries()) {
      exactFields(r,['kind','ownerIndex','publicKeyBytes','inputCM'],'owner_ready_allowlist');
      need(r.kind==='ready'&&r.ownerIndex===i,'owner_ready');
    }
    const {h}=await math(), anchor=h([ar.inputCM,br.inputCM]);
    const bundles=[],exits=[];
    for(const [i,o] of owners.entries()) {
      o.c.send({kind:'sign-fixed-records',anchor:anchor.toString(),peerInputCM:[br,ar][i].inputCM});
      const m=await o.next();validateBundle(m,i);
      rejectSecrets(m);const ex=await o.exit;need(ex.code===0&&!ex.signal,'owner_exit');
      bundles.push(m);exits.push({ownerIndex:i,code:ex.code,signal:ex.signal});
    }
    need(bundles[0].baseline.nf!==bundles[1].baseline.nf,'fixture_distinct_nf');
    const handoff={schema:'signature-authority-public-handoff/v1',classification:'NON-PRIVATE',
      planSHA256:'42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2',
      fixtureRecipeSHA256:RECIPE_SHA,
      ownerProcessesExitedBeforeAnyWitness:true,ownerExits:exits,owners:bundles};
    const text=json(handoff);await writeFile(join(dir,'HANDOFF.json'),text,{flag:'wx',mode:0o600});
    await save(join(dir,'PREPARE-RECORD.json'),{schema:'signature-predicate-prepare/v1',
      handoffSHA256:sha(text),handoffBytes:Buffer.byteLength(text),resources:await resources(dir),
      noSigningKeyInHandoff:true,scope:'synthetic authorization only; no witness/proof/native action'});
    console.log(json({status:'PUBLIC_HANDOFF_FROZEN_OWNERS_EXITED',handoffSHA256:sha(text)}));
  } catch(e) {
    await save(join(dir,'PREPARE-FAILURE.json'),{schema:'signature-predicate-prepare-failure/v1',
      failure:String(e.message).slice(0,500),resources:await resources(dir,false),noSigningKeyLogged:true});
    throw e;
  } finally {for(const o of owners) if(o.c.exitCode===null) o.c.kill('SIGTERM');}
}

function witnessSection(b) {
  need(b.subarray(0,4).toString()==='wtns'&&b.readUInt32LE(4)===2,'wtns_v2');
  let off=12,n8=0,count=0,prime=0n,data=-1;
  for(let n=0;n<b.readUInt32LE(8);n++) {
    const id=b.readUInt32LE(off),len=Number(b.readBigUInt64LE(off+4));off+=12;
    need(Number.isSafeInteger(len)&&off+len<=b.length,'wtns_section_bounds');
    if(id===1){n8=b.readUInt32LE(off);prime=le(b.subarray(off+4,off+4+n8));count=b.readUInt32LE(off+4+n8);}
    if(id===2)data=off;off+=len;
  }
  need(n8===32&&prime===P&&count>35&&data>=0&&data+count*n8===b.length,'wtns_header');
  return {n8,count,data,get:(i)=>le(b.subarray(data+32*i,data+32*(i+1)))};
}
function patchWitness(b,index,value) {
  const r=Buffer.from(b),w=witnessSection(r);need(index<w.count,'patch_index');
  Buffer.from(bytes32(value)).copy(r,w.data+32*index);return r;
}
function golden() {
  const d=createHash('sha256').update('abc','ascii').digest();
  need(d.toString('hex')==='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','sha_abc_golden');
  need(le(d.subarray(0,16))===0x2322ae5dde404141eacf018fbf1678ban,'le128_low_golden');
  need(le(d.subarray(16))===0xad1500f261ff10b49c7a1796a36103b0n,'le128_high_golden');
}
function cases(handoff,h,baby) {
  const [a,b]=handoff.owners, base=a.baseline, out=[];
  const add=(id,input,expected,notes='overlapping checks; rejection is not isolated constraint coverage')=>
    out.push({id,input:exactInput(input),expected,notes});
  for(const [i,o] of handoff.owners.entries()) {
    add('owner-'+i+'-unchanged-after-exit',clone(o.baseline),true,'R1CS satisfaction after owner exit; NON-PRIVATE');
    add('owner-'+i+'-new-exact-consent',clone(o.alternative),true,'AUTHORIZATION-ONLY; arbitrary fictional output validity remains unbuilt');
  }
  const mutate=(id,fn)=>{const r=clone(base);fn(r);add(id,r,false);};
  mutate('payment-npk-old-signature',r=>{r.outputNPK[0]=(BigInt(r.outputNPK[0])+1n).toString();refreshOutputs(r,h);});
  mutate('payment-value-old-signature',r=>{r.valueOut=['100000001','1889999999'];refreshOutputs(r,h);});
  mutate('nf-old-signature',r=>r.nf=(BigInt(r.nf)+1n).toString());
  mutate('fee-old-signature',r=>{r.feeSompi='10000001';r.valueOut[1]='1889999999';refreshOutputs(r,h);});
  for(const key of ['testTag','chainId','poolId','profileId','roleId','nonce','anchor'])
    mutate(key+'-old-signature',r=>r[key]=(BigInt(r[key])+1n).toString());
  for(const [label,offset] of [['cv',32],['cf',96],['ciphertextHash',360],['consistencyProof',392]])
    mutate(label+'-byte-old-signature',r=>r.outputTuple[0][offset]^=1);
  mutate('output-order-old-signature',r=>{r.outputTuple.reverse();r.outputNPK.reverse();r.valueOut.reverse();r.commitmentsOut.reverse();});
  mutate('byte-256',r=>r.outputTuple[0][96]=256);
  mutate('missing-signature-zero',r=>{r.signatureR8Bytes=[bytes32(0n),bytes32(0n)];r.signatureSBytes=bytes32(0n);});
  mutate('wrong-owner-signature',r=>{r.signatureR8Bytes=clone(b.baseline.signatureR8Bytes);r.signatureSBytes=clone(b.baseline.signatureSBytes);});
  add('replacement-key-valid-signature-original-leaf',clone(b.replacementForPeer),false);
  add('changed-nullifying-key-valid-signature-original-leaf',clone(a.nullifierKeyControl),false);
  mutate('leaf-index-changed',r=>r.leafIndex='1');
  mutate('sibling-cm-changed',r=>r.siblingCM=(BigInt(r.siblingCM)+1n).toString());
  mutate('height-before-signed-interval',r=>r.evaluationHeight='99');
  mutate('height-after-signed-interval',r=>r.evaluationHeight='201');
  mutate('conservation-fails',r=>{r.valueOut[0]='100000001';refreshOutputs(r,h);});
  for(const field of ['publicKeyBytes','signatureR8Bytes']) {
    mutate(field+'-identity',r=>r[field]=[bytes32(0n),bytes32(1n)]);
    mutate(field+'-offcurve',r=>r[field]=[bytes32(0n),bytes32(0n)]);
    mutate(field+'-smallorder',r=>r[field]=[bytes32(0n),bytes32(P-1n)]);
    mutate(field+'-mixedorder',r=>{const pt=unpackPoint(r[field],baby.F);
      r[field]=packPoint(baby.addPoint(pt,[baby.F.e(0),baby.F.e(P-1n)]),baby.F);});
    mutate(field+'-p-alias',r=>r[field][0]=bytes32(le(r[field][0])+P));
    mutate(field+'-topbit',r=>r[field][0][31]|=128);
  }
  mutate('S-equals-Q',r=>r.signatureSBytes=bytes32(Q));
  mutate('S-plus-Q',r=>r.signatureSBytes=bytes32(le(r.signatureSBytes)+Q));
  mutate('S-topbit',r=>r.signatureSBytes[31]|=128);
  mutate('CM-p-alias',r=>r.outputTuple[0].splice(0,32,...bytes32(BigInt(r.commitmentsOut[0])+P)));
  return out;
}
// Standard official C++ main(input.json, output.wtns); .dat is adjacent.
// This replaces only authority witness generation. No callback suppression,
// host validity verdict or partial-witness fallback. All acceptance is R1CS.
async function generateAuthorityCpp(input,wtnsPath) {
  const dir=dirname(wtnsPath), inputPath=join(dir,'CPP-GENERATION-INPUT.json');
  const executable=join(dir,'build-cpp','authority_cpp','authority');
  await writeFile(inputPath,json(input),{mode:0o600});
  const child=spawnSync(executable,[inputPath,wtnsPath],
    {cwd:dirname(executable),maxBuffer:65536,env:{...process.env,TMPDIR:join(SCRATCH,'tmp')}});
  await writeFile(join(dir,'CPP-GENERATION-STDOUT.log'),child.stdout||'');
  await writeFile(join(dir,'CPP-GENERATION-STDERR.log'),child.stderr||'');
  need(!child.error&&child.status===0&&child.signal===null,
    'CPP_GENERATION_FAILED:'+String(child.status)+':'+String(child.signal)+':'+String(child.stderr||child.error||'').slice(0,500));
  need((await stat(wtnsPath)).size>0,'CPP_EMPTY_WITNESS_NOT_SUCCESS');
}

async function check(dir,expected) {
  need(expected===RUN02_HANDOFF_SHA,'exact_reused_handoff_sha256_required');
  await absent(join(dir,'RESULT.json'));await absent(join(dir,'RUN-RECORD.json'));
  const handoffBytes=guardRead(join(dir,'HANDOFF.json'),expected),handoff=JSON.parse(handoffBytes);
  exactFields(handoff,['schema','classification','planSHA256','fixtureRecipeSHA256',
    'ownerProcessesExitedBeforeAnyWitness','ownerExits','owners'],'handoff_exact_schema');
  need(handoff.schema==='signature-authority-public-handoff/v1'&&handoff.owners.length===2,'handoff_schema');
  need(handoff.classification==='NON-PRIVATE'&&handoff.planSHA256==='42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2','handoff_scope');
  need(handoff.fixtureRecipeSHA256===RECIPE_SHA,'handoff_recipe_pin');
  need(handoff.ownerExits.length===2,'owner_exit_count');
  for(const [i,x]of handoff.ownerExits.entries()) {
    exactFields(x,['ownerIndex','code','signal'],'owner_exit_schema');
    need(x.ownerIndex===i&&x.code===0&&x.signal===null,'owner_exit_status');
    validateBundle(handoff.owners[i],i);
  }
  need(handoff.ownerProcessesExitedBeforeAnyWitness===true,'owners_exited');
  rejectSecrets(handoff);golden();
  const r1cs=join(dir,'build','authority.r1cs'),wasm=join(dir,'build','authority_js','authority.wasm');
  for(const [id,p]of Object.entries({authorityR1cs:r1cs,authorityWasm:wasm,
    hashGoldenR1cs:join(dir,'build','hash-golden.r1cs'),hashGoldenWasm:join(dir,'build','hash-golden_js','hash-golden.wasm')}))
    COMPILED_PINS[id]={path:p,...guardPin(p)};
  for(const [id,pin] of Object.entries(COMPILED_PINS))
    need(pin.sha256===REUSED_ASSET_SHAS[id],'reused_compiled_asset_changed:'+id);
  // Control1: byte identity, not merely the same circuit name/constraint count.
  const original=guardRead(ORIGINAL_AUTHORITY_R1CS,ORIGINAL_AUTHORITY_R1CS_SHA);
  const reference=guardRead(r1cs,ORIGINAL_AUTHORITY_R1CS_SHA);
  const rebuiltR1cs=join(dir,'build-cpp','authority.r1cs');
  const rebuilt=guardRead(rebuiltR1cs,ORIGINAL_AUTHORITY_R1CS_SHA);
  need(original.equals(reference)&&original.equals(rebuilt),'FULL_R1CS_BYTE_IDENTITY_REQUIRED');
  COMPILED_PINS.cppRebuiltR1cs={path:rebuiltR1cs,...guardPin(rebuiltR1cs)};
  for(const [id,p]of Object.entries({cppGenerator:join(dir,'build-cpp','authority_cpp','authority'),
    cppData:join(dir,'build-cpp','authority_cpp','authority.dat')}))
    COMPILED_PINS[id]={path:p,...guardPin(p)};
  const {h,baby}=await math();
  const {default:calculate}=await import(pathToFileURL(join(HERE,'tools/node_modules/snarkjs/src/wtns_calculate.js')));
  const {default:checkSerial}=await import('./check-serial.mjs');
  const rows=[],tests=cases(handoff,h,baby),started=process.hrtime.bigint();let positiveA;
  need(tests.map(x=>x.id).join('|')===RECIPE.authorityCases.map(x=>x.id).join('|'),'finite_case_ids');
  need(tests.every((x,i)=>x.expected===RECIPE.authorityCases[i].expectedAccepted),'finite_case_expectations');
  const logger={info:()=>{},warn:()=>{}};let failure=null;
  const tryCheck=async(path)=>{try{return {checked:true,accepted:await checkSerial(r1cs,path,logger)};}
    catch(e){return {checked:false,error:String(e.message).slice(0,500)};}};
  try {
    await resources(dir);
    const gr=join(dir,'build','hash-golden.r1cs'),gw=join(dir,'build','hash-golden_js','hash-golden.wasm');
    const gp=join(dir,'hash-golden.wtns'),gb=RECIPE.staticInputs.hashGoldenBytes;
    need(gb.length===64&&gb.every((x,i)=>x===i),'golden_fixed_bytes_0_to_63');
    await calculate({bytes:gb},gw,gp,{sanityCheck:false});
    const gRow={id:'hash-golden-padding-55-56-63-64',expectedAccepted:true,witnessGenerated:true,
      checked:true,accepted:await checkSerial(gr,gp,logger),vectors:[],notes:'one R1CS check of four length-specific SHA relations'};
    const gRaw=guardRead(gp),gW=witnessSection(gRaw);
    for(const [i,n] of [55,56,63,64].entries()) {
      const digest=createHash('sha256').update(Buffer.from(gb.slice(0,n))).digest();
      const start=1+i*34,fields=Array.from({length:32},(_x,k)=>gW.get(start+k));
      need(fields.every(x=>x>=0n&&x<256n),'golden_digest_output_byte_range');
      const got=fields.map(Number);
      gRow.vectors.push({bytes:n,digestHex:Buffer.from(got).toString('hex'),
        digestMatchesNode:Buffer.from(got).equals(digest),
        limbsMatchNode:gW.get(start+32)===le(digest.subarray(0,16))&&gW.get(start+33)===le(digest.subarray(16))});
    }
    gRow.matchesExpected=gRow.accepted&&gRow.vectors.every(v=>v.digestMatchesNode&&v.limbsMatchNode);
    rows.push(gRow);need(gRow.matchesExpected,'hash_golden_r1cs_or_byte_order');
    for(const tc of tests) {
      await resources(dir);const path=join(dir,tc.expected?tc.id+'.wtns':'negative.wtns');
      const row={id:tc.id,expectedAccepted:tc.expected,notes:tc.notes};
      try {await generateAuthorityCpp(tc.input,path);row.witnessGenerated=true;}
      catch(e) {row.witnessGenerated=false;row.generationError=String(e.message).slice(0,500);}
      if(row.witnessGenerated) {
        Object.assign(row,await tryCheck(path));
        if(row.accepted) {
          try {
            const raw=guardRead(path),w=witnessSection(raw),m=message(tc.input,h);
            const fields=Array.from({length:32},(_x,i)=>w.get(i+1));
            need(fields.every(x=>x>=0n&&x<256n),'digest_output_byte_range');
            const got=fields.map(Number);
            row.digestHex=Buffer.from(got).toString('hex');
            row.digestMatchesNode=row.digestHex===m.digestHex;
            row.limbsMatchNode=w.get(33)===m.limbs[0]&&w.get(34)===m.limbs[1];
            row.messageMatchesNode=w.get(35)===m.M;
            need(row.digestMatchesNode&&row.limbsMatchNode&&row.messageMatchesNode,'digest_or_message_differential');
            if(tc.id==='owner-0-unchanged-after-exit') positiveA=raw;
          } catch(e) {row.differentialError=String(e.message).slice(0,500);}
        }
      }
      row.outcome=row.checked?'R1CS_CHECK_'+(row.accepted?'ACCEPT':'REJECT'):
        row.witnessGenerated?'CHECKER_ERROR':'GENERATION_ONLY_REJECTION';
      row.matchesExpected=!!(!row.differentialError && (tc.expected?row.checked&&row.accepted:
        row.checked?!row.accepted:!row.witnessGenerated));
      row.actualCheckerRequired=RECIPE.authorityCases.find(x=>x.id===tc.id).actualCheckerRequired;
      if(row.actualCheckerRequired) row.matchesExpected=!!(row.matchesExpected&&row.checked&&row.accepted===tc.expected);
      rows.push(row);
      if(!row.matchesExpected) {
        await save(join(dir,'CASE-FAILURE-INPUT.json'),{id:tc.id,input:tc.input,expectedAccepted:tc.expected});
        if(row.witnessGenerated) row.failureWitness={path,...guardPin(path)};
      }
      if(!tc.expected && row.witnessGenerated && row.matchesExpected) await unlink(path);
      need(row.matchesExpected,'unexpected_case:'+tc.id);
    }
    need(positiveA,'positive_witness_for_stale_limb');
    const w=witnessSection(positiveA);
    for(const slot of [33,34]) {
      await resources(dir);const path=join(dir,'negative.wtns');
      await writeFile(path,patchWitness(positiveA,slot,(w.get(slot)+1n)%P));
      const row={id:'stale-derived-digest-limb-slot-'+slot,expectedAccepted:false,
        witnessGenerated:true,...await tryCheck(path),notes:'known positive witness output limb patched; actual R1CS-check control'};
      row.matchesExpected=row.checked&&!row.accepted;rows.push(row);
      if(row.matchesExpected) await unlink(path);
      else {
        row.failureWitness={path,...guardPin(path)};
        await save(join(dir,'CASE-FAILURE-INPUT.json'),{id:row.id,positiveSource:'owner-0-unchanged-after-exit.wtns',
          mutation:'slot '+slot+' add1modP only',expectedAccepted:false});
      }
      need(row.matchesExpected,'unexpected_stale_limb:'+slot);
    }
  } catch(e) {failure=String(e.message).slice(0,1000);}
  const result={schema:'signature-authority-predicate-result/v1',classification:'NON-PRIVATE_NO_GROTH16_NATIVE_OR_PRIVACY_PROOF',
    status:failure?'FAIL_PRESERVED':'BOUNDED_PREDICATE_CHECKS_MATCH_FROZEN_EXPECTATIONS',failure,
    runIdentity:'run-02',priorRun01FailurePreserved:true,authorityWitnessGenerator:'OFFICIAL_CPP_SANITY0_NO_ASM_ORIGINAL_R1CS',
    expectedFiniteRows:tests.length+3,completedRows:rows.length,rows,
    authorizationOnlyOutputValidityUnbuilt:true,activeRetryFailureUnchanged:true,twoPercentFeeFailureUnchanged:true,
    noSigningKeyInHandoff:true,ownerProcessesExitedBeforeWitness:true,
    limits:['plain prover sees full map and all shared note/NF material','no native note/profile compatibility',
      'no encryption/output proof/receipt validation','no replay database or accepted-chain current-state oracle',
      'no MPC/malicious prover/independent exit/liveness claim','generation-only rejection is not R1CS-check evidence']};
  await save(join(dir,'RESULT.json'),result);
  await save(join(dir,'RUN-RECORD.json'),{schema:'signature-predicate-run/v1',handoffSHA256:expected,
    elapsedNanoseconds:(process.hrtime.bigint()-started).toString(),resources:await resources(dir,false),
    compiledAssets:COMPILED_PINS,fixtureRecipeSHA256:RECIPE_SHA,
    resultSHA256:sha(json(result)),retention:'positive witnesses and first mismatch witness/input; expected rejected witnesses deleted',oneSerialJob:true});
  console.log(json({status:result.status,completedRows:rows.length,expectedRows:tests.length+3,failure}));
  if(failure)process.exitCode=1;
}

async function main() {
  need(process.execPath===NODE,'explicit_selected_node_required');
  loadRecipe();
  const [mode,arg,expected]=process.argv.slice(2);
  // No owner/prepare mode: reuse frozen public handoff; never rekey/resign.
  if(mode==='check')return check(runPath(arg),expected);
  fail('usage: explicit-node run-02.mjs check <exact-run-02-dir> <fixed-reused-handoff-sha256>');
}
main().catch(async e=>{
  const message=String(e.message).slice(0,1000),[mode,arg]=process.argv.slice(2);
  try {
    if(mode==='prepare'||mode==='check') {
      const dir=runPath(arg);await stat(dir);
      const stop={schema:'signature-predicate-source-or-preflight-stop/v1',mode,failure:message,
        resources:await resources(dir,false),compiledAssets:COMPILED_PINS,
        classification:'PRESERVED_FAILURE_NO_NATIVE_OR_PROOF_CLAIM'};
      await save(join(dir,'STOP-RECORD.json'),stop);
      try {await save(join(dir,'RUN-RECORD.json'),stop);}catch(_e) {}
    }
  }catch(_e) {}
  console.error('SIGNATURE_PREDICATE_STOP:'+message);process.exitCode=1;
});
