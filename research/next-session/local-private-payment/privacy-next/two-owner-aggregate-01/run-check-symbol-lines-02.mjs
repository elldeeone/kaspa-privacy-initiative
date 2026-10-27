// SOURCE ONLY until Root selects this complete finite source/run closure.
// Public fictional mechanics. No owners, signing, setup/proving/native/network API.
import {createHash} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {dirname,join,resolve} from 'node:path';
import {mkdir,writeFile,lstat,readdir,unlink,access} from 'node:fs/promises';

const HERE=dirname(fileURLToPath(import.meta.url));
const NODE='/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node';
const GUARD='/var/tmp/kpi-root-guard-helper-09.py';
const TOOLS='/var/tmp/kpi-signature-predicate-tools-20261026-01';
const PRIOR=resolve(HERE,'../signature-authority-predicate-01');
const CHECKER=join(PRIOR,'check-serial.mjs');
const CHECKER_SHA='922d1aefa3cbf99768a0bad34a00214df64de6c9253f2c27702e0ffab7b8a429';
const PLAN_SHA='458451f62e00bade1a7207b312ded0081ae05ac526c9c46318d54f6c5ddb2bc1';
const RECIPE_SHA='55c41c689eda997355ad92b879b744dd05246866ca9969e2f1865e647689c2b5';
const HANDOFF='/dev/shm/kpi-signature-predicate-scratch-01/run-01/HANDOFF.json';
const HANDOFF_SHA='284aef4352a57132a289dc81a8067290a0b15e6dc66e8735c5da71e73ae7f218';
const SCRATCH='/dev/shm/kpi-two-owner-aggregate-scratch-01';
const RUN=join(SCRATCH,'run-02');
const P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SHARED=['anchor','evaluationHeight','testTag','chainId','poolId','profileId','roleId','assetTag'];
const PRIVATE=['nf','commitmentsOut','publicKeyBytes','signatureR8Bytes','signatureSBytes',
  'nullifyingKey','inputRandom','inputSompi','leafIndex','siblingCM','outputNPK','valueOut',
  'feeSompi','nonce','validFrom','validUntil','outputTuple'];
const PUBKEYS=[...SHARED,'NF','tuple','feeTotal'];
const ALLKEYS=[...PUBKEYS,...PRIVATE.map(k=>'owner_'+k),'U','V'];
const CLASSIFICATION='PUBLIC_FICTIONAL_NON_PRIVATE_RELATION_WIRING_ONLY';
let invocationOwnsWritableRun=false;
const requireTools=createRequire(join(TOOLS,'package.json'));
const json=v=>JSON.stringify(v,(_k,x)=>typeof x==='bigint'?x.toString():x,2)+'\n';
const clone=v=>structuredClone(v);
const sha=b=>createHash('sha256').update(b).digest('hex');
const need=(ok,msg)=>{if(!ok)throw new Error(msg);};
const mod=x=>(BigInt(x)%P+P)%P;
const same=(a,b)=>json(a)===json(b);
const expectedIds=[...Array.from({length:7},(_,i)=>'P'+String(i+1).padStart(2,'0')),
  ...Array.from({length:22},(_,i)=>'N'+String(i+1).padStart(2,'0'))];

function guardRead(path,expected='') {
  need(resolve(path)===path,'guard_absolute_path');
  const code='import runpy,sys; h=runpy.run_path(sys.argv[1]); b=h["read"](sys.argv[2],sys.argv[3] or None); sys.stdout.buffer.write(b)';
  return execFileSync('python3',['-c',code,GUARD,path,expected],{maxBuffer:1024*1024**2});
}
function guardPin(path) {
  const code='import runpy,sys,hashlib,json; h=runpy.run_path(sys.argv[1]); b=h["read"](sys.argv[2]); print(json.dumps({"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}))';
  return JSON.parse(execFileSync('python3',['-c',code,GUARD,path],{maxBuffer:65536}));
}
function exactKeys(value,keys,label) {
  need(value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.keys(value).sort().join('|')===keys.slice().sort().join('|'),label);
}
function rejectSecrets(value) {
  if(!value||typeof value!=='object')return;
  for(const [key,child]of Object.entries(value)) {
    need(!/^(seed|privateSeed|privateKey|signingKey|spendSigningKey|ownerSpendSigningKey)$/i.test(key),'forbidden_secret_field');
    rejectSecrets(child);
  }
}
function recipe() {
  const row=JSON.parse(guardRead(join(HERE,'FIXTURE-RECIPE-01.json'),RECIPE_SHA));
  need(row.schema==='two-owner-aggregate-finite-fixture/v1'&&row.classification===CLASSIFICATION,'recipe_schema');
  need(row.planSHA256===PLAN_SHA&&row.handoffSHA256===HANDOFF_SHA&&row.handoffBytes===173104,'recipe_identity');
  need(row.expectedPublicFieldCount===2091&&row.expectedOutputs===0,'recipe_public_arity');
  need(same(row.publicFields,PUBKEYS)&&same(row.staticInputs.sharedFields,SHARED),'recipe_public_fields');
  need(row.staticInputs.fieldPrime===P.toString()&&row.staticInputs.expectedRows===29&&
    row.staticInputs.expectedAccepts===7&&row.staticInputs.expectedRejects===22,'recipe_counts');
  need(row.cases.length===29&&same(row.cases.map(x=>x.id),expectedIds),'recipe_case_ids');
  for(const [i,r]of row.cases.entries()) {
    exactKeys(r,['id','expectedAccepted','actualCheckerRequired','mutation'],'recipe_case_schema');
    need(r.actualCheckerRequired===true&&r.expectedAccepted===(i<7)&&typeof r.mutation==='string','recipe_case_criterion');
  }
  return row;
}
function handoff(raw) {
  const h=JSON.parse(raw);
  exactKeys(h,['schema','classification','planSHA256','fixtureRecipeSHA256',
    'ownerProcessesExitedBeforeAnyWitness','ownerExits','owners'],'handoff_schema_fields');
  need(h.schema==='signature-authority-public-handoff/v1'&&h.classification==='NON-PRIVATE'&&
    h.ownerProcessesExitedBeforeAnyWitness===true,'handoff_scope');
  need(h.owners.length===2&&h.ownerExits.length===2,'handoff_owner_count');
  for(const [i,owner]of h.owners.entries()) {
    exactKeys(owner,['kind','ownerIndex','publicKeyBytes','inputCM','baseline','alternative',
      'nullifierKeyControl','replacementForPeer','usage'],'handoff_bundle_fields');
    need(owner.kind==='signed-fixed-records'&&owner.ownerIndex===i,'handoff_owner_index');
    exactKeys(h.ownerExits[i],['ownerIndex','code','signal'],'handoff_exit_fields');
    need(h.ownerExits[i].ownerIndex===i&&h.ownerExits[i].code===0&&h.ownerExits[i].signal===null,'handoff_owner_not_exited');
    for(const key of ['baseline','alternative','nullifierKeyControl','replacementForPeer'])
      exactKeys(owner[key],[...SHARED,...PRIVATE],'handoff_record_fields');
  }
  rejectSecrets(h);return h;
}
function matrix(n,order) {
  need(order.length===n&&new Set(order).size===n&&order.every(x=>Number.isInteger(x)&&x>=0&&x<n),'construction_permutation');
  return Array.from({length:n},(_,row)=>order.map(source=>Number(source===row)));
}
function aggregate(records,nfOrder=[0,1],outOrder=[0,1,2,3]) {
  const a={};for(const key of SHARED) {
    need(records[0][key]===records[1][key],'construction_common_context:'+key);a[key]=records[0][key];
  }
  for(const key of PRIVATE)a['owner_'+key]=records.map(x=>clone(x[key]));
  const tuples=records.flatMap(x=>x.outputTuple);
  a.NF=nfOrder.map(i=>records[i].nf);a.tuple=outOrder.map(i=>clone(tuples[i]));
  a.feeTotal=records.reduce((n,r)=>n+BigInt(r.feeSompi),0n).toString();
  a.U=matrix(2,nfOrder);a.V=matrix(4,outOrder);exactKeys(a,ALLKEYS,'constructed_outer_fields');return a;
}
function publicView(input) {
  const v={};for(const k of PUBKEYS)v[k]=clone(input[k]);return v;
}
function flatPublic(input) {
  const values=[...SHARED.map(k=>input[k]),...input.NF,...input.tuple.flat(),input.feeTotal].map(BigInt);
  need(values.length===2091&&values.every(x=>x>=0n&&x<P),'canonical_public_fields');return values;
}
function le32(x) {x=BigInt(x);return Array.from({length:32},()=>{const b=Number(x&255n);x>>=8n;return b;});}
async function cases(h) {
  // The pinned library is used only for the predeclared N12 CM recomputation.
  // There is no signing API, key generation, owner child process or semantic validity filter.
  const {buildPoseidon}=requireTools('circomlibjs');const poseidon=await buildPoseidon();
  const hash=values=>BigInt(poseidon.F.toObject(poseidon(values.map(BigInt))));
  const A=clone(h.owners[0].baseline),B=clone(h.owners[1].baseline),out=[];
  const add=(id,input)=>out.push({id,input});
  const mutate=(id,fn)=>{const a=aggregate([A,B]);fn(a);add(id,a);};
  add('P01',aggregate([A,B]));add('P02',aggregate([A,B],[1,0]));
  add('P03',aggregate([A,B],[0,1],[0,2,1,3]));
  add('P04',aggregate([A,B],[1,0],[3,2,1,0]));
  add('P05',aggregate([B,A],[1,0],[2,0,3,1]));
  add('P06',aggregate([clone(h.owners[0].alternative),B]));
  add('P07',clone(out.find(x=>x.id==='P03').input));
  mutate('N01',a=>a.NF[1]=a.NF[0]);add('N02',aggregate([A,A]));
  mutate('N03',a=>a.tuple[0]=clone(a.tuple[1]));
  mutate('N04',a=>a.U[1]=[1,0]);mutate('N05',a=>a.V[1]=clone(a.V[0]));
  mutate('N06',a=>{a.U=[[2,(P-1n).toString()],[(P-1n).toString(),2]];
    a.NF=[mod(2n*BigInt(A.nf)-BigInt(B.nf)).toString(),mod(2n*BigInt(B.nf)-BigInt(A.nf)).toString()];});
  mutate('N07',a=>{a.owner_signatureR8Bytes.reverse();a.owner_signatureSBytes.reverse();});
  mutate('N08',a=>{const x=a.tuple[0].slice(0,32),y=a.tuple[1].slice(0,32);
    a.tuple[0].splice(0,32,...y);a.tuple[1].splice(0,32,...x);});
  mutate('N09',a=>a.tuple[0][96]^=1);
  mutate('N10',a=>{a.tuple[0][96]^=1;a.owner_outputTuple[0][0][96]^=1;});
  mutate('N11',a=>a.feeTotal=(BigInt(a.feeTotal)+1n).toString());
  const f=[clone(A),clone(B)];for(const [i,r]of f.entries()) {
    const shift=i===0?1n:-1n;r.feeSompi=(BigInt(r.feeSompi)+shift).toString();
    r.valueOut[1]=(BigInt(r.valueOut[1])-shift).toString();
    r.commitmentsOut=r.outputNPK.map((npk,j)=>hash([npk,r.assetTag,r.valueOut[j]]).toString());
    r.outputTuple.forEach((t,j)=>t.splice(0,32,...le32(r.commitmentsOut[j])));
  }add('N12',aggregate(f));
  for(const [i,k]of ['chainId','poolId','profileId','roleId'].entries())
    mutate('N'+String(13+i).padStart(2,'0'),a=>a[k]=(BigInt(a[k])+1n).toString());
  mutate('N17',a=>a.anchor=(BigInt(a.anchor)+1n).toString());
  mutate('N18',a=>a.evaluationHeight='99');mutate('N19',a=>a.evaluationHeight='201');
  mutate('N20',a=>{a.tuple[0][96]=256;a.owner_outputTuple[0][0][96]=256;});
  mutate('N21',a=>{a.owner_feeSompi[0]=(1n<<64n).toString();
    a.feeTotal=((1n<<64n)+BigInt(a.owner_feeSompi[1])).toString();});
  mutate('N22',a=>a.testTag=(BigInt(a.testTag)+1n).toString());
  need(same(out.map(x=>x.id),expectedIds),'constructed_finite_case_ids');
  for(const row of out){exactKeys(row.input,ALLKEYS,'case_input_schema:'+row.id);flatPublic(row.input);}
  need(same(publicView(out[2].input),publicView(out[4].input)),'P05_public_bytes_must_equal_P03');
  need(same(out[2].input,out[6].input),'P07_exact_same_state_replay_input');
  need(out.find(x=>x.id==='N12').input.feeTotal===out[0].input.feeTotal,'N12_preserve_aggregate_fee');
  return out;
}
async function absent(path) {try{await access(path);throw new Error('artifact_exists:'+path);}catch(e){if(e.code!=='ENOENT')throw e;}}
async function save(path,value) {await writeFile(path,json(value),{flag:'wx',mode:0o600});}
async function usedBytes(path) {let bytes=0;for(const e of await readdir(path,{withFileTypes:true})) {
  const p=join(path,e.name);need(!e.isSymbolicLink(),'scratch_symlink');
  const s=await lstat(p);need(s.isFile()||s.isDirectory(),'scratch_nonregular');
  bytes+=e.isDirectory()?await usedBytes(p):s.size;
}return bytes;}
async function resources(enforce=true) {
  const u=process.resourceUsage(),r={nodeCpuMicros:u.userCPUTime+u.systemCPUTime,
    nodeMaxRSSKiB:u.maxRSS,nodeRSSBytes:process.memoryUsage().rss,scratchBytes:await usedBytes(RUN),
    childAndCompilerResources:'Root outer GNUtime/envelope required; Node metrics do not sum children'};
  if(enforce){need(r.nodeCpuMicros<=1800e6,'NODE_CPU_30MIN');need(r.nodeRSSBytes<=8*1024**3,'NODE_RAM_8GIB');
    need(r.scratchBytes<=3*1024**3,'SCRATCH_3GIB');}return r;
}
async function prepare() {
  const r=recipe();await mkdir(SCRATCH,{mode:0o700,recursive:true});
  const ps=await lstat(SCRATCH);need(ps.isDirectory()&&!ps.isSymbolicLink()&&ps.uid===process.getuid()&&
    (ps.mode&0o777)===0o700,'owned0700_scratch_parent');
  await mkdir(RUN,{mode:0o700});invocationOwnsWritableRun=true;
  await mkdir(join(RUN,'cases'),{mode:0o700});
  const raw=guardRead(HANDOFF,HANDOFF_SHA),h=handoff(raw);need(raw.length===173104,'handoff_bytes');
  await writeFile(join(RUN,'HANDOFF.json'),raw,{flag:'wx',mode:0o600});
  const rows=await cases(h),selected=[];
  for(const [i,row]of rows.entries()) {
    const relative='cases/'+row.id+'.json',b=Buffer.from(json(row.input));
    await writeFile(join(RUN,relative),b,{flag:'wx',mode:0o600});
    selected.push({id:row.id,expectedAccepted:r.cases[i].expectedAccepted,actualCheckerRequired:true,
      input:{path:relative,bytes:b.length,sha256:sha(b)},publicProjectionSHA256:sha(json(publicView(row.input)))});
  }
  const map=h.owners.map((o,i)=>({ownerIndex:i,nf:o.baseline.nf,
    outputCMs:o.baseline.commitmentsOut,wholeTupleSHA256:o.baseline.outputTuple.map(t=>sha(Buffer.from(t)))}));
  await save(join(RUN,'PLAIN-CONSTRUCTOR-MAP.json'),{schema:'two-owner-plain-constructor-negative-control/v1',
    classification:CLASSIFICATION,expectedMappingDisclosure:true,publicRecipeAlsoRevealsMapping:true,
    reason:'owner-coded public fixture and full plaintext constructor; private U/V wires supply no anonymity',map});
  await save(join(RUN,'PUBLIC-PROJECTION.json'),{schema:'two-owner-aggregate-public-projection/v1',
    classification:CLASSIFICATION,publicFields:PUBKEYS,publicFieldCount:2091,publicOutputs:0,
    noMappingPrivacyClaim:true,fixtureAndMappingTruthPublic:true,
    rows:rows.filter(x=>x.id.startsWith('P')).map(x=>({id:x.id,public:publicView(x.input)}))});
  const selection={schema:'two-owner-aggregate-case-selection/v1',classification:CLASSIFICATION,
    planSHA256:PLAN_SHA,recipeSHA256:RECIPE_SHA,handoffSHA256:HANDOFF_SHA,rows:selected};
  await save(join(RUN,'CASE-SELECTION.json'),selection);await save(join(RUN,'PREPARATION-RECORD.json'),{
    schema:'two-owner-aggregate-preparation/v1',caseSelectionSHA256:sha(json(selection)),
    preparedRows:29,expectedAccepts:7,expectedRejects:22,ownerProcessStarted:false,signingKeyRead:false,
    conditionalCompileCheckNotExecuted:true,resources:await resources(false)});
  console.log(json({status:'PREPARED_PUBLIC_INPUTS_NO_COMPILE_OR_CHECK',caseSelectionSHA256:sha(json(selection)),rows:29}));
}
function r1csHeader(raw) {
  need(raw.subarray(0,4).toString()==='r1cs'&&raw.readUInt32LE(4)===1,'r1cs_magic_version');
  const n=raw.readUInt32LE(8);let pos=12,header=null;const seen=new Set();
  for(let i=0;i<n;i++) {
    need(pos+12<=raw.length,'r1cs_section_header');const type=raw.readUInt32LE(pos),length=raw.readBigUInt64LE(pos+4);pos+=12;
    need(!seen.has(type)&&length<=BigInt(raw.length-pos),'r1cs_section_bounds');seen.add(type);
    if(type===1)header=raw.subarray(pos,pos+Number(length));pos+=Number(length);
  }
  need(pos===raw.length&&header&&header.length===64&&header.readUInt32LE(0)===32,'r1cs_header_shape');
  const le=b=>{let x=0n;for(let i=b.length-1;i>=0;i--)x=(x<<8n)+BigInt(b[i]);return x;};
  need(le(header.subarray(4,36))===P,'r1cs_field');
  const h={nWires:header.readUInt32LE(36),nPublicOutputs:header.readUInt32LE(40),
    nPublicInputs:header.readUInt32LE(44),nPrivateInputs:header.readUInt32LE(48),
    nLabels:header.readBigUInt64LE(52).toString(),nConstraints:header.readUInt32LE(60)};
  need(h.nPublicOutputs===0&&h.nPublicInputs===2091&&h.nWires>2092,'outer_public_arity_or_output_leak');return h;
}
function publicNames() {return [...SHARED.map(x=>'main.'+x),...Array.from({length:2},(_,i)=>`main.NF[${i}]`),
  ...Array.from({length:4},(_,i)=>Array.from({length:520},(_,j)=>`main.tuple[${i}][${j}]`)).flat(),'main.feeTotal'];}
function symbolAudit(raw) {
  const names=publicNames(),seen=new Map(),aliases=[];need(names.length===2091,'public_name_count');
  // Decode one LF-delimited row at a time: the full .sym can exceed Node's
  // maximum string length. Remove CR only when followed by LF, as /\r?\n/.
  let start=0;
  while(start<=raw.length) {
    const lf=raw.indexOf(10,start),stop=lf<0?raw.length:lf;
    const end=lf>=0&&stop>start&&raw[stop-1]===13?stop-1:stop;
    const line=raw.subarray(start,end).toString('utf8');
    start=lf<0?raw.length+1:lf+1;
    if(!line)continue;const m=/^(\d+),(-?\d+),(\d+),(.+)$/.exec(line);need(m,'symbol_row');
    const wire=Number(m[2]),name=m[4];if(wire<1||wire>2091)continue;
    need(!/^main\.owner_/.test(name)&&!/^main\.authority\[\d+\]\.out\[/.test(name),'private_owner_or_child_output_public_alias:'+name);
    if(names.includes(name)){need(!seen.has(name),'duplicate_top_level_public_symbol');seen.set(name,wire);}
    else aliases.push({wire,name});
  }
  for(const [i,name]of names.entries())need(seen.get(name)===i+1,'public_symbol_order:'+name);
  return {publicOutputs:0,publicInputs:2091,allTopLevelNamesAndWireOrderMatched:true,
    childOut35Public:false,privateOwnerInputPublicAlias:false,additionalAliases:aliases};
}
function witnessValues(raw,nWires) {
  need(raw.subarray(0,4).toString()==='wtns'&&raw.readUInt32LE(4)===2,'witness_magic_version');
  let pos=12,head=null,body=null;const n=raw.readUInt32LE(8),seen=new Set();
  for(let i=0;i<n;i++) {need(pos+12<=raw.length,'witness_section_header');const t=raw.readUInt32LE(pos),l=raw.readBigUInt64LE(pos+4);pos+=12;
    need(!seen.has(t)&&l<=BigInt(raw.length-pos),'witness_section_bounds');seen.add(t);
    if(t===1)head=raw.subarray(pos,pos+Number(l));if(t===2)body=raw.subarray(pos,pos+Number(l));pos+=Number(l);}
  need(pos===raw.length&&head&&body&&head.length===40&&head.readUInt32LE(0)===32&&
    head.readUInt32LE(36)===nWires&&body.length===nWires*32,'witness_width_count_length');
  const le=b=>{let x=0n;for(let i=b.length-1;i>=0;i--)x=(x<<8n)+BigInt(b[i]);return x;};
  need(le(head.subarray(4,36))===P&&le(body.subarray(0,32))===1n,'witness_field_or_unit');
  return i=>{need(i>=0&&i<nWires,'witness_index');const x=le(body.subarray(i*32,(i+1)*32));need(x<P,'noncanonical_witness_field');return x;};
}
function compiledSelection(expected) {
  const raw=guardRead(join(RUN,'COMPILED-SELECTION.json'),expected),s=JSON.parse(raw);
  exactKeys(s,['schema','ordinaryR1cs','cppR1cs','cppGenerator','cppData','sym'],'compiled_selection_fields');
  need(s.schema==='two-owner-aggregate-compiled-selection/v1','compiled_selection_schema');
  const paths={ordinaryR1cs:'build-ordinary/aggregate.r1cs',cppR1cs:'build-cpp/aggregate.r1cs',
    cppGenerator:'build-cpp/aggregate_cpp/aggregate',cppData:'build-cpp/aggregate_cpp/aggregate.dat',sym:'build-ordinary/aggregate.sym'};
  for(const [key,path]of Object.entries(paths)) {
    exactKeys(s[key],['path','bytes','sha256'],'compiled_row_fields');need(s[key].path===path&&
      Number.isSafeInteger(s[key].bytes)&&s[key].bytes>0&&/^[0-9a-f]{64}$/.test(s[key].sha256),'compiled_row_identity');
    const pin=guardPin(join(RUN,path));need(pin.bytes===s[key].bytes&&pin.sha256===s[key].sha256,'compiled_asset_changed:'+key);
  }
  const a=guardRead(join(RUN,paths.ordinaryR1cs),s.ordinaryR1cs.sha256),b=guardRead(join(RUN,paths.cppR1cs),s.cppR1cs.sha256);
  need(a.equals(b),'ORDINARY_AND_CPP0_FULL_R1CS_BYTE_IDENTITY_REQUIRED');
  return {selection:s,header:r1csHeader(a),audit:symbolAudit(guardRead(join(RUN,paths.sym),s.sym.sha256))};
}
async function check(caseSelectionSHA,compiledSelectionSHA) {
  recipe();need(/^[0-9a-f]{64}$/.test(caseSelectionSHA||'')&&/^[0-9a-f]{64}$/.test(compiledSelectionSHA||''),'selected_case_and_compiled_sha_required');
  await absent(join(RUN,'RESULT.json'));await absent(join(RUN,'RUN-RECORD.json'));
  await absent(join(RUN,'STOP-RECORD.json'));invocationOwnsWritableRun=true;
  handoff(guardRead(join(RUN,'HANDOFF.json'),HANDOFF_SHA));
  const raw=guardRead(join(RUN,'CASE-SELECTION.json'),caseSelectionSHA),s=JSON.parse(raw);
  exactKeys(s,['schema','classification','planSHA256','recipeSHA256','handoffSHA256','rows'],'case_selection_fields');
  need(s.schema==='two-owner-aggregate-case-selection/v1'&&s.classification===CLASSIFICATION&&s.planSHA256===PLAN_SHA&&
    s.recipeSHA256===RECIPE_SHA&&s.handoffSHA256===HANDOFF_SHA&&same(s.rows.map(x=>x.id),expectedIds),'case_selection_identity');
  const comp=compiledSelection(compiledSelectionSHA);guardRead(CHECKER,CHECKER_SHA);
  const {default:checkSerial}=await import(pathToFileURL(CHECKER));const logger={info:()=>{},warn:()=>{}};
  await mkdir(join(RUN,'logs'),{mode:0o700});const rows=[],started=process.hrtime.bigint();let failure=null;
  try {
    await resources();for(const [i,row]of s.rows.entries()) {
      exactKeys(row,['id','expectedAccepted','actualCheckerRequired','input','publicProjectionSHA256'],'selected_case_fields');
      exactKeys(row.input,['path','bytes','sha256'],'selected_case_input_fields');
      need(row.expectedAccepted===(i<7)&&row.actualCheckerRequired===true&&row.input.path==='cases/'+row.id+'.json','selected_case_criterion');
      const inputRaw=guardRead(join(RUN,row.input.path),row.input.sha256);need(inputRaw.length===row.input.bytes,'case_input_size');
      const input=JSON.parse(inputRaw);exactKeys(input,ALLKEYS,'actual_case_schema');rejectSecrets(input);
      need(sha(json(publicView(input)))===row.publicProjectionSHA256,'case_public_projection_changed');
      const wtns=join(RUN,row.id+'.wtns'),result={id:row.id,expectedAccepted:row.expectedAccepted,actualCheckerRequired:true};
      const executable=join(RUN,comp.selection.cppGenerator.path);
      const child=spawnSync(executable,[join(RUN,row.input.path),wtns],{cwd:dirname(executable),maxBuffer:1024**2,
        env:{...process.env,TMPDIR:SCRATCH}});
      await writeFile(join(RUN,'logs',row.id+'.stdout'),child.stdout||'',{flag:'wx',mode:0o600});
      await writeFile(join(RUN,'logs',row.id+'.stderr'),child.stderr||'',{flag:'wx',mode:0o600});
      result.witnessGenerated=!child.error&&child.status===0&&child.signal===null;
      if(!result.witnessGenerated)result.generationError={status:child.status,signal:child.signal,error:String(child.error||child.stderr||'').slice(0,1000)};
      if(result.witnessGenerated) {
        try {const wb=guardRead(wtns),get=witnessValues(wb,comp.header.nWires),expected=flatPublic(input);
          result.publicWitnessMatches=expected.every((v,k)=>get(k+1)===v);need(result.publicWitnessMatches,'actual_public_witness_differs_from_selected_case');
          result.checked=true;result.accepted=await checkSerial(join(RUN,comp.selection.ordinaryR1cs.path),wtns,logger);
        }catch(e){result.checked=false;result.checkerError=String(e.message).slice(0,1000);}
      }
      result.matchesExpected=!!(result.witnessGenerated&&result.publicWitnessMatches&&result.checked&&result.accepted===result.expectedAccepted);
      result.outcome=result.checked?'R1CS_CHECK_'+(result.accepted?'ACCEPT':'REJECT'):
        result.witnessGenerated?'CHECKER_OR_PUBLIC_WITNESS_ERROR':'GENERATION_ONLY_REJECTION';
      rows.push(result);
      if(!result.matchesExpected) {
        await writeFile(join(RUN,'CASE-FAILURE-INPUT.json'),inputRaw,{flag:'wx',mode:0o600});
        result.failureInputSelection=clone(row.input);
        try {result.failureInputCopy={path:'CASE-FAILURE-INPUT.json',...guardPin(join(RUN,'CASE-FAILURE-INPUT.json'))};}
        catch(e){result.failureInputPinError=String(e.message).slice(0,500);}
        // A failed generator may leave an empty/partial regular witness. Pin it
        // if present; a pin failure is retained and can never rescue this FAIL.
        try {result.failureWitness={path:row.id+'.wtns',...guardPin(wtns)};}
        catch(e){result.failureWitnessPinError=String(e.message).slice(0,500);}
        await save(join(RUN,'CASE-FAILURE.json'),result);throw new Error('unexpected_case:'+row.id);
      }
      if(!result.expectedAccepted)await unlink(wtns);await resources();
    }
    // Detect mutation during the trusted-host run; no concurrent-filesystem attacker is claimed.
    compiledSelection(compiledSelectionSHA);guardRead(CHECKER,CHECKER_SHA);
  }catch(e){failure=String(e.message).slice(0,1000);}
  const result={schema:'two-owner-aggregate-result/v1',classification:CLASSIFICATION,
    status:failure?'FAIL_PRESERVED':'BOUNDED_AGGREGATE_R1CS_EXPECTATIONS_MATCHED',failure,
    expectedRows:29,completedRows:rows.length,rows,expectedAccepts:7,expectedRejects:22,
    actualR1csChecks:rows.filter(x=>x.checked).length,generationOnlyRejections:rows.filter(x=>!x.witnessGenerated).length,
    ordinaryCpp0FullR1csByteIdentity:true,publicSignalAudit:comp.audit,r1csHeader:comp.header,
    signingKeyRead:false,ownerProcessStarted:false,noPrivacyClaim:true,fixtureAndMappingTruthPublic:true,
    sameStateReplayExpectedAccepted:true,
    sameStateReplayAccepts:rows.some(x=>x.id==='P07'&&x.checked===true&&x.accepted===true),
    noCVAlgebraOrOutputValidity:true,noNativeStateOrRecoveryClaim:true,
    activeRetryFailureUnchanged:true,twoPercentFeeFailureUnchanged:true};
  await save(join(RUN,'RESULT.json'),result);await save(join(RUN,'RUN-RECORD.json'),{
    schema:'two-owner-aggregate-run/v1',runIdentity:'run-02',planSHA256:PLAN_SHA,recipeSHA256:RECIPE_SHA,
    handoffSHA256:HANDOFF_SHA,caseSelectionSHA256:caseSelectionSHA,compiledSelectionSHA256:compiledSelectionSHA,
    checkerSHA256:CHECKER_SHA,resultSHA256:sha(json(result)),elapsedNanoseconds:(process.hrtime.bigint()-started).toString(),
    resources:await resources(false),retention:'positive witnesses and first unexpected input/witness/logs; only expected rejected witnesses deleted',
    witnessGenerator:'OFFICIAL_CPP_SANITY0_NO_ASM_ORDINARY_FULL_R1CS_AUTHORITY',oneSerialJob:true});
  console.log(json({status:result.status,completedRows:rows.length,expectedRows:29,failure}));if(failure)process.exitCode=1;
}
async function main() {
  need(process.execPath===NODE,'explicit_selected_node_required');const [mode,path,a,b]=process.argv.slice(2);
  need(resolve(path||'')===RUN,'exact_fresh_synthetic_run02_required');
  if(mode==='check')return check(a,b);
  throw new Error('check-only run02: use explicit-node run-check-symbol-lines-02.mjs check <exact-run02> <case-selection-sha> <compiled-selection-sha>; prepare/owners/rekey are unavailable');
}
main().catch(async e=>{const message=String(e.message).slice(0,1200);try{
  const s=await lstat(RUN);if(invocationOwnsWritableRun&&s.isDirectory())await save(join(RUN,'STOP-RECORD.json'),{
    schema:'two-owner-aggregate-stop/v1',classification:CLASSIFICATION,failure:message,
    noAutomaticRetry:true,resources:await resources(false)});
}catch(_e){}console.error('TWO_OWNER_AGGREGATE_STOP:'+message);process.exitCode=1;});
