// Pure small parser controls only. No full-driver import, toolchain, circuits,
// witness generator, R1CS checker, cryptographic library or large .sym read.
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {writeFile} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';

const HERE=dirname(fileURLToPath(import.meta.url));
const NODE='/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node';
const GUARD='/var/tmp/kpi-root-guard-helper-09.py';
const OLD='run-check-large-symbols-01.mjs';
const OLD_SHA='6a3c84ef737cab6b46e1efd5723e6e93df5bd1807e36e2e04d1061736e910e83';
const NEXT='run-check-symbol-lines-02.mjs';
const NEXT_SHA='38d9221e841567cdf61e0c0781a21ba05ec0814001f7dc13392f0fc3777f8f6e';
const SHARED=['anchor','evaluationHeight','testTag','chainId','poolId','profileId','roleId','assetTag'];
const need=(ok,label)=>{if(!ok)throw new Error(label);};
const sha=b=>createHash('sha256').update(b).digest('hex');
const json=v=>JSON.stringify(v,null,2)+'\n';
const read=(name,want)=>execFileSync('python3',['-c',
  'import runpy,sys; h=runpy.run_path(sys.argv[1]); sys.stdout.buffer.write(h["read"](sys.argv[2],sys.argv[3]))',
  GUARD,join(HERE,name),want],{maxBuffer:1024**2});

function isolate(raw) {
  const s=raw.toString('utf8'),start=s.indexOf('function publicNames() {'),end=s.indexOf('function witnessValues(',start);
  need(start>=0&&end>start,'selected_pure_function_boundaries');
  const isolated=s.slice(start,end);
  need((isolated.match(/function\s+\w+\(/g)||[]).length===2,'exactly_publicNames_and_symbolAudit');
  need(!/\b(?:import|requireTools|spawnSync|execFileSync)\b/.test(isolated),'no_runtime_dependency_in_extracted_functions');
  // Only these already reviewed, SHA-selected pure function definitions are
  // evaluated. The driver CLI, imports and every other function stay inert.
  const audit=new Function('SHARED','need',isolated+'\nreturn symbolAudit;')(SHARED,need);
  return {audit,functionSHA256:sha(isolated),functionBytes:Buffer.byteLength(isolated)};
}
function observe(audit,bytes) {
  try{return {accepted:true,result:audit(bytes)};}
  catch(e){return {accepted:false,error:String(e.message)};}
}

need(process.execPath===NODE,'explicit_selected_node_required');
const oldRaw=read(OLD,OLD_SHA),newRaw=read(NEXT,NEXT_SHA),old=isolate(oldRaw),next=isolate(newRaw);
const names=[...SHARED.map(x=>'main.'+x),...Array.from({length:2},(_,i)=>`main.NF[${i}]`),
  ...Array.from({length:4},(_,i)=>Array.from({length:520},(_,j)=>`main.tuple[${i}][${j}]`)).flat(),'main.feeTotal'];
need(names.length===2091,'independent_public_name_recipe');
const rows=names.map((name,i)=>`${i+1},${i+1},0,${name}`);
const lf=rows.join('\n'),tests=[];
const add=(id,text,expectedAccepted)=>tests.push({id,bytes:Buffer.isBuffer(text)?text:Buffer.from(text),expectedAccepted});
add('LF-with-final-LF',lf+'\n',true);
add('LF-without-final-LF',lf,true);
add('CRLF-with-final-CRLF',rows.join('\r\n')+'\r\n',true);
add('CRLF-without-final-CRLF',rows.join('\r\n'),true);
add('blank-LF-lines','\n'+rows.map(x=>'\n'+x).join('\n')+'\n\n',true);
add('blank-CRLF-lines','\r\n'+rows.map(x=>'\r\n'+x).join('\r\n')+'\r\n\r\n',true);
add('last-lone-CR-is-not-CRLF',lf+'\r',false);
add('negative-optimized-wire-row','0,-1,0,main.optimized\n'+lf,true);
add('zero-and-private-wire-rows','0,0,0,main.constant\n'+lf+'\n9999,9000,1,main.owner_nf[0]',true);
add('shared-context-public-alias',lf+'\n9999,1,7,main.authority[0].anchor',true);
add('missing-first-public-name',rows.slice(1).join('\n'),false);
add('missing-last-public-name',rows.slice(0,-1).join('\n'),false);
const wrongOrder=rows.slice();wrongOrder[0]='1,2,0,main.anchor';wrongOrder[1]='2,1,0,main.evaluationHeight';
add('wrong-public-wire-order',wrongOrder.join('\n'),false);
add('duplicate-top-level-public-name',lf+'\n9999,1,0,main.anchor',false);
add('late-private-owner-public-alias',lf+'\n9999,1,7,main.owner_nf[0]',false);
add('late-child-out-public-alias',lf+'\n9999,1,7,main.authority[0].out[0]',false);
add('malformed-first-row','not-a-symbol\n'+lf,false);
add('malformed-final-unterminated-row',lf+'\nnot-a-symbol',false);
add('embedded-CR-in-final-name',lf+'\n9999,3000,1,main.bad\rname',false);
const componentNegative=rows.slice();componentNegative[0]='1,1,-1,main.anchor';
add('negative-component-id',componentNegative.join('\n'),false);
const badWire=rows.slice();badWire[0]='1,wire,0,main.anchor';
add('noninteger-wire-id',badWire.join('\n'),false);
add('empty-buffer',Buffer.alloc(0),false);

const started=process.hrtime.bigint(),out=[];
for(const test of tests) {
  const a=observe(old.audit,test.bytes),b=observe(next.audit,test.bytes);
  const same=JSON.stringify(a)===JSON.stringify(b);
  out.push({id:test.id,inputBytes:test.bytes.length,inputSHA256:sha(test.bytes),expectedAccepted:test.expectedAccepted,
    oldAccepted:a.accepted,newAccepted:b.accepted,identicalOutcomeAndAudit:same,
    oldError:a.error??null,newError:b.error??null,
    matchesExpected:same&&a.accepted===test.expectedAccepted&&b.accepted===test.expectedAccepted});
}
// A tiny proxy rejects conversion of the complete object to a string. Old
// code must hit it; new code must stringify only returned one-line subarrays.
// This is path evidence, not a simulation of the real645MB file's resources.
const base=Buffer.from(lf+'\n');
const protectedBuffer=new Proxy(base,{get(target,key) {
  if(key==='toString')return ()=>{throw new Error('blocked_whole_buffer_toString');};
  const value=Reflect.get(target,key,target);
  return typeof value==='function'?value.bind(target):value;
}});
const oldProbe=observe(old.audit,protectedBuffer),newProbe=observe(next.audit,protectedBuffer);
const baseline=observe(old.audit,base);
const wholeBufferProbe={id:'whole-object-toString-red-old-green-new',inputBytes:base.length,
  oldAccepted:oldProbe.accepted,newAccepted:newProbe.accepted,oldError:oldProbe.error??null,newError:newProbe.error??null,
  newAuditEqualsOldOrdinaryBaseline:JSON.stringify(newProbe)===JSON.stringify(baseline)};
wholeBufferProbe.matchesExpected=!oldProbe.accepted&&oldProbe.error==='blocked_whole_buffer_toString'&&
  newProbe.accepted&&wholeBufferProbe.newAuditEqualsOldOrdinaryBaseline;
const elapsed=process.hrtime.bigint()-started;
const record={schema:'two-owner-symbol-line-parser-pure-controls/v1',
  classification:'SMALL_PURE_PARSER_CONTROLS_NO_DRIVER_OR_CRYPTO_EXECUTION',
  status:out.every(x=>x.matchesExpected)&&wholeBufferProbe.matchesExpected?'PASS':'FAIL_PRESERVED',
  oldSource:{file:OLD,bytes:oldRaw.length,sha256:OLD_SHA,extractedFunctionBytes:old.functionBytes,extractedFunctionSHA256:old.functionSHA256},
  newSource:{file:NEXT,bytes:newRaw.length,sha256:NEXT_SHA,extractedFunctionBytes:next.functionBytes,extractedFunctionSHA256:next.functionSHA256},
  controlCount:out.length+1,semanticControlCount:out.length,
  expectedSemanticAccepts:tests.filter(x=>x.expectedAccepted).length,expectedSemanticRejects:tests.filter(x=>!x.expectedAccepted).length,
  matchedCount:out.filter(x=>x.matchesExpected).length+Number(wholeBufferProbe.matchesExpected),
  largestInputBytes:Math.max(...tests.map(x=>x.bytes.length)),
  elapsedNanoseconds:elapsed.toString(),controls:out,wholeBufferProbe,
  noLargeSymbolFixtureRead:true,noFullDriverImport:true,noCircuitCompilerBuildWitnessOrR1csCheck:true,
  limits:['These small tests compare selected parser semantics; they do not exercise a645MB file.','Actual aggregate run remains unexecuted under the new run02 identity pending RootGO.']};
await writeFile(join(HERE,'SYMBOL-LINE-PARSER-CONTROLS-02.json'),json(record),{flag:'wx',mode:0o600});
console.log(json({status:record.status,controls:record.controlCount,matched:record.matchedCount,
  elapsedNanoseconds:record.elapsedNanoseconds,largestInputBytes:record.largestInputBytes,
  reportSHA256:sha(json(record))}));
if(record.status!=='PASS')process.exitCode=1;
