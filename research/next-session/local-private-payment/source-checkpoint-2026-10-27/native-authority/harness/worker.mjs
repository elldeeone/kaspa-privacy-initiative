// SOURCE-ONLY stdin/stdout public synthetic worker; no file/path/network API.
// Future bwrap mounts selected readonly node_modules at /src/node_modules.
import {createHash} from 'node:crypto';
const PUBLIC_SEEDS=[0,32,64].map(start=>Uint8Array.from({length:32},(_,i)=>start+i));
function need(x,c){if(!x)throw new Error(c)}
function raw(hex){need(typeof hex==='string'&&hex.length%2===0&&/^[0-9a-f]*$/.test(hex),'HEX');return Buffer.from(hex,'hex')}
function hash(b){return createHash('sha256').update(b).digest('hex')}
function artifact(a){return{hex:a.bytes.toString('hex'),sha256:a.sha256,byteLength:a.byteLength}}
async function matrixInput(v){
 const a=raw(v.ordinaryR1csHex),b=raw(v.cpp0R1csHex),s=raw(v.symHex);
 return{ordinaryR1cs:a,cpp0R1cs:b,symBytes:s,pins:{ordinaryR1cs:{sha256:hash(a),byteLength:a.length},cpp0R1cs:{sha256:hash(b),byteLength:b.length},symBytes:{sha256:hash(s),byteLength:s.length}}};
}
async function run(v){
 if(v.mode==='keys'){
  const {derivePublicOnly}=await import('../owner-source/owner_signer.mjs');
  const keys=[];for(const seed of PUBLIC_SEEDS)keys.push((await derivePublicOnly(seed)).toString('hex'));
  return{schema:'kpi-nativeauth-public-test-keys/v1',ownerKeys:keys,allKeysPublicKnownUnfunded:true};
 }
 if(v.mode==='sign'){
  need(Number.isInteger(v.role)&&v.role>=0&&v.role<3,'PUBLIC_ROLE');
  const{signApprovedPacket}=await import('../owner-source/owner_signer.mjs');
  return signApprovedPacket(PUBLIC_SEEDS[v.role],raw(v.packetHex));
 }
 if(v.mode==='prepare'){
  const{verifierInputs}=await import('../owner-source/verifier_aux.mjs');
  return verifierInputs(raw(v.packetHex),v.authorization,v.explicitPreimages);
 }
 if(v.mode==='matrix'||v.mode==='witness'){
  // Qualified source modules; no implicit curve construction in the bridge.
  const [{readR1cs},{default:F1Field},{default:exportWitnessJson},bridge]=await Promise.all([
   import('r1csfile'),import('../node_modules/r1csfile/node_modules/ffjavascript/src/f1field.js'),
   import('../node_modules/snarkjs/src/wtns_export_json.js'),import('../source-bridge/signature-component-adapter-selected.mjs')]);
  const prepared=await bridge.prepareSignatureMatrix(await matrixInput(v),{readR1cs,F1Field});
  const result={matrix:artifact(prepared.matrix),mapping:artifact(prepared.mapping),metadata:artifact(prepared.metadata)};
  if(v.mode==='witness'){
   const b=raw(v.wtnsHex);const r=await bridge.prepareSignatureWitness({wtns:b,pin:{sha256:hash(b),byteLength:b.length},frozen:v.frozen},prepared,{exportWitnessJson});
   result.witness=artifact(r.witness);result.witnessMetadata=artifact(r.metadata);
  }return result;
 }
 throw new Error('MODE');
}
let input='';for await(const b of process.stdin)input+=b.toString('utf8');
try{const v=JSON.parse(input);const r=await run(v);process.stdout.write(JSON.stringify(r)+'\n')}
catch(e){process.stderr.write(JSON.stringify({status:'FIRST_FAILURE_RETAIN',name:e.name,code:e.code||null,message:e.message})+'\n');process.exitCode=2}
