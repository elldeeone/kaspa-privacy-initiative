// Owner-only adapter to the retained mature Circomlib implementation.
// Seeds arrive on private stdin; responses never contain a seed/scalar/nonce.
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';

const P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const Q=2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const INV8=(7n*Q+1n)/8n;
function need(value,code){if(!value)throw new Error(code);}
function fields(value,names){need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('|')===[...names].sort().join('|'),'FIELDS');}
function raw(text,width){need(typeof text==='string'&&/^[0-9a-f]*$/.test(text)&&text.length%2===0&&(width===undefined||text.length===2*width),'HEX');return Buffer.from(text,'hex');}
function decimal(text,max){need(typeof text==='string'&&/^(0|[1-9][0-9]*)$/.test(text),'DECIMAL');const value=BigInt(text);need(value<max,'RANGE');return value;}
function le(bytes){return BigInt('0x'+Buffer.from(bytes).reverse().toString('hex'));}
function enc(value){return Buffer.from(value.toString(16).padStart(64,'0'),'hex').reverse();}

const {buildEddsa,buildPoseidon}=await import(pathToFileURL(process.argv[2]).href);
const [eddsa,poseidon]=await Promise.all([buildEddsa(),buildPoseidon()]);
const F=eddsa.babyJub.F;
function point(values){return values.map(value=>F.e(value));}
function checkPoint(value){
 need(eddsa.babyJub.inCurve(value)&&eddsa.babyJub.inSubgroup(value),'POINT');
 const result=value.map(x=>F.toObject(x));need(result.every(x=>x>=0n&&x<P)&&result[0]!==0n,'POINT_CANONICAL_NONIDENTITY');return result;
}
function statement(rawHex){const bytes=raw(rawHex);need(bytes.length===152||bytes.length===1460,'STATEMENT_WIDTH');const digest=createHash('sha256').update(bytes).digest();const limbs=[le(digest.subarray(0,16)),le(digest.subarray(16))];return{digest,limbs,message:eddsa.F.e(poseidon.F.toObject(poseidon(limbs)))};}
function authorization(value){
 fields(value,['owner_key_hex64','R8','S']);const key=raw(value.owner_key_hex64,64);
 const xy=[le(key.subarray(0,32)),le(key.subarray(32))];need(xy.every(x=>x<P),'KEY_CANONICAL');checkPoint(point(xy));
 need(Array.isArray(value.R8)&&value.R8.length===2,'R8');const R8=value.R8.map(x=>decimal(x,P));checkPoint(point(R8));
 return{key,xy,R8,S:decimal(value.S,Q)};
}
function execute(request){
 if(request.operation==='derive-public'){
  fields(request,['operation','seed_hex32']);const key=checkPoint(eddsa.prv2pub(raw(request.seed_hex32,32)));
  return{owner_key_hex64:Buffer.concat(key.map(enc)).toString('hex')};
 }
 if(request.operation==='sign'){
  fields(request,['operation','seed_hex32','statement_hex']);const seed=raw(request.seed_hex32,32),s=statement(request.statement_hex);
  const A=checkPoint(eddsa.prv2pub(seed)),signature=eddsa.signPoseidon(seed,s.message),R8=checkPoint(signature.R8);
  // This refusal precedes exporting a possibly degenerate deterministic signature.
  need(typeof signature.S==='bigint'&&signature.S>=0n&&signature.S<Q,'SIGNATURE_SCALAR');
  return{owner_key_hex64:Buffer.concat(A.map(enc)).toString('hex'),R8:R8.map(String),S:signature.S.toString(),statement_sha256:s.digest.toString('hex')};
 }
 if(request.operation==='verify'||request.operation==='signature-inputs'){
  fields(request,['operation','statement_hex','authorization']);const a=authorization(request.authorization),s=statement(request.statement_hex);
  const valid=eddsa.verifyPoseidon(s.message,{R8:point(a.R8),S:a.S},point(a.xy));
  if(request.operation==='verify')return{valid};
  need(valid,'SIGNATURE_INVALID');const preimageA=checkPoint(eddsa.babyJub.mulPointEscalar(point(a.xy),INV8));
  const preimageR8=checkPoint(eddsa.babyJub.mulPointEscalar(point(a.R8),INV8));
  return{digestLimbs:s.limbs.map(String),ownerKeyBytes:[...a.key].map(String),sigR8:a.R8.map(String),sigS:a.S.toString(),preimageA:preimageA.map(String),preimageR8:preimageR8.map(String)};
 }
 throw new Error('OPERATION');
}
const input=createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of input){
 try{need(line.length<=16384,'REQUEST_SIZE');process.stdout.write(JSON.stringify({result:execute(JSON.parse(line))})+'\n');}
 catch{process.stdout.write(JSON.stringify({error:'OWNER_AUTHORITY_REFUSED'})+'\n');}
}
process.exit(0);
