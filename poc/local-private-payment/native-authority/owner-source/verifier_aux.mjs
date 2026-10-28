// VERIFIER-ONLY SOURCE. No signing function, seed/key/nonce parameter or file I/O.
import {buildEddsa} from 'circomlibjs';
import {FIELD_P,SUBGROUP_Q,reconstructStatement,need,le,canonicalField} from './public_packet.mjs';
const INV8=(7n*SUBGROUP_Q+1n)/8n;
let context;async function ctx(){if(!context)context=buildEddsa();return {eddsa:await context};}
function canonicalPoint(eddsa,p){const F=eddsa.babyJub.F;const x=F.toObject(p[0]),y=F.toObject(p[1]);need(x>=0n&&x<FIELD_P&&y>=0n&&y<FIELD_P,'POINT_FIELD');return[x,y]}
export async function verifierInputs(admittedPacket,authorization,explicitPreimages){
 const keys=['schema','ownerKeyHex','R8','S','statementSha256','packetSha256'];need(authorization&&Object.keys(authorization).sort().join('|')===keys.sort().join('|'),'AUTHORIZATION_KEYS');
 need(authorization.schema==='kpi-nativeauth-owner-authorization/v1'&&/^[0-9a-f]{128}$/.test(authorization.ownerKeyHex),'AUTHORIZATION_SCHEMA');
 const t=reconstructStatement(admittedPacket),key=Buffer.from(authorization.ownerKeyHex,'hex');const ax=le(key.subarray(0,32)),ay=le(key.subarray(32));need(ax<FIELD_P&&ay<FIELD_P,'NONCANONICAL_KEY');
 need(Array.isArray(authorization.R8)&&authorization.R8.length===2,'R8_LENGTH');const rx=canonicalField(authorization.R8[0]),ry=canonicalField(authorization.R8[1]),S=canonicalField(authorization.S);
 const{eddsa}=await ctx(),F=eddsa.babyJub.F;let pa,pr;
 if(explicitPreimages){need(Object.keys(explicitPreimages).sort().join('|')==='A|R8','PREIMAGE_KEYS');need(explicitPreimages.A.length===2&&explicitPreimages.R8.length===2,'PREIMAGE_LENGTH');pa=explicitPreimages.A.map(canonicalField);pr=explicitPreimages.R8.map(canonicalField)}
 else{pa=canonicalPoint(eddsa,eddsa.babyJub.mulPointEscalar([F.e(ax),F.e(ay)],INV8));pr=canonicalPoint(eddsa,eddsa.babyJub.mulPointEscalar([F.e(rx),F.e(ry)],INV8))}
 // Old signature metadata intentionally does NOT override the newly rebuilt M.
 // Stale-signature controls keep old R8/S but feed the new actual packet limbs.
 return{digestLimbs:t.limbs.map(String),ownerKeyBytes:[...key].map(String),sigR8:[rx.toString(),ry.toString()],sigS:S.toString(),preimageA:pa.map(String),preimageR8:pr.map(String)};
}
