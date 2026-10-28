// OWNER-ONLY SOURCE. Never loaded in a verifier process; no CLI or logs.
import {buildEddsa,buildPoseidon} from 'circomlibjs';
import {FIELD_P,SUBGROUP_Q,reconstructStatement,need,enc} from './public_packet.mjs';
let context;
async function ctx(){if(!context)context=Promise.all([buildEddsa(),buildPoseidon()]);const [eddsa,poseidon]=await context;return{eddsa,poseidon}}
function canonicalPoint(eddsa,p){const F=eddsa.babyJub.F;const x=F.toObject(p[0]),y=F.toObject(p[1]);need(x>=0n&&x<FIELD_P&&y>=0n&&y<FIELD_P,'POINT_FIELD');return[x,y]}
function checkBeforeExport(eddsa,p){need(eddsa.babyJub.inCurve(p)&&eddsa.babyJub.inSubgroup(p),'SIGNER_POINT');const c=canonicalPoint(eddsa,p);need(c[0]!==0n,'SIGNER_DEGENERATE_STOP_BEFORE_EXPORT');return c}
export async function derivePublicOnly(ownerLocalSeed){
 need(ownerLocalSeed instanceof Uint8Array&&ownerLocalSeed.length===32,'OWNER_SEED_LENGTH');const{eddsa}=await ctx();const A=eddsa.prv2pub(Buffer.from(ownerLocalSeed));const[x,y]=checkBeforeExport(eddsa,A);return Buffer.concat([enc(x,32),enc(y,32)]);
}
/// Deliberate owner consent only. This function is never mounted in verifier jobs.
/// No seed/expanded scalar/prefix/nonce is returned or logged. Zero-R8 guard is
/// BEFORE any export; rejection after sharing would be too late.
export async function signApprovedPacket(ownerLocalSeed,admittedApprovedPacket){
 need(ownerLocalSeed instanceof Uint8Array&&ownerLocalSeed.length===32,'OWNER_SEED_LENGTH');const t=reconstructStatement(admittedApprovedPacket);const{eddsa,poseidon}=await ctx();
 const seed=Buffer.from(ownerLocalSeed),A=eddsa.prv2pub(seed);const[x,y]=checkBeforeExport(eddsa,A);
 const mValue=poseidon.F.toObject(poseidon(t.limbs));need(mValue>=0n&&mValue<FIELD_P,'MESSAGE_FIELD');const msg=eddsa.F.e(mValue);
 const sig=eddsa.signPoseidon(seed,msg);const[rx,ry]=checkBeforeExport(eddsa,sig.R8);need(typeof sig.S==='bigint'&&sig.S>=0n&&sig.S<SUBGROUP_Q,'SIGNER_SCALAR');
 return{schema:'kpi-nativeauth-owner-authorization/v1',ownerKeyHex:Buffer.concat([enc(x,32),enc(y,32)]).toString('hex'),R8:[rx.toString(),ry.toString()],S:sig.S.toString(),statementSha256:t.digest.toString('hex'),packetSha256:t.packetSha256};
}
