// OWNER-LOCAL SOURCE ONLY. No import, key derivation, signing or hash run yet.
// Not a wallet/approval RPC. Caller must deliberately approve the complete packet
// and run the retained public path/current-head checks before calling this API.
import {createHash} from 'node:crypto';
import {buildEddsa,buildPoseidon} from 'circomlibjs';
export const FIELD_P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const SUBGROUP_Q=2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const MAX=2870000000000000000n,FLOOR=60000000n;
const D=Buffer.alloc(32,0xa6), ZERO32=Buffer.alloc(32), INV8=(7n*SUBGROUP_Q+1n)/8n;
function need(x,c){if(!x)throw new Error(c)}
const sha=(...p)=>createHash('sha256').update(Buffer.concat(p.map(x=>Buffer.from(x)))).digest();
function le(b){let x=0n;for(let i=b.length-1;i>=0;i--)x=(x<<8n)|BigInt(b[i]);return x}
function enc(x,n){need(typeof x==='bigint'&&x>=0n&&x<(1n<<BigInt(n*8)),'ENCODING');const b=Buffer.alloc(n);for(let i=0;i<n;i++){b[i]=Number(x&255n);x>>=8n}return b}
function field(x){need(typeof x==='string'&&/^(0|[1-9][0-9]*)$/.test(x),'DECIMAL');const v=BigInt(x);need(v<FIELD_P,'NONCANONICAL_FIELD');return v}
function eq(a,b){return Buffer.from(a).equals(Buffer.from(b))}
function tag(b,t){need(eq(b,Buffer.from(t,'ascii')),'TAG')}
function spk(b){need(b.length===37&&eq(b.subarray(0,4),Buffer.from([0,0,0xaa,0x20]))&&b[36]===0x87,'SPK_FORMAT')}
/// Independently reconstruct public statement; this does NOT authenticate state,
/// evaluate successor paths, verify opaque proofs or replace a Native acceptor.
export function reconstructStatement(admittedPacket){
 need(admittedPacket instanceof Uint8Array,'PACKET_BYTES');const packet=Buffer.from(admittedPacket);need(packet.length===4077,'PACKET_LENGTH');
 const p=packet.subarray(0,193),b=packet.subarray(193);tag(p.subarray(0,8),'KPBPFX01');tag(b.subarray(0,8),'KPBPBD01');
 need(eq(p.subarray(8,12),Buffer.from([1,0,1,0]))&&eq(b.subarray(8,16),Buffer.from([1,0,1,0,2,0,0,0])),'SHAPE');need(eq(b.subarray(16,48),D),'DOMAIN');
 need(eq(p.subarray(12,48),b.subarray(112,148))&&!eq(b.subarray(112,144),ZERO32),'POINT_ALIAS');need(eq(p.subarray(48,56),Buffer.alloc(8,255)),'SEQUENCE');
 need(eq(p.subarray(64,66),Buffer.from([37,0]))&&eq(p.subarray(103,105),Buffer.from([1,0]))&&eq(p.subarray(113,115),Buffer.from([37,0])),'COUNTS');
 need(eq(p.subarray(152,189),Buffer.alloc(37))&&le(p.subarray(189,193))===3884n,'PREFIX_TAIL');spk(p.subarray(66,103));spk(p.subarray(115,152));
 need(!eq(b.subarray(48,80),ZERO32)&&eq(b.subarray(80,112),ZERO32),'ACTION_RESERVED');
 for(const at of [148,268]){tag(b.subarray(at,at+8),'KPBPST01');need(eq(b.subarray(at+8,at+40),D),'STATE_DOMAIN')}
 const oldCm=le(b.subarray(220,224)),newCm=le(b.subarray(340,344)),oldNf=le(b.subarray(256,260)),newNf=le(b.subarray(376,380));
 need(oldCm>=1n&&oldCm<=65534n&&newCm===oldCm+2n&&oldNf>=1n&&oldNf<131072n&&newNf===oldNf+1n,'STATE_COUNTS');
 const old=le(b.subarray(260,268)),now=le(b.subarray(380,388)),fee=le(b.subarray(388,396));need(old>=FLOOR&&old<=MAX&&now>=FLOOR&&now<=MAX&&fee>=1n&&fee<=MAX&&now+fee===old&&le(b.subarray(396,404))===0n,'RESERVE');
 need(le(p.subarray(56,64))===old&&le(p.subarray(105,113))===now,'AMOUNT_ALIAS');need(le(b.subarray(404,436))<SUBGROUP_Q&&!eq(b.subarray(436,468),ZERO32),'DELTA_NF');
 const empty=sha(Buffer.from('KPX1CME\0','ascii'));const rows=[b.subarray(532,1052),b.subarray(1052,1572)];
 for(const r of rows){need(!eq(r.subarray(0,32),ZERO32)&&!eq(r.subarray(0,32),empty),'EMPTY_CM');need(eq(sha(r.subarray(96,360)),r.subarray(360,392)),'CF_HASH')}
 need(!eq(rows[0].subarray(0,32),rows[1].subarray(0,32))&&!eq(rows[0],rows[1]),'DUPLICATE_OUTPUT');
 const effects=sha(Buffer.from('KPBPEF01','ascii'),p,b.subarray(0,3756));
 const statement=Buffer.concat([Buffer.from('KPBPSP01','ascii'),D,b.subarray(188,220),b.subarray(436,468),b.subarray(468,532),effects]);need(statement.length===200,'STATEMENT_LENGTH');
 const digest=sha(statement),limbs=[le(digest.subarray(0,16)),le(digest.subarray(16))];
 return {statement,digest,limbs,effects,packetSha256:sha(packet).toString('hex')};
}
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
/// Public/verifier-only auxiliary preparation. No seed/scalar/nonce accepted.
/// Explicit point preimages permit direct invalid-admission candidates; they
/// are not host-validity flags. Actual circuit rows enforce every predicate.
export async function verifierInputs(admittedPacket,authorization,explicitPreimages){
 const keys=['schema','ownerKeyHex','R8','S','statementSha256','packetSha256'];need(authorization&&Object.keys(authorization).sort().join('|')===keys.sort().join('|'),'AUTHORIZATION_KEYS');
 need(authorization.schema==='kpi-nativeauth-owner-authorization/v1'&&/^[0-9a-f]{128}$/.test(authorization.ownerKeyHex),'AUTHORIZATION_SCHEMA');
 const t=reconstructStatement(admittedPacket),key=Buffer.from(authorization.ownerKeyHex,'hex');const ax=le(key.subarray(0,32)),ay=le(key.subarray(32));need(ax<FIELD_P&&ay<FIELD_P,'NONCANONICAL_KEY');
 need(Array.isArray(authorization.R8)&&authorization.R8.length===2,'R8_LENGTH');const rx=field(authorization.R8[0]),ry=field(authorization.R8[1]),S=field(authorization.S);
 const{eddsa}=await ctx(),F=eddsa.babyJub.F;let pa,pr;
 if(explicitPreimages){need(Object.keys(explicitPreimages).sort().join('|')==='A|R8','PREIMAGE_KEYS');need(explicitPreimages.A.length===2&&explicitPreimages.R8.length===2,'PREIMAGE_LENGTH');pa=explicitPreimages.A.map(field);pr=explicitPreimages.R8.map(field)}
 else{pa=canonicalPoint(eddsa,eddsa.babyJub.mulPointEscalar([F.e(ax),F.e(ay)],INV8));pr=canonicalPoint(eddsa,eddsa.babyJub.mulPointEscalar([F.e(rx),F.e(ry)],INV8))}
 // Old signature metadata intentionally does NOT override the newly rebuilt M.
 // Stale-signature controls keep old R8/S but feed the new actual packet limbs.
 return{digestLimbs:t.limbs.map(String),ownerKeyBytes:[...key].map(String),sigR8:[rx.toString(),ry.toString()],sigS:S.toString(),preimageA:pa.map(String),preimageR8:pr.map(String)};
}
