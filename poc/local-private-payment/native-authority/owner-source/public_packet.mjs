// SOURCE ONLY. Public structural reconstruction, not state/proof acceptance.
import {createHash} from 'node:crypto';
export const FIELD_P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const SUBGROUP_Q=2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const MAX=2870000000000000000n,FLOOR=60000000n;
const D=Buffer.alloc(32,0xa6), ZERO32=Buffer.alloc(32);
export function need(x,c){if(!x)throw new Error(c)}
const sha=(...p)=>createHash('sha256').update(Buffer.concat(p.map(x=>Buffer.from(x)))).digest();
export function le(b){let x=0n;for(let i=b.length-1;i>=0;i--)x=(x<<8n)|BigInt(b[i]);return x}
export function enc(x,n){need(typeof x==='bigint'&&x>=0n&&x<(1n<<BigInt(n*8)),'ENCODING');const b=Buffer.alloc(n);for(let i=0;i<n;i++){b[i]=Number(x&255n);x>>=8n}return b}
export function canonicalField(x){need(typeof x==='string'&&/^(0|[1-9][0-9]*)$/.test(x),'DECIMAL');const v=BigInt(x);need(v<FIELD_P,'NONCANONICAL_FIELD');return v}
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
