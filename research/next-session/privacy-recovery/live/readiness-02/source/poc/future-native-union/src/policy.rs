//! New experimental actual private-Groth16 / revealing P2SH union.
//! Exact NOTE-STATE-CONTRACT core1–5 plus native public ADMIT. No wallet or old PK imports.
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
use sha2::{Digest, Sha256};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const DOMAIN: [u8; 32] = [
    0x7b, 0x2e, 0x38, 0x5d, 0x17, 0x2c, 0x8d, 0x1a, 0x7b, 0x50, 0x91, 0x74, 0xed, 0xe8, 0x83, 0xfa,
    0xa2, 0x28, 0xd5, 0x53, 0xde, 0xc9, 0x4f, 0x1a, 0xe6, 0xa5, 0x56, 0x04, 0x35, 0xbd, 0xe9, 0x56,
];
pub const STATE_MAGIC: &[u8; 8] = b"KPX2ST01";
pub const AUTH_MAGIC: &[u8; 8] = b"KPX2AU01";
pub const REVEAL_MAGIC: &[u8; 8] = b"KPX2RV01";
pub const MAX: i64 = 2_870_000_000_000_000_000;
pub const NOTE_FLOOR: i64 = 60_000_000;
pub const PAYOUT_FLOOR: i64 = 10_000_000;
pub const REDEEM_START: usize = 199;
pub const PRIVATE_PAYLOAD: usize = 4356;
pub const REVEAL_PAYLOAD: usize = 2029;
pub const PRIVATE_BUDGET: u16 = 1600;
pub const REVEAL_BUDGET: u16 = 200;
const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
const LEAF_TAG: &[u8; 8] = b"KPX1NFL\0";
const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
const NF_NODE: &[u8; 8] = b"KPX1NFN\0";
const O: usize = 9;
const INC: usize = 41;
const VALUE: usize = 73;
const RHO: usize = 81;
const KEY: usize = 113;
const PK: usize = 145;
const POS: usize = 177;
const KC: usize = 181;
const CM: usize = 213;
const CMPATH: usize = 245;
const NF: usize = 1917;
const NEWROOT: usize = 1981;
const FEE: usize = 2013;
const PAY: usize = 2021;
fn op(b: &mut ScriptBuilder, c: u8) {
    b.add_op(c).unwrap();
}
fn num(b: &mut ScriptBuilder, n: i64) {
    b.add_i64(n).unwrap();
}
fn data(b: &mut ScriptBuilder, d: &[u8]) {
    b.add_data(d).unwrap();
}
fn cat(b: &mut ScriptBuilder) {
    op(b, OpCat)
}
fn verify(b: &mut ScriptBuilder) {
    op(b, OpVerify)
}
fn pl(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxPayloadSubstr)
}
fn ss(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, 0);
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxInputScriptSigSubstr)
}
fn st(b: &mut ScriptBuilder, o: usize, l: usize) {
    ss(b, REDEEM_START + 2 + o, l)
}
fn unum(b: &mut ScriptBuilder, o: usize, l: usize) {
    pl(b, o, l);
    if l < 8 {
        data(b, &[0]);
        cat(b)
    }
    op(b, OpBin2Num)
}
fn snum(b: &mut ScriptBuilder, o: usize) {
    st(b, o, 4);
    data(b, &[0]);
    cat(b);
    op(b, OpBin2Num)
}
fn eqn(b: &mut ScriptBuilder, c: u8, n: i64) {
    op(b, c);
    num(b, n);
    op(b, OpNumEqualVerify)
}
fn eqdata(b: &mut ScriptBuilder, o: usize, d: &[u8]) {
    pl(b, o, d.len());
    data(b, d);
    op(b, OpEqualVerify)
}
fn range(b: &mut ScriptBuilder, o: usize, l: usize, lo: i64, hi: i64) {
    unum(b, o, l);
    num(b, lo);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    unum(b, o, l);
    num(b, hi);
    op(b, OpLessThanOrEqual);
    verify(b)
}
fn state_count_bounds(b: &mut ScriptBuilder) {
    for (o, hi) in [(72, 65535), (108, 131071)] {
        snum(b, o);
        num(b, 1);
        op(b, OpGreaterThanOrEqual);
        verify(b);
        snum(b, o);
        num(b, hi);
        op(b, OpLessThanOrEqual);
        verify(b)
    }
    snum(b, 108);
    snum(b, 72);
    num(b, 2);
    op(b, OpMul);
    num(b, 1);
    op(b, OpAdd);
    op(b, OpLessThanOrEqual);
    verify(b)
}
#[derive(Copy, Clone)]
enum Index {
    Payload(usize),
    State { offset: usize, add: i64 },
}
fn index(b: &mut ScriptBuilder, i: Index) {
    match i {
        Index::Payload(o) => unum(b, o, 4),
        Index::State { offset, add } => {
            snum(b, offset);
            if add != 0 {
                num(b, add);
                op(b, OpAdd)
            }
        }
    }
}
fn path(b: &mut ScriptBuilder, start: usize, depth: usize, i: Index, tag: &[u8]) {
    for j in 0..depth {
        index(b, i);
        num(b, 1 << j);
        op(b, OpDiv);
        num(b, 2);
        op(b, OpMod);
        op(b, OpIf);
        pl(b, start + 32 * j, 32);
        op(b, OpSwap);
        op(b, OpElse);
        pl(b, start + 32 * j, 32);
        op(b, OpEndIf);
        cat(b);
        data(b, tag);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256)
    }
}
fn lt256(b: &mut ScriptBuilder, a: usize, c: usize) {
    num(b, 0);
    for (start, len) in [(0, 7), (7, 7), (14, 7), (21, 7), (28, 4)] {
        unum(b, a + start, len);
        unum(b, c + start, len);
        op(b, OpEqual);
        op(b, OpBoolAnd);
        unum(b, a + start, len);
        unum(b, c + start, len);
        op(b, OpLessThan);
        op(b, OpBoolOr)
    }
}
fn leaf(b: &mut ScriptBuilder, v: usize, next: usize, nexti: Index) {
    data(b, LEAF_TAG);
    pl(b, v, 32);
    cat(b);
    pl(b, next, 32);
    cat(b);
    match nexti {
        Index::Payload(o) => pl(b, o, 4),
        i => {
            index(b, i);
            num(b, 4);
            op(b, OpNum2Bin)
        }
    }
    cat(b);
    op(b, OpSHA256)
}
fn empty(tag: &[u8]) -> [u8; 32] {
    Sha256::digest(tag).into()
}
// Stack currentNFroot -> exact newNFroot. The authenticated predecessor path
// and append index are reused; there is no independent old/new path walk.
fn insert_nf(b: &mut ScriptBuilder, nf: usize, w: usize, slot: i64, mid: Option<usize>) {
    let pi = w;
    let pv = w + 4;
    let pn = w + 36;
    let pni = w + 68;
    let pp = w + 72;
    let ap = w + 616;
    let append = Index::State {
        offset: 108,
        add: slot,
    };
    for off in [pi, pni] {
        unum(b, off, 4);
        index(b, append);
        op(b, OpLessThan);
        verify(b)
    }
    unum(b, pi, 4);
    num(b, 0);
    op(b, OpNumEqual);
    pl(b, pv, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpEqualVerify);
    unum(b, pni, 4);
    num(b, 0);
    op(b, OpNumEqual);
    pl(b, pn, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpEqualVerify);
    pl(b, nf, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    verify(b);
    op(b, OpToAltStack);
    leaf(b, pv, pn, Index::Payload(pni));
    path(b, pp, 17, Index::Payload(pi), NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    lt256(b, pv, nf);
    verify(b);
    pl(b, pn, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    op(b, OpIf);
    lt256(b, nf, pn);
    verify(b);
    op(b, OpEndIf);
    leaf(b, pv, nf, append);
    path(b, pp, 17, Index::Payload(pi), NF_NODE);
    if let Some(o) = mid {
        op(b, OpDup);
        pl(b, o, 32);
        op(b, OpEqualVerify)
    }
    op(b, OpToAltStack);
    data(b, &empty(b"KPX1NFE\0"));
    path(b, ap, 17, append, NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    leaf(b, nf, pn, Index::Payload(pni));
    path(b, ap, 17, append, NF_NODE)
}
// Stack currentCMroot -> newCMroot, with current empty-slot authentication.
fn append_cm(b: &mut ScriptBuilder, cm: usize, w: usize, slot: i64) {
    let at = Index::State {
        offset: 72,
        add: slot,
    };
    op(b, OpToAltStack);
    data(b, &empty(b"KPX1CME\0"));
    path(b, w, 16, at, CM_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    pl(b, cm, 32);
    path(b, w, 16, at, CM_NODE)
}
fn native_amount(b: &mut ScriptBuilder, code: u8, which: i64) {
    num(b, which);
    op(b, code)
}
fn amount_bytes(b: &mut ScriptBuilder, code: u8, which: i64) {
    native_amount(b, code, which);
    num(b, 8);
    op(b, OpNum2Bin)
}
fn successor(b: &mut ScriptBuilder, len: usize, private: bool) {
    ss(b, REDEEM_START, 2);
    if private {
        pl(b, 364, 112)
    } else {
        st(b, 0, 76);
        pl(b, NEWROOT, 32);
        cat(b);
        snum(b, 108);
        num(b, 1);
        op(b, OpAdd);
        num(b, 4);
        op(b, OpNum2Bin);
        cat(b)
    }
    cat(b);
    ss(b, REDEEM_START + 114, len - 114);
    cat(b);
    op(b, OpBlake2b);
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    cat(b);
    data(b, &[OpEqual]);
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify)
}
fn private_branch(b: &mut ScriptBuilder, len: usize, vk: &[u8]) {
    data(b, &[0; 65]);
    op(b, OpEqualVerify);
    eqn(b, OpTxPayloadLen, PRIVATE_PAYLOAD as i64);
    eqn(b, OpTxInputCount, 1);
    eqn(b, OpTxOutputCount, 1);
    eqdata(b, 8, &DOMAIN);
    st(b, 0, 112);
    pl(b, 76, 112);
    op(b, OpEqualVerify);
    num(b, 0);
    op(b, OpOutpointTxId);
    pl(b, 40, 32);
    op(b, OpEqualVerify);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
    num(b, 0);
    num(b, 4);
    op(b, OpSubstr);
    pl(b, 72, 4);
    op(b, OpEqualVerify);
    amount_bytes(b, OpTxInputAmount, 0);
    pl(b, 188, 8);
    op(b, OpEqualVerify);
    range(b, 188, 8, NOTE_FLOOR, MAX);
    range(b, 196, 8, 1, MAX);
    range(b, 476, 8, NOTE_FLOOR, MAX);
    unum(b, 188, 8);
    unum(b, 196, 8);
    op(b, OpSub);
    unum(b, 476, 8);
    op(b, OpNumEqualVerify);
    amount_bytes(b, OpTxOutputAmount, 0);
    pl(b, 476, 8);
    op(b, OpEqualVerify);
    eqdata(b, 364, STATE_MAGIC);
    eqdata(b, 372, &DOMAIN);
    snum(b, 72);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, 65535);
    op(b, OpLessThanOrEqual);
    verify(b);
    unum(b, 436, 4);
    op(b, OpNumEqualVerify);
    snum(b, 108);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, 131071);
    op(b, OpLessThanOrEqual);
    verify(b);
    unum(b, 472, 4);
    op(b, OpNumEqualVerify);
    pl(b, 204, 32);
    pl(b, 236, 32);
    op(b, OpEqual);
    op(b, OpNot);
    verify(b);
    pl(b, 268, 32);
    pl(b, 300, 32);
    op(b, OpEqual);
    op(b, OpNot);
    verify(b);
    st(b, 76, 32);
    insert_nf(b, 204, 1012, 0, None);
    insert_nf(b, 236, 2172, 1, None);
    pl(b, 440, 32);
    op(b, OpEqualVerify);
    st(b, 40, 32);
    append_cm(b, 268, 3332, 0);
    append_cm(b, 300, 3844, 1);
    pl(b, 404, 32);
    op(b, OpEqualVerify);
    pl(b, 484, 528);
    op(b, OpSHA256);
    pl(b, 332, 32);
    op(b, OpEqualVerify);
    successor(b, len, true);
    pl(b, 0, 484);
    op(b, OpSHA256);
    op(b, OpDup);
    num(b, 16);
    num(b, 32);
    op(b, OpSubstr);
    data(b, &[0; 16]);
    cat(b);
    op(b, OpSwap);
    num(b, 0);
    num(b, 16);
    op(b, OpSubstr);
    data(b, &[0; 16]);
    cat(b);
    num(b, 2);
    op(b, OpFromAltStack);
    data(b, vk);
    data(b, &[0x20]);
    op(b, OpZkPrecompile)
}
fn payout_index(b: &mut ScriptBuilder) {
    native_amount(b, OpTxInputAmount, 0);
    unum(b, VALUE, 8);
    op(b, OpNumEqual);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf)
}
fn reveal_branch(b: &mut ScriptBuilder, len: usize) {
    eqdata(b, 0, REVEAL_MAGIC);
    eqdata(b, 8, &[1]);
    eqn(b, OpTxPayloadLen, REVEAL_PAYLOAD as i64);
    eqn(b, OpTxInputCount, 1);
    op(b, OpFromAltStack);
    data(b, &[0; 128]);
    op(b, OpEqualVerify);
    ss(b, 65, 1);
    data(b, &[1]);
    op(b, OpEqualVerify);
    native_amount(b, OpTxInputAmount, 0);
    num(b, NOTE_FLOOR);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    native_amount(b, OpTxInputAmount, 0);
    num(b, MAX);
    op(b, OpLessThanOrEqual);
    verify(b);
    range(b, VALUE, 8, NOTE_FLOOR, MAX);
    range(b, PAY, 8, PAYOUT_FLOOR, MAX);
    range(b, FEE, 8, 1, MAX);
    snum(b, 108);
    num(b, 1);
    op(b, OpAdd);
    snum(b, 72);
    num(b, 2);
    op(b, OpMul);
    num(b, 1);
    op(b, OpAdd);
    op(b, OpLessThanOrEqual);
    verify(b);
    data(b, KEY_TAG);
    data(b, &DOMAIN);
    cat(b);
    pl(b, KEY, 32);
    cat(b);
    op(b, OpSHA256);
    pl(b, KC, 32);
    op(b, OpEqualVerify);
    data(b, NOTE_TAG);
    data(b, &DOMAIN);
    cat(b);
    for (o, l) in [
        (O, 32),
        (INC, 32),
        (VALUE, 8),
        (RHO, 32),
        (KC, 32),
        (PK, 32),
    ] {
        pl(b, o, l);
        cat(b)
    }
    op(b, OpSHA256);
    pl(b, CM, 32);
    op(b, OpEqualVerify);
    unum(b, POS, 4);
    snum(b, 72);
    op(b, OpLessThan);
    verify(b);
    pl(b, CM, 32);
    path(b, CMPATH, 16, Index::Payload(POS), CM_NODE);
    st(b, 40, 32);
    op(b, OpEqualVerify);
    pl(b, KEY, 32);
    data(b, &[0; 32]);
    cat(b);
    data(b, &[0x5c; 64]);
    op(b, OpXor);
    pl(b, KEY, 32);
    data(b, &[0; 32]);
    cat(b);
    data(b, &[0x36; 64]);
    op(b, OpXor);
    data(b, NF_TAG);
    cat(b);
    data(b, &DOMAIN);
    cat(b);
    pl(b, CM, 32);
    cat(b);
    pl(b, POS, 4);
    cat(b);
    op(b, OpSHA256);
    cat(b);
    op(b, OpSHA256);
    pl(b, NF, 32);
    op(b, OpEqualVerify);
    // Reveal wire's predecessor witness757..1917 is exactly NFwitness1160.
    st(b, 76, 32);
    insert_nf(b, NF, 757, 0, Some(1949));
    pl(b, NEWROOT, 32);
    op(b, OpEqualVerify);
    unum(b, PAY, 8);
    unum(b, FEE, 8);
    op(b, OpAdd);
    unum(b, VALUE, 8);
    op(b, OpNumEqualVerify);
    native_amount(b, OpTxInputAmount, 0);
    unum(b, VALUE, 8);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    native_amount(b, OpTxInputAmount, 0);
    unum(b, VALUE, 8);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    eqn(b, OpTxOutputCount, 2);
    native_amount(b, OpTxInputAmount, 0);
    unum(b, VALUE, 8);
    op(b, OpSub);
    op(b, OpDup);
    num(b, NOTE_FLOOR);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    native_amount(b, OpTxOutputAmount, 0);
    op(b, OpNumEqualVerify);
    successor(b, len, false);
    num(b, 1);
    eqn(b, OpOutputAuthorizingInput, -1);
    op(b, OpEndIf);
    payout_index(b);
    op(b, OpTxOutputAmount);
    unum(b, PAY, 8);
    op(b, OpNumEqualVerify);
    data(b, &[0, 0, 32]);
    pl(b, PK, 32);
    cat(b);
    data(b, &[OpCheckSig]);
    cat(b);
    payout_index(b);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify);
    pl(b, PK, 32);
    op(b, OpCheckSig)
}

pub const ADMIT_MAGIC: &[u8; 8] = b"KPX2AD01";
pub const ADMIT_PAYLOAD: usize = 1344;
pub const ADMIT_BUDGET: u16 = 200;
pub fn note_cm(note: &[u8; 168]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NOTE_TAG);
    h.update(DOMAIN);
    h.update(note);
    h.finalize().into()
}
fn tagged_node(tag: &[u8], a: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(a);
    h.update(c);
    h.finalize().into()
}
pub fn cm_empty_siblings() -> Vec<[u8; 32]> {
    let mut a = empty(b"KPX1CME\0");
    let mut path = vec![];
    for _ in 0..16 {
        path.push(a);
        a = tagged_node(CM_NODE, &a, &a)
    }
    path
}
pub fn sentinel_nf_root() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_TAG);
    h.update([0; 68]);
    let mut leaf: [u8; 32] = h.finalize().into();
    let mut blank = empty(b"KPX1NFE\0");
    for _ in 0..17 {
        leaf = tagged_node(NF_NODE, &leaf, &blank);
        blank = tagged_node(NF_NODE, &blank, &blank)
    }
    leaf
}
pub fn singleton_state(note: &[u8; 168]) -> [u8; 112] {
    let mut cm = note_cm(note);
    for sibling in cm_empty_siblings() {
        cm = tagged_node(CM_NODE, &cm, &sibling)
    }
    let mut state = [0; 112];
    state[..8].copy_from_slice(STATE_MAGIC);
    state[8..40].copy_from_slice(&DOMAIN);
    state[40..72].copy_from_slice(&cm);
    state[72..76].copy_from_slice(&1u32.to_le_bytes());
    state[76..108].copy_from_slice(&sentinel_nf_root());
    state[108..112].copy_from_slice(&1u32.to_le_bytes());
    state
}
fn admission_successor(b: &mut ScriptBuilder, len: usize) {
    ss(b, REDEEM_START, 2);
    pl(b, 1048, 112);
    cat(b);
    ss(b, REDEEM_START + 114, len - 114);
    cat(b);
    op(b, OpBlake2b);
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    cat(b);
    data(b, &[OpEqual]);
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify)
}
fn funding_ss(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, 1);
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxInputScriptSigSubstr)
}
fn funding_spk_slice(b: &mut ScriptBuilder, o: usize, l: usize) {
    num(b, 1);
    num(b, o as i64);
    num(b, (o + l) as i64);
    op(b, OpTxInputSpkSubstr)
}
fn admit_branch(b: &mut ScriptBuilder, len: usize) {
    eqdata(b, 0, ADMIT_MAGIC);
    eqdata(b, 8, &DOMAIN);
    eqn(b, OpTxPayloadLen, ADMIT_PAYLOAD as i64);
    eqn(b, OpTxInputCount, 2);
    data(b, &[0; 65]);
    op(b, OpEqualVerify);
    op(b, OpFromAltStack);
    data(b, &[0; 128]);
    op(b, OpEqualVerify);
    native_amount(b, OpTxInputAmount, 0);
    num(b, NOTE_FLOOR);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    native_amount(b, OpTxInputAmount, 0);
    num(b, MAX);
    op(b, OpLessThanOrEqual);
    verify(b);
    num(b, 1);
    op(b, OpTxInputSeq);
    data(b, &u64::MAX.to_le_bytes());
    op(b, OpEqualVerify);
    num(b, 1);
    eqn(b, OpTxInputIsCoinbase, 0);
    num(b, 1);
    op(b, OpInputCovenantId);
    data(b, &[0; 32]);
    op(b, OpEqualVerify);
    num(b, 1);
    eqn(b, OpTxInputScriptSigLen, 66);
    funding_ss(b, 0, 1);
    data(b, &[65]);
    op(b, OpEqualVerify);
    funding_ss(b, 65, 1);
    data(b, &[1]);
    op(b, OpEqualVerify);
    num(b, 1);
    op(b, OpTxInputSpk);
    eqn(b, OpSize, 36);
    op(b, OpDrop);
    funding_spk_slice(b, 0, 3);
    data(b, &[0, 0, 32]);
    op(b, OpEqualVerify);
    funding_spk_slice(b, 35, 1);
    data(b, &[OpCheckSig]);
    op(b, OpEqualVerify);
    native_amount(b, OpTxInputAmount, 1);
    num(b, 1);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    native_amount(b, OpTxInputAmount, 1);
    num(b, MAX);
    op(b, OpLessThanOrEqual);
    verify(b);
    native_amount(b, OpTxInputAmount, 0);
    native_amount(b, OpTxInputAmount, 1);
    op(b, OpAdd);
    num(b, MAX);
    op(b, OpLessThanOrEqual);
    verify(b);
    range(b, 104, 8, NOTE_FLOOR, MAX);
    range(b, 1160, 8, 1, MAX);
    range(b, 1168, 8, 0, MAX);
    unum(b, 104, 8);
    unum(b, 1160, 8);
    op(b, OpAdd);
    unum(b, 1168, 8);
    op(b, OpAdd);
    native_amount(b, OpTxInputAmount, 1);
    op(b, OpNumEqualVerify);
    native_amount(b, OpTxInputAmount, 0);
    unum(b, 104, 8);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, MAX);
    op(b, OpLessThanOrEqual);
    verify(b);
    native_amount(b, OpTxOutputAmount, 0);
    op(b, OpNumEqualVerify);
    data(b, NOTE_TAG);
    data(b, &DOMAIN);
    cat(b);
    pl(b, 40, 168);
    cat(b);
    op(b, OpSHA256);
    pl(b, 208, 32);
    op(b, OpEqualVerify);
    pl(b, 240, 264);
    op(b, OpSHA256);
    pl(b, 504, 32);
    op(b, OpEqualVerify);
    eqdata(b, 1048, STATE_MAGIC);
    eqdata(b, 1056, &DOMAIN);
    snum(b, 72);
    num(b, 1);
    op(b, OpAdd);
    op(b, OpDup);
    num(b, 65535);
    op(b, OpLessThanOrEqual);
    verify(b);
    unum(b, 1120, 4);
    op(b, OpNumEqualVerify);
    st(b, 76, 36);
    pl(b, 1124, 36);
    op(b, OpEqualVerify);
    st(b, 40, 32);
    append_cm(b, 208, 536, 0);
    pl(b, 1088, 32);
    op(b, OpEqualVerify);
    admission_successor(b, len);
    unum(b, 1168, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    eqn(b, OpTxOutputCount, 2);
    native_amount(b, OpTxOutputAmount, 1);
    unum(b, 1168, 8);
    op(b, OpNumEqualVerify);
    num(b, 1);
    op(b, OpTxOutputSpk);
    num(b, 1);
    op(b, OpTxInputSpk);
    op(b, OpEqualVerify);
    num(b, 1);
    eqn(b, OpOutputAuthorizingInput, -1);
    op(b, OpEndIf);
    snum(b, 72);
    num(b, 1);
    op(b, OpNumEqual);
    snum(b, 108);
    num(b, 1);
    op(b, OpNumEqual);
    op(b, OpBoolAnd);
    op(b, OpIf);
    range(b, 1240, 8, NOTE_FLOOR, MAX);
    unum(b, 1240, 8);
    native_amount(b, OpTxInputAmount, 0);
    op(b, OpNumEqualVerify);
    data(b, NOTE_TAG);
    data(b, &DOMAIN);
    cat(b);
    pl(b, 1176, 168);
    cat(b);
    op(b, OpSHA256);
    for sibling in cm_empty_siblings() {
        data(b, &sibling);
        cat(b);
        data(b, CM_NODE);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256)
    }
    st(b, 40, 32);
    op(b, OpEqualVerify);
    st(b, 76, 32);
    data(b, &sentinel_nf_root());
    op(b, OpEqualVerify);
    op(b, OpElse);
    pl(b, 1176, 168);
    data(b, &[0; 168]);
    op(b, OpEqualVerify);
    op(b, OpEndIf);
    op(b, OpTrue)
}
fn build(state: &[u8; 112], vk: &[u8], len: usize) -> Vec<u8> {
    let mut b = ScriptBuilder::new();
    data(&mut b, state);
    op(&mut b, OpDrop);
    eqn(&mut b, OpDepth, 2);
    eqn(&mut b, OpSize, 128);
    op(&mut b, OpToAltStack);
    eqn(&mut b, OpSize, 65);
    for (c, n) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
    ] {
        eqn(&mut b, c, n)
    }
    op(&mut b, OpTxSubnetId);
    data(&mut b, &[0; 20]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    op(&mut b, OpTxInputSeq);
    data(&mut b, &u64::MAX.to_le_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputIsCoinbase, 0);
    num(&mut b, 0);
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqn(&mut b, OpOutputAuthorizingInput, -1);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    ss(&mut b, 0, 1);
    data(&mut b, &[65]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 66, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 196, 3);
    data(&mut b, &[OpPushData2, (len & 255) as u8, (len >> 8) as u8]);
    op(&mut b, OpEqualVerify);
    st(&mut b, 0, 8);
    data(&mut b, STATE_MAGIC);
    op(&mut b, OpEqualVerify);
    st(&mut b, 8, 32);
    data(&mut b, &DOMAIN);
    op(&mut b, OpEqualVerify);
    state_count_bounds(&mut b);
    pl(&mut b, 0, 8);
    data(&mut b, AUTH_MAGIC);
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    private_branch(&mut b, len, vk);
    op(&mut b, OpElse);
    pl(&mut b, 0, 8);
    data(&mut b, ADMIT_MAGIC);
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    admit_branch(&mut b, len);
    op(&mut b, OpElse);
    reveal_branch(&mut b, len);
    op(&mut b, OpEndIf);
    op(&mut b, OpEndIf);
    b.drain()
}
pub fn redeem(state: &[u8; 112], vk: &[u8]) -> Result<Vec<u8>> {
    if vk.len() != 328 {
        return Err("requires fresh two-input VK328".into());
    }
    if &state[..8] != STATE_MAGIC || state[8..40] != DOMAIN {
        return Err("new state version/domain".into());
    }
    let mut len = 16384;
    for _ in 0..8 {
        let r = build(state, vk, len);
        if r.len() == len {
            return Ok(r);
        }
        len = r.len();
        if !(256..=65535).contains(&len) {
            return Err("union exceeds canonical PUSHDATA2 limit".into());
        }
    }
    Err("canonical script length did not converge".into())
}
pub fn witness(signature: &[u8; 65], proof: &[u8; 128], redeem: &[u8]) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    b.add_data(signature)?.add_data(proof)?.add_data(redeem)?;
    let r = b.drain();
    if r.len() != REDEEM_START + redeem.len() {
        return Err("canonical common witness offset".into());
    }
    Ok(r)
}
pub fn owner_tag() -> &'static [u8; 8] {
    OWNER_TAG
}
