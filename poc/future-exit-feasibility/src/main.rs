//! Public synthetic offline experiment. No private circuit, wallet, prover,
//! funding, broadcast, accepted-chain lineage or existing-note compatibility.
use hmac::{Hmac, Mac};
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SigHashType,
    },
    mass::{MassCalculator, transaction_estimated_serialized_size},
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    EngineCtx, SigCacheKey, TxScriptEngine,
    caches::{Cache, TxScriptCacheCounters},
    opcodes::codes::*,
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
    script_class::ScriptClass,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
type R<T> = Result<T, Box<dyn std::error::Error>>;
type H = [u8; 32];
const STATE_MAGIC: &[u8; 8] = b"KPX1ST01";
const WIRE_MAGIC: &[u8; 8] = b"KPX1RV01";
const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
const LEAF_TAG: &[u8; 8] = b"KPX1NFL\0";
const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
const NF_NODE: &[u8; 8] = b"KPX1NFN\0";
const MAX: u64 = 2_870_000_000_000_000_000;
const V: u64 = 60_000_000;
const P: u64 = 10_000_000;
const F: u64 = 50_000_000;
const BUDGET: u16 = 200;
const REDEEM_START: usize = 69; // push65, signature65, pushdata2 header3
// Fixed payload offsets; unsigned u32/u64 little endian, exact lengths.
const MODE: usize = 8;
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
const PI: usize = 757;
const PV: usize = 761;
const PN: usize = 793;
const PNI: usize = 825;
const PPATH: usize = 829;
const APATH: usize = 1373;
const NF: usize = 1917;
const MID: usize = 1949;
const NEWROOT: usize = 1981;
const FEE: usize = 2013;
const PAY: usize = 2021;
const WIRE: usize = 2029;
fn hash(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p)
    }
    h.finalize().into()
}
fn nf(k: &H, d: &H, cm: &H, pos: u32) -> H {
    let mut h = Hmac::<Sha256>::new_from_slice(k).unwrap();
    h.update(NF_TAG);
    h.update(d);
    h.update(cm);
    h.update(&pos.to_le_bytes());
    h.finalize().into_bytes().into()
}
#[derive(Clone)]
struct Note {
    s: H,
    incoming: H,
    rho: H,
    k: H,
    native_secret: H,
    pk: H,
    owner: H,
    kc: H,
    cm: H,
    value: u64,
}
impl Note {
    fn new(d: &H, seed: u8) -> Self {
        Self::with_value(d, seed, V)
    }
    fn with_value(d: &H, seed: u8, value: u64) -> Self {
        let s = [seed; 32];
        let incoming = [seed + 1; 32];
        let rho = [seed + 2; 32];
        let k = [seed + 3; 32];
        let native_secret = [seed + 4; 32];
        let secp = secp256k1::Secp256k1::new();
        let pair = secp256k1::Keypair::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&native_secret).unwrap(),
        );
        let pk = pair.x_only_public_key().0.serialize();
        let owner = hash(&[OWNER_TAG, d, &s, &incoming]);
        let kc = hash(&[KEY_TAG, d, &k]);
        let cm = hash(&[
            NOTE_TAG,
            d,
            &owner,
            &incoming,
            &value.to_le_bytes(),
            &rho,
            &kc,
            &pk,
        ]);
        Self {
            s,
            incoming,
            rho,
            k,
            native_secret,
            pk,
            owner,
            kc,
            cm,
            value,
        }
    }
    fn private_reference(&self, d: &H, s: &H, k: &H) -> bool {
        hash(&[OWNER_TAG, d, s, &self.incoming]) == self.owner && hash(&[KEY_TAG, d, k]) == self.kc
    }
}
#[derive(Clone)]
struct Tree {
    levels: Vec<Vec<H>>,
    tag: H,
}
impl Tree {
    fn new(depth: usize, leaves: &[H], tag: &[u8; 8], empty: H) -> Self {
        let mut first = vec![empty; 1 << depth];
        first[..leaves.len()].copy_from_slice(leaves);
        let mut levels = vec![first];
        for i in 0..depth {
            let upper = levels[i]
                .chunks_exact(2)
                .map(|x| hash(&[tag, &x[0], &x[1]]))
                .collect();
            levels.push(upper)
        }
        let mut tag32 = [0; 32];
        tag32[..8].copy_from_slice(tag);
        Self { levels, tag: tag32 }
    }
    fn root(&self) -> H {
        self.levels.last().unwrap()[0]
    }
    fn path(&self, mut i: usize) -> Vec<H> {
        let mut p = vec![];
        for l in &self.levels[..self.levels.len() - 1] {
            p.push(l[i ^ 1]);
            i >>= 1
        }
        p
    }
    fn set(&mut self, mut i: usize, h: H) {
        self.levels[0][i] = h;
        for j in 1..self.levels.len() {
            i >>= 1;
            self.levels[j][i] = hash(&[
                &self.tag[..8],
                &self.levels[j - 1][2 * i],
                &self.levels[j - 1][2 * i + 1],
            ])
        }
    }
}
fn leaf(v: &H, next: &H, i: u32) -> H {
    hash(&[LEAF_TAG, v, next, &i.to_le_bytes()])
}
#[derive(Clone)]
struct State {
    d: H,
    cm: H,
    n: u32,
    nf: H,
    m: u32,
}
impl State {
    fn bytes(&self) -> Vec<u8> {
        [
            STATE_MAGIC.as_slice(),
            &self.d,
            &self.cm,
            &self.n.to_le_bytes(),
            &self.nf,
            &self.m.to_le_bytes(),
        ]
        .concat()
    }
}
fn op(b: &mut ScriptBuilder, c: u8) {
    b.add_op(c).unwrap();
}
fn num(b: &mut ScriptBuilder, n: i64) {
    b.add_i64(n).unwrap();
}
fn data(b: &mut ScriptBuilder, d: &[u8]) {
    b.add_data(d).unwrap();
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
        op(b, OpCat)
    }
    op(b, OpBin2Num)
}
fn snum(b: &mut ScriptBuilder, o: usize) {
    st(b, o, 4);
    data(b, &[0]);
    op(b, OpCat);
    op(b, OpBin2Num)
}
fn eqn(b: &mut ScriptBuilder, c: u8, n: i64) {
    op(b, c);
    num(b, n);
    op(b, OpNumEqualVerify)
}
fn cat(b: &mut ScriptBuilder) {
    op(b, OpCat)
}
fn verify(b: &mut ScriptBuilder) {
    op(b, OpVerify)
}
fn field_range(b: &mut ScriptBuilder, o: usize, l: usize, lo: i64, hi: i64) {
    unum(b, o, l);
    num(b, lo);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    unum(b, o, l);
    num(b, hi);
    op(b, OpLessThanOrEqual);
    verify(b)
}
fn state_range(b: &mut ScriptBuilder, o: usize, lo: i64, hi: i64) {
    snum(b, o);
    num(b, lo);
    op(b, OpGreaterThanOrEqual);
    verify(b);
    snum(b, o);
    num(b, hi);
    op(b, OpLessThanOrEqual);
    verify(b)
}
fn path(
    b: &mut ScriptBuilder,
    offset: usize,
    depth: usize,
    index: usize,
    state_index: bool,
    tag: &[u8],
) {
    for level in 0..depth {
        if state_index {
            snum(b, index)
        } else {
            unum(b, index, 4)
        }
        num(b, 1i64 << level);
        op(b, OpDiv);
        num(b, 2);
        op(b, OpMod);
        op(b, OpIf);
        pl(b, offset + level * 32, 32);
        op(b, OpSwap);
        op(b, OpElse);
        pl(b, offset + level * 32, 32);
        op(b, OpEndIf);
        cat(b);
        data(b, tag);
        op(b, OpSwap);
        cat(b);
        op(b, OpSHA256)
    }
}
// Unsigned256 LE ordering, five <=56-bit limbs so ScriptNum never overflows.
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
fn leaf_payload(b: &mut ScriptBuilder, value: usize, next: usize, index: usize, state_index: bool) {
    data(b, LEAF_TAG);
    pl(b, value, 32);
    cat(b);
    pl(b, next, 32);
    cat(b);
    if state_index {
        snum(b, index);
        num(b, 4);
        op(b, OpNum2Bin)
    } else {
        pl(b, index, 4)
    }
    cat(b);
    op(b, OpSHA256)
}
fn payout_index(b: &mut ScriptBuilder) {
    num(b, 0);
    op(b, OpTxInputAmount);
    unum(b, VALUE, 8);
    op(b, OpNumEqual);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf)
}
fn successor(b: &mut ScriptBuilder, len: usize) {
    ss(b, REDEEM_START, 78);
    pl(b, NEWROOT, 32);
    cat(b);
    snum(b, 108);
    num(b, 1);
    op(b, OpAdd);
    num(b, 4);
    op(b, OpNum2Bin);
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
fn redeem(state: &State, padded: Option<usize>) -> R<Vec<u8>> {
    let len = padded.unwrap_or(24000);
    let mut b = ScriptBuilder::new();
    data(&mut b, &state.bytes());
    op(&mut b, OpDrop);
    eqn(&mut b, OpDepth, 1);
    eqn(&mut b, OpSize, 65);
    for (c, n) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxInputCount, 1),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
        (OpTxPayloadLen, WIRE as i64),
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
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    ss(&mut b, 0, 1);
    data(&mut b, &[65]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 65, 1);
    data(&mut b, &[1]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 66, 3);
    data(&mut b, &[OpPushData2, (len & 255) as u8, (len >> 8) as u8]);
    op(&mut b, OpEqualVerify);
    st(&mut b, 0, 8);
    data(&mut b, STATE_MAGIC);
    op(&mut b, OpEqualVerify);
    pl(&mut b, 0, 8);
    data(&mut b, WIRE_MAGIC);
    op(&mut b, OpEqualVerify);
    pl(&mut b, MODE, 1);
    data(&mut b, &[1]);
    op(&mut b, OpEqualVerify);
    state_range(&mut b, 72, 1, 65536);
    state_range(&mut b, 108, 1, 131071);
    // Sentinel + previously consumed notes; one unspent note requires m<=n.
    snum(&mut b, 108);
    snum(&mut b, 72);
    op(&mut b, OpLessThanOrEqual);
    verify(&mut b);
    field_range(&mut b, VALUE, 8, 10_000_000, MAX as i64);
    field_range(&mut b, PAY, 8, 10_000_000, MAX as i64);
    field_range(&mut b, FEE, 8, 0, MAX as i64);
    // CM binds note-local credential and native signature authority.
    data(&mut b, KEY_TAG);
    st(&mut b, 8, 32);
    cat(&mut b);
    pl(&mut b, KEY, 32);
    cat(&mut b);
    op(&mut b, OpSHA256);
    pl(&mut b, KC, 32);
    op(&mut b, OpEqualVerify);
    data(&mut b, NOTE_TAG);
    st(&mut b, 8, 32);
    cat(&mut b);
    for (o, l) in [
        (O, 32),
        (INC, 32),
        (VALUE, 8),
        (RHO, 32),
        (KC, 32),
        (PK, 32),
    ] {
        pl(&mut b, o, l);
        cat(&mut b)
    }
    op(&mut b, OpSHA256);
    pl(&mut b, CM, 32);
    op(&mut b, OpEqualVerify);
    unum(&mut b, POS, 4);
    snum(&mut b, 72);
    op(&mut b, OpLessThan);
    verify(&mut b);
    pl(&mut b, CM, 32);
    path(&mut b, CMPATH, 16, POS, false, CM_NODE);
    st(&mut b, 40, 32);
    op(&mut b, OpEqualVerify);
    // Exact HMAC-SHA256 with fixed32-byte key, no nonstandard primitive.
    pl(&mut b, KEY, 32);
    data(&mut b, &[0; 32]);
    cat(&mut b);
    data(&mut b, &[0x5c; 64]);
    op(&mut b, OpXor);
    pl(&mut b, KEY, 32);
    data(&mut b, &[0; 32]);
    cat(&mut b);
    data(&mut b, &[0x36; 64]);
    op(&mut b, OpXor);
    data(&mut b, NF_TAG);
    cat(&mut b);
    st(&mut b, 8, 32);
    cat(&mut b);
    pl(&mut b, CM, 32);
    cat(&mut b);
    pl(&mut b, POS, 4);
    cat(&mut b);
    op(&mut b, OpSHA256);
    cat(&mut b);
    op(&mut b, OpSHA256);
    pl(&mut b, NF, 32);
    op(&mut b, OpEqualVerify);
    pl(&mut b, NF, 32);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqual);
    op(&mut b, OpNot);
    verify(&mut b);
    unum(&mut b, PI, 4);
    snum(&mut b, 108);
    op(&mut b, OpLessThan);
    verify(&mut b);
    unum(&mut b, PNI, 4);
    snum(&mut b, 108);
    op(&mut b, OpLessThan);
    verify(&mut b);
    // Sentinel encoding and strictly sorted predecessor interval.
    unum(&mut b, PI, 4);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    pl(&mut b, PV, 32);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqual);
    op(&mut b, OpEqualVerify);
    unum(&mut b, PNI, 4);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    pl(&mut b, PN, 32);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqual);
    op(&mut b, OpEqualVerify);
    leaf_payload(&mut b, PV, PN, PNI, false);
    path(&mut b, PPATH, 17, PI, false, NF_NODE);
    st(&mut b, 76, 32);
    op(&mut b, OpEqualVerify);
    lt256(&mut b, PV, NF);
    verify(&mut b);
    pl(&mut b, PN, 32);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqual);
    op(&mut b, OpNot);
    op(&mut b, OpIf);
    lt256(&mut b, NF, PN);
    verify(&mut b);
    op(&mut b, OpEndIf);
    leaf_payload(&mut b, PV, NF, 108, true);
    path(&mut b, PPATH, 17, PI, false, NF_NODE);
    pl(&mut b, MID, 32);
    op(&mut b, OpEqualVerify);
    data(&mut b, &hash(&[b"KPX1NFE\0"]));
    path(&mut b, APATH, 17, 108, true, NF_NODE);
    pl(&mut b, MID, 32);
    op(&mut b, OpEqualVerify);
    leaf_payload(&mut b, NF, PN, PNI, false);
    path(&mut b, APATH, 17, 108, true, NF_NODE);
    pl(&mut b, NEWROOT, 32);
    op(&mut b, OpEqualVerify);
    // Whole-note value, real input reserve and owner-signed payout/fee.
    unum(&mut b, PAY, 8);
    unum(&mut b, FEE, 8);
    op(&mut b, OpAdd);
    unum(&mut b, VALUE, 8);
    op(&mut b, OpNumEqualVerify);
    num(&mut b, 0);
    op(&mut b, OpTxInputAmount);
    unum(&mut b, VALUE, 8);
    op(&mut b, OpGreaterThanOrEqual);
    verify(&mut b);
    num(&mut b, 0);
    op(&mut b, OpTxInputAmount);
    unum(&mut b, VALUE, 8);
    op(&mut b, OpNumEqual);
    op(&mut b, OpIf);
    eqn(&mut b, OpTxOutputCount, 1);
    op(&mut b, OpElse);
    eqn(&mut b, OpTxOutputCount, 2);
    num(&mut b, 0);
    op(&mut b, OpTxInputAmount);
    unum(&mut b, VALUE, 8);
    op(&mut b, OpSub);
    num(&mut b, 0);
    op(&mut b, OpTxOutputAmount);
    op(&mut b, OpNumEqualVerify);
    successor(&mut b, len);
    op(&mut b, OpEndIf);
    payout_index(&mut b);
    op(&mut b, OpTxOutputAmount);
    unum(&mut b, PAY, 8);
    op(&mut b, OpNumEqualVerify);
    data(&mut b, &[0, 0, 32]);
    pl(&mut b, PK, 32);
    cat(&mut b);
    data(&mut b, &[OpCheckSig]);
    cat(&mut b);
    payout_index(&mut b);
    op(&mut b, OpTxOutputSpk);
    op(&mut b, OpEqualVerify);
    for i in 0..2 {
        if i == 1 {
            num(&mut b, 0);
            op(&mut b, OpTxInputAmount);
            unum(&mut b, VALUE, 8);
            op(&mut b, OpGreaterThan);
            op(&mut b, OpIf)
        }
        num(&mut b, i);
        eqn(&mut b, OpOutputAuthorizingInput, -1);
        if i == 1 {
            op(&mut b, OpEndIf)
        }
    }
    pl(&mut b, PK, 32);
    op(&mut b, OpCheckSig);
    let mut bytes = b.drain();
    if bytes.len() > len {
        return Err(format!("script {} exceeds frozen envelope {len}", bytes.len()).into());
    }
    if padded.is_none() {
        // Measure minimal exact script by rerendering with its stable length.
        let actual = bytes.len();
        if actual != len {
            return redeem(state, Some(actual));
        }
    }
    bytes.resize(len, OpNop);
    Ok(bytes)
}
fn p2pk(pk: &H) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, [vec![32], pk.to_vec(), vec![OpCheckSig]].concat())
}
fn put(p: &mut [u8], o: usize, d: &[u8]) {
    p[o..o + d.len()].copy_from_slice(d)
}
#[derive(Clone)]
struct Fixture {
    name: String,
    state: State,
    next: State,
    payload: Vec<u8>,
    note: Note,
    reserve: u64,
    spent_path: Vec<H>,
}
fn fixture(name: &str, reserve: u64, high: bool) -> R<Fixture> {
    let d = hash(&[b"DO_NOT_FUND_PUBLIC_FUTURE_EXIT_01"]);
    let note = Note::new(&d, 17);
    let terminal = reserve == V;
    let n = if high {
        65536
    } else if terminal {
        1
    } else {
        2
    };
    let pos = if high { 65535 } else { 0 };
    let other = Note::with_value(&d, 31, reserve - V);
    // Complete public near-capacity note openings: all earlier leaves have their
    // exact derived NF in the indexed set. This is constructible supplied state,
    // not a chain or private-proof history. All credentials here are PUBLIC fixtures.
    let mut cms = Vec::with_capacity(n);
    let mut consumed = vec![];
    for i in 0..n {
        if i == pos {
            cms.push(note.cm)
        } else if !high {
            cms.push(other.cm)
        } else {
            let rho = hash(&[b"public-prior-note-rho", &(i as u32).to_le_bytes()]);
            let k = hash(&[b"public-prior-NF-key", &(i as u32).to_le_bytes()]);
            let kc = hash(&[KEY_TAG, &d, &k]);
            let c = hash(&[
                NOTE_TAG,
                &d,
                &note.owner,
                &note.incoming,
                &V.to_le_bytes(),
                &rho,
                &kc,
                &note.pk,
            ]);
            cms.push(c);
            consumed.push(nf(&k, &d, &c, i as u32));
        }
    }
    consumed.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
    if consumed.windows(2).any(|v| v[0] == v[1]) || consumed.iter().any(|v| *v == [0; 32]) {
        return Err("duplicate synthetic NF".into());
    }
    let cm = Tree::new(16, &cms, CM_NODE, hash(&[b"KPX1CME\0"]));
    let m = consumed.len() + 1;
    let mut vals = vec![[0; 32]];
    vals.extend(consumed);
    let leaves: Vec<H> = (0..m)
        .map(|i| {
            leaf(
                &vals[i],
                if i + 1 < m { &vals[i + 1] } else { &[0; 32] },
                if i + 1 < m { (i + 1) as u32 } else { 0 },
            )
        })
        .collect();
    let mut tree = Tree::new(17, &leaves, NF_NODE, hash(&[b"KPX1NFE\0"]));
    let state = State {
        d,
        cm: cm.root(),
        n: n as u32,
        nf: tree.root(),
        m: m as u32,
    };
    let nullifier = nf(&note.k, &d, &note.cm, pos as u32);
    let pred = vals
        .iter()
        .enumerate()
        .filter(|(_, x)| x.iter().rev().cmp(nullifier.iter().rev()).is_lt())
        .last()
        .map(|(i, _)| i)
        .ok_or("zero future NF")?;
    if vals.iter().any(|v| *v == nullifier) {
        return Err("NF collision".into());
    }
    let next_value = if pred + 1 < m {
        vals[pred + 1]
    } else {
        [0; 32]
    };
    let next_index = if pred + 1 < m { (pred + 1) as u32 } else { 0 };
    let mut payload = vec![0; WIRE];
    put(&mut payload, 0, WIRE_MAGIC);
    payload[MODE] = 1;
    for (o, x) in [
        (O, note.owner),
        (INC, note.incoming),
        (RHO, note.rho),
        (KEY, note.k),
        (PK, note.pk),
        (KC, note.kc),
        (CM, note.cm),
        (PV, vals[pred]),
        (PN, next_value),
        (NF, nullifier),
    ] {
        put(&mut payload, o, &x)
    }
    put(&mut payload, VALUE, &note.value.to_le_bytes());
    put(&mut payload, POS, &(pos as u32).to_le_bytes());
    put(&mut payload, PI, &(pred as u32).to_le_bytes());
    put(&mut payload, PNI, &next_index.to_le_bytes());
    for (i, h) in cm.path(pos).iter().enumerate() {
        put(&mut payload, CMPATH + 32 * i, h)
    }
    for (i, h) in tree.path(pred).iter().enumerate() {
        put(&mut payload, PPATH + 32 * i, h)
    }
    tree.set(pred, leaf(&vals[pred], &nullifier, m as u32));
    put(&mut payload, MID, &tree.root());
    for (i, h) in tree.path(m).iter().enumerate() {
        put(&mut payload, APATH + 32 * i, h)
    }
    tree.set(m, leaf(&nullifier, &next_value, next_index));
    put(&mut payload, NEWROOT, &tree.root());
    put(&mut payload, FEE, &F.to_le_bytes());
    put(&mut payload, PAY, &P.to_le_bytes());
    let next = State {
        nf: tree.root(),
        m: state.m + 1,
        ..state.clone()
    };
    Ok(Fixture {
        name: name.to_string(),
        state,
        next,
        payload,
        note,
        reserve,
        spent_path: tree.path(m),
    })
}

fn validator() -> TransactionValidator {
    let p = TESTNET_PARAMS;
    TransactionValidator::new(
        p.max_tx_inputs,
        p.max_tx_outputs,
        p.max_signature_script_len,
        p.max_script_public_key_len,
        p.coinbase_payload_script_public_key_max_len,
        p.coinbase_maturity(),
        p.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(&p),
        p.mass_per_sig_op,
    )
}
fn setmass(tx: &Transaction, entries: &[UtxoEntry]) -> R<()> {
    let m = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("undefined storage mass")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}
fn sign(tx: &mut Transaction, entries: &[UtxoEntry], note: &Note, redeem: &[u8], typ: u8) {
    let secp = secp256k1::Secp256k1::new();
    let pair = secp256k1::Keypair::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_slice(&note.native_secret).unwrap(),
    );
    let hash = calc_schnorr_signature_hash(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        0,
        SigHashType::from_u8(typ).expect("supported requested sighash"),
        &SigHashReusedValuesUnsync::new(),
    );
    let sig = secp.sign_schnorr_no_aux_rand(
        &secp256k1::Message::from_digest_slice(&hash.as_bytes()).unwrap(),
        &pair,
    );
    let mut b = ScriptBuilder::new();
    let mut s = sig.as_ref().to_vec();
    s.push(typ);
    data(&mut b, &s);
    data(&mut b, redeem);
    tx.inputs[0].signature_script = b.drain();
    tx.finalize();
}
fn body(f: &Fixture, padded: Option<usize>) -> R<(Transaction, Vec<UtxoEntry>, Vec<u8>)> {
    let r = redeem(&f.state, padded)?;
    let entry = UtxoEntry::new(f.reserve, pay_to_script_hash_script(&r), 0, false, None);
    let mut outs = vec![];
    if f.reserve > V {
        outs.push(TransactionOutput::new(
            f.reserve - V,
            pay_to_script_hash_script(&redeem(&f.next, Some(r.len()))?),
        ))
    }
    let payout = u64::from_le_bytes(f.payload[PAY..PAY + 8].try_into().unwrap());
    outs.push(TransactionOutput::new(payout, p2pk(&f.note.pk)));
    let mut tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(
                kaspa_hashes::Hash::from_bytes(hash(&[b"SYNTHETIC_UNFUNDED", f.name.as_bytes()])),
                0,
            ),
            vec![],
            u64::MAX,
            BUDGET,
        )],
        outs,
        0,
        Default::default(),
        0,
        f.payload.clone(),
    );
    let entries = vec![entry];
    setmass(&tx, &entries)?;
    sign(&mut tx, &entries, &f.note, &r, 1);
    setmass(&tx, &entries)?;
    Ok((tx, entries, r))
}
fn execute(tx: &Transaction, e: &[UtxoEntry]) -> Value {
    let v = validator();
    let iso = v.validate_tx_in_isolation(tx);
    let pop = PopulatedTransaction::new(tx, e.to_vec());
    let full = if iso.is_ok() {
        v.validate_populated_transaction_and_get_fee(
            &pop,
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )
        .map_err(|e| format!("{e:?}"))
    } else {
        Err(format!("isolation:{:?}", iso.as_ref().err()))
    };
    let cache: Cache<SigCacheKey, bool> = Cache::new(10);
    let reused = SigHashReusedValuesUnsync::new();
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &pop,
        &tx.inputs[0],
        0,
        &e[0],
        EngineCtx::new(&cache).with_reused(&reused),
        Default::default(),
        tx.inputs[0].compute_commit.allowed_script_units(),
    );
    let script = vm.execute();
    json!({"isolation":iso.map(|_|"PASS".to_string()).unwrap_or_else(|e|format!("{e:?}")),"Full":match full{Ok(f)=>json!({"accepted":true,"fee_sompi":f}),Err(e)=>json!({"accepted":false,"typed_error":e})},"ScriptEngine":match script{Ok(_)=>json!({"accepted":true,"units":vm.used_script_units().0}),Err(e)=>json!({"accepted":false,"typed_error":format!("{e:?}"),"units":vm.used_script_units().0})}})
}
fn metrics(tx: &Transaction, e: &[UtxoEntry]) -> R<Value> {
    let c = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let m = c.calc_non_contextual_masses(tx);
    let storage = c
        .calc_contextual_masses(&PopulatedTransaction::new(tx, e.to_vec()))
        .ok_or("undefined storage")?
        .storage_mass;
    let relay = m.compute_mass.max(m.transient_mass.div_ceil(2));
    let mining = relay.max(storage);
    let fee =
        e.iter().map(|x| x.amount).sum::<u64>() - tx.outputs.iter().map(|x| x.value).sum::<u64>();
    let standard = e
        .iter()
        .map(|x| &x.script_public_key)
        .chain(tx.outputs.iter().map(|x| &x.script_public_key))
        .all(|s| s.version() == 0 && ScriptClass::from_script(s) != ScriptClass::NonStandard);
    let quotes:Vec<Value>=[100u64,200,500].into_iter().map(|rate|json!({"rate_sompi_per_mass":rate,"required_sompi":mining*rate,"actual_sompi":fee,"passes":fee>=mining*rate})).collect();
    let sigops = tx
        .inputs
        .iter()
        .zip(e)
        .map(|(i, u)| kaspa_txscript::p2sh_sig_scanner(&i.signature_script, &u.script_public_key))
        .collect::<Vec<_>>();
    Ok(json!({
      "estimated_bytes":transaction_estimated_serialized_size(tx),
      "compute_mass":m.compute_mass,"transient_mass":m.transient_mass,
      "storage_mass":storage,"relay_mass":relay,"mining_mass":mining,
      "fee_sompi":fee,"standard_script_classes":standard,
      "P2SH_sigop_counts":sigops,"source_adapted_sigop_policy":sigops.iter().all(|n|*n<=15),
      "source_adapted_default_relay_fee":fee>=relay*100,
      "source_adapted_block_mass_caps":m.compute_mass<=500000&&m.transient_mass<=1000000&&storage<=500000,
      "fee_quotes":quotes,
      "singleton_rate500_gate":mining<=100000&&fee<=50000000&&fee>=mining*500&&tx.outputs.last().unwrap().value>=10000000
    }))
}
fn write(path: &Path, v: &impl serde::Serialize) -> R<()> {
    std::fs::write(path, serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
// Frozen fee agility: monotone body-dependent least fixed point, never a quote
// transplanted from another payout. Each prepared body is owner-signed afresh.
fn fee_agility(fixtures: &[Fixture], mode: &str, out: &Path) -> R<()> {
    let mut rows = vec![];
    for f in fixtures {
        for pad in [None, Some(32768), Some(49152)] {
            for rate in [100u64, 200, 500] {
                let mut fee: u64 = 0;
                let mut sequence = vec![];
                let mut failed = false;
                let (tx, e, r) = loop {
                    let mut candidate = f.clone();
                    put(&mut candidate.payload, FEE, &fee.to_le_bytes());
                    put(&mut candidate.payload, PAY, &(V - fee).to_le_bytes());
                    let (tx, e, r) = body(&candidate, pad)?;
                    let mass = metrics(&tx, &e)?["mining_mass"]
                        .as_u64()
                        .ok_or("mass field")?;
                    let required = mass.checked_mul(rate).ok_or("fee multiplication")?;
                    sequence.push(json!({"fee_sompi":fee,"payout_sompi":V-fee,"mining_mass":mass,"required_fee_sompi":required,"native_id":tx.id().to_string()}));
                    if required <= fee {
                        break (tx, e, r);
                    }
                    if required > F {
                        failed = true;
                        break (tx, e, r);
                    }
                    fee = required;
                };
                let label = format!(
                    "agility-{}-{}-r{}",
                    f.name,
                    pad.map(|x| x.to_string()).unwrap_or("minimal".to_string()),
                    rate
                );
                std::fs::write(out.join(format!("{label}.redeem.bin")), &r)?;
                write(&out.join(format!("{label}.transaction.json")), &tx)?;
                let mut row = json!({"name":label,"prospective_fee_fixed_point":true,"rate_sompi_per_mass":rate,"economic_gate_passed":!failed,"failure_reason":if failed{Some("next required fee exceeds50M /10M payout floor")}else{None},"iterations":sequence,"final_actual_fee_sompi":fee,"final_payout_sompi":V-fee,"metrics":metrics(&tx,&e)?});
                if mode == "run" {
                    row["native_execution"] = execute(&tx, &e);
                    write(&out.join(format!("{label}.validation.json")), &row)?;
                    if row["native_execution"]["Full"]["accepted"] != true {
                        return Err(format!(
                            "fee agility native failure {label}: {}",
                            row["native_execution"]
                        )
                        .into());
                    }
                }
                rows.push(row);
            }
        }
    }
    write(
        &out.join(if mode == "run" {
            "fee-agility-results.json"
        } else {
            "frozen-fee-agility.json"
        }),
        &rows,
    )?;
    Ok(())
}
fn require_rejection(mode: &str, name: &str, result: &Value) -> R<()> {
    if mode != "run" {
        return Ok(());
    }
    if result["ScriptEngine"]["typed_error"] != "VerifyError"
        || result["Full"]["typed_error"] != "SignatureInvalid(VerifyError)"
    {
        return Err(format!("wrong rejection cause {name}: {result}").into());
    }
    Ok(())
}
fn main() -> R<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("freeze");
    let out = Path::new(args.get(2).ok_or("output directory required")?);
    std::fs::create_dir_all(out)?;
    let fixtures = vec![
        fixture("terminal-singleton", V, false)?,
        fixture("continuing-remainder60M", 120_000_000, false)?,
        fixture("continuing-remainder20M", 80_000_000, false)?,
        fixture("continuing-remainder10M", 70_000_000, false)?,
        fixture("high-index65536", 120_000_000, true)?,
    ];
    write(
        &out.join("unsupported-underbacked-terminal-context.json"),
        &json!({"input_R_sompi":V,"current_note_V_sompi":V,"another_current_unspent_note_W_sompi":20000000,"complete_liability_sompi":80000000,"violates_prior_I1":true,"native_execution":"NOT RUN: outside valid-prior-state assumption","meaning":"terminal algebra does not erase other liabilities or prove accepted backing"}),
    )?;
    let mut rows = vec![];
    for f in &fixtures {
        for pad in [None, Some(32768), Some(49152)] {
            let (tx, e, r) = body(f, pad)?;
            let label = format!(
                "{}-{}",
                f.name,
                pad.map(|x| x.to_string()).unwrap_or("minimal".to_string())
            );
            let mut record = json!({"name":label,"redeem_bytes":r.len(),"padded_feasibility_only":pad.is_some(),"input_reserve_sompi":f.reserve,"principal_sompi":V,"payout_sompi":P,"owner_authorized_fee_sompi":F,"state_hex":hex::encode(f.state.bytes()),"next_state_hex":hex::encode(f.next.bytes()),"CM_position":u32::from_le_bytes(f.payload[POS..POS+4].try_into().unwrap()),"NF_append_index":f.state.m,"payload_hex":hex::encode(&f.payload),"redeem_sha256":hex::encode(hash(&[&r])),"native_id":tx.id().to_string(),"private_reference_owner":f.note.private_reference(&f.state.d,&f.note.s,&f.note.k),"copied_k_wrong_s_private_reference":f.note.private_reference(&f.state.d,&[0;32],&f.note.k),"unsafe_single_secret_reference_accepts_copied_k":hash(&[KEY_TAG,&f.state.d,&f.note.k])==f.note.kc,"metrics":metrics(&tx,&e)?});
            std::fs::write(out.join(format!("{label}.redeem.bin")), &r)?;
            std::fs::write(out.join(format!("{label}.payload.bin")), &tx.payload)?;
            write(&out.join(format!("{label}.transaction.json")), &tx)?;
            if mode == "run" {
                record["native_execution"] = execute(&tx, &e);
                write(&out.join(format!("{label}.validation.json")), &record)?;
                if record["native_execution"]["Full"]["accepted"] != true {
                    return Err(
                        format!("positive failed {label}: {}", record["native_execution"]).into(),
                    );
                }
            }
            rows.push(record)
        }
    }
    write(
        &out.join(if mode == "run" {
            "positive-results.json"
        } else {
            "frozen-fixtures.json"
        }),
        &rows,
    )?;
    fee_agility(&fixtures, mode, out)?;
    let f = &fixtures[1];
    let (tx, e, r) = body(f, None)?;
    let mutations: Vec<(&str, usize, usize)> = vec![
        ("wire-magic", 0, 1),
        ("private-unimplemented-branch", MODE, 1),
        ("owner-opening", O, 1),
        ("incoming", INC, 1),
        ("value-opening", VALUE, 1),
        ("rho-opening", RHO, 1),
        ("copied-k", KEY, 1),
        ("native-PK-substitution", PK, 1),
        ("position-alias", POS + 2, 1),
        ("K-commitment", KC, 1),
        ("CM", CM, 1),
        ("CM-current-root-path", CMPATH, 1),
        ("pred-index", PI, 1),
        ("pred-value", PV, 1),
        ("pred-next", PN, 1),
        ("pred-next-index", PNI, 1),
        ("pred-path", PPATH, 1),
        ("append-path", APATH, 1),
        ("exact-NF", NF, 1),
        ("intermediate-root", MID, 1),
        ("new-NF-root", NEWROOT, 1),
        ("fee-payload", FEE, 1),
        ("payout-payload", PAY, 1),
    ];
    let mut negatives = vec![];
    for (name, o, x) in mutations {
        let mut bad = tx.clone();
        bad.payload[o] ^= x as u8;
        sign(&mut bad, &e, &f.note, &r, 1);
        setmass(&bad, &e)?;
        write(&out.join(format!("negative-{name}.transaction.json")), &bad)?;
        let result = if mode == "run" {
            execute(&bad, &e)
        } else {
            json!({"expected":"Full and ScriptEngine reject","not_executed":true})
        };
        require_rejection(mode, name, &result)?;
        negatives.push(json!({"case":name,"owner_resigned":true,"result":result}))
    }
    for name in [
        "weak-sighash",
        "payout-redirection",
        "fee-increase",
        "reserve-value",
        "successor-policy",
        "stale-NF-state",
        "cross-domain",
        "extra-input",
        "trailing-payload",
        "reveal-after-reference-private-consume",
        "current-authenticated-spent-NF-equality",
        "CM-count-zero",
        "CM-count-overflow",
        "NF-count-zero",
        "NF-count-over-CM",
        "unsigned-CM-count-high-bit",
    ] {
        let mut bad = tx.clone();
        let mut entries = e.clone();
        match name {
            "weak-sighash" => {}
            "payout-redirection" => {
                bad.outputs.last_mut().unwrap().script_public_key = p2pk(&[77; 32])
            }
            "fee-increase" => bad.outputs.last_mut().unwrap().value -= 1,
            "reserve-value" => bad.outputs[0].value -= 1,
            "successor-policy" => bad.outputs[0].script_public_key = p2pk(&[77; 32]),
            "stale-NF-state"
            | "cross-domain"
            | "reveal-after-reference-private-consume"
            | "current-authenticated-spent-NF-equality"
            | "CM-count-zero"
            | "CM-count-overflow"
            | "NF-count-zero"
            | "NF-count-over-CM"
            | "unsigned-CM-count-high-bit" => {
                let mut s = f.state.clone();
                if name == "CM-count-zero" {
                    s.n = 0
                } else if name == "CM-count-overflow" {
                    s.n = 65537
                } else if name == "NF-count-zero" {
                    s.m = 0
                } else if name == "NF-count-over-CM" {
                    s.m = s.n + 1
                } else if name == "unsigned-CM-count-high-bit" {
                    s.n = 0x80000000
                } else if name == "cross-domain" {
                    s.d[0] ^= 1
                } else if name == "stale-NF-state" {
                    s.nf[0] ^= 1
                } else {
                    s.nf = f.next.nf;
                    s.m = f.next.m
                }
                if name == "current-authenticated-spent-NF-equality" {
                    let current_nf: H = f.payload[NF..NF + 32].try_into().unwrap();
                    put(&mut bad.payload, PI, &f.state.m.to_le_bytes());
                    put(&mut bad.payload, PV, &current_nf);
                    for (j, h) in f.spent_path.iter().enumerate() {
                        put(&mut bad.payload, PPATH + j * 32, h)
                    }
                    let next_value: H = f.payload[PN..PN + 32].try_into().unwrap();
                    let next_index =
                        u32::from_le_bytes(f.payload[PNI..PNI + 4].try_into().unwrap());
                    let mut h = leaf(&current_nf, &next_value, next_index);
                    let mut index = f.state.m as usize;
                    for sibling in &f.spent_path {
                        h = if index & 1 == 0 {
                            hash(&[NF_NODE, &h, sibling])
                        } else {
                            hash(&[NF_NODE, sibling, &h])
                        };
                        index >>= 1
                    }
                    if h != s.nf {
                        return Err(
                            "spent-NF membership control is not current-root authenticated".into(),
                        );
                    }
                }
                let br = redeem(&s, Some(r.len()))?;
                entries[0].script_public_key = pay_to_script_hash_script(&br);
                sign(&mut bad, &entries, &f.note, &br, 1);
                setmass(&bad, &entries)?;
                write(&out.join(format!("negative-{name}.transaction.json")), &bad)?;
                let result = if mode == "run" {
                    execute(&bad, &entries)
                } else {
                    json!({"expected":"Full and ScriptEngine reject","not_executed":true})
                };
                require_rejection(mode, name, &result)?;
                negatives.push(json!({"case":name,"owner_resigned":true,"result":result}));
                continue;
            }
            "extra-input" => {
                bad.inputs.push(bad.inputs[0].clone());
                bad.inputs[1].previous_outpoint.index = 1;
                entries.push(entries[0].clone())
            }
            "trailing-payload" => bad.payload.push(0),
            _ => unreachable!(),
        }
        sign(
            &mut bad,
            &entries,
            &f.note,
            &r,
            if name == "weak-sighash" { 2 } else { 1 },
        );
        setmass(&bad, &entries)?;
        if name == "weak-sighash" {
            let digest = calc_schnorr_signature_hash(
                &PopulatedTransaction::new(&bad, entries.clone()),
                0,
                SigHashType::from_u8(2).unwrap(),
                &SigHashReusedValuesUnsync::new(),
            );
            let signature =
                secp256k1::schnorr::Signature::from_slice(&bad.inputs[0].signature_script[1..65])?;
            secp256k1::Secp256k1::new().verify_schnorr(
                &signature,
                &secp256k1::Message::from_digest_slice(&digest.as_bytes())?,
                &secp256k1::XOnlyPublicKey::from_slice(&f.note.pk)?,
            )?;
            write(
                &out.join("weak-sighash-cryptographic-control.json"),
                &json!({"actual_type":2,"type":"SIG_HASH_NONE","signature_valid_under_requested_type":true,"exact_ALL_guard_expected_error":"VerifyError"}),
            )?;
        }
        write(&out.join(format!("negative-{name}.transaction.json")), &bad)?;
        let result = if mode == "run" {
            execute(&bad, &entries)
        } else {
            json!({"expected":"Full and ScriptEngine reject","not_executed":true})
        };
        require_rejection(mode, name, &result)?;
        negatives.push(json!({"case":name,"owner_resigned":true,"result":result}))
    }
    write(
        &out.join(if mode == "run" {
            "negative-results.json"
        } else {
            "frozen-negatives.json"
        }),
        &negatives,
    )?;
    if mode != "run" {
        return Ok(());
    }
    write(
        &out.join("summary.json"),
        &json!({"positive_cases":rows.len(),"negative_cases":negatives.len(),"scope":"public synthetic supplied contexts only; no accepted-chain or private-circuit result","terminal_assumption":"valid prior I1 complete liabilities L<=R and current unspent V imply R=V => L=V; no remaining liability. R=V with another positive unspent note violates I1 and is unsupported","private_reference_is_not_a_SNARK":true,"official_native_revision":"01b532e8b553523216471682649693af92f0fd16"}),
    )?;
    Ok(())
}
