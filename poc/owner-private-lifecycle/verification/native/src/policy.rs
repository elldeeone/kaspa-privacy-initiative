//! New ADR0064 mixed/direct-exit covenant. Existing funded templates remain unchanged.
//! Introspection helpers adapt the repository's public W policy; the R0
//! receipt fragment is the pinned upstream SDK implementation, not an oracle.
use crate::r0_fragment::append_r0_groth16_verifier;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const DOMAIN: [u8; 32] = [
    190, 44, 98, 209, 202, 135, 20, 188, 206, 81, 101, 157, 254, 18, 193, 144, 172, 196, 34, 52,
    198, 177, 194, 255, 60, 15, 166, 12, 246, 83, 228, 128,
];
pub const BODY_LEN: usize = 10780;
pub const PREFIX_LEN: usize = 193;
pub const PROJECTION_LEN: usize = BODY_LEN + PREFIX_LEN;
pub const REDEEM_START: usize = 133;
pub const METADATA_PREFIX: usize = 559;
pub const EXIT_VK_AT: usize = 220;
pub const EXIT_BODY_LEN: usize = 1632;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub const PROFILE_AT: usize = 150;
pub const IMAGE_AT: usize = 184;
pub const MARKER_AT: usize = 550;
pub const MARKER: &[u8; 8] = b"KPX8WN01";
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const FLOOR: u64 = 60_000_000;
pub const OLD_STATE: usize = 148;
pub const NEW_STATE: usize = 268;

fn op(b: &mut ScriptBuilder, code: u8) {
    b.add_op(code).unwrap();
}
fn num(b: &mut ScriptBuilder, value: i64) {
    b.add_i64(value).unwrap();
}
fn data(b: &mut ScriptBuilder, value: &[u8]) {
    b.add_data(value).unwrap();
}
fn cat(b: &mut ScriptBuilder) {
    op(b, OpCat);
}
fn eqn(b: &mut ScriptBuilder, code: u8, value: i64) {
    op(b, code);
    num(b, value);
    op(b, OpNumEqualVerify);
}
fn pl(b: &mut ScriptBuilder, start: usize, len: usize) {
    num(b, start as i64);
    num(b, (start + len) as i64);
    op(b, OpTxPayloadSubstr);
}
fn ss(b: &mut ScriptBuilder, start: usize, len: usize) {
    num(b, 0);
    num(b, start as i64);
    num(b, (start + len) as i64);
    op(b, OpTxInputScriptSigSubstr);
}
fn st(b: &mut ScriptBuilder, start: usize, len: usize) {
    ss(b, REDEEM_START + 2 + start, len);
}
fn eqpayload(b: &mut ScriptBuilder, start: usize, value: &[u8]) {
    pl(b, start, value.len());
    data(b, value);
    op(b, OpEqualVerify);
}
fn unum(b: &mut ScriptBuilder, start: usize, len: usize) {
    pl(b, start, len);
    if len < 8 {
        data(b, &[0]);
        cat(b);
    }
    op(b, OpBin2Num);
}
fn native_amount(b: &mut ScriptBuilder, code: u8) {
    num(b, 0);
    op(b, code);
}
fn amount_bytes(b: &mut ScriptBuilder, code: u8) {
    native_amount(b, code);
    num(b, 8);
    op(b, OpNum2Bin);
}
fn range_payload(b: &mut ScriptBuilder, start: usize, len: usize, min: i64, max: i64) {
    unum(b, start, len);
    num(b, min);
    op(b, OpGreaterThanOrEqual);
    op(b, OpVerify);
    unum(b, start, len);
    num(b, max);
    op(b, OpLessThanOrEqual);
    op(b, OpVerify);
}
fn point_bytes(b: &mut ScriptBuilder) {
    num(b, 0);
    op(b, OpOutpointTxId);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
    num(b, 0);
    num(b, 4);
    op(b, OpSubstr);
    cat(b);
}
fn actual_fee(b: &mut ScriptBuilder) {
    native_amount(b, OpTxInputAmount);
    native_amount(b, OpTxOutputAmount);
    op(b, OpSub);
}
fn same_tail_successor(b: &mut ScriptBuilder, len: usize) {
    ss(b, REDEEM_START, 2);
    pl(b, NEW_STATE, 112);
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
    op(b, OpEqualVerify);
}
/// Reconstruct every native effect, including exact continuation/terminal layout.
fn indexed_amount_bytes(b: &mut ScriptBuilder, code: u8, index: i64) {
    num(b, index);
    op(b, code);
    num(b, 8);
    op(b, OpNum2Bin);
}
fn output_bytes(b: &mut ScriptBuilder, index: i64) {
    indexed_amount_bytes(b, OpTxOutputAmount, index);
    cat(b);
    num(b, index);
    op(b, OpTxOutputSpkLen);
    num(b, 2);
    op(b, OpNum2Bin);
    cat(b);
    num(b, index);
    op(b, OpTxOutputSpk);
    cat(b);
    data(b, &[0]);
    cat(b);
}
fn projection_bytes(b: &mut ScriptBuilder, body_len: usize) {
    data(b, b"KPX8FX01\x01\0\x01\0");
    point_bytes(b);
    cat(b);
    num(b, 0);
    op(b, OpTxInputSeq);
    cat(b);
    amount_bytes(b, OpTxInputAmount);
    cat(b);
    data(b, &37u16.to_le_bytes());
    cat(b);
    num(b, 0);
    op(b, OpTxInputSpk);
    cat(b);
    op(b, OpTxOutputCount);
    num(b, 2);
    op(b, OpNum2Bin);
    cat(b);
    output_bytes(b, 0);
    op(b, OpTxOutputCount);
    num(b, 2);
    op(b, OpNumEqual);
    op(b, OpIf);
    output_bytes(b, 1);
    op(b, OpEndIf);
    data(b, &[0; 8]);
    cat(b);
    op(b, OpTxSubnetId);
    cat(b);
    data(b, &[0; 8]);
    cat(b);
    data(b, &(body_len as u32).to_le_bytes());
    cat(b);
    pl(b, 0, body_len);
    cat(b);
}
fn journal_hash(b: &mut ScriptBuilder, component: &[u8; 32]) {
    data(b, b"KPX8JR01");
    data(b, &DOMAIN);
    cat(b);
    data(b, component);
    cat(b);
    projection_bytes(b, BODY_LEN);
    op(b, OpSHA256);
    cat(b);
    op(b, OpSHA256);
}
fn build(
    state: &[u8; 112],
    image: &[u8; 32],
    component: &[u8; 32],
    exit_vk: &[u8; 328],
    len: usize,
) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    data(&mut b, state);
    op(&mut b, OpDrop);
    data(&mut b, &DOMAIN);
    op(&mut b, OpDrop);
    data(&mut b, component);
    op(&mut b, OpDrop);
    data(&mut b, image);
    op(&mut b, OpDrop);
    data(&mut b, exit_vk);
    op(&mut b, OpDrop);
    data(&mut b, MARKER);
    op(&mut b, OpDrop);
    assert_eq!(b.script().len(), METADATA_PREFIX);
    // One genuine proof only. No signature placeholder or diagnostic oracle branch.
    eqn(&mut b, OpDepth, 1);
    eqn(&mut b, OpSize, 128);
    op(&mut b, OpToAltStack);
    for (code, value) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxInputCount, 1),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
    ] {
        eqn(&mut b, code, value);
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
    eqn(&mut b, OpTxInputSpkLen, 37);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    ss(&mut b, 0, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 130, 3);
    data(&mut b, &[OpPushData2, (len & 255) as u8, (len >> 8) as u8]);
    op(&mut b, OpEqualVerify);
    st(&mut b, 0, 8);
    data(&mut b, b"KPX8ST01");
    op(&mut b, OpEqualVerify);
    st(&mut b, 8, 32);
    data(&mut b, &DOMAIN);
    op(&mut b, OpEqualVerify);
    pl(&mut b, 0, 8);
    data(&mut b, b"KPX8PB01");
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    eqn(&mut b, OpTxOutputCount, 1);
    num(&mut b, 0);
    eqn(&mut b, OpTxOutputSpkLen, 37);
    eqn(&mut b, OpTxPayloadLen, BODY_LEN as i64);
    eqpayload(&mut b, 0, b"KPX8PB01\x01\0\x03\0\x06\0\0\0");
    eqpayload(&mut b, 16, &DOMAIN);
    eqpayload(&mut b, NEW_STATE, b"KPX8ST01");
    eqpayload(&mut b, NEW_STATE + 8, &DOMAIN);
    eqpayload(&mut b, 396, &[0; 8]);
    st(&mut b, 0, 112);
    pl(&mut b, OLD_STATE, 112);
    op(&mut b, OpEqualVerify);
    point_bytes(&mut b);
    pl(&mut b, 112, 36);
    op(&mut b, OpEqualVerify);
    amount_bytes(&mut b, OpTxInputAmount);
    pl(&mut b, 260, 8);
    op(&mut b, OpEqualVerify);
    amount_bytes(&mut b, OpTxOutputAmount);
    pl(&mut b, 380, 8);
    op(&mut b, OpEqualVerify);
    for code in [OpTxInputAmount, OpTxOutputAmount] {
        native_amount(&mut b, code);
        num(&mut b, FLOOR as i64);
        op(&mut b, OpGreaterThanOrEqual);
        op(&mut b, OpVerify);
        native_amount(&mut b, code);
        num(&mut b, MAX as i64);
        op(&mut b, OpLessThanOrEqual);
        op(&mut b, OpVerify);
    }
    range_payload(&mut b, 388, 8, 1, MAX as i64);
    actual_fee(&mut b);
    unum(&mut b, 388, 8);
    op(&mut b, OpNumEqualVerify);
    for (old, new, increment, lo, hi) in [(220, 340, 6, 3, 65530), (256, 376, 3, 1, 131069)] {
        range_payload(&mut b, old, 4, lo, hi);
        unum(&mut b, old, 4);
        num(&mut b, increment);
        op(&mut b, OpAdd);
        unum(&mut b, new, 4);
        op(&mut b, OpNumEqualVerify);
    }
    same_tail_successor(&mut b, len);
    journal_hash(&mut b, component);
    op(&mut b, OpFromAltStack);
    append_r0_groth16_verifier(&mut b, *image)?;
    op(&mut b, OpElse);
    exit_branch(&mut b, len, exit_vk);
    op(&mut b, OpEndIf);
    Ok(b.drain())
}

const LEAF_TAG: &[u8; 8] = b"KPX1NFL\0";
const NF_NODE: &[u8; 8] = b"KPX1NFN\0";
fn snum(b: &mut ScriptBuilder, offset: usize) {
    st(b, offset, 4);
    data(b, &[0]);
    cat(b);
    op(b, OpBin2Num);
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
        op(b, OpVerify)
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
    op(b, OpVerify);
    op(b, OpToAltStack);
    leaf(b, pv, pn, Index::Payload(pni));
    path(b, pp, 17, Index::Payload(pi), NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    lt256(b, pv, nf);
    op(b, OpVerify);
    pl(b, pn, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    op(b, OpIf);
    lt256(b, nf, pn);
    op(b, OpVerify);
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

fn exit_payout_index(b: &mut ScriptBuilder) {
    unum(b, 380, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf);
}
fn exit_branch(b: &mut ScriptBuilder, len: usize, exit_vk: &[u8; 328]) {
    eqn(b, OpTxPayloadLen, EXIT_BODY_LEN as i64);
    eqpayload(b, 0, b"KPX8XB01\x01\0\x01\0\0\0\x01\0");
    eqpayload(b, 16, &DOMAIN);
    eqpayload(b, 80, &[0; 32]);
    pl(b, 48, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    op(b, OpVerify);
    st(b, 0, 112);
    pl(b, OLD_STATE, 112);
    op(b, OpEqualVerify);
    eqpayload(b, NEW_STATE, b"KPX8ST01");
    eqpayload(b, NEW_STATE + 8, &DOMAIN);
    point_bytes(b);
    pl(b, 112, 36);
    op(b, OpEqualVerify);
    amount_bytes(b, OpTxInputAmount);
    pl(b, 260, 8);
    op(b, OpEqualVerify);
    range_payload(b, 260, 8, FLOOR as i64, MAX as i64);
    range_payload(b, 388, 8, 1, MAX as i64);
    range_payload(b, 396, 8, PAYOUT_FLOOR as i64, MAX as i64);
    range_payload(b, 380, 8, 0, MAX as i64);
    unum(b, 260, 8);
    unum(b, 388, 8);
    op(b, OpSub);
    unum(b, 396, 8);
    op(b, OpSub);
    unum(b, 380, 8);
    op(b, OpNumEqualVerify);
    // CM membership root and cursor never change for a full-note exit.
    st(b, 0, 76);
    pl(b, NEW_STATE, 76);
    op(b, OpEqualVerify);
    range_payload(b, 220, 4, 1, 65536);
    range_payload(b, 256, 4, 1, 131071);
    unum(b, 256, 4);
    num(b, 1);
    op(b, OpAdd);
    unum(b, 376, 4);
    op(b, OpNumEqualVerify);
    st(b, 76, 32);
    insert_nf(b, 440, 472, 0, None);
    pl(b, 344, 32);
    op(b, OpEqualVerify);
    unum(b, 380, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    range_payload(b, 380, 8, FLOOR as i64, MAX as i64);
    eqn(b, OpTxOutputCount, 2);
    indexed_amount_bytes(b, OpTxOutputAmount, 0);
    pl(b, 380, 8);
    op(b, OpEqualVerify);
    same_tail_successor(b, len);
    num(b, 1);
    eqn(b, OpOutputAuthorizingInput, -1);
    op(b, OpEndIf);
    eqpayload(b, 404, &[0, 0, OpData32]);
    eqpayload(b, 439, &[OpCheckSig]);
    exit_payout_index(b);
    op(b, OpTxOutputSpk);
    pl(b, 404, 36);
    op(b, OpEqualVerify);
    exit_payout_index(b);
    op(b, OpTxOutputSpkLen);
    num(b, 36);
    op(b, OpNumEqualVerify);
    exit_payout_index(b);
    op(b, OpTxOutputAmount);
    unum(b, 396, 8);
    op(b, OpNumEqualVerify);
    // Exact actual projection and complete public exit body are authorized.
    data(b, b"KPX8EX01");
    data(b, &DOMAIN);
    cat(b);
    st(b, 40, 32);
    cat(b);
    pl(b, 440, 32);
    cat(b);
    data(b, b"KPX8EF01");
    projection_bytes(b, EXIT_BODY_LEN);
    cat(b);
    op(b, OpSHA256);
    cat(b);
    pl(b, 396, 8);
    cat(b);
    pl(b, 388, 8);
    cat(b);
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
    data(b, exit_vk);
    data(b, &[0x20]);
    op(b, OpZkPrecompile);
}
pub fn validate_state(state: &[u8; 112]) -> Result<()> {
    if &state[..8] != b"KPX8ST01" || state[8..40] != DOMAIN {
        return Err("state_identity".into());
    }
    let n = u32::from_le_bytes(state[72..76].try_into()?);
    let m = u32::from_le_bytes(state[108..112].try_into()?);
    if !(1..=65536).contains(&n) || !(1..=131072).contains(&m) {
        return Err("state_counts".into());
    }
    Ok(())
}
pub fn redeem(
    state: &[u8; 112],
    image: &[u8; 32],
    component: &[u8; 32],
    exit_vk: &[u8; 328],
) -> Result<Vec<u8>> {
    validate_state(state)?;
    if *image == [0; 32] || *component == [0; 32] || *exit_vk == [0; 328] {
        return Err("selected_image_component_identity".into());
    }
    let mut len = 4096;
    for _ in 0..8 {
        let raw = build(state, image, component, exit_vk, len)?;
        if raw.len() == len {
            return Ok(raw);
        }
        len = raw.len();
        if !(METADATA_PREFIX..=u16::MAX as usize).contains(&len) {
            return Err("redeem_width".into());
        }
    }
    Err("redeem_selflength".into())
}
pub fn witness(proof: &[u8; 128], redeem: &[u8]) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    b.add_data(proof)?.add_data(redeem)?;
    let raw = b.drain();
    if raw.len() != REDEEM_START + redeem.len() {
        return Err("canonical_witness_frame".into());
    }
    Ok(raw)
}
