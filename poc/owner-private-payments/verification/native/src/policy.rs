//! New ADR0063 P0 covenant. Existing funded templates are never imported.
//! Introspection helpers adapt the repository's public W policy; the R0
//! receipt fragment is the pinned upstream SDK implementation, not an oracle.
use crate::r0_fragment::append_r0_groth16_verifier;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const DOMAIN: [u8; 32] = [
    0x32, 0xb4, 0xf3, 0x1a, 0x58, 0xcc, 0x52, 0xd2, 0x28, 0x62, 0xc2, 0x0a, 0x92, 0x3c, 0x59, 0xcd,
    0xd0, 0x12, 0x77, 0x85, 0xe9, 0x99, 0x8f, 0x63, 0x2e, 0xae, 0x2b, 0x3b, 0xb3, 0x19, 0x91, 0x9d,
];
pub const BODY_LEN: usize = 10780;
pub const PREFIX_LEN: usize = 193;
pub const PROJECTION_LEN: usize = BODY_LEN + PREFIX_LEN;
pub const REDEEM_START: usize = 133;
pub const METADATA_PREFIX: usize = 227;
pub const PROFILE_AT: usize = 150;
pub const IMAGE_AT: usize = 184;
pub const MARKER_AT: usize = 218;
pub const MARKER: &[u8; 8] = b"KPX7WN01";
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
/// Hash the exact actual native FX193 prefix followed by the full body.
fn projection_hash(b: &mut ScriptBuilder) {
    data(b, b"KPX7FX01\x01\0\x01\0");
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
    data(b, &1u16.to_le_bytes());
    cat(b);
    amount_bytes(b, OpTxOutputAmount);
    cat(b);
    data(b, &37u16.to_le_bytes());
    cat(b);
    num(b, 0);
    op(b, OpTxOutputSpk);
    cat(b);
    data(b, &[0]);
    cat(b);
    data(b, &[0; 8]);
    cat(b);
    op(b, OpTxSubnetId);
    cat(b);
    data(b, &[0; 8]);
    cat(b);
    data(b, &(BODY_LEN as u32).to_le_bytes());
    cat(b);
    pl(b, 0, BODY_LEN);
    cat(b);
    op(b, OpSHA256);
}
fn journal_hash(b: &mut ScriptBuilder, component: &[u8; 32]) {
    data(b, b"KPX7JR01");
    data(b, &DOMAIN);
    cat(b);
    data(b, component);
    cat(b);
    projection_hash(b);
    cat(b);
    op(b, OpSHA256);
}
fn build(state: &[u8; 112], image: &[u8; 32], component: &[u8; 32], len: usize) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    data(&mut b, state);
    op(&mut b, OpDrop);
    data(&mut b, &DOMAIN);
    op(&mut b, OpDrop);
    data(&mut b, component);
    op(&mut b, OpDrop);
    data(&mut b, image);
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
        (OpTxOutputCount, 1),
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
    eqn(&mut b, OpTxOutputSpkLen, 37);
    num(&mut b, 0);
    eqn(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    ss(&mut b, 0, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    ss(&mut b, 130, 3);
    data(&mut b, &[OpPushData2, (len & 255) as u8, (len >> 8) as u8]);
    op(&mut b, OpEqualVerify);
    st(&mut b, 0, 8);
    data(&mut b, b"KPX7ST01");
    op(&mut b, OpEqualVerify);
    st(&mut b, 8, 32);
    data(&mut b, &DOMAIN);
    op(&mut b, OpEqualVerify);
    eqn(&mut b, OpTxPayloadLen, BODY_LEN as i64);
    eqpayload(&mut b, 0, b"KPX7PB01\x01\0\x03\0\x06\0\0\0");
    eqpayload(&mut b, 16, &DOMAIN);
    eqpayload(&mut b, NEW_STATE, b"KPX7ST01");
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
    Ok(b.drain())
}

pub fn validate_state(state: &[u8; 112]) -> Result<()> {
    if &state[..8] != b"KPX7ST01" || state[8..40] != DOMAIN {
        return Err("state_identity".into());
    }
    let n = u32::from_le_bytes(state[72..76].try_into()?);
    let m = u32::from_le_bytes(state[108..112].try_into()?);
    if !(1..=65536).contains(&n) || !(1..=131072).contains(&m) {
        return Err("state_counts".into());
    }
    Ok(())
}
pub fn redeem(state: &[u8; 112], image: &[u8; 32], component: &[u8; 32]) -> Result<Vec<u8>> {
    validate_state(state)?;
    if *image == [0; 32] || *component == [0; 32] {
        return Err("selected_image_component_identity".into());
    }
    let mut len = 4096;
    for _ in 0..8 {
        let raw = build(state, image, component, len)?;
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
