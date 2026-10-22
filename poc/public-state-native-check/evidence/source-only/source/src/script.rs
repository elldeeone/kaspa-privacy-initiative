//! One-shot synthetic P2SH diagnostic. It is deliberately not a continuing pool.
use crate::{receipt::Constants, Result, MAX_SOMPI, POOL_ID};
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};

pub const PREFIX: usize = 142;
pub const STATE_START: usize = 36;
pub const REDEEM_START: usize = 133;
pub const PAYLOAD_LEN: usize = 1203;
pub const P_START: usize = 10;
pub const P_END: usize = 1098;
pub const NEXT_START: usize = 1098;
pub const BUDGET: u16 = 1600;
pub struct Policy {
    pub image: [u8; 32],
    pub designated_prior: TransactionOutpoint,
}
fn op(b: &mut ScriptBuilder, x: u8) {
    b.add_op(x).unwrap();
}
fn num(b: &mut ScriptBuilder, x: i64) {
    b.add_i64(x).unwrap();
}
fn data(b: &mut ScriptBuilder, x: &[u8]) {
    b.add_data(x).unwrap();
}
fn eqnum(b: &mut ScriptBuilder, code: u8, value: i64) {
    op(b, code);
    num(b, value);
    op(b, OpNumEqualVerify);
}
fn sig(b: &mut ScriptBuilder, start: usize, end: usize) {
    num(b, 0);
    num(b, start as i64);
    num(b, end as i64);
    op(b, OpTxInputScriptSigSubstr);
}
fn payload(b: &mut ScriptBuilder, start: usize, end: usize) {
    num(b, start as i64);
    num(b, end as i64);
    op(b, OpTxPayloadSubstr);
}
fn amount(b: &mut ScriptBuilder, code: u8) {
    num(b, 0);
    op(b, code);
}
fn bounded_amount(b: &mut ScriptBuilder, code: u8) {
    amount(b, code);
    op(b, OpDup);
    num(b, 0);
    op(b, OpGreaterThan);
    op(b, OpVerify);
    op(b, OpDup);
    num(b, MAX_SOMPI as i64);
    op(b, OpLessThanOrEqual);
    op(b, OpVerify);
}
fn fixed_amount_bytes(b: &mut ScriptBuilder, code: u8) {
    amount(b, code);
    num(b, 8);
    op(b, OpNum2Bin);
}

fn successor(b: &mut ScriptBuilder, len: usize) {
    sig(b, REDEEM_START, REDEEM_START + STATE_START);
    payload(b, NEXT_START, PAYLOAD_LEN);
    op(b, OpCat);
    data(b, &[OpDrop]);
    op(b, OpCat);
    sig(b, REDEEM_START + PREFIX, REDEEM_START + len);
    op(b, OpCat);
    op(b, OpBlake2b);
    // SPK introspection uses version u16 BIG-ENDIAN followed by script bytes.
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    op(b, OpCat);
    data(b, &[OpEqual]);
    op(b, OpCat);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify);
}
fn journal_hash(b: &mut ScriptBuilder) {
    data(b, b"KPI2V6S1\x01\x00");
    payload(b, P_START, P_END);
    op(b, OpSHA256);
    op(b, OpCat);
    data(b, &POOL_ID);
    op(b, OpCat);
    num(b, 0);
    op(b, OpOutpointTxId);
    op(b, OpCat);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
    // Four-byte NUM2BIN would reject valid high-bit u32 indices as ScriptNums.
    num(b, 0);
    num(b, 4);
    op(b, OpSubstr);
    op(b, OpCat);
    sig(
        b,
        REDEEM_START + STATE_START,
        REDEEM_START + STATE_START + 105,
    );
    op(b, OpCat);
    payload(b, NEXT_START, PAYLOAD_LEN);
    op(b, OpCat);
    fixed_amount_bytes(b, OpTxInputAmount);
    op(b, OpCat);
    fixed_amount_bytes(b, OpTxOutputAmount);
    op(b, OpCat);
    op(b, OpSHA256);
}

// Adapted field-for-field from vProgs f9b84a8 covenant::compute_receipt_claim,
// verify_risc0_groth16 and split_at_mid. No replacement claim arithmetic.
fn claim(b: &mut ScriptBuilder, c: &Constants) {
    op(b, OpToAltStack);
    data(b, &c.output_tag);
    op(b, OpSwap);
    op(b, OpCat);
    data(b, &[0; 32]);
    op(b, OpCat);
    data(b, &2u16.to_le_bytes());
    op(b, OpCat);
    op(b, OpSHA256);
    data(b, &c.claim_tag);
    data(b, &[0; 32]);
    op(b, OpCat);
    op(b, OpFromAltStack);
    op(b, OpCat);
    data(b, &c.post);
    op(b, OpCat);
    op(b, OpSwap);
    op(b, OpCat);
    data(b, &[0, 0, 0, 0, 0, 0, 0, 0, 4, 0]);
    op(b, OpCat);
    op(b, OpSHA256);
}
fn split(b: &mut ScriptBuilder) {
    op(b, OpSize);
    num(b, 2);
    op(b, OpDiv);
    op(b, Op2Dup);
    num(b, 0);
    op(b, OpSwap);
    op(b, OpSubstr);
    op(b, OpRot);
    op(b, OpRot);
    op(b, OpDup);
    num(b, 2);
    op(b, OpMul);
    op(b, OpSubstr);
}
fn verify(b: &mut ScriptBuilder, p: &Policy, c: &Constants) {
    // [...,proof,Jhash] -> official successful assumption-free claim -> five inputs.
    data(b, &p.image);
    op(b, OpRot);
    op(b, OpToAltStack);
    claim(b, c);
    op(b, OpToAltStack);
    data(b, &c.id);
    op(b, OpFromAltStack);
    split(b);
    data(b, &[0; 16]);
    op(b, OpCat);
    op(b, OpSwap);
    data(b, &[0; 16]);
    op(b, OpCat);
    data(b, &c.root[1]);
    data(b, &c.root[0]);
    num(b, 5);
    op(b, OpFromAltStack);
    data(b, &c.vk);
    data(b, &[0x20]);
    op(b, OpZkPrecompile);
    op(b, OpVerify);
}
fn build(p: &Policy, state: &[u8; 105], c: &Constants, len: usize) -> Vec<u8> {
    let mut b = ScriptBuilder::new();
    data(&mut b, &POOL_ID);
    op(&mut b, OpDrop);
    data(&mut b, state);
    op(&mut b, OpDrop);
    assert_eq!(b.script().len(), PREFIX);
    eqnum(&mut b, OpDepth, 1);
    eqnum(&mut b, OpSize, 128);
    op(&mut b, OpToAltStack);
    for (code, value) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxInputCount, 1),
        (OpTxOutputCount, 1),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
        (OpTxPayloadLen, PAYLOAD_LEN as i64),
    ] {
        eqnum(&mut b, code, value);
    }
    op(&mut b, OpTxSubnetId);
    data(&mut b, &[0; 20]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    op(&mut b, OpTxInputSeq);
    data(&mut b, &u64::MAX.to_le_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqnum(&mut b, OpTxInputIsCoinbase, 0);
    num(&mut b, 0);
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqnum(&mut b, OpOutputAuthorizingInput, -1);
    num(&mut b, 0);
    op(&mut b, OpOutpointTxId);
    data(&mut b, &p.designated_prior.transaction_id.as_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 0);
    eqnum(&mut b, OpOutpointIndex, p.designated_prior.index as i64);
    num(&mut b, 0);
    eqnum(&mut b, OpTxInputScriptSigLen, (REDEEM_START + len) as i64);
    sig(&mut b, 0, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    let l = (len as u16).to_le_bytes();
    sig(&mut b, 130, 133);
    data(&mut b, &[OpPushData2, l[0], l[1]]);
    op(&mut b, OpEqualVerify);
    payload(&mut b, 0, 10);
    data(&mut b, b"KPI2V6T1\x01\x00");
    op(&mut b, OpEqualVerify);
    sig(
        &mut b,
        REDEEM_START + STATE_START,
        REDEEM_START + STATE_START + 1,
    );
    data(&mut b, &[7]);
    op(&mut b, OpEqualVerify);
    payload(&mut b, NEXT_START, NEXT_START + 1);
    data(&mut b, &[7]);
    op(&mut b, OpEqualVerify);
    successor(&mut b, len);
    // P.F is u128; independently prohibit truncation/sign/negative-zero aliases.
    payload(&mut b, 94, 102);
    data(&mut b, &[0; 8]);
    op(&mut b, OpEqualVerify);
    bounded_amount(&mut b, OpTxInputAmount);
    bounded_amount(&mut b, OpTxOutputAmount);
    op(&mut b, OpSub);
    payload(&mut b, 86, 94);
    op(&mut b, OpDup);
    op(&mut b, OpBin2Num);
    op(&mut b, OpDup);
    num(&mut b, 0);
    op(&mut b, OpGreaterThan);
    op(&mut b, OpVerify);
    op(&mut b, OpDup);
    num(&mut b, MAX_SOMPI as i64);
    op(&mut b, OpLessThanOrEqual);
    op(&mut b, OpVerify);
    op(&mut b, OpDup);
    num(&mut b, 8);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpRot);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpNumEqualVerify);
    journal_hash(&mut b);
    op(&mut b, OpFromAltStack);
    op(&mut b, OpSwap);
    verify(&mut b, p, c);
    op(&mut b, OpTrue);
    b.drain()
}
pub fn redeem(p: &Policy, state: &[u8; 105], c: &Constants) -> Result<Vec<u8>> {
    if state[0] != 7 {
        return Err("state version must be7".into());
    }
    // Resolve only the canonical witness's length constants. No padding or
    // receipt tuning: the second build must have exactly the derived length.
    let size = build(p, state, c, 2048).len();
    if !(256..=u16::MAX as usize).contains(&size) {
        return Err("redeem length framing".into());
    }
    let code = build(p, state, c, size);
    if code.len() != size {
        return Err("redeem length encoding did not converge".into());
    }
    Ok(code)
}
