//! Native introspection binds the complete transition; no digest is trusted
//! from the witness. Immutable rules and VK propagate from the executed script.
use crate::{Result, protocol::*};
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
pub const REDEEM_LEN: usize = 4096;
pub const BUDGET: u16 = 1600;
pub const WITNESS_LEN: usize = 2 + 128 + 3 + REDEEM_LEN;
const REDEEM_START: i64 = 133;
const PREFIX_LEN: i64 = (STATE_LEN + 38) as i64;
fn op(b: &mut ScriptBuilder, x: u8) {
    b.add_op(x).unwrap();
}
fn num(b: &mut ScriptBuilder, x: i64) {
    b.add_i64(x).unwrap();
}
fn data(b: &mut ScriptBuilder, x: &[u8]) {
    b.add_data(x).unwrap();
}
fn eqnum(b: &mut ScriptBuilder, x: u8, n: i64) {
    op(b, x);
    num(b, n);
    op(b, OpNumEqualVerify);
}
fn sig(b: &mut ScriptBuilder, start: i64, end: i64) {
    num(b, 0);
    num(b, start);
    num(b, end);
    op(b, OpTxInputScriptSigSubstr);
}
fn payload(b: &mut ScriptBuilder, start: i64, end: i64) {
    num(b, start);
    num(b, end);
    op(b, OpTxPayloadSubstr);
}
fn mode_is(b: &mut ScriptBuilder, n: u8) {
    payload(b, 8, 9);
    data(b, &[n]);
    op(b, OpEqual);
}
fn output_metadata(b: &mut ScriptBuilder, i: i64) {
    num(b, i);
    eqnum(b, OpOutputAuthorizingInput, -1);
}
fn successor(b: &mut ScriptBuilder) {
    // Actual redeem prefix through the state push header, new state, DROP,
    // actual immutable suffix. Constants below follow the canonical witness.
    sig(b, REDEEM_START, REDEEM_START + 37);
    payload(b, 9, CIPHER_START as i64);
    op(b, OpCat);
    data(b, &[OpDrop]);
    op(b, OpCat);
    sig(b, REDEEM_START + PREFIX_LEN, WITNESS_LEN as i64);
    op(b, OpCat);
    op(b, OpBlake2b);
    data(b, &[0, 0, OpBlake2b, OpData32]);
    op(b, OpSwap);
    op(b, OpCat);
    data(b, &[OpEqual]);
    op(b, OpCat);
    num(b, 0);
    op(b, OpTxOutputSpk);
    op(b, OpEqualVerify);
}
fn payout_index(b: &mut ScriptBuilder) {
    mode_is(b, 3);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf);
}
fn amount_bytes(b: &mut ScriptBuilder, code: u8) {
    op(b, code);
    num(b, 8);
    op(b, OpNum2Bin);
}
pub fn redeem(domain: &H, state: &State, vk: &[u8]) -> Result<Vec<u8>> {
    state.check()?;
    if vk.len() != 328 {
        return Err("expected two-public-input compressed Groth16 VK".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, domain);
    op(&mut b, OpDrop);
    data(&mut b, &state.bytes());
    op(&mut b, OpDrop);
    eqnum(&mut b, OpDepth, 1);
    eqnum(&mut b, OpSize, 128);
    op(&mut b, OpToAltStack);
    for (code, n) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
        (OpTxPayloadLen, PAYLOAD_LEN as i64),
    ] {
        eqnum(&mut b, code, n);
    }
    mode_is(&mut b, 0);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxInputCount, 2);
    num(&mut b, 1);
    op(&mut b, OpTxInputSeq);
    data(&mut b, &u64::MAX.to_le_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpElse);
    eqnum(&mut b, OpTxInputCount, 1);
    op(&mut b, OpEndIf);
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
    eqnum(&mut b, OpTxInputScriptSigLen, WITNESS_LEN as i64);
    sig(&mut b, 0, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    sig(&mut b, 130, 133);
    data(&mut b, &[OpPushData2, 0, 16]);
    op(&mut b, OpEqualVerify);
    payload(&mut b, 0, 8);
    data(&mut b, b"KPISP03\0");
    op(&mut b, OpEqualVerify);
    output_metadata(&mut b, 0);
    mode_is(&mut b, 0);
    mode_is(&mut b, 1);
    op(&mut b, OpBoolOr);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxOutputCount, 1);
    successor(&mut b);
    op(&mut b, OpElse);
    mode_is(&mut b, 3);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxOutputCount, 1);
    op(&mut b, OpElse);
    mode_is(&mut b, 2);
    mode_is(&mut b, 4);
    op(&mut b, OpBoolOr);
    op(&mut b, OpVerify);
    eqnum(&mut b, OpTxOutputCount, 2);
    output_metadata(&mut b, 1);
    successor(&mut b);
    op(&mut b, OpEndIf);
    op(&mut b, OpEndIf);
    // The complete 431-byte transition preimage, reconstructed on the stack.
    data(&mut b, b"KPIBN03\0");
    sig(&mut b, REDEEM_START + 1, REDEEM_START + 33);
    op(&mut b, OpCat);
    sig(
        &mut b,
        REDEEM_START + 37,
        REDEEM_START + 37 + STATE_LEN as i64,
    );
    op(&mut b, OpCat);
    num(&mut b, 0);
    op(&mut b, OpOutpointTxId);
    op(&mut b, OpCat);
    num(&mut b, 0);
    amount_bytes(&mut b, OpOutpointIndex);
    op(&mut b, OpCat);
    num(&mut b, 0);
    amount_bytes(&mut b, OpTxInputAmount);
    op(&mut b, OpCat);
    mode_is(&mut b, 3);
    op(&mut b, OpIf);
    data(&mut b, &[0; 8]);
    op(&mut b, OpElse);
    num(&mut b, 0);
    amount_bytes(&mut b, OpTxOutputAmount);
    op(&mut b, OpEndIf);
    op(&mut b, OpCat);
    mode_is(&mut b, 0);
    mode_is(&mut b, 1);
    op(&mut b, OpBoolOr);
    op(&mut b, OpIf);
    data(&mut b, &[0; 8]);
    op(&mut b, OpElse);
    payout_index(&mut b);
    amount_bytes(&mut b, OpTxOutputAmount);
    op(&mut b, OpEndIf);
    op(&mut b, OpCat);
    mode_is(&mut b, 0);
    mode_is(&mut b, 1);
    op(&mut b, OpBoolOr);
    op(&mut b, OpIf);
    data(&mut b, &[0; 36]);
    op(&mut b, OpElse);
    payout_index(&mut b);
    op(&mut b, OpTxOutputSpk);
    eqnum(&mut b, OpSize, 36);
    op(&mut b, OpEndIf);
    op(&mut b, OpCat);
    mode_is(&mut b, 0);
    op(&mut b, OpIf);
    num(&mut b, 1);
    op(&mut b, OpOutpointTxId);
    num(&mut b, 1);
    amount_bytes(&mut b, OpOutpointIndex);
    op(&mut b, OpCat);
    num(&mut b, 1);
    amount_bytes(&mut b, OpTxInputAmount);
    op(&mut b, OpCat);
    num(&mut b, 1);
    op(&mut b, OpTxInputSpk);
    eqnum(&mut b, OpSize, 36);
    op(&mut b, OpCat);
    op(&mut b, OpElse);
    data(&mut b, &[0; 84]);
    op(&mut b, OpEndIf);
    op(&mut b, OpCat);
    payload(&mut b, 0, PAYLOAD_LEN as i64);
    op(&mut b, OpSHA256);
    op(&mut b, OpCat);
    eqnum(&mut b, OpSize, TRANSCRIPT_LEN as i64);
    op(&mut b, OpSHA256);
    // Verifier pops public inputs in order: push second limb before first.
    op(&mut b, OpDup);
    num(&mut b, 16);
    num(&mut b, 32);
    op(&mut b, OpSubstr);
    data(&mut b, &[0; 16]);
    op(&mut b, OpCat);
    op(&mut b, OpSwap);
    num(&mut b, 0);
    num(&mut b, 16);
    op(&mut b, OpSubstr);
    data(&mut b, &[0; 16]);
    op(&mut b, OpCat);
    num(&mut b, 2);
    op(&mut b, OpFromAltStack);
    data(&mut b, vk);
    data(&mut b, &[0x20]);
    op(&mut b, OpZkPrecompile);
    let mut bytes = b.drain();
    if bytes.len() > REDEEM_LEN {
        return Err(format!(
            "correct redeem needs {} bytes, target {}",
            bytes.len(),
            REDEEM_LEN
        )
        .into());
    }
    bytes.resize(REDEEM_LEN, OpNop);
    Ok(bytes)
}
pub fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || redeem.len() != REDEEM_LEN {
        return Err("witness dimensions".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, proof);
    data(&mut b, redeem);
    let bytes = b.drain();
    if bytes.len() != WITNESS_LEN {
        return Err("canonical witness framing".into());
    }
    Ok(bytes)
}
