//! Current-state settlement using native introspection. No host-supplied digest,
//! retained-state assertion, operator signature or second proof is trusted.
use super::*;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
pub const REDEEM_LEN: usize = 8192;
pub const BUDGET: u16 = 2000;
pub const WITNESS_LEN: usize = 133 + REDEEM_LEN;
const R: i64 = 133;
const S: i64 = R + 37;
const SUFFIX: i64 = S + STATE_LEN as i64 + 1;
fn op(b: &mut ScriptBuilder, x: u8) {
    b.add_op(x).unwrap();
}
fn num(b: &mut ScriptBuilder, x: i64) {
    b.add_i64(x).unwrap();
}
fn data(b: &mut ScriptBuilder, x: &[u8]) {
    b.add_data(x).unwrap();
}
fn eqnum(b: &mut ScriptBuilder, code: u8, n: i64) {
    op(b, code);
    num(b, n);
    op(b, OpNumEqualVerify);
}
fn sig(b: &mut ScriptBuilder, start: i64, end: i64) {
    num(b, 0);
    num(b, start);
    num(b, end);
    op(b, OpTxInputScriptSigSubstr);
}
fn pay(b: &mut ScriptBuilder, start: usize, end: usize) {
    num(b, start as i64);
    num(b, end as i64);
    op(b, OpTxPayloadSubstr);
}
fn auth(b: &mut ScriptBuilder, start: usize, end: usize) {
    pay(b, P_AUTH + start, P_AUTH + end);
}
fn anum(b: &mut ScriptBuilder, start: usize, end: usize) {
    auth(b, start, end);
    op(b, OpBin2Num);
}
fn count(b: &mut ScriptBuilder, n: i64) {
    sig(b, S + n, S + n + 1);
    op(b, OpBin2Num);
}
fn transfer(b: &mut ScriptBuilder) {
    auth(b, A_MODE, A_MODE + 1);
    data(b, &[1]);
    op(b, OpEqual);
}
fn new_cm(b: &mut ScriptBuilder) {
    count(b, 1);
    transfer(b);
    op(b, OpIf);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpEndIf);
}
fn new_nf(b: &mut ScriptBuilder) {
    count(b, 2);
    num(b, 1);
    op(b, OpAdd);
}
fn terminal(b: &mut ScriptBuilder) {
    new_cm(b);
    new_nf(b);
    op(b, OpNumEqual);
}
fn range(b: &mut ScriptBuilder, min: i64, max_exclusive: i64) {
    num(b, min);
    num(b, max_exclusive);
    op(b, OpWithin);
    op(b, OpVerify);
}
fn active(b: &mut ScriptBuilder, base: i64, which: i64) {
    num(b, 0);
    num(b, S + base);
    count(b, which);
    num(b, 32);
    op(b, OpMul);
    num(b, S + base);
    op(b, OpAdd);
    op(b, OpTxInputScriptSigSubstr);
}
fn zeros_after(b: &mut ScriptBuilder, used: fn(&mut ScriptBuilder)) {
    data(b, &[0; 32 * CAP]);
    num(b, 0);
    num(b, CAP as i64);
    used(b);
    op(b, OpSub);
    num(b, 32);
    op(b, OpMul);
    op(b, OpSubstr);
}
fn anchor_count(b: &mut ScriptBuilder) {
    anum(b, A_COUNT, A_COUNT + 1);
}
fn amount(b: &mut ScriptBuilder, code: u8, index: i64) {
    num(b, index);
    op(b, code);
}
fn payout_index(b: &mut ScriptBuilder) {
    terminal(b);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf);
}
fn metadata(b: &mut ScriptBuilder, index: i64) {
    num(b, index);
    eqnum(b, OpOutputAuthorizingInput, -1);
}
fn successor(b: &mut ScriptBuilder) {
    sig(b, R, R + 37);
    pay(b, P_STATE, PAYLOAD_SIZE);
    op(b, OpCat);
    data(b, &[OpDrop]);
    op(b, OpCat);
    sig(b, SUFFIX, WITNESS_LEN as i64);
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
pub fn redeem(domain: &H, state: &State, vk: &[u8]) -> Result<Vec<u8>> {
    state.check()?;
    if vk.len() != 328 {
        return Err("two-input Groth16 VK dimensions".into());
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
        (OpTxInputCount, 1),
        (OpTxPayloadLen, PAYLOAD_SIZE as i64),
    ] {
        eqnum(&mut b, code, n);
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
    eqnum(&mut b, OpTxInputScriptSigLen, WITNESS_LEN as i64);
    sig(&mut b, 0, 2);
    data(&mut b, &[OpPushData1, 128]);
    op(&mut b, OpEqualVerify);
    sig(&mut b, 130, 133);
    data(&mut b, &[OpPushData2, 0, 32]);
    op(&mut b, OpEqualVerify);
    pay(&mut b, 0, 8);
    data(&mut b, b"KPIAR01\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 0, 8);
    data(&mut b, b"KPIAU01\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 8, 40);
    sig(&mut b, R + 1, R + 33);
    op(&mut b, OpEqualVerify);
    anum(&mut b, A_MODE, A_MODE + 1);
    range(&mut b, 1, 3);
    sig(&mut b, S, S + 1);
    data(&mut b, &[3]);
    op(&mut b, OpEqualVerify);
    count(&mut b, 1);
    range(&mut b, 1, CAP as i64 + 1);
    count(&mut b, 2);
    num(&mut b, 0);
    count(&mut b, 1);
    op(&mut b, OpWithin);
    op(&mut b, OpVerify);
    new_cm(&mut b);
    range(&mut b, 1, CAP as i64 + 1);
    new_nf(&mut b);
    range(&mut b, 1, CAP as i64 + 1);

    // Authenticate a padded historical commitment prefix against this UTXO.
    anchor_count(&mut b);
    num(&mut b, 1);
    count(&mut b, 1);
    num(&mut b, 1);
    op(&mut b, OpAdd);
    op(&mut b, OpWithin);
    op(&mut b, OpVerify);
    auth(&mut b, A_COUNT, A_COUNT + 1);
    num(&mut b, 0);
    num(&mut b, S + 3);
    anchor_count(&mut b);
    num(&mut b, 32);
    op(&mut b, OpMul);
    num(&mut b, S + 3);
    op(&mut b, OpAdd);
    op(&mut b, OpTxInputScriptSigSubstr);
    op(&mut b, OpCat);
    zeros_after(&mut b, anchor_count);
    op(&mut b, OpCat);
    op(&mut b, OpSHA256);
    auth(&mut b, A_ANCHOR, A_NF);
    op(&mut b, OpEqualVerify);

    // Check CURRENT spentness, including updates after authorization creation.
    for i in 0..CAP {
        auth(&mut b, A_NF, A_CM);
        sig(
            &mut b,
            S + (NF_START + 32 * i) as i64,
            S + (NF_START + 32 * (i + 1)) as i64,
        );
        op(&mut b, OpEqual);
        op(&mut b, OpNot);
        op(&mut b, OpVerify);
    }
    transfer(&mut b);
    op(&mut b, OpIf);
    for i in 0..CAP {
        for j in 0..2 {
            auth(&mut b, A_CM + 32 * j, A_CM + 32 * (j + 1));
            sig(&mut b, S + 3 + 32 * i as i64, S + 35 + 32 * i as i64);
            op(&mut b, OpEqual);
            op(&mut b, OpNot);
            op(&mut b, OpVerify);
        }
    }
    op(&mut b, OpElse);
    pay(&mut b, P_CIPHER, P_STATE);
    data(&mut b, &[0; 370]);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpEndIf);

    // Construct the exact next state, retaining ALL preceding entries.
    data(&mut b, &[3]);
    new_cm(&mut b);
    num(&mut b, 1);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpCat);
    new_nf(&mut b);
    num(&mut b, 1);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpCat);
    active(&mut b, 3, 1);
    op(&mut b, OpCat);
    transfer(&mut b);
    op(&mut b, OpIf);
    auth(&mut b, A_CM, A_MODE);
    op(&mut b, OpCat);
    op(&mut b, OpEndIf);
    zeros_after(&mut b, new_cm);
    op(&mut b, OpCat);
    active(&mut b, NF_START as i64, 2);
    op(&mut b, OpCat);
    auth(&mut b, A_NF, A_CM);
    op(&mut b, OpCat);
    zeros_after(&mut b, new_nf);
    op(&mut b, OpCat);
    pay(&mut b, P_STATE, PAYLOAD_SIZE);
    op(&mut b, OpEqualVerify);

    // Bootstrap proves exact initial backing; cannot be replayed afterwards.
    count(&mut b, 2);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    op(&mut b, OpIf);
    count(&mut b, 1);
    num(&mut b, 1);
    op(&mut b, OpNumEqualVerify);
    transfer(&mut b);
    op(&mut b, OpVerify);
    auth(&mut b, A_BOOT, A_CIPHER);
    amount(&mut b, OpTxInputAmount, 0);
    num(&mut b, 8);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpElse);
    auth(&mut b, A_BOOT, A_CIPHER);
    data(&mut b, &[0; 8]);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpEndIf);

    metadata(&mut b, 0);
    transfer(&mut b);
    terminal(&mut b);
    op(&mut b, OpBoolOr);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxOutputCount, 1);
    op(&mut b, OpElse);
    eqnum(&mut b, OpTxOutputCount, 2);
    metadata(&mut b, 1);
    op(&mut b, OpEndIf);
    terminal(&mut b);
    op(&mut b, OpIf);
    num(&mut b, 0);
    op(&mut b, OpElse);
    successor(&mut b);
    amount(&mut b, OpTxOutputAmount, 0);
    op(&mut b, OpDup);
    range(&mut b, NOTE_FLOOR as i64, MAX_SOMPI as i64 + 1);
    op(&mut b, OpEndIf);
    // Stack: current successor value (zero only if terminal).
    anum(&mut b, A_PAYOUT, A_FEE);
    op(&mut b, OpAdd);
    anum(&mut b, A_FEE, A_SPK);
    op(&mut b, OpDup);
    range(&mut b, 1, MAX_SOMPI as i64 + 1);
    op(&mut b, OpAdd);
    amount(&mut b, OpTxInputAmount, 0);
    op(&mut b, OpNumEqualVerify);
    transfer(&mut b);
    op(&mut b, OpNot);
    op(&mut b, OpIf);
    payout_index(&mut b);
    op(&mut b, OpTxOutputAmount);
    anum(&mut b, A_PAYOUT, A_FEE);
    op(&mut b, OpNumEqualVerify);
    payout_index(&mut b);
    op(&mut b, OpTxOutputSpk);
    auth(&mut b, A_SPK, A_BOOT);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpEndIf);
    pay(&mut b, P_CIPHER, P_STATE);
    op(&mut b, OpSHA256);
    auth(&mut b, A_CIPHER, AUTH_LEN);
    op(&mut b, OpEqualVerify);

    // Compute public inputs from the actual fixed authorization, never a digest
    // supplied independently by the transaction builder.
    pay(&mut b, P_AUTH, P_CIPHER);
    op(&mut b, OpSHA256);
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
        return Err(format!("anchored redeem needs {} bytes", bytes.len()).into());
    }
    bytes.resize(REDEEM_LEN, OpNop);
    Ok(bytes)
}
pub fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || redeem.len() != REDEEM_LEN {
        return Err("anchored witness dimensions".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, proof);
    data(&mut b, redeem);
    Ok(b.drain())
}
