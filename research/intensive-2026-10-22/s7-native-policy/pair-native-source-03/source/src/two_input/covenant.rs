//! v6 covenant: authenticate history, insert two current NFs, conserve native value.
use super::*;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
pub const REDEEM_LEN: usize = 24576;
pub const BUDGET: u16 = 3000;
pub const WITNESS_LEN: usize = 133 + REDEEM_LEN;
const R: i64 = 133;
const S: i64 = R + 36;
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
    sig(b, S + n, S + n + 4);
    op(b, OpBin2Num);
}
fn transfer(b: &mut ScriptBuilder) {
    auth(b, A_MODE, A_MODE + 1);
    data(b, &[2]);
    op(b, OpEqual);
    op(b, OpNot);
}
fn new_cm(b: &mut ScriptBuilder) {
    count(b, 1);
    transfer(b);
    op(b, OpIf);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpEndIf);
}
fn deposit(b: &mut ScriptBuilder) {
    auth(b, A_MODE, A_MODE + 1);
    data(b, &[0]);
    op(b, OpEqual);
}
fn new_nf(b: &mut ScriptBuilder) {
    count(b, 5);
    deposit(b);
    op(b, OpNot);
    op(b, OpIf);
    num(b, 2);
    op(b, OpAdd);
    op(b, OpEndIf);
}
fn remaining(b: &mut ScriptBuilder) {
    amount(b, OpTxInputAmount, 0);
    deposit(b);
    op(b, OpIf);
    amount(b, OpTxInputAmount, 1);
    op(b, OpAdd);
    op(b, OpEndIf);
    anum(b, A_PAYOUT, A_FEE);
    op(b, OpSub);
    anum(b, A_FEE, A_SPK);
    op(b, OpSub);
}
fn terminal(b: &mut ScriptBuilder) {
    remaining(b);
    num(b, 0);
    op(b, OpNumEqual);
}
fn range(b: &mut ScriptBuilder, min: i64, max_exclusive: i64) {
    num(b, min);
    num(b, max_exclusive);
    op(b, OpWithin);
    op(b, OpVerify);
}
fn anchor_count(b: &mut ScriptBuilder) {
    anum(b, A_COUNT, A_ANCHOR);
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
    sig(b, R, R + 36);
    pay(b, P_STATE, P_WITNESS);
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
fn witness(b: &mut ScriptBuilder, start: usize, end: usize) {
    pay(b, P_WITNESS + start, P_WITNESS + end);
}
fn history_count(b: &mut ScriptBuilder) {
    count(b, 1);
    num(b, 1);
    op(b, OpAdd);
    num(b, 2);
    op(b, OpDiv);
}
fn merkle(b: &mut ScriptBuilder, path: usize, depth: usize, index: impl Fn(&mut ScriptBuilder)) {
    // Input/output is one digest. Index is range-checked by the caller.
    for level in 0..depth {
        witness(b, path + level * 32, path + (level + 1) * 32);
        index(b);
        num(b, 1 << level);
        op(b, OpDiv);
        num(b, 2);
        op(b, OpMod);
        op(b, OpIf);
        op(b, OpSwap);
        op(b, OpEndIf);
        op(b, OpCat);
        data(b, &[1]);
        op(b, OpSwap);
        op(b, OpCat);
        op(b, OpSHA256);
    }
}
fn limb(b: &mut ScriptBuilder, base: usize, start: usize, end: usize) {
    pay(b, base + start, base + end);
    data(b, &[0]);
    op(b, OpCat);
    op(b, OpBin2Num);
}
fn less256(b: &mut ScriptBuilder, a: usize, c: usize) {
    // Little-endian unsigned key. Each seven-byte limb stays below 2^56.
    // Fold from low to high: higher unequal limbs override the lower result.
    num(b, 0);
    for (lo, hi) in [(0, 7), (7, 14), (14, 21), (21, 28), (28, 32)] {
        limb(b, a, lo, hi);
        limb(b, c, lo, hi);
        op(b, OpNumEqual);
        op(b, OpIf);
        op(b, OpElse);
        op(b, OpDrop);
        limb(b, a, lo, hi);
        limb(b, c, lo, hi);
        op(b, OpLessThan);
        op(b, OpEndIf);
    }
}
fn zero(b: &mut ScriptBuilder, start: usize, end: usize) {
    pay(b, start, end);
    data(b, &vec![0; end - start]);
    op(b, OpEqualVerify);
}
fn n_index(b: &mut ScriptBuilder, slot: usize) {
    count(b, 5);
    num(b, slot as i64 + 1);
    op(b, OpAdd);
}
fn p_index(b: &mut ScriptBuilder, base: usize) {
    witness(b, base, base + 4);
    op(b, OpBin2Num);
}
pub fn redeem(domain: &H, state: &tree::State, vk: &[u8]) -> Result<Vec<u8>> {
    state.check()?;
    if vk.len() != 328 {
        return Err("VK dimensions".into());
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
        (OpTxPayloadLen, PAYLOAD_SIZE as i64),
    ] {
        eqnum(&mut b, code, n);
    }
    deposit(&mut b);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxInputCount, 2);
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
    data(
        &mut b,
        &[
            OpPushData2,
            (REDEEM_LEN & 255) as u8,
            (REDEEM_LEN >> 8) as u8,
        ],
    );
    op(&mut b, OpEqualVerify);
    pay(&mut b, 0, 8);
    data(&mut b, b"KPICR06\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 0, 8);
    data(&mut b, b"KPICU06\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 8, 40);
    sig(&mut b, R + 1, R + 33);
    op(&mut b, OpEqualVerify);
    anum(&mut b, A_MODE, A_MODE + 1);
    range(&mut b, 0, 3);
    sig(&mut b, S, S + 1);
    data(&mut b, &[6]);
    op(&mut b, OpEqualVerify);
    count(&mut b, 1);
    range(&mut b, 1, 65536);
    count(&mut b, 1);
    num(&mut b, 2);
    op(&mut b, OpMod);
    num(&mut b, 1);
    op(&mut b, OpNumEqualVerify);
    count(&mut b, 5);
    range(&mut b, 0, 131071);
    count(&mut b, 5);
    num(&mut b, 2);
    op(&mut b, OpMod);
    num(&mut b, 0);
    op(&mut b, OpNumEqualVerify);
    count(&mut b, 5);
    count(&mut b, 1);
    num(&mut b, 2);
    op(&mut b, OpMul);
    op(&mut b, OpLessThanOrEqual);
    op(&mut b, OpVerify);
    new_cm(&mut b);
    range(&mut b, 1, 65536);
    new_nf(&mut b);
    range(&mut b, 0, 131071);
    remaining(&mut b);
    range(&mut b, 0, MAX_SOMPI as i64 + 1);
    terminal(&mut b);
    op(&mut b, OpIf);
    anum(&mut b, A_MODE, A_MODE + 1);
    num(&mut b, 2);
    op(&mut b, OpNumEqualVerify);
    zero(&mut b, P_STATE, P_WITNESS);
    op(&mut b, OpEndIf);
    deposit(&mut b);
    op(&mut b, OpIf);
    count(&mut b, 5);
    range(&mut b, 2, 131071);
    zero(&mut b, P_WITNESS, P_WITNESS + W_CM_APPEND);
    sig(&mut b, S + 41, S + 73);
    pay(&mut b, P_STATE + 41, P_STATE + 73);
    op(&mut b, OpEqualVerify);
    amount(&mut b, OpTxInputAmount, 1);
    anum(&mut b, A_DEP, A_FUND);
    op(&mut b, OpNumEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpOutpointTxId);
    auth(&mut b, A_FUND, A_FUND + 32);
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpOutpointIndex);
    num(&mut b, 4);
    op(&mut b, OpNum2Bin);
    auth(&mut b, A_FUND + 32, A_FSPK);
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpTxInputSpk);
    auth(&mut b, A_FSPK, A_BOOT);
    op(&mut b, OpEqualVerify);
    auth(&mut b, A_FSPK, A_FSPK + 3);
    data(&mut b, &[0, 0, OpData32]);
    op(&mut b, OpEqualVerify);
    auth(&mut b, A_BOOT - 1, A_BOOT);
    data(&mut b, &[OpCheckSig]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpTxInputIsCoinbase);
    op(&mut b, OpNot);
    op(&mut b, OpVerify);
    num(&mut b, 1);
    op(&mut b, OpInputCovenantId);
    data(&mut b, &[0; 32]);
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    op(&mut b, OpTxInputSeq);
    data(&mut b, &u64::MAX.to_le_bytes());
    op(&mut b, OpEqualVerify);
    num(&mut b, 1);
    eqnum(&mut b, OpTxInputScriptSigLen, 66);
    for (start, end, bytes) in [(0, 1, vec![65]), (65, 66, vec![1])] {
        num(&mut b, 1);
        num(&mut b, start);
        num(&mut b, end);
        op(&mut b, OpTxInputScriptSigSubstr);
        data(&mut b, &bytes);
        op(&mut b, OpEqualVerify);
    }
    op(&mut b, OpElse);
    anchor_count(&mut b);
    num(&mut b, 1);
    count(&mut b, 1);
    num(&mut b, 1);
    op(&mut b, OpAdd);
    op(&mut b, OpWithin);
    op(&mut b, OpVerify);
    anchor_count(&mut b);
    num(&mut b, 2);
    op(&mut b, OpMod);
    num(&mut b, 1);
    op(&mut b, OpNumEqualVerify);
    data(&mut b, &[3]);
    auth(&mut b, A_COUNT, A_NF);
    op(&mut b, OpCat);
    op(&mut b, OpSHA256);
    merkle(&mut b, W_ANCHOR, 16, |b| {
        anchor_count(b);
        num(b, 1);
        op(b, OpSub);
        num(b, 2);
        op(b, OpDiv);
    });
    sig(&mut b, S + 73, S + 105);
    op(&mut b, OpEqualVerify);
    for slot in 0..2 {
        let base = W_NF + slot * NF_WIT;
        let leaf = base + 4;
        let pp = base + 72;
        let ap = base + 616;
        let nf = A_NF + slot * 32;
        p_index(&mut b, base);
        num(&mut b, 0);
        n_index(&mut b, slot);
        op(&mut b, OpWithin);
        op(&mut b, OpVerify);
        less256(&mut b, P_WITNESS + leaf, P_AUTH + nf);
        op(&mut b, OpVerify);
        witness(&mut b, leaf + 36, leaf + 68);
        data(&mut b, &[0; 32]);
        op(&mut b, OpEqual);
        op(&mut b, OpIf);
        witness(&mut b, leaf + 32, leaf + 36);
        data(&mut b, &[0; 4]);
        op(&mut b, OpEqualVerify);
        op(&mut b, OpElse);
        less256(&mut b, P_AUTH + nf, P_WITNESS + leaf + 36);
        op(&mut b, OpVerify);
        witness(&mut b, leaf + 32, leaf + 36);
        op(&mut b, OpBin2Num);
        num(&mut b, 1);
        n_index(&mut b, slot);
        op(&mut b, OpWithin);
        op(&mut b, OpVerify);
        op(&mut b, OpEndIf);
        data(&mut b, &[2]);
        witness(&mut b, leaf, leaf + 68);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
        merkle(&mut b, pp, 17, |b| p_index(b, base));
        if slot == 0 {
            sig(&mut b, S + 41, S + 73);
        } else {
            op(&mut b, OpFromAltStack);
        }
        op(&mut b, OpEqualVerify);
        data(&mut b, &[2]);
        witness(&mut b, leaf, leaf + 32);
        op(&mut b, OpCat);
        n_index(&mut b, slot);
        num(&mut b, 4);
        op(&mut b, OpNum2Bin);
        op(&mut b, OpCat);
        auth(&mut b, nf, nf + 32);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
        merkle(&mut b, pp, 17, |b| p_index(b, base));
        op(&mut b, OpToAltStack);
        data(&mut b, &[0; 32]);
        merkle(&mut b, ap, 17, |b| n_index(b, slot));
        op(&mut b, OpFromAltStack);
        op(&mut b, OpEqualVerify);
        data(&mut b, &[2]);
        auth(&mut b, nf, nf + 32);
        op(&mut b, OpCat);
        witness(&mut b, leaf + 32, leaf + 68);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
        merkle(&mut b, ap, 17, |b| n_index(b, slot));
        if slot == 0 {
            op(&mut b, OpToAltStack);
        } else {
            terminal(&mut b);
            op(&mut b, OpIf);
            op(&mut b, OpDrop);
            op(&mut b, OpElse);
            pay(&mut b, P_STATE + 41, P_STATE + 73);
            op(&mut b, OpEqualVerify);
            op(&mut b, OpEndIf);
        }
    }
    // Initial liability is exactly the actual singleton reserve; no phantom roots/NFs.
    count(&mut b, 5);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    op(&mut b, OpIf);
    count(&mut b, 1);
    num(&mut b, 1);
    op(&mut b, OpNumEqualVerify);
    sig(&mut b, S + 41, S + 73);
    data(
        &mut b,
        &tree::Tree::new(vec![crate::compact::tree::NfLeaf::default().digest()], 17)?.root(),
    );
    op(&mut b, OpEqualVerify);
    data(&mut b, &[3]);
    data(&mut b, &1u32.to_le_bytes());
    op(&mut b, OpCat);
    sig(&mut b, S + 9, S + 41);
    op(&mut b, OpCat);
    op(&mut b, OpSHA256);
    for sibling in tree::empty_path(16) {
        data(&mut b, &sibling);
        op(&mut b, OpCat);
        data(&mut b, &[1]);
        op(&mut b, OpSwap);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
    }
    sig(&mut b, S + 73, S + 105);
    op(&mut b, OpEqualVerify);
    amount(&mut b, OpTxInputAmount, 0);
    anum(&mut b, A_BOOT, A_CIPHER);
    op(&mut b, OpNumEqualVerify);
    op(&mut b, OpElse);
    zero(&mut b, P_AUTH + A_BOOT, P_AUTH + A_CIPHER);
    op(&mut b, OpEndIf);
    op(&mut b, OpEndIf);
    transfer(&mut b);
    op(&mut b, OpIf);
    for i in 0..2 {
        data(&mut b, &[0; 32]);
        merkle(&mut b, W_CM_APPEND + i * 512, 16, |b| {
            count(b, 1);
            num(b, i as i64);
            op(b, OpAdd);
        });
        if i == 0 {
            sig(&mut b, S + 9, S + 41);
        } else {
            op(&mut b, OpFromAltStack);
        }
        op(&mut b, OpEqualVerify);
        data(&mut b, &[0]);
        auth(&mut b, A_CM + i * 32, A_CM + (i + 1) * 32);
        op(&mut b, OpCat);
        op(&mut b, OpSHA256);
        merkle(&mut b, W_CM_APPEND + i * 512, 16, |b| {
            count(b, 1);
            num(b, i as i64);
            op(b, OpAdd);
        });
        if i == 0 {
            op(&mut b, OpToAltStack);
        } else {
            pay(&mut b, P_STATE + 9, P_STATE + 41);
            op(&mut b, OpEqualVerify);
        }
    }
    data(&mut b, &[0; 32]);
    merkle(&mut b, W_HISTORY_APPEND, 16, history_count);
    sig(&mut b, S + 73, S + 105);
    op(&mut b, OpEqualVerify);
    data(&mut b, &[3]);
    new_cm(&mut b);
    num(&mut b, 4);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpCat);
    pay(&mut b, P_STATE + 9, P_STATE + 41);
    op(&mut b, OpCat);
    op(&mut b, OpSHA256);
    merkle(&mut b, W_HISTORY_APPEND, 16, history_count);
    pay(&mut b, P_STATE + 73, P_STATE + 105);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpElse);
    zero(&mut b, P_CIPHER, P_STATE);
    zero(&mut b, P_WITNESS + W_CM_APPEND, PAYLOAD_SIZE);
    terminal(&mut b);
    op(&mut b, OpNot);
    op(&mut b, OpIf);
    sig(&mut b, S + 9, S + 41);
    pay(&mut b, P_STATE + 9, P_STATE + 41);
    op(&mut b, OpEqualVerify);
    sig(&mut b, S + 73, S + 105);
    pay(&mut b, P_STATE + 73, P_STATE + 105);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpEndIf);
    op(&mut b, OpEndIf);
    terminal(&mut b);
    op(&mut b, OpNot);
    op(&mut b, OpIf);
    data(&mut b, &[6]);
    new_cm(&mut b);
    num(&mut b, 4);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpCat);
    new_nf(&mut b);
    num(&mut b, 4);
    op(&mut b, OpNum2Bin);
    op(&mut b, OpCat);
    pay(&mut b, P_STATE, P_STATE + 9);
    op(&mut b, OpEqualVerify);
    successor(&mut b);
    amount(&mut b, OpTxOutputAmount, 0);
    remaining(&mut b);
    op(&mut b, OpNumEqualVerify);
    op(&mut b, OpEndIf);
    metadata(&mut b, 0);
    terminal(&mut b);
    anum(&mut b, A_PAYOUT, A_FEE);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    op(&mut b, OpBoolOr);
    op(&mut b, OpIf);
    eqnum(&mut b, OpTxOutputCount, 1);
    op(&mut b, OpElse);
    eqnum(&mut b, OpTxOutputCount, 2);
    metadata(&mut b, 1);
    op(&mut b, OpEndIf);
    anum(&mut b, A_PAYOUT, A_FEE);
    num(&mut b, 0);
    op(&mut b, OpGreaterThan);
    op(&mut b, OpIf);
    payout_index(&mut b);
    op(&mut b, OpTxOutputAmount);
    anum(&mut b, A_PAYOUT, A_FEE);
    op(&mut b, OpNumEqualVerify);
    payout_index(&mut b);
    op(&mut b, OpTxOutputSpk);
    auth(&mut b, A_SPK, A_DEP);
    op(&mut b, OpEqualVerify);
    op(&mut b, OpEndIf);
    pay(&mut b, P_CIPHER, P_STATE);
    op(&mut b, OpSHA256);
    auth(&mut b, A_CIPHER, AUTH_LEN);
    op(&mut b, OpEqualVerify);
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
        return Err(format!("redeem length {}", bytes.len()).into());
    }
    bytes.resize(REDEEM_LEN, OpNop);
    Ok(bytes)
}
pub fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || redeem.len() != REDEEM_LEN {
        return Err("proof/redeem dimensions".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, proof);
    data(&mut b, redeem);
    Ok(b.drain())
}
