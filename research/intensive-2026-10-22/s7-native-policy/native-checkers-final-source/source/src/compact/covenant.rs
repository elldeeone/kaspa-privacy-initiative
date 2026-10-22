//! Current-state settlement using native introspection. No host-supplied digest,
//! retained-state assertion, operator signature or second proof is trusted.
use super::*;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
pub const REDEEM_LEN: usize = 12288;
pub const BUDGET: u16 = 2000;
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
    count(b, 5);
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
fn witness(b:&mut ScriptBuilder,start:usize,end:usize){pay(b,P_WITNESS+start,P_WITNESS+end);}
fn pred_index(b:&mut ScriptBuilder){witness(b,W_PRED_INDEX,W_PRED_INDEX+4);op(b,OpBin2Num);}
fn history_count(b:&mut ScriptBuilder){count(b,1);num(b,1);op(b,OpAdd);num(b,2);op(b,OpDiv);}
fn merkle(b:&mut ScriptBuilder,path:usize,index:impl Fn(&mut ScriptBuilder)){
    // Input/output is one digest. Index is range-checked by the caller.
    for level in 0..tree::DEPTH {
        witness(b,path+level*32,path+(level+1)*32);
        index(b);num(b,1<<level);op(b,OpDiv);num(b,2);op(b,OpMod);
        op(b,OpIf);op(b,OpSwap);op(b,OpEndIf);
        op(b,OpCat);data(b,&[1]);op(b,OpSwap);op(b,OpCat);op(b,OpSHA256);
    }
}
fn limb(b:&mut ScriptBuilder,base:usize,start:usize,end:usize){
    pay(b,base+start,base+end);data(b,&[0]);op(b,OpCat);op(b,OpBin2Num);
}
fn less256(b:&mut ScriptBuilder,a:usize,c:usize){
    // Little-endian unsigned key. Each seven-byte limb stays below 2^56.
    // Fold from low to high: higher unequal limbs override the lower result.
    num(b,0);
    for (lo,hi) in [(0,7),(7,14),(14,21),(21,28),(28,32)] {
        limb(b,a,lo,hi);limb(b,c,lo,hi);op(b,OpNumEqual);
        op(b,OpIf);op(b,OpElse);op(b,OpDrop);
        limb(b,a,lo,hi);limb(b,c,lo,hi);op(b,OpLessThan);op(b,OpEndIf);
    }
}
#[cfg(test)]
pub(super) fn comparison_script()->Vec<u8>{
    let mut b=ScriptBuilder::new();less256(&mut b,0,32);b.drain()
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
    data(&mut b, &[OpPushData2, 0, 48]);
    op(&mut b, OpEqualVerify);
    pay(&mut b, 0, 8);
    data(&mut b, b"KPICR01\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 0, 8);
    data(&mut b, b"KPICU01\0");
    op(&mut b, OpEqualVerify);
    auth(&mut b, 8, 40);
    sig(&mut b, R + 1, R + 33);
    op(&mut b, OpEqualVerify);
    anum(&mut b, A_MODE, A_MODE + 1);
    range(&mut b, 1, 3);
    sig(&mut b, S, S + 1);
    data(&mut b, &[4]);
    op(&mut b, OpEqualVerify);
    count(&mut b, 1); range(&mut b, 1, tree::LIMIT as i64);
    count(&mut b, 1); num(&mut b, 2); op(&mut b, OpMod); num(&mut b, 1); op(&mut b, OpNumEqualVerify);
    count(&mut b, 5); num(&mut b, 0); count(&mut b, 1); op(&mut b, OpWithin); op(&mut b, OpVerify);
    new_cm(&mut b); range(&mut b, 1, tree::LIMIT as i64);
    // Authenticate the exact historical count/root through the current archive.
    anchor_count(&mut b); num(&mut b,1); count(&mut b,1); num(&mut b,1); op(&mut b,OpAdd); op(&mut b,OpWithin); op(&mut b,OpVerify);
    anchor_count(&mut b); num(&mut b,2); op(&mut b,OpMod); num(&mut b,1); op(&mut b,OpNumEqualVerify);
    data(&mut b,&[3]); auth(&mut b,A_COUNT,A_NF); op(&mut b,OpCat); op(&mut b,OpSHA256);
    merkle(&mut b,W_ANCHOR,|b|{anchor_count(b);num(b,1);op(b,OpSub);num(b,2);op(b,OpDiv);});
    sig(&mut b,S+73,S+105);op(&mut b,OpEqualVerify);

    // Indexed nullifier predecessor, strict unsigned 256-bit gap and insertion.
    witness(&mut b,W_PRED_INDEX,W_PRED_INDEX+4);op(&mut b,OpBin2Num);
    num(&mut b,0);new_nf(&mut b);op(&mut b,OpWithin);op(&mut b,OpVerify);
    less256(&mut b,P_WITNESS+W_PRED,P_AUTH+A_NF);op(&mut b,OpVerify);
    witness(&mut b,W_PRED+36,W_PRED+68);data(&mut b,&[0;32]);op(&mut b,OpEqual);
    op(&mut b,OpIf);
    witness(&mut b,W_PRED+32,W_PRED+36);data(&mut b,&[0;4]);op(&mut b,OpEqualVerify);
    op(&mut b,OpElse);
    less256(&mut b,P_AUTH+A_NF,P_WITNESS+W_PRED+36);op(&mut b,OpVerify);
    witness(&mut b,W_PRED+32,W_PRED+36);op(&mut b,OpBin2Num);num(&mut b,1);new_nf(&mut b);op(&mut b,OpWithin);op(&mut b,OpVerify);
    op(&mut b,OpEndIf);
    data(&mut b,&[2]);witness(&mut b,W_PRED,W_PRED+68);op(&mut b,OpCat);op(&mut b,OpSHA256);
    merkle(&mut b,W_PRED_PATH,pred_index);sig(&mut b,S+41,S+73);op(&mut b,OpEqualVerify);
    data(&mut b,&[2]);witness(&mut b,W_PRED,W_PRED+32);op(&mut b,OpCat);
    new_nf(&mut b);num(&mut b,4);op(&mut b,OpNum2Bin);op(&mut b,OpCat);
    auth(&mut b,A_NF,A_CM);op(&mut b,OpCat);op(&mut b,OpSHA256);
    merkle(&mut b,W_PRED_PATH,pred_index);op(&mut b,OpToAltStack);
    data(&mut b,&[0;32]);merkle(&mut b,W_NF_APPEND,new_nf);op(&mut b,OpFromAltStack);op(&mut b,OpEqualVerify);
    data(&mut b,&[2]);auth(&mut b,A_NF,A_CM);op(&mut b,OpCat);
    witness(&mut b,W_PRED+32,W_PRED+68);op(&mut b,OpCat);op(&mut b,OpSHA256);
    merkle(&mut b,W_NF_APPEND,new_nf);pay(&mut b,P_STATE+41,P_STATE+73);op(&mut b,OpEqualVerify);

    transfer(&mut b);op(&mut b,OpIf);
    for i in 0..2 {
        data(&mut b,&[0;32]);merkle(&mut b,W_CM_APPEND+i*PATH_LEN,|b|{count(b,1);num(b,i as i64);op(b,OpAdd);});
        if i==0 {sig(&mut b,S+9,S+41);} else {op(&mut b,OpFromAltStack);}
        op(&mut b,OpEqualVerify);
        data(&mut b,&[0]);auth(&mut b,A_CM+i*32,A_CM+(i+1)*32);op(&mut b,OpCat);op(&mut b,OpSHA256);
        merkle(&mut b,W_CM_APPEND+i*PATH_LEN,|b|{count(b,1);num(b,i as i64);op(b,OpAdd);});
        if i==0 {op(&mut b,OpToAltStack);} else {pay(&mut b,P_STATE+9,P_STATE+41);op(&mut b,OpEqualVerify);}
    }
    data(&mut b,&[0;32]);merkle(&mut b,W_HISTORY_APPEND,history_count);sig(&mut b,S+73,S+105);op(&mut b,OpEqualVerify);
    data(&mut b,&[3]);new_cm(&mut b);num(&mut b,4);op(&mut b,OpNum2Bin);op(&mut b,OpCat);
    pay(&mut b,P_STATE+9,P_STATE+41);op(&mut b,OpCat);op(&mut b,OpSHA256);
    merkle(&mut b,W_HISTORY_APPEND,history_count);pay(&mut b,P_STATE+73,P_STATE+105);op(&mut b,OpEqualVerify);
    op(&mut b,OpElse);
    pay(&mut b,P_CIPHER,P_STATE);data(&mut b,&[0;370]);op(&mut b,OpEqualVerify);
    witness(&mut b,W_CM_APPEND,W_LEN);data(&mut b,&[0;3*PATH_LEN]);op(&mut b,OpEqualVerify);
    sig(&mut b,S+9,S+41);pay(&mut b,P_STATE+9,P_STATE+41);op(&mut b,OpEqualVerify);
    sig(&mut b,S+73,S+105);pay(&mut b,P_STATE+73,P_STATE+105);op(&mut b,OpEqualVerify);
    op(&mut b,OpEndIf);
    data(&mut b,&[4]);new_cm(&mut b);num(&mut b,4);op(&mut b,OpNum2Bin);op(&mut b,OpCat);
    new_nf(&mut b);num(&mut b,4);op(&mut b,OpNum2Bin);op(&mut b,OpCat);
    pay(&mut b,P_STATE,P_STATE+9);op(&mut b,OpEqualVerify);

    // Bootstrap proves exact initial backing; cannot be replayed afterwards.
    count(&mut b, 5);
    num(&mut b, 0);
    op(&mut b, OpNumEqual);
    op(&mut b, OpIf);
    count(&mut b, 1);
    num(&mut b, 1);
    op(&mut b, OpNumEqualVerify);
    transfer(&mut b);
    op(&mut b, OpVerify);
    // No creator-supplied phantom spentness or historical roots at bootstrap.
    sig(&mut b,S+41,S+73);
    data(&mut b,&tree::Tree::new(vec![tree::NfLeaf::default().digest()])?.root());op(&mut b,OpEqualVerify);
    data(&mut b,&[3]);data(&mut b,&1u32.to_le_bytes());op(&mut b,OpCat);
    sig(&mut b,S+9,S+41);op(&mut b,OpCat);op(&mut b,OpSHA256);
    for sibling in tree::empty_path() {data(&mut b,&sibling);op(&mut b,OpCat);data(&mut b,&[1]);op(&mut b,OpSwap);op(&mut b,OpCat);op(&mut b,OpSHA256);}
    sig(&mut b,S+73,S+105);op(&mut b,OpEqualVerify);
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
        return Err(format!("compact redeem needs {} bytes", bytes.len()).into());
    }
    bytes.resize(REDEEM_LEN, OpNop);
    Ok(bytes)
}
pub fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || redeem.len() != REDEEM_LEN {
        return Err("compact witness dimensions".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, proof);
    data(&mut b, redeem);
    Ok(b.drain())
}
