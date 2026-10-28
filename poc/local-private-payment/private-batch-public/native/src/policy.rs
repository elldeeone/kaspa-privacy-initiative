//! Fresh ADR-0074 payment/independent-AuthExit covenant.
//!
//! Every receipt is checked by the retained genuine R0 fragment. A separate
//! direct Groth16 exit branch remains usable without an R0 receipt or service.
//! State112 is reconstructed from split body fields; no legacy body offset or
//! funded profile is reinterpreted. The emitting caller selects fresh profile
//! identities; a nonzero parameter is not proof that its source was qualified.
use crate::r0_fragment::append_r0_groth16_verifier;
use kaspa_txscript::{opcodes::codes::*, script_builder::ScriptBuilder};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const BODY_LEN: usize = 10492;
pub const PREFIX_LEN: usize = 193;
pub const PROJECTION_LEN: usize = BODY_LEN + PREFIX_LEN;
pub const CORE_LEN: usize = 10364;
pub const EXIT_BODY_LEN: usize = 1604;
pub const REDEEM_START: usize = 133;
pub const METADATA_PREFIX: usize = 695;
pub const CHAIN_AT: usize = 150;
pub const POOL_AT: usize = 184;
pub const PROFILE_AT: usize = 218;
pub const SERVICE_AT: usize = 252;
pub const COMPONENT_AT: usize = 286;
pub const IMAGE_AT: usize = 320;
pub const EXIT_VK_AT: usize = 356;
pub const MARKER_AT: usize = 686;
pub const MARKER: &[u8; 8] = b"KPBAWN01";
pub const STATE_TAG: &[u8; 8] = b"KPBAST01";
pub const PAYMENT_TAG: &[u8; 8] = b"KPBAEF01";
pub const PAYMENT_PROJECTION_TAG: &[u8; 8] = b"KPBAFX01";
pub const EXIT_TAG: &[u8; 8] = b"KPBXEF01";
pub const EXIT_PROJECTION_TAG: &[u8; 8] = b"KPBXFX01";
pub const EXIT_STATEMENT_TAG: &[u8; 8] = b"KPBPEX01";
pub const EXIT_DIGEST_TAG: &[u8; 8] = b"KPBXDG01";
pub const JOURNAL_TAG: &[u8; 8] = b"KPBAJR01";
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const FLOOR: u64 = 60_000_000;
pub const PAYOUT_FLOOR: u64 = 10_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub domain: [u8; 32],
    pub chain: [u8; 32],
    pub pool: [u8; 32],
    pub profile: [u8; 32],
    pub service: [u8; 32],
    pub image: [u8; 32],
    pub component: [u8; 32],
    pub exit_vk: [u8; 328],
}

impl Parameters {
    pub fn validate(&self) -> Result<()> {
        if [
            &self.domain,
            &self.chain,
            &self.pool,
            &self.profile,
            &self.service,
            &self.image,
            &self.component,
        ]
        .iter()
        .any(|v| **v == [0; 32])
            || self.exit_vk == [0; 328]
        {
            return Err("missing_selected_profile_identity".into());
        }
        // These are the legacy ADR-0066 domain bytes. New tags and fresh keys
        // cannot silently recast the old funded profile as ADR-0074.
        if self.domain
            == [
                184, 98, 58, 98, 68, 168, 30, 212, 44, 67, 249, 90, 172, 119, 236, 205, 146, 127,
                165, 132, 219, 2, 161, 168, 41, 250, 163, 200, 87, 254, 211, 140,
            ]
        {
            return Err("legacy_domain_is_not_new_profile".into());
        }
        Ok(())
    }
}

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
fn actual_payment_fee(b: &mut ScriptBuilder) {
    native_amount(b, OpTxInputAmount);
    native_amount(b, OpTxOutputAmount);
    op(b, OpSub);
}

/// The common 276-byte context follows the action-specific eight-byte tag.
fn check_context(b: &mut ScriptBuilder, p: &Parameters) {
    for (offset, expected) in [
        (8, &p.chain),
        (40, &p.pool),
        (72, &p.profile),
        (104, &p.domain),
        (136, &p.service),
    ] {
        eqpayload(b, offset, expected);
    }
    point_bytes(b);
    pl(b, 168, 36);
    op(b, OpEqualVerify);
    amount_bytes(b, OpTxInputAmount);
    pl(b, 276, 8);
    op(b, OpEqualVerify);
    range_payload(b, 276, 8, FLOOR as i64, MAX as i64);
    st(b, 0, 112);
    state_from_payload(b, p, StateKind::Old);
    op(b, OpEqualVerify);
}

#[derive(Copy, Clone)]
enum StateKind {
    Old,
    PaymentNext,
    ExitNext,
}

/// Body roots/counts are split and their order differs from State112.
fn state_from_payload(b: &mut ScriptBuilder, p: &Parameters, kind: StateKind) {
    data(b, STATE_TAG);
    data(b, &p.domain);
    cat(b);
    let (cm, n, nf, m) = match kind {
        StateKind::Old => (204, 268, 236, 272),
        StateKind::PaymentNext => (284, 348, 316, 352),
        StateKind::ExitNext => (204, 268, 316, 348),
    };
    for (start, len) in [(cm, 32), (n, 4), (nf, 32), (m, 4)] {
        pl(b, start, len);
        cat(b);
    }
}

fn same_tail_successor(b: &mut ScriptBuilder, p: &Parameters, len: usize, kind: StateKind) {
    ss(b, REDEEM_START, 2);
    state_from_payload(b, p, kind);
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

/// Reconstruct the complete native projection from actual transaction fields.
fn projection_bytes(b: &mut ScriptBuilder, tag: &[u8; 8], body_len: usize) {
    data(b, tag);
    data(b, b"\x01\0\x01\0");
    cat(b);
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

fn payment_journal_hash(b: &mut ScriptBuilder, p: &Parameters) {
    data(b, JOURNAL_TAG);
    data(b, &p.domain);
    cat(b);
    data(b, &p.component);
    cat(b);
    projection_bytes(b, PAYMENT_PROJECTION_TAG, BODY_LEN);
    op(b, OpSHA256);
    cat(b);
    op(b, OpSHA256);
}

fn build(state: &[u8; 112], p: &Parameters, len: usize) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    data(&mut b, state);
    op(&mut b, OpDrop);
    for identity in [
        &p.domain,
        &p.chain,
        &p.pool,
        &p.profile,
        &p.service,
        &p.component,
        &p.image,
    ] {
        data(&mut b, identity);
        op(&mut b, OpDrop);
    }
    data(&mut b, &p.exit_vk);
    op(&mut b, OpDrop);
    data(&mut b, MARKER);
    op(&mut b, OpDrop);
    assert_eq!(b.script().len(), METADATA_PREFIX);

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
    data(&mut b, STATE_TAG);
    op(&mut b, OpEqualVerify);
    st(&mut b, 8, 32);
    data(&mut b, &p.domain);
    op(&mut b, OpEqualVerify);

    pl(&mut b, 0, 8);
    data(&mut b, PAYMENT_TAG);
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    payment_branch(&mut b, p, len)?;
    op(&mut b, OpElse);
    exit_branch(&mut b, p, len);
    op(&mut b, OpEndIf);
    Ok(b.drain())
}

fn payment_branch(b: &mut ScriptBuilder, p: &Parameters, len: usize) -> Result<()> {
    eqn(b, OpTxOutputCount, 1);
    num(b, 0);
    eqn(b, OpTxOutputSpkLen, 37);
    eqn(b, OpTxPayloadLen, BODY_LEN as i64);
    eqpayload(b, 0, PAYMENT_TAG);
    check_context(b, p);
    amount_bytes(b, OpTxOutputAmount);
    pl(b, 356, 8);
    op(b, OpEqualVerify);
    range_payload(b, 356, 8, FLOOR as i64, MAX as i64);
    range_payload(b, 364, 8, 1, MAX as i64);
    actual_payment_fee(b);
    unum(b, 364, 8);
    op(b, OpNumEqualVerify);
    for (old, new, increment, max_old) in [(268, 348, 6, 65530), (272, 352, 3, 131069)] {
        range_payload(b, old, 4, 1, max_old);
        unum(b, old, 4);
        num(b, increment);
        op(b, OpAdd);
        unum(b, new, 4);
        op(b, OpNumEqualVerify);
    }
    same_tail_successor(b, p, len, StateKind::PaymentNext);
    payment_journal_hash(b, p);
    op(b, OpFromAltStack);
    append_r0_groth16_verifier(b, p.image)
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
        Index::Payload(offset) => unum(b, offset, 4),
        Index::State { offset, add } => {
            snum(b, offset);
            if add != 0 {
                num(b, add);
                op(b, OpAdd);
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
        op(b, OpSHA256);
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
        op(b, OpBoolOr);
    }
}
fn leaf(b: &mut ScriptBuilder, v: usize, next: usize, nexti: Index) {
    data(b, LEAF_TAG);
    pl(b, v, 32);
    cat(b);
    pl(b, next, 32);
    cat(b);
    match nexti {
        Index::Payload(offset) => pl(b, offset, 4),
        i => {
            index(b, i);
            num(b, 4);
            op(b, OpNum2Bin);
        }
    }
    cat(b);
    op(b, OpSHA256);
}

/// Same indexed-tree successor rule as the existing native direct exit. The
/// proof's incoming NF is independently checked against the current state.
fn insert_nf(b: &mut ScriptBuilder, nf: usize, w: usize) {
    let (pi, pv, pn, pni, pp, ap) = (w, w + 4, w + 36, w + 68, w + 72, w + 616);
    let append = Index::State {
        offset: 108,
        add: 0,
    };
    for off in [pi, pni] {
        unum(b, off, 4);
        index(b, append);
        op(b, OpLessThan);
        op(b, OpVerify);
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
    op(b, OpToAltStack);
    data(b, &Sha256::digest(b"KPX1NFE\0"));
    path(b, ap, 17, append, NF_NODE);
    op(b, OpFromAltStack);
    op(b, OpEqualVerify);
    leaf(b, nf, pn, Index::Payload(pni));
    path(b, ap, 17, append, NF_NODE);
}

fn exit_payout_index(b: &mut ScriptBuilder) {
    unum(b, 352, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    num(b, 0);
    op(b, OpElse);
    num(b, 1);
    op(b, OpEndIf);
}

fn exit_branch(b: &mut ScriptBuilder, p: &Parameters, len: usize) {
    eqn(b, OpTxPayloadLen, EXIT_BODY_LEN as i64);
    eqpayload(b, 0, EXIT_TAG);
    check_context(b, p);
    pl(b, 284, 32);
    data(b, &[0; 32]);
    op(b, OpEqual);
    op(b, OpNot);
    op(b, OpVerify);
    range_payload(b, 360, 8, 1, MAX as i64);
    range_payload(b, 368, 8, PAYOUT_FLOOR as i64, MAX as i64);
    range_payload(b, 352, 8, 0, MAX as i64);
    unum(b, 276, 8);
    unum(b, 360, 8);
    op(b, OpSub);
    unum(b, 368, 8);
    op(b, OpSub);
    unum(b, 352, 8);
    op(b, OpNumEqualVerify);
    range_payload(b, 268, 4, 1, 65536);
    range_payload(b, 272, 4, 1, 131071);
    unum(b, 272, 4);
    num(b, 1);
    op(b, OpAdd);
    unum(b, 348, 4);
    op(b, OpNumEqualVerify);
    st(b, 76, 32);
    insert_nf(b, 412, 444);
    pl(b, 316, 32);
    op(b, OpEqualVerify);

    unum(b, 352, 8);
    num(b, 0);
    op(b, OpNumEqual);
    op(b, OpIf);
    eqn(b, OpTxOutputCount, 1);
    op(b, OpElse);
    range_payload(b, 352, 8, FLOOR as i64, MAX as i64);
    eqn(b, OpTxOutputCount, 2);
    indexed_amount_bytes(b, OpTxOutputAmount, 0);
    pl(b, 352, 8);
    op(b, OpEqualVerify);
    same_tail_successor(b, p, len, StateKind::ExitNext);
    num(b, 1);
    eqn(b, OpOutputAuthorizingInput, -1);
    op(b, OpEndIf);
    eqpayload(b, 376, &[0, 0, OpData32]);
    eqpayload(b, 411, &[OpCheckSig]);
    exit_payout_index(b);
    op(b, OpTxOutputSpk);
    pl(b, 376, 36);
    op(b, OpEqualVerify);
    exit_payout_index(b);
    op(b, OpTxOutputSpkLen);
    num(b, 36);
    op(b, OpNumEqualVerify);
    exit_payout_index(b);
    op(b, OpTxOutputAmount);
    unum(b, 368, 8);
    op(b, OpNumEqualVerify);

    // Statement152 = tag || D || current CM root || NF || exact actual effects
    // digest || native payout || native fee. No R0 image/service approval call.
    data(b, EXIT_STATEMENT_TAG);
    data(b, &p.domain);
    cat(b);
    st(b, 40, 32);
    cat(b);
    pl(b, 412, 32);
    cat(b);
    data(b, EXIT_DIGEST_TAG);
    projection_bytes(b, EXIT_PROJECTION_TAG, EXIT_BODY_LEN);
    cat(b);
    op(b, OpSHA256);
    cat(b);
    pl(b, 368, 8);
    cat(b);
    pl(b, 360, 8);
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
    data(b, &p.exit_vk);
    data(b, &[0x20]);
    op(b, OpZkPrecompile);
}

pub fn validate_state(state: &[u8; 112], p: &Parameters) -> Result<()> {
    if &state[..8] != STATE_TAG || state[8..40] != p.domain {
        return Err("state_identity".into());
    }
    let n = u32::from_le_bytes(state[72..76].try_into()?);
    let m = u32::from_le_bytes(state[108..112].try_into()?);
    if !(1..=65536).contains(&n) || !(1..=131072).contains(&m) {
        return Err("state_counts".into());
    }
    Ok(())
}

pub fn redeem(state: &[u8; 112], p: &Parameters) -> Result<Vec<u8>> {
    p.validate()?;
    validate_state(state, p)?;
    let mut len = 8192;
    for _ in 0..8 {
        let raw = build(state, p, len)?;
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
