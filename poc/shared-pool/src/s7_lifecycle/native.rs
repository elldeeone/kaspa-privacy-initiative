//! Isolated ADR-0037 immutable S7 ordinary/paired native policy.
//! DO_NOT_FUND. Native checks concern supplied UTXOs, not accepted ancestry.
use crate::{
    Result, native as base_native,
    protocol::{H, MAX_SOMPI, hash},
    two_input::{self, Bundle, tree::PublicState},
};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{opcodes::codes::*, pay_to_script_hash_script, script_builder::ScriptBuilder};
use serde::{Deserialize, Serialize};

pub const REDEEM_LEN: usize = 24_576;
pub const WITNESS_LEN: usize = 133 + REDEEM_LEN;
pub const BUDGET: u16 = 1700; // Provisional: qualify actual emitted code and native branches.
pub const HEADER: [u8; 10] = *b"KPI2LCT1\x01\x00";
pub const ORDINARY_LEN: usize = 5231;
pub const PAIRED_LEN: usize = 1204;
pub const ORDINARY_BRANCH: u8 = 0;
pub const PAIRED_BRANCH: u8 = 1;
pub const PAIRED_P: usize = 11;
pub const PAIRED_NEXT: usize = 1099;
const REDEEM_START: usize = 133;
const STATE_START: usize = 36;
const PREFIX: usize = 142;

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
mod hex_h {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        hex::decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected32bytehex"))
    }
}
mod hex_roots {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(v: &[[u8; 32]; 2], s: S) -> Result<S::Ok, S::Error> {
        [hex::encode(v[0]), hex::encode(v[1])].serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[[u8; 32]; 2], D::Error> {
        let values: [String; 2] = Deserialize::deserialize(d)?;
        let mut out = [[0; 32]; 2];
        for (i, value) in values.into_iter().enumerate() {
            out[i] = hex::decode(value)
                .map_err(serde::de::Error::custom)?
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected32bytehex"))?;
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterConstants {
    #[serde(with = "hex_vec")]
    pub vk: Vec<u8>,
    #[serde(with = "hex_roots")]
    pub root: [[u8; 32]; 2],
    #[serde(with = "hex_h")]
    pub id: H,
    #[serde(with = "hex_h")]
    pub output_tag: H,
    #[serde(with = "hex_h")]
    pub claim_tag: H,
    #[serde(with = "hex_h")]
    pub post: H,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(with = "hex_h")]
    pub domain: H,
    #[serde(with = "hex_h")]
    pub pool_id: H,
    #[serde(with = "hex_vec")]
    pub inner_vk: Vec<u8>,
    #[serde(with = "hex_h")]
    pub pair_image: H,
    pub outer: OuterConstants,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        use ark_bn254::Bn254;
        use ark_groth16::VerifyingKey;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        if self.domain == [0; 32]
            || self.pool_id == [0; 32]
            || self.domain == self.pool_id
            || self.pair_image == [0; 32]
            || self.inner_vk.len() != 328
            || self.outer.vk.len() != 424
            || self.outer.output_tag != hash(b"risc0.Output")
            || self.outer.claim_tag != hash(b"risc0.ReceiptClaim")
            || self.outer.root.iter().any(|x| x[16..] != [0; 16])
        {
            return Err("S7 lifecycle policy identity/dimensions".into());
        }
        // Official SDK3.0.3 values independently retained in the closed one-shot
        // claim-boundary packet fd0a18b75dee686a822f5f4cffb420fdb2704bcb365ce8dc8e0389b14c996323.
        // Shape-valid caller keys/roots cannot replace these verifier parameters.
        if hex::encode(hash(&self.outer.vk))
            != "78886245c5d55b850f2ac26af823802cd128eb4a43d6c52c8a62af46d54306a4"
            || hex::encode(self.outer.root[0])
                != "a54dc85ac99f851c92d7c96d7318af4100000000000000000000000000000000"
            || hex::encode(self.outer.root[1])
                != "dbe7c0194edfcc37eb4d422a998c1f5600000000000000000000000000000000"
            || hex::encode(self.outer.id)
                != "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404"
            || hex::encode(self.outer.post)
                != "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2"
        {
            return Err("S7 lifecycle official outer parameter identity".into());
        }
        for (raw, arity) in [(&self.inner_vk, 3usize), (&self.outer.vk, 6usize)] {
            let mut reader = raw.as_slice();
            let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)?;
            let mut canonical = Vec::new();
            vk.serialize_compressed(&mut canonical)?;
            if !reader.is_empty() || canonical != *raw || vk.gamma_abc_g1.len() != arity {
                return Err("S7 lifecycle canonical fixed key/arity".into());
            }
        }
        Ok(())
    }
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
fn payload(b: &mut ScriptBuilder, start: usize, end: usize) {
    num(b, start as i64);
    num(b, end as i64);
    op(b, OpTxPayloadSubstr);
}
fn sig(b: &mut ScriptBuilder, start: usize, end: usize) {
    num(b, 0);
    num(b, start as i64);
    num(b, end as i64);
    op(b, OpTxInputScriptSigSubstr);
}
fn eqnum(b: &mut ScriptBuilder, code: u8, value: i64) {
    op(b, code);
    num(b, value);
    op(b, OpNumEqualVerify);
}
fn amount(b: &mut ScriptBuilder, code: u8) {
    num(b, 0);
    op(b, code);
}
fn fixed_amount(b: &mut ScriptBuilder, code: u8) {
    amount(b, code);
    num(b, 8);
    op(b, OpNum2Bin);
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
fn successor(b: &mut ScriptBuilder, next: usize, end: usize) {
    sig(b, REDEEM_START, REDEEM_START + STATE_START);
    payload(b, next, end);
    op(b, OpCat);
    data(b, &[OpDrop]);
    op(b, OpCat);
    sig(b, REDEEM_START + PREFIX, WITNESS_LEN);
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
pub fn state_bytes(state: &PublicState) -> Result<[u8; 105]> {
    let mut bytes: [u8; 105] = state
        .compact()?
        .bytes()
        .try_into()
        .map_err(|_| "state dimensions")?;
    bytes[0] = 7;
    Ok(bytes)
}
pub fn checked_state(bytes: &[u8; 105]) -> Result<two_input::tree::State> {
    if bytes[0] != 7 {
        return Err("S7 lifecycle state discriminator".into());
    }
    let mut legacy = *bytes;
    legacy[0] = 6;
    two_input::tree::State::parse(&legacy)
}
fn raw_redeem(policy: &Policy, state: &[u8; 105]) -> Result<Vec<u8>> {
    policy.validate()?;
    checked_state(state)?;
    let mut b = ScriptBuilder::new();
    data(&mut b, &policy.pool_id);
    op(&mut b, OpDrop);
    data(&mut b, state);
    op(&mut b, OpDrop);
    if b.script().len() != PREFIX {
        return Err("S7 immutable prefix layout".into());
    }
    payload(&mut b, 0, 10);
    data(&mut b, &HEADER);
    op(&mut b, OpEqualVerify);
    payload(&mut b, 10, 11);
    data(&mut b, &[ORDINARY_BRANCH]);
    op(&mut b, OpEqual);
    op(&mut b, OpIf);
    b.add_ops(&ordinary::body(policy)?)
        .map_err(|e| format!("ordinary script append: {e}"))?;
    op(&mut b, OpElse);
    payload(&mut b, 10, 11);
    data(&mut b, &[PAIRED_BRANCH]);
    op(&mut b, OpEqualVerify);
    pair_body(&mut b, policy);
    op(&mut b, OpEndIf);
    let code = b.drain();
    if code.len() > REDEEM_LEN {
        return Err(format!("S7 union emitted{} exceeds{}", code.len(), REDEEM_LEN).into());
    }
    Ok(code)
}
/// Actual emitter length before the fixed immutable NOP suffix.
pub fn emitted_length(policy: &Policy, state: &[u8; 105]) -> Result<usize> {
    Ok(raw_redeem(policy, state)?.len())
}
pub fn redeem(policy: &Policy, state: &[u8; 105]) -> Result<Vec<u8>> {
    let mut code = raw_redeem(policy, state)?;
    code.resize(REDEEM_LEN, OpNop);
    Ok(code)
}
pub fn reserve_spk(policy: &Policy, state: &PublicState) -> Result<ScriptPublicKey> {
    Ok(pay_to_script_hash_script(&redeem(
        policy,
        &state_bytes(state)?,
    )?))
}
pub fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || redeem.len() != REDEEM_LEN {
        return Err("S7 proof/redeem dimensions".into());
    }
    let mut b = ScriptBuilder::new();
    data(&mut b, proof);
    data(&mut b, redeem);
    let bytes = b.drain();
    if bytes.len() != WITNESS_LEN {
        return Err("S7 canonical scriptsig dimensions".into());
    }
    Ok(bytes)
}
pub fn ordinary_settle(
    policy: &Policy,
    old: &PublicState,
    u: &base_native::Utxo,
    bundle: &Bundle,
    external: Option<&base_native::Utxo>,
) -> Result<(Transaction, Vec<UtxoEntry>, PublicState)> {
    let a = bundle.auth()?;
    let c = bundle.ciphers()?;
    if a.domain != policy.domain
        || hash(&c) != a.cipher_hash
        || (a.mode == 2 && c != [0; 370])
        || u.spk != hex::encode(base_native::encode_spk(&reserve_spk(policy, old)?))
        || (a.mode == 0) != external.is_some()
    {
        return Err("S7 ordinary domain/reserve/cipher/admission binding".into());
    }
    let (next, w) = old.witness(&a)?;
    let mut total = u.amount;
    if let Some(e) = external {
        let point = [hex::decode(&e.txid)?, e.index.to_le_bytes().to_vec()].concat();
        if e.is_coinbase
            || e.amount != a.deposit
            || point != a.funding
            || hex::decode(&e.spk)? != a.funding_spk
        {
            return Err("S7 funding binding".into());
        }
        total = total
            .checked_add(e.amount)
            .filter(|x| *x <= MAX_SOMPI)
            .ok_or("S7 input amount bound")?;
    }
    let remaining = total
        .checked_sub(a.payout)
        .and_then(|x| x.checked_sub(a.fee))
        .ok_or("S7 backing underflow")?;
    if remaining == 0 && a.mode != 2 {
        return Err("S7 terminal requires DRAIN".into());
    }
    let mut outputs = Vec::new();
    if remaining > 0 {
        outputs.push(TransactionOutput::new(
            remaining,
            reserve_spk(policy, &next)?,
        ));
    }
    if a.payout > 0 {
        outputs.push(TransactionOutput::new(
            a.payout,
            base_native::decode_spk(&hex::encode(a.spk))?,
        ));
    }
    let next_bytes = if remaining == 0 {
        [0; 105]
    } else {
        state_bytes(&next)?
    };
    let payload = [
        HEADER.as_slice(),
        &[ORDINARY_BRANCH],
        &a.bytes(),
        &c,
        &next_bytes,
        &w,
    ]
    .concat();
    if payload.len() != ORDINARY_LEN {
        return Err("S7 ordinary envelope".into());
    }
    let mut inputs = vec![TransactionInput::new_with_compute_budget(
        u.outpoint()?,
        signature(
            &hex::decode(&bundle.proof)?,
            &redeem(policy, &state_bytes(old)?)?,
        )?,
        u64::MAX,
        BUDGET,
    )];
    let mut entries = vec![u.entry()?];
    if let Some(e) = external {
        let mut sig = vec![0; 66];
        sig[0] = 65;
        sig[65] = 1;
        inputs.push(TransactionInput::new_with_compute_budget(
            e.outpoint()?,
            sig,
            u64::MAX,
            10,
        ));
        entries.push(e.entry()?);
    }
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, payload);
    base_native::set_mass(&tx, &entries)?;
    Ok((tx, entries, next))
}
pub fn founding(
    policy: &Policy,
    cm: H,
    value: u64,
    funding: &base_native::Utxo,
    key: &H,
) -> Result<(Transaction, Vec<UtxoEntry>, PublicState)> {
    if !(two_input::NOTE_FLOOR..=MAX_SOMPI).contains(&value) {
        return Err("S7 initial value bound".into());
    }
    let state = PublicState::initial(cm)?;
    let (tx, entries) = base_native::ordinary(
        funding,
        key,
        vec![TransactionOutput::new(value, reserve_spk(policy, &state)?)],
    )?;
    Ok((tx, entries, state))
}
pub fn paired_settle(
    policy: &Policy,
    old: &PublicState,
    u: &base_native::Utxo,
    p: &[u8],
    next: &[u8; 105],
    proof: &[u8],
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let current = old.compact()?;
    let successor = checked_state(next)?;
    if current.nf_count < 2
        || p.len() != 1088
        || &p[..12] != b"KPI2V6P1\x01\x00\x02\x00"
        || p[12..44] != policy.domain
        || u.spk != hex::encode(base_native::encode_spk(&reserve_spk(policy, old)?))
        || successor.cm_count
            != current
                .cm_count
                .checked_add(4)
                .ok_or("S7 pair CM overflow")?
        || successor.nf_count
            != current
                .nf_count
                .checked_add(4)
                .ok_or("S7 pair NF overflow")?
    {
        return Err("S7 paired supplied context/framing".into());
    }
    let fee = u128::from_le_bytes(p[76..92].try_into()?);
    let fee = u64::try_from(fee).map_err(|_| "S7 paired fee narrowing")?;
    let remaining = u
        .amount
        .checked_sub(fee)
        .filter(|x| *x > 0 && *x <= MAX_SOMPI)
        .ok_or("S7 paired reserve/fee")?;
    if fee == 0 || fee > MAX_SOMPI {
        return Err("S7 paired fee range".into());
    }
    let outputs = vec![TransactionOutput::new(
        remaining,
        pay_to_script_hash_script(&redeem(policy, next)?),
    )];
    let payload = [HEADER.as_slice(), &[PAIRED_BRANCH], p, next].concat();
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            u.outpoint()?,
            signature(proof, &redeem(policy, &state_bytes(old)?)?)?,
            u64::MAX,
            BUDGET,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload,
    );
    let entries = vec![u.entry()?];
    base_native::set_mass(&tx, &entries)?;
    Ok((tx, entries))
}

fn journal_hash(b: &mut ScriptBuilder, p: &Policy) {
    data(b, b"KPI2V6S1\x01\x00");
    payload(b, PAIRED_P, PAIRED_NEXT);
    op(b, OpSHA256);
    op(b, OpCat);
    data(b, &p.pool_id);
    op(b, OpCat);
    num(b, 0);
    op(b, OpOutpointTxId);
    op(b, OpCat);
    num(b, 0);
    op(b, OpOutpointIndex);
    num(b, 8);
    op(b, OpNum2Bin);
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
    payload(b, PAIRED_NEXT, PAIRED_LEN);
    op(b, OpCat);
    fixed_amount(b, OpTxInputAmount);
    op(b, OpCat);
    fixed_amount(b, OpTxOutputAmount);
    op(b, OpCat);
    op(b, OpSHA256);
}
fn claim(b: &mut ScriptBuilder, c: &OuterConstants) {
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
fn outer_verify(b: &mut ScriptBuilder, p: &Policy) {
    let c = &p.outer;
    data(b, &p.pair_image);
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
fn pair_body(b: &mut ScriptBuilder, p: &Policy) {
    eqnum(b, OpDepth, 1);
    eqnum(b, OpSize, 128);
    op(b, OpToAltStack);
    for (code, value) in [
        (OpTxVersion, 1),
        (OpTxInputIndex, 0),
        (OpTxInputCount, 1),
        (OpTxOutputCount, 1),
        (OpTxGas, 0),
        (OpTxLockTime, 0),
        (OpTxPayloadLen, PAIRED_LEN as i64),
    ] {
        eqnum(b, code, value);
    }
    op(b, OpTxSubnetId);
    data(b, &[0; 20]);
    op(b, OpEqualVerify);
    num(b, 0);
    op(b, OpTxInputSeq);
    data(b, &u64::MAX.to_le_bytes());
    op(b, OpEqualVerify);
    num(b, 0);
    eqnum(b, OpTxInputIsCoinbase, 0);
    num(b, 0);
    op(b, OpInputCovenantId);
    data(b, &[0; 32]);
    op(b, OpEqualVerify);
    num(b, 0);
    eqnum(b, OpOutputAuthorizingInput, -1);
    num(b, 0);
    eqnum(b, OpTxInputScriptSigLen, WITNESS_LEN as i64);
    sig(b, 0, 2);
    data(b, &[OpPushData1, 128]);
    op(b, OpEqualVerify);
    sig(b, 130, 133);
    data(
        b,
        &[
            OpPushData2,
            (REDEEM_LEN & 255) as u8,
            (REDEEM_LEN >> 8) as u8,
        ],
    );
    op(b, OpEqualVerify);
    sig(
        b,
        REDEEM_START + STATE_START,
        REDEEM_START + STATE_START + 1,
    );
    data(b, &[7]);
    op(b, OpEqualVerify);
    // Pair is unavailable before the ordinary bootstrap establishes liabilities.
    sig(
        b,
        REDEEM_START + STATE_START + 5,
        REDEEM_START + STATE_START + 9,
    );
    op(b, OpBin2Num);
    num(b, 2);
    op(b, OpGreaterThanOrEqual);
    op(b, OpVerify);
    payload(b, PAIRED_NEXT, PAIRED_NEXT + 1);
    data(b, &[7]);
    op(b, OpEqualVerify);
    payload(b, PAIRED_P + 12, PAIRED_P + 44);
    data(b, &p.domain);
    op(b, OpEqualVerify);
    payload(b, PAIRED_P, PAIRED_P + 12);
    data(b, b"KPI2V6P1\x01\x00\x02\x00");
    op(b, OpEqualVerify);
    successor(b, PAIRED_NEXT, PAIRED_LEN);
    payload(b, PAIRED_P + 84, PAIRED_P + 92);
    data(b, &[0; 8]);
    op(b, OpEqualVerify);
    bounded_amount(b, OpTxInputAmount);
    bounded_amount(b, OpTxOutputAmount);
    op(b, OpSub);
    payload(b, PAIRED_P + 76, PAIRED_P + 84);
    op(b, OpDup);
    op(b, OpBin2Num);
    op(b, OpDup);
    num(b, 0);
    op(b, OpGreaterThan);
    op(b, OpVerify);
    op(b, OpDup);
    num(b, MAX_SOMPI as i64);
    op(b, OpLessThanOrEqual);
    op(b, OpVerify);
    op(b, OpDup);
    num(b, 8);
    op(b, OpNum2Bin);
    op(b, OpRot);
    op(b, OpEqualVerify);
    op(b, OpNumEqualVerify);
    journal_hash(b, p);
    op(b, OpFromAltStack);
    op(b, OpSwap);
    outer_verify(b, p);
    op(b, OpTrue);
}

// Existing v6 ordinary guards, offset/version/domain adapted into the immutable union.
mod ordinary {
    use super::*;
    use crate::two_input::*;
    const P_AUTH: usize = 11;
    const P_CIPHER: usize = 388;
    const P_STATE: usize = 758;
    const P_WITNESS: usize = 863;
    const PAYLOAD_SIZE: usize = 5231;
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
    fn merkle(
        b: &mut ScriptBuilder,
        path: usize,
        depth: usize,
        index: impl Fn(&mut ScriptBuilder),
    ) {
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

    pub fn body(p: &Policy) -> Result<Vec<u8>> {
        let vk = &p.inner_vk;
        let mut b = ScriptBuilder::new();
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
        data(&mut b, b"KPI2LCT1");
        op(&mut b, OpEqualVerify);
        auth(&mut b, 0, 8);
        data(&mut b, b"KPICU06\0");
        op(&mut b, OpEqualVerify);
        auth(&mut b, 8, 40);
        data(&mut b, &p.domain);
        op(&mut b, OpEqualVerify);
        anum(&mut b, A_MODE, A_MODE + 1);
        range(&mut b, 0, 3);
        sig(&mut b, S, S + 1);
        data(&mut b, &[7]);
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
        data(&mut b, &[7]);
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

        Ok(b.drain())
    }
}
