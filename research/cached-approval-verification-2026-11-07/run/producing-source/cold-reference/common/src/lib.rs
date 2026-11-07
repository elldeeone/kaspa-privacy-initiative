//! Actual wallet/Ledger adapter. All proving inputs here are public operations.
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use bincode::Options;
pub use kpi_private_note_wallet::{ProofVerifier, ledger::Ledger, protocol::*};
use serde::{Deserialize, Serialize};
#[path = "../../../reusable-withdrawal-approvals/common/src/intent.rs"]
mod intent;
pub use intent::WithdrawalIntent;

#[cfg(all(feature = "offline", feature = "testnet"))]
compile_error!("select exactly one experiment profile");
#[cfg(feature = "offline")]
pub const DOMAIN: &[u8] = b"KPI-unfunded-batched-payment-effects-v1\0";
#[cfg(feature = "testnet")]
pub const DOMAIN: &[u8] = b"KPI-testnet-cached-payment-effects-v1\0";
#[cfg(feature = "offline")]
pub const WALLET_VK: &[u8] =
    include_bytes!("../../../reusable-withdrawal-approvals/pins/vk-compressed.bin");
#[cfg(feature = "offline")]
const WALLET_VK_FULL: &[u8] =
    include_bytes!("../../../reusable-withdrawal-approvals/pins/vk-uncompressed.bin");
#[cfg(feature = "testnet")]
pub const WALLET_VK: &[u8] = include_bytes!("../../testnet-pins/vk-compressed.bin");
#[cfg(feature = "testnet")]
const WALLET_VK_FULL: &[u8] = include_bytes!("../../testnet-pins/vk-uncompressed.bin");
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
pub const PAYMENT: u8 = 1;
pub const JOINT: u8 = 2;
pub const SOLO: u8 = 3;
pub const NAMED: u8 = 4;
pub const REFUND: u8 = 5;

#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    pub ledger: Ledger,
    pub pool: H,
    pub wallet_vk: Vec<u8>,
    pub fee_refund_spk: Vec<u8>,
}
impl State {
    pub fn root(&self) -> H {
        hash(
            &[
                b"KPI-batched-bank-state-v1\0".as_slice(),
                &bincode::serialize(self).unwrap(),
            ]
            .concat(),
        )
    }
    pub fn canonical(&self) -> bool {
        self.ledger.exits.is_empty() && self.ledger.paid_native_outputs.is_empty()
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Packet {
    pub mode: u8,
    pub operations: Vec<Operation>,
    pub intent: Option<WithdrawalIntent>,
}
impl Packet {
    pub fn bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    pub fn read(b: &[u8]) -> Result<Self, String> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(b)
            .map_err(|e| e.to_string())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeOutput {
    pub value: u64,
    pub spk: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Effects {
    pub previous: H,
    pub index: u32,
    pub input_value: u64,
    pub outputs: Vec<NativeOutput>,
}
impl Effects {
    pub fn context(&self, old: H) -> H {
        let mut b = DOMAIN.to_vec();
        b.extend(old);
        b.extend(self.previous);
        b.extend((self.index as u64).to_le_bytes());
        b.extend(self.input_value.to_le_bytes());
        b.extend((self.outputs.len() as u64).to_le_bytes());
        for o in &self.outputs {
            b.extend(o.value.to_le_bytes());
            b.extend((o.spk.len() as u64).to_le_bytes());
            b.extend(&o.spk);
        }
        hash(&b)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Input {
    pub state: State,
    pub packet: Packet,
    pub effects: Effects,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    pub state: State,
    pub journal: Vec<u8>,
    pub fee: u64,
    pub payout_principal: u64,
    pub refunded_fee: u64,
}

pub struct Verifier {
    inner: kpi_accelerated_bn254::Verifier,
}
impl Verifier {
    pub fn new(raw: &[u8]) -> Result<Self, String> {
        // Fixed bytes are fully validated and canonically re-encoded by pin().
        // The guest image binds the bytes; supplied state must match exactly.
        // No submitted proof point bypasses its existing checked decoder.
        if raw != WALLET_VK {
            return Err("pinned wallet key mismatch".into());
        }
        let bytes = WALLET_VK_FULL;
        let mut input = bytes;
        let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut input)
            .map_err(|e| e.to_string())?;
        if !input.is_empty() || vk.gamma_abc_g1.len() != 3 {
            return Err("pinned key arity/encoding".into());
        }
        Ok(Self {
            inner: kpi_accelerated_bn254::Verifier::from_validated_program_key(&vk, hash(raw)),
        })
    }
}
impl ProofVerifier for Verifier {
    fn id(&self) -> H {
        self.inner.id
    }
    fn verify(&self, op: &Operation) -> Result<(), String> {
        op.check_public(self.id())?;
        let digest = hash(&op.statement.bytes());
        let fields = digest
            .chunks(16)
            .map(Fr::from_le_bytes_mod_order)
            .collect::<Vec<_>>();
        self.inner
            .verify_inputs(&op.proof, &fields)
            .map_err(str::to_owned)
    }
}
fn ensure(ok: bool, why: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(why.into()) }
}
pub fn execute(input: &Input) -> Result<Output, String> {
    let verifier = Verifier::new(&input.state.wallet_vk)?;
    execute_with_verifier(input, &verifier)
}
fn execute_with_verifier<V: ProofVerifier>(input: &Input, verifier: &V) -> Result<Output, String> {
    let before = &input.state;
    ensure(before.canonical(), "uncanonical prior paid/exit records")?;
    before.ledger.invariant()?;

    ensure(
        verifier.id() == before.ledger.verifier,
        "state wallet verifier",
    )?;
    let e = &input.effects;
    ensure(
        !e.outputs.is_empty() && e.outputs.len() <= 8,
        "native output count",
    )?;
    ensure(e.input_value <= MAX_SOMPI, "native input range")?;
    ensure(
        e.input_value >= before.ledger.reserve,
        "native input backing",
    )?;
    let fees_before = e.input_value - before.ledger.reserve;
    let out_value = e.outputs.iter().try_fold(0u64, |sum, o| {
        if o.value == 0 || o.value > MAX_SOMPI {
            return Err("native output range".to_owned());
        }
        sum.checked_add(o.value)
            .ok_or_else(|| "native output sum overflow".to_owned())
    })?;
    let fee = e
        .input_value
        .checked_sub(out_value)
        .ok_or("native value inflation")?;
    ensure(
        fee > 0 && fee <= fees_before && fee <= 50_000_000,
        "fee allowance/principal separation",
    )?;
    let fees_after = fees_before - fee;
    let packet = &input.packet;
    ensure(
        !packet.operations.is_empty() && packet.operations.len() <= 32,
        "operation count",
    )?;
    let withdrawing = packet.mode != PAYMENT;
    ensure(
        [PAYMENT, JOINT, SOLO, NAMED, REFUND].contains(&packet.mode),
        "packet mode",
    )?;
    if [SOLO, REFUND].contains(&packet.mode) {
        ensure(packet.operations.len() == 1, "single-owner branch")?;
    }
    if packet.mode == JOINT {
        ensure(packet.operations.len() >= 2, "joint branch cohort")?;
    }
    let context = e.context(before.root());
    let approval_context = if let Some(intent) = &packet.intent {
        ensure(packet.mode == JOINT, "intent requires joint mode")?;
        intent.validate(before, &packet.operations)?;
        ensure(fee <= intent.fee_cap, "intent fee cap")?;
        intent.commitment()
    } else {
        context
    };
    let mut next = before.clone();
    let mut payout = 0u64;
    for op in &packet.operations {
        let s = &op.statement;
        if !withdrawing {
            ensure([CREDIT, TRANSFER].contains(&s.kind), "payment kind")?;
        } else {
            ensure(
                s.kind == if packet.mode == REFUND { RECOVER } else { EXIT },
                "withdrawal kind",
            )?;
            if packet.mode != NAMED {
                ensure(
                    s.exit_destination == approval_context,
                    "complete native effects authorization",
                )?;
            }
            payout = payout.checked_add(s.exit_value).ok_or("payout overflow")?;
        }
        next.ledger.apply(verifier, op)?;
    }
    let remaining = before
        .ledger
        .reserve
        .checked_sub(payout)
        .ok_or("principal underflow")?;
    let continuing = remaining > 0;
    let offset = usize::from(continuing);
    let payouts = if withdrawing {
        packet.operations.len()
    } else {
        0
    };
    let refund = if !continuing && fees_after > 0 { 1 } else { 0 };
    ensure(
        e.outputs.len() == offset + payouts + refund,
        "native complete output shape",
    )?;
    if continuing {
        ensure(
            e.outputs[0].value
                == remaining
                    .checked_add(fees_after)
                    .ok_or("reserve overflow")?,
            "successor backing",
        )?;
        ensure(e.outputs[0].spk.len() == 37, "successor script shape")?;
    }
    if let Some(intent) = &packet.intent {
        intent.check_actual_payouts(&e.outputs[offset..offset + payouts])?;
    }
    for (i, op) in packet.operations.iter().enumerate().filter(|_| withdrawing) {
        let o = &e.outputs[offset + i];
        ensure(o.value == op.statement.exit_value, "actual owner principal")?;
        ensure(
            o.spk.len() == 36 && o.spk[..3] == [0, 0, 32] && o.spk[35] == 0xac,
            "actual payout standard key script",
        )?;
        if packet.mode == NAMED {
            ensure(
                op.statement.exit_destination == hash(&[vec![0], o.spk[3..35].to_vec()].concat()),
                "original named destination binding",
            )?;
        }
        if packet.mode == JOINT {
            ensure(
                op.statement.exit_value == packet.operations[0].statement.exit_value,
                "equal-denomination joint scope",
            )?;
        }
        for earlier in &e.outputs[offset..offset + i] {
            ensure(earlier.spk != o.spk, "duplicate principal payout")?;
        }
        let record = hash(
            &[
                b"KPI-atomic-whole-set-paid-record-v1\0".as_slice(),
                &context,
                &op.statement.id(),
            ]
            .concat(),
        );
        next.ledger.confirm_authenticated_fixture_payout(
            op.statement.id(),
            op.statement.exit_value,
            op.statement.exit_destination,
            record,
        )?;
    }
    if refund == 1 {
        let o = e.outputs.last().unwrap();
        ensure(
            o.value == fees_after && o.spk == before.fee_refund_spk,
            "unused allowance refund",
        )?;
    }
    ensure(next.ledger.reserve == remaining, "post reserve principal")?;
    ensure(
        next.ledger.exits.values().all(|x| x.paid),
        "unpaid liability cannot be normalized away",
    )?;
    // These records concern THIS actual, atomically applied native effect set.
    // Keep every NF/deposit/tree/anchor; old payout records cannot spend a new
    // outpoint or recreate an old consumed NF. Full public history is retained.
    next.ledger.exits.clear();
    next.ledger.paid_native_outputs.clear();
    next.ledger.invariant()?;
    let new_root = if remaining == 0 { [0; 32] } else { next.root() };
    let mut journal = before.root().to_vec();
    journal.extend(new_root);
    journal.extend(context);
    journal.extend(hash(&packet.bytes()));
    Ok(Output {
        state: next,
        journal,
        fee,
        payout_principal: payout,
        refunded_fee: if refund == 1 { fees_after } else { 0 },
    })
}

mod certificate;
pub use certificate::{authorization_journal, authorize_packet, execute_with_certificate};
