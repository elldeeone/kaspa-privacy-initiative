//! Full transition relation, including both native digest layers. No host check
//! substitutes for a predicate needed to protect backing or authorization.
use crate::protocol::*;
use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    select::CondSelectGadget, uint8::UInt8, uint64::UInt64,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
type B = UInt8<Fr>;
type Flag = Boolean<Fr>;
type R<T> = std::result::Result<T, SynthesisError>;

#[derive(Clone)]
pub struct SpendCircuit {
    pub transition: Transition,
    pub secret: H,
    pub input: Note,
    pub outputs: [Note; 2],
    pub fee: u64,
    pub public: [Fr; 2],
}
fn field(b: &[B]) -> R<FpVar<Fr>> {
    let mut bits = Vec::new();
    for byte in b {
        bits.extend(byte.to_bits_le()?);
    }
    Boolean::le_bits_to_fp(&bits)
}
fn digest(tag: &[u8], domain: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut bytes = B::constant_vec(tag);
    bytes.extend_from_slice(domain);
    for p in parts {
        bytes.extend_from_slice(p);
    }
    Ok(Sha256Gadget::digest(&bytes)?.0)
}
fn choose(flag: &Flag, a: &[B], b: &[B]) -> R<Vec<B>> {
    a.iter()
        .zip(b)
        .map(|(x, y)| B::conditionally_select(flag, x, y))
        .collect()
}
fn any(flags: &[Flag]) -> Flag {
    flags.iter().fold(Flag::FALSE, |v, f| v | f)
}
fn count_flags(count: &B, allow_zero: bool) -> R<Vec<Flag>> {
    let flags = (0..=4)
        .map(|n| count.is_eq(&B::constant(n)))
        .collect::<R<Vec<_>>>()?;
    any(&flags[if allow_zero { 0 } else { 1 }..]).enforce_equal(&Flag::TRUE)?;
    Ok(flags)
}
fn state(bytes: &[B]) -> R<(Vec<Flag>, Vec<Flag>)> {
    bytes[0].enforce_equal(&B::constant(1))?;
    let cm = count_flags(&bytes[1], false)?;
    let nf = count_flags(&bytes[2], true)?;
    for (i, a) in nf.iter().enumerate() {
        for b in &cm[..i] {
            (a & b).enforce_equal(&Flag::FALSE)?;
        }
    }
    let zero = B::constant_vec(&[0; 32]);
    for (start, flags) in [(3, &cm), (131, &nf)] {
        for i in 0..4 {
            let active = any(&flags[i + 1..]);
            let slot = &bytes[start + 32 * i..start + 32 * (i + 1)];
            slot.is_eq(&zero)?.enforce_equal(&!&active)?;
            for j in 0..i {
                slot.is_eq(&bytes[start + 32 * j..start + 32 * (j + 1)])?
                    .conditional_enforce_equal(&Flag::FALSE, &active)?;
            }
        }
    }
    Ok((cm, nf))
}
fn note(cs: ConstraintSystemRef<Fr>, d: &[B], n: &Note) -> R<(Vec<B>, Vec<B>, Vec<B>, Vec<B>)> {
    let owner = B::new_witness_vec(cs.clone(), &n.owner)?;
    let incoming = B::new_witness_vec(cs.clone(), &n.incoming)?;
    let v = UInt64::new_witness(cs.clone(), || Ok(n.value))?;
    let value = v
        .to_bits_le()?
        .chunks(8)
        .map(B::from_bits_le)
        .collect::<Vec<_>>();
    let rho = B::new_witness_vec(cs, &n.rho)?;
    let cm = digest(NOTE_TAG, d, &[&owner, &incoming, &value, &rho])?;
    Ok((owner, incoming, value, cm))
}
impl SpendCircuit {
    pub fn check(&self) -> R<(usize, bool)> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone())?;
        Ok((cs.num_constraints(), cs.is_satisfied()?))
    }
}
impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let t = &self.transition;
        if t.bytes().len() != TRANSCRIPT_LEN
            || t.payload.len() != PAYLOAD_LEN
            || t.payout_spk.len() != 36
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let transcript = B::new_witness_vec(cs.clone(), &t.bytes())?;
        let payload = B::new_witness_vec(cs.clone(), &t.payload)?;
        transcript[..8].enforce_equal(&B::constant_vec(b"KPIBND1\0"))?;
        payload[..8].enforce_equal(&B::constant_vec(b"KPIDF01\0"))?;
        let d = &transcript[8..40];
        let old = &transcript[40..299];
        let new = &payload[9..268];
        let (cm_flags, nf_flags) = state(old)?;
        state(new)?;
        let transfer = payload[8].is_eq(&B::constant(1))?;
        let continuing = payload[8].is_eq(&B::constant(2))?;
        let terminal = payload[8].is_eq(&B::constant(3))?;
        any(&[transfer.clone(), continuing.clone(), terminal.clone()])
            .enforce_equal(&Flag::TRUE)?;
        let withdrawing = !&transfer;
        let z8 = B::constant_vec(&[0; 8]);
        let z32 = B::constant_vec(&[0; 32]);
        transcript[335..339].enforce_equal(&B::constant_vec(&[0; 4]))?; // zero-extended u32 predecessor index
        let rin = &transcript[339..347];
        let rout = &transcript[347..355];
        let payout = &transcript[355..363];
        rin.is_eq(&z8)?.enforce_equal(&Flag::FALSE)?;
        rout.is_eq(&z8)?.enforce_equal(&terminal)?;
        payout.is_eq(&z8)?.enforce_equal(&transfer)?;
        transcript[363..399].conditional_enforce_equal(&B::constant_vec(&[0; 36]), &transfer)?;
        transcript[363..366]
            .conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), &withdrawing)?;
        transcript[398].conditional_enforce_equal(&B::constant(0xac), &withdrawing)?;
        payload[268..].conditional_enforce_equal(&B::constant_vec(&[0; 370]), &withdrawing)?;
        let secret = B::new_witness_vec(cs.clone(), &self.secret)?;
        let (owner, view, value, input_cm) = note(cs.clone(), d, &self.input)?;
        owner.enforce_equal(&digest(OWNER_TAG, d, &[&secret, &view])?)?;
        value.is_eq(&z8)?.enforce_equal(&Flag::FALSE)?;
        let mut memberships = Vec::new();
        for i in 0..4 {
            memberships.push(
                input_cm.as_slice().is_eq(&old[3 + 32 * i..35 + 32 * i])? & any(&cm_flags[i + 1..]),
            );
        }
        any(&memberships).enforce_equal(&Flag::TRUE)?;
        let mut padded = secret;
        padded.extend(B::constant_vec(&[0; 32]));
        let mut inner = padded
            .iter()
            .map(|b| b ^ B::constant(0x36))
            .collect::<Vec<_>>();
        inner.extend(B::constant_vec(NF_TAG));
        inner.extend_from_slice(d);
        inner.extend_from_slice(&input_cm);
        let mut outer = padded
            .iter()
            .map(|b| b ^ B::constant(0x5c))
            .collect::<Vec<_>>();
        outer.extend(Sha256Gadget::digest(&inner)?.0);
        let nf = Sha256Gadget::digest(&outer)?.0;
        nf.is_eq(&z32)?.enforce_equal(&Flag::FALSE)?;
        for i in 0..4 {
            nf.as_slice()
                .is_eq(&old[131 + 32 * i..163 + 32 * i])?
                .enforce_equal(&Flag::FALSE)?;
        }
        let mut output_values = Vec::new();
        let mut output_cms = Vec::new();
        for n in &self.outputs {
            let (_, _, v, cm) = note(cs.clone(), d, n)?;
            v.is_eq(&z8)?.enforce_equal(&withdrawing)?;
            output_values.push(field(&v)?);
            output_cms.push(cm);
        }
        output_cms[0]
            .is_eq(&output_cms[1])?
            .conditional_enforce_equal(&Flag::FALSE, &transfer)?;
        let transfer_fp = Boolean::le_bits_to_fp(&[transfer.clone()])?;
        field(&new[1..2])?.enforce_equal(&(field(&old[1..2])? + transfer_fp * Fr::from(2u64)))?;
        field(&new[2..3])?.enforce_equal(&(field(&old[2..3])? + Fr::from(1u64)))?;
        for i in 0..4 {
            let insert0 = &cm_flags[i] & &transfer;
            let insert1 = if i == 0 {
                Flag::FALSE
            } else {
                &cm_flags[i - 1] & &transfer
            };
            let appended = choose(
                &insert0,
                &output_cms[0],
                &choose(&insert1, &output_cms[1], &z32)?,
            )?;
            let expected = choose(
                &any(&cm_flags[i + 1..]),
                &old[3 + 32 * i..35 + 32 * i],
                &appended,
            )?;
            new[3 + 32 * i..35 + 32 * i].enforce_equal(&expected)?;
            let expected = choose(
                &any(&nf_flags[i + 1..]),
                &old[131 + 32 * i..163 + 32 * i],
                &choose(&nf_flags[i], &nf, &z32)?,
            )?;
            new[131 + 32 * i..163 + 32 * i].enforce_equal(&expected)?;
        }
        let fee = B::new_witness_vec(cs.clone(), &self.fee.to_le_bytes())?;
        fee.is_eq(&z8)?.enforce_equal(&Flag::FALSE)?;
        // Every quantity is an unsigned 64-bit byte decomposition. These sums
        // remain far below Fr, so equality cannot hide integer overflow.
        field(rin)?.enforce_equal(&(field(rout)? + field(payout)? + field(&fee)?))?;
        field(&value)?.enforce_equal(
            &(output_values[0].clone() + output_values[1].clone() + field(payout)? + field(&fee)?),
        )?;
        let genesis = &nf_flags[0];
        old[1].conditional_enforce_equal(&B::constant(1), genesis)?;
        value.as_slice().conditional_enforce_equal(rin, genesis)?;
        value.as_slice().conditional_enforce_equal(rin, &terminal)?;
        new[2].conditional_enforce_equal(&new[1], &terminal)?;
        new[2]
            .is_eq(&new[1])?
            .conditional_enforce_equal(&Flag::FALSE, &continuing)?;
        Sha256Gadget::digest(&payload)?
            .0
            .as_slice()
            .enforce_equal(&transcript[399..431])?;
        let h = Sha256Gadget::digest(&transcript)?.0;
        // Bind every digest bit, never reduce a full SHA256 value modulo Fr.
        for i in 0..2 {
            let public = FpVar::new_input(cs.clone(), || Ok(self.public[i]))?;
            field(&h[16 * i..16 * (i + 1)])?.enforce_equal(&public)?;
        }
        Ok(())
    }
}
