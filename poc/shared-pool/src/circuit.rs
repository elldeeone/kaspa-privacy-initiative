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
    let flags = (0..=CAP)
        .map(|n| count.is_eq(&B::constant(n as u8)))
        .collect::<R<Vec<_>>>()?;
    any(&flags[if allow_zero { 0 } else { 1 }..]).enforce_equal(&Flag::TRUE)?;
    Ok(flags)
}
fn state(bytes: &[B]) -> R<(Vec<Flag>, Vec<Flag>)> {
    bytes[0].enforce_equal(&B::constant(2))?;
    let cm = count_flags(&bytes[1], false)?;
    let nf = count_flags(&bytes[2], true)?;
    for (i, a) in nf.iter().enumerate() {
        for b in &cm[..i] {
            (a & b).enforce_equal(&Flag::FALSE)?;
        }
    }
    let zero = B::constant_vec(&[0; 32]);
    for (start, flags) in [(3, &cm), (NF_START, &nf)] {
        for i in 0..CAP {
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
            || t.deposit.len() != 84
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let tr = B::new_witness_vec(cs.clone(), &t.bytes())?;
        let p = B::new_witness_vec(cs.clone(), &t.payload)?;
        tr[..8].enforce_equal(&B::constant_vec(b"KPIBN02\0"))?;
        p[..8].enforce_equal(&B::constant_vec(b"KPISP02\0"))?;
        let d = &tr[8..40];
        let old = &tr[40..T_PREV];
        let new = &p[9..CIPHER_START];
        let (cf, nf_flags) = state(old)?;
        state(new)?;
        let modes = (0..5)
            .map(|n| p[8].is_eq(&B::constant(n)))
            .collect::<R<Vec<_>>>()?;
        any(&modes).enforce_equal(&Flag::TRUE)?;
        let deposit = &modes[0];
        let transfer = &modes[1];
        let full = &modes[2];
        let terminal = &modes[3];
        let partial = &modes[4];
        let spending = !deposit;
        let withdraw = full | terminal | partial;
        let output0 = deposit | transfer | partial;
        let z8 = B::constant_vec(&[0; 8]);
        let z32 = B::constant_vec(&[0; 32]);
        tr[T_PREV + 36..T_PREV + 40].enforce_equal(&B::constant_vec(&[0; 4]))?;
        let rin = &tr[T_RIN..T_ROUT];
        let rout = &tr[T_ROUT..T_PAYOUT];
        let payout = &tr[T_PAYOUT..T_PSPK];
        rin.is_eq(&z8)?.enforce_equal(&Flag::FALSE)?;
        rout.is_eq(&z8)?.enforce_equal(terminal)?;
        payout.is_eq(&z8)?.enforce_equal(&!&withdraw)?;
        tr[T_PSPK..T_DEP].conditional_enforce_equal(&B::constant_vec(&[0; 36]), &!&withdraw)?;
        tr[T_PSPK..T_PSPK + 3]
            .conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), &withdraw)?;
        tr[T_DEP - 1].conditional_enforce_equal(&B::constant(0xac), &withdraw)?;
        tr[T_DEP..T_HASH].conditional_enforce_equal(&B::constant_vec(&[0; 84]), &spending)?;
        tr[T_DEP + 36..T_DEP + 40].enforce_equal(&B::constant_vec(&[0; 4]))?;
        tr[T_DEP + 48..T_DEP + 51]
            .conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), deposit)?;
        tr[T_HASH - 1].conditional_enforce_equal(&B::constant(0xac), deposit)?;
        let dep = &tr[T_DEP + 40..T_DEP + 48];
        dep.is_eq(&z8)?.enforce_equal(&spending)?;
        p[CIPHER_START..CIPHER_START + 185]
            .conditional_enforce_equal(&B::constant_vec(&[0; 185]), &!&output0)?;
        p[CIPHER_START + 185..]
            .conditional_enforce_equal(&B::constant_vec(&[0; 185]), &!transfer)?;
        let secret = B::new_witness_vec(cs.clone(), &self.secret)?;
        let (owner, view, value, input_cm) = note(cs.clone(), d, &self.input)?;
        owner.conditional_enforce_equal(&digest(OWNER_TAG, d, &[&secret, &view])?, &spending)?;
        value.is_eq(&z8)?.enforce_equal(deposit)?;
        let memberships = (0..CAP)
            .map(|i| {
                Ok(input_cm.as_slice().is_eq(&old[3 + 32 * i..35 + 32 * i])? & any(&cf[i + 1..]))
            })
            .collect::<R<Vec<_>>>()?;
        any(&memberships).conditional_enforce_equal(&Flag::TRUE, &spending)?;
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
        nf.is_eq(&z32)?
            .conditional_enforce_equal(&Flag::FALSE, &spending)?;
        for i in 0..CAP {
            nf.as_slice()
                .is_eq(&old[NF_START + 32 * i..NF_START + 32 * (i + 1)])?
                .conditional_enforce_equal(&Flag::FALSE, &spending)?;
        }
        let mut vals = Vec::new();
        let mut cms = Vec::new();
        for (i, n) in self.outputs.iter().enumerate() {
            let (_, _, v, cm) = note(cs.clone(), d, n)?;
            let active = if i == 0 {
                output0.clone()
            } else {
                transfer.clone()
            };
            v.is_eq(&z8)?.enforce_equal(&!active)?;
            vals.push(field(&v)?);
            cms.push(cm);
        }
        cms[0]
            .is_eq(&cms[1])?
            .conditional_enforce_equal(&Flag::FALSE, transfer)?;
        let fp = |f: &Flag| Boolean::le_bits_to_fp(&[f.clone()]);
        field(&new[1..2])?.enforce_equal(&(field(&old[1..2])? + fp(&output0)? + fp(transfer)?))?;
        field(&new[2..3])?.enforce_equal(&(field(&old[2..3])? + fp(&spending)?))?;
        for i in 0..CAP {
            let first = &cf[i] & &output0;
            let second = if i == 0 {
                Flag::FALSE
            } else {
                &cf[i - 1] & transfer
            };
            let inserted = choose(&first, &cms[0], &choose(&second, &cms[1], &z32)?)?;
            let expected = choose(&any(&cf[i + 1..]), &old[3 + 32 * i..35 + 32 * i], &inserted)?;
            new[3 + 32 * i..35 + 32 * i].enforce_equal(&expected)?;
            let inserted = choose(&(&nf_flags[i] & &spending), &nf, &z32)?;
            let expected = choose(
                &any(&nf_flags[i + 1..]),
                &old[NF_START + 32 * i..NF_START + 32 * (i + 1)],
                &inserted,
            )?;
            new[NF_START + 32 * i..NF_START + 32 * (i + 1)].enforce_equal(&expected)?;
        }
        let fee = B::new_witness_vec(cs.clone(), &self.fee.to_le_bytes())?;
        fee.is_eq(&z8)?.enforce_equal(&Flag::FALSE)?;
        // All operands are UInt64/byte decompositions; sums are below Fr.
        (field(rin)? + field(dep)?)
            .enforce_equal(&(field(rout)? + field(payout)? + field(&fee)?))?;
        (field(&value)? + field(dep)?)
            .enforce_equal(&(vals[0].clone() + vals[1].clone() + field(payout)? + field(&fee)?))?;
        // Before anyone joins, the first private spend proves the sole initial
        // liability against the actual reserve. Deposits cannot skip bootstrap.
        let genesis = &nf_flags[0];
        old[1].conditional_enforce_equal(&B::constant(1), genesis)?;
        deposit.conditional_enforce_equal(&Flag::FALSE, genesis)?;
        value.as_slice().conditional_enforce_equal(rin, genesis)?;
        value.as_slice().conditional_enforce_equal(rin, terminal)?;
        new[2].is_eq(&new[1])?.enforce_equal(terminal)?;
        Sha256Gadget::digest(&p)?
            .0
            .as_slice()
            .enforce_equal(&tr[T_HASH..])?;
        let h = Sha256Gadget::digest(&tr)?.0;
        for i in 0..2 {
            let public = FpVar::new_input(cs.clone(), || Ok(self.public[i]))?;
            field(&h[16 * i..16 * (i + 1)])?.enforce_equal(&public)?;
        }
        Ok(())
    }
}
