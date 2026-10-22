//! v6 private ownership/value relation. Current spentness is enforced by native script.
use super::*;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    uint8::UInt8, uint64::UInt64,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
type B = UInt8<Fr>;
type Flag = Boolean<Fr>;
type R<T> = std::result::Result<T, SynthesisError>;
#[derive(Clone)]
pub struct Input {
    pub real: bool,
    pub note: Note,
    pub secret: H,
    pub position: u32,
    pub path: Vec<H>,
    pub dummy_key: H,
    pub dummy_seed: H,
}
impl Input {
    pub fn padding() -> Self {
        Self {
            real: false,
            note: Note::dummy(),
            secret: [0; 32],
            position: 0,
            path: vec![[0; 32]; 16],
            dummy_key: random(),
            dummy_seed: random(),
        }
    }
}
#[derive(Clone)]
pub struct Circuit {
    pub auth: Authorization,
    pub inputs: [Input; 2],
    pub outputs: [Note; 2],
}
fn field(bytes: &[B]) -> R<FpVar<Fr>> {
    let bits = bytes
        .iter()
        .map(|x| x.to_bits_le())
        .collect::<R<Vec<_>>>()?
        .concat();
    Boolean::le_bits_to_fp(&bits)
}
fn hash_g(bytes: &[B]) -> R<Vec<B>> {
    Ok(Sha256Gadget::digest(bytes)?.0)
}
fn digest(tag: &[u8], d: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut bytes = B::constant_vec(tag);
    bytes.extend_from_slice(d);
    for p in parts {
        bytes.extend_from_slice(p);
    }
    hash_g(&bytes)
}
fn bounds(cs: ConstraintSystemRef<Fr>, bytes: &[B], value: u64, min: u64, active: &Flag) -> R<()> {
    // Both slacks are UInt64; these equalities cannot wrap the 254-bit field.
    let lo = UInt64::new_witness(cs.clone(), || Ok(value.saturating_sub(min)))?;
    let hi = UInt64::new_witness(cs, || Ok(MAX_SOMPI.saturating_sub(value)))?;
    let v = field(bytes)?;
    v.conditional_enforce_equal(
        &(Boolean::le_bits_to_fp(&lo.to_bits_le()?)? + Fr::from(min)),
        active,
    )?;
    (v + Boolean::le_bits_to_fp(&hi.to_bits_le()?)?)
        .conditional_enforce_equal(&FpVar::Constant(Fr::from(MAX_SOMPI)), active)
}
fn note(
    cs: ConstraintSystemRef<Fr>,
    d: &[B],
    n: &Note,
) -> R<(Vec<B>, Vec<B>, Vec<B>, Vec<B>, Vec<B>)> {
    let owner = B::new_witness_vec(cs.clone(), &n.owner)?;
    let incoming = B::new_witness_vec(cs.clone(), &n.incoming)?;
    let value = B::new_witness_vec(cs.clone(), &n.value.to_le_bytes())?;
    let rho = B::new_witness_vec(cs, &n.rho)?;
    let cm = digest(NOTE_TAG, d, &[&owner, &incoming, &value, &rho])?;
    Ok((owner, incoming, value, rho, cm))
}

fn hmac_g(key: &[B], message: &[B]) -> R<Vec<B>> {
    let mut key = key.to_vec();
    key.extend(B::constant_vec(&[0; 32]));
    let mut inner = key
        .iter()
        .map(|x| x ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend_from_slice(message);
    let mut outer = key
        .iter()
        .map(|x| x ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(hash_g(&inner)?);
    hash_g(&outer)
}
impl Circuit {
    pub fn check(&self) -> R<(usize, bool)> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone())?;
        Ok((cs.num_constraints(), cs.is_satisfied()?))
    }
}
impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let public = self.auth.inputs();
        let a = B::new_witness_vec(cs.clone(), &self.auth.bytes())?;
        a[..8].enforce_equal(&B::constant_vec(b"KPICU06\0"))?;
        let z32 = B::constant_vec(&[0; 32]);
        let z8 = B::constant_vec(&[0; 8]);
        let d = &a[8..40];
        let admit = a[A_MODE].is_eq(&B::constant(0))?;
        let spend = a[A_MODE].is_eq(&B::constant(1))?;
        let drain = a[A_MODE].is_eq(&B::constant(2))?;
        (&admit | &spend | &drain).enforce_equal(&Flag::TRUE)?;
        let active = !&admit;
        let append = !&drain;
        let boot = !a[A_BOOT..A_CIPHER].is_eq(&z8)?;
        (&boot & &admit).enforce_equal(&Flag::FALSE)?;
        let mut in_values = Vec::new();
        let mut reals = Vec::new();
        let mut positions = Vec::new();
        for (slot, input) in self.inputs.iter().enumerate() {
            if input.path.len() != 16 {
                return Err(SynthesisError::Unsatisfiable);
            }
            let real = Flag::new_witness(cs.clone(), || Ok(input.real))?;
            (&real & &admit).enforce_equal(&Flag::FALSE)?;
            let (owner, incoming, value, rho, cm) = note(cs.clone(), d, &input.note)?;
            let secret = B::new_witness_vec(cs.clone(), &input.secret)?;
            owner
                .conditional_enforce_equal(&digest(OWNER_TAG, d, &[&secret, &incoming])?, &real)?;
            bounds(cs.clone(), &value, input.note.value, NOTE_FLOOR, &real)?;
            for bytes in [&owner[..], &incoming[..], &secret[..]] {
                bytes.conditional_enforce_equal(&z32, &!&real)?;
            }
            value.conditional_enforce_equal(&z8, &!&real)?;
            rho.conditional_enforce_equal(&z32, &!&real)?;
            let index = B::new_witness_vec(cs.clone(), &input.position.to_le_bytes())?;
            index[2..].enforce_equal(&B::constant_vec(&[0; 2]))?;
            index.conditional_enforce_equal(&B::constant_vec(&[0; 4]), &!&real)?;
            let slack = UInt64::new_witness(cs.clone(), || {
                Ok((self.auth.count as u64).saturating_sub(input.position as u64 + 1))
            })?;
            (field(&index)? + Boolean::le_bits_to_fp(&slack.to_bits_le()?)? + Fr::from(1u64))
                .conditional_enforce_equal(&field(&a[A_COUNT..A_ANCHOR])?, &real)?;
            index.conditional_enforce_equal(&B::constant_vec(&[0; 4]), &(&boot & &real))?;
            let bits = index
                .iter()
                .map(|x| x.to_bits_le())
                .collect::<R<Vec<_>>>()?
                .concat();
            let mut leaf = hash_g(&[B::constant_vec(&[0]), cm.clone()].concat())?;
            for (level, sibling) in input.path.iter().enumerate() {
                let s = B::new_witness_vec(cs.clone(), sibling)?;
                s.conditional_enforce_equal(&z32, &!&real)?;
                s.conditional_enforce_equal(
                    &B::constant_vec(&tree::empty_path(16)[level]),
                    &(&boot & &real),
                )?;
                let l = s
                    .iter()
                    .zip(&leaf)
                    .map(|(s, l)| bits[level].select(s, l))
                    .collect::<R<Vec<_>>>()?;
                let r = s
                    .iter()
                    .zip(&leaf)
                    .map(|(s, l)| bits[level].select(l, s))
                    .collect::<R<Vec<_>>>()?;
                leaf = hash_g(&[B::constant_vec(&[1]), l, r].concat())?;
            }
            leaf.as_slice()
                .conditional_enforce_equal(&a[A_ANCHOR..A_NF], &real)?;
            let real_nf = hmac_g(
                &secret,
                &[
                    B::constant_vec(crate::compact::NF_TAG),
                    d.to_vec(),
                    cm,
                    index.clone(),
                ]
                .concat(),
            )?;
            let dk = B::new_witness_vec(cs.clone(), &input.dummy_key)?;
            let seed = B::new_witness_vec(cs.clone(), &input.dummy_seed)?;
            let dummy_nf = hmac_g(
                &dk,
                &[
                    B::constant_vec(DUMMY_TAG),
                    d.to_vec(),
                    seed,
                    vec![B::constant(slot as u8)],
                ]
                .concat(),
            )?;
            let nf = &a[A_NF + slot * 32..A_NF + (slot + 1) * 32];
            nf.conditional_enforce_equal(&real_nf, &real)?;
            nf.conditional_enforce_equal(&dummy_nf, &(&active & !&real))?;
            nf.conditional_enforce_equal(&z32, &admit)?;
            nf.is_eq(&z32)?
                .conditional_enforce_equal(&Flag::FALSE, &active)?;
            in_values.push(field(&value)?);
            reals.push(real);
            positions.push(index);
        }
        (&reals[0] | &reals[1]).enforce_equal(&active)?;
        positions[0]
            .is_eq(&positions[1])?
            .conditional_enforce_equal(&Flag::FALSE, &(&reals[0] & &reals[1]))?;
        a[A_NF..A_NF + 32]
            .is_eq(&a[A_NF + 32..A_CM])?
            .conditional_enforce_equal(&Flag::FALSE, &active)?;
        // Bootstrap must consume only the unique position-zero initial note.
        (&reals[0] & &reals[1]).conditional_enforce_equal(&Flag::FALSE, &boot)?;
        let mut out_values = Vec::new();
        let mut positives = Vec::new();
        for (slot, n) in self.outputs.iter().enumerate() {
            let (_, _, v, _, cm) = note(cs.clone(), d, n)?;
            let positive = !v.is_eq(&z8)?;
            bounds(cs.clone(), &v, n.value, NOTE_FLOOR, &positive)?;
            v.conditional_enforce_equal(&z8, &drain)?;
            let target = &a[A_CM + slot * 32..A_CM + (slot + 1) * 32];
            target.conditional_enforce_equal(&cm, &append)?;
            target.conditional_enforce_equal(&z32, &drain)?;
            target
                .is_eq(&z32)?
                .conditional_enforce_equal(&Flag::FALSE, &append)?;
            out_values.push(field(&v)?);
            positives.push(positive);
        }
        a[A_CM..A_CM + 32]
            .is_eq(&a[A_CM + 32..A_MODE])?
            .conditional_enforce_equal(&Flag::FALSE, &append)?;
        let w = &a[A_PAYOUT..A_FEE];
        let f = &a[A_FEE..A_SPK];
        let dep = &a[A_DEP..A_FUND];
        let paid = !w.is_eq(&z8)?;
        bounds(cs.clone(), w, self.auth.payout, PAYOUT_FLOOR, &paid)?;
        bounds(cs.clone(), f, self.auth.fee, 1, &Flag::TRUE)?;
        bounds(cs.clone(), dep, self.auth.deposit, NOTE_FLOOR, &admit)?;
        paid.conditional_enforce_equal(&Flag::TRUE, &drain)?;
        paid.conditional_enforce_equal(&Flag::FALSE, &admit)?;
        (&positives[0] | &positives[1] | &paid).enforce_equal(&Flag::TRUE)?;
        a[A_SPK..A_DEP].conditional_enforce_equal(&B::constant_vec(&[0; 36]), &!&paid)?;
        a[A_SPK..A_SPK + 3].conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), &paid)?;
        a[A_DEP - 1].conditional_enforce_equal(&B::constant(0xac), &paid)?;
        a[A_DEP..A_BOOT].conditional_enforce_equal(&B::constant_vec(&[0; 80]), &active)?;
        a[A_COUNT..A_CM].conditional_enforce_equal(&B::constant_vec(&[0; 100]), &admit)?;
        let total = in_values[0].clone() + in_values[1].clone() + field(dep)?;
        let hi = UInt64::new_witness(cs.clone(), || {
            Ok(MAX_SOMPI.saturating_sub(
                self.inputs
                    .iter()
                    .map(|i| i.note.value as u128)
                    .sum::<u128>()
                    .saturating_add(self.auth.deposit as u128)
                    .min(u64::MAX as u128) as u64,
            ))
        })?;
        (total.clone() + Boolean::le_bits_to_fp(&hi.to_bits_le()?)?)
            .enforce_equal(&FpVar::Constant(Fr::from(MAX_SOMPI)))?;
        total.enforce_equal(
            &(out_values[0].clone() + out_values[1].clone() + field(w)? + field(f)?),
        )?;
        field(&a[A_BOOT..A_CIPHER])?
            .conditional_enforce_equal(&(in_values[0].clone() + in_values[1].clone()), &boot)?;
        a[A_COUNT..A_ANCHOR]
            .conditional_enforce_equal(&B::constant_vec(&1u32.to_le_bytes()), &boot)?;
        let digest = hash_g(&a)?;
        for i in 0..2 {
            field(&digest[16 * i..16 * (i + 1)])?
                .enforce_equal(&FpVar::new_input(cs.clone(), || Ok(public[i]))?)?;
        }
        Ok(())
    }
}
