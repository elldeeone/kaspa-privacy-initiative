//! Private ownership/value authorization. Current spentness and reserve checks
//! are deliberately native covenant predicates, not omitted security predicates.
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
pub struct AuthorizationCircuit {
    pub auth: Authorization,
    pub path: tree::Path,
    pub position: u32,
    pub secret: H,
    pub input: Note,
    pub outputs: [Note; 2],
    pub public: [Fr; 2],
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
fn note(cs: ConstraintSystemRef<Fr>, d: &[B], n: &Note) -> R<(Vec<B>, Vec<B>, Vec<B>, Vec<B>)> {
    let owner = B::new_witness_vec(cs.clone(), &n.owner)?;
    let incoming = B::new_witness_vec(cs.clone(), &n.incoming)?;
    let value = B::new_witness_vec(cs.clone(), &n.value.to_le_bytes())?;
    let rho = B::new_witness_vec(cs, &n.rho)?;
    let cm = digest(NOTE_TAG, d, &[&owner, &incoming, &value, &rho])?;
    Ok((owner, incoming, value, cm))
}
impl AuthorizationCircuit {
    pub fn check(&self) -> R<(usize, bool)> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone())?;
        Ok((cs.num_constraints(), cs.is_satisfied()?))
    }
}
impl ConstraintSynthesizer<Fr> for AuthorizationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        if self.position as usize >= tree::LIMIT {
            return Err(SynthesisError::Unsatisfiable);
        }
        let a = B::new_witness_vec(cs.clone(), &self.auth.bytes())?;
        a[..8].enforce_equal(&B::constant_vec(b"KPICU01\0"))?;
        let d = &a[8..40];
        let z8 = B::constant_vec(&[0; 8]);
        let z32 = B::constant_vec(&[0; 32]);
        let transfer = a[A_MODE].is_eq(&B::constant(1))?;
        let exit = a[A_MODE].is_eq(&B::constant(2))?;
        (&transfer | &exit).enforce_equal(&Flag::TRUE)?;
        let secret = B::new_witness_vec(cs.clone(), &self.secret)?;
        let (owner, view, value, input_cm) = note(cs.clone(), d, &self.input)?;
        owner.enforce_equal(&digest(OWNER_TAG, d, &[&secret, &view])?)?;
        bounds(
            cs.clone(),
            &value,
            self.input.value,
            NOTE_FLOOR,
            &Flag::TRUE,
        )?;
        let index = B::new_witness_vec(cs.clone(), &self.position.to_le_bytes())?;
        index[2..].enforce_equal(&B::constant_vec(&[0,0]))?;
        let slack = UInt64::new_witness(cs.clone(), || Ok((self.auth.count as u64).saturating_sub(1 + self.position as u64)))?;
        (field(&index)? + Boolean::le_bits_to_fp(&slack.to_bits_le()?)? + Fr::from(1u64))
            .enforce_equal(&field(&a[A_COUNT..A_ANCHOR])?)?;
        let bits = index.iter().map(|x| x.to_bits_le()).collect::<R<Vec<_>>>()?.concat();
        let mut leaf = hash_g(&[B::constant_vec(&[0]), input_cm.clone()].concat())?;
        for (level, sibling) in self.path.iter().enumerate() {
            let s = B::new_witness_vec(cs.clone(), sibling)?;
            let left = s.iter().zip(&leaf).map(|(s,l)|bits[level].select(s,l)).collect::<R<Vec<_>>>()?;
            let right = s.iter().zip(&leaf).map(|(s,l)|bits[level].select(l,s)).collect::<R<Vec<_>>>()?;
            leaf = hash_g(&[B::constant_vec(&[1]), left, right].concat())?;
        }
        leaf.as_slice().enforce_equal(&a[A_ANCHOR..A_NF])?;
        let mut padded = secret;
        padded.extend(B::constant_vec(&[0; 32]));
        let mut inner = padded
            .iter()
            .map(|b| b ^ B::constant(0x36))
            .collect::<Vec<_>>();
        inner.extend(B::constant_vec(NF_TAG));
        inner.extend_from_slice(d);
        inner.extend_from_slice(&input_cm);
        inner.extend_from_slice(&index);
        let mut outer = padded
            .iter()
            .map(|b| b ^ B::constant(0x5c))
            .collect::<Vec<_>>();
        outer.extend(hash_g(&inner)?);
        hash_g(&outer)?.as_slice().enforce_equal(&a[A_NF..A_CM])?;
        a[A_NF..A_CM].is_eq(&z32)?.enforce_equal(&Flag::FALSE)?;
        let mut values = Vec::new();
        for (i, n) in self.outputs.iter().enumerate() {
            let (_, _, v, cm) = note(cs.clone(), d, n)?;
            v.is_eq(&z8)?.enforce_equal(&exit)?;
            bounds(cs.clone(), &v, n.value, NOTE_FLOOR, &transfer)?;
            let public_cm = &a[A_CM + 32 * i..A_CM + 32 * (i + 1)];
            cm.as_slice()
                .conditional_enforce_equal(public_cm, &transfer)?;
            public_cm.conditional_enforce_equal(&z32, &exit)?;
            public_cm.is_eq(&z32)?.enforce_equal(&exit)?;
            values.push(field(&v)?);
        }
        a[A_CM..A_CM + 32]
            .is_eq(&a[A_CM + 32..A_MODE])?
            .conditional_enforce_equal(&Flag::FALSE, &transfer)?;
        let payout = &a[A_PAYOUT..A_FEE];
        let fee = &a[A_FEE..A_SPK];
        payout.is_eq(&z8)?.enforce_equal(&transfer)?;
        bounds(cs.clone(), payout, self.auth.payout, PAYOUT_FLOOR, &exit)?;
        bounds(cs.clone(), fee, self.auth.fee, 1, &Flag::TRUE)?;
        a[A_SPK..A_BOOT].conditional_enforce_equal(&B::constant_vec(&[0; 36]), &transfer)?;
        a[A_SPK..A_SPK + 3].conditional_enforce_equal(&B::constant_vec(&[0, 0, 0x20]), &exit)?;
        a[A_BOOT - 1].conditional_enforce_equal(&B::constant(0xac), &exit)?;
        field(&value)?.enforce_equal(
            &(values[0].clone() + values[1].clone() + field(payout)? + field(fee)?),
        )?;
        let bootstrap = &a[A_BOOT..A_CIPHER];
        let boot_active = !bootstrap.is_eq(&z8)?;
        bootstrap.conditional_enforce_equal(&value, &boot_active)?;
        let h = hash_g(&a)?;
        for i in 0..2 {
            field(&h[16 * i..16 * (i + 1)])?
                .enforce_equal(&FpVar::new_input(cs.clone(), || Ok(self.public[i]))?)?;
        }
        Ok(())
    }
}
