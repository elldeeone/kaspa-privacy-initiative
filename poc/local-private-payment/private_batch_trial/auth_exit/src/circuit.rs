//! Native SHA/HMAC/membership/range/CV constraints adapted from ADR-0066.
//! The changed authority is AK-bound and has its own mature signature join.
use crate::{exact_sha256::Sha256Gadget, *};
use ark_bn254::Fr;
use ark_ed_on_bn254::{Fr as Scalar, constraints::EdwardsVar};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget}, eq::EqGadget, fields::fp::FpVar,
    groups::CurveVar, uint8::UInt8,
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
type B = UInt8<Fr>;
type R<T> = Result<T, SynthesisError>;

fn digest(bytes: &[B]) -> R<Vec<B>> { Ok(Sha256Gadget::digest(bytes)?.0) }
fn tagged(tag: &[u8; 8], domain: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut bytes = B::constant_vec(tag); bytes.extend_from_slice(domain);
    for part in parts { bytes.extend_from_slice(part); } digest(&bytes)
}
fn bits(bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
    Ok(bytes.iter().map(ToBitsGadget::to_bits_le).collect::<R<Vec<_>>>()?.concat())
}
fn field(bytes: &[B]) -> R<FpVar<Fr>> {
    if bytes.len() > 16 { return Err(SynthesisError::Unsatisfiable); }
    Boolean::le_bits_to_fp(&bits(bytes)?)
}
fn bounded(bytes: &[B], minimum: u64, maximum: u64) -> R<()> {
    let bits = bits(bytes)?;
    if bits.len() != 64 { return Err(SynthesisError::Unsatisfiable); }
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&bits, [maximum])?;
    let complement = bits.iter().map(|bit| !bit).collect::<Vec<_>>();
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&complement, [u64::MAX - minimum])?;
    Ok(())
}
fn bind_digest(bytes: &[B], edges: &[FpVar<Fr>; 2]) -> R<()> {
    let digest = digest(bytes)?;
    for i in 0..2 { field(&digest[i * 16..i * 16 + 16])?.enforce_equal(&edges[i])?; }
    Ok(())
}
fn note_vars(cs: ConstraintSystemRef<Fr>, domain: &[B], note: &Note) -> R<(Vec<B>, Vec<B>)> {
    let note = B::new_witness_vec(cs, &note.bytes())?;
    let cm = tagged(native::NOTE_TAG, domain, &[&note])?; Ok((note, cm))
}
fn original_nf(domain: &[B], key: &[B], cm: &[B], position: &[B]) -> R<Vec<B>> {
    let mut inner = key.iter().map(|b| b ^ B::constant(0x36)).collect::<Vec<_>>();
    inner.extend(B::constant_vec(&[0x36; 32])); inner.extend(B::constant_vec(native::NF_TAG));
    inner.extend_from_slice(domain); inner.extend_from_slice(cm); inner.extend_from_slice(position);
    let inner = digest(&inner)?;
    let mut outer = key.iter().map(|b| b ^ B::constant(0x5c)).collect::<Vec<_>>();
    outer.extend(B::constant_vec(&[0x5c; 32])); outer.extend(inner); digest(&outer)
}
fn membership(cs: ConstraintSystemRef<Fr>, cm: &[B], position: u32, path: &[H; CM_DEPTH]) -> R<(Vec<B>, Vec<B>)> {
    let position = B::new_witness_vec(cs.clone(), &position.to_le_bytes())?;
    position[2..].enforce_equal(&B::constant_vec(&[0; 2]))?;
    let position_bits = bits(&position)?; let mut root = cm.to_vec();
    for (level, sibling) in path.iter().enumerate() {
        let sibling = B::new_witness_vec(cs.clone(), sibling)?;
        let left = sibling.iter().zip(&root).map(|(s, r)| position_bits[level].select(s, r)).collect::<R<Vec<_>>>()?;
        let right = sibling.iter().zip(&root).map(|(s, r)| position_bits[level].select(r, s)).collect::<R<Vec<_>>>()?;
        root = tagged(native::CM_NODE, &[], &[&left, &right])?;
    }
    Ok((root, position))
}
fn value_cv(cs: ConstraintSystemRef<Fr>, value: &[B], blinding: &H, expected: &[B]) -> R<()> {
    bounded(value, NOTE_FLOOR, MAX)?;
    let r = B::new_witness_vec(cs, &blinding[..])?; let rb = bits(&r)?;
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&rb, (-Scalar::ONE).into_bigint())?;
    let vb = bits(value)?; let parameters = native::cv::parameters();
    if vb.len() != 64 || rb.len() != 256 || parameters.generators[0].len() != 64 || parameters.randomness_generator.len() != 251 { return Err(SynthesisError::Unsatisfiable); }
    let mut result = EdwardsVar::zero();
    result.precomputed_base_scalar_mul_le(vb.iter().zip(parameters.generators[0].iter()))?;
    result.precomputed_base_scalar_mul_le(rb[..251].iter().zip(parameters.randomness_generator.iter()))?;
    result.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    result.to_bytes_le()?.as_slice().enforce_equal(expected)?; Ok(())
}

impl ConstraintSynthesizer<Fr> for AuthExitCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let inputs = self.statement.public_inputs();
        let edges = [FpVar::new_input(cs.clone(), || Ok(inputs[0]))?, FpVar::new_input(cs.clone(), || Ok(inputs[1]))?];
        let mut key_edges = Vec::with_capacity(64);
        for byte in self.witness.owner_key { key_edges.push(FpVar::new_input(cs.clone(), || Ok(Fr::from(byte as u64)))?); }
        let key = B::new_witness_vec(cs.clone(), &self.witness.owner_key)?;
        for (byte, edge) in key.iter().zip(&key_edges) { field(core::slice::from_ref(byte))?.enforce_equal(edge)?; }
        let statement = B::new_witness_vec(cs.clone(), &self.statement.bytes())?;
        statement[..8].enforce_equal(&B::constant_vec(AUTH_EXIT_TAG))?;
        statement[8..40].enforce_equal(&B::constant_vec(&self.profile.domain))?;
        let domain = &statement[8..40];
        let (note, cm) = note_vars(cs.clone(), domain, &self.witness.note)?;
        cm.is_eq(&B::constant_vec(&[0; 32]))?.enforce_equal(&Boolean::FALSE)?;
        note[..32].enforce_equal(&tagged(AUTH_OWNER_TAG, domain, &[&key, &note[32..64]])?)?;
        let nk = B::new_witness_vec(cs.clone(), &self.witness.nullifier_key)?;
        note[104..136].enforce_equal(&tagged(native::KEY_TAG, domain, &[&nk])?)?;
        bounded(&note[64..72], NOTE_FLOOR, MAX)?;
        bounded(&statement[136..144], PAYOUT_FLOOR, MAX)?;
        bounded(&statement[144..152], 1, MAX)?;
        // Exact integer equality: all terms bounded u64, sum below 2^65 << Fr.
        field(&note[64..72])?.enforce_equal(&(field(&statement[136..144])? + field(&statement[144..152])?))?;
        let (root, position) = membership(cs.clone(), &cm, self.witness.position, &self.witness.path)?;
        root.as_slice().enforce_equal(&statement[40..72])?;
        original_nf(domain, &nk, &cm, &position)?.as_slice().enforce_equal(&statement[72..104])?;
        statement[72..104].is_eq(&B::constant_vec(&[0; 32]))?.enforce_equal(&Boolean::FALSE)?;
        // Exact native payout destination/state/profile live in the effects digest.
        // The new native policy must independently reconstruct that full digest;
        // this membership/authority relation is not an accepted-head oracle.
        bind_digest(&statement, &edges)
    }
}

impl ConstraintSynthesizer<Fr> for OutputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R<()> {
        let inputs = self.statement.public_inputs();
        let edges = [FpVar::new_input(cs.clone(), || Ok(inputs[0]))?, FpVar::new_input(cs.clone(), || Ok(inputs[1]))?];
        let statement = B::new_witness_vec(cs.clone(), &self.statement.bytes())?;
        statement[..8].enforce_equal(&B::constant_vec(OUTPUT_TAG))?;
        statement[8..40].enforce_equal(&B::constant_vec(&self.profile.domain))?;
        let (note, cm) = note_vars(cs.clone(), &statement[8..40], &self.witness.note)?;
        cm.as_slice().enforce_equal(&statement[40..72])?;
        value_cv(cs, &note[64..72], &self.witness.blinding, &statement[72..136])?;
        // The actual CF hash is committed. Encryption correctness stays the
        // explicit deterministic receiver-validation boundary of RFC-0030.
        bind_digest(&statement, &edges)
    }
}
