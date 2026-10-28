//! NEW research owner-key predicate; native SHA/HMAC/range/CV helpers below are retained.
//! Source only, no current key/profile or independent Exit claim.
use crate::{exact_sha256::Sha256Gadget, *};
use ark_bn254::Fr;
use ark_ed_on_bn254::{Fr as Scalar, constraints::EdwardsVar};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    uint8::UInt8,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
type B = UInt8<Fr>;
type R<T> = core::result::Result<T, SynthesisError>;
fn digest(bytes: &[B]) -> R<Vec<B>> {
    Ok(Sha256Gadget::digest(bytes)?.0)
}
fn tagged(tag: &[u8; 8], domain: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut b = B::constant_vec(tag);
    b.extend_from_slice(domain);
    for p in parts {
        b.extend_from_slice(p)
    }
    digest(&b)
}
fn bits(bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
    Ok(bytes
        .iter()
        .map(ToBitsGadget::to_bits_le)
        .collect::<R<Vec<_>>>()?
        .concat())
}
fn field(bytes: &[B]) -> R<FpVar<Fr>> {
    if bytes.len() > 16 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::le_bits_to_fp(&bits(bytes)?)
}
fn range(value: &[B]) -> R<()> {
    bounded_u64(value, NOTE_FLOOR, MAX)
}
fn bounded_u64(value: &[B], minimum: u64, maximum: u64) -> R<()> {
    let b = bits(value)?;
    if b.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&b, [maximum])?;
    // v>=floor iff the unsigned reverse bitwise complement is <=MAX_u64-floor.
    let complement = b.iter().map(|b| !b).collect::<Vec<_>>();
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&complement, [u64::MAX - minimum])?;
    Ok(())
}
fn value_cv(cs: ConstraintSystemRef<Fr>, value: &[B], r: &H, expected: &[B]) -> R<()> {
    range(value)?;
    let r = B::new_witness_vec(cs, &r[..])?;
    let rb = bits(&r)?;
    // ALL256 bits are bounded by the subgroup scalar modulus, not BN254 Fr.
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&rb, (-Scalar::ONE).into_bigint())?;
    let vb = bits(value)?;
    let p = cv::parameters();
    if vb.len() != 64
        || rb.len() != 256
        || p.generators[0].len() != 64
        || p.randomness_generator.len() != 251
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut result = EdwardsVar::zero();
    result.precomputed_base_scalar_mul_le(vb.iter().zip(p.generators[0].iter()))?;
    result.precomputed_base_scalar_mul_le(rb[..251].iter().zip(p.randomness_generator.iter()))?;
    result.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    // Canonical full x/y bytes; this also enforces subgroup by fixed-base equality.
    result.to_bytes_le()?.as_slice().enforce_equal(expected)?;
    Ok(())
}
fn note_vars(cs: ConstraintSystemRef<Fr>, domain: &[B], note: &Note) -> R<(Vec<B>, Vec<B>)> {
    let b = B::new_witness_vec(cs, &note.bytes())?;
    let cm = tagged(NOTE_TAG, domain, &[&b])?;
    Ok((b, cm))
}
fn original_nf(domain: &[B], key: &[B], cm: &[B], position: &[B]) -> R<Vec<B>> {
    let mut inner = key
        .iter()
        .map(|b| b ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend(B::constant_vec(&[0x36; 32]));
    inner.extend(B::constant_vec(NF_TAG));
    inner.extend_from_slice(domain);
    inner.extend_from_slice(cm);
    inner.extend_from_slice(position);
    let inner = digest(&inner)?;
    let mut outer = key
        .iter()
        .map(|b| b ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(B::constant_vec(&[0x5c; 32]));
    outer.extend(inner);
    digest(&outer)
}

/// All 66 component edges are internalized by join.rs, not published PK inputs.
impl ConstraintSynthesizer<Fr> for AuthSpendCircuit {
    fn generate_constraints(self, cs:ConstraintSystemRef<Fr>)->R<()> {
        // Allocate two digest edges FIRST, then exactly 64 byte Fr edges.
        let pi=self.statement.public_inputs();
        let digest_edges=[FpVar::new_input(cs.clone(),||Ok(pi[0]))?,FpVar::new_input(cs.clone(),||Ok(pi[1]))?];
        let mut key_edges=Vec::with_capacity(64);
        for byte in self.owner_key_bytes { key_edges.push(FpVar::new_input(cs.clone(),||Ok(Fr::from(byte as u64)))?); }
        let key_bytes=B::new_witness_vec(cs.clone(),&self.owner_key_bytes)?;
        for (byte,edge) in key_bytes.iter().zip(&key_edges) { field(core::slice::from_ref(byte))?.enforce_equal(edge)?; }
        let s=B::new_witness_vec(cs.clone(),&self.statement.bytes())?;
        s[..8].enforce_equal(&B::constant_vec(AUTH_SPEND_TAG))?;
        s[8..40].enforce_equal(&B::constant_vec(&DOMAIN))?; let d=&s[8..40];
        let (n,cm)=note_vars(cs.clone(),d,&self.witness.note)?;
        cm.is_eq(&B::constant_vec(&[0;32]))?.enforce_equal(&Boolean::FALSE)?;
        let key=B::new_witness_vec(cs.clone(),&self.witness.nullifier_secret)?;
        // NEW authority binding; preserve the actual consumed incoming bytes.
        n[..32].enforce_equal(&tagged(AUTH_OWNER_TAG,d,&[&key_bytes,&n[32..64]])?)?;
        n[104..136].enforce_equal(&tagged(KEY_TAG,d,&[&key])?)?;
        value_cv(cs.clone(),&n[64..72],&self.witness.blinding,&s[104..168])?;
        let pos=B::new_witness_vec(cs.clone(),&self.witness.position.to_le_bytes())?;
        pos[2..].enforce_equal(&B::constant_vec(&[0;2]))?; let pb=bits(&pos)?;
        let mut root=cm.clone();
        for (level,sibling) in self.witness.path.iter().enumerate() {
            let sibling=B::new_witness_vec(cs.clone(),sibling)?;
            let left=sibling.iter().zip(&root).map(|(sib,r)|pb[level].select(sib,r)).collect::<R<Vec<_>>>()?;
            let right=sibling.iter().zip(&root).map(|(sib,r)|pb[level].select(r,sib)).collect::<R<Vec<_>>>()?;
            root=tagged(CM_NODE,&[],&[&left,&right])?;
        }
        root.as_slice().enforce_equal(&s[40..72])?;
        original_nf(d,&key,&cm,&pos)?.as_slice().enforce_equal(&s[72..104])?;
        s[72..104].is_eq(&B::constant_vec(&[0;32]))?.enforce_equal(&Boolean::FALSE)?;
        let dg=digest(&s)?;
        for i in 0..2 { field(&dg[i*16..i*16+16])?.enforce_equal(&digest_edges[i])?; }
        Ok(())
    }
}
impl ConstraintSynthesizer<Fr> for ReferenceOutputCircuit {
    fn generate_constraints(self,cs:ConstraintSystemRef<Fr>)->R<()> {
        let mut statement=REFERENCE_OUTPUT_TAG.to_vec(); statement.extend(self.domain); statement.extend(self.cm);
        statement.extend(self.cv); statement.extend(self.cf_hash);
        let p=native::statements::digest_fields(&native::hash(&[&statement]));
        let edges=[FpVar::new_input(cs.clone(),||Ok(p[0]))?,FpVar::new_input(cs.clone(),||Ok(p[1]))?];
        let s=B::new_witness_vec(cs.clone(),&statement)?;
        s[..8].enforce_equal(&B::constant_vec(REFERENCE_OUTPUT_TAG))?; s[8..40].enforce_equal(&B::constant_vec(&DOMAIN))?;
        let (n,cm)=note_vars(cs.clone(),&s[8..40],&self.note)?; cm.as_slice().enforce_equal(&s[40..72])?;
        value_cv(cs.clone(),&n[64..72],&self.blinding,&s[72..136])?;
        let dg=digest(&s)?; for i in 0..2 {field(&dg[i*16..i*16+16])?.enforce_equal(&edges[i])?;}
        Ok(())
    }
}
