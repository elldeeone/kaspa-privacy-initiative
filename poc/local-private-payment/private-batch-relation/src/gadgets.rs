//! Reuse of the retained Native SHA/HMAC, membership, integer and Pedersen
//! contracts. No caller-supplied signature/path/financial validity Boolean.
use crate::{H, MAX, NOTE_FLOOR, cv, exact_sha256::Sha256Gadget};
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
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

pub type B = UInt8<Fr>;
pub type R<T> = Result<T, SynthesisError>;
pub fn hash(bytes: &[B]) -> R<Vec<B>> {
    Ok(Sha256Gadget::digest(bytes)?.0)
}
pub fn tagged(tag: &[u8], domain: &[B], parts: &[&[B]]) -> R<Vec<B>> {
    let mut b = B::constant_vec(tag);
    b.extend_from_slice(domain);
    for p in parts {
        b.extend_from_slice(p);
    }
    hash(&b)
}
pub fn bits(bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
    Ok(bytes
        .iter()
        .map(ToBitsGadget::to_bits_le)
        .collect::<R<Vec<_>>>()?
        .concat())
}
pub fn number(bytes: &[B]) -> R<FpVar<Fr>> {
    if bytes.len() > 16 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::le_bits_to_fp(&bits(bytes)?)
}
pub fn bounded_u64(bytes: &[B], minimum: u64, maximum: u64) -> R<()> {
    let b = bits(bytes)?;
    if b.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&b, [maximum])?;
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(
        &b.iter().map(|x| !x).collect::<Vec<_>>(),
        [u64::MAX - minimum],
    )?;
    Ok(())
}
pub fn bounded_fee_sum(sum: &FpVar<Fr>) -> R<()> {
    // Three canonical u64 fees need66 bits before the separate nativeu64 bound.
    for bit in &sum.to_bits_le()?[66..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}
pub fn less_than(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> R<Boolean<Fr>> {
    if a.len() != b.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut equal = Boolean::TRUE;
    let mut less = Boolean::FALSE;
    for (x, y) in a.iter().zip(b).rev() {
        less = &less | &(&equal & &(!x & y));
        equal = &equal & &(!(x ^ y));
    }
    Ok(less)
}
pub fn scalar_bits(bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
    let b = bits(bytes)?;
    if b.len() != 256 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&b, (-Scalar::ONE).into_bigint())?;
    Ok(b)
}
pub fn scalar_field(bytes: &[B]) -> R<FpVar<Fr>> {
    Boolean::le_bits_to_fp(&scalar_bits(bytes)?)
}
pub fn bind_delta_sum(cs: ConstraintSystemRef<Fr>, private: &[FpVar<Fr>], public: &[B], quotient: u8) -> R<()> {
    if private.len()!=3 { return Err(SynthesisError::Unsatisfiable); }
    let delta=scalar_field(public)?;
    let k=B::new_witness_vec(cs,&[quotient])?;
    Boolean::<Fr>::enforce_smaller_or_equal_than_le(&bits(&k)?,[2])?;
    let q:Fr=cv::SCALAR_MODULUS_DECIMAL.parse().expect("fixed canonical Q below Fr");
    // Each private input was Q-bounded in its owner-local component. Both
    // sides are <3Q<Fr, so this is an exact integer equality, never a P wrap.
    private.iter().cloned().sum::<FpVar<Fr>>().enforce_equal(&(delta+number(&k)?*q))
}
pub fn commitment(value: &[B], blind: &[B], expected: &[B]) -> R<EdwardsVar> {
    bounded_u64(value, NOTE_FLOOR, MAX)?;
    let rb = scalar_bits(blind)?;
    let vb = bits(value)?;
    let p = cv::parameters();
    if p.generators[0].len() != 64 || p.randomness_generator.len() != 251 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut result = EdwardsVar::zero();
    result.precomputed_base_scalar_mul_le(vb.iter().zip(p.generators[0].iter()))?;
    result.precomputed_base_scalar_mul_le(rb[..251].iter().zip(p.randomness_generator.iter()))?;
    result.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    result.to_bytes_le()?.as_slice().enforce_equal(expected)?;
    Ok(result)
}
pub fn nullifier(domain: &[B], key: &[B], cm: &[B], position: &[B]) -> R<Vec<B>> {
    let mut inner = key
        .iter()
        .map(|b| b ^ B::constant(0x36))
        .collect::<Vec<_>>();
    inner.extend(B::constant_vec(&[0x36; 32]));
    inner.extend(B::constant_vec(auth::NF_TAG));
    inner.extend_from_slice(domain);
    inner.extend_from_slice(cm);
    inner.extend_from_slice(position);
    let inner = hash(&inner)?;
    let mut outer = key
        .iter()
        .map(|b| b ^ B::constant(0x5c))
        .collect::<Vec<_>>();
    outer.extend(B::constant_vec(&[0x5c; 32]));
    outer.extend(inner);
    hash(&outer)
}
pub fn membership(
    leaf: &[B],
    position: &[B],
    path: &[H; 16],
    cs: ConstraintSystemRef<Fr>,
) -> R<Vec<B>> {
    let pb = bits(position)?;
    if pb.len() != 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    for bit in &pb[16..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    let mut root = leaf.to_vec();
    for (level, sibling) in path.iter().enumerate() {
        let sibling = B::new_witness_vec(cs.clone(), sibling)?;
        let left = sibling
            .iter()
            .zip(&root)
            .map(|(s, r)| pb[level].select(s, r))
            .collect::<R<Vec<_>>>()?;
        let right = sibling
            .iter()
            .zip(&root)
            .map(|(s, r)| pb[level].select(r, s))
            .collect::<R<Vec<_>>>()?;
        root = tagged(auth::CM_NODE, &[], &[&left, &right])?;
    }
    Ok(root)
}

pub fn permutation<const N: usize>(
    cs: ConstraintSystemRef<Fr>,
    values: &[[Fr; N]; N],
) -> R<Vec<Vec<FpVar<Fr>>>> {
    let mut rows = Vec::with_capacity(N);
    for row in values {
        let mut allocated = Vec::with_capacity(N);
        for v in row {
            let edge = FpVar::new_witness(cs.clone(), || Ok(*v))?;
            (&edge * (&edge - Fr::ONE)).enforce_equal(&FpVar::Constant(Fr::from(0u64)))?;
            allocated.push(edge);
        }
        rows.push(allocated);
    }
    for i in 0..N {
        rows[i]
            .iter()
            .cloned()
            .sum::<FpVar<Fr>>()
            .enforce_equal(&FpVar::Constant(Fr::ONE))?;
        (0..N)
            .map(|j| rows[j][i].clone())
            .sum::<FpVar<Fr>>()
            .enforce_equal(&FpVar::Constant(Fr::ONE))?;
    }
    Ok(rows)
}
pub fn route(rows: &[Vec<B>], public: &[Vec<B>], selector: &[Vec<FpVar<Fr>>]) -> R<()> {
    if rows.len() != public.len() || rows.len() != selector.len() || rows.is_empty() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let width = rows[0].len();
    if rows.iter().chain(public).any(|r| r.len() != width) {
        return Err(SynthesisError::Unsatisfiable);
    }
    for col in 0..rows.len() {
        for byte in 0..width {
            let mut sum = FpVar::Constant(Fr::from(0u64));
            for row in 0..rows.len() {
                sum += &selector[row][col] * number(&rows[row][byte..byte + 1])?;
            }
            sum.enforce_equal(&number(&public[col][byte..byte + 1])?)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::ConstraintSystem;
    fn sat(values: [[u64; 3]; 3]) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let v = values.map(|r| r.map(Fr::from));
        permutation(cs.clone(), &v).unwrap();
        cs.is_satisfied().unwrap()
    }
    #[test]
    fn permutations_require_boolean_rows_and_columns() {
        assert!(sat([[1, 0, 0], [0, 0, 1], [0, 1, 0]]));
        assert!(!sat([[1, 0, 0], [1, 0, 0], [0, 0, 1]]));
        assert!(!sat([[2, 0, 0], [0, 1, 0], [0, 0, 1]]));
        assert!(!sat([[0, 0, 0], [0, 1, 0], [0, 0, 1]]));
    }
    #[test]
    fn bytewise_comparison_does_not_reduce_256_bits_mod_fr() {
        for (a, b, expected) in [
            ([0u8; 32], [255u8; 32], true),
            ([255u8; 32], [0u8; 32], false),
            ([255u8; 32], [255u8; 32], false),
        ] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = B::new_witness_vec(cs.clone(), &a).unwrap();
            let b = B::new_witness_vec(cs.clone(), &b).unwrap();
            less_than(&bits(&a).unwrap(), &bits(&b).unwrap())
                .unwrap()
                .enforce_equal(&Boolean::constant(expected))
                .unwrap();
            assert!(cs.is_satisfied().unwrap());
        }
    }
    #[test]
    fn whole_rows_cannot_be_spliced_between_permutation_columns() {
        for altered in [false, true] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let rows = [vec![1, 2], vec![3, 4], vec![5, 6]]
                .iter()
                .map(|r| B::new_witness_vec(cs.clone(), r).unwrap())
                .collect::<Vec<_>>();
            let wanted = if altered {
                vec![vec![3, 6], vec![5, 4], vec![1, 2]]
            } else {
                vec![vec![3, 4], vec![5, 6], vec![1, 2]]
            };
            let public = wanted
                .iter()
                .map(|r| B::new_witness_vec(cs.clone(), r).unwrap())
                .collect::<Vec<_>>();
            let values = [[0u64, 0, 1], [1, 0, 0], [0, 1, 0]].map(|r| r.map(Fr::from));
            let selectors = permutation(cs.clone(), &values).unwrap();
            route(&rows, &public, &selectors).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), !altered);
        }
    }
    #[test]
    fn bounded_sompi_rejects_below_floor_and_u64_extremes() {
        for (value, expected) in [
            (NOTE_FLOOR, true),
            (MAX, true),
            (NOTE_FLOOR - 1, false),
            (MAX + 1, false),
            (u64::MAX, false),
        ] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = B::new_witness_vec(cs.clone(), &value.to_le_bytes()).unwrap();
            bounded_u64(&b, NOTE_FLOOR, MAX).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), expected);
        }
    }
    #[test]
    fn scalar_bounds_use_q_instead_of_constraint_field_p() {
        let maximum = cv::scalar_bytes(&(-Scalar::ONE));
        let mut modulus = maximum;
        for byte in &mut modulus {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        for (value, expected) in [
            ([0; 32], true),
            (maximum, true),
            (modulus, false),
            ([255; 32], false),
        ] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let b = B::new_witness_vec(cs.clone(), &value).unwrap();
            scalar_bits(&b).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), expected);
        }
    }
    #[test]
    fn three_fee_intermediate_has_exactly_66_bits() {
        for (value, expected) in [
            (0u128, true),
            (3 * u64::MAX as u128, true),
            ((1u128 << 66) - 1, true),
            (1u128 << 66, false),
        ] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let value = Fr::from_le_bytes_mod_order(&value.to_le_bytes());
            let sum = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
            bounded_fee_sum(&sum).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), expected);
        }
    }
    #[test]
    fn private_delta_sum_requires_q_ranges_exact_quotient_and_public_delta() {
        let maximum=cv::scalar_bytes(&(-Scalar::ONE));
        let mut modulus=maximum;
        for byte in &mut modulus {let(n,c)=byte.overflowing_add(1);*byte=n;if !c {break;}}
        let mut alias=modulus;alias[0]+=1;
        let one=cv::scalar_bytes(&Scalar::from(1u64));let zero=[0;32];
        let qm3=cv::scalar_bytes(&(-Scalar::from(3u64)));
        for (private,public,k,expected) in [
            ([zero,zero,zero],zero,0,true),
            ([maximum,one,zero],zero,1,true),
            ([maximum,maximum,maximum],qm3,2,true),
            ([maximum,one,zero],one,1,false),
            ([zero,zero,zero],zero,3,false),
            ([alias,zero,zero],one,1,false),
            ([maximum,one,zero],modulus,0,false),
        ] {
            let cs=ConstraintSystem::<Fr>::new_ref();
            let values=private.iter().map(|v|{
                let b=B::new_witness_vec(cs.clone(),v).unwrap();scalar_field(&b).unwrap()
            }).collect::<Vec<_>>();
            let public=B::new_witness_vec(cs.clone(),&public).unwrap();
            bind_delta_sum(cs.clone(),&values,&public,k).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(),expected);
        }
    }
}
