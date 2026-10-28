//! Exact Ark0.6 joint-column recipes. Public structural branches only.
//!
//! Wallet-local gadgets remain complete owner inputs. This adapter records the
//! existing joint Boolean/Fp/SHA operations at their actual allocated IDs. The
//! retained Fp equality inverse uses fixed public exponent P-2 (zero maps zero),
//! then reproduces Ark's equal-case multiplier1. No sample values are read.
use crate::{
    cv,
    gadgets::{B, R, bits, number},
    trace::{Lc, TraceBuilder},
    trace_sha256::{ark_bit, ark_lc, digest_with_ark_trace},
};
use ark_bn254::Fr;
use ark_ed_on_bn254::Fr as Scalar;
use ark_ff::{AdditiveGroup, BigInteger, BitIteratorBE, Field, PrimeField};
use ark_r1cs_std::{
    GR1CSVar, alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

fn err(_: crate::trace::Error) -> SynthesisError {
    SynthesisError::Unsatisfiable
}
fn field_lc(v: &FpVar<Fr>) -> R<Lc> {
    match v {
        FpVar::Constant(x) => Ok(Lc::constant(*x)),
        FpVar::Var(x) => ark_lc(&x.cs, LinearCombination::from(x.variable)).map_err(err),
    }
}
pub(crate) struct JointArk<'a> {
    trace: Option<&'a mut TraceBuilder>,
}
impl<'a> JointArk<'a> {
    pub fn new(trace: Option<&'a mut TraceBuilder>) -> Self {
        Self { trace }
    }
    fn bool_op(&mut self, a: &Boolean<Fr>, b: &Boolean<Fr>, kind: u8) -> R<Boolean<Fr>> {
        let cs = a.cs().or(b.cs());
        let before = cs.num_witness_variables();
        let result = match kind {
            0 => a & b,
            1 => a ^ b,
            2 => a | b,
            _ => return Err(SynthesisError::Unsatisfiable),
        };
        if let Some(t) = self.trace.as_deref_mut() {
            if cs.num_witness_variables() != before {
                if cs.num_witness_variables() != before + 1
                    || result.variable() != Variable::witness(before)
                {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let aa = ark_bit(a).map_err(err)?;
                let bb = ark_bit(b).map_err(err)?;
                let (left, add) = match kind {
                    0 => (aa, Lc::zero()),
                    1 => (aa.scaled(-Fr::from(2u64)), aa.plus(&bb)),
                    _ => (aa.scaled(-Fr::ONE), aa.plus(&bb)),
                };
                t.assign_muladd(cs.num_instance_variables() + before, left, bb, add)
                    .map_err(err)?;
            }
        }
        Ok(result)
    }
    fn inverse_or_zero(t: &mut TraceBuilder, value: &Lc) -> R<Lc> {
        let mut exponent = (-Fr::ONE).into_bigint();
        exponent.sub_with_borrow(&ark_ff::BigInt::from(1u64));
        let mut result = Lc::constant(Fr::ONE);
        for bit in BitIteratorBE::without_leading_zeros(exponent) {
            result = t.muladd(result.clone(), result, Lc::zero()).map_err(err)?;
            if bit {
                result = t.muladd(result, value.clone(), Lc::zero()).map_err(err)?;
            }
        }
        Ok(result)
    }
    fn fp_eq(&mut self, a: &FpVar<Fr>, b: &FpVar<Fr>) -> R<Boolean<Fr>> {
        let cs = a.cs().or(b.cs());
        let before = cs.num_witness_variables();
        let result = a.is_eq(b)?;
        if let Some(t) = self.trace.as_deref_mut() {
            if cs.num_witness_variables() != before {
                if cs.num_witness_variables() != before + 2 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                // FpVar::is_eq reverses constant-vs-variable into c.is_eq(v),
                // including when the constant is the RHS. Retain that exact sign.
                let difference = match (a, b) {
                    (FpVar::Var(_), FpVar::Constant(_)) => field_lc(b)?.minus(&field_lc(a)?),
                    _ => field_lc(a)?.minus(&field_lc(b)?),
                };
                let inverse = Self::inverse_or_zero(t, &difference)?;
                let ne = cs.num_instance_variables() + before;
                t.assign_muladd(ne, difference, inverse.clone(), Lc::zero())
                    .map_err(err)?;
                t.assign_linear(
                    ne + 1,
                    inverse.plus(&Lc::constant(Fr::ONE)).minus(&Lc::wire(ne)),
                )
                .map_err(err)?;
            }
        }
        Ok(result)
    }
    fn kary_and(&mut self, bits: &[Boolean<Fr>]) -> R<Boolean<Fr>> {
        if bits.is_empty() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if bits.len() <= 3 {
            let mut result = bits[0].clone();
            for b in &bits[1..] {
                result = self.bool_op(&result, b, 0)?;
            }
            Ok(result)
        } else {
            let sum = bits.iter().cloned().map(FpVar::from).sum::<FpVar<Fr>>();
            self.fp_eq(&sum, &FpVar::Constant(Fr::from(bits.len() as u64)))
        }
    }
    pub fn bytes_eq(&mut self, a: &[B], b: &[B]) -> R<Boolean<Fr>> {
        if a.len() != b.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if a.is_empty() {
            return Ok(Boolean::TRUE);
        }
        let mut results = Vec::with_capacity(a.len());
        for (a, b) in a.iter().zip(b) {
            results.push(self.fp_eq(
                &number(core::slice::from_ref(a))?,
                &number(core::slice::from_ref(b))?,
            )?);
        }
        self.kary_and(&results)
    }
    pub fn nonzero(&mut self, a: &[B]) -> R<()> {
        self.bytes_eq(a, &B::constant_vec(&vec![0; a.len()]))?
            .enforce_equal(&Boolean::FALSE)
    }
    pub fn bound(&mut self, bits: &[Boolean<Fr>], bound: impl AsRef<[u64]>) -> R<Vec<Boolean<Fr>>> {
        let bound = bound.as_ref();
        let width = BitIteratorBE::without_leading_zeros(bound).count();
        let mut it = bits.iter().rev();
        let mut last = Boolean::TRUE;
        let mut current = Vec::new();
        if bits.len() > width {
            let mut or = Boolean::FALSE;
            for bit in &bits[width..] {
                or = self.bool_op(&or, bit, 2)?;
                it.next().ok_or(SynthesisError::Unsatisfiable)?;
            }
            or.enforce_equal(&Boolean::FALSE)?;
        }
        for (public, bit) in BitIteratorBE::without_leading_zeros(bound).zip(it.by_ref()) {
            if public {
                current.push(bit.clone());
            } else {
                if !current.is_empty() {
                    current.push(last);
                    last = self.kary_and(&current)?;
                    current.clear();
                }
                self.kary_and(&[last.clone(), bit.clone()])?
                    .enforce_equal(&Boolean::FALSE)?;
            }
        }
        if it.next().is_some() {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(current)
    }
    pub fn bounded_u64(&mut self, bytes: &[B], minimum: u64, maximum: u64) -> R<()> {
        let b = bits(bytes)?;
        if b.len() != 64 {
            return Err(SynthesisError::Unsatisfiable);
        }
        self.bound(&b, [maximum])?;
        self.bound(
            &b.iter().map(|b| !b).collect::<Vec<_>>(),
            [u64::MAX - minimum],
        )?;
        Ok(())
    }
    pub fn scalar_bits(&mut self, bytes: &[B]) -> R<Vec<Boolean<Fr>>> {
        let b = bits(bytes)?;
        if b.len() != 256 {
            return Err(SynthesisError::Unsatisfiable);
        }
        self.bound(&b, (-Scalar::ONE).into_bigint())?;
        Ok(b)
    }
    pub fn less_than(&mut self, a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> R<Boolean<Fr>> {
        if a.len() != b.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut equal = Boolean::TRUE;
        let mut less = Boolean::FALSE;
        for (x, y) in a.iter().zip(b).rev() {
            let xy = self.bool_op(&!x, y, 0)?;
            let at = self.bool_op(&equal, &xy, 0)?;
            less = self.bool_op(&less, &at, 2)?;
            let different = self.bool_op(x, y, 1)?;
            equal = self.bool_op(&equal, &!different, 0)?;
        }
        Ok(less)
    }
    fn fp_mul(&mut self, a: &FpVar<Fr>, b: &FpVar<Fr>) -> R<FpVar<Fr>> {
        let cs = a.cs().or(b.cs());
        let before = cs.num_witness_variables();
        let result = a * b;
        if let Some(t) = self.trace.as_deref_mut() {
            if cs.num_witness_variables() != before {
                if cs.num_witness_variables() != before + 1 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                t.assign_muladd(
                    cs.num_instance_variables() + before,
                    field_lc(a)?,
                    field_lc(b)?,
                    Lc::zero(),
                )
                .map_err(err)?;
            }
        }
        Ok(result)
    }
    pub fn assign_bytes(&mut self, bytes: &[B], prepared: &[Vec<Lc>]) -> R<()> {
        if let Some(t) = self.trace.as_deref_mut() {
            if bytes.len() != prepared.len() {
                return Err(SynthesisError::Unsatisfiable);
            }
            for (byte, values) in bytes.iter().zip(prepared) {
                if values.len() != 8 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                for (bit, value) in byte.to_bits_le()?.iter().zip(values) {
                    let target = bit
                        .variable()
                        .get_variable_index(bit.cs().num_instance_variables())
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    t.assign_linear(target, value.clone()).map_err(err)?;
                }
            }
        }
        Ok(())
    }
    pub fn fee_sum(&mut self, sum: &FpVar<Fr>, fee_bits: &[Vec<Lc>]) -> R<()> {
        let b = sum.to_non_unique_bits_le()?;
        if let Some(t) = self.trace.as_deref_mut() {
            let targets = b
                .iter()
                .map(|b| {
                    b.variable()
                        .get_variable_index(b.cs().num_instance_variables())
                        .ok_or(SynthesisError::Unsatisfiable)
                })
                .collect::<R<Vec<_>>>()?;
            let mut words = fee_bits.to_vec();
            for word in &mut words {
                word.resize(targets.len(), Lc::zero());
            }
            t.assign_add_bits(&targets, &words).map_err(err)?;
        }
        self.bound(&b, (-Fr::ONE).into_bigint())?;
        for bit in &b[66..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        Ok(())
    }
    pub fn delta_sum(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        private: &[FpVar<Fr>],
        public: &[B],
        quotient: u8,
        prepared: &[Lc],
    ) -> R<()> {
        if private.len() != 3 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let delta_bits = self.scalar_bits(public)?;
        // Boolean::le_bits_to_fp additionally enforces P for >=254 input
        // bits. Retain and record that complete allocation, even after Q.
        let mut coefficient = Fr::ONE;
        let delta = delta_bits
            .iter()
            .map(|bit| {
                let c = coefficient;
                coefficient.double_in_place();
                FpVar::from(bit.clone()) * c
            })
            .sum::<FpVar<Fr>>();
        self.bound(&delta_bits, (-Fr::ONE).into_bigint())?;
        let k = B::new_witness_vec(cs, &[quotient])?;
        self.assign_bytes(&k, &[prepared.to_vec()])?;
        self.bound(&bits(&k)?, [2])?;
        let q: Fr = cv::SCALAR_MODULUS_DECIMAL
            .parse()
            .expect("fixed canonical Q below P");
        private
            .iter()
            .cloned()
            .sum::<FpVar<Fr>>()
            .enforce_equal(&(delta + number(&k)? * q))
    }
    pub fn permutation<const N: usize>(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        values: &[[Fr; N]; N],
        prepared: &[Vec<Lc>],
    ) -> R<Vec<Vec<FpVar<Fr>>>> {
        let mut rows = Vec::with_capacity(N);
        for (i, row) in values.iter().enumerate() {
            let mut allocated = Vec::with_capacity(N);
            for (j, v) in row.iter().enumerate() {
                let before = cs.num_witness_variables();
                let edge = FpVar::new_witness(cs.clone(), || Ok(*v))?;
                if let Some(t) = self.trace.as_deref_mut() {
                    t.assign_linear(
                        cs.num_instance_variables() + before,
                        prepared
                            .get(i)
                            .and_then(|r| r.get(j))
                            .ok_or(SynthesisError::Unsatisfiable)?
                            .clone(),
                    )
                    .map_err(err)?;
                }
                self.fp_mul(&edge, &(&edge - Fr::ONE))?
                    .enforce_equal(&FpVar::Constant(Fr::ZERO))?;
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
    pub fn route(
        &mut self,
        rows: &[Vec<B>],
        public: &[Vec<B>],
        selector: &[Vec<FpVar<Fr>>],
    ) -> R<()> {
        if rows.len() != public.len() || rows.len() != selector.len() || rows.is_empty() {
            return Err(SynthesisError::Unsatisfiable);
        }
        let width = rows[0].len();
        if rows.iter().chain(public).any(|r| r.len() != width) {
            return Err(SynthesisError::Unsatisfiable);
        }
        for col in 0..rows.len() {
            for byte in 0..width {
                let mut sum = FpVar::Constant(Fr::ZERO);
                for row in 0..rows.len() {
                    sum +=
                        self.fp_mul(&selector[row][col], &number(&rows[row][byte..byte + 1])?)?;
                }
                sum.enforce_equal(&number(&public[col][byte..byte + 1])?)?;
            }
        }
        Ok(())
    }
    pub fn bind_digest(&mut self, bytes: &[B], edges: &[FpVar<Fr>; 2]) -> R<()> {
        let digest = if let Some(t) = self.trace.as_deref_mut() {
            digest_with_ark_trace(bytes, t).map_err(err)?
        } else {
            crate::gadgets::hash(bytes)?
        };
        if let Some(t) = self.trace.as_deref_mut() {
            for (i, edge) in edges.iter().enumerate() {
                let target = match edge {
                    FpVar::Var(v) => v
                        .variable
                        .get_variable_index(v.cs.num_instance_variables())
                        .ok_or(SynthesisError::Unsatisfiable)?,
                    _ => return Err(SynthesisError::Unsatisfiable),
                };
                t.assign_linear(target, field_lc(&number(&digest[16 * i..16 * (i + 1)])?)?)
                    .map_err(err)?;
            }
        }
        for i in 0..2 {
            number(&digest[16 * i..16 * (i + 1)])?.enforce_equal(&edges[i])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{gadgets as retained, trace::Bindings};
    use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    fn suite(
        cs: ConstraintSystemRef<Fr>,
        adapter: bool,
        trace: Option<&mut TraceBuilder>,
        salt: u8,
    ) -> R<usize> {
        let a = [0, salt, 2, 3];
        let b = [0, 2, 2, 4];
        let digest: [u8; 32] = Sha256::digest(a).into();
        let global = [
            FpVar::new_input(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&digest[..16]))
            })?,
            FpVar::new_input(cs.clone(), || {
                Ok(Fr::from_le_bytes_mod_order(&digest[16..]))
            })?,
        ];
        let a = B::new_witness_vec(cs.clone(), &a)?;
        let b = B::new_witness_vec(cs.clone(), &b)?;
        let fees = [7_000_000u64, 8_000_000, 9_000_000]
            .map(|v| B::new_witness_vec(cs.clone(), &v.to_le_bytes()).unwrap());
        let scalar = B::new_witness_vec(cs.clone(), &cv::scalar_bytes(&(-Scalar::ONE)))?;
        let primary_end = cs.num_instance_variables() + cs.num_witness_variables();
        let mut tracked = JointArk::new(trace);
        let fee_lcs = fees
            .iter()
            .map(|f| {
                bits(f)?
                    .iter()
                    .map(|b| ark_bit(b).map_err(err))
                    .collect::<R<Vec<_>>>()
            })
            .collect::<R<Vec<_>>>()?;
        let fee_sum = fees
            .iter()
            .map(|f| number(f))
            .collect::<R<Vec<_>>>()?
            .into_iter()
            .sum::<FpVar<Fr>>();
        if adapter {
            tracked.nonzero(&a)?;
            tracked.bytes_eq(&a, &b)?.enforce_equal(&Boolean::FALSE)?;
            tracked.bounded_u64(&fees[0], 1, crate::MAX)?;
            tracked.scalar_bits(&scalar)?;
            tracked
                .less_than(&bits(&a)?, &bits(&b)?)?
                .enforce_equal(&Boolean::Constant(salt < 2))?;
            tracked.fee_sum(&fee_sum, &fee_lcs)?;
        } else {
            a.is_eq(&B::constant_vec(&[0; 4]))?
                .enforce_equal(&Boolean::FALSE)?;
            a.is_eq(&b)?.enforce_equal(&Boolean::FALSE)?;
            retained::bounded_u64(&fees[0], 1, crate::MAX)?;
            retained::scalar_bits(&scalar)?;
            retained::less_than(&bits(&a)?, &bits(&b)?)?
                .enforce_equal(&Boolean::Constant(salt < 2))?;
            retained::bounded_fee_sum(&fee_sum)?;
        }
        let private = [number(&fees[0])?, number(&fees[1])?, number(&fees[2])?];
        if adapter {
            tracked.delta_sum(cs.clone(), &private, &scalar, 0, &vec![Lc::zero(); 8])?;
        } else {
            retained::bind_delta_sum(cs.clone(), &private, &scalar, 0)?;
        }
        let values = [[Fr::ZERO, Fr::ONE], [Fr::ONE, Fr::ZERO]];
        let prepared = values
            .iter()
            .map(|r| r.iter().copied().map(Lc::constant).collect())
            .collect::<Vec<_>>();
        let rows = vec![a[..2].to_vec(), b[..2].to_vec()];
        let public = vec![rows[1].clone(), rows[0].clone()];
        if adapter {
            let p = tracked.permutation(cs.clone(), &values, &prepared)?;
            tracked.route(&rows, &public, &p)?;
            tracked.bind_digest(&a, &global)?;
        } else {
            let p = retained::permutation(cs.clone(), &values)?;
            retained::route(&rows, &public, &p)?;
            let d = retained::hash(&a)?;
            for i in 0..2 {
                number(&d[16 * i..16 * (i + 1)])?.enforce_equal(&global[i])?;
            }
        }
        Ok(primary_end)
    }
    fn rows(cs: &ConstraintSystemRef<Fr>) -> auth::join::R1cs {
        cs.finalize();
        let mut m = cs.to_matrices().unwrap();
        auth::join::R1cs {
            instances: cs.num_instance_variables(),
            witnesses: cs.num_witness_variables(),
            matrices: m.remove(R1CS_PREDICATE_LABEL).unwrap().try_into().unwrap(),
        }
    }
    fn new_cs() -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs
    }
    #[test]
    fn joint_recipes_retain_exact_matrices_and_every_auxiliary() {
        for salt in [1, 255] {
            let original = new_cs();
            let primary = suite(original.clone(), false, None, salt).unwrap();
            let original_rows = rows(&original);
            let adapted = new_cs();
            suite(adapted.clone(), true, None, salt).unwrap();
            let adapted_rows = rows(&adapted);
            assert_eq!(
                auth::join::fingerprint(&original_rows),
                auth::join::fingerprint(&adapted_rows)
            );
            assert_eq!(
                original.witness_assignment().unwrap(),
                adapted.witness_assignment().unwrap()
            );
            let variables = adapted.num_variables();
            let mut trace = TraceBuilder::new(variables, 3).unwrap();
            trace.input_range(3, primary).unwrap();
            let traced = new_cs();
            suite(traced.clone(), true, Some(&mut trace), salt).unwrap();
            assert!(
                trace.unassigned_model_columns().is_empty(),
                "missing {:?}",
                trace.unassigned_model_columns()
            );
            assert_eq!(
                auth::join::fingerprint(&rows(&traced)),
                auth::join::fingerprint(&original_rows)
            );
            let mut z = traced.instance_assignment().unwrap();
            z.extend(traced.witness_assignment().unwrap());
            let inputs = (3..primary).map(|i| (i, z[i])).collect::<BTreeMap<_, _>>();
            let extended = trace.evaluate_public_fixture(&inputs).unwrap();
            assert_eq!(&extended[..variables], z);
            let mut out = Vec::new();
            trace
                .write_text(
                    &mut out,
                    &Bindings {
                        source_sha256: "1".repeat(64),
                        model_sha256: "2".repeat(64),
                        layout_sha256: "3".repeat(64),
                    },
                )
                .unwrap();
            assert!(!out.is_empty());
        }
    }
}
