//! Direct PUBLIC source/setup synthesis of the exact composed batch matrix.
//!
//! This avoids retaining dense core, joined and imported-source copies at once.
//! The template contains PUBLIC invalid filler only; this is never a private
//! joint WTNS generator/dealer. Real private execution uses the bound trace and
//! three isolated masked owner inputs. Stock setup still needs real matrices.
use crate::{BatchCircuit, BatchLayout, COMPONENT_INSTANCES, OWNERS};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use auth::join::R1cs;

/// Pinned complete EdDSA matrices are public model data. No signature witness,
/// seed, signing scalar or signing nonce is accepted by this source seam.
#[derive(Clone)]
pub struct JoinedSourceCircuit {
    public_template: BatchCircuit,
    signature_matrices: [R1cs; OWNERS],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceShape {
    pub layout: BatchLayout,
    pub core_variables: usize,
    pub signature_variables: [usize; OWNERS],
    pub final_variables: usize,
}
pub fn append_public_signature_matrices(
    cs: ConstraintSystemRef<Fr>,
    core_variables: usize,
    signatures: &[R1cs; OWNERS],
) -> Result<[usize; OWNERS], SynthesisError> {
    if cs.num_instance_variables() != 3
        || cs.num_variables() != core_variables
        || core_variables < COMPONENT_INSTANCES
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut signature_variables = [0; OWNERS];
    let mut starts = [0; OWNERS];
    for (owner, signature) in signatures.iter().enumerate() {
        signature
            .validate()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        if signature.instances != 67 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let variables = signature
            .variables()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        signature_variables[owner] = variables;
        starts[owner] = cs.num_variables();
        let mut columns = Vec::with_capacity(variables);
        columns.push(Variable::One);
        for _ in 1..variables {
            columns.push(cs.new_witness_variable(|| Ok(Fr::ZERO))?);
        }
        for row in 0..signature.constraints() {
            let mut axes = Vec::with_capacity(3);
            for matrix in &signature.matrices {
                let terms = canonical_terms(&matrix[row])?;
                axes.push(LinearCombination(
                    terms.iter().map(|(c, i)| (*c, columns[*i])).collect(),
                ));
            }
            cs.enforce_r1cs_constraint(|| axes[0].clone(), || axes[1].clone(), || axes[2].clone())?;
        }
    }
    for (owner, start) in starts.into_iter().enumerate() {
        for edge in 0..66 {
            let native = Variable::witness(3 + owner * 66 + edge - 3);
            let signature = Variable::witness(start + edge - 3);
            cs.enforce_r1cs_constraint(
                || LinearCombination(vec![(Fr::ONE, native), (-Fr::ONE, signature)]),
                || LinearCombination::from(Variable::One),
                LinearCombination::zero,
            )?;
        }
    }
    Ok(signature_variables)
}

/// Explicit bijective term-order representation change. The original pinned
/// signature rows are untouched. The NEW model identity uses stock Ark's
/// finalized sorted rows; it must never reuse the old order-sensitive hash.
/// No coefficient combination, zero elision, remapping or row changes occur.
pub fn canonical_terms(original: &auth::join::Row) -> Result<auth::join::Row, SynthesisError> {
    if original.iter().any(|(c, _)| *c == Fr::ZERO) {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut indexed = original.iter().copied().enumerate().collect::<Vec<_>>();
    indexed.sort_by_key(|(_, (_, index))| *index);
    if indexed.windows(2).any(|p| p[0].1.1 == p[1].1.1) {
        return Err(SynthesisError::Unsatisfiable);
    }
    let sorted = indexed.iter().map(|(_, term)| *term).collect::<Vec<_>>();
    let mut inverse = indexed;
    inverse.sort_by_key(|(original_index, _)| *original_index);
    if sorted.len() != original.len() || inverse.iter().zip(original).any(|((_, a), b)| a != b) {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(sorted)
}
impl JoinedSourceCircuit {
    /// Sole constructor accepts PUBLIC context and pinned PUBLIC matrices.
    /// Caller-supplied OwnerWitness records and clear signature assignments
    /// cannot enter this source/setup interface.
    pub fn from_public_context(
        context: crate::Context,
        signature_matrices: [R1cs; OWNERS],
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            public_template: crate::owner_local::public_source_template(context)?,
            signature_matrices,
        })
    }
    pub fn public_component_template(&self) -> BatchCircuit {
        self.public_template.clone()
    }
    pub fn generate_with_shape(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<SourceShape, SynthesisError> {
        let layout = self.public_template.generate_internalized(cs.clone())?;
        let core_variables = cs.num_variables();
        let signature_variables =
            append_public_signature_matrices(cs.clone(), core_variables, &self.signature_matrices)?;
        Ok(SourceShape {
            layout,
            core_variables,
            signature_variables,
            final_variables: cs.num_variables(),
        })
    }
}
impl ConstraintSynthesizer<Fr> for JoinedSourceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.generate_with_shape(cs).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL};
    fn collect(cs: &ConstraintSystemRef<Fr>) -> R1cs {
        cs.finalize();
        let mut matrices = cs.to_matrices().unwrap();
        R1cs {
            instances: cs.num_instance_variables(),
            witnesses: cs.num_witness_variables(),
            matrices: matrices
                .remove(R1CS_PREDICATE_LABEL)
                .unwrap()
                .try_into()
                .unwrap(),
        }
    }
    #[test]
    fn direct_signature_append_matches_exact_composed_rows_and_columns() {
        let core = R1cs {
            instances: COMPONENT_INSTANCES,
            witnesses: 1,
            matrices: [
                vec![vec![(Fr::ONE, 1), (Fr::from(2u64), COMPONENT_INSTANCES)]],
                vec![vec![(Fr::ONE, 0)]],
                vec![vec![(Fr::ONE, 2)]],
            ],
        };
        let signatures = core::array::from_fn(|i| R1cs {
            instances: 67,
            witnesses: i + 1,
            matrices: [
                vec![vec![(Fr::from((i + 1) as u64), 0), (Fr::ONE, 67 + i)]],
                vec![vec![(Fr::ONE, 1)]],
                vec![vec![(Fr::ONE, 66)]],
            ],
        });
        let joined = crate::compose::join(&core, &signatures).unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        let _ = cs.new_input_variable(|| Ok(Fr::ZERO)).unwrap();
        let _ = cs.new_input_variable(|| Ok(Fr::ZERO)).unwrap();
        for _ in 3..=COMPONENT_INSTANCES {
            let _ = cs.new_witness_variable(|| Ok(Fr::ZERO)).unwrap();
        }
        let variable = |i| {
            if i == 0 {
                Variable::One
            } else if i < 3 {
                Variable::instance(i)
            } else {
                Variable::witness(i - 3)
            }
        };
        let lc = |axis: usize| {
            LinearCombination(
                core.matrices[axis][0]
                    .iter()
                    .map(|(c, i)| (*c, variable(*i)))
                    .collect(),
            )
        };
        cs.enforce_r1cs_constraint(|| lc(0), || lc(1), || lc(2))
            .unwrap();
        append_public_signature_matrices(cs.clone(), core.variables().unwrap(), &signatures)
            .unwrap();
        let direct = collect(&cs);
        assert_eq!(
            auth::join::fingerprint(&direct),
            auth::join::fingerprint(&joined.cs)
        );
        assert_eq!(direct.matrices, joined.cs.matrices);
    }
}
