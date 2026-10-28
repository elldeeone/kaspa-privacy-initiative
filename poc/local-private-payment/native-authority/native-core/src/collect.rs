//! Actual Ark GR1CS extraction. Every predicate and row must be admitted.
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer,ConstraintSystem,OptimizationGoal,R1CS_PREDICATE_LABEL};
use crate::join::{R1cs,Boundary};
/// No caller-selected validity Boolean; the caller evaluates returned matrices.
pub fn collect<C:ConstraintSynthesizer<Fr>>(c:C,expected_instances:usize)->Result<(R1cs,Vec<Fr>),Boundary>{
 let cs=ConstraintSystem::<Fr>::new_ref();cs.set_optimization_goal(OptimizationGoal::Constraints);
 c.generate_constraints(cs.clone()).map_err(|_|Boundary::Synthesis)?;cs.finalize();
 if cs.num_instance_variables()!=expected_instances{return Err(Boundary::Shape)}
 let mut groups=cs.to_matrices().map_err(|_|Boundary::Synthesis)?;
 if groups.len()!=1||!groups.contains_key(R1CS_PREDICATE_LABEL){return Err(Boundary::Predicate)}
 let matrices=groups.remove(R1CS_PREDICATE_LABEL).ok_or(Boundary::Predicate)?.try_into().map_err(|_|Boundary::Shape)?;
 let system=R1cs{instances:cs.num_instance_variables(),witnesses:cs.num_witness_variables(),matrices};system.validate()?;
 if system.constraints()!=cs.num_constraints(){return Err(Boundary::Shape)}
 let mut z=cs.instance_assignment().map_err(|_|Boundary::Synthesis)?;z.extend(cs.witness_assignment().map_err(|_|Boundary::Synthesis)?);
 if z.len()!=system.variables()?{return Err(Boundary::Length)}
 Ok((system,z))
}
