//! PUBLIC source representation/geometry control only; no private WTNS/dealer.
#[path = "qualify_joint_core.rs"]
mod qualifier;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, LinearCombination, OptimizationGoal,
    R1CS_PREDICATE_LABEL, SynthesisMode, Variable,
};
use auth::join::R1cs;
use kpi_private_batch_relation::{
    COMPONENT_INSTANCES, compose,
    joined_source::{JoinedSourceCircuit, append_public_signature_matrices, canonical_terms},
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};
fn cs(matrices: bool) -> ConstraintSystemRef<Fr> {
    let c = ConstraintSystem::new_ref();
    c.set_optimization_goal(OptimizationGoal::Constraints);
    c.set_mode(SynthesisMode::Prove {
        construct_matrices: matrices,
        generate_lc_assignments: matrices,
    });
    c
}
fn collect(c: &ConstraintSystemRef<Fr>) -> Result<R1cs, Box<dyn std::error::Error>> {
    c.finalize();
    let mut m = c.to_matrices()?;
    if m.len() != 1 {
        return Err("predicate shape".into());
    }
    Ok(R1cs {
        instances: c.num_instance_variables(),
        witnesses: c.num_witness_variables(),
        matrices: m
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or("R1CS absent")?
            .try_into()
            .map_err(|_| "matrix arity")?,
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: compare_joined_source PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json EXPECTED-MATRIX-SHA EXPECTED-MAP-SHA".into());
    }
    let started = Instant::now();
    let v: Value = serde_json::from_slice(&fs::read(Path::new(&args[0]))?)?;
    let context = qualifier::context(
        hex::decode(v["context_hex"].as_str().ok_or("public context")?)?
            .try_into()
            .map_err(|_| "context bytes")?,
    );
    let signature = auth::interchange::signature_matrix(&fs::read(&args[1])?, &args[2], &args[3])?;
    let signatures = core::array::from_fn(|_| signature.clone());
    let component = cs(false);
    let source = JoinedSourceCircuit::from_public_context(context.clone(), signatures.clone())?;
    let template = source.public_component_template();
    let layout = template.clone().generate_with_layout(component.clone())?;
    let core = component.num_variables();
    let mut prefix = component.instance_assignment()?;
    prefix.extend(component.witness_assignment()?);
    drop(component);
    let internal = cs(false);
    let shape = source.generate_with_shape(internal.clone())?;
    if shape.layout != layout
        || shape.core_variables != core
        || shape.final_variables
            != core + 3 * (signature.variables().map_err(|_| "signature vars")? - 1)
        || internal.num_instance_variables() != 3
    {
        return Err("source geometry changed".into());
    }
    let public = internal.instance_assignment()?;
    if prefix[..3] != public {
        return Err("source public values changed".into());
    }
    {
        let borrowed = internal.borrow().ok_or("CS")?;
        let values = borrowed.witness_assignment()?;
        if prefix[3..] != values[..core - 3] {
            return Err("source physical core assignment changed".into());
        }
    }
    drop(internal);
    drop(prefix);
    // A small core plus ALL real EdDSA rows isolates exact append equivalence
    // without allocating the full financial matrix before the resource plan.
    let toy = R1cs {
        instances: COMPONENT_INSTANCES,
        witnesses: 1,
        matrices: [
            vec![vec![(Fr::ONE, 1), (Fr::from(2u64), COMPONENT_INSTANCES)]],
            vec![vec![(Fr::ONE, 0)]],
            vec![vec![(Fr::ONE, 2)]],
        ],
    };
    let joined = compose::join(&toy, &signatures).map_err(|_| "public compose")?;
    let original_fingerprint =
        auth::join::fingerprint(&joined.cs).map_err(|_| "raw fingerprint")?;
    let mut expected = joined.cs;
    let mut reordered = 0usize;
    for axis in &mut expected.matrices {
        for row in axis {
            let sorted = canonical_terms(row)?;
            reordered += usize::from(sorted != *row);
            *row = sorted;
        }
    }
    let direct = cs(true);
    let _ = direct.new_input_variable(|| Ok(Fr::ZERO))?;
    let _ = direct.new_input_variable(|| Ok(Fr::ZERO))?;
    for _ in 3..=COMPONENT_INSTANCES {
        let _ = direct.new_witness_variable(|| Ok(Fr::ZERO))?;
    }
    let var = |i| {
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
            toy.matrices[axis][0]
                .iter()
                .map(|(c, i)| (*c, var(*i)))
                .collect(),
        )
    };
    direct.enforce_r1cs_constraint(|| lc(0), || lc(1), || lc(2))?;
    append_public_signature_matrices(
        direct.clone(),
        toy.variables().map_err(|_| "toy variables")?,
        &signatures,
    )?;
    let actual = collect(&direct)?;
    if actual.matrices != expected.matrices
        || actual.instances != expected.instances
        || actual.witnesses != expected.witnesses
    {
        return Err("canonical real signature rows changed".into());
    }
    let fp = auth::join::fingerprint(&actual).map_err(|_| "canonical fingerprint")?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"kpb-direct-source-equivalence/v1","scope":"PUBLIC_INVALID_SOURCE_CORE_GEOMETRY_PLUS_REAL_SIGNATURE_ROWS","source_component_core_variables":core,"source_final_variables":shape.final_variables,"source_instances":3,"every_physical_core_value_equal":true,"signature_variables_each":shape.signature_variables,"real_signature_rows_each":signature.constraints(),"canonical_reordered_term_lists":reordered,"small_core_plus_real_signature_rows":actual.constraints(),"raw_small_composed_fingerprint":original_fingerprint,"new_canonical_small_composed_and_direct_fingerprint":fp,"all_rows_terms_coefficients_columns_recovered":true,"original_signature_matrix_sha256":args[2],"original_signature_mapping_sha256":args[3],"elapsed_seconds":started.elapsed().as_secs_f64(),"full_financial_matrices_setup_or_proof_claim":false})
        )?
    );
    Ok(())
}
