//! Authorized one-pass PUBLIC/unassigned stock matrix resource probe.
//! No parameter generation, private assignment, proof or MPC is performed.
#[path = "qualify_joint_core.rs"]
mod qualifier;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::gr1cs::{
    ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use kpi_private_batch_relation::{
    joined_source::JoinedSourceCircuit,
    row_transport::{self, AxisReceipt},
};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    time::Instant,
};
fn rows_json(r: &AxisReceipt, file: &str) -> Value {
    json!({"axis":r.axis,"file":file,"uncompressed_bytes":r.raw_bytes,"uncompressed_sha256":r.raw_sha256,"compressed_bytes":r.compressed_bytes,"compressed_sha256":r.compressed_sha256})
}
fn event(v: Value) -> io::Result<()> {
    println!("{}", v);
    io::stdout().flush()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 7 {
        return Err("usage: probe_direct_matrices PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json EXPECTED-MATRIX-SHA EXPECTED-MAP-SHA SOURCE-SHA NEW-ARTIFACT-DIRECTORY COMPRESSED-BYTE-BUDGET".into());
    }
    if args[4].len() != 64
        || !args[4]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("source identity format".into());
    }
    let output = PathBuf::from(&args[5]);
    if output.exists() {
        return Err("fresh output directory required".into());
    }
    let budget: u64 = args[6].parse()?;
    let started = Instant::now();
    let context_json: Value = serde_json::from_slice(&fs::read(&args[0])?)?;
    let context = qualifier::context(
        hex::decode(
            context_json["context_hex"]
                .as_str()
                .ok_or("public context")?,
        )?
        .try_into()
        .map_err(|_| "public context length")?,
    );
    let signature = auth::interchange::signature_matrix(&fs::read(&args[1])?, &args[2], &args[3])?;
    let source = JoinedSourceCircuit::from_public_context(
        context,
        core::array::from_fn(|_| signature.clone()),
    )?;
    event(
        json!({"stage":"stock_setup_mode_matrix_synthesis_start","private_assignment":false,"source_sha256":args[4]}),
    )?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    let shape = source.generate_with_shape(cs.clone())?;
    event(
        json!({"stage":"stock_matrix_synthesis_done","variables":cs.num_variables(),"instances":cs.num_instance_variables(),"actual_constraint_rows":cs.num_constraints(),"elapsed_seconds":started.elapsed().as_secs_f64()}),
    )?;
    cs.finalize();
    let mut axes = cs.to_matrices()?;
    if axes.len() != 1 || !axes.contains_key(R1CS_PREDICATE_LABEL) {
        return Err("unsupported actual predicate".into());
    }
    let matrices = auth::join::R1cs {
        instances: cs.num_instance_variables(),
        witnesses: cs.num_witness_variables(),
        matrices: axes
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or("R1CS absent")?
            .try_into()
            .map_err(|_| "axis count")?,
    };
    if matrices.constraints() != cs.num_constraints()
        || matrices.variables().map_err(|_| "shape")? != shape.final_variables
    {
        return Err("actual final matrix geometry changed".into());
    }
    drop(cs);
    matrices.validate().map_err(|_| "actual matrix shape")?;
    event(
        json!({"stage":"actual_finalized_matrices_available","rows":matrices.constraints(),"variables":shape.final_variables,"elapsed_seconds":started.elapsed().as_secs_f64()}),
    )?;
    let gzip_pin = row_transport::gzip_binary_sha256()?;
    let mut fingerprint = row_transport::fingerprint_start(&matrices)?;
    let mut estimated = Vec::new();
    for axis in 0..3 {
        let r = row_transport::gzip_axis(&matrices, axis, None, Some(&mut fingerprint))?;
        event(
            json!({"stage":"compressed_axis_estimate","axis":axis,"compressed_bytes":r.compressed_bytes,"raw_bytes":r.raw_bytes}),
        )?;
        estimated.push(r);
    }
    let fingerprint = hex::encode(fingerprint.finalize());
    let total = estimated.iter().try_fold(0u64, |s, r| {
        s.checked_add(r.compressed_bytes)
            .ok_or("compressed total overflow")
    })?;
    event(
        json!({"stage":"complete_compressed_estimate_before_write","compressed_bytes":total,"byte_budget":budget,"canonical_r1cs_fingerprint":fingerprint,"elapsed_seconds":started.elapsed().as_secs_f64()}),
    )?;
    if total > budget {
        event(
            json!({"stage":"measurement_complete_artifact_budget_exceeded","artifact_written":false,"all_rows_measured":true,"compressed_bytes":total,"canonical_r1cs_fingerprint":fingerprint}),
        )?;
        return Ok(());
    }
    if row_transport::gzip_binary_sha256()? != gzip_pin {
        return Err("gzip producer identity changed".into());
    }
    fs::create_dir(&output)?;
    let names = ["A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz"];
    let mut files = Vec::new();
    for axis in 0..3 {
        let actual =
            row_transport::gzip_axis(&matrices, axis, Some(&output.join(names[axis])), None)?;
        if actual != estimated[axis] {
            return Err("lossless compressed estimate/artifact identity changed".into());
        }
        files.push(rows_json(&actual, names[axis]));
    }
    let manifest = json!({"schema":"kpi-r1cs-axis-gzip/v1","classification":"PUBLIC_UNASSIGNED_STOCK_ROWS_NO_PK_SETUP_PROOF_OR_ACCEPTANCE","magic_ascii":"KPI_R1CS_AXIS_V1","field_decimal":Fr::MODULUS.to_string(),"num_instances":matrices.instances,"num_witnesses":matrices.witnesses,"num_constraints":matrices.constraints(),"model_variables":shape.final_variables,"source_sha256":args[4],"canonical_r1cs_fingerprint":fingerprint,"original_signature_matrix_sha256":args[2],"original_signature_mapping_sha256":args[3],"signature_variables":shape.signature_variables,"public_prefix_policy":{"slots":3,"policy":"derived_only_after_global_private_validity","fixed_digest_values":false,"prefix_recipe_status":"separately_bound_required_before_jobs"},"gzip_binary_sha256":gzip_pin,"gzip_arguments":["-1","-n","-c"],"axes":files,"private_assignment_included":false,"parameter_or_vk_identity_claim":false});
    fs::write(
        output.join("PUBLIC-ROWS-MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    event(
        json!({"stage":"lossless_public_rows_artifacts_complete","output":output,"compressed_bytes":total,"canonical_r1cs_fingerprint":fingerprint,"elapsed_seconds":started.elapsed().as_secs_f64(),"setup_proof_mpc_or_financial_acceptance":false}),
    )?;
    Ok(())
}
