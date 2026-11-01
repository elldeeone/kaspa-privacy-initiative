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
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    time::Instant,
};

struct SourceSelection {
    sha256: String,
    members: usize,
}
fn rows_json(r: &AxisReceipt, file: &str) -> Value {
    json!({"axis":r.axis,"file":file,"uncompressed_bytes":r.raw_bytes,"uncompressed_sha256":r.raw_sha256,"compressed_bytes":r.compressed_bytes,"compressed_sha256":r.compressed_sha256})
}
fn event(v: Value) -> io::Result<()> {
    println!("{}", v);
    io::stdout().flush()
}
#[cfg(target_os = "linux")]
fn read_opened_regular(
    path: &Path,
    expected_canonical_path: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err("source table member is not a regular file".into());
    }
    let opened =
        fs::canonicalize(PathBuf::from("/proc/self/fd").join(file.as_raw_fd().to_string()))?;
    if opened != expected_canonical_path {
        return Err("source table member opened outside its exact path".into());
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    Ok(raw)
}

#[cfg(not(target_os = "linux"))]
fn read_opened_regular(
    _path: &Path,
    _expected_canonical_path: &Path,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("exact source table verification requires pinned Linux /proc file descriptors".into())
}

fn selected_source_table(path: &Path) -> Result<SourceSelection, Box<dyn std::error::Error>> {
    let expected = option_env!("KPB_MATRIX_SOURCE_TABLE_SHA256")
        .ok_or("matrix source table build binding absent")?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("matrix source table build binding format".into());
    }
    let expected_count: usize = option_env!("KPB_MATRIX_SOURCE_MEMBER_COUNT")
        .ok_or("matrix source count build binding absent")?
        .parse()?;
    if expected_count == 0 {
        return Err("matrix source count build binding empty".into());
    }
    let configured_repository =
        PathBuf::from(option_env!("KPB_REPOSITORY_ROOT").ok_or("repository build binding absent")?);
    if !configured_repository.is_absolute() {
        return Err("repository build binding is not absolute".into());
    }
    let repository = fs::canonicalize(&configured_repository)?;
    if repository != configured_repository || !repository.is_dir() {
        return Err("repository build binding is not its canonical directory".into());
    }
    let canonical_table = fs::canonicalize(path)?;
    let raw = read_opened_regular(path, &canonical_table)?;
    let actual = hex::encode(sha2::Sha256::digest(&raw));
    if actual != expected {
        return Err("exact source table build binding".into());
    }
    let table: Value = serde_json::from_slice(&raw)?;
    if serde_json::to_vec(&table)? != raw {
        return Err("canonical unique source table".into());
    }
    let members = table.as_object().ok_or("source table object")?;
    if members.len() != expected_count || members.is_empty() {
        return Err("source table exact count".into());
    }
    for (relative, selected) in members {
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative.components().any(|component| {
                !matches!(component, Component::Normal(_))
                    || matches!(component, Component::Normal(value) if value == "target" || value == "evidence" || value == ".git")
            })
        {
            return Err("source table canonical repository path".into());
        }
        let selected = selected.as_str().ok_or("source table SHA string")?;
        if selected.len() != 64
            || !selected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("source table SHA format".into());
        }
        let source = repository.join(relative);
        if fs::canonicalize(&source)? != source {
            return Err("source table member path is not canonical".into());
        }
        let raw = read_opened_regular(&source, &source)?;
        if hex::encode(sha2::Sha256::digest(raw)) != selected {
            return Err("source table member drift".into());
        }
    }
    Ok(SourceSelection {
        sha256: actual,
        members: members.len(),
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 2 && args[0] == "--check-source-table" {
        let source = selected_source_table(Path::new(&args[1]))?;
        event(json!({
            "stage":"exact_source_table_verified",
            "source_sha256":source.sha256,
            "source_members":source.members,
            "matrix_synthesis_started":false,
            "private_assignment":false,
            "parameter_generation_proof_or_mpc":false
        }))?;
        return Ok(());
    }
    if args.len() != 7 {
        return Err("usage: probe_direct_matrices --check-source-table EXACT-SOURCE-TABLE.json | PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json EXPECTED-MATRIX-SHA EXPECTED-MAP-SHA EXACT-SOURCE-TABLE.json NEW-ARTIFACT-DIRECTORY COMPRESSED-BYTE-BUDGET".into());
    }
    let source = selected_source_table(Path::new(&args[4]))?;
    let source_sha = source.sha256;
    let source_members = source.members;
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
        json!({"stage":"stock_setup_mode_matrix_synthesis_start","private_assignment":false,"source_sha256":source_sha}),
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
    let manifest = json!({"schema":"kpi-r1cs-axis-gzip/v1","classification":"PUBLIC_UNASSIGNED_STOCK_ROWS_NO_PK_SETUP_PROOF_OR_ACCEPTANCE","magic_ascii":"KPI_R1CS_AXIS_V1","field_decimal":Fr::MODULUS.to_string(),"num_instances":matrices.instances,"num_witnesses":matrices.witnesses,"num_constraints":matrices.constraints(),"model_variables":shape.final_variables,"source_sha256":source_sha,"source_member_count":source_members,"canonical_r1cs_fingerprint":fingerprint,"original_signature_matrix_sha256":args[2],"original_signature_mapping_sha256":args[3],"signature_variables":shape.signature_variables,"public_prefix_policy":{"slots":3,"policy":"derived_only_after_global_private_validity","fixed_digest_values":false,"prefix_recipe_status":"separately_bound_required_before_jobs"},"gzip_binary_sha256":gzip_pin,"gzip_arguments":["-1","-n","-c"],"axes":files,"private_assignment_included":false,"parameter_or_vk_identity_claim":false});
    fs::write(
        output.join("PUBLIC-ROWS-MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    event(
        json!({"stage":"lossless_public_rows_artifacts_complete","output":output,"compressed_bytes":total,"canonical_r1cs_fingerprint":fingerprint,"elapsed_seconds":started.elapsed().as_secs_f64(),"setup_proof_mpc_or_financial_acceptance":false}),
    )?;
    Ok(())
}
