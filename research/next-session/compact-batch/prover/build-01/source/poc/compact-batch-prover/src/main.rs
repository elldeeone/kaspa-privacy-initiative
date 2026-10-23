//! One authenticated local parameter load, then one private owner witness.
use ark_bn254::Fr;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use kpi_compact_batch_prover as payment;
use payment::{Role, parameters};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, &'static str>;
fn emit(value: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value).map_err(|_| "public_output_io")?;
    out.write_all(b"\n")
        .and_then(|_| out.flush())
        .map_err(|_| "public_output_io")
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "output_create")?;
    f.write_all(raw)
        .and_then(|_| f.sync_all())
        .map_err(|_| "output_io")
}
fn new_private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "output_create")
}
fn save_report(path: &Path, value: &Value) -> Result<()> {
    write_new(
        path,
        &serde_json::to_vec_pretty(value).map_err(|_| "public_output_encode")?,
    )
}
fn report(loaded: &parameters::Loaded) -> Value {
    json!({"schema":"kpx4-own-prover-public-report/v1",
        "domain_hex32":hex::encode(payment::DOMAIN),
        "role":loaded.selected.manifest.role,"output_arity":loaded.selected.manifest.output_arity,
        "parameter_manifest_sha256":loaded.selected.manifest_sha256,
        "vk_sha256":loaded.selected.manifest.vk_sha256,
        "pk_sha256":loaded.selected.manifest.pk_sha256,"pk_bytes":loaded.selected.manifest.pk_bytes,
        "source_identity":parameters::source_identity_value(),
        "compiled_build_identity_sha256":parameters::build_identity_sha256(),
        "parameter_phase_seconds":loaded.phase_seconds,
        "network_or_broadcast_performed":false,"hosted_prover":false})
}
fn prove(role: Role, pk_path: &Path, fd: &str, output: &Path) -> Result<()> {
    // Only public argument syntax is touched before authentication. In
    // particular no File/reader for the inherited witness descriptor exists.
    let number: u32 = fd.parse().map_err(|_| "witness_fd_invalid")?;
    let loaded = parameters::load(role, pk_path).map_err(|e| e.0)?;
    emit(&loaded.ready())?;
    // Linux procfs reopens the inherited descriptor without a caller-supplied
    // private path or unsafe ownership conversion. No read precedes ready.
    let mut witness =
        fs::File::open(format!("/proc/self/fd/{number}")).map_err(|_| "private_request_io")?;
    let circuit = payment::request::read_for_role(&mut witness, role).map_err(|e| e.code())?;
    drop(witness);
    let auth = circuit.authorization.clone();
    let began = Instant::now();
    let proof = payment::prove(&loaded.pk, circuit, &mut rand::rngs::OsRng)
        .map_err(|_| "private_proof_failed")?;
    let vk = payment::verification_key(&loaded.pk).map_err(|_| "selected_vk_invalid")?;
    if vk.as_slice() != parameters::selected_vk(role).map_err(|e| e.0)?
        || !payment::Verifier::new(&vk, role)
            .map_err(|_| "selected_vk_invalid")?
            .verify(&auth, &proof)
            .map_err(|_| "private_verification_failed")?
    {
        return Err("private_verification_failed");
    }
    let seconds = began.elapsed().as_secs_f64();
    // No output artifact is created until proof verification succeeds. This
    // allowlist contains public statement/proof/parameter data only.
    new_private_dir(output)?;
    write_new(&output.join("proof128.bin"), &proof)?;
    write_new(&output.join("authorization528.bin"), &auth.bytes())?;
    write_new(&output.join("verification-key.bin"), &vk)?;
    let mut r = report(&loaded);
    r["genuine_Groth16_verified"] = true.into();
    r["proof_sha256"] = parameters::digest(&proof).into();
    r["authorization_sha256"] = parameters::digest(&auth.bytes()).into();
    r["prove_and_checked_verification_seconds"] = seconds.into();
    save_report(&output.join("report.json"), &r)?;
    fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|_| "output_io")?;
    emit(
        &json!({"event":"proof-complete","role":role.name(),"genuine_Groth16_verified":true,
        "proof_sha256":parameters::digest(&proof),"authorization_sha256":parameters::digest(&auth.bytes()),
        "vk_sha256":parameters::digest(&vk)}),
    )
}
fn role(value: &str) -> Result<Role> {
    Role::parse(value).map_err(|_| "role_invalid")
}

/// Development-only shape command. It never loads parameters, makes a proof,
/// prints assignments, hashes a witness, or claims accepted-chain state.
fn shape(role: Role, input: &Path, output: &Path) -> Result<()> {
    parameters::trial_identity().map_err(|e| e.0)?;
    let mut file = fs::File::open(input).map_err(|_| "shape_request_io")?;
    let circuit = payment::request::read_for_role(&mut file, role).map_err(|e| e.code())?;
    drop(file);
    let began = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });
    circuit
        .generate_constraints(cs.clone())
        .map_err(|_| "shape_synthesis_failed")?;
    cs.finalize();
    let satisfied = cs.is_satisfied().map_err(|_| "shape_satisfaction_failed")?;
    let mut dimensions = parameters::Shape {
        constraints: cs.num_constraints(),
        witness_variables: cs.num_witness_variables(),
        instances_including_one: cs.num_instance_variables(),
        matrix_sha256: payment::circuit::matrix_fingerprint(&cs)
            .map_err(|_| "shape_matrix_failed")?,
        fft_domain_size: 0,
    };
    dimensions.fft_domain_size = parameters::fft_domain_size(&dimensions).map_err(|e| e.0)?;
    drop(cs);
    let value = json!({"schema":"kpx4-finalized-constraint-shape/v1", "role":role.name(),
        "output_arity":role.output_count(),"domain_hex32":hex::encode(payment::DOMAIN),
        "constraint_shape":dimensions,"relation_satisfied":satisfied,
        "synthesize_finalize_check_and_public_matrix_hash_seconds":began.elapsed().as_secs_f64(),
        "compiled_build_identity_sha256":parameters::build_identity_sha256(),
        "matrix_hash_contains_assignments_or_private_input_hash":false,
        "proof_setup_native_or_network_execution":false});
    new_private_dir(output)?;
    save_report(&output.join("report.json"), &value)?;
    emit(&value)
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 6 => prove(
            role(&args[2])?,
            Path::new(&args[3]),
            &args[4],
            Path::new(&args[5]),
        ),
        Some("loader-only") if args.len() == 5 => {
            let role = role(&args[2])?;
            let loaded = parameters::load(role, Path::new(&args[3])).map_err(|e| e.0)?;
            new_private_dir(Path::new(&args[4]))?;
            save_report(&Path::new(&args[4]).join("report.json"), &report(&loaded))?;
            emit(&loaded.ready())
        }
        Some("verify") if args.len() == 5 => {
            let role = role(&args[2])?;
            let vk = parameters::selected_vk(role).map_err(|e| e.0)?;
            let mut auth = Vec::new();
            fs::File::open(&args[3])
                .map_err(|_| "public_auth_io")?
                .take(529)
                .read_to_end(&mut auth)
                .map_err(|_| "public_auth_io")?;
            let auth = payment::Authorization::parse(&auth).map_err(|_| "public_auth_invalid")?;
            let mut proof = Vec::new();
            fs::File::open(&args[4])
                .map_err(|_| "public_proof_io")?
                .take(129)
                .read_to_end(&mut proof)
                .map_err(|_| "public_proof_io")?;
            if !payment::Verifier::new(vk, role)
                .map_err(|_| "selected_vk_invalid")?
                .verify(&auth, &proof)
                .map_err(|_| "public_proof_invalid")?
            {
                return Err("public_proof_invalid");
            }
            emit(&json!({"event":"proof-verified","role":role.name(),
                "authorization_sha256":parameters::digest(&auth.bytes()),
                "proof_sha256":parameters::digest(&proof),"vk_sha256":parameters::digest(vk)}))
        }
        Some("shape") if args.len() == 5 => {
            shape(role(&args[2])?, Path::new(&args[3]), Path::new(&args[4]))
        }
        _ => Err("arguments_invalid"),
    }
}

fn main() {
    // Dependency panics must not echo a private parser value or assertion.
    std::panic::set_hook(Box::new(|_| {
        let _ = writeln!(
            std::io::stderr(),
            "{{\"event\":\"error\",\"code\":\"internal_failure\"}}"
        );
    }));
    match std::panic::catch_unwind(run) {
        Ok(Ok(())) => {}
        Ok(Err(code)) => {
            let _ = emit(&json!({"event":"error","code":code}));
            std::process::exit(1);
        }
        Err(_) => std::process::exit(1),
    }
}
