//! One authenticated local parameter load, then one private owner witness.
use kpi_private_cashout_prover as payment;
use payment::parameters;
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
    json!({"schema":"kpx3-own-prover-public-report/v1",
        "domain_hex32":hex::encode(payment::DOMAIN),
        "parameter_manifest_sha256":loaded.selected.manifest_sha256,
        "vk_sha256":loaded.selected.manifest.vk_sha256,
        "pk_sha256":loaded.selected.manifest.pk_sha256,"pk_bytes":loaded.selected.manifest.pk_bytes,
        "source_identity":parameters::source_identity_value(),
        "compiled_build_identity_sha256":parameters::build_identity_sha256(),
        "parameter_phase_seconds":loaded.phase_seconds,
        "network_or_broadcast_performed":false,"hosted_prover":false})
}
fn prove(pk_path: &Path, fd: &str, output: &Path) -> Result<()> {
    // Only public argument syntax is touched before authentication. In
    // particular no File/reader for the inherited witness descriptor exists.
    let number: u32 = fd.parse().map_err(|_| "witness_fd_invalid")?;
    let loaded = parameters::load(pk_path).map_err(|e| e.0)?;
    emit(&loaded.ready())?;
    // Linux procfs reopens the inherited descriptor without a caller-supplied
    // private path or unsafe ownership conversion. No read precedes ready.
    let mut witness =
        fs::File::open(format!("/proc/self/fd/{number}")).map_err(|_| "private_request_io")?;
    let circuit = payment::request::read(&mut witness).map_err(|e| e.code())?;
    drop(witness);
    let auth = circuit.authorization.clone();
    let began = Instant::now();
    let proof = payment::prove(&loaded.pk, circuit, &mut rand::rngs::OsRng)
        .map_err(|_| "private_proof_failed")?;
    let vk = payment::verification_key(&loaded.pk).map_err(|_| "selected_vk_invalid")?;
    if vk.as_slice() != parameters::selected_vk().map_err(|e| e.0)?
        || !payment::Verifier::new(&vk)
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
        &json!({"event":"proof-complete","genuine_Groth16_verified":true,
        "proof_sha256":parameters::digest(&proof),"authorization_sha256":parameters::digest(&auth.bytes()),
        "vk_sha256":parameters::digest(&vk)}),
    )
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prove") if args.len() == 5 => {
            prove(Path::new(&args[2]), &args[3], Path::new(&args[4]))
        }
        Some("loader-only") if args.len() == 4 => {
            let loaded = parameters::load(Path::new(&args[2])).map_err(|e| e.0)?;
            new_private_dir(Path::new(&args[3]))?;
            save_report(&Path::new(&args[3]).join("report.json"), &report(&loaded))?;
            emit(&loaded.ready())
        }
        Some("verify") if args.len() == 4 => {
            let vk = parameters::selected_vk().map_err(|e| e.0)?;
            let mut auth = Vec::new();
            fs::File::open(&args[2])
                .map_err(|_| "public_auth_io")?
                .take(529)
                .read_to_end(&mut auth)
                .map_err(|_| "public_auth_io")?;
            let auth = payment::Authorization::parse(&auth).map_err(|_| "public_auth_invalid")?;
            let mut proof = Vec::new();
            fs::File::open(&args[3])
                .map_err(|_| "public_proof_io")?
                .take(129)
                .read_to_end(&mut proof)
                .map_err(|_| "public_proof_io")?;
            if !payment::Verifier::new(vk)
                .map_err(|_| "selected_vk_invalid")?
                .verify(&auth, &proof)
                .map_err(|_| "public_proof_invalid")?
            {
                return Err("public_proof_invalid");
            }
            emit(
                &json!({"event":"proof-verified","authorization_sha256":parameters::digest(&auth.bytes()),
                "proof_sha256":parameters::digest(&proof),"vk_sha256":parameters::digest(vk)}),
            )
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
