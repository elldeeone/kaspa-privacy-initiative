//! Fresh private TN10 trial runner. Keys never enter the source worktree.
//! Session mode retains the freshly generated PK until the actual Auth exists.
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_future_private_payment::{
    self as payment,
    circuit::{InputWitness, TransferCircuit},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CLASS: &str = "PRIVATE_TN10_TEST_KAS_ONLY";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    real: bool,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    dummy_key_hex32: String,
    dummy_seed_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    note_hex168: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    classification: String,
    trial_id: String,
    auth_hex484: String,
    inputs: [Input; 2],
    outputs: [Output; 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    classification: String,
    trial_id: String,
    domain_hex32: String,
    local_only_pk_path: String,
    local_only_pk_sha256: String,
    local_only_pk_bytes: u64,
    serialization: String,
    vk_hex328: String,
    circuit_source_sha256: String,
    library_source_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    fixture: String,
    output: String,
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let b = hex::decode(s)?;
    if hex::encode(&b) != s {
        return Err("noncanonical hex".into());
    }
    b.try_into().map_err(|_| "fixed width".into())
}
fn read_circuit(path: &Path) -> Result<(String, String, TransferCircuit)> {
    let raw = fs::read(path)?;
    let fixture_sha256 = hex::encode(Sha256::digest(&raw));
    let f: Fixture = serde_json::from_slice(&raw)?;
    if f.classification != CLASS || f.trial_id.is_empty() {
        return Err("private trial identity required".into());
    }
    let mut inputs = Vec::new();
    for i in f.inputs {
        let mut p = [[0; 32]; 16];
        for (to, from) in p.iter_mut().zip(&i.cm_path_hex) {
            *to = fixed(from)?;
        }
        inputs.push(InputWitness {
            real: i.real,
            note: payment::Note::parse(&fixed::<168>(&i.note_hex168)?)?,
            owner_secret: fixed(&i.s_hex32)?,
            nullifier_secret: fixed(&i.k_hex32)?,
            position: i.position,
            path: p,
            dummy_key: fixed(&i.dummy_key_hex32)?,
            dummy_seed: fixed(&i.dummy_seed_hex32)?,
        });
    }
    Ok((
        f.trial_id,
        fixture_sha256,
        TransferCircuit {
            authorization: payment::Authorization::parse(&fixed::<484>(&f.auth_hex484)?)?,
            inputs: inputs.try_into().map_err(|_| "input count")?,
            outputs: [
                payment::Note::parse(&fixed::<168>(&f.outputs[0].note_hex168)?)?,
                payment::Note::parse(&fixed::<168>(&f.outputs[1].note_hex168)?)?,
            ],
        },
    ))
}
fn source_hashes() -> (String, String) {
    (
        hex::encode(Sha256::digest(include_bytes!(
            "../../../future-private-payment/src/circuit.rs"
        ))),
        hex::encode(Sha256::digest(include_bytes!(
            "../../../future-private-payment/src/lib.rs"
        ))),
    )
}
fn digest(path: &Path) -> Result<String> {
    let mut f = BufReader::new(fs::File::open(path)?);
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn private_output_location(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    for component in absolute.ancestors() {
        if fs::symlink_metadata(component).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("symlink output rejected".into());
        }
    }
    let mut existing = absolute.as_path();
    while !existing.exists() {
        existing = existing.parent().ok_or("output parent")?;
    }
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or("source root")?;
    if absolute.starts_with(source) {
        return Err("private output inside source workspace".into());
    }
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(existing)
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if status.status.success() {
        return Err("private output inside Git".into());
    }
    Ok(())
}
fn fresh_dir(path: &Path) -> Result<()> {
    private_output_location(path)?;
    if path.exists() {
        return Err("fresh output directory required".into());
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn write_new(path: &Path, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn json_new(path: &Path, v: &Value) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(v)?)
}
fn selected(s: &Selection, trial: &str) -> Result<()> {
    let (c, l) = source_hashes();
    if s.schema != "kpx2-tn10-new-key/v1"
        || s.classification != CLASS
        || s.trial_id != trial
        || s.domain_hex32 != hex::encode(payment::DOMAIN)
        || s.serialization != "arkworks-0.6-uncompressed-checked"
        || s.circuit_source_sha256 != c
        || s.library_source_sha256 != l
    {
        return Err("trial/domain/source selection mismatch".into());
    }
    Ok(())
}
fn do_prove(
    pk: &ProvingKey<Bn254>,
    fixture: &Path,
    out: &Path,
    expected_trial: &str,
) -> Result<()> {
    let began = Instant::now();
    let (trial, fixture_sha256, circuit) = read_circuit(fixture)?;
    if trial != expected_trial {
        return Err("wrong trial fixture".into());
    }
    fresh_dir(out)?;
    let vk = payment::verification_key(pk)?;
    let auth = circuit.authorization.clone();
    let proof = payment::prove(pk, circuit, &mut rand::rngs::OsRng)?;
    if !payment::Verifier::new(&vk)?.verify(&auth, &proof)? {
        return Err("proof verification".into());
    }
    write_new(&out.join("proof128.bin"), &proof)?;
    write_new(&out.join("verification-key.bin"), &vk)?;
    let report = json!({"classification":CLASS,"trial_id":trial,"domain_hex32":hex::encode(payment::DOMAIN),
        "fixture_sha256":fixture_sha256,"proof_hex128":hex::encode(proof),"vk_hex328":hex::encode(vk),
        "genuine_Groth16_verified":true,"native_context_checked_here":false,
        "accepted_chain_backing":false,"wall_seconds":began.elapsed().as_secs_f64()});
    json_new(&out.join("report.json"), &report)?;
    println!(
        "{}",
        json!({"event":"proof-complete","report_path":out.join("report.json")})
    );
    std::io::stdout().flush()?;
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let mode = a.get(1).ok_or("mode session/setup/prove/check")?;
    let fixture = Path::new(a.get(2).ok_or("fixture path")?);
    let out = Path::new(a.get(3).ok_or("new output path")?);
    let (trial, _fixture_sha256, circuit) = read_circuit(fixture)?;
    if mode == "prove" {
        let selection = Path::new(a.get(4).ok_or("selection path")?);
        let s: Selection = serde_json::from_slice(&fs::read(selection)?)?;
        selected(&s, &trial)?;
        let key = Path::new(&s.local_only_pk_path);
        if fs::symlink_metadata(key)?.file_type().is_symlink()
            || fs::metadata(key)?.permissions().mode() & 0o777 != 0o600
            || fs::metadata(key)?.len() != s.local_only_pk_bytes
            || digest(key)? != s.local_only_pk_sha256
        {
            return Err("private PK identity/permissions mismatch".into());
        }
        // Resume accepts only fully checked official decoding; no generic unchecked flag.
        let mut reader = BufReader::new(fs::File::open(key)?);
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed(&mut reader)?;
        let mut tail = [0];
        if reader.read(&mut tail)? != 0 {
            return Err("trailing PK bytes".into());
        }
        if hex::encode(payment::verification_key(&pk)?) != s.vk_hex328 {
            return Err("VK mismatch".into());
        }
        return do_prove(&pk, fixture, out, &trial);
    }
    fresh_dir(out)?;
    let started = Instant::now();
    if mode == "check" {
        let stats = circuit.check()?;
        json_new(
            &out.join("report.json"),
            &json!({"trial_id":trial,"constraints":stats.constraints,
            "satisfied":stats.satisfied,"instance_variables":stats.instance_variables,
            "witness_variables":stats.witness_variables}),
        )?;
        if !stats.satisfied {
            return Err("unsatisfied circuit".into());
        }
        return Ok(());
    }
    if mode != "setup" && mode != "session" {
        return Err("unknown mode".into());
    }
    let key = Path::new(a.get(4).ok_or("new private key path")?);
    private_output_location(key)?;
    if key.exists() {
        return Err("new PK must be outside source worktree".into());
    }
    let pk = payment::setup(circuit, &mut rand::rngs::OsRng)?;
    let setup_seconds = started.elapsed().as_secs_f64();
    let vk = payment::verification_key(&pk)?;
    let mut writer = BufWriter::new(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(key)?,
    );
    pk.serialize_uncompressed(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    let (c, l) = source_hashes();
    let selection = json!({"schema":"kpx2-tn10-new-key/v1","classification":CLASS,"trial_id":trial,
        "domain_hex32":hex::encode(payment::DOMAIN),"local_only_pk_path":key.canonicalize()?,
        "local_only_pk_sha256":digest(key)?,"local_only_pk_bytes":fs::metadata(key)?.len(),
        "serialization":"arkworks-0.6-uncompressed-checked","vk_hex328":hex::encode(vk),
        "circuit_source_sha256":c,"library_source_sha256":l});
    write_new(&out.join("verification-key.bin"), &vk)?;
    json_new(&out.join("new-key-selection.json"), &selection)?;
    json_new(
        &out.join("report.json"),
        &json!({"trial_id":trial,"domain_hex32":hex::encode(payment::DOMAIN),
        "setup_seconds":setup_seconds,"setup_and_serialize_seconds":started.elapsed().as_secs_f64(),
        "fresh_local_development_setup":true,"trapdoor_erasure_proved":false}),
    )?;
    println!(
        "{}",
        json!({"event":"ready","trial_id":trial,"selection_path":out.join("new-key-selection.json")})
    );
    std::io::stdout().flush()?;
    if mode == "session" {
        for line in std::io::stdin().lock().lines() {
            let command: Command = serde_json::from_str(&line?)?;
            do_prove(
                &pk,
                Path::new(&command.fixture),
                Path::new(&command.output),
                &trial,
            )?;
        }
    }
    Ok(())
}
