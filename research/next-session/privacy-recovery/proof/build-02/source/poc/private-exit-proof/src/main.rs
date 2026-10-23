//! New unfunded parameters only. No proving-key or matrix loading path exists.
use ark_serialize::CanonicalSerialize;
use kpi_private_exit_proof as payment;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn hash(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn save(path: &Path, raw: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(raw)?;
    f.sync_all()?;
    Ok(())
}
fn json_save(path: &Path, value: &serde_json::Value) -> Result<()> {
    save(path, &serde_json::to_vec_pretty(value)?)
}
fn new_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn file_hash(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)?;
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
fn outside_git(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    for p in absolute.ancestors() {
        if fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("symlink PK path".into());
        }
    }
    let mut p = absolute.as_path();
    while !p.exists() {
        p = p.parent().ok_or("PK parent")?;
    }
    if std::process::Command::new("git")
        .arg("-C")
        .arg(p)
        .args(["rev-parse", "--show-toplevel"])
        .output()?
        .status
        .success()
    {
        return Err("proving key must stay outside Git".into());
    }
    Ok(())
}
fn source_identity() -> serde_json::Value {
    json!({
    "lib_rs_sha256":hash(include_bytes!("lib.rs")),"circuit_rs_sha256":hash(include_bytes!("circuit.rs")),
    "exact_sha256_rs_sha256":hash(include_bytes!("exact_sha256.rs")),"fixture_rs_sha256":hash(include_bytes!("fixture.rs")),
    "main_rs_sha256":hash(include_bytes!("main.rs")),"domain_hex32":hex::encode(payment::DOMAIN)})
}
fn report_base() -> serde_json::Value {
    json!({"classification":payment::fixture::CLASS,
    "source_identity":source_identity(),"native_validation_here":false,"accepted_chain_backing":false,
    "privacy_qualified":false,"p95_qualified":false,"existing_PK_or_matrix_loaded":false})
}

fn check(
    circuit: payment::circuit::ActionCircuit,
    out: &Path,
    kind: &str,
    expected: bool,
) -> Result<()> {
    new_dir(out)?;
    json_save(
        &out.join("fixture.json"),
        &payment::fixture::to_value(&circuit),
    )?;
    let began = Instant::now();
    // Deliberately bypass host public validation: malformed-control results
    // must be actual complete R1CS outcomes, not parser/host rejections.
    let stats = circuit.check()?;
    let mut report = report_base();
    report["case"] = kind.into();
    report["expected_satisfied"] = expected.into();
    report["constraints"] = stats.constraints.into();
    report["instance_variables"] = stats.instance_variables.into();
    report["witness_variables"] = stats.witness_variables.into();
    report["satisfied"] = stats.satisfied.into();
    report["wall_seconds"] = began.elapsed().as_secs_f64().into();
    report["matches_expectation"] = (stats.satisfied == expected).into();
    report["public_root_updates_checked_here"] = false.into();
    json_save(&out.join("report.json"), &report)?;
    println!("{}", report);
    if stats.satisfied != expected {
        return Err("unexpected complete R1CS result".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveCommand {
    fixture: String,
    output: String,
}

fn do_prove(
    pk: &ark_groth16::ProvingKey<ark_bn254::Bn254>,
    fixture: &Path,
    out: &Path,
) -> Result<()> {
    let began = Instant::now();
    let raw = fs::read(fixture)?;
    let circuit = payment::fixture::from_bytes(&raw)?;
    let auth = circuit.authorization.clone();
    new_dir(out)?;
    let proof = payment::prove(pk, circuit, &mut rand::rngs::OsRng)?;
    let seconds = began.elapsed().as_secs_f64();
    let vk = payment::verification_key(pk)?;
    if !payment::Verifier::new(&vk)?.verify(&auth, &proof)? {
        return Err("additional checked proof verification failed".into());
    }
    save(&out.join("proof128.bin"), &proof)?;
    save(&out.join("verification-key.bin"), &vk)?;
    save(&out.join("authorization528.bin"), &auth.bytes())?;
    let mut r = report_base();
    r["fixture_sha256"] = hash(&raw).into();
    r["authorization_sha256"] = hash(&auth.bytes()).into();
    r["proof_sha256"] = hash(&proof).into();
    r["vk_sha256"] = hash(&vk).into();
    r["genuine_Groth16_verified"] = true.into();
    r["resident_fixture_parse_prove_and_checked_verification_seconds"] = seconds.into();
    r["payout_sompi"] = auth.payout.into();
    r["reserve_after_sompi"] = auth.reserve_after.into();
    json_save(&out.join("report.json"), &r)?;
    println!(
        "{}",
        json!({"event":"proof-complete","report_path":out.join("report.json"),"genuine_Groth16_verified":true})
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn session(fixture: &Path, out: &Path, pk_path: &Path) -> Result<()> {
    outside_git(pk_path)?;
    let raw = fs::read(fixture)?;
    let shape = payment::fixture::from_bytes(&raw)?;
    shape.authorization.validate_public()?;
    new_dir(out)?;
    println!(
        "{}",
        json!({"event":"setup-started","source_identity":source_identity()})
    );
    std::io::stdout().flush()?;
    let began = Instant::now();
    let pk = payment::setup(shape, &mut rand::rngs::OsRng)?;
    let setup_seconds = began.elapsed().as_secs_f64();
    let vk = payment::verification_key(&pk)?;
    let mut f = BufWriter::new(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pk_path)?,
    );
    pk.serialize_uncompressed(&mut f)?;
    f.flush()?;
    f.get_ref().sync_all()?;
    drop(f);
    if let Some(parent) = pk_path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    save(&out.join("verification-key.bin"), &vk)?;
    let mut r = report_base();
    r["schema"] = "kpx3-private-action-new-setup/v1".into();
    r["setup_rng"] = "OsRng".into();
    r["shape_fixture_sha256"] = hash(&raw).into();
    r["fresh_setup_seconds"] = setup_seconds.into();
    r["setup_and_uncompressed_serialization_seconds"] = began.elapsed().as_secs_f64().into();
    r["vk_hex328"] = hex::encode(vk).into();
    r["vk_sha256"] = hash(&vk).into();
    r["local_only_pk_path"] = pk_path.to_string_lossy().as_ref().into();
    r["local_only_pk_bytes"] = pk_path.metadata()?.len().into();
    r["local_only_pk_sha256"] = file_hash(pk_path)?.into();
    r["pk_serialization"] = "arkworks0.6-official-uncompressed".into();
    r["queries"] = json!({"a":pk.a_query.len(),"b_g1":pk.b_g1_query.len(),"b_g2":pk.b_g2_query.len(),
        "l":pk.l_query.len(),"h":pk.h_query.len(),"instances_including_one":pk.vk.gamma_abc_g1.len()});
    json_save(&out.join("report.json"), &r)?;
    println!(
        "{}",
        json!({"event":"ready","report_path":out.join("report.json"),"vk_hex328":hex::encode(vk)})
    );
    std::io::stdout().flush()?;
    for line in BufReader::new(std::io::stdin()).lines() {
        let line = line?;
        if line.trim() == "quit" {
            break;
        }
        let command: ProveCommand = serde_json::from_str(&line)?;
        do_prove(&pk, Path::new(&command.fixture), Path::new(&command.output))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let mode = a
        .get(1)
        .ok_or("mode fixture/positive/negative/check/session/verify/list")?;
    match mode.as_str() {
        "list" => println!(
            "{}",
            json!({"positive":payment::fixture::POSITIVES,"negative":payment::fixture::NEGATIVES})
        ),
        "fixture" => {
            let kind = a.get(2).ok_or("fixture kind")?;
            let c = payment::fixture::positive(kind)?;
            json_save(
                Path::new(a.get(3).ok_or("new fixture file")?),
                &payment::fixture::to_value(&c),
            )?;
        }
        "positive" | "negative" => {
            let kind = a.get(2).ok_or("case")?;
            let expected = mode == "positive";
            let c = if expected {
                payment::fixture::positive(kind)?
            } else {
                payment::fixture::negative(kind)?
            };
            check(c, Path::new(a.get(3).ok_or("new output")?), kind, expected)?;
        }
        "check" => {
            let p = Path::new(a.get(2).ok_or("fixture")?);
            let c = payment::fixture::from_bytes(&fs::read(p)?)?;
            check(
                c,
                Path::new(a.get(3).ok_or("new output")?),
                "external-frozen-fixture",
                true,
            )?;
        }
        "session" => session(
            Path::new(a.get(2).ok_or("shape")?),
            Path::new(a.get(3).ok_or("new setup directory")?),
            Path::new(a.get(4).ok_or("new external PK path")?),
        )?,
        "verify" => {
            let vk = fs::read(a.get(2).ok_or("selected VK")?)?;
            let c = payment::fixture::from_bytes(&fs::read(a.get(3).ok_or("fixture")?)?)?;
            let proof = fs::read(a.get(4).ok_or("proof")?)?;
            let accepted = payment::Verifier::new(&vk)?.verify(&c.authorization, &proof)?;
            println!(
                "{}",
                json!({"accepted":accepted,"auth_sha256":hash(&c.authorization.bytes()),"vk_sha256":hash(&vk)})
            );
            if !accepted {
                return Err("proof rejected".into());
            }
        }
        _ => return Err("unsupported mode; there is no PK/matrix loader".into()),
    }
    Ok(())
}
