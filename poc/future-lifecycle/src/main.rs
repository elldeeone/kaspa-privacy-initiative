//! Fresh public synthetic integration only. No old key, wallet, native engine,
//! node or network is imported. The caller separately authenticates native data.
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_future_private_payment::{
    self as payment,
    circuit::{InputWitness, TransferCircuit},
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
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
    auth_hex484: String,
    inputs: [Input; 2],
    outputs: [Output; 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySelection {
    schema: String,
    classification: String,
    domain_hex32: String,
    local_only_pk_path: String,
    local_only_pk_sha256: String,
    vk_hex328: String,
    circuit_source_sha256: String,
    library_source_sha256: String,
}
fn source_hashes() -> (String, String) {
    (
        hex::encode(Sha256::digest(include_bytes!(
            "../../future-private-payment/src/circuit.rs"
        ))),
        hex::encode(Sha256::digest(include_bytes!(
            "../../future-private-payment/src/lib.rs"
        ))),
    )
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s)?;
    if hex::encode(&bytes) != s {
        return Err("noncanonical hex".into());
    }
    bytes.try_into().map_err(|_| "fixed width".into())
}
fn read_circuit(path: &Path) -> Result<TransferCircuit> {
    let fixture: Fixture = serde_json::from_slice(&fs::read(path)?)?;
    if fixture.classification != "PUBLIC_SYNTHETIC_DO_NOT_FUND" {
        return Err("public synthetic identity required".into());
    }
    let mut inputs = Vec::new();
    for i in fixture.inputs {
        let mut path = [[0; 32]; 16];
        for (to, from) in path.iter_mut().zip(&i.cm_path_hex) {
            *to = fixed(from)?;
        }
        inputs.push(InputWitness {
            real: i.real,
            note: payment::Note::parse(&fixed::<168>(&i.note_hex168)?)?,
            owner_secret: fixed(&i.s_hex32)?,
            nullifier_secret: fixed(&i.k_hex32)?,
            position: i.position,
            path,
            dummy_key: fixed(&i.dummy_key_hex32)?,
            dummy_seed: fixed(&i.dummy_seed_hex32)?,
        });
    }
    Ok(TransferCircuit {
        authorization: payment::Authorization::parse(&fixed::<484>(&fixture.auth_hex484)?)?,
        inputs: inputs.try_into().map_err(|_| "input count")?,
        outputs: [
            payment::Note::parse(&fixed::<168>(&fixture.outputs[0].note_hex168)?)?,
            payment::Note::parse(&fixed::<168>(&fixture.outputs[1].note_hex168)?)?,
        ],
    })
}
fn fresh(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(format!("refuse overwrite: {}", path.display()).into());
    }
    Ok(())
}
fn digest(path: &Path) -> Result<String> {
    // PK is deliberately local-only; streaming hashing avoids a second copy.
    use std::io::Read;
    let mut reader = BufReader::new(fs::File::open(path)?);
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    loop {
        let n = reader.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).ok_or("mode check/setup/prove")?;
    let fixture = Path::new(args.get(2).ok_or("fixture JSON")?);
    let out = Path::new(args.get(3).ok_or("fresh output directory")?);
    fresh(out)?;
    fs::create_dir_all(out)?;
    let started = Instant::now();
    let circuit = read_circuit(fixture)?;
    let mut report = json!({"classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND",
        "mode":mode,"fixture_sha256":digest(fixture)?,
        "accepted_chain_backing":false,"privacy_qualified":false,
        "native_context_checked_here":false});
    match mode.as_str() {
        "check" => {
            let stats = circuit.check()?;
            report["constraints"] = stats.constraints.into();
            report["instance_variables"] = stats.instance_variables.into();
            report["witness_variables"] = stats.witness_variables.into();
            report["satisfied"] = stats.satisfied.into();
            if !stats.satisfied {
                return Err("unsatisfied circuit".into());
            }
        }
        "setup" => {
            let keypath = Path::new(args.get(4).ok_or("new local-only PK path")?);
            fresh(keypath)?;
            // The reviewed runner executes from its read-only source workspace;
            // private outputs must be outside that workspace, also in bwrap.
            let repo = std::env::current_dir()?.canonicalize()?;
            if keypath
                .parent()
                .ok_or("PK parent")?
                .canonicalize()?
                .starts_with(repo)
            {
                return Err("new PK must remain outside Git workspace".into());
            }
            let pk = payment::setup(circuit, &mut rand::rngs::OsRng)?;
            let vk = payment::verification_key(&pk)?;
            use std::os::unix::fs::OpenOptionsExt;
            let mut writer = BufWriter::new(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(keypath)?,
            );
            pk.serialize_compressed(&mut writer)?;
            writer.flush()?;
            fs::write(out.join("verification-key.bin"), vk)?;
            report["vk_hex328"] = hex::encode(vk).into();
            report["local_only_pk_sha256"] = digest(keypath)?.into();
            report["local_only_pk_bytes"] = fs::metadata(keypath)?.len().into();
            report["setup_trust"] =
                "Fresh local development setup; trapdoor erasure unproved".into();
            let (circuit_hash, library_hash) = source_hashes();
            let selection = json!({"schema":"kpx2-new-development-key-selection/v1",
                "classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND",
                "domain_hex32":hex::encode(payment::DOMAIN),
                "local_only_pk_path":keypath.canonicalize()?.to_string_lossy(),
                "local_only_pk_sha256":digest(keypath)?,"vk_hex328":hex::encode(vk),
                "circuit_source_sha256":circuit_hash,"library_source_sha256":library_hash});
            fs::write(
                out.join("new-key-selection.json"),
                serde_json::to_vec_pretty(&selection)?,
            )?;
        }
        "prove" => {
            let selection_path = Path::new(args.get(4).ok_or("selected new-key-selection.json")?);
            let selected: KeySelection = serde_json::from_slice(&fs::read(selection_path)?)?;
            let (circuit_hash, library_hash) = source_hashes();
            if selected.schema != "kpx2-new-development-key-selection/v1"
                || selected.classification != "PUBLIC_SYNTHETIC_DO_NOT_FUND"
                || selected.domain_hex32 != hex::encode(payment::DOMAIN)
                || selected.circuit_source_sha256 != circuit_hash
                || selected.library_source_sha256 != library_hash
            {
                return Err("wrong new-format key/source selection".into());
            }
            let keypath = Path::new(&selected.local_only_pk_path);
            if digest(keypath)? != selected.local_only_pk_sha256 {
                return Err("PK identity mismatch".into());
            }
            let mut reader = BufReader::new(fs::File::open(keypath)?);
            let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)?;
            use std::io::Read;
            let mut tail = [0];
            if reader.read(&mut tail)? != 0 {
                return Err("trailing PK data".into());
            }
            let vk = payment::verification_key(&pk)?;
            if hex::encode(vk) != selected.vk_hex328 {
                return Err("selected VK mismatch".into());
            }
            let auth = circuit.authorization.clone();
            let proof = payment::prove(&pk, circuit, &mut rand::rngs::OsRng)?;
            if !payment::Verifier::new(&vk)?.verify(&auth, &proof)? {
                return Err("proof verification".into());
            }
            fs::write(out.join("proof128.bin"), proof)?;
            fs::write(out.join("verification-key.bin"), vk)?;
            report["proof_hex128"] = hex::encode(proof).into();
            report["vk_hex328"] = hex::encode(vk).into();
            report["genuine_Groth16_verified"] = true.into();
            report["local_only_pk_sha256"] = digest(keypath)?.into();
        }
        _ => return Err("unknown mode".into()),
    }
    report["wall_seconds"] = started.elapsed().as_secs_f64().into();
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
