//! One sacrificial stock-Groth16 RSS probe over the exact public relation shape.
//!
//! The retained invocation used only the repository's deliberately invalid
//! public filler, a public signature matrix and the historical PK.  This
//! reusable binary accepts caller paths and therefore does not structurally
//! enforce that boundary.  A produced proof is expected to be unverifiable and
//! is resource evidence only.
#[path = "qualify_joint_core.rs"]
mod qualifier;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_private_batch_relation::joined_source::JoinedSourceCircuit;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

struct HashReader<R> {
    inner: R,
    digest: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        self.digest.update(&output[..count]);
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("PK byte count overflow"))?;
        Ok(count)
    }
}

fn hash_file(path: &Path) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let mut input = BufReader::new(fs::File::open(path)?);
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 1 << 20];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or("file byte overflow")?;
    }
    Ok((hex::encode(digest.finalize()), bytes))
}

fn marker(value: Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string(&value)?);
    io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 10 {
        return Err("usage: probe_public_invalid_proof PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json MATRIX-SHA MAP-SHA AGGREGATE-PK.bin.gz COMPRESSED-SHA DECODED-SHA EXPECTED-ROWS EXPECTED-VARIABLES FRESH-OUTPUT".into());
    }
    let context_path = PathBuf::from(&args[0]);
    let signature_path = PathBuf::from(&args[1]);
    let matrix_sha = args[2].to_str().ok_or("matrix SHA")?;
    let map_sha = args[3].to_str().ok_or("map SHA")?;
    let pk_path = PathBuf::from(&args[4]);
    let compressed_sha = args[5].to_str().ok_or("compressed SHA")?;
    let decoded_sha = args[6].to_str().ok_or("decoded SHA")?;
    let expected_rows: usize = args[7].to_str().ok_or("rows")?.parse()?;
    let expected_variables: usize = args[8].to_str().ok_or("variables")?.parse()?;
    let output = PathBuf::from(&args[9]);
    if output.exists() {
        return Err("fresh probe output required".into());
    }
    fs::create_dir(&output)?;
    let started = Instant::now();
    let context_raw = fs::read(&context_path)?;
    let signature_raw = fs::read(&signature_path)?;
    if hex::encode(Sha256::digest(&signature_raw)) != matrix_sha {
        return Err("public signature matrix pin".into());
    }
    let context_value: Value = serde_json::from_slice(&context_raw)?;
    if context_value["schema"] != "kpb-public-context-history/v1" {
        return Err("public context schema".into());
    }
    let context_bytes: [u8; 276] =
        hex::decode(context_value["context_hex"].as_str().ok_or("context hex")?)?
            .try_into()
            .map_err(|_| "context width")?;
    let context = qualifier::context(context_bytes);
    let signature = auth::interchange::signature_matrix(&signature_raw, matrix_sha, map_sha)?;
    let source = JoinedSourceCircuit::from_public_context(
        context,
        core::array::from_fn(|_| signature.clone()),
    )?;
    let effects_digest = source.public_component_template().effects.digest();
    let public_inputs = [
        Fr::from_le_bytes_mod_order(&effects_digest[..16]),
        Fr::from_le_bytes_mod_order(&effects_digest[16..]),
    ];
    let (actual_compressed_sha, compressed_bytes) = hash_file(&pk_path)?;
    if actual_compressed_sha != compressed_sha || compressed_bytes != 1_749_414_110 {
        return Err("historical compressed PK pin".into());
    }
    marker(json!({
        "stage":"public_invalid_probe_start",
        "classification":"PUBLIC_INVALID_EXACT_RELATION_RESOURCE_PROBE_ONLY",
        "context_sha256":hex::encode(Sha256::digest(&context_raw)),
        "signature_matrix_sha256":matrix_sha,
        "historical_compressed_pk_sha256":compressed_sha,
        "expected_rows":expected_rows,
        "expected_variables":expected_variables,
        "private_fixture_or_trial_identity_read":false,
        "proof_feasibility_privacy_or_financial_acceptance":false
    }))?;
    marker(json!({
        "stage":"historical_pk_decode_start",
        "elapsed_seconds":started.elapsed().as_secs_f64()
    }))?;
    let mut gzip = Command::new("/usr/bin/gzip")
        .args(["-d", "-c"])
        .arg(&pk_path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = gzip.stdout.take().ok_or("gzip stdout")?;
    let mut decoded = HashReader {
        inner: BufReader::with_capacity(1 << 20, stdout),
        digest: Sha256::new(),
        bytes: 0,
    };
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut decoded)?;
    let mut trailing = Vec::new();
    decoded.read_to_end(&mut trailing)?;
    if !trailing.is_empty() {
        return Err("decoded PK trailing bytes".into());
    }
    let decoded_bytes = decoded.bytes;
    let actual_decoded_sha = hex::encode(decoded.digest.finalize());
    if !gzip.wait()?.success()
        || actual_decoded_sha != decoded_sha
        || decoded_bytes != 2_608_842_576
    {
        return Err("historical decoded PK pin".into());
    }
    if pk.vk.gamma_abc_g1.len() != 3
        || pk.a_query.len() != expected_variables
        || pk.b_g1_query.len() != expected_variables
        || pk.b_g2_query.len() != expected_variables
        || pk.l_query.len() + 3 != expected_variables
        || pk.h_query.len() != 16_777_215
    {
        return Err("historical PK exact query shape".into());
    }
    marker(json!({
        "stage":"historical_pk_decoded_and_query_shape_checked",
        "elapsed_seconds":started.elapsed().as_secs_f64(),
        "decoded_pk_sha256":actual_decoded_sha,
        "decoded_pk_bytes":decoded_bytes,
        "a_query":pk.a_query.len(),
        "b_g1_query":pk.b_g1_query.len(),
        "b_g2_query":pk.b_g2_query.len(),
        "h_query":pk.h_query.len(),
        "l_query":pk.l_query.len()
    }))?;
    marker(json!({
        "stage":"public_invalid_ark_prover_entry",
        "elapsed_seconds":started.elapsed().as_secs_f64(),
        "single_attempt_no_retry":true
    }))?;
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(source, &pk, &mut rand::rngs::OsRng)?;
    marker(json!({
        "stage":"public_invalid_ark_prover_returned",
        "elapsed_seconds":started.elapsed().as_secs_f64()
    }))?;
    let prepared = prepare_verifying_key(&pk.vk);
    let accepted = Groth16::<Bn254>::verify_proof(&prepared, &proof, &public_inputs)?;
    if accepted {
        return Err("fatal sentinel: public-invalid filler proof verified".into());
    }
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let mut proof_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("PUBLIC-INVALID-PROOF.bin"))?;
    proof_file.write_all(&proof_bytes)?;
    proof_file.sync_all()?;
    let result = json!({
        "schema":"kpb-public-invalid-exact-shape-proof-rss-probe/v1",
        "classification":"PUBLIC_INVALID_EXACT_RELATION_RESOURCE_PROBE_ONLY",
        "historical_pk_sha256":actual_decoded_sha,
        "expected_rows":expected_rows,
        "expected_variables":expected_variables,
        "proof_sha256":hex::encode(Sha256::digest(&proof_bytes)),
        "proof_bytes":proof_bytes.len(),
        "verification_accepted":accepted,
        "private_fixture_or_trial_identity_read":false,
        "feasibility_privacy_financial_or_authority_claim":false,
        "elapsed_seconds":started.elapsed().as_secs_f64()
    });
    let raw = serde_json::to_vec_pretty(&result)?;
    let mut result_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("RESULT.json"))?;
    result_file.write_all(&raw)?;
    result_file.sync_all()?;
    fs::File::open(&output)?.sync_all()?;
    marker(json!({
        "stage":"public_invalid_probe_complete",
        "verification_accepted":accepted,
        "result_sha256":hex::encode(Sha256::digest(&raw)),
        "elapsed_seconds":started.elapsed().as_secs_f64(),
        "proof_feasibility_privacy_or_financial_acceptance":false
    }))?;
    Ok(())
}
