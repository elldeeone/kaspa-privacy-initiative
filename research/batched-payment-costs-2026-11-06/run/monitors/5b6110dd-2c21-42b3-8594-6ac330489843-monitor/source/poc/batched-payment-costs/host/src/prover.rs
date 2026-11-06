//! Existing SDK proof + compression, strict new-image/journal verification.
use crate::proof;
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;
use kpi_batched_payment_core as app;
use risc0_zkvm::{
    ExecutorEnv, ProverOpts, Receipt, VerifierContext, compute_image_id, default_executor,
    default_prover,
    sha::{Digest, Digestible},
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn write(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)?;
    f.write_all(bytes)?;
    Ok(())
}
pub fn env(input: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut env = ExecutorEnv::builder();
    env.write_slice(&[u32::try_from(input.len())?])
        .write_slice(input)
        .segment_limit_po2(19)
        .session_limit(Some(1_000_000_000));
    Ok(env.build()?)
}
pub fn verify(r: &Receipt, image: Digest, journal: &[u8]) -> Result<()> {
    r.inner.groth16()?;
    r.verify_with_context(&VerifierContext::default().with_dev_mode(false), image)?;
    if r.journal.bytes != journal {
        return Err("exact independent journal".into());
    }
    if !r
        .claim()?
        .value()?
        .output
        .value()?
        .ok_or("missing claim output")?
        .assumptions
        .is_empty()
    {
        return Err("unresolved assumptions".into());
    }
    if r.claim()?.digest() != risc0_zkvm::ReceiptClaim::ok(image, journal.to_vec()).digest() {
        return Err("successful complete claim".into());
    }
    Ok(())
}
pub fn native_proof(r: &Receipt) -> Result<Vec<u8>> {
    let params = risc0_zkvm::Groth16ReceiptVerifierParameters::default();
    let v = risc0_groth16::Verifier::new(
        &r.inner.groth16()?.seal,
        params.control_root,
        r.claim()?.digest(),
        params.bn254_control_id,
        &params.verifying_key,
    )?;
    // Exact pinned SDK serde-encoded fields (PVK, uncompressed proof, prepared
    // inputs). Decode the proof with standard checked Arkworks and re-encode;
    // no curve arithmetic or unchecked submitted-point parser is invented.
    let (_, bytes, _): (Vec<u8>, Vec<u8>, Vec<u8>) =
        bincode::deserialize(&bincode::serialize(&v)?)?;
    let mut cursor = bytes.as_slice();
    let p = Proof::<Bn254>::deserialize_uncompressed(&mut cursor)?;
    if !cursor.is_empty() {
        return Err("SDK proof trailing bytes".into());
    }
    let raw = proof::serialize(&p);
    if raw.len() != 128 {
        return Err("native proof size".into());
    }
    Ok(raw)
}
pub fn prove(program: &[u8], input: &app::Input, out: &Path) -> Result<(Vec<u8>, Value)> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode forbidden".into());
    }
    fs::create_dir(out)?;
    let raw = bincode::serialize(input)?;
    write(&out.join("input.bin"), &raw)?;
    let expected = app::execute(input).map_err(|e| format!("host kernel: {e}"))?;
    write(&out.join("expected-journal.bin"), &expected.journal)?;
    let image = compute_image_id(program)?;
    eprintln!(
        "PROVE_START {} image={image} operations={}",
        out.display(),
        input.packet.operations.len()
    );
    let started = Instant::now();
    let info = default_prover().prove_with_opts(env(&raw)?, program, &ProverOpts::succinct())?;
    write(
        &out.join("candidate-succinct.bin"),
        &bincode::serialize(&info.receipt)?,
    )?;
    info.receipt
        .verify_with_context(&VerifierContext::default().with_dev_mode(false), image)?;
    if info.receipt.journal.bytes != expected.journal {
        return Err("guest/host independent journal mismatch".into());
    }
    let succinct_seconds = started.elapsed().as_secs_f64();
    eprintln!(
        "COMPRESS_START {} succinct_seconds={succinct_seconds:.3}",
        out.display()
    );
    let t = Instant::now();
    let compressed = default_prover().compress(&ProverOpts::groth16(), &info.receipt)?;
    write(
        &out.join("candidate-compressed.bin"),
        &bincode::serialize(&compressed)?,
    )?;
    verify(&compressed, image, &expected.journal)?;
    let raw_proof = native_proof(&compressed)?;
    write(&out.join("native-proof.bin"), &raw_proof)?;
    let report = json!({"image":image.to_string(),"operations":input.packet.operations.len(),"mode":input.packet.mode,"stats":info.stats,"succinctSeconds":succinct_seconds,"compressionSeconds":t.elapsed().as_secs_f64(),"totalProofSeconds":started.elapsed().as_secs_f64(),"nativeProofBytes":raw_proof.len(),"compressedReceiptBytes":bincode::serialize(&compressed)?.len(),"journalBytes":expected.journal.len(),"developmentMode":false,"completeReceiptVerified":true,"publicProverInputsOnly":true,"claimDigest":compressed.claim()?.digest().to_string(),"sourceInputSha256":hex::encode(proof::hash(&raw))});
    write(
        &out.join("proof-report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!(
        "PROVE_DONE {} seconds={:.3}",
        out.display(),
        started.elapsed().as_secs_f64()
    );
    Ok((raw_proof, report))
}
pub fn reject_guest(program: &[u8], input: &app::Input) -> Result<String> {
    let raw = bincode::serialize(input)?;
    match default_executor().execute(env(&raw)?, program) {
        Ok(_) => Err("invalid guest input accepted".into()),
        Err(e) => Ok(format!("{e:#}")),
    }
}
