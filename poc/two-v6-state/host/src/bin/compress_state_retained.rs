//! Compress one independently pinned retained Succinct receipt; never run a guest.
//! New J336/image; unchanged dependencies and no guest re-execution.
use kpi_private_note_proof as checks;
use kpi_two_v6_state_proof_host as state_host;
use risc0_zkvm::{
    default_prover, sha::Digestible, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde_json::json;
use std::{error::Error, fs, io::Write, path::Path, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

const COMPONENT_ARCHIVE_SHA256: &str =
    "4b4f2b2fb8380369ed14f0dc48380a1bbcbc82c7d553f1888b47d0a9f8e72e4d";

fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err(
            "usage: compress_state_retained SOURCE_RECEIPT EXPECTED_SOURCE_SHA256 NEW_OUTPUT_DIR"
                .into(),
        );
    }
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("RISC0_DEV_MODE must be absent".into());
    }
    if std::env::var("RISC0_PROVER")?.as_str() != "ipc" {
        return Err("only the explicitly selected existing IPC CUDA worker is allowed".into());
    }
    // rzup otherwise attempts to discover a token in the user's gh configuration.
    if std::env::var("GITHUB_TOKEN")?.as_str() != "" {
        return Err("set GITHUB_TOKEN to an empty string to disable credential discovery".into());
    }
    let component_home = std::env::var("RISC0_HOME")?;
    if !Path::new(&component_home).is_absolute() {
        return Err("RISC0_HOME must explicitly name the task-local asset directory".into());
    }
    let work_dir = std::env::var("RISC0_WORK_DIR")?;
    if !Path::new(&work_dir).is_absolute() || !Path::new(&work_dir).is_dir() {
        return Err(
            "RISC0_WORK_DIR must explicitly name an existing task-local scratch directory".into(),
        );
    }
    let component = Path::new(&component_home).join("extensions/v0.1.0-risc0-groth16");
    for filename in [
        "preprocessed_coeffs.bin",
        "fuzzed_msm_results.bin",
        "stark_verify_final.zkey",
        "stark_verify_graph.bin",
    ] {
        if !component.join(filename).is_file() {
            return Err(format!("missing pinned component member {filename}").into());
        }
    }
    let pin = state_host::context("historical-anchor")?;
    let input_path = Path::new(&args[1]);
    if fs::metadata(input_path)?.len() > checks::MAX_RECEIPT_BYTES {
        return Err("source receipt exceeds retained-receipt byte limit".into());
    }
    let source_bytes = fs::read(input_path)?;
    if args[2].len() != 64 || checks::sha(&source_bytes) != args[2] {
        return Err("source receipt differs from externally frozen SHA256".into());
    }
    let source: Receipt = checks::read_receipt(input_path)?;
    if !matches!(&source.inner, InnerReceipt::Succinct(_)) {
        return Err("source must be a genuine Succinct receipt".into());
    }
    let (image_hex, _) = state_host::selection()?;
    let image = checks::digest(&image_hex)?;
    let journal = pin.journal.to_vec();
    state_host::check_receipt(&source, &pin)?;
    let source_claim = source.claim()?.digest();
    let expected_claim = risc0_zkvm::ReceiptClaim::ok(image, journal.clone()).digest();
    if source_claim != expected_claim {
        return Err(
            "source differs from the independently expected successful historical-state claim"
                .into(),
        );
    }
    let output = Path::new(&args[3]);
    fs::create_dir(output)?;
    save(
        output,
        "source-receipt-sha256.txt",
        format!("{}\n", checks::sha(&source_bytes)).as_bytes(),
    )?;

    eprintln!("stage=compress-retained-succinct-to-groth16");
    let started = Instant::now();
    // Only compression: no ExecutorEnv, ELF, execution or prove_with_opts call.
    let compressed = default_prover().compress(&ProverOpts::groth16(), &source)?;
    let seconds = started.elapsed().as_secs_f64();
    let compressed_bytes = bincode::serialize(&compressed)?;
    // Preserve even if any subsequent verification fails.
    save(output, "candidate-groth16-receipt.bin", &compressed_bytes)?;
    let inner = compressed.inner.groth16()?;
    if compressed.journal.bytes != journal || compressed.claim()?.digest() != source_claim {
        return Err("compression changed the pinned journal or top-level claim".into());
    }
    let ctx = VerifierContext::default().with_dev_mode(false);
    compressed.verify_with_context(&ctx, image)?;
    let output_claim = compressed.claim()?.value()?;
    if !output_claim
        .output
        .value()?
        .ok_or("missing output")?
        .assumptions
        .is_empty()
    {
        return Err("compressed receipt has unresolved assumptions".into());
    }
    let mut wrong_image_bytes: [u8; 32] = image.into();
    wrong_image_bytes[0] ^= 1;
    let wrong_image = compressed
        .verify_with_context(&ctx, risc0_zkvm::sha::Digest::from(wrong_image_bytes))
        .err()
        .ok_or("wrong image accepted")?;
    let mut changed_journal = compressed.clone();
    changed_journal.journal.bytes[0] ^= 1;
    let wrong_journal = changed_journal
        .verify_with_context(&ctx, image)
        .err()
        .ok_or("changed journal accepted")?;
    let mut changed_seal = compressed.clone();
    if let InnerReceipt::Groth16(g) = &mut changed_seal.inner {
        let first = g.seal.first_mut().ok_or("empty Groth16 seal")?;
        *first ^= 1;
    }
    let wrong_seal = changed_seal
        .verify_with_context(&ctx, image)
        .err()
        .ok_or("changed Groth16 seal accepted")?;
    save(output, "groth16-receipt.bin", &compressed_bytes)?;
    save(output, "groth16-seal.bin", &inner.seal)?;
    let report = json!({
        "source_kind": "Succinct", "output_kind": "Groth16",
        "same_retained_receipt_compressed": true, "guest_reexecuted": false,
        "source_receipt_sha256": checks::sha(&source_bytes),
        "output_receipt_sha256": checks::sha(&compressed_bytes),
        "output_receipt_bytes": compressed_bytes.len(), "groth16_seal_bytes": inner.seal.len(),
        "groth16_seal_sha256": checks::sha(&inner.seal),
        "image_id": image_hex, "context":pin.name, "journal_bytes": journal.len(), "journal_sha256": checks::sha(&journal),
        "source_claim_digest": source_claim.to_string(), "output_claim_digest": compressed.claim()?.digest().to_string(),
        "verifier_parameters_digest": inner.verifier_parameters.to_string(),
        "expected_component_archive_sha256": COMPONENT_ARCHIVE_SHA256,
        "compression_seconds": seconds, "sdk_verification_passed": true,
        "sdk_negative_controls": {"wrong_image": wrong_image.to_string(), "wrong_journal": wrong_journal.to_string(), "wrong_seal": wrong_seal.to_string()},
        "scope": "Same NONFUNDABLE synthetic state assertion compressed under the established RISC Zero Groth16 wrapper. Actual native predecessor authentication, backing, exits and privacy remain separate gates."
    });
    save(
        output,
        "compression-result.json",
        &[serde_json::to_vec_pretty(&report)?, vec![b'\n']].concat(),
    )?;
    println!("{}", report);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("compress-state-retained: {error}");
        std::process::exit(1);
    }
}
