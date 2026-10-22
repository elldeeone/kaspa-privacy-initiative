//! ADR0038: one unchanged public B2 claim, with separately selected host scheduling.
//! No new guest, circuit, setup, input/context, native transaction or owner path.
use kpi_private_note_proof as checks;
use kpi_s7_lifecycle_proof_host as h;
use risc0_zkvm::{default_prover, sha::Digestible, ExecutorEnv, ProverOpts, ReceiptClaim};
use serde_json::json;
use std::{fs, path::Path, time::Instant};

const WORKER_SHA: &str = "3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7";
const CLAIM: &str = "88f54f54030b2fc884c777a872262679fa15bffca8e613a0f6d40f7d90e92aaa";

fn main() -> h::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || !["ipc", "actor"].contains(&args[1].as_str()) {
        return Err("kpi-s7-proof-performance ipc|actor PROGRAMS INPUT NEW_OUTPUT".into());
    }
    h::no_dev_mode()?;
    if std::env::var("RISC0_PROVER")? != args[1] {
        return Err("explicit selected performance backend required".into());
    }
    if args[1] == "actor" && std::env::var("RISC0_DEFAULT_PROVER_NUM_GPUS")? != "1" {
        return Err("actor requires exactly one selected GPU".into());
    }
    let worker = std::env::var("RISC0_SERVER_PATH")?;
    if !Path::new(&worker).is_absolute() || h::sha(&fs::read(&worker)?) != WORKER_SHA {
        return Err("immutable qualified CUDA worker mismatch".into());
    }
    let pin = h::context("initial-pair")?;
    let program = h::program(Path::new(&args[2]))?;
    let input = fs::read(&args[3])?;
    h::check_source(&input, &pin)?;
    let (image, _) = h::selection()?;
    if ReceiptClaim::ok(checks::digest(&image)?, pin.journal.to_vec()).digest().to_string() != CLAIM {
        return Err("independent expected successful claim mismatch".into());
    }
    let mut builder = ExecutorEnv::builder();
    builder.write_slice(&input).stdout(std::io::stdout()).segment_limit_po2(18).session_limit(Some(h::CYCLE_LIMIT));
    let env = builder.build()?;
    let out = Path::new(&args[4]);
    fs::create_dir(out)?;
    h::save(out, "selected-input.bin", &input)?;
    let start = Instant::now();
    // Bind explicitly: actor Drop stops/waits for its worker processes. It must
    // not silently inflate the API-response interval we report below.
    let prover = default_prover();
    let startup_seconds = start.elapsed().as_secs_f64();
    let proof_start = Instant::now();
    let result = prover.prove_with_opts(env, &program, &ProverOpts::succinct());
    let proof_response_seconds = proof_start.elapsed().as_secs_f64();
    let startup_and_response_seconds = start.elapsed().as_secs_f64();
    let info = match result {
        Ok(info) => info,
        Err(error) => {
            h::save(out, "prover-error.json", &serde_json::to_vec_pretty(&json!({"seconds":start.elapsed().as_secs_f64(),"error":format!("{error:#}")}))?)?;
            return Err(error.into());
        }
    };
    let bytes = bincode::serialize(&info.receipt)?;
    h::save(out, "candidate-receipt.bin", &bytes)?;
    let cleanup_start = Instant::now();
    drop(prover);
    let backend_cleanup_seconds = cleanup_start.elapsed().as_secs_f64();
    h::check_receipt(&info.receipt, &pin)?;
    if info.receipt.claim()?.digest().to_string() != CLAIM {
        return Err("returned genuine claim differs from the selected historical claim".into());
    }
    h::save(out, "receipt.bin", &bytes)?;
    h::save(out, "report.json", &serde_json::to_vec_pretty(&json!({
        "scope":"DO_NOT_FUND_EXISTING_B2_CLAIM_PERFORMANCE_ONLY","backend":args[1],"segment_limit_po2":18,
        "image":image,"input_sha256":h::sha(&input),"journal_sha256":h::sha(pin.journal),"claim_digest":CLAIM,
        "receipt_sha256":h::sha(&bytes),"receipt_bytes":bytes.len(),"backend_startup_seconds":startup_seconds,
        "proof_response_seconds":proof_response_seconds,"startup_and_response_seconds":startup_and_response_seconds,
        "backend_cleanup_seconds":backend_cleanup_seconds,"proof_cleanup_and_verification_seconds":start.elapsed().as_secs_f64(),"stats":info.stats,
        "paging_and_reserved_cycles_available":args[1]=="ipc",
        "development_mode":false,"no_unresolved_assumptions":true,"official_decoded_control":h::JOIN,
        "session_limit_forwarded":args[1]=="ipc","compression_performed":false,"independent_verification_still_required":true
    }))?)?;
    Ok(())
}
