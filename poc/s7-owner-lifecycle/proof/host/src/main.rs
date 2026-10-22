//! A synthetic declared-context assertion, never a reserve release interface.
use h::{Context, Result};
use kpi_private_note_proof as receipt_checks;
use kpi_s7_lifecycle_proof_host as h;
use kpi_two_v6_state::{StateGate, INPUT_LEN};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ExitCode, ProverOpts,
};
use serde_json::json;
use std::{fs, path::Path, time::Instant};
mod controls;
mod outer_constants;

fn env(input: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(input)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(Some(h::CYCLE_LIMIT));
    Ok(builder.build()?)
}
fn input(path: &Path, pin: &Context) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    h::check_source(&bytes, pin)?;
    Ok(bytes)
}
fn require_ipc() -> Result<()> {
    if std::env::var("RISC0_PROVER").as_deref() != Ok("ipc") {
        return Err("explicit RISC0_PROVER=ipc required".into());
    }
    let server = std::env::var("RISC0_SERVER_PATH")?;
    if !Path::new(&server).is_absolute() || !Path::new(&server).is_file() {
        return Err("absolute task-selected RISC0_SERVER_PATH required".into());
    }
    Ok(())
}
fn wrap(raw: &Path, out: &Path) -> Result<()> {
    StateGate::new()?; // host checks the exact immutable key before guest build/use
    let raw = fs::read(raw)?;
    let program =
        risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image = compute_image_id(&program)?;
    fs::create_dir(out)?;
    h::save(out, "guest.raw.elf", &raw)?;
    h::save(out, "guest.program.bin", &program)?;
    h::save(out, "derived-image.txt", format!("{image}\n").as_bytes())?;
    println!(
        "{}",
        json!({"derived_image":image.to_string(),"program_sha256":h::sha(&program),
        "raw_elf_sha256":h::sha(&raw),"trusted_image_selected":false,"native_settlement":false})
    );
    Ok(())
}
fn host_check(pin: &Context, source: &Path, out: &Path) -> Result<()> {
    let source = fs::read(source)?;
    let assertion = h::check_source(&source, pin)?;
    fs::create_dir(out)?;
    h::save(out, "public.bin", &assertion.projection)?;
    h::save(out, "journal.bin", &assertion.journal)?;
    h::save(
        out,
        "host-checked.json",
        &serde_json::to_vec_pretty(&json!({
            "scope":"DO_NOT_FUND_FRESH_INITIAL_PAIR_HOST_STATE_ASSERTION", "context":pin.name,
            "input_sha256":h::sha(&source),"journal_sha256":h::sha(&assertion.journal),
            "prior_state_sha256":h::sha(&assertion.prior_state.bytes()),
            "next_state_sha256":h::sha(&assertion.next_state.bytes()),
            "reserve_before_sompi":assertion.reserve_before.to_string(),
            "reserve_after_sompi":assertion.reserve_after.to_string(),
            "oracle_matches":true,"native_predecessor_authenticated":false,"native_settlement":false
        }))?,
    )?;
    Ok(())
}
fn execute(pin: &Context, programs: &Path, source: &Path, out: &Path, case: &str) -> Result<()> {
    h::no_dev_mode()?;
    require_ipc()?;
    let program = h::program(programs)?;
    let mut input = input(source, pin)?;
    let expected = controls::mutate(&mut input, pin, case)?;
    fs::create_dir(out)?;
    h::save(out, "input.bin", &input)?;
    let (image, _) = h::selection()?;
    let start = Instant::now();
    let result = default_executor().execute(env(&input)?, &program);
    let mut report = json!({"scope":"DO_NOT_FUND_FRESH_INITIAL_PAIR_GUEST_STATE_EXECUTION_NO_RECEIPT",
        "context":pin.name,"case":case,"image":image,"input_sha256":h::sha(&input),
        "seconds":start.elapsed().as_secs_f64(),"cycle_limit":h::CYCLE_LIMIT,"segment_po2":19,
        "native_predecessor_authenticated":false,"native_settlement":false,"proof_generation":false});
    let passed = match result {
        Ok(session) => {
            h::save(out, "journal.bin", &session.journal.bytes)?;
            report["cycles"] = json!(session.cycles());
            report["segments"] = json!(session.segments.iter().map(|s| s.po2).collect::<Vec<_>>());
            report["exit_code"] = json!(format!("{:?}", session.exit_code));
            report["journal_sha256"] = json!(h::sha(&session.journal.bytes));
            match expected {
                controls::Expected::Journal(journal) => {
                    let matches = session.journal.bytes == journal;
                    report["expected_journal_sha256"] = json!(h::sha(&journal));
                    report["journal_matches"] = json!(matches);
                    report["declared_context_changed"] = json!(case != "valid");
                    matches && session.exit_code == ExitCode::Halted(0)
                }
                controls::Expected::Reject(reason) => {
                    report["expected_rejection"] = json!(reason);
                    false
                }
            }
        }
        Err(error) => {
            let message = format!("{error:#}");
            report["error"] = json!(message);
            match expected {
                controls::Expected::Reject(reason) => {
                    let matches =
                        message.contains(&format!("s7 initial-pair state rejection: {reason}"));
                    report["expected_rejection"] = json!(reason);
                    matches
                }
                controls::Expected::Journal(_) => false,
            }
        }
    };
    report["passed"] = json!(passed);
    h::save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    if !passed {
        return Err("state execution did not match the declared exact result".into());
    }
    Ok(())
}
fn prove(pin: &Context, programs: &Path, source: &Path, out: &Path) -> Result<()> {
    h::no_dev_mode()?;
    require_ipc()?;
    let program = h::program(programs)?;
    let input = input(source, pin)?;
    let (image, program_sha256) = h::selection()?;
    fs::create_dir(out)?;
    h::save(
        out,
        "proof-started.json",
        &serde_json::to_vec_pretty(&json!({
            "scope":"DO_NOT_FUND_FRESH_INITIAL_PAIR_STATE_RECEIPT_ATTEMPT","context":pin.name,
            "image":image,"program_sha256":program_sha256,"input_sha256":pin.input_sha256,
            "journal_sha256":h::sha(pin.journal),"expected_control":h::JOIN,
            "segment_po2":19,"cycle_limit":h::CYCLE_LIMIT,"development_mode":false,
            "native_predecessor_authenticated":false,"native_settlement":false
        }))?,
    )?;
    let start = Instant::now();
    let result = default_prover().prove_with_opts(env(&input)?, &program, &ProverOpts::succinct());
    let info = match result {
        Ok(info) => info,
        Err(error) => {
            h::save(
                out,
                "prover-error.json",
                &serde_json::to_vec_pretty(&json!({
                    "seconds":start.elapsed().as_secs_f64(),"error":format!("{error:#}")
                }))?,
            )?;
            return Err(error.into());
        }
    };
    let bytes = bincode::serialize(&info.receipt)?;
    // Preserve the actual candidate before cryptographic/profile checks.
    h::save(out, "candidate-receipt.bin", &bytes)?;
    h::save(
        out,
        "proof-stats.json",
        &serde_json::to_vec_pretty(&info.stats)?,
    )?;
    h::check_receipt(&info.receipt, pin)?;
    h::save(out, "receipt.bin", &bytes)?;
    h::save(out, "public.bin", h::PUBLIC)?;
    h::save(out, "journal.bin", pin.journal)?;
    h::save(
        out,
        "proof-complete.json",
        &serde_json::to_vec_pretty(&json!({
            "scope":"REAL_DO_NOT_FUND_FRESH_INITIAL_PAIR_STATE_SUCCINCT_RECEIPT","context":pin.name,
            "image":image,"expected_control":h::JOIN,"proof_seconds":start.elapsed().as_secs_f64(),
            "receipt_sha256":h::sha(&bytes),"receipt_bytes":bytes.len(),"stats":info.stats,
            "native_predecessor_authenticated":false,"native_settlement":false,
            "independent_verification_still_required":true
        }))?,
    )?;
    Ok(())
}
fn verify(pin: &Context, receipt: &Path, out: &Path) -> Result<()> {
    h::no_dev_mode()?;
    let bytes = fs::read(receipt)?;
    let receipt = receipt_checks::read_receipt(receipt)?;
    h::check_receipt(&receipt, pin)?;
    let (image, _) = h::selection()?;
    let negatives = receipt_checks::crypto_negatives(&receipt, receipt_checks::digest(&image)?)?;
    fs::create_dir(out)?;
    h::save(out, "public.bin", h::PUBLIC)?;
    h::save(out, "journal.bin", pin.journal)?;
    h::save(
        out,
        "verified.json",
        &serde_json::to_vec_pretty(&json!({
            "scope":"INDEPENDENT_SOFTWARE_SYNTHETIC_STATE_RECEIPT_VERIFICATION",
            "context":pin.name,"image":image,"expected_control":h::JOIN,
            "receipt_sha256":h::sha(&bytes),"journal_sha256":h::sha(pin.journal),
            "journal_bytes":pin.journal.len(),"negatives":negatives,
            "native_predecessor_authenticated":false,"native_settlement":false,
            "development_mode":false,"no_unresolved_assumptions":true
        }))?,
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("validate-key") if args.len() == 2 => {
            StateGate::new()?;
            println!("{}",json!({"checked_immutable_key":true,"input_bytes":INPUT_LEN,
                "journal_bytes":kpi_two_v6_state::JOURNAL_LEN,"native_settlement":false,
                "domain":hex::encode(kpi_two_v6_binding::compiled::COMPILED_DOMAIN),
                "vk_sha256":hex::encode(kpi_two_v6_binding::compiled::COMPILED_KEY_SHA256),
                "pool_id":hex::encode(kpi_two_v6_state::POOL_ID)}));
            Ok(())
        }
        Some("outer-constants") if args.len() == 3 => outer_constants::dump(Path::new(&args[2])),
        Some("wrap") if args.len() == 4 => wrap(Path::new(&args[2]), Path::new(&args[3])),
        Some("host-check") if args.len() == 5 => host_check(&h::context(&args[2])?, Path::new(&args[3]), Path::new(&args[4])),
        Some("check-target") if args.len() == 5 => {
            h::program(Path::new(&args[3]))?;
            input(Path::new(&args[4]), &h::context(&args[2])?)?;
            println!("{}",json!({"target_verified":true,"context":args[2],"proof_started":false}));
            Ok(())
        }
        Some("execute") if args.len() == 7 => execute(&h::context(&args[2])?, Path::new(&args[3]), Path::new(&args[4]), Path::new(&args[5]), &args[6]),
        Some("prove") if args.len() == 6 => prove(&h::context(&args[2])?, Path::new(&args[3]), Path::new(&args[4]), Path::new(&args[5])),
        Some("verify") if args.len() == 5 => verify(&h::context(&args[2])?, Path::new(&args[3]), Path::new(&args[4])),
        _ => Err("validate-key | wrap RAW_ELF NEW_PROGRAMS | host-check CONTEXT INPUT NEW_OUTPUT | check-target CONTEXT PROGRAMS INPUT | execute CONTEXT PROGRAMS INPUT NEW_OUTPUT CASE | prove CONTEXT PROGRAMS INPUT NEW_OUTPUT | verify CONTEXT RECEIPT NEW_OUTPUT".into()),
    }
}
