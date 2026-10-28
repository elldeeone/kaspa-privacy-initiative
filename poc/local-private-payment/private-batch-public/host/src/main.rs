//! Genuine ADR0074 public R0 runner. No owner witness, wallet or network input.
mod native_proof;
mod receipt_checks;
use kpi_private_batch_public::{evaluate, sha, Profile, Projection, JOURNAL_LEN, PROJECTION_LEN};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digestible, ExecutorEnv, ExitCode,
    ProverOpts,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{error::Error, fs, io::Read, path::Path, time::Instant};
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn hash(bytes: &[u8]) -> String {
    hex::encode(sha(&[bytes]))
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("public input width".into());
    }
    Ok(bytes)
}
fn save(output: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn report(output: &Path, value: Value) -> Result<()> {
    save(output, "report.json", &serde_json::to_vec_pretty(&value)?)?;
    println!("{value}");
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    selected: bool,
    classification: String,
    image_id_hex32: String,
    program_sha256: String,
    component_profile_sha256: String,
}
fn selected() -> Result<Selection> {
    let selection: Selection =
        serde_json::from_slice(include_bytes!("../../outer-selection.json"))?;
    let profile = Profile::installed().map_err(|error| format!("component profile: {error}"))?;
    if !selection.selected
        || selection.schema != "private-batch-outer-selection/v1"
        || selection.classification != "RESEARCH_TESTNET_ONLY"
        || selection.component_profile_sha256 != hex::encode(profile.sha)
    {
        return Err("new outer image unselected".into());
    }
    for digest in [
        &selection.image_id_hex32,
        &selection.program_sha256,
        &selection.component_profile_sha256,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("canonical selected identity".into());
        }
    }
    Ok(selection)
}
fn program(path: &Path) -> Result<(Vec<u8>, String)> {
    let selection = selected()?;
    let bytes = read(path, 256 * 1024 * 1024)?;
    if hash(&bytes) != selection.program_sha256
        || compute_image_id(&bytes)?.to_string() != selection.image_id_hex32
    {
        return Err("new program identity mismatch".into());
    }
    Ok((bytes, selection.image_id_hex32))
}
fn no_dev() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode must be absent".into());
    }
    Ok(())
}
fn ipc() -> Result<()> {
    if std::env::var("RISC0_PROVER").as_deref() != Ok("ipc") {
        return Err("explicit IPC prover required".into());
    }
    let path = std::env::var("RISC0_SERVER_PATH")?;
    if !Path::new(&path).is_absolute() || !Path::new(&path).is_file() {
        return Err("absolute selected IPC worker required".into());
    }
    Ok(())
}
fn input(path: &Path) -> Result<(Vec<u8>, [u8; JOURNAL_LEN])> {
    let bytes = read(path, PROJECTION_LEN)?;
    let journal = evaluate(&bytes).map_err(|error| format!("public predicate: {error}"))?;
    Ok((bytes, journal))
}
fn environment(bytes: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(bytes)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(None);
    Ok(builder.build()?)
}
fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("parameters") if arguments.len() == 2 => {
            let (value, blind, digest) = kpi_private_batch_public::public_parameters();
            println!("{}", json!({"value_generator_hex64":hex::encode(value),
                "blinding_generator_hex64":hex::encode(blind), "curve_parameters_sha256":hex::encode(digest),
                "financial_profile_selected_or_executed":false}));
            Ok(())
        }
        Some("key-check") if arguments.len() == 2 => {
            let profile = Profile::installed().map_err(|error| format!("profile: {error}"))?;
            println!("{}", json!({"component_profile_sha256":hex::encode(profile.sha),
                "aggregate_vk_sha256":hex::encode(profile.aggregate_vk_sha),
                "output_vk_sha256":hex::encode(profile.output_vk_sha), "auth_exit_vk_sha256":hex::encode(profile.auth_exit_vk_sha),
                "domain_hex32":hex::encode(profile.context.domain), "private_input_read":false}));
            Ok(())
        }
        Some("frame-check") if arguments.len() == 4 => {
            let profile = Profile::installed().map_err(|error| format!("profile: {error}"))?;
            let bytes = read(Path::new(&arguments[2]), PROJECTION_LEN)?;
            let projection = Projection::parse(&bytes, &profile.context).map_err(|error| format!("frame: {error}"))?;
            kpi_private_batch_public::wire::validate_transition(&projection).map_err(|error| format!("transition: {error}"))?;
            let output = Path::new(&arguments[3]); fs::create_dir(output)?;
            report(output, json!({"public_frame_and_transition_validated":true,
                "effects_digest_hex32":hex::encode(kpi_private_batch_public::wire::effects_digest(&projection)),
                "G16_or_group_balance_or_VM_verified":false, "accepted_chain_authority":false}))
        }
        Some("host-check") | Some("cross-check") if arguments.len() == 4 => {
            let (bytes, journal) = input(Path::new(&arguments[2]))?;
            if arguments[1] == "cross-check" && kpi_private_batch_public::evaluate_reference(&bytes)
                .map_err(|error| format!("reference: {error}"))? != journal { return Err("reference journal mismatch".into()); }
            let output = Path::new(&arguments[3]); fs::create_dir(output)?; save(output, "journal.bin", &journal)?;
            report(output, json!({"aggregate_and_six_Output_G16_verified":true,
                "independent_arkworks_reference_checked":arguments[1]=="cross-check",
                "public_state_and_global_balance_verified":true, "projection_sha256":hash(&bytes),
                "journal_hex104":hex::encode(journal), "journal_sha256":hash(&journal),
                "R0_or_native_VM_executed":false, "accepted_chain_authority":false}))
        }
        Some("wrap") if arguments.len() == 4 => {
            let raw = read(Path::new(&arguments[2]), 256 * 1024 * 1024)?;
            let bytes = risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            let output = Path::new(&arguments[3]); fs::create_dir(output)?;
            save(output, "guest.program.bin", &bytes)?; save(output, "guest.raw.elf", &raw)?;
            report(output, json!({"image_id_hex32":compute_image_id(&bytes)?.to_string(),
                "program_sha256":hash(&bytes), "selected":false, "proof_or_VM_execution":false}))
        }
        Some("execute") | Some("prove") if arguments.len() == 5 => {
            no_dev()?; ipc()?;
            let (program, image) = program(Path::new(&arguments[2]))?;
            let (bytes, journal) = input(Path::new(&arguments[3]))?;
            let output = Path::new(&arguments[4]); fs::create_dir(output)?; let started = Instant::now();
            if arguments[1] == "execute" {
                let session = default_executor().execute(environment(&bytes)?, &program)?;
                if session.exit_code != ExitCode::Halted(0) || session.journal.bytes != journal {
                    return Err("new guest exact journal/exit mismatch".into());
                }
                save(output, "journal.bin", &journal)?;
                report(output, json!({"genuine_seven_G16_public_guest_execution_passed":true,
                    "image_id_hex32":image,"projection_sha256":hash(&bytes),"journal_sha256":hash(&journal),
                    "cycles":session.cycles(),"seconds":started.elapsed().as_secs_f64(),
                    "operational_session_cycle_limit":null,"proof_generation":false,"native_VM_executed":false}))
            } else {
                let info = default_prover().prove_with_opts(environment(&bytes)?, &program, &ProverOpts::succinct())?;
                let raw = bincode::serialize(&info.receipt)?; save(output,"candidate-receipt.bin",&raw)?;
                receipt_checks::verify(&info.receipt, &image, &journal)?;
                save(output,"receipt.bin",&raw)?;save(output,"journal.bin",&journal)?;
                report(output,json!({"genuine_seven_G16_succinct_receipt_verified":true,"image_id_hex32":image,
                    "receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),"journal_sha256":hash(&journal),
                    "seconds":started.elapsed().as_secs_f64(),"stats":info.stats,"native_VM_executed":false}))
            }
        }
        Some("verify") | Some("native-proof") if arguments.len() == 5 => {
            no_dev()?; let selection = selected()?;
            let journal = read(Path::new(&arguments[3]), JOURNAL_LEN)?;
            let receipt = receipt_checks::read(Path::new(&arguments[2]))?;
            receipt_checks::verify(&receipt, &selection.image_id_hex32, &journal)?;
            let output = Path::new(&arguments[4]); fs::create_dir(output)?;
            if arguments[1] == "native-proof" {
                receipt.inner.groth16()?; let proof = native_proof::encode(&receipt)?;
                save(output,"native-proof.bin",&proof)?;save(output,"journal.bin",&journal)?;
                report(output,json!({"genuine_new_image_Groth16_receipt_verified":true,
                    "native_proof_sha256":hash(&proof),"native_proof_bytes":proof.len(),
                    "image_id_hex32":selection.image_id_hex32,"journal_sha256":hash(&journal),"native_VM_executed":false}))
            } else {
                report(output,json!({"genuine_new_image_receipt_verified":true,"image_id_hex32":selection.image_id_hex32,"journal_sha256":hash(&journal),
                    "development_mode":false,"unresolved_assumptions":false,"native_VM_executed":false}))
            }
        }
        Some("compress") if arguments.len() == 6 => {
            no_dev()?;ipc()?;
            if std::env::var("GITHUB_TOKEN").as_deref()!=Ok("") { return Err("empty GitHub token required".into()); }
            let selection=selected()?;let source=receipt_checks::read(Path::new(&arguments[2]))?;
            if hash(&fs::read(&arguments[2])?)!=arguments[3] { return Err("source receipt SHA mismatch".into()); }
            let journal=read(Path::new(&arguments[4]),JOURNAL_LEN)?;source.inner.succinct()?;
            receipt_checks::verify(&source,&selection.image_id_hex32,&journal)?;
            let claim=source.claim()?.digest();let output=Path::new(&arguments[5]);fs::create_dir(output)?;
            let started=Instant::now();let receipt=default_prover().compress(&ProverOpts::groth16(),&source)?;
            let raw=bincode::serialize(&receipt)?;save(output,"candidate-groth16-receipt.bin",&raw)?;
            receipt.inner.groth16()?;receipt_checks::verify(&receipt,&selection.image_id_hex32,&journal)?;
            if receipt.claim()?.digest()!=claim { return Err("compression changed claim".into()); }
            save(output,"groth16-receipt.bin",&raw)?;save(output,"journal.bin",&journal)?;
            report(output,json!({"same_claim_genuine_Groth16_compression_verified":true,
                "image_id_hex32":selection.image_id_hex32,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),
                "seconds":started.elapsed().as_secs_f64(),"journal_sha256":hash(&journal),"guest_reexecuted":false,"native_VM_executed":false}))
        }
        _ => Err("parameters | key-check | frame-check/host-check/cross-check INPUT NEWOUT | wrap RAW_ELF NEWOUT | execute/prove PROGRAM INPUT NEWOUT | verify/native-proof RECEIPT EXPECTED_J NEWOUT | compress RECEIPT SHA EXPECTED_J NEWOUT".into()),
    }
}
fn main() -> Result<()> {
    run()
}
