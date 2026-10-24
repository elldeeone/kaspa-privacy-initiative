//! Genuine new-profile R0 runner. No wallet, witness construction or network.
mod native_proof;
mod receipt_checks;
use kpi_owner_private_lifecycle_verifier::{
    evaluate, sha, Profile, Projection, JOURNAL_LEN, PROJECTION_LEN,
};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digestible, ExecutorEnv, ExitCode,
    ProverOpts,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{error::Error, fs, io::Read, path::Path, time::Instant};
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SESSION_CYCLES: u64 = 2_000_000_000;
fn hash(b: &[u8]) -> String {
    hex::encode(sha(&[b]))
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    fs::File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut b)?;
    if b.len() > max {
        return Err("public input size".into());
    }
    Ok(b)
}
fn save(out: &Path, name: &str, b: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(name))?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn report(out: &Path, v: Value) -> Result<()> {
    save(out, "report.json", &serde_json::to_vec_pretty(&v)?)?;
    println!("{v}");
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
    let v: Selection = serde_json::from_slice(include_bytes!("../../outer-selection.json"))?;
    let p = Profile::installed().map_err(|e| format!("component profile: {e}"))?;
    if v.schema != "kpx8-owner-private-outer-selection/v1"
        || !v.selected
        || v.classification != "TN10_RESEARCH_ONLY_ADR0064"
        || v.component_profile_sha256 != hex::encode(p.sha)
    {
        return Err("new outer image unselected".into());
    }
    for h in [
        &v.image_id_hex32,
        &v.program_sha256,
        &v.component_profile_sha256,
    ] {
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("canonical selected identity".into());
        }
    }
    Ok(v)
}
fn program(path: &Path) -> Result<(Vec<u8>, String)> {
    let s = selected()?;
    let b = read(path, 256 * 1024 * 1024)?;
    if hash(&b) != s.program_sha256 || compute_image_id(&b)?.to_string() != s.image_id_hex32 {
        return Err("new program identity mismatch".into());
    }
    Ok((b, s.image_id_hex32))
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
    let p = std::env::var("RISC0_SERVER_PATH")?;
    if !Path::new(&p).is_absolute() || !Path::new(&p).is_file() {
        return Err("absolute selected IPC worker required".into());
    }
    Ok(())
}
fn input(path: &Path) -> Result<(Vec<u8>, [u8; JOURNAL_LEN])> {
    let b = read(path, PROJECTION_LEN)?;
    let j = evaluate(&b).map_err(|e| format!("public predicate: {e}"))?;
    Ok((b, j))
}
fn env(b: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut e = ExecutorEnv::builder();
    e.write_slice(b)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(Some(SESSION_CYCLES));
    Ok(e.build()?)
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str){
    Some("parameters")if a.len()==2=>{let(v,r,d)=kpi_owner_private_lifecycle_verifier::public_parameters();println!("{}",json!({"domain_hex32":hex::encode(kpi_owner_private_lifecycle_verifier::DOMAIN),"value_generator_hex64":hex::encode(v),"blinding_generator_hex64":hex::encode(r),"curve_parameters_sha256":hex::encode(d),"selected_financial_profile_or_proof_execution":false}));Ok(())},
    Some("key-check")if a.len()==2=>{let p=Profile::installed().map_err(|e|format!("profile: {e}"))?;println!("{}",json!({"component_profile_sha256":hex::encode(p.sha),"spend_vk_sha256":hex::encode(p.spend_vk_sha),"output_vk_sha256":hex::encode(p.output_vk_sha),"exit_vk_sha256":hex::encode(p.exit_vk_sha),"new_domain_hex32":hex::encode(kpi_owner_private_lifecycle_verifier::DOMAIN),"private_input_read":false}));Ok(())},
    Some("frame-check")if a.len()==4=>{let b=read(Path::new(&a[2]),PROJECTION_LEN)?;let p=Projection::parse(&b).map_err(|e|format!("frame: {e}"))?;kpi_owner_private_lifecycle_verifier::wire::validate_transition(&p).map_err(|e|format!("transition: {e}"))?;let out=Path::new(&a[3]);fs::create_dir(out)?;report(out,json!({"public_frame_and_transition_validated":true,"effects_digest_hex32":hex::encode(kpi_owner_private_lifecycle_verifier::wire::effects_digest(&p)),"G16_or_group_balance_or_VM_verified":false,"accepted_chain_authority":false}))},
    Some("host-check")|Some("cross-check")if a.len()==4=>{let(b,j)=input(Path::new(&a[2]))?;if a[1]=="cross-check"{if kpi_owner_private_lifecycle_verifier::evaluate_reference(&b).map_err(|e|format!("reference verifier: {e}"))?!=j{return Err("reference journal mismatch".into());}}let out=Path::new(&a[3]);fs::create_dir(out)?;save(out,"journal.bin",&j)?;report(out,json!({"all_three_Spend_and_six_Output_G16_verified":true,"independent_arkworks_pairing_reference_checked":a[1]=="cross-check","public_state_native_effects_and_global_balance_verified":true,"input_sha256":hash(&b),"journal_hex104":hex::encode(j),"journal_sha256":hash(&j),"R0_or_native_VM_executed":false,"accepted_chain_authority":false}))},
    Some("exit-check")if a.len()==5=>{let raw=read(Path::new(&a[2]),2000)?;let proof=read(Path::new(&a[3]),128)?;let j=kpi_owner_private_lifecycle_verifier::evaluate_exit(&raw,&proof).map_err(|e|format!("direct exit: {e}"))?;let out=Path::new(&a[4]);fs::create_dir(out)?;save(out,"journal.bin",&j)?;report(out,json!({"direct_Exit_G16_verified":true,"independent_arkworks_pairing_reference_checked":true,"public_exit_transition_and_native_effects_checked":true,"projection_sha256":hash(&raw),"journal_sha256":hash(&j),"R0_or_native_VM_executed":false,"accepted_chain_authority":false}))},
    Some("wrap")if a.len()==4=>{let raw=read(Path::new(&a[2]),256*1024*1024)?;let b=risc0_binfmt::ProgramBinary::new(&raw,risc0_zkos_v1compat::V1COMPAT_ELF).encode();let out=Path::new(&a[3]);fs::create_dir(out)?;save(out,"guest.program.bin",&b)?;save(out,"guest.raw.elf",&raw)?;report(out,json!({"image_id_hex32":compute_image_id(&b)?.to_string(),"program_sha256":hash(&b),"selected":false,"proof_or_VM_execution":false}))},
    Some("execute")|Some("prove")if a.len()==5=>{no_dev()?;ipc()?;let(program,image)=program(Path::new(&a[2]))?;let(b,j)=input(Path::new(&a[3]))?;let out=Path::new(&a[4]);fs::create_dir(out)?;let began=Instant::now();
        if a[1]=="execute"{let s=default_executor().execute(env(&b)?,&program)?;if s.exit_code!=ExitCode::Halted(0)||s.journal.bytes!=j{return Err("new guest exact journal or exit mismatch".into());}save(out,"journal.bin",&j)?;report(out,json!({"genuine_nine_G16_public_guest_execution_passed":true,"image_id_hex32":image,"input_sha256":hash(&b),"journal_sha256":hash(&j),"cycles":s.cycles(),"seconds":began.elapsed().as_secs_f64(),"declared_operational_session_cycle_allowance":SESSION_CYCLES,"proof_generation":false,"native_VM_executed":false}))}
        else{let info=default_prover().prove_with_opts(env(&b)?,&program,&ProverOpts::succinct())?;let raw=bincode::serialize(&info.receipt)?;save(out,"candidate-receipt.bin",&raw)?;receipt_checks::verify(&info.receipt,&image,&j)?;save(out,"receipt.bin",&raw)?;save(out,"journal.bin",&j)?;report(out,json!({"genuine_nine_G16_succinct_receipt_verified":true,"image_id_hex32":image,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),"journal_sha256":hash(&j),"seconds":began.elapsed().as_secs_f64(),"stats":info.stats,"native_VM_executed":false}))}},
    Some("verify")|Some("native-proof")if a.len()==5=>{no_dev()?;let s=selected()?;let j=read(Path::new(&a[3]),JOURNAL_LEN)?;let r=receipt_checks::read(Path::new(&a[2]))?;receipt_checks::verify(&r,&s.image_id_hex32,&j)?;let out=Path::new(&a[4]);fs::create_dir(out)?;
        if a[1]=="native-proof"{r.inner.groth16()?;let proof=native_proof::encode(&r)?;save(out,"native-proof.bin",&proof)?;save(out,"journal.bin",&j)?;report(out,json!({"genuine_new_image_Groth16_receipt_verified":true,"native_proof_sha256":hash(&proof),"native_proof_bytes":proof.len(),"image_id_hex32":s.image_id_hex32,"journal_sha256":hash(&j),"native_VM_executed":false}))}
        else{report(out,json!({"genuine_new_image_receipt_verified":true,"journal_sha256":hash(&j),"development_mode":false,"unresolved_assumptions":false,"native_VM_executed":false}))}},
    Some("compress")if a.len()==6=>{no_dev()?;ipc()?;if std::env::var("GITHUB_TOKEN").as_deref()!=Ok(""){return Err("empty GitHub token disables credential discovery".into());}let s=selected()?;let source=receipt_checks::read(Path::new(&a[2]))?;if hash(&fs::read(&a[2])?)!=a[3]{return Err("source succinct receipt SHA mismatch".into());}let j=read(Path::new(&a[4]),JOURNAL_LEN)?;source.inner.succinct()?;receipt_checks::verify(&source,&s.image_id_hex32,&j)?;let claim=source.claim()?.digest();let out=Path::new(&a[5]);fs::create_dir(out)?;let began=Instant::now();let r=default_prover().compress(&ProverOpts::groth16(),&source)?;let raw=bincode::serialize(&r)?;save(out,"candidate-groth16-receipt.bin",&raw)?;r.inner.groth16()?;receipt_checks::verify(&r,&s.image_id_hex32,&j)?;if r.claim()?.digest()!=claim{return Err("compression changed claim".into());}save(out,"groth16-receipt.bin",&raw)?;save(out,"journal.bin",&j)?;report(out,json!({"same_claim_genuine_Groth16_compression_verified":true,"image_id_hex32":s.image_id_hex32,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),"seconds":began.elapsed().as_secs_f64(),"guest_reexecuted":false,"native_VM_executed":false}))},
    _=>Err("key-check | frame-check/host-check INPUT NEWOUT | wrap RAW_ELF NEWOUT | execute/prove PROGRAM INPUT NEWOUT | verify/native-proof RECEIPT EXPECTED_J NEWOUT | compress RECEIPT SHA EXPECTED_J NEWOUT".into())}
}
fn main() -> Result<()> {
    run()
}
