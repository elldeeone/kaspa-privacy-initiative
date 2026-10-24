//! Unfunded ADR59 public predicate runner. No owner witness, key setup or network.
mod native_proof;
use kpi_private_note_proof as checks;
use kpi_shared_settlement_public::{evaluate, sha, Profile, JOURNAL_LEN, PROJECTION_LEN};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digestible, ExecutorEnv, ExitCode,
    InnerReceipt, ProverOpts, Receipt, VerifierContext,
};
use serde_json::{json, Value};
use std::{error::Error, fs, io::Read, path::Path, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const JOIN: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
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
fn selected() -> Result<(String, String)> {
    let v: Value = serde_json::from_slice(include_bytes!("../../outer-selection.json"))?;
    if v["schema"] != "kpx5-public-virtual-settlement-outer-selection/v1"
        || v["selected"] != true
        || v["classification"] != "TESTNET_REHEARSAL_ONLY_ADR0060"
        || v["financial_profile_id"] != "68312927-f203-4317-9816-c47c020eed16"
        || v["journal_bytes"] != JOURNAL_LEN
        || v["funding_or_chain_currentness_authority"] != false
    {
        return Err("outer image unselected".into());
    }
    let image = v["image_id_hex32"]
        .as_str()
        .ok_or("selected image")?
        .to_owned();
    let program = v["program_sha256"]
        .as_str()
        .ok_or("selected program")?
        .to_owned();
    if hex::decode(&image)?.len() != 32 || hex::decode(&program)?.len() != 32 {
        return Err("selected identity width".into());
    }
    Ok((image, program))
}
fn program(path: &Path) -> Result<(Vec<u8>, String)> {
    let (image, expected) = selected()?;
    let b = read(path, 128 * 1024 * 1024)?;
    if hash(&b) != expected || compute_image_id(&b)?.to_string() != image {
        return Err("program identity".into());
    }
    Ok((b, image))
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
        return Err("selected absolute IPC worker required".into());
    }
    Ok(())
}
fn input_and_journal(input: &Path, journal: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let b = read(input, PROJECTION_LEN)?;
    let j = read(journal, JOURNAL_LEN)?;
    if evaluate(&b)
        .map_err(|e| format!("public predicate: {e}"))?
        .as_slice()
        != j
    {
        return Err("independent journal mismatch".into());
    }
    Ok((b, j))
}
fn verify_receipt(r: &Receipt, image: &str, j: &[u8]) -> Result<()> {
    if j.len() != JOURNAL_LEN {
        return Err("exact journal width".into());
    }
    match &r.inner {
        InnerReceipt::Succinct(_) => {
            checks::verify_claim(r, checks::digest(image)?, j, checks::digest(JOIN)?)?
        }
        InnerReceipt::Groth16(_) => {
            r.verify_with_context(
                &VerifierContext::default().with_dev_mode(false),
                checks::digest(image)?,
            )?;
            if r.journal.bytes != j
                || !r
                    .claim()?
                    .value()?
                    .output
                    .value()?
                    .ok_or("claim output")?
                    .assumptions
                    .is_empty()
            {
                return Err("receipt journal or assumptions".into());
            }
        }
        _ => return Err("only genuine succinct or groth16 receipt".into()),
    }
    Ok(())
}
fn env(b: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut e = ExecutorEnv::builder();
    e.write_slice(b)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(Some(512_000_000));
    Ok(e.build()?)
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str){
    Some("key-check") if a.len()==2=>{let p=Profile::installed()?;println!("{}",json!({"checked_static_key":true,"vk_sha256":hex::encode(p.vk_sha),"child_domain":hex::encode(p.domain),"wrapper_domain":hex::encode(p.wrapper),"child_tail_sha256":hash(&p.tail),"private_input_read":false}));Ok(())},
    Some("crypto-check") if a.len()==4=>{let b=read(Path::new(&a[2]),528)?;let q=read(Path::new(&a[3]),128)?;Profile::installed()?.crypto(&b,&q).map_err(|e|format!("public crypto: {e}"))?;println!("{}",json!({"genuine_G16_verified":true,"authorization_sha256":hash(&b),"proof_sha256":hash(&q)}));Ok(())},
    Some("virtual-id") if a.len()==3=>{let p=read(Path::new(&a[2]),3920)?;let id=kpi_shared_settlement_public::virtual_id(&Profile::installed()?,&p).map_err(|e|format!("virtual id: {e}"))?;println!("{}",json!({"canonical_virtual_id":hex::encode(id),"crypto_or_native_execution":false}));Ok(())},
    Some("wrap") if a.len()==4=>{Profile::installed()?;let raw=read(Path::new(&a[2]),128*1024*1024)?;let b=risc0_binfmt::ProgramBinary::new(&raw,risc0_zkos_v1compat::V1COMPAT_ELF).encode();let out=Path::new(&a[3]);fs::create_dir(out)?;save(out,"guest.program.bin",&b)?;save(out,"guest.raw.elf",&raw)?;report(out,json!({"image_id":compute_image_id(&b)?.to_string(),"program_sha256":hash(&b),"selected":false,"native_or_proof_execution":false}))},
    Some("host-check") if a.len()==5=>{let(b,j)=input_and_journal(Path::new(&a[2]),Path::new(&a[3]))?;let out=Path::new(&a[4]);fs::create_dir(out)?;save(out,"journal.bin",&j)?;report(out,json!({"host_public_predicate_passed":true,"input_sha256":hash(&b),"journal_sha256":hash(&j),"journal_bytes":j.len(),"native_or_R0_or_proof_execution":false}))},
    Some("execute")|Some("prove") if a.len()==6=>{no_dev()?;ipc()?;let(b,image)=program(Path::new(&a[2]))?;let(input,j)=input_and_journal(Path::new(&a[3]),Path::new(&a[4]))?;let out=Path::new(&a[5]);fs::create_dir(out)?;let began=Instant::now();
        if a[1]=="execute"{let s=default_executor().execute(env(&input)?,&b)?;save(out,"journal.bin",&s.journal.bytes)?;if s.exit_code!=ExitCode::Halted(0) || s.journal.bytes!=j{return Err("guest journal or exit mismatch".into())}
            report(out,json!({"public_guest_execution_passed":true,"image":image,"journal_sha256":hash(&j),"cycles":s.cycles(),"seconds":began.elapsed().as_secs_f64(),"proof_generation":false,"native_settlement":false}))}
        else{let info=default_prover().prove_with_opts(env(&input)?,&b,&ProverOpts::succinct())?;let raw=bincode::serialize(&info.receipt)?;save(out,"candidate-receipt.bin",&raw)?;verify_receipt(&info.receipt,&image,&j)?;save(out,"receipt.bin",&raw)?;save(out,"journal.bin",&j)?;
            report(out,json!({"genuine_succinct_receipt":true,"image":image,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),"journal_sha256":hash(&j),"stats":info.stats,"seconds":began.elapsed().as_secs_f64(),"native_settlement":false}))}},
    Some("verify") if a.len()==5=>{no_dev()?;let(image,_)=selected()?;let j=read(Path::new(&a[3]),JOURNAL_LEN)?;let r=checks::read_receipt(Path::new(&a[2]))?;verify_receipt(&r,&image,&j)?;let out=Path::new(&a[4]);fs::create_dir(out)?;
        report(out,json!({"genuine_receipt_verified":true,"image":image,"journal_sha256":hash(&j),"development_mode":false,"no_unresolved_assumptions":true,"native_settlement":false}))},
    Some("native-proof") if a.len()==5=>{no_dev()?;let(image,_)=selected()?;let j=read(Path::new(&a[3]),JOURNAL_LEN)?;let r=checks::read_receipt(Path::new(&a[2]))?;r.inner.groth16()?;verify_receipt(&r,&image,&j)?;let proof=native_proof::encode(&r)?;let out=Path::new(&a[4]);fs::create_dir(out)?;save(out,"native-proof.bin",&proof)?;save(out,"journal.bin",&j)?;report(out,json!({"genuine_groth16_receipt_verified":true,"image":image,"journal_sha256":hash(&j),"native_proof_sha256":hash(&proof),"native_proof_bytes":proof.len(),"development_mode":false,"native_settlement":false}))},
    Some("compress") if a.len()==6=>{no_dev()?;ipc()?;if std::env::var("GITHUB_TOKEN").as_deref()!=Ok(""){return Err("empty GitHub token disables credential discovery".into())}
        let(image,_)=selected()?;let raw=read(Path::new(&a[2]),checks::MAX_RECEIPT_BYTES as usize)?;if hash(&raw)!=a[3]{return Err("source receipt digest".into())}let j=read(Path::new(&a[4]),JOURNAL_LEN)?;let source=checks::read_receipt(Path::new(&a[2]))?;
        source.inner.succinct()?;verify_receipt(&source,&image,&j)?;let claim=source.claim()?.digest();let out=Path::new(&a[5]);fs::create_dir(out)?;let began=Instant::now();let r=default_prover().compress(&ProverOpts::groth16(),&source)?;let raw=bincode::serialize(&r)?;save(out,"candidate-groth16-receipt.bin",&raw)?;
        r.inner.groth16()?;verify_receipt(&r,&image,&j)?;if r.claim()?.digest()!=claim{return Err("compression changed claim".into())}save(out,"groth16-receipt.bin",&raw)?;save(out,"groth16-seal.bin",&r.inner.groth16()?.seal)?;save(out,"journal.bin",&j)?;
        report(out,json!({"same_claim_compressed":true,"guest_reexecuted":false,"claim_digest":claim.to_string(),"image":image,"receipt_sha256":hash(&raw),"receipt_bytes":raw.len(),"seconds":began.elapsed().as_secs_f64(),"native_settlement":false}))},
    _=>Err("key-check | crypto-check AUTH PROOF | virtual-id CHILD_PAYLOAD | wrap RAW_ELF NEWOUT | host-check INPUT EXPECTED_J NEWOUT | execute/prove PROGRAM INPUT EXPECTED_J NEWOUT | verify/native-proof RECEIPT EXPECTED_J NEWOUT | compress RECEIPT EXPECTED_SHA EXPECTED_J NEWOUT".into())}
}
fn main() -> Result<()> {
    run()
}
