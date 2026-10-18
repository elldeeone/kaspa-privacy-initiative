//! Owner-authorized local segmentation experiment; no wallet or native IO.
use anyhow::{ensure, Result};
use risc0_zkvm::{
    compute_image_id, default_prover, sha::{Digest, Digestible, Sha256}, ApiClient,
    Asset, AssetRequest, ExecutorEnv, ProverOpts, Receipt, ReceiptClaim,
    SegmentReceipt, SuccinctReceipt, VerifierContext,
};
use serde_json::{json, Value};
use std::{fs, io::Write, path::{Path, PathBuf}, time::Instant};

const IMAGE: &str = "397bcdca688462b9573a4b55e3516e1a2511140512c53337eb54da0849a93716";
const INPUT: &str = "56e5010fd63dfd974d4f166a58c24bd4e0ae6bb38d437b9d624a8b8b850f5c90";
const PROGRAM: &str = "3db122223c3c374ee7a858cc9063b0627d224778c6bed571cc24c23796f30739";
const JOURNAL: &str = "625f5c4cc784d3736663b796174e5342cd9ab95ee62507f6680a128f95d99ce2";
fn hash(b: &[u8]) -> String { risc0_zkvm::sha::Impl::hash_bytes(b).to_string() }
fn context() -> VerifierContext { VerifierContext::default().with_dev_mode(false) }
fn image() -> Result<Digest> {
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&IMAGE[i..i+2],16)).collect::<std::result::Result<_,_>>()?;
    Ok(bytes.as_slice().try_into()?)
}
fn save(out: &Path, name: &str, data: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(out.join(name))?;
    f.write_all(data)?; f.sync_all()?; Ok(())
}
fn report(out: &Path, name: &str, v: Value) -> Result<()> {
    save(out, name, &serde_json::to_vec_pretty(&v)?)
}
fn inputs(package: &Path) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let p = fs::read(package.join("inputs/program.bin"))?;
    let i = fs::read(package.join("inputs/input.bin"))?;
    let j = fs::read(package.join("inputs/expected-journal.bin"))?;
    ensure!(hash(&p) == PROGRAM && hash(&i) == INPUT && hash(&j) == JOURNAL, "original public input identity mismatch");
    ensure!(compute_image_id(&p)? == image()?, "program identity mismatch");
    Ok((p, i, j))
}
fn env(input: &[u8], po2: u32) -> Result<ExecutorEnv<'static>> {
    ensure!([17,18,19].contains(&po2), "undeclared segment size");
    let mut b = ExecutorEnv::builder();
    b.write_slice(&[u32::try_from(input.len())?]).write_slice(input)
        .segment_limit_po2(po2).session_limit(Some(192_000_000));
    Ok(b.build()?)
}
fn segment_check(r: &SegmentReceipt) -> Result<()> {
    r.verify_integrity_with_context(&context())?;
    let mut bad = r.clone(); bad.seal[0] ^= 1;
    ensure!(bad.verify_integrity_with_context(&context()).is_err(), "altered segment seal accepted");
    let mut bad = r.clone(); bad.claim.pre = risc0_zkvm::MaybePruned::Pruned(Digest::ZERO);
    ensure!(bad.verify_integrity_with_context(&context()).is_err(), "altered segment claim accepted");
    Ok(())
}
fn succinct_check(r: &SuccinctReceipt<ReceiptClaim>, expected: &ReceiptClaim) -> Result<()> {
    r.verify_integrity_with_context(&context())?;
    ensure!(r.claim.digest() == expected.digest(), "wrong succinct claim");
    let mut bad = r.clone(); bad.seal[0] ^= 1;
    ensure!(bad.verify_integrity_with_context(&context()).is_err(), "altered succinct seal accepted");
    let mut bad = r.clone(); bad.claim = ReceiptClaim::ok(Digest::ZERO, vec![]).into();
    ensure!(bad.verify_integrity_with_context(&context()).is_err(), "altered succinct claim accepted");
    Ok(())
}
fn export(package: &Path, out: &Path, po2: u32) -> Result<()> {
    let (program, input, journal) = inputs(package)?;
    fs::create_dir(out)?; fs::create_dir(out.join("segments"))?;
    let mut rows = vec![]; let mut cycle = 0u64;
    let start = Instant::now();
    let session = ApiClient::from_env()?.execute(&env(&input,po2)?, Asset::Inline(program.into()),
        AssetRequest::Path(out.join("segments").canonicalize()?), |info, asset| {
            let index = rows.len(); let raw = asset.as_bytes()?;
            save(&out.join("segments"), &format!("{index}.bincode"), &raw)?;
            rows.push(json!({"index":index,"po2":info.po2,"userCycleStart":cycle,
                "userCycleEnd":cycle+u64::from(info.cycles),"assetSha256":hash(&raw)}));
            cycle += u64::from(info.cycles); Ok(())
        })?;
    ensure!(session.journal.bytes == journal, "execution journal mismatch");
    ensure!(session.receipt_claim.as_ref().ok_or_else(||anyhow::anyhow!("missing claim"))?.digest()
            == ReceiptClaim::ok(image()?,journal).digest(), "execution claim mismatch");
    ensure!(rows.iter().all(|r| r["po2"].as_u64().unwrap() <= u64::from(po2)), "oversized exported segment");
    let selected = rows.iter().position(|r| r["userCycleEnd"].as_u64().unwrap() > 24_000_000)
        .ok_or_else(||anyhow::anyhow!("missing representative interval"))?;
    ensure!(selected+1 < rows.len() && rows[selected]["po2"] == po2 && rows[selected+1]["po2"] == po2,
            "representative segments not full-sized");
    report(out,"session.json",json!({"scope":"EXECUTION_ONLY_NEW_SEGMENTATION","segmentPo2":po2,
        "userCycles":session.cycles(),"segmentCount":rows.len(),"seconds":start.elapsed().as_secs_f64(),
        "selected":[selected,selected+1],"segments":rows,"expectedProgramImage":IMAGE,
        "programSha256":PROGRAM,"inputSha256":INPUT,"expectedJournalSha256":JOURNAL}))
}
fn bench(out: &Path) -> Result<()> {
    let m: Value = serde_json::from_slice(&fs::read(out.join("session.json"))?)?;
    let api = ApiClient::from_env()?; let mut lifted = vec![]; let mut timings = vec![];
    for i in m["selected"].as_array().ok_or_else(||anyhow::anyhow!("selected indices"))? {
        let index = i.as_u64().unwrap() as usize;
        let path = out.join(format!("segments/{index}.bincode"));
        ensure!(hash(&fs::read(&path)?) == m["segments"][index]["assetSha256"], "trace identity mismatch");
        let t = Instant::now();
        let r = api.prove_segment(&ProverOpts::succinct(),Asset::Path(path.canonicalize()?),AssetRequest::Inline)?;
        let seconds = t.elapsed().as_secs_f64();
        save(out,&format!("segment-{index}.bin"),&bincode::serialize(&r)?)?;
        segment_check(&r)?; ensure!(r.index == index as u32, "wrong segment index");
        timings.push(json!({"stage":"segment","index":index,"apiSeconds":seconds,"claimDigest":r.claim.digest().to_string()}));
        let t = Instant::now();
        let s = api.lift(&ProverOpts::succinct(),r.clone().try_into()?,AssetRequest::Inline)?;
        let seconds = t.elapsed().as_secs_f64();
        save(out,&format!("lift-{index}.bin"),&bincode::serialize(&s)?)?;
        succinct_check(&s,&r.claim)?;
        timings.push(json!({"stage":"lift","index":index,"apiSeconds":seconds,"claimDigest":s.claim.digest().to_string()}));
        lifted.push(s);
    }
    let l = lifted[0].claim.as_value()?.clone(); let r = lifted[1].claim.as_value()?.clone();
    ensure!(l.post.digest() == r.pre.digest(), "discontinuous segments");
    let expected = l.join(&r); let t = Instant::now();
    let joined = api.join(&ProverOpts::succinct(),lifted[0].clone().try_into()?,lifted[1].clone().try_into()?,AssetRequest::Inline)?;
    let seconds = t.elapsed().as_secs_f64();
    save(out,"join.bin",&bincode::serialize(&joined)?)?; succinct_check(&joined,&expected)?;
    timings.push(json!({"stage":"join","apiSeconds":seconds,"claimDigest":joined.claim.digest().to_string()}));
    report(out,"benchmark.json",json!({"scope":"NEW_SEGMENTATION_PARTIAL_GPU_PROOFS_NOT_FULL_RECEIPT",
        "segmentPo2":m["segmentPo2"],"timings":timings,"sealAndClaimMutationsRejected":true,
        "developmentMode":false}))
}
fn full_check(r: &Receipt, journal: &[u8]) -> Result<()> {
    r.inner.succinct()?;
    r.verify_with_context(&context(),image()?)?;
    ensure!(r.journal.bytes == journal, "wrong full journal");
    ensure!(r.claim()?.value()?.output.value()?.ok_or_else(||anyhow::anyhow!("missing output"))?.assumptions.is_empty(), "unresolved assumptions");
    let mut bad = r.clone();
    if let risc0_zkvm::InnerReceipt::Succinct(ref mut s) = bad.inner { s.seal[0] ^= 1; }
    ensure!(bad.verify_with_context(&context(),image()?).is_err(), "altered full seal accepted");
    ensure!(r.verify_with_context(&context(),Digest::ZERO).is_err(), "wrong image accepted");
    for offset in [0,32,44,76,166] {
        let mut bad = r.clone(); bad.journal.bytes[offset] ^= 1;
        ensure!(bad.verify_with_context(&context(),image()?).is_err(), "altered journal accepted");
    }
    Ok(())
}
fn prove(package: &Path, out: &Path, po2: u32) -> Result<()> {
    let (program,input,journal) = inputs(package)?;
    fs::create_dir(out)?;
    report(out,"started.json",json!({"segmentPo2":po2,"scope":"FULL_PROXY_CLASSIFIER_PROOF_ATTEMPT",
        "expectedProgramImage":IMAGE,"expectedJournalSha256":JOURNAL,"developmentMode":false}))?;
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env(&input,po2)?,&program,&ProverOpts::succinct())?;
    let seconds = t.elapsed().as_secs_f64();
    let raw = bincode::serialize(&info.receipt)?;
    save(out,"candidate-receipt.bin",&raw)?;
    full_check(&info.receipt,&journal)?;
    save(out,"classifier-receipt.bin",&raw)?;
    report(out,"complete.json",json!({"scope":"FULL_PROXY_CLASSIFIER_NOT_PRIVATE_PAYMENT_RELATION",
        "segmentPo2":po2,"proofSeconds":seconds,"stats":info.stats,"receiptSha256":hash(&raw),
        "receiptBytes":raw.len(),"expectedProgramImage":IMAGE,"journalSha256":hash(&journal),
        "noUnresolvedAssumptions":true,"sealImageAndJournalMutationsRejected":true,"developmentMode":false}))
}
fn main() -> Result<()> {
    ensure!(std::env::var_os("RISC0_DEV_MODE").is_none(), "development mode forbidden");
    ensure!(std::env::var("RISC0_PROVER").as_deref() == Ok("ipc"), "explicit IPC prover required");
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("export") | Some("prove") if a.len() == 5 => {
            let package=PathBuf::from(&a[2]); let out=PathBuf::from(&a[3]); let po2=a[4].parse()?;
            if a[1] == "export" { export(&package,&out,po2) } else { prove(&package,&out,po2) }
        }
        Some("bench") if a.len() == 3 => bench(Path::new(&a[2])),
        _ => anyhow::bail!("export|prove PACKAGE NEW_OUTPUT PO2 | bench EXPORTED_OUTPUT"),
    }
}
