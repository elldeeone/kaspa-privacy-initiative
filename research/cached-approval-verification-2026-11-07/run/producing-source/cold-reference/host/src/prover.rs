pub use crate::original_prover::{Result, native_proof, verify, write};
use kpi_batched_payment_core as app;
use risc0_zkvm::{
    ExecutorEnv, ProverOpts, Receipt, VerifierContext, compute_image_id, default_prover,
    sha::{Digest, Digestible},
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};
fn input(path: &Path) -> Result<app::Input> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&fs::read(path)?)?)
}
fn check_auth(receipt: &Receipt, image: Digest, journal: &[u8]) -> Result<()> {
    receipt.inner.succinct()?;
    receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false), image)?;
    if receipt.journal.bytes != journal
        || receipt.claim()?.digest()
            != risc0_zkvm::ReceiptClaim::ok(image, journal.to_vec()).digest()
    {
        return Err("certificate exact successful unconditional claim".into());
    }
    if !receipt
        .claim()?
        .value()?
        .output
        .value()?
        .ok_or("certificate missing output")?
        .assumptions
        .is_empty()
    {
        return Err("certificate unresolved assumptions".into());
    }
    Ok(())
}
fn environment(
    raw: &[u8],
    receipt: Option<Receipt>,
    method: Option<u32>,
) -> Result<ExecutorEnv<'static>> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode forbidden".into());
    }
    let mut env = ExecutorEnv::builder();
    if let Some(method) = method {
        env.write_slice(&[method]);
    }
    env.write_slice(&[u32::try_from(raw.len())?])
        .write_slice(raw)
        .segment_limit_po2(19)
        .session_limit(Some(1_000_000_000));
    if let Some(receipt) = receipt {
        env.add_assumption(receipt);
    }
    Ok(env.build()?)
}
pub fn authorize(program: &Path, path: &Path, out: &Path) -> Result<Value> {
    let input = input(path)?;
    let expected = app::authorize_packet(&input)?;
    let raw = bincode::serialize(&input)?;
    let program = fs::read(program)?;
    let image = compute_image_id(&program)?;
    fs::create_dir(out)?;
    write(&out.join("input.bin"), &raw)?;
    write(&out.join("journal.bin"), &expected)?;
    let started = Instant::now();
    eprintln!("AUTHORIZE_START {}", out.display());
    let info = default_prover().prove_with_opts(
        environment(&raw, None, None)?,
        &program,
        &ProverOpts::succinct(),
    )?;
    check_auth(&info.receipt, image, &expected)?;
    write(
        &out.join("receipt.bin"),
        &bincode::serialize(&info.receipt)?,
    )?;
    let report = json!({"image":image.to_string(),"seconds":started.elapsed().as_secs_f64(),"stats":info.stats,"operations":input.packet.operations.len(),"journalHex":hex::encode(&expected),"unconditionalSuccinct":true,"developmentMode":false});
    write(
        &out.join("REPORT.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!("AUTHORIZE_DONE {report}");
    Ok(report)
}
pub fn settle(
    auth_program: &Path,
    program: &Path,
    path: &Path,
    cache: &Path,
    out: &Path,
) -> Result<Value> {
    settle_inner(Some((auth_program, cache)), program, path, out)
}
pub fn direct(program: &Path, path: &Path, out: &Path) -> Result<Value> {
    settle_inner(None, program, path, out)
}
fn settle_inner(
    cached: Option<(&Path, &Path)>,
    program: &Path,
    path: &Path,
    out: &Path,
) -> Result<Value> {
    let input = input(path)?;
    let expected = app::execute(&input)?;
    let raw = bincode::serialize(&input)?;
    let mut auth_image = None;
    use bincode::Options;
    let receipt = if let Some((auth_program, cache)) = cached {
        let image = compute_image_id(&fs::read(auth_program)?)?;
        auth_image = Some(image);
        let receipt: Receipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(
                &fs::read(cache).map_err(|e| format!("missing cached proof receipt: {e}"))?,
            )?;
        check_auth(&receipt, image, &app::authorization_journal(&input)?)?;
        Some(receipt)
    } else {
        None
    };
    let program = fs::read(program)?;
    let image = compute_image_id(&program)?;
    fs::create_dir(out)?;
    write(&out.join("input.bin"), &raw)?;
    write(&out.join("expected-journal.bin"), &expected.journal)?;
    let started = Instant::now();
    eprintln!("SETTLE_START {}", out.display());
    let info = default_prover().prove_with_opts(
        environment(&raw, receipt, Some(u32::from(cached.is_some())))?,
        &program,
        &ProverOpts::succinct(),
    )?;
    info.receipt
        .verify_with_context(&VerifierContext::default().with_dev_mode(false), image)?;
    if info.receipt.journal.bytes != expected.journal {
        return Err("composed exact journal".into());
    }
    write(
        &out.join("candidate-succinct.bin"),
        &bincode::serialize(&info.receipt)?,
    )?;
    let compose_seconds = started.elapsed().as_secs_f64();
    let receipt = default_prover().compress(&ProverOpts::groth16(), &info.receipt)?;
    verify(&receipt, image, &expected.journal)?;
    write(
        &out.join("candidate-compressed.bin"),
        &bincode::serialize(&receipt)?,
    )?;
    write(&out.join("native-proof.bin"), &native_proof(&receipt)?)?;
    let report = json!({"image":image.to_string(),"authorizationImage":auth_image.map(|i|i.to_string()),"seconds":started.elapsed().as_secs_f64(),"compositionSeconds":compose_seconds,"stats":info.stats,"unresolvedAssumptions":0,"nativeGroth16":true,"currentStateChecksFresh":true,"cachedVerification":cached.is_some()});
    write(
        &out.join("REPORT.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!("SETTLE_DONE {report}");
    Ok(report)
}
/// Legacy helper required by reused benchmark source; the original full-check
/// path remains available for explicit direct controls, never a cached shortcut.
pub fn prove(program: &[u8], input: &app::Input, out: &Path) -> Result<(Vec<u8>, Value)> {
    crate::original_prover::prove(program, input, out)
}
pub use crate::original_prover::reject_guest;

pub fn receipt_controls(auth_program: &Path, run: &Path, out: &Path) -> Result<()> {
    let image = compute_image_id(&fs::read(auth_program)?)?;
    let cache: Receipt =
        bincode::deserialize(&fs::read(run.join("authorization-cache/receipt.bin"))?)?;
    let expected = fs::read(run.join("authorization-cache/journal.bin"))?;
    check_auth(&cache, image, &expected)?;
    let mut rows = vec![];
    let mut refused = |name: &str, receipt: &Receipt, id: Digest, journal: &[u8]| -> Result<()> {
        let e = check_auth(receipt, id, journal)
            .err()
            .ok_or_else(|| format!("accepted {name}"))?;
        rows.push(json!({"case":name,"error":e.to_string()}));
        Ok(())
    };
    refused("wrong authorization image", &cache, Digest::ZERO, &expected)?;
    for (name, index) in [
        ("purpose or domain changed", 0),
        ("pool changed", 32),
        ("key changed", 64),
        ("packet or intent changed", 96),
    ] {
        let mut changed = expected.clone();
        changed[index] ^= 1;
        refused(name, &cache, image, &changed)?;
    }
    let mut corrupt = cache.clone();
    if let risc0_zkvm::InnerReceipt::Succinct(ref mut r) = corrupt.inner {
        r.seal[0] ^= 1;
    } else {
        return Err("expected Succinct cache".into());
    }
    refused("corrupt Succinct seal", &corrupt, image, &expected)?;
    let fake = Receipt::new(
        risc0_zkvm::InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(risc0_zkvm::ReceiptClaim::ok(
            image,
            expected.clone(),
        ))),
        expected.clone(),
    );
    refused("fake cache forbidden", &fake, image, &expected)?;
    if fake
        .verify_with_context(&VerifierContext::default().with_dev_mode(false), image)
        .is_ok()
    {
        return Err("development Fake verification accepted".into());
    }
    let final_receipt: Receipt =
        bincode::deserialize(&fs::read(run.join("composed-2/candidate-compressed.bin"))?)?;
    refused(
        "compressed Groth16 is not a composable cache",
        &final_receipt,
        image,
        &expected,
    )?;
    if fs::read(run.join("never-created-receipt.bin")).is_ok() {
        return Err("missing receipt fixture exists".into());
    }
    rows.push(json!({"case":"missing receipt","rejectedBeforeProving":true}));
    fs::write(
        out,
        serde_json::to_vec_pretty(&json!({"developmentMode":false,"controls":rows}))?,
    )?;
    println!("{} actual-receipt refusal controls passed", rows.len());
    Ok(())
}

pub fn replay_cache(program:&Path,cache:&Path)->Result<()> {
 let input=input(&cache.join("input.bin"))?;let expected=app::authorize_packet(&input)?;
 let receipt:Receipt=bincode::deserialize(&fs::read(cache.join("receipt.bin"))?)?;
 check_auth(&receipt,compute_image_id(&fs::read(program)?)?,&expected)
}

/// Produce a real conditional negative control. Never used by settlement APIs.
pub fn unresolved_control(auth_program:&Path,program:&Path,path:&Path,out:&Path)->Result<()> {
 if std::env::var_os("RISC0_DEV_MODE").is_some(){return Err("development mode forbidden".into());}
 let input=input(path)?;let expected=app::execute(&input)?;let raw=bincode::serialize(&input)?;
 let authorization=compute_image_id(&fs::read(auth_program)?)?;let program=fs::read(program)?;let image=compute_image_id(&program)?;
 let mut env=ExecutorEnv::builder();env.write_slice(&[1u32]).write_slice(&[u32::try_from(raw.len())?]).write_slice(&raw).segment_limit_po2(19).session_limit(Some(1_000_000_000));
 env.add_assumption(risc0_zkvm::ReceiptClaim::ok(authorization,app::authorization_journal(&input)?));
 fs::create_dir(out)?;let started=Instant::now();
 let info=default_prover().prove_with_opts(env.build()?,&program,&ProverOpts::succinct())?;
 if info.receipt.journal.bytes!=expected.journal || info.receipt.claim()?.value()?.output.value()?.ok_or("missing output")?.assumptions.is_empty(){return Err("expected actual conditional successful receipt".into());}
 write(&out.join("conditional-succinct.bin"),&bincode::serialize(&info.receipt)?)?;
 let receipt=default_prover().compress(&ProverOpts::groth16(),&info.receipt)?;
 let error=verify(&receipt,image,&expected.journal).err().ok_or("accepted unresolved final receipt")?;
 write(&out.join("conditional-compressed.bin"),&bincode::serialize(&receipt)?)?;
 write(&out.join("native-proof.bin"),&native_proof(&receipt)?)?;
 write(&out.join("REPORT.json"),&serde_json::to_vec_pretty(&json!({"realConditionalProof":true,"suppliedAssumption":"Claim only, no Proven receipt","strictFinalVerificationError":error.to_string(),"seconds":started.elapsed().as_secs_f64(),"developmentMode":false}))?)?;
 println!("Actual conditional receipt refused by strict final verifier");Ok(())
}
