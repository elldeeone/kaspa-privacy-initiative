//! Real wallet receipts; host verification is not a proved outer classifier.
use crate::fixture::save;
use anyhow::{ensure, Context, Result};
use kpi_wallet_core::{hash, Witness};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digest, ExecutorEnv, ProverOpts,
    Receipt, VerifierContext,
};
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::Path, time::Instant};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    program_sha256: String,
    input_sha256: String,
    expected_journal_sha256: String,
    expected_program_image: String,
}
struct CaseInputs {
    program: Vec<u8>,
    input: Vec<u8>,
    journal: Vec<u8>,
    image: Digest,
}
fn inputs(p: &Path) -> Result<CaseInputs> {
    let c: Case = serde_json::from_slice(&fs::read(p.join("case.json"))?)?;
    let program = fs::read(p.join("program.bin"))?;
    let input = fs::read(p.join("input.bin"))?;
    let journal = fs::read(p.join("expected-journal.bin"))?;
    ensure!(
        hex::encode(hash(&program)) == c.program_sha256
            && hex::encode(hash(&input)) == c.input_sha256
            && hex::encode(hash(&journal)) == c.expected_journal_sha256,
        "frozen case identity mismatch"
    );
    let image = compute_image_id(&program)?;
    ensure!(
        image.to_string() == c.expected_program_image,
        "actual program image mismatch"
    );
    let w = Witness::decode(&input)?;
    ensure!(
        w.intent.journal(&w.auth)? == journal,
        "expected complete journal mismatch"
    );
    Ok(CaseInputs {
        program,
        input,
        journal,
        image,
    })
}
fn env(input: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut transport = (input.len() as u32).to_le_bytes().to_vec();
    transport.extend(input);
    let mut b = ExecutorEnv::builder();
    b.write_slice(&transport)
        .segment_limit_po2(19)
        .session_limit(None);
    b.build()
}
/// Exact bincode 1.3.3 receipt profile. The SDK's top-level deserialize allows
/// trailing data, so require byte equality before admitting an envelope.
pub fn decode_receipt(raw: &[u8]) -> Result<Receipt> {
    let receipt: Receipt = bincode::deserialize(raw)?;
    ensure!(
        bincode::serialize(&receipt)? == raw,
        "noncanonical receipt envelope"
    );
    Ok(receipt)
}

pub fn verify(receipt: &Receipt, image: Digest, journal: &[u8]) -> Result<()> {
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "development mode forbidden"
    );
    receipt.inner.succinct()?;
    let context = VerifierContext::default().with_dev_mode(false);
    receipt.verify_with_context(&context, image)?;
    ensure!(
        receipt.journal.bytes == journal,
        "complete journal mismatch"
    );
    ensure!(
        receipt
            .claim()?
            .value()?
            .output
            .value()?
            .context("missing successful output")?
            .assumptions
            .is_empty(),
        "unresolved assumptions"
    );
    Ok(())
}
fn controls(r: &Receipt, image: Digest, journal: &[u8]) -> Result<usize> {
    verify(r, image, journal)?;
    let mut bad = r.clone();
    if let risc0_zkvm::InnerReceipt::Succinct(ref mut inner) = bad.inner {
        inner.seal[0] ^= 1
    }
    ensure!(
        verify(&bad, image, journal).is_err(),
        "mutated seal accepted"
    );
    ensure!(
        verify(r, Digest::ZERO, journal).is_err(),
        "wrong actual image accepted"
    );
    let mut n = 2;
    for at in [0, 36, 68, 100, 132, 164, 196, 228] {
        let mut bad = r.clone();
        bad.journal.bytes[at] ^= 1;
        ensure!(
            verify(&bad, image, journal).is_err(),
            "mutated journal accepted"
        );
        n += 1
    }
    let mut expected = journal.to_vec();
    *expected.last_mut().unwrap() ^= 1;
    ensure!(
        verify(r, image, &expected).is_err(),
        "other authorization envelope accepted"
    );
    Ok(n + 1)
}
pub fn run(mode: &str, p: &Path, receipt: Option<&Path>, out: &Path) -> Result<()> {
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "development mode forbidden"
    );
    let CaseInputs {
        program,
        input,
        journal,
        image,
    } = inputs(p)?;
    fs::create_dir(out)?;
    let start = Instant::now();
    let mut report = match mode {
        "execute-negative" => {
            ensure!(
                std::env::var("RISC0_PROVER").as_deref() == Ok("ipc"),
                "explicit IPC required"
            );
            let reason = fs::read_to_string(p.join("expected-rejection.txt"))?;
            let error = default_executor()
                .execute(env(&input)?, &program)
                .err()
                .context("invalid wallet witness executed successfully")?;
            let error = format!("{error:#}");
            ensure!(
                error.contains("Guest panicked: wallet relation") && error.contains(&reason),
                "unexpected VM failure: {error}"
            );
            json!({"invalidWitnessExecutionRejected":true,"reason":reason,"invalidityProofProduced":false})
        }
        "profile" => {
            ensure!(
                std::env::var("RISC0_PROVER").as_deref() == Ok("ipc"),
                "explicit IPC required"
            );
            let session = default_executor().execute(env(&input)?, &program)?;
            ensure!(
                session.journal.bytes == journal,
                "VM wallet journal differs"
            );
            json!({"executionOnly":true,"userCycles":session.cycles(),"segments":session.segments.iter().map(|s|s.po2).collect::<Vec<_>>()})
        }
        "prove" => {
            ensure!(
                std::env::var("RISC0_PROVER").as_deref() == Ok("ipc"),
                "explicit IPC required"
            );
            let info = default_prover().prove_with_opts(
                env(&input)?,
                &program,
                &ProverOpts::succinct(),
            )?;
            let raw = bincode::serialize(&info.receipt)?;
            save(&out.join("wallet-receipt.bin"), &raw)?;
            let rejected = controls(&info.receipt, image, &journal)?;
            json!({"walletReceiptVerified":true,"receiptBytes":raw.len(),"receiptSha256":hex::encode(hash(&raw)),"stats":info.stats,"proofMutationControlsRejected":rejected,"verifierParameters":info.receipt.inner.verifier_parameters().to_string()})
        }
        "verify" => {
            let raw = fs::read(receipt.context("receipt path")?)?;
            let r = decode_receipt(&raw)?;
            let rejected = controls(&r, image, &journal)?;
            json!({"savedWalletReceiptVerified":true,"receiptSha256":hex::encode(hash(&raw)),"proofMutationControlsRejected":rejected,"verifierParameters":r.inner.verifier_parameters().to_string()})
        }
        _ => anyhow::bail!("profile/prove/verify required"),
    };
    report["scope"] = json!("FULL_OFFLINE_WALLET_RELATION_NOT_PROVED_OUTER_OR_NATIVE_BACKING");
    report["seconds"] = json!(start.elapsed().as_secs_f64());
    report["expectedProgramImage"] = json!(image.to_string());
    report["expectedJournalSha256"] = json!(hex::encode(hash(&journal)));
    report["noUnresolvedAssumptions"] = json!(true);
    report["developmentMode"] = json!(false);
    report["nativeTransactions"] = json!(0);
    save(
        &out.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{report}");
    Ok(())
}
