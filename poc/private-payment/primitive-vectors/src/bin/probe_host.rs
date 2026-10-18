//! P1 public primitive compatibility measurement; never a payment verifier.
use anyhow::{ensure, Context, Result};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, sha::Digest, ExecutorEnv, ProverOpts,
    Receipt, VerifierContext,
};
use serde::Deserialize;
use serde_json::json;
use std::{fs, io::Write, path::Path, time::Instant};

const SCOPE: &str = "ESTABLISHED_PRIMITIVE_PROBE_NOT_PRIVATE_WALLET_RELATION";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    program_sha256: String,
    input_sha256: String,
    expected_journal_sha256: String,
    expected_program_image: String,
}
fn hash(bytes: &[u8]) -> String {
    use risc0_zkvm::sha::Sha256;
    risc0_zkvm::sha::Impl::hash_bytes(bytes).to_string()
}
fn save(out: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn inputs(dir: &Path) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Digest)> {
    let c: Case = serde_json::from_slice(&fs::read(dir.join("case.json"))?)?;
    let p = fs::read(dir.join("program.bin"))?;
    let i = fs::read(dir.join("input.bin"))?;
    let j = fs::read(dir.join("expected-journal.bin"))?;
    ensure!(
        hash(&p) == c.program_sha256
            && hash(&i) == c.input_sha256
            && hash(&j) == c.expected_journal_sha256,
        "predeclared fixture identity mismatch"
    );
    ensure!(
        i.len() == 115
            && j.starts_with(b"KPI/P1/OrchardV2/primitive-check/v1")
            && j.len() == b"KPI/P1/OrchardV2/primitive-check/v1".len() + 64,
        "wrong primitive fixture shape"
    );
    let image = compute_image_id(&p)?;
    ensure!(
        image.to_string() == c.expected_program_image,
        "program image differs from predeclared case"
    );
    Ok((p, i, j, image))
}
fn env(input: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut b = ExecutorEnv::builder();
    b.write_slice(input)
        .segment_limit_po2(19)
        .session_limit(Some(2_000_000_000));
    Ok(b.build()?)
}
fn check(r: &Receipt, image: Digest, journal: &[u8]) -> Result<()> {
    let context = VerifierContext::default().with_dev_mode(false);
    r.inner.succinct()?;
    r.verify_with_context(&context, image)?;
    ensure!(r.journal.bytes == journal, "wrong public primitive output");
    ensure!(
        r.claim()?
            .value()?
            .output
            .value()?
            .context("missing output")?
            .assumptions
            .is_empty(),
        "unresolved assumptions"
    );
    let mut bad = r.clone();
    if let risc0_zkvm::InnerReceipt::Succinct(ref mut s) = bad.inner {
        s.seal[0] ^= 1;
    }
    ensure!(
        bad.verify_with_context(&context, image).is_err(),
        "seal mutation accepted"
    );
    ensure!(
        r.verify_with_context(&context, Digest::ZERO).is_err(),
        "wrong program accepted"
    );
    for offset in [0, journal.len() - 64, journal.len() - 1] {
        let mut bad = r.clone();
        bad.journal.bytes[offset] ^= 1;
        ensure!(
            bad.verify_with_context(&context, image).is_err(),
            "journal mutation accepted"
        );
    }
    Ok(())
}
fn main() -> Result<()> {
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "development mode forbidden"
    );
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 4 || a.len() == 5,
        "profile|prove CASE NEW_OUTPUT | verify CASE RECEIPT NEW_OUTPUT"
    );
    let (program, input, journal, image) = inputs(Path::new(&a[2]))?;
    let out = Path::new(a.last().unwrap());
    fs::create_dir(out)?;
    let start = Instant::now();
    let report = match a[1].as_str() {
        "profile" if a.len() == 4 => {
            ensure!(
                std::env::var("RISC0_PROVER").as_deref() == Ok("ipc"),
                "explicit IPC required"
            );
            let session = default_executor().execute(env(&input)?, &program)?;
            ensure!(
                session.journal.bytes == journal,
                "VM differs from upstream expected commitment/nullifier"
            );
            json!({"scope":SCOPE,"executionOnly":true,"segments":session.segments.iter().map(|s|s.po2).collect::<Vec<_>>(),
                "userCycles":session.cycles(),"journalMatchesUpstream":true})
        }
        "prove" if a.len() == 4 => {
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
            save(out, "candidate-receipt.bin", &raw)?;
            check(&info.receipt, image, &journal)?;
            json!({"scope":SCOPE,"primitiveReceiptVerified":true,"receiptSha256":hash(&raw),
                "receiptBytes":raw.len(),"stats":info.stats,"noUnresolvedAssumptions":true,
                "sealImageAndJournalMutationsRejected":true})
        }
        "verify" if a.len() == 5 => {
            let raw = fs::read(&a[3])?;
            let r: Receipt = bincode::deserialize(&raw)?;
            check(&r, image, &journal)?;
            json!({"scope":SCOPE,"savedPrimitiveReceiptVerified":true,"receiptSha256":hash(&raw),
                "sealImageAndJournalMutationsRejected":true,"noUnresolvedAssumptions":true})
        }
        _ => anyhow::bail!("profile|prove CASE NEW_OUTPUT | verify CASE RECEIPT NEW_OUTPUT"),
    };
    let mut report = report;
    report["seconds"] = json!(start.elapsed().as_secs_f64());
    report["expectedProgramImage"] = json!(image.to_string());
    report["expectedJournalSha256"] = json!(hash(&journal));
    report["fullWalletRelationImplemented"] = json!(false);
    report["nativeTransactions"] = json!(0);
    report["developmentMode"] = json!(false);
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
