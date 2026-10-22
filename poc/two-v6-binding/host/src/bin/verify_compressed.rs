//! Independent software invocation for the retained compressed claim. No prover.
use kpi_private_note_proof as checks;
use kpi_two_v6_binding::compiled::CompiledResearchGate;
use risc0_zkvm::{sha::Digestible, InnerReceipt, Receipt, VerifierContext};
use serde_json::json;
use std::{error::Error, fs, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

const IMAGE: &str = "50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832";
const SOURCE_CLAIM: &str = "7e5bed968ae55ede2c88edb1021b5bb718d8785061d8df761050badd2210b2e3";
const PUBLIC: &[u8] = include_bytes!("../../pins/expected-public.bin");
const JOURNAL: &[u8] = include_bytes!("../../pins/expected-journal.bin");

fn verify(receipt: &Receipt) -> Result<()> {
    receipt.inner.groth16()?; // Reject every fake, composite or Succinct variant.
    receipt.verify_with_context(
        &VerifierContext::default().with_dev_mode(false),
        checks::digest(IMAGE)?,
    )?;
    if receipt.journal.bytes != JOURNAL || receipt.claim()?.digest().to_string() != SOURCE_CLAIM {
        return Err(
            "compressed receipt differs from independently selected source claim/journal".into(),
        );
    }
    if !receipt
        .claim()?
        .value()?
        .output
        .value()?
        .ok_or("missing claim output")?
        .assumptions
        .is_empty()
    {
        return Err("unresolved assumptions".into());
    }
    CompiledResearchGate::new()?.check_publication(PUBLIC, &receipt.journal.bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode must be absent".into());
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("verify_compressed RECEIPT NEW_OUTPUT".into());
    }
    let receipt_path = Path::new(&args[1]);
    let receipt = checks::read_receipt(receipt_path)?;
    verify(&receipt)?;
    let context = VerifierContext::default().with_dev_mode(false);
    let image = checks::digest(IMAGE)?;
    let mut wrong_image_bytes: [u8; 32] = image.into();
    wrong_image_bytes[0] ^= 1;
    if receipt
        .verify_with_context(&context, risc0_zkvm::sha::Digest::from(wrong_image_bytes))
        .is_ok()
    {
        return Err("wrong image accepted".into());
    }
    let journal_offsets = [0, 8, 10, 41];
    for offset in journal_offsets {
        let mut changed = receipt.clone();
        changed.journal.bytes[offset] ^= 1;
        if changed.verify_with_context(&context, image).is_ok() {
            return Err("changed journal accepted".into());
        }
    }
    let mut changed = receipt.clone();
    if let InnerReceipt::Groth16(inner) = &mut changed.inner {
        inner.seal[0] ^= 1;
    }
    if changed.verify_with_context(&context, image).is_ok() {
        return Err("changed seal accepted".into());
    }
    let fake = Receipt::new(
        InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(risc0_zkvm::ReceiptClaim::ok(
            image,
            JOURNAL.to_vec(),
        ))),
        JOURNAL.to_vec(),
    );
    if verify(&fake).is_ok() {
        return Err("fake receipt accepted".into());
    }
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    checks::save(out, "public.bin", PUBLIC)?;
    checks::save(out, "journal.bin", JOURNAL)?;
    let report = json!({"scope":"INDEPENDENT_SOFTWARE_COMPRESSED_RECEIPT_VERIFICATION",
        "receipt_kind":"Groth16","receipt_sha256":checks::sha(&fs::read(receipt_path)?),
        "image":IMAGE,"source_claim_digest":SOURCE_CLAIM,"journal_bytes":JOURNAL.len(),
        "journal_sha256":checks::sha(JOURNAL),"projection_bytes":PUBLIC.len(),
        "sdk_verification_passed":true,"development_mode":false,"no_unresolved_assumptions":true,
        "wrong_image_rejected":true,"tampered_journal_offsets_rejected":journal_offsets,
        "corrupted_seal_rejected":true,"fake_receipt_rejected":true,
        "native_acceptance_checked":false,"proof_generation":false});
    checks::save(out, "verified.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
