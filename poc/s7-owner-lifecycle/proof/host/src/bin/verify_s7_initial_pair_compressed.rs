//! Independent software invocation for the retained compressed claim. No prover.
use kpi_private_note_proof as checks;
use kpi_s7_lifecycle_proof_host as state_host;
use risc0_zkvm::{sha::Digestible, InnerReceipt, Receipt, VerifierContext};
use serde_json::json;
use std::{error::Error, fs, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn verify(receipt: &Receipt, pin: &state_host::Context) -> Result<()> {
    let (image_hex, _) = state_host::selection()?;
    let image = checks::digest(&image_hex)?;
    let expected_claim = risc0_zkvm::ReceiptClaim::ok(image, pin.journal.to_vec()).digest();
    receipt.inner.groth16()?; // Reject every fake, composite or Succinct variant.
    receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false), image)?;
    if receipt.journal.bytes != pin.journal || receipt.claim()?.digest() != expected_claim {
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
    state_host::check_journal(&receipt.journal.bytes, pin.journal)?;
    Ok(())
}

fn main() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode must be absent".into());
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("verify_s7_initial_pair_compressed RECEIPT NEW_OUTPUT".into());
    }
    let pin = state_host::context("initial-pair")?;
    let receipt_path = Path::new(&args[1]);
    let receipt = checks::read_receipt(receipt_path)?;
    verify(&receipt, &pin)?;
    let context = VerifierContext::default().with_dev_mode(false);
    let (image_hex, _) = state_host::selection()?;
    let image = checks::digest(&image_hex)?;
    let mut wrong_image_bytes: [u8; 32] = image.into();
    wrong_image_bytes[0] ^= 1;
    if receipt
        .verify_with_context(&context, risc0_zkvm::sha::Digest::from(wrong_image_bytes))
        .is_ok()
    {
        return Err("wrong image accepted".into());
    }
    let journal_offsets = [0, 8, 10, 42, 74, 106, 110, 215, 320, 328, 335];
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
            pin.journal.to_vec(),
        ))),
        pin.journal.to_vec(),
    );
    if verify(&fake, &pin).is_ok() {
        return Err("fake receipt accepted".into());
    }
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    checks::save(out, "public.bin", state_host::PUBLIC)?;
    checks::save(out, "journal.bin", pin.journal)?;
    let report = json!({"scope":"INDEPENDENT_SOFTWARE_NONFUNDABLE_STATE_COMPRESSED_RECEIPT_VERIFICATION",
        "receipt_kind":"Groth16","receipt_sha256":checks::sha(&fs::read(receipt_path)?),
        "image":image_hex,"context":pin.name,"source_claim_digest":receipt.claim()?.digest().to_string(),"journal_bytes":pin.journal.len(),
        "journal_sha256":checks::sha(pin.journal),"projection_bytes":state_host::PUBLIC.len(),
        "sdk_verification_passed":true,"development_mode":false,"no_unresolved_assumptions":true,
        "wrong_image_rejected":true,"tampered_journal_offsets_rejected":journal_offsets,
        "corrupted_seal_rejected":true,"fake_receipt_rejected":true,
        "native_acceptance_checked":false,"native_predecessor_authenticated":false,"native_settlement":false,"proof_generation":false});
    checks::save(out, "verified.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
