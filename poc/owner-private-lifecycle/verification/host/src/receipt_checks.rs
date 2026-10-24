//! Adapted selected3.0.3 checks from private-note-proof; Result failures, no pins
//! for the old financial program and no private witness/parameter operations.
use crate::Result;
use bincode::Options;
use risc0_circuit_recursion::{control_id::ALLOWED_CONTROL_ROOT, CIRCUIT};
use risc0_zkp::{core::hash::poseidon2::Poseidon2HashSuite, verify::VerificationError};
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt, VerifierContext};
use std::{fs, path::Path};
const JOIN: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
const MAX_RECEIPT_BYTES: u64 = 256 * 1024 * 1024;
pub fn digest(raw: &str) -> Result<Digest> {
    let b = hex::decode(raw)?;
    Ok(b.as_slice().try_into()?)
}
pub fn read(path: &Path) -> Result<Receipt> {
    if fs::metadata(path)?.len() > MAX_RECEIPT_BYTES {
        return Err("receipt operational size bound".into());
    }
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES)
        .reject_trailing_bytes()
        .deserialize(&fs::read(path)?)?)
}
pub fn verify(r: &Receipt, image: &str, journal: &[u8]) -> Result<()> {
    if journal.len() != kpi_owner_private_lifecycle_verifier::JOURNAL_LEN {
        return Err("journal104 required".into());
    }
    match &r.inner {
        InnerReceipt::Succinct(s) => {
            let control = digest(JOIN)?;
            if s.hashfn != "poseidon2" || s.control_id != control {
                return Err("expected succinct control metadata".into());
            }
            r.verify_with_context(
                &VerifierContext::default().with_dev_mode(false),
                digest(image)?,
            )?;
            let suite = Poseidon2HashSuite::new_suite();
            risc0_zkp::verify::verify(&CIRCUIT, &suite, &s.seal, |_, decoded: &Digest| {
                if *decoded != control || *decoded != s.control_id {
                    return Err(VerificationError::ControlVerificationError {
                        control_id: *decoded,
                    });
                }
                s.control_inclusion_proof
                    .verify(decoded, &ALLOWED_CONTROL_ROOT, suite.hashfn.as_ref())
                    .map_err(|_| VerificationError::ControlVerificationError {
                        control_id: *decoded,
                    })
            })?;
        }
        InnerReceipt::Groth16(_) => {
            r.verify_with_context(
                &VerifierContext::default().with_dev_mode(false),
                digest(image)?,
            )?;
        }
        _ => return Err("genuine succinct or Groth16 receipt required".into()),
    }
    if r.journal.bytes != journal
        || !r
            .claim()?
            .value()?
            .output
            .value()?
            .ok_or("claim output")?
            .assumptions
            .is_empty()
    {
        return Err("exact journal or empty assumptions".into());
    }
    Ok(())
}
