//! P1 public primitive input-policy prototype. No native or wallet authority.
use anyhow::{ensure, Context, Result};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const CREDIT_TAG: &[u8] = b"KPI/credit-recovery/v1";
pub const AUTH_TAG: &[u8] = b"KPI/private-payment/authorization/v1";
pub const JOURNAL_TAG: &[u8] = b"KPI/private-payment/wallet-journal/v1";

/// Existing point APIs only. to_bytes() on VerifyingKey preserves its input;
/// canonicality must compare the decompressed point's recompression instead.
pub fn canonical_point(bytes: &[u8]) -> Result<()> {
    let raw: [u8; 32] = bytes.try_into().context("point length")?;
    let point = CompressedEdwardsY(raw)
        .decompress()
        .context("invalid point")?;
    ensure!(point.compress().to_bytes() == raw, "noncanonical point");
    ensure!(
        !point.is_small_order() && point.is_torsion_free(),
        "non-prime-order point"
    );
    Ok(())
}

pub fn verify_profile(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let pk: [u8; 32] = public_key.try_into().context("public key length")?;
    let sig: [u8; 64] = signature.try_into().context("signature length")?;
    canonical_point(&pk)?;
    canonical_point(&sig[..32])?;
    ensure!(
        bool::from(Scalar::from_canonical_bytes(sig[32..].try_into()?).is_some()),
        "noncanonical signature scalar"
    );
    VerifyingKey::from_bytes(&pk)?.verify_strict(message, &Signature::from_bytes(&sig))?;
    Ok(())
}

/// A proposed tagged tuple, not proof that the supplied key owns a deposit.
pub fn credit_message(genesis_descriptor_hash: &[u8; 32], intent_id: &[u8; 32]) -> Vec<u8> {
    [
        CREDIT_TAG,
        genesis_descriptor_hash.as_slice(),
        intent_id.as_slice(),
    ]
    .concat()
}

/// Structural framing only. The actual guest must also verify CREDIT's
/// signature and outer policy must authenticate its native deposit authority.
pub fn parse_authorization(kind: u8, bytes: &[u8]) -> Result<Option<[u8; 64]>> {
    match kind {
        0 => {
            ensure!(
                bytes.len() == 65 && bytes[0] == 1,
                "CREDIT requires flag1/signature64"
            );
            Ok(Some(bytes[1..].try_into()?))
        }
        1 | 2 => {
            ensure!(bytes == [0], "TRANSFER/EXIT require absent authorization");
            Ok(None)
        }
        _ => anyhow::bail!("unknown operation kind"),
    }
}

pub fn authorization_digest(kind: u8, bytes: &[u8]) -> Result<[u8; 32]> {
    parse_authorization(kind, bytes)?;
    Ok(Sha256::digest([AUTH_TAG, bytes].concat()).into())
}

/// Expected public bytes, not a proof verifier or authenticated pool policy.
/// IDs are G_hash, statement_id, proof_suite_id, wallet image in that order.
pub fn expected_journal(
    ids: &[[u8; 32]; 4],
    intent_id: &[u8; 32],
    auth_digest: &[u8; 32],
) -> Vec<u8> {
    let mut out = JOURNAL_TAG.to_vec();
    for id in ids {
        out.extend(id);
    }
    out.extend(intent_id);
    out.extend(auth_digest);
    out
}
