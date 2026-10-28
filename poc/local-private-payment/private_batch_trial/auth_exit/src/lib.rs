//! ADR-0074 NEW research Output and independent AuthExit components.
//! No legacy VK, funded-profile, native acceptance or ciphertext-validity claim.
#![forbid(unsafe_code)]
mod circuit;
mod exact_sha256;
pub mod proof;
pub use authority::{H, CV, Note, CM_DEPTH, MAX, NOTE_FLOOR};
pub use authority::{collect, interchange, join};
pub use native::{OutputWitness, hash};
use ark_bn254::Fr;

pub const AUTH_EXIT_TAG: &[u8; 8] = b"KPBPEX01";
pub const AUTH_OWNER_TAG: &[u8; 8] = b"KPBPOW01";
pub const OUTPUT_TAG: &[u8; 8] = b"KPXAOU01";
pub const PAYOUT_FLOOR: u64 = 10_000_000;

/// Circuit parameters are fixed by setup, not caller-selected public inputs.
#[derive(Clone, Copy)]
pub struct Profile {
    pub domain: H,
    pub profile_id: H,
}

#[derive(Clone)]
pub struct ExitStatement {
    pub domain: H,
    pub anchor: H,
    pub nf: H,
    pub effects_digest: H,
    pub payout: u64,
    pub fee: u64,
}
impl ExitStatement {
    pub fn bytes(&self) -> [u8; 152] {
        let mut out = [0; 152];
        out[..8].copy_from_slice(AUTH_EXIT_TAG);
        out[8..40].copy_from_slice(&self.domain);
        out[40..72].copy_from_slice(&self.anchor);
        out[72..104].copy_from_slice(&self.nf);
        out[104..136].copy_from_slice(&self.effects_digest);
        out[136..144].copy_from_slice(&self.payout.to_le_bytes());
        out[144..152].copy_from_slice(&self.fee.to_le_bytes());
        out
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        native::statements::digest_fields(&hash(&[&self.bytes()]))
    }
}

/// Signing seed/scalar/nonce are deliberately absent; no Debug or Serialize.
#[derive(Clone)]
pub struct ExitWitness {
    pub note: Note,
    pub owner_key: [u8; 64],
    pub nullifier_key: H,
    pub position: u32,
    pub path: [H; CM_DEPTH],
}

#[derive(Clone)]
pub struct AuthExitCircuit {
    pub profile: Profile,
    pub statement: ExitStatement,
    pub witness: ExitWitness,
}

#[derive(Clone)]
pub struct OutputStatement {
    pub domain: H,
    pub cm: H,
    pub cv: CV,
    pub cf_hash: H,
}
impl OutputStatement {
    pub fn bytes(&self) -> [u8; 168] {
        let mut out = [0; 168];
        out[..8].copy_from_slice(OUTPUT_TAG);
        out[8..40].copy_from_slice(&self.domain);
        out[40..72].copy_from_slice(&self.cm);
        out[72..136].copy_from_slice(&self.cv);
        out[136..].copy_from_slice(&self.cf_hash);
        out
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        native::statements::digest_fields(&hash(&[&self.bytes()]))
    }
}

#[derive(Clone)]
pub struct OutputCircuit {
    pub profile: Profile,
    pub statement: OutputStatement,
    pub witness: OutputWitness,
}

pub fn owner(domain: &H, key: &[u8; 64], incoming: &H) -> H {
    hash(&[AUTH_OWNER_TAG, domain, key, incoming])
}

/// Complete native component + mature signature component + 68 actual links.
/// The signature component must be externally authenticated before this API.
pub fn join_exit(
    circuit: AuthExitCircuit,
    signature: &join::R1cs,
    signature_assignment: &[Fr],
) -> Result<(join::Joined, Vec<Fr>), join::Boundary> {
    let public = circuit.statement.public_inputs();
    let (native, assignment) = collect::collect(circuit, 67)?;
    let joined = join::join(&native, signature)?;
    let full = join::assignment(&joined, &assignment, signature_assignment, public)?;
    Ok((joined, full))
}
