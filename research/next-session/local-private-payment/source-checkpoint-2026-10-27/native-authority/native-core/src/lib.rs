//! SOURCE-ONLY NEW RESEARCH PROFILE. No Native/production acceptance or key reuse.
//! No legacy owner_secret, signing seed/scalar or signing nonce is an input.
#![forbid(unsafe_code)]
mod exact_sha256;
pub mod circuit;
pub mod join;
pub mod collect;
pub mod interchange;
pub use native::{cv, Note, H, CV, CM_DEPTH, NOTE_FLOOR, MAX, NOTE_TAG, KEY_TAG, NF_TAG, CM_NODE};
use ark_bn254::Fr;
pub const DOMAIN: H = [0xa6; 32];
pub const AUTH_OWNER_TAG: &[u8; 8] = b"KPBPOW01";
pub const AUTH_SPEND_TAG: &[u8; 8] = b"KPBPSP01";
pub const REFERENCE_OUTPUT_TAG: &[u8; 8] = b"KPBPOU01";
/// These are public synthetic/profile values, not a selected production ABI.
#[derive(Clone)]
pub struct AuthSpendStatement { pub domain:H, pub anchor:H, pub nf:H, pub cv:CV, pub effects_digest:H }
impl AuthSpendStatement {
    pub fn bytes(&self)->[u8;200] {
        let mut b=[0;200]; b[..8].copy_from_slice(AUTH_SPEND_TAG); b[8..40].copy_from_slice(&self.domain);
        b[40..72].copy_from_slice(&self.anchor); b[72..104].copy_from_slice(&self.nf);
        b[104..168].copy_from_slice(&self.cv); b[168..].copy_from_slice(&self.effects_digest); b
    }
    pub fn public_inputs(&self)->[Fr;2] { native::statements::digest_fields(&native::hash(&[&self.bytes()])) }
}
/// Openings stay out of Debug/Serialize. Deliberately not native::SpendWitness.
#[derive(Clone)]
pub struct AuthSpendWitness { pub note:Note, pub nullifier_secret:H, pub position:u32, pub path:[H;CM_DEPTH], pub blinding:H }
#[derive(Clone)]
pub struct AuthSpendCircuit { pub statement:AuthSpendStatement, pub witness:AuthSpendWitness, pub owner_key_bytes:[u8;64] }
/// A data commitment to a verification key, not knowledge of legacy s.
pub fn owner_key_commitment(domain:&H, key:&[u8;64], incoming:&H)->H {
    native::hash(&[AUTH_OWNER_TAG,domain,key,incoming])
}
/// Reference output core only: CFhash is bound, ciphertext/proofs are NOT checked.
#[derive(Clone)]
pub struct ReferenceOutputCircuit { pub domain:H, pub note:Note, pub cm:H, pub cv:CV, pub cf_hash:H, pub blinding:H }
