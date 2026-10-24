//! ADR0063 unfunded Spend/Output relations. No old financial identity or backup.
#[cfg(feature = "prover")]
pub mod circuit;
pub mod cv;
#[cfg(feature = "prover")]
#[allow(dead_code, unused_imports)]
mod exact_sha256;
#[cfg(feature = "prover")]
pub mod keys;
#[cfg(feature = "prover")]
pub mod request;
pub mod statements;
pub mod wire;
#[cfg(feature = "prover")]
pub use circuit::{OutputCircuit, SpendCircuit};
pub use cv::{
    check_balance, generators_bytes, parameter_powers_digest, point_from_bytes, scalar_from_bytes,
    value_commitment,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
pub use statements::{OutputStatement, SpendStatement};
pub use wire::{
    PROOF_LEN, Role, VK_LEN, Verifier, checked_proof, checked_vk, proof_bytes, vk_bytes,
};
pub type H = [u8; 32];
pub type CV = [u8; 64];
pub const DOMAIN: H = [
    0x32, 0xb4, 0xf3, 0x1a, 0x58, 0xcc, 0x52, 0xd2, 0x28, 0x62, 0xc2, 0x0a, 0x92, 0x3c, 0x59, 0xcd,
    0xd0, 0x12, 0x77, 0x85, 0xe9, 0x99, 0x8f, 0x63, 0x2e, 0xae, 0x2b, 0x3b, 0xb3, 0x19, 0x91, 0x9d,
];
pub const NOTE_LEN: usize = 168;
pub const CM_DEPTH: usize = 16;
pub const NOTE_FLOOR: u64 = 60_000_000;
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
pub const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
pub const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
pub const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
pub const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
pub const CM_EMPTY: &[u8; 8] = b"KPX1CME\0";
/// Fixed codes: never embed private parser, IO or proving details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Encoding,
    Domain,
    Range,
    Identity,
    Arity,
    Role,
    Request,
    Io,
    Parameters,
    Synthesis,
    Verification,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "owner_private_{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;
pub fn hash(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p)
    }
    h.finalize().into()
}
pub fn owner(domain: &H, s: &H, incoming: &H) -> H {
    hash(&[OWNER_TAG, domain, s, incoming])
}
pub fn key_commitment(domain: &H, k: &H) -> H {
    hash(&[KEY_TAG, domain, k])
}
pub fn nullifier(domain: &H, k: &H, cm: &H, position: u32) -> H {
    let mut h = Hmac::<Sha256>::new_from_slice(k).expect("fixed HMAC key width");
    for p in [NF_TAG.as_slice(), domain, cm, &position.to_le_bytes()] {
        h.update(p)
    }
    h.finalize().into_bytes().into()
}
pub fn cm_parent(left: &H, right: &H) -> H {
    hash(&[CM_NODE, left, right])
}
pub fn membership_root(cm: &H, position: u32, path: &[H; CM_DEPTH]) -> Result<H> {
    if position >= (1 << CM_DEPTH) {
        return Err(Error::Range);
    }
    let mut r = *cm;
    for (level, s) in path.iter().enumerate() {
        r = if (position >> level) & 1 == 0 {
            cm_parent(&r, s)
        } else {
            cm_parent(s, &r)
        }
    }
    Ok(r)
}
/// Openings are private: deliberately no Debug or Serialize implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct Note {
    pub owner: H,
    pub incoming: H,
    pub value: u64,
    pub rho: H,
    pub key_commitment: H,
    pub native_pk: H,
}
impl Note {
    pub fn bytes(&self) -> [u8; NOTE_LEN] {
        let mut b = [0; NOTE_LEN];
        b[..32].copy_from_slice(&self.owner);
        b[32..64].copy_from_slice(&self.incoming);
        b[64..72].copy_from_slice(&self.value.to_le_bytes());
        b[72..104].copy_from_slice(&self.rho);
        b[104..136].copy_from_slice(&self.key_commitment);
        b[136..].copy_from_slice(&self.native_pk);
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != NOTE_LEN {
            return Err(Error::Length);
        }
        Ok(Self {
            owner: b[..32].try_into().unwrap(),
            incoming: b[32..64].try_into().unwrap(),
            value: u64::from_le_bytes(b[64..72].try_into().unwrap()),
            rho: b[72..104].try_into().unwrap(),
            key_commitment: b[104..136].try_into().unwrap(),
            native_pk: b[136..].try_into().unwrap(),
        })
    }
    pub fn commitment(&self, domain: &H) -> H {
        hash(&[NOTE_TAG, domain, &self.bytes()])
    }
}
#[cfg(feature = "prover")]
#[derive(Clone)]
pub struct SpendWitness {
    pub note: Note,
    pub owner_secret: H,
    pub nullifier_secret: H,
    pub position: u32,
    pub path: [H; CM_DEPTH],
    pub blinding: H,
}
#[cfg(feature = "prover")]
#[derive(Clone)]
pub struct OutputWitness {
    pub note: Note,
    pub blinding: H,
}
