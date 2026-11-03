//! Unfunded codec/verifier interoperability. No native consensus acceptance.
#![forbid(unsafe_code)]

pub mod codec;
pub mod effects;
pub mod fixtures;
pub mod verifier;

pub const ORCHARD_REV: &str = "616a669df8c9a59c33d47064d3ce04b25d026b2e";
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
pub const ACTIONS: usize = 2;
pub const PROOF_BYTES: usize = orchard::Proof::expected_proof_size(ACTIONS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode(&'static str),
    Profile,
    Range,
    Balance,
    DuplicateInput,
    Domain,
    Anchor,
    Spentness,
    PoolBalance,
    Proof,
    SpendSignature,
    BindingSignature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub fn profile_id() -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"KPIInteropPrfV1!")
        .hash(format!("orchard:{ORCHARD_REV}:FixedPostNu6_2:NoteV2:2-actions:codec-v1").as_bytes())
        .as_bytes()
        .try_into()
        .unwrap()
}
