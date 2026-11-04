//! Unfunded native-draft authorization checks. No consensus or state application.
#![forbid(unsafe_code)]

pub mod codec;
pub mod fixtures;
pub mod signing;
pub mod verifier;

pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
pub const ACTIONS: usize = 2;
pub const PROOF_BYTES: usize = orchard::Proof::expected_proof_size(ACTIONS);
pub const PROFILE_ID: &str = "337249a87fd85d2212fd9f8ce5727d1795017f588b73b1c76ab1c474fd02aad2";
pub const KEY_ID: &str = "743fa19c541fa2c7881c4ed0e3340c82d88780dbbc549cc2f3bfd982c2e517e0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Decode(&'static str),
    Profile,
    KeyIdentity,
    Range,
    Balance,
    DuplicateInput,
    MissingInput,
    UnsupportedScript,
    UnsupportedContext,
    InputSignature,
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
    hex::decode(PROFILE_ID).unwrap().try_into().unwrap()
}

pub fn hash(tag: &str, bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .key(format!("KNS1/{tag}").as_bytes())
        .hash(bytes)
        .as_bytes()
        .try_into()
        .unwrap()
}
