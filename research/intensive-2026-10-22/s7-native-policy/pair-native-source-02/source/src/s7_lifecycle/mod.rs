//! Separate supplied-UTXO DO_NOT_FUND fixture. No owner CLI or ledger replayer.
pub mod fixture;
#[cfg(feature = "s7-native-policy")]
pub mod native;
pub mod profile;
