use crate::{
    codec::{effect_digest, Envelope},
    Error, MAX_SOMPI,
};
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Caller-supplied context, NOT authenticated Kaspa chain state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedContext {
    pub network: [u8; 32],
    pub genesis: [u8; 32],
    pub pool: [u8; 32],
    pub accepted_context: [u8; 32],
    pub eligible_anchors: BTreeSet<[u8; 32]>,
    /// Immutable pool spentness: not namespaced by the current verifier version.
    pub spent: BTreeSet<[u8; 32]>,
    #[serde(with = "decimal_u64")]
    pub pool_balance: u64,
}

#[derive(Debug)]
pub struct Verifier {
    key: VerifyingKey,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}
impl Verifier {
    pub fn new() -> Self {
        Self {
            key: VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2),
        }
    }

    /// Diagnostic fingerprint of upstream Rust Debug under locked dependencies.
    /// This is NOT a portable serialized verification key or consensus encoding.
    pub fn key_fingerprint(&self) -> String {
        key_fingerprint(&self.key)
    }

    /// Checks complete Halo2 and both RedPallas roles. Does NOT check chain state
    /// or ordinary funding. Exposed separately to isolate cryptographic negatives.
    pub fn verify_crypto(&self, envelope: &Envelope) -> Result<(), Error> {
        let digest = effect_digest(&envelope.effects, &envelope.bundle)?;
        envelope
            .bundle
            .verify_proof(&self.key)
            .map_err(|_| Error::Proof)?;
        for action in envelope.bundle.actions() {
            action
                .rk()
                .verify(&digest, action.authorization())
                .map_err(|_| Error::SpendSignature)?;
        }
        envelope
            .bundle
            .binding_validating_key()
            .verify(&digest, envelope.bundle.authorization().binding_signature())
            .map_err(|_| Error::BindingSignature)
    }

    /// Returns the modeled next pool value without mutating supplied context.
    /// Success is local interoperability only, never native transaction acceptance.
    pub fn verify(&self, bytes: &[u8], context: &SuppliedContext) -> Result<u64, Error> {
        let envelope = Envelope::decode(bytes)?;
        let e = &envelope.effects;
        if (e.network, e.genesis, e.pool, e.accepted_context)
            != (
                context.network,
                context.genesis,
                context.pool,
                context.accepted_context,
            )
        {
            return Err(Error::Domain);
        }
        e.validate(*envelope.bundle.value_balance())?;
        if !context
            .eligible_anchors
            .contains(&envelope.bundle.anchor().to_bytes())
        {
            return Err(Error::Anchor);
        }
        let markers: BTreeSet<_> = envelope
            .bundle
            .actions()
            .iter()
            .map(|a| a.nullifier().to_bytes())
            .collect();
        if markers.len() != crate::ACTIONS || !markers.is_disjoint(&context.spent) {
            return Err(Error::Spentness);
        }
        if context.pool_balance > MAX_SOMPI {
            return Err(Error::PoolBalance);
        }
        let next = i128::from(context.pool_balance) - i128::from(*envelope.bundle.value_balance());
        if !(0..=i128::from(MAX_SOMPI)).contains(&next) {
            return Err(Error::PoolBalance);
        }
        self.verify_crypto(&envelope)?;
        Ok(next as u64)
    }
}

pub fn key_fingerprint(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(format!("{key:?}").as_bytes()))
}

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("noncanonical decimal sompi"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}
