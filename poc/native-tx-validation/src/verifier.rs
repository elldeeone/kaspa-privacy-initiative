//! Stateless authorization plus explicitly synthetic current-context controls.
use crate::{
    codec::Transaction,
    signing::{locking_key, signing_message, verify_inputs, SyntheticUtxoView},
    Error, ACTIONS, KEY_ID, MAX_SOMPI,
};
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// All fields are local test data, NOT a qualified node or authenticated UTXO view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticView {
    pub domain: [u8; 32],
    pub utxos: SyntheticUtxoView,
    pub anchors: BTreeSet<(u64, u64, [u8; 32])>,
    pub spent: BTreeSet<[u8; 32]>,
    pub balance: u64,
}

pub struct Verifier {
    key: VerifyingKey,
}
#[derive(Debug)]
pub struct LocalAuthorization {
    pub txid: [u8; 32],
    pub txhash: [u8; 32],
    pub signing_message: [u8; 32],
}
impl Verifier {
    pub fn new() -> Result<Self, Error> {
        // A pinned upstream constructor, NOT a portable capsule importer.
        let capsule = include_bytes!(
            "../../../docs/spec/native-shielded/artifacts/fixed-post-nu6-2.vk-capsule.bin"
        );
        if hex::encode(Sha256::digest(capsule)) != KEY_ID {
            return Err(Error::KeyIdentity);
        }
        let key = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        // The copied-source export establishes the link to the fixed capsule.
        // This remains a build-specific diagnostic; changes fail closed.
        if hex::encode(Sha256::digest(format!("{key:?}")))
            != "eafbdf6694e6da29789e105a15ce9509b957dd9f5ca3a1fa4c468bb6546686af"
        {
            return Err(Error::KeyIdentity);
        }
        Ok(Self { key })
    }

    /// Complete actual Halo2 proof, separately callable to isolate rejection layers.
    pub fn verify_proof(&self, tx: &Transaction) -> Result<(), Error> {
        tx.bundle.verify_proof(&self.key).map_err(|_| Error::Proof)
    }
    pub fn verify_shielded_signatures(
        &self,
        tx: &Transaction,
        view: &SyntheticView,
    ) -> Result<(), Error> {
        let s = signing_message(&tx.effects, &tx.bundle, &view.utxos)?;
        for a in tx.bundle.actions() {
            a.rk()
                .verify(&s, a.authorization())
                .map_err(|_| Error::SpendSignature)?;
        }
        tx.bundle
            .binding_validating_key()
            .verify(&s, tx.bundle.authorization().binding_signature())
            .map_err(|_| Error::BindingSignature)
    }

    /// Checks no real chain, resource schedule, PoW, DAG, undo or bootstrap.
    /// No state mutation, native acceptance result or transferable spend permit.
    pub fn verify_local(
        &self,
        bytes: &[u8],
        view: &SyntheticView,
    ) -> Result<LocalAuthorization, Error> {
        let tx = Transaction::decode(bytes)?;
        self.check_synthetic_context(&tx, view)?;
        verify_inputs(&tx, &view.utxos)?;
        self.verify_proof(&tx)?;
        self.verify_shielded_signatures(&tx, view)?;
        Ok(LocalAuthorization {
            txid: tx.txid()?,
            txhash: tx.txhash()?,
            signing_message: signing_message(&tx.effects, &tx.bundle, &view.utxos)?,
        })
    }

    pub fn check_synthetic_context(
        &self,
        tx: &Transaction,
        view: &SyntheticView,
    ) -> Result<(), Error> {
        let e = &tx.effects;
        // Enforce the full structural profile even when called with a typed tx.
        tx.encode()?;
        if e.domain != view.domain {
            return Err(Error::Domain);
        }
        // This package has no consensus DAA/time/relative-lock implementation.
        // Accept only the unconditional subset rather than pretend to check it.
        if e.lock_time != 0 || e.inputs.iter().any(|i| i.sequence != u64::MAX) {
            return Err(Error::UnsupportedContext);
        }
        let outpoints: BTreeSet<_> = e.inputs.iter().map(|i| i.previous).collect();
        if outpoints.len() != e.inputs.len() {
            return Err(Error::DuplicateInput);
        }
        let mut incoming = 0u128;
        for input in &e.inputs {
            let u = view.utxos.get(&input.previous).ok_or(Error::MissingInput)?;
            if u.coinbase {
                return Err(Error::UnsupportedContext);
            }
            locking_key(u.script_version, &u.script, u.covenant)?;
            if u.amount == 0 || u.amount > MAX_SOMPI {
                return Err(Error::Range);
            }
            incoming += u128::from(u.amount);
        }
        let mut outgoing = 0u128;
        for o in &e.outputs {
            locking_key(o.script_version, &o.script, o.covenant.is_some())?;
            if o.value == 0 || o.value > MAX_SOMPI {
                return Err(Error::Range);
            }
            outgoing += u128::from(o.value);
        }
        if incoming > u128::from(MAX_SOMPI) || outgoing > u128::from(MAX_SOMPI) {
            return Err(Error::Range);
        }
        let b = i128::from(*tx.bundle.value_balance());
        if incoming as i128 + b != outgoing as i128 + i128::from(e.fee) {
            return Err(Error::Balance);
        }
        if view.balance > MAX_SOMPI
            || !(0..=i128::from(MAX_SOMPI)).contains(&(i128::from(view.balance) - b))
        {
            return Err(Error::PoolBalance);
        }
        if !view
            .anchors
            .contains(&(e.anchor_tree, e.anchor_count, tx.bundle.anchor().to_bytes()))
        {
            return Err(Error::Anchor);
        }
        let markers: BTreeSet<_> = tx
            .bundle
            .actions()
            .iter()
            .map(|a| a.nullifier().to_bytes())
            .collect();
        if markers.len() != ACTIONS || !markers.is_disjoint(&view.spent) {
            return Err(Error::Spentness);
        }
        Ok(())
    }
}
