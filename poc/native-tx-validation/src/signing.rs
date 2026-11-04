//! Native-draft signature messages and standard-key policy, using a supplied view.
use crate::{
    codec::{blob, effect_bytes, Effects, OutPoint, Transaction},
    hash, Error,
};
use orchard::{bundle::Authorization, Bundle};
use secp256k1::{ecdsa, schnorr, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Local test input record. This type carries NO chain authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticUtxo {
    pub amount: u64,
    pub script_version: u16,
    pub script: Vec<u8>,
    pub covenant: bool,
    pub coinbase: bool,
}
pub type SyntheticUtxoView = BTreeMap<OutPoint, SyntheticUtxo>;

#[derive(Clone, Debug)]
pub enum LockingKey {
    Schnorr(XOnlyPublicKey),
    Ecdsa(PublicKey),
}
pub fn locking_key(version: u16, script: &[u8], covenant: bool) -> Result<LockingKey, Error> {
    if version != 0 || covenant {
        return Err(Error::UnsupportedScript);
    }
    match script {
        [0x20, key @ .., 0xac] if key.len() == 32 => Ok(LockingKey::Schnorr(
            XOnlyPublicKey::from_slice(key).map_err(|_| Error::UnsupportedScript)?,
        )),
        [0x21, key @ .., 0xab] if key.len() == 33 => {
            let parsed = PublicKey::from_slice(key).map_err(|_| Error::UnsupportedScript)?;
            if parsed.serialize() != key {
                return Err(Error::UnsupportedScript);
            }
            Ok(LockingKey::Ecdsa(parsed))
        }
        _ => Err(Error::UnsupportedScript),
    }
}

pub fn input_context(e: &Effects, view: &SyntheticUtxoView) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(&(e.inputs.len() as u64).to_le_bytes());
    for input in &e.inputs {
        let u = view.get(&input.previous).ok_or(Error::MissingInput)?;
        locking_key(u.script_version, &u.script, u.covenant)?;
        input.previous.write(&mut out);
        out.extend_from_slice(&u.amount.to_le_bytes());
        out.extend_from_slice(&u.script_version.to_le_bytes());
        blob(&mut out, &u.script)?;
        out.push(0);
    }
    Ok(out)
}

pub fn signing_message<T: Authorization>(
    e: &Effects,
    bundle: &Bundle<T, i64>,
    view: &SyntheticUtxoView,
) -> Result<[u8; 32], Error> {
    let txid = hash("TxID", &effect_bytes(e, bundle, false)?);
    let ic = hash("InputCtx", &input_context(e, view)?);
    let mut preimage = txid.to_vec();
    preimage.extend_from_slice(&ic);
    Ok(hash("SigMsg", &preimage))
}

pub fn input_hash(s: [u8; 32], index: u32, ecdsa: bool) -> [u8; 32] {
    let mut preimage = s.to_vec();
    preimage.extend_from_slice(&index.to_le_bytes());
    preimage.push(1);
    let schnorr = hash("InputSig", &preimage);
    if ecdsa {
        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(b"TransactionSigningHashECDSA"));
        hasher.update(schnorr);
        hasher.finalize().into()
    } else {
        schnorr
    }
}

pub fn verify_inputs(tx: &Transaction, view: &SyntheticUtxoView) -> Result<(), Error> {
    let s = signing_message(&tx.effects, &tx.bundle, view)?;
    let secp = Secp256k1::verification_only();
    for (index, input) in tx.effects.inputs.iter().enumerate() {
        let u = view.get(&input.previous).ok_or(Error::MissingInput)?;
        let script = &input.signature_script;
        if script.len() != 66 || script[0] != 0x41 || script[65] != 1 {
            return Err(Error::InputSignature);
        }
        match locking_key(u.script_version, &u.script, u.covenant)? {
            LockingKey::Schnorr(key) => {
                let sig = schnorr::Signature::from_slice(&script[1..65])
                    .map_err(|_| Error::InputSignature)?;
                let msg = Message::from_digest(input_hash(s, index as u32, false));
                secp.verify_schnorr(&sig, &msg, &key)
                    .map_err(|_| Error::InputSignature)?;
            }
            LockingKey::Ecdsa(key) => {
                let sig = ecdsa::Signature::from_compact(&script[1..65])
                    .map_err(|_| Error::InputSignature)?;
                let mut normalized = sig;
                normalized.normalize_s();
                if sig != normalized {
                    return Err(Error::InputSignature);
                }
                let msg = Message::from_digest(input_hash(s, index as u32, true));
                secp.verify_ecdsa(&msg, &sig, &key)
                    .map_err(|_| Error::InputSignature)?;
            }
        }
    }
    Ok(())
}
