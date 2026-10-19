//! Separate experimental relation. Version-3 exact-state proofs are unchanged.
pub mod circuit;
mod controls;
pub mod tree;
pub use tree::{PublicState, State};
pub mod covenant;
pub mod experiment;
pub mod recovery;
pub mod fresh;
pub mod deposits;
#[cfg(test)]
mod tests;

use crate::{Result, native, protocol::{H, Note, Wallet, Receive, hash, random, MAX_SOMPI, GENESIS_HEX, OWNER_TAG, NOTE_TAG}};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use serde::{Deserialize, Serialize};

pub const NOTE_FLOOR: u64 = 60_000_000;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub const RESERVE: u64 = 10_000_000_000;
pub const PAYMENT: u64 = 400_000_000;
pub const STATE_LEN: usize = 105;
pub const NF_TAG: &[u8] = b"KPI-positioned-nullifier-v1\0";
pub const AUTH_LEN: usize = 265;
pub const A_COUNT: usize = 40;
pub const A_ANCHOR: usize = 44;
pub const A_NF: usize = 76;
pub const A_CM: usize = 108;
pub const A_MODE: usize = 172;
pub const A_PAYOUT: usize = 173;
pub const A_FEE: usize = 181;
pub const A_SPK: usize = 189;
pub const A_BOOT: usize = 225;
pub const A_CIPHER: usize = 233;
pub const P_AUTH: usize = 8;
pub const P_CIPHER: usize = P_AUTH + AUTH_LEN;
pub const P_STATE: usize = P_CIPHER + 370;
pub const P_WITNESS: usize = P_STATE + STATE_LEN;
pub const PATH_LEN: usize = 32 * tree::DEPTH;
pub const W_ANCHOR: usize = 0;
pub const W_PRED_INDEX: usize = PATH_LEN;
pub const W_PRED: usize = W_PRED_INDEX + 4;
pub const W_PRED_PATH: usize = W_PRED + 68;
pub const W_NF_APPEND: usize = W_PRED_PATH + PATH_LEN;
pub const W_CM_APPEND: usize = W_NF_APPEND + PATH_LEN;
pub const W_HISTORY_APPEND: usize = W_CM_APPEND + 2*PATH_LEN;
pub const W_LEN: usize = W_HISTORY_APPEND + PATH_LEN;
pub const PAYLOAD_SIZE: usize = P_WITNESS + W_LEN;
pub fn nullifier(d:&H, secret:&H, cm:&H, index:u32)->H {
    use hmac::{Hmac, Mac}; use sha2::Sha256;
    let mut h=Hmac::<Sha256>::new_from_slice(secret).unwrap();
    h.update(NF_TAG); h.update(d); h.update(cm); h.update(&index.to_le_bytes());
    h.finalize().into_bytes().into()
}

#[derive(Clone, Debug)]
pub struct Authorization {
    pub domain: H,
    pub count: u32,
    pub anchor: H,
    pub nullifier: H,
    pub outputs: [H; 2],
    pub mode: u8, // 1: two-output private transfer; 2: whole-note exit
    pub payout: u64,
    pub fee: u64,
    pub spk: [u8; 36],
    pub bootstrap: u64,
    pub cipher_hash: H,
}
impl Authorization {
    pub fn bytes(&self) -> Vec<u8> {
        [
            b"KPICU01\0".as_slice(),
            &self.domain,
            &self.count.to_le_bytes(),
            &self.anchor,
            &self.nullifier,
            &self.outputs[0],
            &self.outputs[1],
            &[self.mode],
            &self.payout.to_le_bytes(),
            &self.fee.to_le_bytes(),
            &self.spk,
            &self.bootstrap.to_le_bytes(),
            &self.cipher_hash,
        ]
        .concat()
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != AUTH_LEN || &b[..8] != b"KPICU01\0" {
            return Err("authorization framing".into());
        }
        Ok(Self {
            domain: b[8..40].try_into()?,
            count: u32::from_le_bytes(b[A_COUNT..A_ANCHOR].try_into()?),
            anchor: b[A_ANCHOR..A_NF].try_into()?,
            nullifier: b[A_NF..A_CM].try_into()?,
            outputs: [
                b[A_CM..A_CM + 32].try_into()?,
                b[A_CM + 32..A_MODE].try_into()?,
            ],
            mode: b[A_MODE],
            payout: u64::from_le_bytes(b[A_PAYOUT..A_FEE].try_into()?),
            fee: u64::from_le_bytes(b[A_FEE..A_SPK].try_into()?),
            spk: b[A_SPK..A_BOOT].try_into()?,
            bootstrap: u64::from_le_bytes(b[A_BOOT..A_CIPHER].try_into()?),
            cipher_hash: b[A_CIPHER..].try_into()?,
        })
    }
    pub fn inputs(&self) -> [Fr; 2] {
        let h = hash(&self.bytes());
        [
            Fr::from_le_bytes_mod_order(&h[..16]),
            Fr::from_le_bytes_mod_order(&h[16..]),
        ]
    }

}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub authorization: String,
    pub proof: String,
    pub ciphertexts: [String; 2],
}
impl Bundle {
    pub fn auth(&self) -> Result<Authorization> {
        Authorization::parse(&hex::decode(&self.authorization)?)
    }
    pub fn ciphertext_bytes(&self) -> Result<Vec<u8>> {
        let c = self
            .ciphertexts
            .iter()
            .map(hex::decode)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if c.iter().any(|x| x.len() != 185) {
            return Err("ciphertext dimensions".into());
        }
        Ok(c.concat())
    }
    pub fn payload(&self, next: &State, witness: &[u8]) -> Result<Vec<u8>> {
        let a = self.auth()?;
        let c = self.ciphertext_bytes()?;
        if hash(&c) != a.cipher_hash || (a.mode == 2 && c != vec![0; 370]) {
            return Err("ciphertext binding/padding".into());
        }
        Ok([b"KPICR01\0".as_slice(), &a.bytes(), &c, &next.bytes(), witness].concat())
    }
}
pub fn parse_payload(b: &[u8]) -> Result<(Authorization, State)> {
    if b.len() != PAYLOAD_SIZE || &b[..8] != b"KPICR01\0" {
        return Err("anchored payload framing".into());
    }
    let a = Authorization::parse(&b[P_AUTH..P_CIPHER])?;
    if a.cipher_hash != hash(&b[P_CIPHER..P_STATE])
        || (a.mode == 2 && b[P_CIPHER..P_STATE].iter().any(|x| *x != 0))
    {
        return Err("ciphertext binding".into());
    }
    Ok((a, State::parse(&b[P_STATE..P_WITNESS])?))
}
pub fn settle(
    domain: &H,
    old: &PublicState,
    input: &native::Utxo,
    vk: &[u8],
    bundle: &Bundle,
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let a = bundle.auth()?;
    if a.domain != *domain {
        return Err("wrong pool".into());
    }
    let (next, witness) = old.witness(&a)?;
    let compact = old.compact()?;
    let next_compact = next.compact()?;
    let redeem = covenant::redeem(domain, &compact, vk)?;
    if input.spk != hex::encode(native::encode_spk(&pay_to_script_hash_script(&redeem))) {
        return Err("current reserve script mismatch".into());
    }
    let remaining = input
        .amount
        .checked_sub(a.payout)
        .and_then(|v| v.checked_sub(a.fee))
        .ok_or("reserve underflow")?;
    let terminal = next_compact.cm_count == next_compact.nf_count;
    let mut outputs = Vec::new();
    if !terminal {
        outputs.push(TransactionOutput::new(
            remaining,
            pay_to_script_hash_script(&covenant::redeem(domain, &next_compact, vk)?),
        ));
    } else if remaining != 0 {
        return Err("terminal backing mismatch".into());
    }
    if a.mode == 2 {
        outputs.push(TransactionOutput::new(
            a.payout,
            native::decode_spk(&hex::encode(a.spk))?,
        ));
    }
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            input.outpoint()?,
            covenant::signature(&hex::decode(&bundle.proof)?, &redeem)?,
            u64::MAX,
            covenant::BUDGET,
        )],
        outputs,
        0,
        Default::default(),
        0,
        bundle.payload(&next_compact, &witness)?,
    );
    let entries = vec![input.entry()?];
    native::set_mass(&tx, &entries)?;
    Ok((tx, entries))
}
