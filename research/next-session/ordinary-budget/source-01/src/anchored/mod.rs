//! Separate experimental relation. Version-3 exact-state proofs are unchanged.
pub mod circuit;
mod controls;
pub mod covenant;
pub mod experiment;
#[cfg(test)]
mod tests;

use crate::{Result, native, protocol::*};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use serde::{Deserialize, Serialize};

pub const NOTE_FLOOR: u64 = 40_000_000;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub const AUTH_LEN: usize = 262;
pub const A_COUNT: usize = 40;
pub const A_ANCHOR: usize = 41;
pub const A_NF: usize = 73;
pub const A_CM: usize = 105;
pub const A_MODE: usize = 169;
pub const A_PAYOUT: usize = 170;
pub const A_FEE: usize = 178;
pub const A_SPK: usize = 186;
pub const A_BOOT: usize = 222;
pub const A_CIPHER: usize = 230;
pub const P_AUTH: usize = 8;
pub const P_CIPHER: usize = P_AUTH + AUTH_LEN;
pub const P_STATE: usize = P_CIPHER + 370;
pub const PAYLOAD_SIZE: usize = P_STATE + STATE_LEN;

#[derive(Clone, Debug)]
pub struct Authorization {
    pub domain: H,
    pub count: u8,
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
pub fn anchor_bytes(commitments: &[H]) -> Vec<u8> {
    let mut b = vec![commitments.len() as u8];
    for i in 0..CAP {
        b.extend(commitments.get(i).copied().unwrap_or([0; 32]));
    }
    b
}
impl Authorization {
    pub fn bytes(&self) -> Vec<u8> {
        [
            b"KPIAU01\0".as_slice(),
            &self.domain,
            &[self.count],
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
        if b.len() != AUTH_LEN || &b[..8] != b"KPIAU01\0" {
            return Err("authorization framing".into());
        }
        Ok(Self {
            domain: b[8..40].try_into()?,
            count: b[A_COUNT],
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
    pub fn next(&self, old: &State) -> Result<State> {
        old.check()?;
        let count = usize::from(self.count);
        if count == 0
            || count > old.commitments.len()
            || hash(&anchor_bytes(&old.commitments[..count])) != self.anchor
        {
            return Err("unauthenticated commitment anchor".into());
        }
        if ![1, 2].contains(&self.mode) || self.fee == 0 || self.fee > MAX_SOMPI {
            return Err("authorization mode/fee".into());
        }
        let mut next = old.clone();
        next.nullifiers.push(self.nullifier);
        if self.mode == 1 {
            next.commitments.extend(self.outputs);
        } else if self.outputs != [[0; 32]; 2] {
            return Err("exit output padding".into());
        }
        next.check()?;
        Ok(next)
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
    pub fn payload(&self, next: &State) -> Result<Vec<u8>> {
        let a = self.auth()?;
        let c = self.ciphertext_bytes()?;
        if hash(&c) != a.cipher_hash || (a.mode == 2 && c != vec![0; 370]) {
            return Err("ciphertext binding/padding".into());
        }
        Ok([b"KPIAR01\0".as_slice(), &a.bytes(), &c, &next.bytes()].concat())
    }
}
pub fn parse_payload(b: &[u8]) -> Result<(Authorization, State)> {
    if b.len() != PAYLOAD_SIZE || &b[..8] != b"KPIAR01\0" {
        return Err("anchored payload framing".into());
    }
    let a = Authorization::parse(&b[P_AUTH..P_CIPHER])?;
    if a.cipher_hash != hash(&b[P_CIPHER..P_STATE])
        || (a.mode == 2 && b[P_CIPHER..P_STATE].iter().any(|x| *x != 0))
    {
        return Err("ciphertext binding".into());
    }
    Ok((a, State::parse(&b[P_STATE..])?))
}
pub fn settle(
    domain: &H,
    old: &State,
    input: &native::Utxo,
    vk: &[u8],
    bundle: &Bundle,
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let a = bundle.auth()?;
    if a.domain != *domain {
        return Err("wrong pool".into());
    }
    let next = a.next(old)?;
    let redeem = covenant::redeem(domain, old, vk)?;
    if input.spk != hex::encode(native::encode_spk(&pay_to_script_hash_script(&redeem))) {
        return Err("current reserve script mismatch".into());
    }
    let remaining = input
        .amount
        .checked_sub(a.payout)
        .and_then(|v| v.checked_sub(a.fee))
        .ok_or("reserve underflow")?;
    let terminal = next.commitments.len() == next.nullifiers.len();
    let mut outputs = Vec::new();
    if !terminal {
        outputs.push(TransactionOutput::new(
            remaining,
            pay_to_script_hash_script(&covenant::redeem(domain, &next, vk)?),
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
        bundle.payload(&next)?,
    );
    let entries = vec![input.entry()?];
    native::set_mass(&tx, &entries)?;
    Ok((tx, entries))
}
