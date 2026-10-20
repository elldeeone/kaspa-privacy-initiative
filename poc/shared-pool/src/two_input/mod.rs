//! Separate immutable v6 research candidate. No live-network runner.
mod audit;
pub mod circuit;
pub mod covenant;
pub mod harness;
pub mod live;
pub mod replay;
pub mod tree;
use crate::{
    Result, native,
    protocol::{H, MAX_SOMPI, NOTE_TAG, Note, OWNER_TAG, Wallet, hash, random},
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use serde::{Deserialize, Serialize};
pub const NOTE_FLOOR: u64 = 60_000_000;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub const FEE: u64 = 40_000_000;
pub const DUMMY_TAG: &[u8] = b"KPI-dummy-nullifier-v1\0";
pub const AUTH_LEN: usize = 377;
pub const A_COUNT: usize = 40;
pub const A_ANCHOR: usize = 44;
pub const A_NF: usize = 76;
pub const A_CM: usize = 140;
pub const A_MODE: usize = 204;
pub const A_PAYOUT: usize = 205;
pub const A_FEE: usize = 213;
pub const A_SPK: usize = 221;
pub const A_DEP: usize = 257;
pub const A_FUND: usize = 265;
pub const A_FSPK: usize = 301;
pub const A_BOOT: usize = 337;
pub const A_CIPHER: usize = 345;
pub const STATE_LEN: usize = 105;
pub const P_AUTH: usize = 8;
pub const P_CIPHER: usize = 385;
pub const P_STATE: usize = 755;
pub const P_WITNESS: usize = 860;
pub const W_ANCHOR: usize = 0;
pub const W_NF: usize = 512;
pub const NF_WIT: usize = 1160;
pub const W_CM_APPEND: usize = 2832;
pub const W_HISTORY_APPEND: usize = 3856;
pub const W_LEN: usize = 4368;
pub const PAYLOAD_SIZE: usize = 5228;
pub const PATH_LEN: usize = 512;
#[derive(Clone, Debug)]
pub struct Authorization {
    pub domain: H,
    pub count: u32,
    pub anchor: H,
    pub nfs: [H; 2],
    pub outputs: [H; 2],
    pub mode: u8,
    pub payout: u64,
    pub fee: u64,
    pub spk: [u8; 36],
    pub deposit: u64,
    pub funding: [u8; 36],
    pub funding_spk: [u8; 36],
    pub bootstrap: u64,
    pub cipher_hash: H,
}
impl Authorization {
    pub fn bytes(&self) -> Vec<u8> {
        [
            b"KPICU06\0".as_slice(),
            &self.domain,
            &self.count.to_le_bytes(),
            &self.anchor,
            &self.nfs.concat(),
            &self.outputs.concat(),
            &[self.mode],
            &self.payout.to_le_bytes(),
            &self.fee.to_le_bytes(),
            &self.spk,
            &self.deposit.to_le_bytes(),
            &self.funding,
            &self.funding_spk,
            &self.bootstrap.to_le_bytes(),
            &self.cipher_hash,
        ]
        .concat()
    }
    pub fn inputs(&self) -> [Fr; 2] {
        let h = hash(&self.bytes());
        std::array::from_fn(|i| Fr::from_le_bytes_mod_order(&h[16 * i..16 * (i + 1)]))
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != AUTH_LEN || &b[..8] != b"KPICU06\0" {
            return Err("v6 authorization framing".into());
        }
        Ok(Self {
            domain: b[8..40].try_into()?,
            count: u32::from_le_bytes(b[40..44].try_into()?),
            anchor: b[44..76].try_into()?,
            nfs: [b[76..108].try_into()?, b[108..140].try_into()?],
            outputs: [b[140..172].try_into()?, b[172..204].try_into()?],
            mode: b[204],
            payout: u64::from_le_bytes(b[205..213].try_into()?),
            fee: u64::from_le_bytes(b[213..221].try_into()?),
            spk: b[221..257].try_into()?,
            deposit: u64::from_le_bytes(b[257..265].try_into()?),
            funding: b[265..301].try_into()?,
            funding_spk: b[301..337].try_into()?,
            bootstrap: u64::from_le_bytes(b[337..345].try_into()?),
            cipher_hash: b[345..377].try_into()?,
        })
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
    pub fn ciphers(&self) -> Result<Vec<u8>> {
        let c = self
            .ciphertexts
            .iter()
            .map(hex::decode)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if c.iter().any(|x| x.len() != 185) {
            return Err("cipher dimensions".into());
        }
        Ok(c.concat())
    }
}
pub fn dummy_nf(d: &H, key: &H, seed: &H, slot: u8) -> H {
    use hmac::{Hmac, Mac};
    let mut h = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    h.update(DUMMY_TAG);
    h.update(d);
    h.update(seed);
    h.update(&[slot]);
    h.finalize().into_bytes().into()
}
pub fn reserve_spk(
    d: &H,
    s: &tree::PublicState,
    vk: &[u8],
) -> Result<kaspa_consensus_core::tx::ScriptPublicKey> {
    Ok(pay_to_script_hash_script(&covenant::redeem(
        d,
        &s.compact()?,
        vk,
    )?))
}
pub fn settle(
    d: &H,
    old: &tree::PublicState,
    u: &native::Utxo,
    vk: &[u8],
    bundle: &Bundle,
    external: Option<&native::Utxo>,
) -> Result<(Transaction, Vec<UtxoEntry>, tree::PublicState)> {
    let a = bundle.auth()?;
    let c = bundle.ciphers()?;
    if a.domain != *d
        || hash(&c) != a.cipher_hash
        || (a.mode == 2 && c != [0; 370])
        || u.spk != hex::encode(native::encode_spk(&reserve_spk(d, old, vk)?))
    {
        return Err("v6 domain/reserve/cipher binding".into());
    }
    if (a.mode == 0) != external.is_some() {
        return Err("v6 admission framing".into());
    }
    let (next, w) = old.witness(&a)?;
    let mut total = u.amount;
    if let Some(e) = external {
        let point = [hex::decode(&e.txid)?, e.index.to_le_bytes().to_vec()].concat();
        if e.is_coinbase
            || e.amount != a.deposit
            || point != a.funding
            || hex::decode(&e.spk)? != a.funding_spk
        {
            return Err("v6 funding binding".into());
        }
        total = total
            .checked_add(e.amount)
            .filter(|v| *v <= MAX_SOMPI)
            .ok_or("input amount bound")?;
    }
    let remaining = total
        .checked_sub(a.payout)
        .and_then(|v| v.checked_sub(a.fee))
        .ok_or("backing underflow")?;
    if remaining == 0 && a.mode != 2 {
        return Err("terminal requires DRAIN".into());
    }
    let mut outputs = Vec::new();
    if remaining > 0 {
        outputs.push(TransactionOutput::new(
            remaining,
            reserve_spk(d, &next, vk)?,
        ));
    }
    if a.payout > 0 {
        outputs.push(TransactionOutput::new(
            a.payout,
            native::decode_spk(&hex::encode(a.spk))?,
        ));
    }
    let state = if remaining == 0 {
        vec![0; 105]
    } else {
        next.compact()?.bytes()
    };
    let payload = [b"KPICR06\0".as_slice(), &a.bytes(), &c, &state, &w].concat();
    let redeem = covenant::redeem(d, &old.compact()?, vk)?;
    let mut inputs = vec![TransactionInput::new_with_compute_budget(
        u.outpoint()?,
        covenant::signature(&hex::decode(&bundle.proof)?, &redeem)?,
        u64::MAX,
        covenant::BUDGET,
    )];
    let mut entries = vec![u.entry()?];
    if let Some(e) = external {
        let mut sig = vec![0; 66];
        sig[0] = 65;
        sig[65] = 1;
        inputs.push(TransactionInput::new_with_compute_budget(
            e.outpoint()?,
            sig,
            u64::MAX,
            10,
        ));
        entries.push(e.entry()?);
    }
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, payload);
    native::set_mass(&tx, &entries)?;
    Ok((tx, entries, next))
}
#[cfg(test)]
mod tests;
