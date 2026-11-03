//! Modeled economic effects, not Kaspa transaction/UTXO types.
use crate::{Error, MAX_SOMPI};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub txid: [u8; 32],
    pub index: u32,
    /// Supplied context, never independently authenticated by this package.
    pub value: u64,
    pub sequence: u64,
    /// 0: sigop count (<=255); 1: compute budget. No other tags.
    pub compute_kind: u8,
    pub compute: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub script_version: u16,
    pub script: Vec<u8>,
    pub covenant: Option<(u32, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effects {
    pub tx_version: u16,
    pub network: [u8; 32],
    pub genesis: [u8; 32],
    pub pool: [u8; 32],
    /// Supplied accepted-context identifier, not authenticated ancestry.
    pub accepted_context: [u8; 32],
    pub lock_time: u64,
    pub subnetwork: [u8; 20],
    pub gas: u64,
    pub storage_mass: u64,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub payload: Vec<u8>,
}

impl Effects {
    pub fn validate(&self, balance: i64) -> Result<(), Error> {
        let outpoints: std::collections::BTreeSet<_> =
            self.inputs.iter().map(|i| (i.txid, i.index)).collect();
        if outpoints.len() != self.inputs.len() {
            return Err(Error::DuplicateInput);
        }
        if self.fee > MAX_SOMPI || balance.unsigned_abs() > MAX_SOMPI {
            return Err(Error::Range);
        }
        let sum = |values: Vec<u64>| -> Result<u128, Error> {
            if values.iter().any(|v| *v > MAX_SOMPI) {
                return Err(Error::Range);
            }
            let result: u128 = values.into_iter().map(u128::from).sum();
            if result > u128::from(MAX_SOMPI) {
                return Err(Error::Range);
            }
            Ok(result)
        };
        let incoming = sum(self.inputs.iter().map(|i| i.value).collect())?;
        let outgoing = sum(self.outputs.iter().map(|o| o.value).collect())?;
        if incoming as i128 + i128::from(balance) != outgoing as i128 + i128::from(self.fee) {
            return Err(Error::Balance);
        }
        Ok(())
    }
}
