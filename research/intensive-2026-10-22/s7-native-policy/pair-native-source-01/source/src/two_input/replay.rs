//! Offline replay of the unchanged v6 relation, without a depositor roster.
//!
//! The caller must authenticate the descriptor and supply an externally
//! authenticated accepted-chain view. Matching parent bytes/IDs do NOT prove
//! acceptance, freshness, current spendability or absence of an external spend.
//! This component validates founding/pool transactions with resolved input
//! context; it does not recursively validate funding parents' input ancestry.
use super::*;
use crate::protocol::GENESIS_HEX;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

pub const DESCRIPTOR_FORMAT: &str = "kpi-v6-public-replay-v1";
pub const SCOPE: &str =
    "offline native replay; descriptor and accepted-chain view must be authenticated externally";

/// Pool identity, not a registry of permitted participants or funding sources.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub network: String,
    pub genesis: String,
    pub domain: H,
    pub initial_commitment: H,
    pub initial_value_sompi: String,
    pub vk_sha256: String,
    pub funding_txid: String,
    pub funding_full_hash: String,
}

impl Descriptor {
    pub(super) fn validate(&self, vk: &[u8]) -> Result<u64> {
        if self.format != DESCRIPTOR_FORMAT
            || self.network != "testnet-10"
            || self.genesis != GENESIS_HEX
            || vk.len() != 328
            || self.vk_sha256 != hex::encode(hash(vk))
        {
            return Err("public replay descriptor/VK identity".into());
        }
        for value in [&self.vk_sha256, &self.funding_txid, &self.funding_full_hash] {
            let bytes = hex::decode(value)?;
            if bytes.len() != 32 || hex::encode(&bytes) != *value {
                return Err("descriptor hash encoding".into());
            }
        }
        let amount: u64 = self.initial_value_sompi.parse()?;
        if amount.to_string() != self.initial_value_sompi
            || !(NOTE_FLOOR..=MAX_SOMPI).contains(&amount)
        {
            return Err("initial reserve amount encoding/range".into());
        }
        Ok(amount)
    }
}

/// Cumulative accounting uses decimal u128, since turnover can exceed the
/// maximum value of an individual native amount. No floats cross this API.
#[derive(Clone, Debug, Serialize)]
pub struct Accounting {
    pub initial_reserve_sompi: String,
    pub admitted_sompi: String,
    pub paid_sompi: String,
    pub pool_fees_sompi: String,
    pub remaining_reserve_sompi: String,
    pub founding_input_sompi: String,
    pub founding_change_sompi: String,
    pub founding_fee_sompi: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicRecord {
    pub transaction: Value,
    pub full_hash: String,
    pub authorization_sha256: Option<String>,
    pub proof_sha256: Option<String>,
}

/// Public records retain the exact validated ciphertext/proof/transaction bytes.
/// A valid founding output alone is not yet an admission-ready pool: the
/// founder's first bootstrap transition must validate before bootstrap_validated.
#[derive(Clone, Serialize)]
pub struct Replay {
    pub scope: &'static str,
    pub chain_acceptance_verified: bool,
    pub bootstrap_validated: bool,
    pub state: tree::PublicState,
    pub reserve: Option<native::Utxo>,
    pub accounting: Accounting,
    pub records: Vec<PublicRecord>,
}

impl Replay {
    pub fn summary(&self) -> Result<Value> {
        Ok(json!({
            "scope": self.scope,
            "chain_acceptance_verified": self.chain_acceptance_verified,
            "bootstrap_validated": self.bootstrap_validated,
            "transactions": self.records.len(),
            "drained": self.reserve.is_none(),
            "state": self.state.compact()?,
            "reserve": self.reserve,
            "accounting": self.accounting,
            "records": self.records.iter().map(|r| json!({
                "transaction_id":r.transaction["id"],
                "full_hash":r.full_hash,
                "authorization_sha256":r.authorization_sha256,
                "proof_sha256":r.proof_sha256,
            })).collect::<Vec<_>>(),
        }))
    }
}

/// Deliberately narrow parent support: canonical version-1 native transaction,
/// zero locktime/gas, empty payload and no output covenant metadata. The common
/// native parser checks the canonical ID and envelope. Native subnetwork plus
/// nonempty ordinary inputs excludes a coinbase parent before creating context.
pub(super) struct Parents {
    transactions: HashMap<String, Transaction>,
    consumed: HashSet<(String, u32)>,
}

impl Parents {
    pub(super) fn new(bodies: &[Value]) -> Result<Self> {
        let mut transactions = HashMap::new();
        for body in bodies {
            let tx = native::parse_tx(body)
                .map_err(|e| format!("unsupported or noncanonical funding parent: {e}"))?;
            if tx.inputs.is_empty() || !tx.payload.is_empty() || tx.outputs.is_empty() {
                return Err(
                    "unsupported funding parent: ordinary inputs/empty payload required".into(),
                );
            }
            let id = tx.id().to_string();
            if let Some(previous) = transactions.get(&id) {
                if native::tx_json(previous) != *body {
                    return Err("conflicting funding parent bodies for one ID".into());
                }
            } else {
                transactions.insert(id, tx);
            }
        }
        Ok(Self {
            transactions,
            consumed: HashSet::new(),
        })
    }

    pub(super) fn consume(
        &mut self,
        point: &kaspa_consensus_core::tx::TransactionOutpoint,
    ) -> Result<native::Utxo> {
        let id = point.transaction_id.to_string();
        if self.consumed.contains(&(id.clone(), point.index)) {
            return Err("external funding outpoint already consumed".into());
        }
        let parent = self
            .transactions
            .get(&id)
            .ok_or("missing funding parent body")?;
        let output = parent
            .outputs
            .get(point.index as usize)
            .ok_or("funding output index out of range")?;
        let spk = native::encode_spk(&output.script_public_key);
        if spk.len() != 36 || spk[..3] != [0, 0, 0x20] || spk[35] != 0xac {
            return Err("unsupported funding output: ordinary P2PK required".into());
        }
        if output.value == 0 || output.value > MAX_SOMPI {
            return Err("funding output amount out of range".into());
        }
        self.consumed.insert((id, point.index));
        // Ordinary/non-coinbase status follows the checked parent envelope.
        // DAA is irrelevant here: coinbase and relative-locktime inputs are
        // unsupported; accepted-chain authentication is external to this API.
        Ok(native::Utxo::output(parent, point.index as usize, 0))
    }
}

pub(super) fn bundle(tx: &Transaction) -> Result<Bundle> {
    let signature = &tx
        .inputs
        .first()
        .ok_or("missing reserve input")?
        .signature_script;
    if tx.payload.len() != PAYLOAD_SIZE
        || &tx.payload[..8] != b"KPICR06\0"
        || signature.len() != covenant::WITNESS_LEN
        || signature[..2] != [0x4c, 128]
    {
        return Err("v6 pool transaction framing".into());
    }
    Ok(Bundle {
        authorization: hex::encode(&tx.payload[P_AUTH..P_CIPHER]),
        proof: hex::encode(&signature[2..130]),
        ciphertexts: [
            hex::encode(&tx.payload[P_CIPHER..P_CIPHER + 185]),
            hex::encode(&tx.payload[P_CIPHER + 185..P_STATE]),
        ],
    })
}

fn record(tx: &Transaction, authorization: Option<&Bundle>) -> Result<PublicRecord> {
    Ok(PublicRecord {
        transaction: native::tx_json(tx),
        full_hash: kaspa_consensus_core::hashing::tx::hash(tx).to_string(),
        authorization_sha256: authorization
            .map(|b| {
                Ok::<_, Box<dyn std::error::Error>>(hex::encode(hash(&hex::decode(
                    &b.authorization,
                )?)))
            })
            .transpose()?,
        proof_sha256: authorization
            .map(|b| {
                Ok::<_, Box<dyn std::error::Error>>(hex::encode(hash(&hex::decode(&b.proof)?)))
            })
            .transpose()?,
    })
}

/// Replay accepted *public* inputs supplied by the caller. No network, private
/// keys, proving parameters, new proofs or broadcasts are used.
pub fn replay(
    descriptor: &Descriptor,
    vk: &[u8],
    lineage: &[Value],
    funding_parents: &[Value],
) -> Result<Replay> {
    let initial = descriptor.validate(vk)?;
    let mut parents = Parents::new(funding_parents)?;
    let founding = native::parse_tx(lineage.first().ok_or("missing pool lineage")?)?;
    let mut state = tree::PublicState::initial(descriptor.initial_commitment)?;
    if founding.id().to_string() != descriptor.funding_txid
        || kaspa_consensus_core::hashing::tx::hash(&founding).to_string()
            != descriptor.funding_full_hash
        || founding.inputs.len() != 1
        || founding.outputs.len() != 2
        || !founding.payload.is_empty()
        || founding.inputs[0].sequence != u64::MAX
        || founding.outputs[0].value != initial
        || founding.outputs[0].script_public_key != reserve_spk(&descriptor.domain, &state, vk)?
    {
        return Err("pinned founding transaction/initial reserve mismatch".into());
    }
    let source = parents.consume(&founding.inputs[0].previous_outpoint)?;
    let founding_fee = native::validate(&founding, &[source.entry()?])
        .map_err(|e| format!("founding native validation: {e}"))?;
    let mut reserve = Some(native::Utxo::output(&founding, 0, 0));
    let mut records = vec![record(&founding, None)?];
    let mut seen = HashSet::from([founding.id()]);
    let (mut admitted, mut paid, mut fees) = (0u128, 0u128, 0u128);
    for body in lineage.iter().skip(1) {
        let tx = native::parse_tx(body)?;
        if !seen.insert(tx.id()) {
            return Err("duplicate pool transaction".into());
        }
        let prior = reserve
            .as_ref()
            .ok_or("pool history continues after drainage")?;
        if tx
            .inputs
            .first()
            .ok_or("missing reserve input")?
            .previous_outpoint
            != prior.outpoint()?
        {
            return Err("reserve lineage discontinuity".into());
        }
        let b = bundle(&tx)?;
        let a = b.auth()?;
        let external = if a.mode == 0 {
            Some(
                parents.consume(
                    &tx.inputs
                        .get(1)
                        .ok_or("missing admission input")?
                        .previous_outpoint,
                )?,
            )
        } else {
            None
        };
        let (mut expected, entries, next) =
            settle(&descriptor.domain, &state, prior, vk, &b, external.as_ref())?;
        if external.is_some() {
            expected.inputs[1].signature_script = tx.inputs[1].signature_script.clone();
            expected.finalize();
        }
        if native::tx_json(&expected) != *body {
            return Err("public state/transaction reconstruction mismatch".into());
        }
        let fee =
            native::validate(&tx, &entries).map_err(|e| format!("pool native validation: {e}"))?;
        if fee != a.fee {
            return Err("native fee/authorization mismatch".into());
        }
        let credit = external.as_ref().map_or(0, |u| u.amount);
        let remaining = prior
            .amount
            .checked_add(credit)
            .and_then(|v| v.checked_sub(a.payout))
            .and_then(|v| v.checked_sub(fee))
            .ok_or("reserve accounting overflow/underflow")?;
        admitted = admitted
            .checked_add(u128::from(credit))
            .ok_or("admission accounting overflow")?;
        paid = paid
            .checked_add(u128::from(a.payout))
            .ok_or("payout accounting overflow")?;
        fees = fees
            .checked_add(u128::from(fee))
            .ok_or("fee accounting overflow")?;
        if u128::from(initial) + admitted != paid + fees + u128::from(remaining) {
            return Err("public reserve accounting mismatch".into());
        }
        reserve = if remaining == 0 {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        state = next;
        records.push(record(&tx, Some(&b))?);
    }
    Ok(Replay {
        scope: SCOPE,
        chain_acceptance_verified: false,
        bootstrap_validated: records.len() > 1,
        state,
        accounting: Accounting {
            initial_reserve_sompi: initial.to_string(),
            admitted_sompi: admitted.to_string(),
            paid_sompi: paid.to_string(),
            pool_fees_sompi: fees.to_string(),
            remaining_reserve_sompi: reserve.as_ref().map_or(0, |u| u.amount).to_string(),
            founding_input_sompi: source.amount.to_string(),
            founding_change_sompi: founding.outputs[1].value.to_string(),
            founding_fee_sompi: founding_fee.to_string(),
        },
        reserve,
        records,
    })
}

pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 5 || !matches!(args[0].as_str(), "check" | "replay") {
        return Err("check|replay DESCRIPTOR_JSON VK_BIN LINEAGE_JSON FUNDING_PARENTS_JSON".into());
    }
    let read = |p: &str| -> Result<Value> { Ok(serde_json::from_slice(&fs::read(Path::new(p))?)?) };
    let descriptor: Descriptor = serde_json::from_value(read(&args[1])?)?;
    let lineage: Vec<Value> = serde_json::from_value(read(&args[3])?)?;
    let parents: Vec<Value> = serde_json::from_value(read(&args[4])?)?;
    let result = replay(&descriptor, &fs::read(&args[2])?, &lineage, &parents)?;
    let output = if args[0] == "check" {
        result.summary()?
    } else {
        serde_json::to_value(&result)?
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests;
