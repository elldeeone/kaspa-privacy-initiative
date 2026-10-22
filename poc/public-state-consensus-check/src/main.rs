//! OFFLINE Full validator of one exact NONFUNDABLE synthetic transaction.
//! This imports no SDK, prover or shared-pool implementation.
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    constants::{MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI},
    errors::tx::TxRuleError,
    hashing::tx as tx_hash,
    mass::{Mass, MassCalculator, transaction_estimated_serialized_size},
    tx::{ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry},
};
use kaspa_txscript::{
    caches::TxScriptCacheCounters, opcodes::codes::OpTrue, p2sh_sig_scanner,
    pay_to_script_hash_script, script_class::ScriptClass, zk_precompiles::groth16::Groth16Error,
};
use kaspa_txscript_errors::TxScriptError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io::Write, path::Path, sync::Arc, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const REV: &str = "01b532e8b553523216471682649693af92f0fd16";
// Synthetic caller-supplied context, not a queried selected-chain view.
const POV_DAA: u64 = 1_000_000_000;
const BLOCK_DAA: u64 = 2_000_000_000_000;
const FEE: u64 = 80_000_000;
const EXPECTED_TX_ID: &str = "b79c32deebb2d8800672ec07d4b9996688569750050ebb0de18d94798a6f6b97";
const EXPECTED_FULL_HASH: &str = "056636101fadbf4eb400104e59031fec9499615028713a85c5f3ae078d6af2ed";
const EXPECTED_J_SHA: &str = "457a9c09edd5840a978f8b785e165af3656c77f579b43ff322a9b3548a88c3f3";
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn pinned(dir: &Path, name: &str, size: u64, sha: &str) -> Result<Vec<u8>> {
    let p = dir.join(name);
    if fs::metadata(&p)?.len() != size {
        return Err(format!("pinned size: {name}").into());
    }
    let b = fs::read(p)?;
    if hash(&b) != sha {
        return Err(format!("pinned SHA256: {name}").into());
    }
    Ok(b)
}
fn validator() -> TransactionValidator {
    let p = TESTNET_PARAMS;
    TransactionValidator::new(
        p.max_tx_inputs,
        p.max_tx_outputs,
        p.max_signature_script_len,
        p.max_script_public_key_len,
        p.coinbase_payload_script_public_key_max_len,
        p.coinbase_maturity(),
        p.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(&p),
        p.mass_per_sig_op,
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Isolation,
    Full,
}
fn validate(
    v: &TransactionValidator,
    tx: &Transaction,
    entries: &[UtxoEntry],
) -> std::result::Result<u64, (Stage, TxRuleError)> {
    v.validate_tx_in_isolation(tx)
        .map_err(|e| (Stage::Isolation, e))?;
    v.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        POV_DAA,
        BLOCK_DAA,
        TxValidationFlags::Full,
        None,
        None,
    )
    .map_err(|e| (Stage::Full, e))
}
fn native_case(
    v: &TransactionValidator,
    label: &str,
    tx: &Transaction,
    entries: &[UtxoEntry],
    expected: Option<(Stage, TxRuleError)>,
) -> (Value, bool) {
    let start = Instant::now();
    let actual = validate(v, tx, entries);
    let matched = match (&actual, &expected) {
        (Ok(fee), None) => *fee == FEE,
        (Err(a), Some(e)) => a == e,
        _ => false,
    };
    (
        json!({"case":label,"matched_expectation":matched,"accepted":actual.is_ok(),
        "native_isolation_passed":!matches!(actual, Err((Stage::Isolation,_))),
        "full_validation_executed":!matches!(actual, Err((Stage::Isolation,_))),
        "actual_fee_sompi":actual.as_ref().ok().map(|x|x.to_string()),
        "actual_error":actual.as_ref().err().map(|(s,e)|json!({"stage":format!("{s:?}"),"variant":format!("{e:?}"),"display":e.to_string()})),
        "expected_error":expected.as_ref().map(|(s,e)|json!({"stage":format!("{s:?}"),"variant":format!("{e:?}"),"display":e.to_string()})),
        "seconds":start.elapsed().as_secs_f64()}),
        matched,
    )
}

// Source-adapted policy only: upstream Mempool entrypoints are pub(crate).
// This is not a live Mempool, conflict/RBF check or relay-admission result.
#[derive(Debug, PartialEq, Eq)]
enum PolicyError {
    Dimensions,
    OutputVersion(usize),
    OutputClass(usize),
    InputClass(usize),
    Sigops(usize, u64),
    Fee(u64, u64),
}
fn mass(
    tx: &Transaction,
    entries: &[UtxoEntry],
) -> (
    kaspa_consensus_core::mass::NonContextualMasses,
    kaspa_consensus_core::mass::ContextualMasses,
) {
    let c = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    (
        c.calc_non_contextual_masses(tx),
        c.calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
            .expect("bounded context mass"),
    )
}
fn relay_fee(mass: u64, sompi_per_kg: u64) -> u64 {
    let fee = mass.saturating_mul(sompi_per_kg) / 1000;
    (if fee == 0 { sompi_per_kg } else { fee }).min(MAX_SOMPI)
}
fn policy(
    tx: &Transaction,
    entries: &[UtxoEntry],
    sompi_per_kg: u64,
) -> std::result::Result<(), PolicyError> {
    let (n, c) = mass(tx, entries);
    let limits = TESTNET_PARAMS.block_mass_limits;
    if n.compute_mass > limits.compute
        || n.transient_mass > limits.transient
        || c.storage_mass > limits.storage
    {
        return Err(PolicyError::Dimensions);
    }
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.script_public_key.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION {
            return Err(PolicyError::OutputVersion(i));
        }
        if ScriptClass::from_script(&o.script_public_key) == ScriptClass::NonStandard {
            return Err(PolicyError::OutputClass(i));
        }
    }
    for (i, (input, e)) in tx.inputs.iter().zip(entries).enumerate() {
        match ScriptClass::from_script(&e.script_public_key) {
            ScriptClass::NonStandard => return Err(PolicyError::InputClass(i)),
            ScriptClass::ScriptHash => {
                let count = p2sh_sig_scanner(&input.signature_script, &e.script_public_key);
                if count > 15 {
                    return Err(PolicyError::Sigops(i, count));
                }
            }
            _ => {}
        }
    }
    let fee = entries.iter().map(|e| e.amount).sum::<u64>()
        - tx.outputs.iter().map(|o| o.value).sum::<u64>();
    let floor = relay_fee(n.normalized_max(&limits.cofactors()), sompi_per_kg);
    if fee < floor {
        return Err(PolicyError::Fee(fee, floor));
    }
    Ok(())
}
fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 4 || a[1] != "verify" {
        return Err("usage: verify FROZEN_NATIVE_EVIDENCE NEW_OUTPUT".into());
    }
    let input = Path::new(&a[2]);
    let body = pinned(
        input,
        "transaction.native-borsh.bin",
        2910,
        "8cb44d28e488eab9e59f540b47016394dd8cf440313332e0cac48e827ac18c97",
    )?;
    let redeem = pinned(
        input,
        "previous-redeem.bin",
        1383,
        "4692b76504462ca985630499fa87394e53946023592ef41a7a48e1d58d973f83",
    )?;
    let j = pinned(input, "reconstructed-journal.bin", 336, EXPECTED_J_SHA)?;
    let tx: Transaction = borsh::from_slice(&body)?; // Exact-consumption deserializer.
    if borsh::to_vec(&tx)? != body
        || tx.id().to_string() != EXPECTED_TX_ID
        || tx_hash::hash(&tx).to_string() != EXPECTED_FULL_HASH
    {
        return Err("body/hash identity".into());
    }
    let mut rehashed = tx.clone();
    rehashed.finalize();
    if rehashed != tx || tx.inputs.len() != 1 || tx.outputs.len() != 1 {
        return Err("cached identity or shape".into());
    }
    let reserve = u64::from_le_bytes(j[320..328].try_into()?);
    let next = u64::from_le_bytes(j[328..336].try_into()?);
    if &j[..10] != b"KPI2V6S1\x01\x00"
        || reserve != 1_700_000_000
        || next != 1_620_000_000
        || reserve - next != FEE
        || tx.outputs[0].value != next
        || tx.inputs[0].previous_outpoint.transaction_id.as_bytes() != j[74..106]
        || tx.inputs[0].previous_outpoint.index != u32::from_le_bytes(j[106..110].try_into()?)
        || tx.inputs[0].signature_script.get(133..) != Some(redeem.as_slice())
        || tx.inputs[0].compute_commit.compute_budget() != Some(1600)
    {
        return Err("declared frozen context mismatch".into());
    }
    let entries = vec![UtxoEntry::new(
        reserve,
        pay_to_script_hash_script(&redeem),
        0,
        false,
        None,
    )];
    let v = validator();
    let mut cases = Vec::new();
    let (r, mut passed) = native_case(&v, "frozen-unchanged-positive", &tx, &entries, None);
    cases.push(r);
    for label in [
        "no-inputs",
        "duplicate-input",
        "zero-output",
        "over-max-output",
        "outputs-exceed-input",
        "over-max-input",
        "wrong-storage-mass",
        "changed-P",
        "immature-coinbase-context",
        "unmet-sequence-lock",
    ] {
        let mut changed = tx.clone();
        let mut context = entries.clone();
        let expected = match label {
            "no-inputs" => {
                changed.inputs.clear();
                context.clear();
                (Stage::Isolation, TxRuleError::NoTxInputs)
            }
            "duplicate-input" => {
                changed.inputs.push(changed.inputs[0].clone());
                context.push(context[0].clone());
                (Stage::Isolation, TxRuleError::TxDuplicateInputs)
            }
            "zero-output" => {
                changed.outputs[0].value = 0;
                (Stage::Isolation, TxRuleError::TxOutZero(0))
            }
            "over-max-output" => {
                changed.outputs[0].value = MAX_SOMPI + 1;
                (Stage::Isolation, TxRuleError::TxOutTooHigh(0))
            }
            "outputs-exceed-input" => {
                changed.outputs[0].value = reserve + 1;
                (Stage::Full, TxRuleError::SpendTooHigh(reserve + 1, reserve))
            }
            "over-max-input" => {
                context[0].amount = MAX_SOMPI + 1;
                (Stage::Full, TxRuleError::InputAmountTooHigh)
            }
            "wrong-storage-mass" => {
                changed.set_storage_mass(tx.storage_mass() + 1);
                (
                    Stage::Full,
                    TxRuleError::WrongMass(tx.storage_mass(), tx.storage_mass() + 1),
                )
            }
            "changed-P" => {
                changed.payload[1000] ^= 1;
                (
                    Stage::Full,
                    TxRuleError::SignatureInvalid(TxScriptError::ZkIntegrity(
                        Groth16Error::VerificationFailed.to_string(),
                    )),
                )
            }
            "immature-coinbase-context" => {
                context[0].is_coinbase = true;
                context[0].block_daa_score = POV_DAA;
                (
                    Stage::Full,
                    TxRuleError::ImmatureCoinbaseSpend(
                        0,
                        tx.inputs[0].previous_outpoint,
                        POV_DAA,
                        POV_DAA,
                        TESTNET_PARAMS.coinbase_maturity(),
                    ),
                )
            }
            "unmet-sequence-lock" => {
                context[0].block_daa_score = POV_DAA;
                changed.inputs[0].sequence = 1;
                (Stage::Full, TxRuleError::SequenceLockConditionsAreNotMet)
            }
            _ => unreachable!(),
        };
        changed.finalize();
        let (r, ok) = native_case(&v, label, &changed, &context, Some(expected));
        passed &= ok;
        cases.push(r);
    }
    let mut policies = Vec::new();
    for label in [
        "default-source-adapted-policy",
        "maximum-budget-over-block-mass",
        "nonstandard-output",
        "scenario500-fee-insufficient",
    ] {
        let mut changed = tx.clone();
        let mut rate = 100_000;
        let expected = match label {
            "default-source-adapted-policy" => Ok(()),
            "maximum-budget-over-block-mass" => {
                changed.inputs[0].compute_commit = ComputeCommit::ComputeBudget(u16::MAX.into());
                Err(PolicyError::Dimensions)
            }
            "nonstandard-output" => {
                changed.outputs[0].script_public_key = ScriptPublicKey::from_vec(0, vec![OpTrue]);
                Err(PolicyError::OutputClass(0))
            }
            "scenario500-fee-insufficient" => {
                rate = 500_000;
                Err(PolicyError::Fee(FEE, 81_645_000))
            }
            _ => unreachable!(),
        };
        changed.finalize();
        let actual = policy(&changed, &entries, rate);
        let ok = actual == expected;
        passed &= ok;
        policies.push(json!({"case":label,"source_adapted_not_mempool":true,"matched_expectation":ok,"sompi_per_kg":rate,"actual":format!("{actual:?}"),"expected":format!("{expected:?}")}));
    }
    let (n, c) = mass(&tx, &entries);
    let limits = TESTNET_PARAMS.block_mass_limits;
    let cofactors = limits.cofactors();
    let report = json!({"scope":"OFFLINE_OFFICIAL_FULL_TRANSACTION_VALIDATION_OF_SAME_NONFUNDABLE_ONE_SHOT_BODY","all_expectations_met":passed,
        "native_revision":REV,"body_sha256":hash(&body),"body_bytes":body.len(),"body_changed":false,"journal_sha256":hash(&j),"previous_redeem_sha256":hash(&redeem),
        "checker_binary_sha256":hash(&fs::read(std::env::current_exe()?)?),"transaction_id":tx.id().to_string(),"transaction_full_hash":tx_hash::hash(&tx).to_string(),
        "supplied_context":{"pov_daa_score":POV_DAA,"block_daa_score":BLOCK_DAA,"utxo_block_daa_score":0,"is_coinbase":false,"covenant_id":null,
            "input_amount_sompi":reserve.to_string(),"output_amount_sompi":next.to_string(),"actual_fee_sompi":FEE.to_string(),"utxo_spk_version":entries[0].script_public_key.version(),"utxo_spk_hex":hex::encode(entries[0].script_public_key.script()),"source":"declared synthetic UTXO, no database/selected-chain lookup"},
        "native_validation_flags":"Full","skip_script_or_mass_checks":false,"rbf_threshold":null,"seq_commit_accessor":null,
        "native_cases":cases,"source_adapted_policy_cases":policies,
        "native_mass":{"estimated_bytes":transaction_estimated_serialized_size(&tx),"compute":n.compute_mass,"transient":n.transient_mass,"storage":c.storage_mass,"committed_storage":tx.storage_mass(),"relay":n.normalized_max(&cofactors),"mining":Mass::new(n,c).normalized_max(&cofactors)},
        "block_dimensions":{"compute":limits.compute,"transient":limits.transient,"storage":limits.storage},
        "actual_mempool_admission":false,"chain_acceptance":false,"predecessor_lineage_or_backing_proven":false,"owner_exit_tested":false,"network_or_funding_used":false,
        "limitations":["Full validator trusts supplied UTXO/DAA context and does not prove this predecessor exists or is unspent in an accepted chain.","No header/block contextual HF activation, selected-chain, mempool conflict/RBF or P2P relay execution.","Policy checks are source-adapted public script/scanner/fee predicates because actual Mempool methods are crate-private.","Block dimension policy is separate from the Full validator storage commitment check.","Same immutable literal predecessor makes successor deliberately noncontinuing; NONFUNDABLE, no owner exit or backing claim.","No proof generation or SDK verification; exact retained proof/body/80M fee unchanged."]});
    let out = Path::new(&a[3]);
    fs::create_dir(out)?;
    save(out, "consumed-transaction.native-borsh.bin", &body)?;
    save(
        out,
        "declared-utxo.native-borsh.bin",
        &borsh::to_vec(&entries)?,
    )?;
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    fs::File::open(out)?.sync_all()?;
    println!(
        "{}",
        json!({"all_expectations_met":passed,"output":out,"nonfundable":true})
    );
    if !passed {
        return Err("expectations failed; exact outcome retained".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_fee_matches_native_rounding_and_range() {
        assert_eq!(relay_fee(163290, 100000), 16329000);
        assert_eq!(relay_fee(163290, 500000), 81645000);
        assert_eq!(relay_fee(0, 100000), 100000);
        assert_eq!(relay_fee(1, 1), 1);
        assert_eq!(
            relay_fee(u64::MAX, u64::MAX),
            MAX_SOMPI.min(u64::MAX / 1000)
        );
    }
    #[test]
    fn exact_consumption_borsh_rejects_trailing_bytes() {
        let mut bytes = borsh::to_vec(&1u64).unwrap();
        bytes.push(0);
        assert!(borsh::from_slice::<u64>(&bytes).is_err());
    }
}
