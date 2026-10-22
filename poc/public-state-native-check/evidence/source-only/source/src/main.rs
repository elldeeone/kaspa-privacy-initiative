//! NONFUNDABLE one-shot synthetic transaction-context diagnostic. Never broadcast.
mod receipt;
mod script;

use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::{sighash::SigHashReusedValuesUnsync, tx as tx_hash},
    mass::{transaction_estimated_serialized_size, Mass, MassCalculator},
    tx::{
        PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    caches::Cache, pay_to_script_hash_script, script_builder::ScriptBuilder,
    zk_precompiles::groth16::Groth16Error, EngineCtx, TxScriptEngine,
};
use kaspa_txscript_errors::TxScriptError;
use receipt::{hash, Constants};
use script::Policy;
use serde_json::{json, Value};
use std::{error::Error, fs, io::Write, path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NATIVE_REV: &str = "01b532e8b553523216471682649693af92f0fd16";
const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
const POOL_ID: [u8; 32] = [
    0xca, 0x2c, 0x2a, 0xb5, 0x08, 0x7b, 0xc6, 0x29, 0x65, 0xdb, 0x81, 0x7e, 0xd8, 0x21, 0xa3, 0x89,
    0x8b, 0x25, 0x5d, 0x06, 0xc7, 0x89, 0xe7, 0xc2, 0x04, 0x91, 0xaf, 0xad, 0x88, 0xca, 0x77, 0x56,
];
// Runtime is deliberately unavailable until the coordinator independently
// selects the new state image AND exact J336. These are not J42 pins.
const SELECTED_IMAGE: Option<&str> = None;
const SELECTED_JOURNAL_SHA: Option<&str> = None;
const EXPECTED_JOURNAL: &[u8; 336] = include_bytes!("../pins/expected-journal.bin");
const PUBLIC: &[u8; 1088] = include_bytes!("../pins/expected-public.bin");

#[derive(Clone)]
struct Fixture {
    prior: TransactionOutpoint,
    old: [u8; 105],
    new: [u8; 105],
    reserve: u64,
    next_reserve: u64,
}
fn selected() -> Result<([u8; 32], Fixture)> {
    let image: [u8; 32] =
        hex::decode(SELECTED_IMAGE.ok_or("SOURCE-ONLY: new state image not selected")?)?
            .try_into()
            .map_err(|_| "image length")?;
    let expected = SELECTED_JOURNAL_SHA.ok_or("SOURCE-ONLY: new J336 not selected")?;
    if hex::encode(hash(EXPECTED_JOURNAL)) != expected {
        return Err("compiled J336 SHA mismatch".into());
    }
    let j = EXPECTED_JOURNAL;
    if &j[..10] != b"KPI2V6S1\x01\x00" || j[10..42] != hash(PUBLIC) || j[42..74] != POOL_ID {
        return Err("compiled J336/public/pool framing".into());
    }
    if hash(b"KPI/public-two-v6-state/DO-NOT-FUND/v1") != POOL_ID {
        return Err("pool identity".into());
    }
    let f = Fixture {
        prior: TransactionOutpoint::new(
            Hash::from_bytes(j[74..106].try_into()?),
            u32::from_le_bytes(j[106..110].try_into()?),
        ),
        old: j[110..215].try_into()?,
        new: j[215..320].try_into()?,
        reserve: u64::from_le_bytes(j[320..328].try_into()?),
        next_reserve: u64::from_le_bytes(j[328..336].try_into()?),
    };
    let fee = u128::from_le_bytes(PUBLIC[76..92].try_into()?);
    if f.old[0] != 7
        || f.new[0] != 7
        || fee == 0
        || fee > u128::from(MAX_SOMPI)
        || f.reserve > MAX_SOMPI
        || f.next_reserve == 0
        || f.next_reserve > MAX_SOMPI
        || u128::from(f.reserve) <= fee
        || f.reserve - u64::try_from(fee)? != f.next_reserve
    {
        return Err("compiled fixture state/amount framing".into());
    }
    Ok((image, f))
}
fn signature(proof: &[u8], redeem: &[u8]) -> Result<Vec<u8>> {
    if proof.len() != 128 || !(256..=u16::MAX as usize).contains(&redeem.len()) {
        return Err("canonical witness shape".into());
    }
    let mut b = ScriptBuilder::new();
    b.add_data(proof)?.add_data(redeem)?;
    Ok(b.drain())
}
fn body(
    p: &Policy,
    f: &Fixture,
    c: &Constants,
    proof: &[u8],
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let old = script::redeem(p, &f.old, c)?;
    let new = script::redeem(p, &f.new, c)?;
    let utxo = UtxoEntry::new(f.reserve, pay_to_script_hash_script(&old), 0, false, None);
    let payload = [b"KPI2V6T1\x01\x00".as_slice(), PUBLIC, &f.new].concat();
    if payload.len() != script::PAYLOAD_LEN {
        return Err("payload shape".into());
    }
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            f.prior,
            signature(proof, &old)?,
            u64::MAX,
            script::BUDGET,
        )],
        vec![TransactionOutput::new(
            f.next_reserve,
            pay_to_script_hash_script(&new),
        )],
        0,
        Default::default(),
        0,
        payload,
    );
    Ok((tx, vec![utxo]))
}
fn finalize(tx: &mut Transaction, entries: &[UtxoEntry]) -> Result<()> {
    tx.finalize();
    let c = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let storage = c
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("undefined contextual storage mass")?;
    tx.set_storage_mass(storage.storage_mass);
    tx.finalize();
    Ok(())
}
fn context_journal(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Vec<u8>> {
    if tx.inputs.len() != 1 || tx.outputs.len() != 1 || entries.len() != 1 {
        return Err("host journal oracle shape".into());
    }
    let sig = &tx.inputs[0].signature_script;
    let old = sig
        .get(
            script::REDEEM_START + script::STATE_START
                ..script::REDEEM_START + script::STATE_START + 105,
        )
        .ok_or("host journal oracle old state framing")?;
    let p = tx
        .payload
        .get(10..1098)
        .ok_or("host journal oracle P framing")?;
    let new = tx
        .payload
        .get(1098..1203)
        .ok_or("host journal oracle next state framing")?;
    let point = &tx.inputs[0].previous_outpoint;
    Ok([
        b"KPI2V6S1\x01\x00".as_slice(),
        &hash(p),
        &POOL_ID,
        &point.transaction_id.as_bytes(),
        &point.index.to_le_bytes(),
        old,
        new,
        &entries[0].amount.to_le_bytes(),
        &tx.outputs[0].value.to_le_bytes(),
    ]
    .concat())
}
fn execute(
    tx: &Transaction,
    entries: &[UtxoEntry],
    label: &str,
    layer: &str,
    expected: Option<TxScriptError>,
) -> (Value, bool) {
    let pop = PopulatedTransaction::new(tx, entries.to_vec());
    let cache = Cache::new(1);
    let reused = SigHashReusedValuesUnsync::new();
    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &pop,
        &tx.inputs[0],
        0,
        &entries[0],
        EngineCtx::new(&cache).with_reused(&reused),
        Default::default(),
        tx.inputs[0].compute_commit.allowed_script_units(),
    );
    let start = Instant::now();
    let outcome = vm.execute();
    let seconds = start.elapsed().as_secs_f64();
    let matched = match (&outcome, &expected) {
        (Ok(()), None) => true,
        (Err(a), Some(e)) => a == e,
        _ => false,
    };
    (
        json!({"case":label,"verification_layer":layer,"accepted":outcome.is_ok(),
        "expected_accept":expected.is_none(),"matched_expectation":matched,
        "expected_error":expected.map(|e|e.to_string()),"native_error":outcome.err().map(|e|e.to_string()),
        "used_script_units":vm.used_script_units().0,"committed_budget":script::BUDGET,
        "allowed_script_units":tx.inputs[0].compute_commit.allowed_script_units().0,"seconds":seconds}),
        matched,
    )
}
fn metrics(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Value> {
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let non = calc.calc_non_contextual_masses(tx);
    let context = calc
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("storage mass")?;
    let cofactors = TESTNET_PARAMS.block_mass_limits.cofactors();
    let relay = non.normalized_max(&cofactors);
    let mining = Mass::new(non, context).normalized_max(&cofactors);
    let ins = entries.iter().try_fold(0u64, |a, u| {
        a.checked_add(u.amount).ok_or("input amount overflow")
    })?;
    let outs = tx.outputs.iter().try_fold(0u64, |a, o| {
        a.checked_add(o.value).ok_or("output amount overflow")
    })?;
    let fee = ins.checked_sub(outs).ok_or("negative fee")?;
    let quotes: [Value; 3] = [100u64, 200, 500].map(|rate| {
        let necessary = mining.checked_mul(rate).expect("bounded local mass quote");
        json!({"scenario_sompi_per_gram":rate,"necessary_fee_sompi":necessary.to_string(),
            "unchanged_actual_fee_covers":fee>=necessary,"actual_fee_sompi":fee.to_string()})
    });
    Ok(
        json!({"native_estimated_serialized_bytes":transaction_estimated_serialized_size(tx),
        "native_borsh_transaction_bytes":borsh::to_vec(tx)?.len(),"compute_mass":non.compute_mass,
        "transient_mass":non.transient_mass,"storage_mass":context.storage_mass,"storage_mass_commitment":tx.storage_mass(),
        "relay_mass":relay,"mining_mass":mining,"actual_transaction_fee_sompi":fee.to_string(),"scenario_fee_quotes":quotes,
        "block_dimension_limits":{"compute":500000,"transient":1000000,"storage":500000},
        "fits_pinned_block_dimensions":non.compute_mass<=500000&&non.transient_mass<=1000000&&context.storage_mass<=500000,
        "hypothetical_two_10_kas_one_percent_cap_sompi":"20000000","actual_fee_meets_that_hypothetical_cap":fee<=20000000,
        "paid_fee_reduction_demonstrated":false}),
    )
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
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "design-info" {
        println!(
            "{}",
            json!({"scope":"SOURCE_ONLY_NONFUNDABLE_ONE_SHOT_DIAGNOSTIC", "state_image_selected":SELECTED_IMAGE.is_some(),
            "state_journal_selected":SELECTED_JOURNAL_SHA.is_some(),"journal_bytes":336,"payload_bytes":1203,"prefix_bytes":142,
            "source_only_runtime_blocked":SELECTED_IMAGE.is_none()||SELECTED_JOURNAL_SHA.is_none(),"native_revision":NATIVE_REV})
        );
        return Ok(());
    }
    if args.len() != 4 || args[1] != "verify" {
        return Err(
            "usage: design-info | verify GENUINE_NEW_STATE_GROTH16_RECEIPT NEW_OUTPUT".into(),
        );
    }
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("RISC0_DEV_MODE forbidden".into());
    }
    let (image, fixture) = selected()?; // No native invocation while image/J are placeholders.
    let (r, raw) = receipt::load(Path::new(&args[2]))?;
    if r.journal.bytes != EXPECTED_JOURNAL {
        return Err("receipt is not the independently frozen new J336".into());
    }
    let proof = receipt::proof(&r)?;
    let constants = receipt::constants()?;
    let policy = Policy {
        image,
        designated_prior: fixture.prior,
    };
    let (mut tx, entries) = body(&policy, &fixture, &constants, &proof)?;
    finalize(&mut tx, &entries)?;
    let actual = context_journal(&tx, &entries)?;
    if actual != EXPECTED_JOURNAL {
        return Err("actual transaction journal oracle differs from frozen J336".into());
    }
    if tx.id() == fixture.prior.transaction_id {
        return Err("diagnostic successor unexpectedly matches its one-shot guard".into());
    }
    let encoded = borsh::to_vec(&tx)?;
    let roundtrip: Transaction = borsh::from_slice(&encoded)?;
    if roundtrip != tx {
        return Err("native Borsh full transaction roundtrip".into());
    }
    let out = Path::new(&args[3]);
    fs::create_dir(out)?;
    save(out, "transaction.native-borsh.bin", &encoded)?;
    save(out, "reconstructed-journal.bin", &actual)?;
    save(out, "proof.compressed.bin", &proof)?;
    save(out, "vk.compressed.bin", &constants.vk)?;
    save(
        out,
        "previous-redeem.bin",
        &script::redeem(&policy, &fixture.old, &constants)?,
    )?;
    save(
        out,
        "successor-redeem.bin",
        &script::redeem(&policy, &fixture.new, &constants)?,
    )?;
    save(out, "payload.bin", &tx.payload)?;
    let mut cases = Vec::new();
    let (positive, mut passed) = execute(&tx, &entries, "valid", "native-full-input-script", None);
    cases.push(positive);
    let labels = [
        "wrong-outpoint",
        "wrong-index",
        "wrong-sequence",
        "wrong-gas",
        "extra-input",
        "extra-output",
        "successor-policy-changed",
        "wrong-prior-state-coherent",
        "wrong-next-state-coherent",
        "wrong-P",
        "wrong-reserve-coherent",
        "wrong-fee",
        "fee-upper-bytes",
        "zero-reserve",
        "reserve-over-max",
        "zero-successor",
        "successor-over-max",
        "zero-fee",
        "fee-negative-zero",
        "fee-over-max",
        "payload-trailing",
        "bad-proof",
    ];
    for label in labels {
        let mut changed = tx.clone();
        let mut context = entries.clone();
        let mut pairing = false;
        match label {
            "wrong-outpoint" => {
                changed.inputs[0].previous_outpoint.transaction_id = Hash::from_bytes([0x44; 32])
            }
            "wrong-index" => changed.inputs[0].previous_outpoint.index ^= 1,
            "wrong-sequence" => changed.inputs[0].sequence = 0,
            "wrong-gas" => changed.gas = 1,
            "extra-input" => {
                let mut i = changed.inputs[0].clone();
                i.previous_outpoint.transaction_id = Hash::from_bytes([0x44; 32]);
                changed.inputs.push(i);
                context.push(entries[0].clone());
            }
            "extra-output" => {
                changed.outputs[0].value -= 1;
                let mut o = changed.outputs[0].clone();
                o.value = 1;
                changed.outputs.push(o);
            }
            "successor-policy-changed" => {
                let mut im = image;
                im[0] ^= 1;
                let p = Policy {
                    image: im,
                    designated_prior: fixture.prior,
                };
                changed.outputs[0].script_public_key =
                    pay_to_script_hash_script(&script::redeem(&p, &fixture.new, &constants)?);
            }
            "wrong-prior-state-coherent" => {
                let mut s = fixture.old;
                s[9] ^= 1;
                let code = script::redeem(&policy, &s, &constants)?;
                context[0].script_public_key = pay_to_script_hash_script(&code);
                changed.inputs[0].signature_script = signature(&proof, &code)?;
                pairing = true;
            }
            "wrong-next-state-coherent" => {
                let mut s = fixture.new;
                s[9] ^= 1;
                changed.payload[1098..1203].copy_from_slice(&s);
                changed.outputs[0].script_public_key =
                    pay_to_script_hash_script(&script::redeem(&policy, &s, &constants)?);
                pairing = true;
            }
            "wrong-P" => {
                changed.payload[1000] ^= 1;
                pairing = true;
            }
            "wrong-reserve-coherent" => {
                context[0].amount -= 1;
                changed.outputs[0].value -= 1;
                pairing = true;
            }
            "wrong-fee" => changed.outputs[0].value += 1,
            "fee-upper-bytes" => changed.payload[94] = 1,
            "zero-reserve" => context[0].amount = 0,
            "reserve-over-max" => context[0].amount = MAX_SOMPI + 1,
            "zero-successor" => changed.outputs[0].value = 0,
            "successor-over-max" => changed.outputs[0].value = MAX_SOMPI + 1,
            "zero-fee" => changed.payload[86..94].copy_from_slice(&0u64.to_le_bytes()),
            "fee-negative-zero" => {
                changed.payload[86..94].copy_from_slice(&(1u64 << 63).to_le_bytes())
            }
            "fee-over-max" => {
                changed.payload[86..94].copy_from_slice(&(MAX_SOMPI + 1).to_le_bytes())
            }
            "payload-trailing" => changed.payload.push(0),
            "bad-proof" => {
                let code = script::redeem(&policy, &fixture.old, &constants)?;
                changed.inputs[0].signature_script =
                    signature(&receipt::negate_proof_a(&proof)?, &code)?;
                pairing = true;
            }
            _ => unreachable!(),
        }
        changed.finalize();
        let expected = if pairing {
            TxScriptError::ZkIntegrity(Groth16Error::VerificationFailed.to_string())
        } else {
            TxScriptError::VerifyError
        };
        let layer = if pairing {
            "native-outer-claim-state-binding"
        } else if label == "payload-trailing" {
            "native-payload-framing"
        } else {
            "native-context-policy-or-amount"
        };
        let (result, ok) = execute(&changed, &context, label, layer, Some(expected));
        passed &= ok;
        cases.push(result);
    }
    let m = metrics(&tx, &entries)?;
    let report = json!({"scope":"NONFUNDABLE_ONE_SHOT_SYNTHETIC_TRANSACTION_CONTEXT_ONLY","all_expectations_met":passed,
        "native_revision":NATIVE_REV,"expected_image":hex::encode(image),"expected_journal_sha256":hex::encode(hash(EXPECTED_JOURNAL)),
        "receipt_sha256":hex::encode(hash(&raw)),"receipt_bytes":raw.len(),"checker_binary_sha256":hex::encode(hash(&fs::read(std::env::current_exe()?)?)),
        "native_proof_bytes":proof.len(),"native_proof_sha256":hex::encode(hash(&proof)),"native_vk_sha256":hex::encode(hash(&constants.vk)),
        "transaction_id":tx.id().to_string(),"transaction_full_hash":tx_hash::hash(&tx).to_string(),
        "designated_synthetic_predecessor":{"raw_txid":fixture.prior.transaction_id.to_string(),"index":fixture.prior.index},
        "successor_does_not_match_designated_predecessor":tx.id()!=fixture.prior.transaction_id,
        "metrics":m,"cases":cases,"chain_acceptance":false,"funding_or_network_used":false,"owner_exit_tested":false,
        "limitations":["Synthetic UTXO context is declared, not genesis, accepted lineage or proof of initial KAS backing.",
            "Immutable suffix pins one synthetic predecessor; successor intentionally cannot continue this policy as a pool.",
            "No DRAIN/owner-exit or durable proving-key availability; NONFUNDABLE even if all native checks pass.",
            "Native Borsh artifact includes cached transaction identity; its size is not P2P/RPC wire size. Consensus mass uses the native estimator.",
            "Exact80M fixture fee is unchanged; lower mass/necessary fee quotes do not reduce the actually authorized/paid fee or qualify a1%privacy target.",
            "Official RISC0 Groth16 setup and single-party inner development setup remain assumptions; passing controls are not cryptographic correctness or production safety."]});
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    fs::File::open(out)?.sync_all()?;
    println!(
        "{}",
        json!({"output":out,"all_expectations_met":passed,"nonfundable":true})
    );
    if !passed {
        return Err("native context expectation failed; report retained".into());
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
    fn runtime_selection_is_atomic() {
        match (SELECTED_IMAGE, SELECTED_JOURNAL_SHA) {
            (None, None) => assert!(selected().is_err()),
            (Some(_), Some(_)) => assert!(selected().is_ok()),
            _ => panic!("partial image/journal selection"),
        }
    }
    #[test]
    fn one_shot_structural_framing() {
        let mut state = [0; 105];
        state[0] = 7;
        let p = Policy {
            image: [0; 32],
            designated_prior: TransactionOutpoint::new(Hash::from_bytes([0x33; 32]), 1),
        };
        let c = receipt::constants().unwrap();
        let code = script::redeem(&p, &state, &c).unwrap();
        assert_eq!(
            &code[script::STATE_START..script::STATE_START + 105],
            &state
        );
        assert_eq!(
            code[script::PREFIX - 1],
            kaspa_txscript::opcodes::codes::OpDrop
        );
        // Structural serializer check only: no fake proof and no VM invocation.
        assert!(code.len() > 424);
        assert_eq!(script::PAYLOAD_LEN, 10 + 1088 + 105);
    }
    #[test]
    fn nonuniform_outpoint_and_high_bit_index_encoding() {
        let raw: [u8; 32] = std::array::from_fn(|i| i as u8);
        let p = TransactionOutpoint::new(Hash::from_bytes(raw), u32::MAX);
        assert_eq!(p.transaction_id.as_bytes(), raw);
        let n = kaspa_txscript::serialize_i64(p.index as i64, Some(8)).unwrap();
        assert_eq!(&n[..4], &u32::MAX.to_le_bytes());
        assert!(kaspa_txscript::serialize_i64(p.index as i64, Some(4)).is_err());
    }
}
