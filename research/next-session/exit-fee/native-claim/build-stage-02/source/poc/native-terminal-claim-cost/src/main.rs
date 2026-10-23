//! ADR0039: official source terminal claim, supplied public synthetic UTXOs only.
//! No SDK/prover/private note/owner workflow or continuing permission root.
mod native;
use kaspa_consensus_core::{
    hashing::{sighash_type::SIG_HASH_ALL, tx as tx_hash},
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
    utxo::{utxo_collection::UtxoCollection, utxo_view::UtxoView},
};
use kaspa_hashes::Hash;
use kaspa_txscript::{pay_to_script_hash_script, script_builder::ScriptBuilder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, time::Instant};
use vprogs_zk_abi::withdrawal::StandardSpk;
use vprogs_zk_backend_risc0_api::{
    PermissionTreeAccumulator as Tree, blake2b_script_hash, build_delegate_entry_script,
    build_permission_redeem_script,
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const CLAIM: u64 = 60_000_000;
const RENT: u64 = 50_000_000;
const FEE_COIN: u64 = 100_000_000;
const COV: [u8; 32] = [0x5a; 32];
const RECIPIENT: [u8; 32] = [0x11; 32];
const PAYER: [u8; 32] = [0x44; 32];
const OTHER: [u8; 32] = [0x22; 32];
const NATIVE: &str = "01b532e8b553523216471682649693af92f0fd16";
const UPSTREAM: &str = "f9b84a863a7c7c20586a9cf947550475e894f72e";
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn public_key(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let key = secp256k1::SecretKey::from_slice(secret)?;
    let pair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &key);
    Ok(pair.x_only_public_key().0.serialize())
}
fn p2pk(secret: &[u8; 32]) -> Result<ScriptPublicKey> {
    let pk = public_key(secret)?;
    Ok(ScriptPublicKey::from_vec(
        0,
        [&[0x20], pk.as_slice(), &[0xac]].concat(),
    ))
}
// Visible adaptation of upstream private permission_sig_script helper155–179.
// The emitter and hash functions themselves are linked directly, never rewritten.
fn witness(redeem: &[u8], spk: &[u8], amount: u64, old_sibling: [u8; 32]) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    let empty = Tree::hash_empty();
    // New walk then old walk, each depth1/index0, as in upstream test helper.
    b.add_data(&empty)?.add_i64(0)?;
    b.add_data(&old_sibling)?.add_i64(0)?;
    b.add_data(spk)?
        .add_data(&amount.to_le_bytes())?
        .add_i64(CLAIM as i64)?
        .add_data(redeem)?;
    Ok(b.drain())
}
fn sign(tx: &mut Transaction, entries: &[UtxoEntry], key: &[u8; 32]) -> Result<()> {
    let signature = kaspa_consensus_core::sign::sign_input(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        2,
        key,
        SIG_HASH_ALL,
    );
    if signature.len() != 66 {
        return Err("unexpected Schnorr signature-script length".into());
    }
    tx.inputs[2].signature_script = signature;
    tx.finalize();
    native::set_mass(tx, entries)
}
fn build(rate: u64, kind: &str) -> Result<(Transaction, Vec<UtxoEntry>, Value)> {
    assert_eq!(Tree::required_depth(1), 1);
    let recipient = p2pk(&RECIPIENT)?;
    let pk = public_key(&RECIPIENT)?;
    let leaf = Tree::hash_leaf(StandardSpk::PubKey(&pk), CLAIM);
    let empty = Tree::hash_empty();
    let root = Tree::hash_branch(&leaf, &empty);
    let mut acc = Tree::new();
    acc.add_exit(StandardSpk::PubKey(&pk), CLAIM);
    let normal = build_permission_redeem_script(&root, 1, 1);
    if normal.len() != 467 || acc.finalize() != blake2b_script_hash(&normal) {
        return Err("normal accumulator/emitter boundary".into());
    }
    let mut current_root = root;
    let mut count = 1;
    if kind == "wrong-current-root" {
        current_root[0] ^= 1;
    }
    if kind == "wrong-leaf-hash-domain" {
        let wrong = Sha256::digest([&[0xff], recipient.script(), &CLAIM.to_le_bytes()].concat());
        current_root = Tree::hash_branch(wrong.as_slice().try_into()?, &empty);
    }
    if kind == "malformed-count" {
        count = 2;
    }
    let redeem = build_permission_redeem_script(&current_root, count, 1);
    let mut old_sibling = empty;
    if kind == "wrong-old-sibling" {
        old_sibling[0] ^= 1;
    }
    let leaf_amount = if kind == "wrong-leaf-amount" {
        CLAIM + 1
    } else {
        CLAIM
    };
    let permission_sig = witness(&redeem, recipient.script(), leaf_amount, old_sibling)?;
    let delegated_id = if kind == "wrong-delegate-spk" {
        [0x6b; 32]
    } else {
        COV
    };
    let delegate_redeem = build_delegate_entry_script(&delegated_id);
    let delegate_sig = ScriptBuilder::new().add_data(&delegate_redeem)?.drain();
    let permission_cov = if kind == "wrong-permission-covenant-id" {
        Hash::from_bytes([0x6b; 32])
    } else {
        Hash::from_bytes(COV)
    };
    let mut entries = vec![
        UtxoEntry::new(
            RENT,
            pay_to_script_hash_script(&redeem),
            0,
            false,
            Some(permission_cov),
        ),
        UtxoEntry::new(
            CLAIM,
            pay_to_script_hash_script(&delegate_redeem),
            0,
            false,
            None,
        ),
    ];
    let mut inputs = vec![
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_bytes([0x31; 32]), 0),
            permission_sig,
            0,
            22,
        ),
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_bytes([0x32; 32]), 1),
            delegate_sig,
            0,
            0,
        ),
    ];
    let sponsored = kind != "zero-fee" && !kind.starts_with("claim-funded-fee-");
    if sponsored {
        inputs.push(TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_bytes([0x33; 32]), 2),
            vec![0; 66],
            0,
            10,
        ));
        entries.push(UtxoEntry::new(FEE_COIN, p2pk(&PAYER)?, 0, false, None));
    }
    let output = TransactionOutput::with_covenant(CLAIM + RENT, recipient.clone(), None);
    let mut outputs = vec![output];
    if sponsored {
        outputs.push(TransactionOutput::new(FEE_COIN - 1, p2pk(&PAYER)?));
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    // Quote the complete shaped signature lengths; no script/Full execution here.
    if sponsored {
        let mut fee = 1u64;
        for _ in 0..32 {
            tx.outputs[1].value = FEE_COIN
                .checked_sub(fee)
                .ok_or("fee exceeds external coin")?;
            native::set_mass(&tx, &entries)?;
            let needed = native::metrics(&tx, &entries)?["mining_mass"]
                .as_u64()
                .ok_or("mass type")?
                .checked_mul(rate)
                .ok_or("fee quote overflow")?;
            if fee >= needed {
                break;
            }
            fee = needed;
        }
        native::set_mass(&tx, &entries)?;
        let required = native::metrics(&tx, &entries)?["mining_mass"]
            .as_u64()
            .ok_or("mass")?
            .checked_mul(rate)
            .ok_or("fee overflow")?;
        if native::amounts(&tx, &entries)?.2 < required {
            return Err("fee fixed point did not converge".into());
        }
    }
    if kind.starts_with("claim-funded-fee-") {
        // Exact shape-specific rate quote. Deduct remains full60M; withholding must fail.
        native::set_mass(&tx, &entries)?;
        let fee = native::metrics(&tx, &entries)?["mining_mass"]
            .as_u64()
            .ok_or("mass")?
            .checked_mul(rate)
            .ok_or("fee")?;
        if fee > CLAIM - 10_000_000 {
            return Err("even hypothetical fee exceeds minimum payout budget".into());
        }
        tx.outputs[0].value = CLAIM + RENT - fee;
    }
    if matches!(kind, "underpay-final-one-sompi" | "rent-diversion") {
        let diversion = if kind == "rent-diversion" {
            10_000_000
        } else {
            1
        };
        tx.outputs[0].value -= diversion;
        tx.outputs[1].value += diversion;
    }
    if kind == "wrong-payout-destination" {
        tx.outputs[0].script_public_key = p2pk(&OTHER)?;
    }
    if kind == "unexpected-continuation" {
        tx.outputs[1].value -= RENT;
        tx.outputs.push(TransactionOutput::with_covenant(
            RENT,
            pay_to_script_hash_script(&normal),
            Some(CovenantBinding::new(0, Hash::from_bytes(COV))),
        ));
    }
    if kind == "duplicate-permission-input" {
        tx.inputs.push(tx.inputs[0].clone());
        entries.push(entries[0].clone());
    }
    tx.finalize();
    native::set_mass(&tx, &entries)?;
    if sponsored {
        sign(
            &mut tx,
            &entries,
            if kind == "wrong-payer-key" {
                &OTHER
            } else {
                &PAYER
            },
        )?;
    }
    if kind == "bad-payer-signature" {
        tx.inputs[2].signature_script[1] ^= 1;
        tx.finalize();
    }
    if kind == "post-sign-overpayment" {
        tx.outputs[0].value += 1;
        tx.finalize();
        native::set_mass(&tx, &entries)?;
    }
    let meta = json!({"claim_principal_sompi":CLAIM,"permission_rent_sompi":RENT,"recognized_delegate_backing_sompi":CLAIM,"external_fee_input_sompi":if sponsored{entries[2].amount}else{0},"external_fee_change_sompi":if sponsored{tx.outputs[1].value}else{0},"payout_sompi":tx.outputs[0].value,"principal_payout_excluding_rent_sompi":tx.outputs[0].value.checked_sub(RENT),"principal_fee_budget_sompi":CLAIM-10_000_000,"self_funded_target_qualified":false,"permission_signature":"none: public claim pays fixed committed SPK","fee_payer_signature":"native SIGHASH_ALL when sponsored","tree_depth":1,"old_unclaimed":count,"selected_transition":"legitimate sourcepositive count1->0 terminal; malformed count is a negative","current_root":hex::encode(current_root),"permission_redeem_hex":hex::encode(&redeem),"delegate_redeem_hex":hex::encode(delegate_redeem),"committed_leaf_spk_hex":hex::encode(recipient.script()),"declared_leaf_amount_sompi":leaf_amount,"old_sibling_hex":hex::encode(old_sibling),"new_sibling_hex":hex::encode(empty),"permission_redeem_sha256":sha(&redeem),"delegate_redeem_sha256":sha(&delegate_redeem),"spk_version":0,"root_origin_authenticated":false,"continuation_qualified":false});
    Ok((tx, entries, meta))
}
fn prepare(out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let mut cases = Vec::new();
    let mut selected: Vec<(String, u64, bool)> = vec![];
    for rate in [100, 200, 500] {
        selected.push((format!("sponsored-positive-{rate}"), rate, true));
        selected.push((format!("claim-funded-fee-{rate}"), rate, false));
    }
    selected.push(("zero-fee".into(), 100, true));
    for label in [
        "wrong-payout-destination",
        "underpay-final-one-sompi",
        "rent-diversion",
        "wrong-current-root",
        "wrong-old-sibling",
        "wrong-leaf-amount",
        "malformed-count",
        "wrong-leaf-hash-domain",
        "wrong-delegate-spk",
        "wrong-permission-covenant-id",
        "unexpected-continuation",
        "bad-payer-signature",
        "wrong-payer-key",
        "post-sign-overpayment",
        "duplicate-permission-input",
    ] {
        selected.push((label.into(), 100, false));
    }
    for (name, rate, accepted) in selected {
        let kind = if name.starts_with("sponsored-positive-") {
            "positive"
        } else {
            &name
        };
        let (tx, entries, accounting) = build(rate, kind)?;
        let dir = out.join(&name);
        fs::create_dir(&dir)?;
        let body = borsh::to_vec(&tx)?;
        let context = borsh::to_vec(&entries)?;
        save(&dir, "transaction.native-borsh.bin", &body)?;
        save(&dir, "utxos.native-borsh.bin", &context)?;
        save(
            &dir,
            "accounting.json",
            &serde_json::to_vec_pretty(&accounting)?,
        )?;
        let expected_scripts: Value = if name == "duplicate-permission-input" {
            Value::Null
        } else if accepted {
            json!(vec![true; tx.inputs.len()])
        } else if matches!(
            name.as_str(),
            "bad-payer-signature" | "wrong-payer-key" | "post-sign-overpayment"
        ) {
            json!([true, true, false])
        } else if name.starts_with("claim-funded-fee-") {
            json!([false, true])
        } else {
            json!([false, null, true])
        };
        let signature_negative = matches!(
            name.as_str(),
            "bad-payer-signature" | "wrong-payer-key" | "post-sign-overpayment"
        );
        let full_error = if accepted {
            Value::Null
        } else if name == "duplicate-permission-input" {
            json!("TxDuplicateInputs")
        } else if signature_negative {
            json!("SignatureInvalid(EvalFalse)")
        } else {
            json!("SignatureInvalid(VerifyError)")
        };
        let script_error_predicate = if accepted || name == "duplicate-permission-input" {
            Value::Null
        } else if signature_negative {
            json!({"input":2,"exact_debug":"EvalFalse"})
        } else {
            json!({"input":0,"exact_debug":"VerifyError"})
        };
        cases.push(json!({"expected_full_error_exact":full_error,"expected_script_error_exact":script_error_predicate,"expected_scripts":expected_scripts,"expected_stage":if name=="duplicate-permission-input"{"Isolation"}else{"Full"},"case":name,"rate_sompi_per_gram":rate,"expected_full_accept":accepted,"body_sha256":sha(&body),"context_sha256":sha(&context),"metrics":native::metrics(&tx,&entries)?,"accounting":accounting,"txid":tx.id().to_string(),"full_hash":tx_hash::hash(&tx).to_string()}));
    }
    let manifest = json!({"schema":"native-terminal-claim-public-preparation-v1","native_rev":NATIVE,"emitter_rev":UPSTREAM,"upstream_native_rev":"9fdbaf1b1886fb5742783d2da73c36239bd6f272","no_sdk_prover":true,"no_script_or_full_validation_during_prepare":true,"public_test_keys":"deterministic DO_NOT_FUND constants in source; not live wallets","permission_budget":22,"delegate_budget":0,"payer_budget":10,"cases":cases});
    save(out, "manifest.json", &serde_json::to_vec_pretty(&manifest)?)?;
    println!("{}", sha(&fs::read(out.join("manifest.json"))?));
    Ok(())
}
fn run(input: &Path, expected: &str, out: &Path) -> Result<()> {
    let bytes = fs::read(input.join("manifest.json"))?;
    if sha(&bytes) != expected {
        return Err("externally selected preparation manifest mismatch".into());
    }
    let manifest: Value = serde_json::from_slice(&bytes)?;
    let mut rows = Vec::new();
    let mut all = true;
    fs::create_dir(out)?;
    for c in manifest["cases"].as_array().ok_or("case array")? {
        let name = c["case"].as_str().ok_or("case")?;
        if name.contains('/') || name.contains("..") {
            return Err("case path".into());
        }
        let dir = input.join(name);
        let b = fs::read(dir.join("transaction.native-borsh.bin"))?;
        let u = fs::read(dir.join("utxos.native-borsh.bin"))?;
        if sha(&b) != c["body_sha256"] || sha(&u) != c["context_sha256"] {
            return Err("prepared artifact hash mismatch".into());
        }
        let tx: Transaction = borsh::from_slice(&b)?;
        let entries: Vec<UtxoEntry> = borsh::from_slice(&u)?;
        if borsh::to_vec(&tx)? != b || borsh::to_vec(&entries)? != u {
            return Err("canonical roundtrip".into());
        }
        let mut rehashed = tx.clone();
        rehashed.finalize();
        if rehashed != tx
            || tx.id().to_string() != c["txid"]
            || tx_hash::hash(&tx).to_string() != c["full_hash"]
        {
            return Err("cached transaction identity".into());
        }
        let start = Instant::now();
        let full = native::full(&tx, &entries);
        let meters = native::meter(&tx, &entries);
        let matched = full["accepted"] == c["expected_full_accept"]
            && full["stage"] == c["expected_stage"]
            && full.get("error").unwrap_or(&Value::Null) == &c["expected_full_error_exact"];
        let script_matched = if c["expected_scripts"].is_null() {
            true
        } else {
            c["expected_scripts"]
                .as_array()
                .ok_or("script expectation")?
                .iter()
                .enumerate()
                .all(|(i, want)| {
                    want.is_null() || meters.get(i).map(|m| &m["accepted"]) == Some(want)
                })
        };
        let error_matched = if c["expected_script_error_exact"].is_null() {
            true
        } else {
            let i = c["expected_script_error_exact"]["input"]
                .as_u64()
                .ok_or("error input")? as usize;
            meters.get(i).map(|m| &m["error"])
                == Some(&c["expected_script_error_exact"]["exact_debug"])
        };
        all &= matched && script_matched && error_matched;
        rows.push(json!({"case":name,"expected_full_accept":c["expected_full_accept"],"matched_expectation":matched,"expected_scripts":c["expected_scripts"],"matched_script_expectations":script_matched,"matched_exact_script_error":error_matched,"expected_full_error_exact":c["expected_full_error_exact"],"expected_script_error_exact":c["expected_script_error_exact"],"full":full,"each_input_script_meter":meters,"metrics":native::metrics(&tx,&entries)?,"seconds":start.elapsed().as_secs_f64()}));
    }
    // Source-adapted one-lookup control, not a ledger/replayer or officialFull spentness check.
    let first = input.join("sponsored-positive-100");
    let tx: Transaction =
        borsh::from_slice(&fs::read(first.join("transaction.native-borsh.bin"))?)?;
    let entries: Vec<UtxoEntry> =
        borsh::from_slice(&fs::read(first.join("utxos.native-borsh.bin"))?)?;
    let mut view: UtxoCollection = tx
        .inputs
        .iter()
        .zip(entries)
        .map(|(i, e)| (i.previous_outpoint, e))
        .collect();
    let before = UtxoView::get(&view, &tx.inputs[0].previous_outpoint).is_some();
    view.remove(&tx.inputs[0].previous_outpoint);
    let after = UtxoView::get(&view, &tx.inputs[0].previous_outpoint).is_none();
    all &= before && after;
    let report = json!({"schema":"native-terminal-claim-cost-results-v1","prepared_manifest_sha256":expected,"all_expected_outcomes":all,"cases":rows,"missing_permission_entry_control":{"source_adapted_context_lookup":true,"present_before":before,"missing_after_removal":after,"official_full_spentness_test":false,"not_a_ledger_replayer":true},"self_funded_60M_target_qualified":false,"root_origin_authenticated":false,"multi_claim_continuation_qualified":false,"relay_or_inclusion":false,"new_proof_or_gpu":false});
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    if !all {
        return Err("unexpected native result; retained report, do not weaken checks".into());
    }
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("prepare") if a.len() == 3 => prepare(Path::new(&a[2])),
        Some("run") if a.len() == 5 => run(Path::new(&a[2]), &a[3], Path::new(&a[4])),
        _ => Err(
            "prepare NEW_PUBLIC_DIR | run FROZEN_PUBLIC_DIR EXPECTED_MANIFEST_SHA NEW_OUTPUT"
                .into(),
        ),
    }
}
