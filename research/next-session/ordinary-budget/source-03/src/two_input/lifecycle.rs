//! Bounded offline lifecycle experiment utilities. Synthetic ancestry is explicit.
//! This is not a network client, wallet service, or funded-trial runner.
use super::{replay, reserve_spk, tree::PublicState, wallet};
use crate::{
    Result, native,
    protocol::{GENESIS_HEX, H, MAX_SOMPI, Wallet, hash, random},
};
use kaspa_consensus_core::tx::TransactionOutput;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn read<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn write(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(bytes)?;
    Ok(())
}
fn save(p: &Path, value: &impl Serialize) -> Result<()> {
    write(p, &serde_json::to_vec_pretty(value)?)
}
fn dir(p: &Path) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn synthetic_parent(spk: &str, amount: u64) -> Result<Value> {
    if amount == 0 || amount > MAX_SOMPI - 100_000_000 {
        return Err("synthetic funding amount range".into());
    }
    let key = Wallet::fresh().payout_key(&random(), 0);
    let input = native::Utxo {
        txid: hex::encode(random()),
        index: 0,
        amount: amount.checked_add(100_000_000).ok_or("source overflow")?,
        spk: hex::encode(native::encode_spk(&native::p2pk(&key)?)),
        daa: 0,
        is_coinbase: false,
    };
    let (tx, entries) = native::ordinary(
        &input,
        &key,
        vec![TransactionOutput::new(amount, native::decode_spk(spk)?)],
    )?;
    let fee = native::validate(&tx, &entries)?;
    Ok(json!({
        "scope":"synthetic source UTXO; no chain acceptance or funded transaction",
        "chain_acceptance_verified":false,
        "native_validation_passed":true,
        "transaction":native::tx_json(&tx),
        "input":input,
        "ordinary_fee_sompi":fee.to_string(),
    }))
}
fn founder(vk_path: &Path, pin_path: &Path, out: &Path) -> Result<Value> {
    founder_amount(vk_path, pin_path, out, 2_000_000_000)
}
fn founder_amount(vk_path: &Path, pin_path: &Path, out: &Path, amount: u64) -> Result<Value> {
    if amount < super::NOTE_FLOOR + super::FEE || amount > MAX_SOMPI - 200_000_000 {
        return Err("founder amount range".into());
    }
    let vk = fs::read(vk_path)?;
    let pin: wallet::ParameterPin = read(pin_path)?;
    let domain: H = hash(&[b"KPI/v6/offline-own-key-lifecycle\0".as_slice(), &random()].concat());
    let keys = Wallet::fresh();
    let note = keys.receive(&domain).note(amount)?;
    let state = PublicState::initial(note.commitment(&domain))?;
    let funding_key = keys.funding_key(&domain, 0);
    let parent = synthetic_parent(
        &hex::encode(native::encode_spk(&native::p2pk(&funding_key)?)),
        amount + 100_000_000,
    )?;
    let parent_tx = native::parse_tx(&parent["transaction"])?;
    let input = native::Utxo::output(&parent_tx, 0, 0);
    let (tx, entries) = native::ordinary(
        &input,
        &funding_key,
        vec![TransactionOutput::new(
            amount,
            reserve_spk(&domain, &state, &vk)?,
        )],
    )?;
    native::validate(&tx, &entries)?;
    let descriptor = replay::Descriptor {
        format: replay::DESCRIPTOR_FORMAT.into(),
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        domain,
        initial_commitment: note.commitment(&domain),
        initial_value_sompi: amount.to_string(),
        vk_sha256: hex::encode(hash(&vk)),
        funding_txid: tx.id().to_string(),
        funding_full_hash: kaspa_consensus_core::hashing::tx::hash(&tx).to_string(),
    };
    let backup = wallet::Backup::new(keys, &descriptor, &vk, pin, Some(note))?;
    dir(out)?;
    let public = out.join("public");
    dir(&public)?;
    save(&public.join("descriptor.json"), &descriptor)?;
    write(&public.join("vk.bin"), &vk)?;
    save(&public.join("lineage.json"), &vec![native::tx_json(&tx)])?;
    save(
        &public.join("parents.json"),
        &vec![parent["transaction"].clone()],
    )?;
    save(&out.join("synthetic-parent.json"), &parent)?;
    backup.save_new(&out.join("backup.json"))?;
    save(&out.join("receive.json"), &backup.receive(&descriptor)?)?;
    let summary = checkpoint(&public)?;
    save(&public.join("head.json"), &summary["head"])?;
    Ok(summary)
}
fn checkpoint(public: &Path) -> Result<Value> {
    let descriptor: replay::Descriptor = read(&public.join("descriptor.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    let lineage: Vec<Value> = read(&public.join("lineage.json"))?;
    let parents: Vec<Value> = read(&public.join("parents.json"))?;
    let checked = replay::replay(&descriptor, &vk, &lineage, &parents)?;
    let head = wallet::Head {
        transaction_count: checked.records.len(),
        last_full_hash: checked
            .records
            .last()
            .ok_or("empty lineage")?
            .full_hash
            .clone(),
    };
    Ok(json!({"head":head,"replay":checked.summary()?}))
}
fn context(public: &Path) -> Result<wallet::Context> {
    wallet::Context::new(
        read(&public.join("descriptor.json"))?,
        fs::read(public.join("vk.bin"))?,
        &read::<Vec<Value>>(&public.join("lineage.json"))?,
        &read::<Vec<Value>>(&public.join("parents.json"))?,
        read(&public.join("head.json"))?,
    )
}
fn prepare_check(backup_path: &Path, public: &Path, action_path: &Path) -> Result<Value> {
    let backup: wallet::Backup = read(backup_path)?;
    let context = context(public)?;
    context.prepare(&backup, &read(action_path)?)?;
    Ok(json!({
        "scope":"local request and circuit satisfaction only; no generated proof",
        "request_prepared":true, "chain_acceptance_verified":false,
    }))
}
fn bad_delivery(
    backup_path: &Path,
    public: &Path,
    recipient_path: &Path,
    pk_path: &Path,
    pin_path: &Path,
) -> Result<Value> {
    // This adversarial research helper deliberately reads the malicious sender's
    // own keys. It receives no recipient backup or plaintext recipient note.
    let backup_value: Value = read(backup_path)?;
    let backup: wallet::Backup = serde_json::from_value(backup_value.clone())?;
    let keys: Wallet = serde_json::from_value(backup_value["wallet"].clone())?;
    let context = context(public)?;
    let descriptor = context.descriptor();
    backup.receive(descriptor)?;
    let recipient: wallet::PublicReceive = read(recipient_path)?;
    if recipient.descriptor_sha256 != wallet::descriptor_hash(descriptor)? {
        return Err("research recipient pool mismatch".into());
    }
    let replay = context.replay();
    let bootstrap = native::parse_tx(
        &replay
            .records
            .get(1)
            .ok_or("missing bootstrap")?
            .transaction,
    )?;
    let prior_bundle = super::replay::bundle(&bootstrap)?;
    let old_note = keys.decrypt(
        &descriptor.domain,
        &hex::decode(&prior_bundle.ciphertexts[0])?,
        &prior_bundle.auth()?.outputs[0],
    )?;
    if old_note.value != 1_960_000_000 {
        return Err("malicious fork expected founder bootstrap note".into());
    }
    let input = super::harness::selected(&keys, &old_note, 1, &replay.state)?;
    let outputs = [
        recipient.receive.note(1_920_000_000)?,
        super::harness::output(&keys, &descriptor.domain, 0)?,
    ];
    let (mut circuit, mut bundle) = super::harness::authorize(
        descriptor.domain,
        &replay.state,
        vec![input],
        outputs,
        1,
        0,
        [0; 36],
        None,
    )?;
    let mut invalid_opening = circuit.outputs[0].clone();
    invalid_opening.rho[0] ^= 1;
    bundle.ciphertexts[0] = hex::encode(invalid_opening.encrypt(&descriptor.domain)?);
    circuit.auth.cipher_hash = hash(&bundle.ciphers()?);
    bundle.authorization = hex::encode(circuit.auth.bytes());
    let (constraints, satisfied) = circuit.check()?;
    if !satisfied {
        return Err("malformed-delivery fork relation unexpectedly unsatisfied".into());
    }
    let pin: wallet::ParameterPin = read(pin_path)?;
    if backup.parameters() != &pin {
        return Err("malicious fork parameter pin mismatch".into());
    }
    let vk = fs::read(public.join("vk.bin"))?;
    let prover = wallet::Prover::load(pk_path, &pin, &vk)?;
    let bundle = prover.prove_circuit(circuit, bundle)?;
    let (tx, entries, _) = super::settle(
        &descriptor.domain,
        &replay.state,
        replay.reserve.as_ref().ok_or("pool drained")?,
        &vk,
        &bundle,
        None,
    )?;
    if native::validate(&tx, &entries)? != super::FEE {
        return Err("malicious fork native fee mismatch".into());
    }
    Ok(json!({
        "scope":"separate genuine-proof malformed-delivery fork; no accepted-chain claim",
        "chain_acceptance_verified":false,
        "native_validation_passed":true, "proof_count":1,
        "ciphertext_opens_to_wrong_commitment":true,
        "constraints":constraints,
        "transaction":native::tx_json(&tx),
        "bundle":bundle,
    }))
}
fn payout_spend(
    backup_path: &Path,
    descriptor_path: &Path,
    payout_path: &Path,
    index: u32,
) -> Result<Value> {
    let backup: wallet::Backup = read(backup_path)?;
    let descriptor: replay::Descriptor = read(descriptor_path)?;
    let payout: Value = read(payout_path)?;
    let tx = native::parse_tx(&payout)?;
    let key = backup.exit_key(&descriptor, index)?;
    let spk = native::p2pk(&key)?;
    let (position, output) = tx
        .outputs
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_public_key == spk)
        .ok_or("payout not controlled by restored key")?;
    let input = native::Utxo::output(&tx, position, 0);
    let destination =
        native::p2pk(&backup.exit_key(&descriptor, index.checked_add(1).ok_or("key index")?)?)?;
    let (spend, entries) = native::ordinary(
        &input,
        &key,
        vec![TransactionOutput::new(output.value / 2, destination)],
    )?;
    let fee = native::validate(&spend, &entries)?;
    Ok(json!({
        "scope":"ordinary spend signed with restored native key; synthetic UTXO context",
        "chain_acceptance_verified":false,
        "native_validation_passed":true,
        "input":input,
        "transaction":native::tx_json(&spend),
        "fee_sompi":fee.to_string(),
    }))
}

/// Experiment-only transparent exit-to-funding transfer. The exact input is an
/// actual prior payout, not a synthetic replacement. Cross-user destinations are
/// supported: a public spend edge does not establish common ownership. The
/// caller must additionally enforce global once-only native outpoint use.
fn bridge_transaction(
    payout: &kaspa_consensus_core::tx::Transaction,
    key: &H,
    output_index: usize,
    funding_spk: &str,
    amount: u64,
) -> Result<Value> {
    let output = payout
        .outputs
        .get(output_index)
        .ok_or("payout output index")?;
    if output.script_public_key != native::p2pk(key)? {
        return Err("exact payout not controlled by restored exit key".into());
    }
    let bytes = hex::decode(funding_spk)?;
    if bytes.len() != 36 || bytes[..3] != [0, 0, 0x20] || bytes[35] != 0xac {
        return Err("bridge destination must be canonical P2PK".into());
    }
    if amount < super::NOTE_FLOOR + super::FEE || amount > MAX_SOMPI {
        return Err("bridge funding amount range".into());
    }
    let input = native::Utxo::output(payout, output_index, 0);
    let (tx, entries) = native::ordinary(
        &input,
        key,
        vec![TransactionOutput::new(
            amount,
            native::decode_spk(funding_spk)?,
        )],
    )?;
    let fee = native::validate(&tx, &entries)?;
    if tx.outputs.len() != 2
        || tx.outputs[0].value != amount
        || tx.outputs[1]
            .value
            .checked_add(amount)
            .and_then(|v| v.checked_add(fee))
            != Some(input.amount)
    {
        return Err("bridge accounting mismatch".into());
    }
    Ok(json!({
        "scope":"signed ordinary exit-to-funding transfer; no chain acceptance",
        "chain_acceptance_verified":false,"native_validation_passed":true,
        "input":input,"transaction":native::tx_json(&tx),
        "fee_sompi":fee.to_string(),"change_sompi":tx.outputs[1].value.to_string(),
    }))
}
fn payout_to_funding(
    backup_path: &Path,
    descriptor_path: &Path,
    payout_path: &Path,
    key_index: u32,
    output_index: usize,
    funding_spk: &str,
    amount: u64,
) -> Result<Value> {
    let backup: wallet::Backup = read(backup_path)?;
    let descriptor: replay::Descriptor = read(descriptor_path)?;
    let payout: Value = read(payout_path)?;
    bridge_transaction(
        &native::parse_tx(&payout)?,
        &backup.exit_key(&descriptor, key_index)?,
        output_index,
        funding_spk,
        amount,
    )
}
fn canonical_amount(value: &str) -> Result<u64> {
    let amount: u64 = value.parse()?;
    if amount.to_string() != value || amount > MAX_SOMPI {
        return Err("canonical integer sompi required".into());
    }
    Ok(amount)
}
fn check_native(transaction: &Path, inputs: &Path) -> Result<Value> {
    let tx = native::parse_tx(&read::<Value>(transaction)?)?;
    let inputs: Vec<native::Utxo> = read(inputs)?;
    if inputs.len() != tx.inputs.len() {
        return Err("native input count".into());
    }
    for (utxo, input) in inputs.iter().zip(&tx.inputs) {
        if utxo.outpoint()? != input.previous_outpoint {
            return Err("native input outpoint".into());
        }
    }
    let entries = inputs
        .iter()
        .map(native::Utxo::entry)
        .collect::<Result<Vec<_>>>()?;
    let fee = native::validate(&tx, &entries)?;
    Ok(
        json!({"native_validation_passed":true,"chain_acceptance_verified":false,
        "fee_sompi":fee.to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(&tx).to_string()}),
    )
}
pub fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let arg = |i: usize| {
        a.get(i)
            .map(String::as_str)
            .ok_or("missing lifecycle argument")
    };
    let result = match a.get(1).map(String::as_str) {
        Some("founder") if a.len() == 5 => founder(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?))?,
        Some("founder-amount") if a.len() == 6 => founder_amount(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?), canonical_amount(arg(5)?)?)?,
        Some("fund") if a.len() == 3 => synthetic_parent(arg(2)?, 1_200_000_000)?,
        Some("fund-amount") if a.len() == 4 => synthetic_parent(arg(2)?, canonical_amount(arg(3)?)?)?,
        Some("checkpoint") if a.len() == 3 => checkpoint(Path::new(arg(2)?))?,
        Some("payout-spend") if a.len() == 6 => payout_spend(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?), arg(5)?.parse()?)?,
        Some("payout-to-funding") if a.len() == 9 => payout_to_funding(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?), arg(5)?.parse()?, arg(6)?.parse()?, arg(7)?, canonical_amount(arg(8)?)?)?,
        Some("check-native") if a.len() == 4 => check_native(Path::new(arg(2)?), Path::new(arg(3)?))?,
        Some("prepare-check") if a.len() == 5 => prepare_check(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?))?,
        Some("bad-delivery") if a.len() == 7 => bad_delivery(Path::new(arg(2)?), Path::new(arg(3)?), Path::new(arg(4)?), Path::new(arg(5)?), Path::new(arg(6)?))?,
        _ => return Err("founder VK PIN_JSON NEWDIR | founder-amount VK PIN_JSON NEWDIR SOMPI | fund PUBLIC_SPK_HEX | fund-amount PUBLIC_SPK_HEX SOMPI | checkpoint PUBLIC_DIR | payout-spend BACKUP DESCRIPTOR PAYOUT_TX KEY_INDEX | payout-to-funding BACKUP DESCRIPTOR PAYOUT_TX KEY_INDEX OUTPUT_INDEX FUNDING_SPK SOMPI | check-native TX_JSON INPUT_UTXOS_JSON | prepare-check BACKUP PUBLIC ACTION | bad-delivery SENDER_BACKUP PUBLIC RECIPIENT PK PIN".into()),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
mod native_usage_tests {
    use super::*;

    #[test]
    fn canonical_amount_and_funding_bounds() -> Result<()> {
        assert_eq!(canonical_amount("0")?, 0);
        assert_eq!(canonical_amount(&MAX_SOMPI.to_string())?, MAX_SOMPI);
        for value in ["01", "+1", "-1", "1.0", " 1", "18446744073709551616"] {
            assert!(canonical_amount(value).is_err());
        }
        assert!(canonical_amount(&(MAX_SOMPI + 1).to_string()).is_err());
        let spk = hex::encode(native::encode_spk(&native::p2pk(&[7; 32])?));
        assert!(synthetic_parent(&spk, 0).is_err());
        assert!(synthetic_parent(&spk, MAX_SOMPI - 100_000_000 + 1).is_err());
        let missing = Path::new("/nonexistent-kpi-native-usage-test");
        assert!(
            founder_amount(
                missing,
                missing,
                missing,
                super::super::NOTE_FLOOR + super::super::FEE - 1
            )
            .is_err()
        );
        assert!(founder_amount(missing, missing, missing, MAX_SOMPI - 200_000_000 + 1).is_err());
        Ok(())
    }

    #[test]
    fn exact_payout_bridge_validates_and_rejects_wrong_context() -> Result<()> {
        let key = [7; 32];
        let spk = hex::encode(native::encode_spk(&native::p2pk(&key)?));
        // Ordinary public development transaction, not a new pool proof or a
        // held-out wallet. The bridge checks the exact output and native key.
        let parent = synthetic_parent(&spk, 2_000_000_000)?;
        let tx = native::parse_tx(&parent["transaction"])?;
        let destination = hex::encode(native::encode_spk(&native::p2pk(&[9; 32])?));
        for amount in [super::super::NOTE_FLOOR + super::super::FEE, 1_900_000_000] {
            let result = bridge_transaction(&tx, &key, 0, &destination, amount)?;
            assert_eq!(result["native_validation_passed"], true);
            assert_eq!(result["input"]["txid"], tx.id().to_string());
            assert_eq!(result["input"]["index"], 0);
            let bridge = native::parse_tx(&result["transaction"])?;
            assert_eq!(bridge.outputs[0].value, amount);
            assert_eq!(
                bridge.outputs[0].script_public_key,
                native::decode_spk(&destination)?
            );
            let fee: u64 = result["fee_sompi"].as_str().unwrap().parse()?;
            assert_eq!(amount + bridge.outputs[1].value + fee, tx.outputs[0].value);
            assert!(bridge.outputs[1].value > 0);
        }
        assert!(bridge_transaction(&tx, &[8; 32], 0, &destination, 1_000_000_000).is_err());
        assert!(bridge_transaction(&tx, &key, 2, &destination, 1_000_000_000).is_err());
        assert!(
            bridge_transaction(
                &tx,
                &key,
                0,
                &destination,
                super::super::NOTE_FLOOR + super::super::FEE - 1
            )
            .is_err()
        );
        assert!(bridge_transaction(&tx, &key, 0, &destination, 2_000_000_000).is_err());
        assert!(bridge_transaction(&tx, &key, 0, "0000", 1_000_000_000).is_err());
        Ok(())
    }
}
