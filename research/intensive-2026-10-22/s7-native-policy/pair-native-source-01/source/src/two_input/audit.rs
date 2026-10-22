//! Additional offline controls over already generated transaction bodies.
//! Amount sweeps measure mass only: altered amounts invalidate their proofs.
use super::*;
use crate::compact::experiment::{read, save};
use serde_json::{Value, json};
use std::path::Path;

fn entries(tx: &Transaction) -> Result<Vec<UtxoEntry>> {
    let a = Authorization::parse(&tx.payload[P_AUTH..P_CIPHER])?;
    let amount = tx
        .outputs
        .iter()
        .try_fold(a.fee, |v, o| {
            v.checked_add(o.value).ok_or("audit amount overflow")
        })?
        .checked_sub(a.deposit)
        .ok_or("audit backing underflow")?;
    let redeem = tx.inputs[0]
        .signature_script
        .get(133..)
        .ok_or("missing redeem")?;
    let mut e = vec![UtxoEntry::new(
        amount,
        pay_to_script_hash_script(redeem),
        0,
        false,
        None,
    )];
    if a.mode == 0 {
        e.push(UtxoEntry::new(
            a.deposit,
            native::decode_spk(&hex::encode(a.funding_spk))?,
            0,
            false,
            None,
        ));
    }
    Ok(e)
}

pub(super) fn run(input: &Path, output: &Path) -> Result<()> {
    let r: Value = read(input)?;
    let txs = r["rows"]
        .as_array()
        .ok_or("missing transactions")?
        .iter()
        .map(|v| native::parse_tx(&v["tx"]))
        .collect::<Result<Vec<_>>>()?;
    let mut controls = Vec::new();
    for tx in txs.iter().filter(|tx| tx.inputs.len() == 2) {
        let e = entries(tx)?;
        native::validate(tx, &e)?;
        for name in [
            "invalid-funding-signature",
            "non-ALL-funding-signature",
            "actual-funding-outpoint",
            "actual-funding-value",
            "actual-funding-script",
            "missing-funding-input",
            "reordered-native-inputs",
        ] {
            let mut bad = tx.clone();
            let mut be = e.clone();
            match name {
                "invalid-funding-signature" => bad.inputs[1].signature_script[1] ^= 1,
                "non-ALL-funding-signature" => bad.inputs[1].signature_script[65] = 2,
                "actual-funding-outpoint" => bad.inputs[1].previous_outpoint.index ^= 1,
                "actual-funding-value" => be[1].amount += 1,
                "actual-funding-script" => be[1].script_public_key = native::p2pk(&[8; 32])?,
                "missing-funding-input" => {
                    // Preserve native balance so the reserve script itself must
                    // reject the missing input, before any Schnorr check matters.
                    bad.outputs[0].value = bad.outputs[0]
                        .value
                        .checked_sub(be[1].amount)
                        .ok_or("missing-input control balance")?;
                    bad.inputs.pop();
                    be.pop();
                }
                _ => {
                    bad.inputs.swap(0, 1);
                    be.swap(0, 1);
                }
            }
            bad.finalize();
            native::set_mass(&bad, &be)?;
            // Test the affected script, independently of signatures on other inputs.
            let index = match name {
                "invalid-funding-signature" | "reordered-native-inputs" => 1,
                _ => 0,
            };
            if native::script_units_at(&bad, &be, index).is_ok() {
                return Err(format!("accepted admission mutation {name}").into());
            }
            controls.push(name);
        }
    }
    let continuing = txs
        .iter()
        .find(|tx| tx.payload[P_AUTH + A_MODE] == 2 && tx.outputs.len() == 2)
        .ok_or("no continuing exit")?;
    let terminal = txs
        .iter()
        .find(|tx| tx.payload[P_AUTH + A_MODE] == 2 && tx.outputs.len() == 1)
        .ok_or("no terminal exit")?;
    let mut masses = Vec::new();
    let amounts = [
        PAYOUT_FLOOR,
        NOTE_FLOOR - FEE,
        NOTE_FLOOR,
        100_000_000,
        1_000_000_000,
        MAX_SOMPI / 4,
    ];
    for remainder in [
        0,
        NOTE_FLOOR,
        NOTE_FLOOR + 1,
        100_000_000,
        1_000_000_000,
        MAX_SOMPI / 2,
    ] {
        for payout in amounts {
            let mut tx = if remainder == 0 {
                terminal.clone()
            } else {
                continuing.clone()
            };
            let mut e = entries(&tx)?;
            e[0].amount = remainder + payout + FEE;
            if remainder > 0 {
                tx.outputs[0].value = remainder;
            }
            tx.outputs.last_mut().ok_or("no payout")?.value = payout;
            tx.finalize();
            native::set_mass(&tx, &e)?;
            let m = native::policy(&tx, &e)?;
            if m["mining_mass"].as_u64().ok_or("mass")? * 100 > FEE {
                return Err("fee envelope exceeded".into());
            }
            masses.push(
                json!({"reserve_remaining_sompi":remainder,"payout_sompi":payout,"metrics":m}),
            );
        }
    }
    save(
        output,
        &json!({
            "offline_only":true,
            "synthetic_utxo_entries_reconstructed_from_known_fixture":true,
            "valid_admissions_rechecked":txs.iter().filter(|tx|tx.inputs.len()==2).count(),
            "admission_mutations_rejected":controls,
            "mass_only_amount_sweeps_not_valid_proofs":true,
            "fee_rate_sompi_per_mass":100,
            "mass_cases":masses
        }),
    )
}
