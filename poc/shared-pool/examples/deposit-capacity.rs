//! Supplementary native boundary fixture, not a 32,000-deposit history.
//! Retains a genuine old anchor/proof inside a constructed large public state.
use kpi_shared_pool::{
    Result,
    compact::{
        self,
        deposits::{self, harness},
    },
    native,
};
use serde_json::json;
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    let root = PathBuf::from(std::env::args().nth(1).ok_or("private fixture root")?);
    let public = root.join("public");
    let (d, vk) = harness::context(&public)?;
    let history = harness::replay(&public, &d, &vk)?;
    let saved: harness::Saved =
        serde_json::from_slice(&fs::read(root.join("prover-0/saved.json"))?)?;
    let wallet: harness::Private = serde_json::from_slice(&fs::read(root.join("wallet1.json"))?)?;
    let deposit_tx = &history.transactions[2];
    let bundle = compact::Bundle {
        authorization: hex::encode(&deposit_tx.payload[compact::P_AUTH..compact::P_CIPHER]),
        proof: hex::encode(&deposit_tx.inputs[0].signature_script[2..130]),
        ciphertexts: [
            hex::encode(&deposit_tx.payload[compact::P_CIPHER..compact::P_CIPHER + 185]),
            hex::encode(&deposit_tx.payload[compact::P_CIPHER + 185..compact::P_STATE]),
        ],
    };
    let mut state = history.state;
    state.commitments.resize(65533, [17; 32]);
    state.roots.resize(32767, [18; 32]);
    *state.roots.last_mut().unwrap() = state.cm_tree()?.root();
    let mut reserve = history.reserve.unwrap();
    reserve.amount = 10_000_000_000_000;
    reserve.spk = hex::encode(native::encode_spk(&deposits::reserve_spk(
        &d.identity.domain,
        &state,
        &vk,
    )?));
    let mut funding = d.sources[1].clone();
    funding.txid = hex::encode([19; 32]);
    let (mut last, entries) = deposits::settle(
        &d.identity.domain,
        &state,
        &reserve,
        &vk,
        &bundle,
        Some(&funding),
    )?;
    native::sign(&mut last, &entries, 1, &wallet.funding_key)?;
    native::validate(&last, &entries)?;
    native::policy(&last, &entries)?;
    state = deposits::admission(&state, &bundle.auth()?)?.0;
    assert_eq!(state.compact()?.cm_count, 65535);
    reserve = native::Utxo::output(&last, 0, 0);
    assert!(
        deposits::settle(
            &d.identity.domain,
            &state,
            &reserve,
            &vk,
            &bundle,
            Some(&funding)
        )
        .is_err()
    );
    // Bypass the builder's capacity refusal and require the native script to
    // refuse a further append too. No alternate private proof is generated.
    let mut excess = last.clone();
    excess.inputs[0].previous_outpoint = reserve.outpoint()?;
    excess.inputs[0].signature_script = deposits::covenant::signature(
        &hex::decode(&bundle.proof)?,
        &deposits::covenant::redeem(&d.identity.domain, &state.compact()?, &vk)?,
    )?;
    let entries = vec![reserve.entry()?, funding.entry()?];
    native::sign(&mut excess, &entries, 1, &wallet.funding_key)?;
    native::set_mass(&excess, &entries)?;
    assert!(native::script_units_at(&excess, &entries, 0).is_err());
    assert!(native::validate(&excess, &entries).is_err());
    let (exit, entries) = deposits::settle(
        &d.identity.domain,
        &state,
        &reserve,
        &vk,
        &saved.bundles[0],
        None,
    )?;
    native::validate(&exit, &entries)?;
    native::policy(&exit, &entries)?;
    println!(
        "{}",
        json!({"native_last_admission":true,"commitments":65535,
        "additional_admission_rejected":true,"old_saved_exit_native_valid":true,
        "scope":"Constructed capacity state with genuine proofs; not an accepted full-capacity history or complete drain"})
    );
    Ok(())
}
