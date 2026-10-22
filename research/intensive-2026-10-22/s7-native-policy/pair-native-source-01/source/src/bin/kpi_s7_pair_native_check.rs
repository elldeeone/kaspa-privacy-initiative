//! Supplied-public-input native qualification only; no ledger replay or owner flow.
#[cfg(feature = "s7-native-policy")]
mod check {
    use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
    use kaspa_consensus_core::tx::{
        ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry,
    };
    use kaspa_hashes::Hash;
    use kpi_shared_pool::{
        Result, native as base,
        protocol::hash,
        s7_lifecycle::{native as n, profile::Profile},
        two_input::tree::PublicState,
    };
    use serde_json::{Value, json};
    use std::{fs, path::Path};
    fn read<T: serde::de::DeserializeOwned>(p: &str) -> Result<T> {
        Ok(serde_json::from_slice(&fs::read(p)?)?)
    }
    fn official(tx: &Transaction, e: &[UtxoEntry]) -> Result<u64> {
        let v = base::validator();
        v.validate_tx_in_isolation(tx)
            .map_err(|x| format!("official isolation: {x:?}"))?;
        Ok(v.validate_populated_transaction_and_get_fee(
            &PopulatedTransaction::new(tx, e.to_vec()),
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )
        .map_err(|x| format!("official Full: {x:?}"))?)
    }
    fn refresh(tx: &mut Transaction, e: &[UtxoEntry]) -> Result<()> {
        tx.finalize();
        base::set_mass(tx, e)
    }
    fn rejection(label: &str, mut tx: Transaction, e: Vec<UtxoEntry>) -> Result<Value> {
        refresh(&mut tx, &e)?;
        let full = official(&tx, &e)
            .err()
            .ok_or_else(|| format!("control unexpectedly accepted: {label}"))?;
        let script = base::script_units_at(&tx, &e, 0)
            .err()
            .ok_or_else(|| format!("reserve script unexpectedly accepted: {label}"))?;
        Ok(
            json!({"case":label,"official_rejection":full.to_string(),"reserve_script_rejection":script.to_string()}),
        )
    }
    pub fn run() -> Result<()> {
        let a: Vec<_> = std::env::args().collect();
        if a.len() != 10 {
            return Err("usage: kpi_s7_pair_native_check POLICY PROFILE SELECTED_PAIR_IDENTITY PRIOR_STATE PRIOR_UTXO P1088 NEXT105 PROOF128 OUTPUT_DIRECTORY".into());
        }
        let policy: n::Policy = read(&a[1])?;
        policy.validate()?;
        let profile: Profile = read(&a[2])?;
        profile.validate(&policy.inner_vk)?;
        let selected: Value = read(&a[3])?;
        if profile.domain != policy.domain
            || profile.pool_id != policy.pool_id
            || selected["domain"] != hex::encode(policy.domain)
            || selected["pool_id"] != hex::encode(policy.pool_id)
            || selected["inner_vk_sha256"] != hex::encode(hash(&policy.inner_vk))
            || selected["pair_image"] != hex::encode(policy.pair_image)
        {
            return Err("selected compiled guest/profile/policy tuple mismatch".into());
        }
        let old: PublicState = read(&a[4])?;
        let u: base::Utxo = read(&a[5])?;
        let p = fs::read(&a[6])?;
        let next: [u8; 105] = fs::read(&a[7])?.try_into().map_err(|_| "next105")?;
        let proof = fs::read(&a[8])?;
        if u.amount != 1_660_000_000
            || p.len() != 1088
            || p[12..44] != policy.domain
            || p[8..40] == policy.domain
            || u128::from_le_bytes(p[76..92].try_into()?) != 80_000_000
        {
            return Err("selected initial pair fixed context/fee or exact P-domain offset".into());
        }
        let out = Path::new(&a[9]);
        if out.exists() {
            return Err("fresh output directory required".into());
        }
        fs::create_dir_all(out)?;
        // Host factory failures are separate from actual official Full controls.
        let mut host_controls = Vec::new();
        let mut wrong_p = p.clone();
        wrong_p[12] ^= 1;
        let err = n::paired_settle(&policy, &old, &u, &wrong_p, &next, &proof)
            .err()
            .ok_or("wrong-domain factory accepted")?;
        host_controls.push(
            json!({"case":"P_domain_at_relative12","host_factory_rejection":err.to_string()}),
        );
        let mut wrong_p = p.clone();
        wrong_p[0] ^= 1;
        let err = n::paired_settle(&policy, &old, &u, &wrong_p, &next, &proof)
            .err()
            .ok_or("wrong P-header factory accepted")?;
        host_controls.push(json!({"case":"P_header","host_factory_rejection":err.to_string()}));
        let mut wrong_next = next;
        wrong_next[0] = 6;
        let err = n::paired_settle(&policy, &old, &u, &p, &wrong_next, &proof)
            .err()
            .ok_or("S6 factory accepted")?;
        host_controls.push(json!({"case":"S6_next","host_factory_rejection":err.to_string()}));
        let (tx, entries) = n::paired_settle(&policy, &old, &u, &p, &next, &proof)?;
        let fee = official(&tx, &entries)?;
        if fee != 80_000_000
            || tx.outputs[0].value != 1_580_000_000
            || tx.inputs[0].compute_commit.compute_budget() != Some(n::BUDGET.into())
        {
            return Err("fixed pair fee/reserve/budget changed".into());
        }
        let units = base::script_units_at(&tx, &entries, 0)?;
        let metrics = base::metrics(&tx, &entries)?;
        let standard = base::policy(&tx, &entries)?;
        let mining = metrics["mining_mass"].as_u64().ok_or("mining mass")?;
        let quotes:[Value;3]=[100u64,200,500].map(|rate|json!({"rate_sompi_per_gram":rate,"required_fee_sompi":(mining*rate).to_string(),"actual_fee_sompi":fee.to_string(),"passes":fee>=mining*rate}));
        if quotes[2]["passes"] != false {
            return Err("frozen rate500 negative unexpectedly passes".into());
        }
        let mut controls = Vec::new();
        for (label, index) in [
            ("envelope_magic", 0),
            ("selector", 10),
            ("P_header", n::PAIRED_P),
            ("P_domain_relative12", n::PAIRED_P + 12),
        ] {
            let mut t = tx.clone();
            t.payload[index] ^= 1;
            controls.push(rejection(label, t, entries.clone())?);
        }
        let mut t = tx.clone();
        t.inputs[0].signature_script[2] ^= 1;
        controls.push(rejection("genuine_proof_byte", t, entries.clone())?);
        let mut t = tx.clone();
        t.inputs[0].previous_outpoint.transaction_id = Hash::from_bytes([9; 32]);
        if t.inputs[0].previous_outpoint == tx.inputs[0].previous_outpoint {
            return Err("outpoint control unchanged".into());
        }
        controls.push(rejection(
            "actual_prior_txid_with_genuine_proof",
            t,
            entries.clone(),
        )?);
        let mut t = tx.clone();
        t.inputs[0].previous_outpoint.index = t.inputs[0]
            .previous_outpoint
            .index
            .checked_add(1)
            .ok_or("index control overflow")?;
        controls.push(rejection(
            "actual_prior_index_with_genuine_proof",
            t,
            entries.clone(),
        )?);
        let mut t = tx.clone();
        let mut e = entries.clone();
        e[0].amount += 1;
        t.outputs[0].value += 1;
        controls.push(rejection(
            "actual_R_and_Rprime_plus1_fee80M_unchanged",
            t,
            e,
        )?);
        let mut t = tx.clone();
        let mut changed = next;
        changed[9] ^= 1;
        t.payload[n::PAIRED_NEXT..].copy_from_slice(&changed);
        t.outputs[0].script_public_key =
            kaspa_txscript::pay_to_script_hash_script(&n::redeem(&policy, &changed)?);
        controls.push(rejection(
            "next_root_with_matching_successor_and_genuine_proof",
            t,
            entries.clone(),
        )?);
        let mut t = tx.clone();
        let spk = t.outputs[0].script_public_key.clone();
        let mut script = spk.script().to_vec();
        script[2] ^= 1;
        t.outputs[0].script_public_key = ScriptPublicKey::from_vec(spk.version(), script);
        controls.push(rejection(
            "different_successor_policy_hash",
            t,
            entries.clone(),
        )?);
        let mut t = tx.clone();
        t.inputs[0].compute_commit = ComputeCommit::ComputeBudget(1u16.into());
        let low = rejection("typed_budget1", t, entries.clone())?;
        if !low["reserve_script_rejection"]
            .as_str()
            .ok_or("underbudget string")?
            .to_lowercase()
            .contains("budget")
            && !low["reserve_script_rejection"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("limit")
        {
            return Err(format!("unexpected underbudget failure layer: {low}").into());
        }
        controls.push(low);
        let input_files: Vec<_> = a[1..9]
            .iter()
            .map(|s| Ok(json!({"path":s,"sha256":hex::encode(hash(&fs::read(s)?))})))
            .collect::<Result<_>>()?;
        fs::write(
            out.join("transaction.json"),
            serde_json::to_vec_pretty(&base::tx_json(&tx))?,
        )?;
        let report = json!({"scope":"Supplied genuine public fresh S7 pair; synthetic declared UTXO context, no accepted ancestry or owner/replay workflow","selected_tuple":selected,"inputs":input_files,"transaction_id":tx.id().to_string(),"unpadded_redeem_bytes":n::emitted_length(&policy,&n::state_bytes(&old)?)?,"redeem_bytes":n::REDEEM_LEN,"script_sig_bytes":n::WITNESS_LEN,"official_isolation_and_Full":"pass","native_reserve_script_units":units,"declared_budget":n::BUDGET,"fee_sompi":fee.to_string(),"metrics":metrics,"native_policy":standard,"mining_fee_quotes":quotes,"host_factory_controls":host_controls,"official_Full_and_reserve_script_controls":controls});
        fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
        println!("{}", serde_json::to_string(&report)?);
        Ok(())
    }
}
#[cfg(feature = "s7-native-policy")]
fn main() {
    if let Err(e) = check::run() {
        eprintln!("S7 supplied pair native checker: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(feature = "s7-native-policy"))]
fn main() {
    eprintln!("requires --features s7-native-policy");
    std::process::exit(2);
}
