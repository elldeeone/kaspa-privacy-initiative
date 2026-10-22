//! Two independent supplied-context SPEND forks; never a ledger or owner workflow.
#[cfg(feature = "s7-native-policy")]
mod check {
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
    use kaspa_consensus_core::{
        errors::tx::TxRuleError,
        tx::{PopulatedTransaction, Transaction, UtxoEntry},
    };
    use kaspa_txscript::zk_precompiles::groth16::Groth16Error;
    use kaspa_txscript_errors::TxScriptError;
    use kpi_shared_pool::{
        Result, native as base,
        protocol::hash,
        s7_lifecycle::{native as n, profile::Profile},
        two_input::{Bundle, tree::PublicState},
    };
    use serde_json::{Value, json};
    use std::{fs, path::Path};
    fn full(t: &Transaction, e: &[UtxoEntry]) -> Result<u64> {
        let v = base::validator();
        v.validate_tx_in_isolation(t)?;
        Ok(v.validate_populated_transaction_and_get_fee(
            &PopulatedTransaction::new(t, e.to_vec()),
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )?)
    }
    fn negative(
        label: &str,
        mut t: Transaction,
        e: &[UtxoEntry],
        expected: TxScriptError,
    ) -> Result<Value> {
        t.finalize();
        base::set_mass(&t, e)?;
        let v = base::validator();
        v.validate_tx_in_isolation(&t)?;
        let got = v
            .validate_populated_transaction_and_get_fee(
                &PopulatedTransaction::new(&t, e.to_vec()),
                1_000_000_000,
                2_000_000_000_000,
                TxValidationFlags::Full,
                None,
                None,
            )
            .err()
            .ok_or("negative Full accepted")?;
        let script = base::script_units_at(&t, e, 0)
            .err()
            .ok_or("negative reserve accepted")?;
        if got != TxRuleError::SignatureInvalid(expected.clone())
            || script.downcast_ref::<TxScriptError>() != Some(&expected)
        {
            return Err(format!(
                "wrong SPEND rejection layer {label}: {got:?} / {script:?} expected{expected:?}"
            )
            .into());
        }
        Ok(
            json!({"case":label,"official_stage":"Full","typed_Full":format!("{got:?}"),"typed_reserve":format!("{expected:?}")}),
        )
    }
    fn negated_a(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut reader = bytes;
        let mut p = Proof::<Bn254>::deserialize_compressed(&mut reader)?;
        let mut canonical = Vec::new();
        p.serialize_compressed(&mut canonical)?;
        if !reader.is_empty() || canonical != bytes {
            return Err("noncanonical genuine SPEND proof".into());
        }
        p.a = -p.a;
        let mut out = Vec::new();
        p.serialize_compressed(&mut out)?;
        if out.len() != 128 || out == bytes {
            return Err("SPEND proof negation no-op".into());
        }
        Ok(out)
    }
    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 9 {
            return Err("usage: kpi_s7_ordinary_spend_check POLICY PROFILE SELECTED_TUPLE PRIOR_STATE PRIOR_UTXO BUNDLE0 BUNDLE1 NEW_OUTPUT_DIRECTORY".into());
        }
        let bytes: Vec<Vec<u8>> = args[1..8]
            .iter()
            .map(fs::read)
            .collect::<std::io::Result<_>>()?;
        let p: n::Policy = serde_json::from_slice(&bytes[0])?;
        p.validate()?;
        let profile: Profile = serde_json::from_slice(&bytes[1])?;
        profile.validate(&p.inner_vk)?;
        let selected: Value = serde_json::from_slice(&bytes[2])?;
        if profile.domain != p.domain
            || profile.pool_id != p.pool_id
            || selected["domain"] != hex::encode(p.domain)
            || selected["pool_id"] != hex::encode(p.pool_id)
            || selected["inner_vk_sha256"] != hex::encode(hash(&p.inner_vk))
            || selected["pair_image"] != hex::encode(p.pair_image)
        {
            return Err("selected ordinary policy tuple mismatch".into());
        }
        let old: PublicState = serde_json::from_slice(&bytes[3])?;
        let u: base::Utxo = serde_json::from_slice(&bytes[4])?;
        if u.amount != 1_660_000_000 || old.compact()?.cm_count != 5 || old.compact()?.nf_count != 2
        {
            return Err("exact validated prepair initial context required".into());
        }
        let out = Path::new(&args[8]);
        if out.exists() {
            return Err("fresh output directory required".into());
        }
        fs::create_dir_all(out)?;
        let inputs: Vec<_> = args[1..8]
            .iter()
            .zip(&bytes)
            .map(|(path, b)| json!({"path":path,"bytes":b.len(),"sha256":hex::encode(hash(b))}))
            .collect();
        let mut cases = Vec::new();
        for slot in 0..2 {
            let bundle: Bundle = serde_json::from_slice(&bytes[5 + slot])?;
            let auth = bundle.auth()?;
            if auth.mode != 1 || auth.fee != 40_000_000 || auth.payout != 0 || auth.deposit != 0 {
                return Err("fixed ordinary SPEND authorization".into());
            }
            // Both use the original supplied context. They are alternative forks,
            // never combined into a claimed ledger or two spends of one UTXO.
            let (tx, entries, next) = n::ordinary_settle(&p, &old, &u, &bundle, None)?;
            let fee = full(&tx, &entries)?;
            let units = base::script_units_at(&tx, &entries, 0)?;
            if fee != 40_000_000
                || tx.outputs[0].value != 1_620_000_000
                || tx.inputs[0].previous_outpoint != u.outpoint()?
            {
                return Err("SPEND fork context/fee changed".into());
            }
            let metrics = base::metrics(&tx, &entries)?;
            let policy = base::policy(&tx, &entries)?;
            let mass = metrics["mining_mass"].as_u64().ok_or("mining mass")?;
            let quotes:Vec<_>=[100u64,200,500].into_iter().map(|rate|json!({"rate_sompi_per_gram":rate,"required_fee_sompi":(mass*rate).to_string(),"actual_fee_sompi":fee.to_string(),"passes":fee>=mass*rate})).collect();
            if quotes[1]["passes"] != false || quotes[2]["passes"] != false {
                return Err("frozen ordinary200/500 negative changed".into());
            }
            fs::write(
                out.join(format!("fork-{slot}-transaction.json")),
                serde_json::to_vec_pretty(&base::tx_json(&tx))?,
            )?;
            let mut bad = tx.clone();
            bad.payload[11 + 8] ^= 1;
            let domain = negative(
                "wrong_fixed_domain",
                bad,
                &entries,
                TxScriptError::VerifyError,
            )?;
            let mut bad = tx.clone();
            bad.inputs[0].signature_script[2..130]
                .copy_from_slice(&negated_a(&hex::decode(&bundle.proof)?)?);
            let proof = negative(
                "canonical_negated_proof_A",
                bad,
                &entries,
                TxScriptError::ZkIntegrity(Groth16Error::VerificationFailed.to_string()),
            )?;
            let row = json!({"case":format!("independent-SPEND-fork-{slot}"),"same_prior_outpoint":format!("{}:{}",u.txid,u.index),"official_isolation_and_Full":"pass","native_reserve_script_units":units,"budget":n::BUDGET,"metrics":metrics,"native_policy":policy,"fee_quotes":quotes,"next_state_sha256":hex::encode(hash(&n::state_bytes(&next)?)),"controls":[domain,proof]});
            fs::write(
                out.join(format!("fork-{slot}-report.json")),
                serde_json::to_vec_pretty(&row)?,
            )?;
            cases.push(row);
        }
        let report = json!({"scope":"Two alternative ordinary SPEND factory/native checks against one supplied genuine fresh prepair public context; no combined ledger, chain ancestry, replay, owner workflow or DRAIN execution","inputs":inputs,"selected_tuple":selected,"cases":cases,"DRAIN":"UNEXECUTED"});
        fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
        println!("{}", serde_json::to_string(&report)?);
        Ok(())
    }
}
#[cfg(feature = "s7-native-policy")]
fn main() {
    if let Err(e) = check::run() {
        eprintln!("S7 ordinary supplied SPEND checker: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(feature = "s7-native-policy"))]
fn main() {
    eprintln!("requires --features s7-native-policy");
    std::process::exit(2);
}
