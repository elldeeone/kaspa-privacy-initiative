//! Supplied-public-input native qualification only; no ledger replay or owner flow.
#[cfg(feature = "s7-native-policy")]
mod check {
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
    use kaspa_consensus_core::errors::tx::TxRuleError;
    use kaspa_consensus_core::tx::{
        ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry,
    };
    use kaspa_hashes::Hash;
    use kaspa_txscript::zk_precompiles::groth16::Groth16Error;
    use kaspa_txscript_errors::TxScriptError;
    use kpi_shared_pool::{
        Result, native as base,
        protocol::hash,
        s7_lifecycle::{native as n, profile::Profile},
        two_input::tree::PublicState,
    };
    use serde_json::{Value, json};
    use std::{fs, path::Path};
    fn official(tx: &Transaction, e: &[UtxoEntry]) -> Result<u64> {
        let v = base::validator();
        v.validate_tx_in_isolation(tx)?;
        Ok(v.validate_populated_transaction_and_get_fee(
            &PopulatedTransaction::new(tx, e.to_vec()),
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )?)
    }
    fn refresh(tx: &mut Transaction, e: &[UtxoEntry]) -> Result<()> {
        tx.finalize();
        base::set_mass(tx, e)
    }
    fn rejection(label: &str, mut tx: Transaction, e: Vec<UtxoEntry>) -> Result<Value> {
        refresh(&mut tx, &e)?;
        let v = base::validator();
        v.validate_tx_in_isolation(&tx)?; // Every advertised negative must reach Full.
        let full = v
            .validate_populated_transaction_and_get_fee(
                &PopulatedTransaction::new(&tx, e.clone()),
                1_000_000_000,
                2_000_000_000_000,
                TxValidationFlags::Full,
                None,
                None,
            )
            .err()
            .ok_or_else(|| format!("control unexpectedly accepted: {label}"))?;
        let error = base::script_units_at(&tx, &e, 0)
            .err()
            .ok_or_else(|| format!("reserve script unexpectedly accepted: {label}"))?;
        let script = error
            .downcast_ref::<TxScriptError>()
            .ok_or("reserve error lost its native type")?;
        let expected = match label {
            "actual_prior_txid_with_genuine_proof"
            | "actual_prior_index_with_genuine_proof"
            | "reversed_actual_prior_txid_with_genuine_proof"
            | "actual_R_and_Rprime_plus1_fee80M_unchanged"
            | "next_root_with_matching_successor_and_genuine_proof"
            | "canonical_negated_proof_A" => {
                TxScriptError::ZkIntegrity(Groth16Error::VerificationFailed.to_string())
            }
            "typed_budget1" => {
                let limit = tx.inputs[0].compute_commit.allowed_script_units().0;
                match script {
                    TxScriptError::ExceededCommittedScriptUnits {
                        used,
                        limit: actual,
                    } if *actual == limit && *used > limit => script.clone(),
                    TxScriptError::ZkIntegrity(inner) => {
                        let text=inner.strip_prefix("Kaspa txscript error: script units exceeded the amount committed in the input: used=").ok_or("wrong native underbudget envelope")?;
                        let (used, actual) =
                            text.split_once(", limit=").ok_or("native meter framing")?;
                        let used: u64 = used.parse()?;
                        let actual: u64 = actual.parse()?;
                        let expected = TxScriptError::ExceededCommittedScriptUnits {
                            used,
                            limit: actual,
                        };
                        if actual != limit
                            || used <= limit
                            || *inner != format!("Kaspa txscript error: {expected}")
                        {
                            return Err("native underbudget limit/used/cause mismatch".into());
                        }
                        TxScriptError::ZkIntegrity(format!("Kaspa txscript error: {expected}"))
                    }
                    _ => {
                        return Err(
                            format!("wrong typed native underbudget layer: {script:?}").into()
                        );
                    }
                }
            }
            _ => TxScriptError::VerifyError,
        };
        if *script != expected || full != TxRuleError::SignatureInvalid(expected.clone()) {
            return Err(format!("wrong rejection layer for {label}: Full={full:?}, reserve={script:?}, expected={expected:?}").into());
        }
        Ok(
            json!({"case":label,"official_stage":"Full","typed_official_rejection":format!("{full:?}"),"typed_reserve_rejection":format!("{script:?}"),"expected_typed_cause":format!("{expected:?}")}),
        )
    }
    fn negate_a(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut reader = bytes;
        let mut p = Proof::<Bn254>::deserialize_compressed(&mut reader)?;
        let mut canonical = Vec::new();
        p.serialize_compressed(&mut canonical)?;
        if !reader.is_empty() || canonical != bytes {
            return Err("proof128 canonical encoding".into());
        }
        p.a = -p.a;
        let mut changed = Vec::new();
        p.serialize_compressed(&mut changed)?;
        if changed.len() != 128 || changed == bytes {
            return Err("proof A negation changed no point".into());
        }
        Ok(changed)
    }
    pub fn run() -> Result<()> {
        let a: Vec<_> = std::env::args().collect();
        if a.len() != 10 {
            return Err("usage: kpi_s7_pair_native_check POLICY PROFILE SELECTED_PAIR_IDENTITY PRIOR_STATE PRIOR_UTXO P1088 NEXT105 PROOF128 OUTPUT_DIRECTORY".into());
        }
        let input_bytes: Vec<Vec<u8>> = a[1..9]
            .iter()
            .map(fs::read)
            .collect::<std::io::Result<_>>()?;
        let policy: n::Policy = serde_json::from_slice(&input_bytes[0])?;
        policy.validate()?;
        let profile: Profile = serde_json::from_slice(&input_bytes[1])?;
        profile.validate(&policy.inner_vk)?;
        let selected: Value = serde_json::from_slice(&input_bytes[2])?;
        if profile.domain != policy.domain
            || profile.pool_id != policy.pool_id
            || selected["domain"] != hex::encode(policy.domain)
            || selected["pool_id"] != hex::encode(policy.pool_id)
            || selected["inner_vk_sha256"] != hex::encode(hash(&policy.inner_vk))
            || selected["pair_image"] != hex::encode(policy.pair_image)
        {
            return Err("selected compiled guest/profile/policy tuple mismatch".into());
        }
        let old: PublicState = serde_json::from_slice(&input_bytes[3])?;
        let u: base::Utxo = serde_json::from_slice(&input_bytes[4])?;
        let p = input_bytes[5].clone();
        let next: [u8; 105] = input_bytes[6].clone().try_into().map_err(|_| "next105")?;
        let proof = input_bytes[7].clone();
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
        let input_files:Vec<_>=a[1..9].iter().zip(&input_bytes).map(|(path,bytes)|json!({"path":path,"bytes":bytes.len(),"sha256":hex::encode(hash(bytes))})).collect();
        fs::write(
            out.join("transaction.json"),
            serde_json::to_vec_pretty(&base::tx_json(&tx))?,
        )?;
        fs::write(
            out.join("positive.json"),
            serde_json::to_vec_pretty(
                &json!({"scope":"Supplied-public-input local pair positive only; controls not complete","selected_tuple":selected,"inputs":input_files,"official_isolation_and_Full":"pass","native_reserve_script_units":units,"metrics":metrics,"native_policy":standard,"mining_fee_quotes":quotes,"fee_sompi":fee.to_string()}),
            )?,
        )?;
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
        t.inputs[0].signature_script[2..130].copy_from_slice(&negate_a(&proof)?);
        controls.push(rejection("canonical_negated_proof_A", t, entries.clone())?);
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
        let mut reversed = [0u8; 32];
        reversed.copy_from_slice(
            tx.inputs[0]
                .previous_outpoint
                .transaction_id
                .as_bytes()
                .as_ref(),
        );
        reversed.reverse();
        t.inputs[0].previous_outpoint.transaction_id = Hash::from_bytes(reversed);
        if t.inputs[0].previous_outpoint == tx.inputs[0].previous_outpoint {
            return Err("selected actual txid is palindromic; byte-order control unchanged".into());
        }
        controls.push(rejection(
            "reversed_actual_prior_txid_with_genuine_proof",
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
        controls.push(low);
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
