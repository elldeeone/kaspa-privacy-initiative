//! Prospective operational-budget qualification. Historical policy is immutable.
//! Supplied public contexts only; no owner, ledger replay, DRAIN workflow or prover.
#[cfg(feature = "s7-native-policy")]
mod qualification {
    use ark_bn254::Bn254;
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
    use kaspa_consensus_core::{
        errors::tx::TxRuleError,
        hashing::{
            sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
            sighash_type::SIG_HASH_ALL,
            tx as tx_hash,
        },
        tx::{ComputeCommit, PopulatedTransaction, Transaction, UtxoEntry},
    };
    use kaspa_txscript::zk_precompiles::groth16::Groth16Error;
    use kaspa_txscript_errors::TxScriptError;
    use kpi_shared_pool::{
        Result,
        compact::tree::{NfLeaf, less},
        native,
        protocol::{H, Wallet, hash},
        s7_lifecycle::{
            native as policy,
            profile::{self, Profile},
        },
        two_input::{
            Authorization, Bundle, NF_WIT, W_NF,
            tree::{PublicState, Tree, cm_leaf},
        },
    };
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        collections::{HashMap, HashSet},
        fs,
        path::Path,
    };
    const HISTORICAL: u16 = 1700;
    const CANDIDATE: u16 = 1600;
    const SOURCE_BOUND: u64 = 15_857_502;
    const AUTH: usize = 11;
    const CIPHER: usize = 388;
    const NEXT: usize = 758;
    const WITNESS: usize = 863;
    const LIMBS: [(usize, usize); 5] = [(0, 7), (7, 14), (14, 21), (21, 28), (28, 32)];
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Retained {
        bundle: Bundle,
        transaction: Value,
        utxos: Vec<native::Utxo>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Paired {
        projection: String,
        next_state: String,
        proof: String,
        transaction: Value,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        policy: policy::Policy,
        profile: Profile,
        selected_tuple: Value,
        initial_state: PublicState,
        prior_state: PublicState,
        prior_utxo: native::Utxo,
        bootstrap: Retained,
        admit: Retained,
        spends: [Retained; 2],
        paired: Paired,
        provenance: Value,
    }
    fn official(tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
        let v = native::validator();
        v.validate_tx_in_isolation(tx)?;
        Ok(v.validate_populated_transaction_and_get_fee(
            &PopulatedTransaction::new(tx, entries.to_vec()),
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )?)
    }
    fn refresh(tx: &mut Transaction, entries: &[UtxoEntry]) -> Result<()> {
        tx.finalize();
        native::set_mass(tx, entries)
    }
    fn sighashes(tx: &Transaction, e: &[UtxoEntry]) -> Vec<String> {
        let p = PopulatedTransaction::new(tx, e.to_vec());
        (0..e.len())
            .map(|i| {
                calc_schnorr_signature_hash(&p, i, SIG_HASH_ALL, &SigHashReusedValuesUnsync::new())
                    .to_string()
            })
            .collect()
    }
    fn units(tx: &Transaction, e: &[UtxoEntry]) -> Result<Vec<u64>> {
        (0..e.len())
            .map(|i| native::script_units_at(tx, e, i))
            .collect()
    }
    fn negated_a(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut reader = bytes;
        let mut p = Proof::<Bn254>::deserialize_compressed(&mut reader)?;
        let mut canonical = Vec::new();
        p.serialize_compressed(&mut canonical)?;
        if !reader.is_empty() || canonical != bytes {
            return Err("noncanonical original proof128".into());
        }
        p.a = -p.a;
        let mut out = Vec::new();
        p.serialize_compressed(&mut out)?;
        if out.len() != 128 || out == bytes {
            return Err("proof-A negation did not change a canonical point".into());
        }
        Ok(out)
    }
    fn resource_cause(script: &TxScriptError, limit: u64) -> Result<TxScriptError> {
        match script {
            TxScriptError::ExceededCommittedScriptUnits {
                used,
                limit: actual,
            } if *actual == limit && *used > limit => Ok(script.clone()),
            TxScriptError::ZkIntegrity(inner) => {
                let s=inner.strip_prefix("Kaspa txscript error: script units exceeded the amount committed in the input: used=").ok_or("wrong resource envelope")?;
                let (used, actual) = s.split_once(", limit=").ok_or("resource envelope fields")?;
                let used: u64 = used.parse()?;
                let actual: u64 = actual.parse()?;
                let cause = TxScriptError::ExceededCommittedScriptUnits {
                    used,
                    limit: actual,
                };
                if actual != limit
                    || used <= limit
                    || *inner != format!("Kaspa txscript error: {cause}")
                {
                    return Err("resource cause/limit mismatch".into());
                }
                Ok(TxScriptError::ZkIntegrity(format!(
                    "Kaspa txscript error: {cause}"
                )))
            }
            _ => Err(format!("wrong typed resource cause: {script:?}").into()),
        }
    }
    fn rejected(
        label: &str,
        mut tx: Transaction,
        e: &[UtxoEntry],
        expected: Option<TxScriptError>,
    ) -> Result<Value> {
        refresh(&mut tx, e)?;
        let v = native::validator();
        v.validate_tx_in_isolation(&tx)?;
        let full = v
            .validate_populated_transaction_and_get_fee(
                &PopulatedTransaction::new(&tx, e.to_vec()),
                1_000_000_000,
                2_000_000_000_000,
                TxValidationFlags::Full,
                None,
                None,
            )
            .err()
            .ok_or_else(|| format!("{label}: Full accepted negative"))?;
        let error = native::script_units_at(&tx, e, 0)
            .err()
            .ok_or_else(|| format!("{label}: reserve accepted negative"))?;
        let script = error
            .downcast_ref::<TxScriptError>()
            .ok_or("lost native reserve error type")?;
        let expected = match expected {
            Some(x) => x,
            None => resource_cause(script, tx.inputs[0].compute_commit.allowed_script_units().0)?,
        };
        if *script != expected || full != TxRuleError::SignatureInvalid(expected.clone()) {
            return Err(format!("{label}: incorrect rejection stage: Full{full:?}, reserve{script:?}, expected{expected:?}").into());
        }
        Ok(
            json!({"case":label,"official_stage":"Full","typed_Full":format!("{full:?}"),"typed_reserve":format!("{script:?}")}),
        )
    }
    fn typed_budget(tx: &Transaction) -> Result<u16> {
        match tx
            .inputs
            .first()
            .ok_or("missing reserve input")?
            .compute_commit
        {
            ComputeCommit::ComputeBudget(b) => Ok(b.into()),
            _ => Err("reserve is not version1 ComputeBudget".into()),
        }
    }
    fn quotes(mass: u64, fee: u64) -> Vec<Value> {
        [100u64,200,500].into_iter().map(|rate|json!({"rate_sompi_per_gram":rate,"required_fee_sompi":(mass*rate).to_string(),"actual_fee_sompi":fee.to_string(),"passes":fee>=mass*rate})).collect()
    }
    fn candidate_case(
        name: &str,
        original: &Transaction,
        e: &[UtxoEntry],
        out: &Path,
        semantic_controls: bool,
    ) -> Result<Value> {
        if typed_budget(original)? != HISTORICAL {
            return Err("historical factory no longer emits1700".into());
        }
        let old = native::parse_tx(&native::tx_json(original))?;
        let fee = official(&old, e)?;
        if fee != 40_000_000 {
            return Err("ordinary authorized40M changed".into());
        }
        let old_units = units(&old, e)?;
        let old_metrics = native::metrics(&old, e)?;
        native::policy(&old, e)?;
        let old_hash = tx_hash::hash(&old);
        let old_sighashes = sighashes(&old, e);
        let mut candidate = old.clone();
        candidate.inputs[0].compute_commit = ComputeCommit::ComputeBudget(CANDIDATE.into());
        refresh(&mut candidate, e)?;
        let candidate = native::parse_tx(&native::tx_json(&candidate))?;
        let mut restored = native::tx_json(&candidate);
        restored["inputs"][0]["computeBudget"] = json!(HISTORICAL);
        let mut recalculated = candidate.clone();
        recalculated.finalize();
        if restored != native::tx_json(&old)
            || candidate.id() != old.id()
            || recalculated.id() != old.id()
            || candidate.storage_mass() != old.storage_mass()
            || sighashes(&candidate, e) != old_sighashes
            || tx_hash::hash(&candidate) == old_hash
        {
            return Err(format!(
                "{name}: nonbudget field/ID/storage/SIG_HASH_ALL/fullhash invariant"
            )
            .into());
        }
        if official(&candidate, e)? != fee {
            return Err("candidate Full changed fee".into());
        }
        let used = units(&candidate, e)?;
        let allowed = candidate.inputs[0].compute_commit.allowed_script_units().0;
        if used != old_units || allowed != 16_009_999 || used[0] > SOURCE_BOUND {
            return Err(format!("{name}: candidate units/source bound contradicted").into());
        }
        let metrics = native::metrics(&candidate, e)?;
        let screen = native::policy(&candidate, e)?;
        let old_compute = old_metrics["compute_mass"]
            .as_u64()
            .ok_or("compute metric")?;
        let compute = metrics["compute_mass"].as_u64().ok_or("compute metric")?;
        if old_compute.checked_sub(compute) != Some(10_000)
            || metrics["estimated_bytes"] != old_metrics["estimated_bytes"]
            || metrics["storage_mass"] != old_metrics["storage_mass"]
            || metrics["transient_mass"] != old_metrics["transient_mass"]
        {
            return Err("budget-only mass delta is not exact10000 or context changed".into());
        }
        let mass = metrics["mining_mass"].as_u64().ok_or("mining metric")?;
        let oldmass = old_metrics["mining_mass"].as_u64().ok_or("mining metric")?;
        let quote = quotes(mass, fee);
        let oldquote = quotes(oldmass, fee);
        if quote[0]["passes"] != true
            || quote[1]["passes"] != true
            || quote[2]["passes"] != false
            || oldquote[1]["passes"] != false
        {
            return Err("frozen fee200 hypothesis or500 negative contradicted".into());
        }
        fs::write(
            out.join(format!("{name}-historical1700.json")),
            serde_json::to_vec_pretty(&native::tx_json(&old))?,
        )?;
        fs::write(
            out.join(format!("{name}-candidate1600.json")),
            serde_json::to_vec_pretty(&native::tx_json(&candidate))?,
        )?;
        let mut controls = Vec::new();
        if semantic_controls {
            let mut wrong = candidate.clone();
            let proof = negated_a(&candidate.inputs[0].signature_script[2..130])?;
            wrong.inputs[0].signature_script[2..130].copy_from_slice(&proof);
            controls.push(rejected(
                "canonical_negated_A",
                wrong,
                e,
                Some(TxScriptError::ZkIntegrity(
                    Groth16Error::VerificationFailed.to_string(),
                )),
            )?);
            let minimum: u16 = (used[0] / 10_000).try_into()?;
            let low = minimum.checked_sub(1).ok_or("no lower meter control")?;
            if u64::from(low) * 10_000 + 9999 >= used[0]
                || u64::from(minimum) * 10_000 + 9999 < used[0]
            {
                return Err("below-minimum budget arithmetic".into());
            }
            let mut wrong = candidate.clone();
            wrong.inputs[0].compute_commit = ComputeCommit::ComputeBudget(low.into());
            controls.push(rejected("below_measured_minimum_budget", wrong, e, None)?);
            if e.len() == 1 {
                let mut wrong = candidate.clone();
                wrong.payload[AUTH + 8] ^= 1;
                controls.push(rejected(
                    "wrong_fixed_domain",
                    wrong,
                    e,
                    Some(TxScriptError::VerifyError),
                )?);
                let mut wrong = candidate.clone();
                wrong.payload[CIPHER] ^= 1;
                controls.push(rejected(
                    "cipher_byte_stale_cipher_hash",
                    wrong,
                    e,
                    Some(TxScriptError::VerifyError),
                )?);
                let mut wrong = candidate.clone();
                wrong.outputs[0].value -= 1;
                controls.push(rejected(
                    "reserve_output_minus1_fixed_authorized_fee",
                    wrong,
                    e,
                    Some(TxScriptError::VerifyError),
                )?);
            }
        }
        let row = json!({"name":name,"historical_budget":HISTORICAL,"candidate_budget":CANDIDATE,"official_Full_at_both_budgets":true,"unchanged_all_other_fields":true,"id":candidate.id().to_string(),"SIG_HASH_ALL":old_sighashes,"storage_mass_unchanged":true,"historical_fullhash":old_hash.to_string(),"candidate_fullhash":tx_hash::hash(&candidate).to_string(),"all_input_units":used,"source_bound_reserve_units":SOURCE_BOUND,"allowance1600":allowed,"reserve_margin":allowed-used[0],"historical_metrics":old_metrics,"candidate_metrics":metrics,"source_adapted_mass_standardness_relay_screen":screen,"historical_fee_quotes":oldquote,"candidate_fee_quotes":quote,"typed_negative_controls":controls,"ADMIT_payload_or_output_guard_mutations":"excluded from this matrix to retain exact genuine funding signature; proof and meter controls still isolate reserve", "candidate_transaction":native::tx_json(&candidate)});
        fs::write(
            out.join(format!("{name}-report.json")),
            serde_json::to_vec_pretty(&row)?,
        )?;
        Ok(row)
    }
    fn reconstruct(
        p: &policy::Policy,
        old: &PublicState,
        r: &Retained,
    ) -> Result<(Transaction, Vec<UtxoEntry>, PublicState)> {
        let retained = native::parse_tx(&r.transaction)?;
        let (mut tx, e, next) = policy::ordinary_settle(
            p,
            old,
            r.utxos.first().ok_or("reserve UTXO missing")?,
            &r.bundle,
            r.utxos.get(1),
        )?;
        if r.utxos.len() == 2 {
            tx.inputs[1].signature_script = retained.inputs[1].signature_script.clone();
            refresh(&mut tx, &e)?;
        }
        let declared = r
            .utxos
            .iter()
            .map(native::Utxo::entry)
            .collect::<Result<Vec<_>>>()?;
        if native::tx_json(&tx) != r.transaction || e != declared {
            return Err("factory reconstruction differs from genuine retained body/context".into());
        }
        Ok((tx, e, next))
    }
    fn actual(input: &Input, out: &Path) -> Result<Value> {
        if serde_json::to_value(&input.initial_state)?
            != serde_json::to_value(PublicState::initial(input.profile.initial_commitment)?)?
        {
            return Err("initial state differs from selected profile".into());
        }
        let (boot, be, after_boot) =
            reconstruct(&input.policy, &input.initial_state, &input.bootstrap)?;
        let (admit, ae, after_admit) = reconstruct(&input.policy, &after_boot, &input.admit)?;
        if serde_json::to_value(&input.admit.utxos[0])?
            != serde_json::to_value(native::Utxo::output(&boot, 0, 0))?
            || serde_json::to_value(&input.prior_utxo)?
                != serde_json::to_value(native::Utxo::output(&admit, 0, 0))?
            || serde_json::to_value(&after_admit)? != serde_json::to_value(&input.prior_state)?
        {
            return Err(
                "supplied full prefix output0 linkage/state changed (explicit DAA0 convention)"
                    .into(),
            );
        }
        let mut cases = vec![
            candidate_case("bootstrap", &boot, &be, out, true)?,
            candidate_case("admit", &admit, &ae, out, true)?,
        ];
        for (i, r) in input.spends.iter().enumerate() {
            if r.utxos.len() != 1
                || serde_json::to_value(&r.utxos[0])? != serde_json::to_value(&input.prior_utxo)?
            {
                return Err("SPEND cases are not independent same-context forks".into());
            }
            let (tx, e, _) = reconstruct(&input.policy, &input.prior_state, r)?;
            cases.push(candidate_case(
                &format!("spend-fork-{i}"),
                &tx,
                &e,
                out,
                true,
            )?);
        }
        let p = hex::decode(&input.paired.projection)?;
        let next: [u8; 105] = hex::decode(&input.paired.next_state)?
            .try_into()
            .map_err(|_| "pair state105")?;
        let proof = hex::decode(&input.paired.proof)?;
        let (pair, pe) = policy::paired_settle(
            &input.policy,
            &input.prior_state,
            &input.prior_utxo,
            &p,
            &next,
            &proof,
        )?;
        if native::tx_json(&pair) != input.paired.transaction
            || typed_budget(&pair)? != HISTORICAL
            || official(&pair, &pe)? != 80_000_000
        {
            return Err("paired1700 regression changed".into());
        }
        let pu = units(&pair, &pe)?;
        let pm = native::policy(&pair, &pe)?;
        let pq = quotes(
            pm["mining_mass"].as_u64().ok_or("pair mining mass")?,
            80_000_000,
        );
        if pu[0] != 15_653_862 || pm["compute_mass"] != 196_484 || pq[2]["passes"] != false {
            return Err("paired1700 measured regression differs".into());
        }
        fs::write(
            out.join("paired1700-unchanged.json"),
            serde_json::to_vec_pretty(&native::tx_json(&pair))?,
        )?;
        let mut excessive = boot.clone();
        excessive.inputs[0].compute_commit = ComputeCommit::ComputeBudget(u16::MAX.into());
        refresh(&mut excessive, &be)?;
        official(&excessive, &be)?;
        native::script_units_at(&excessive, &be, 0)?;
        let mass = native::policy(&excessive, &be)
            .err()
            .ok_or("excessive budget passed native mass screen")?;
        if mass.to_string() != "native block mass limit" {
            return Err("excessive budget reached wrong policy gate".into());
        }
        Ok(
            json!({"phase":"actual-genuine-prefix","ordinary_case_count":4,"paired_regression":{"budget":1700,"body_unchanged":true,"Full":true,"all_input_units":pu,"metrics":pm,"quotes":pq},"ordinary":cases,"typed_negative_count":negative_count,"excessive_budget_control":{"budget":65535,"official_Full":true,"reserve_VM":true,"rejected_by":"separate source-adapted native mass cap","error":mass.to_string()},"DRAIN":"source-bound only, no fresh execution","factory_default_changed":false,"owner_replay_implemented":false,"accepted_ancestry_verified":false}),
        )
    }

    fn shifted(mut h: H, delta: i8) -> Result<H> {
        let mut carry = i16::from(delta);
        for b in &mut h {
            let sum = i16::from(*b) + carry;
            *b = sum.rem_euclid(256) as u8;
            carry = sum.div_euclid(256);
        }
        if carry != 0 || h == [0; 32] {
            return Err("public neighbor overflow/zero".into());
        }
        Ok(h)
    }

    fn limb_neighbor(mut h: H, limb: usize, direction: i8) -> Result<H> {
        let (lo, hi) = LIMBS[limb];
        let position = (lo..hi)
            .find(|&i| if direction < 0 { h[i] > 0 } else { h[i] < 255 })
            .ok_or("selected public limb has no simple neighbor")?;
        h[position] = (i16::from(h[position]) + i16::from(direction)) as u8;
        Ok(h)
    }

    fn neighboring_values(a: &Authorization, shape: &str) -> Result<Vec<H>> {
        let (low, high) = if less(&a.nfs[0], &a.nfs[1]) {
            (a.nfs[0], a.nfs[1])
        } else {
            (a.nfs[1], a.nfs[0])
        };
        match shape {
            "sentinel_first" => Ok(vec![shifted(high, 1)?, shifted(high, 2)?]),
            "tail_end" => Ok(vec![shifted(low, -2)?, shifted(low, -1)?]),
            "middle_bracket" => a
                .nfs
                .iter()
                .flat_map(|h| [shifted(*h, -1), shifted(*h, 1)])
                .collect(),
            "mixed_all_limbs" => {
                let mut values = Vec::new();
                for nf in a.nfs {
                    for direction in [-1i8, 1] {
                        let mut neighbor = nf;
                        for limb in 0..4 {
                            // Lower limbs deliberately disagree in the opposite
                            // direction; the highest unequal limb must decide.
                            let (lo, hi) = LIMBS[limb];
                            neighbor[lo..hi].fill(if direction < 0 { 255 } else { 0 });
                        }
                        neighbor = limb_neighbor(neighbor, 4, direction)?;
                        values.push(neighbor);
                    }
                }
                Ok(values)
            }
            name if name.starts_with("limb_") => {
                let limb = name[5..].parse::<usize>()?;
                if limb >= LIMBS.len() {
                    return Err("limb index".into());
                }
                a.nfs
                    .iter()
                    .flat_map(|h| [limb_neighbor(*h, limb, -1), limb_neighbor(*h, limb, 1)])
                    .collect()
            }
            "index_127_128" | "index_32767_32768" | "near_capacity" => {
                neighboring_values(a, "middle_bracket")
            }
            _ => Err("unknown frozen shape".into()),
        }
    }

    fn linked_set(a: &Authorization, shape: &str, count: usize) -> Result<Vec<NfLeaf>> {
        let mut values = neighboring_values(a, shape)?;
        let mut seen: HashSet<H> = values.iter().copied().collect();
        if values.len() != seen.len() || values.iter().any(|x| *x == [0; 32] || a.nfs.contains(x)) {
            return Err("neighbor collision/retained nullifier".into());
        }
        for i in 0u64.. {
            if values.len() >= count {
                break;
            }
            let value = hash(
                &[
                    b"KPI-unfunded-native-budget-NF-v1\0".as_slice(),
                    &i.to_le_bytes(),
                ]
                .concat(),
            );
            if value != [0; 32] && !a.nfs.contains(&value) && seen.insert(value) {
                values.push(value);
            }
        }
        if values.len() != count || count % 2 != 0 {
            return Err("frozen NF count".into());
        }
        // Physical positions are deliberately independent from numeric ordering.
        // Pin exact predecessor indices around script-number encoding boundaries.
        values.reverse();
        if shape.starts_with("index_") || shape == "near_capacity" {
            let desired = match shape {
                "index_127_128" => [127usize, 128],
                "index_32767_32768" => [32767usize, 32768],
                _ => [count - 1, count],
            };
            for (nf, index) in a.nfs.iter().zip(desired) {
                let predecessor = shifted(*nf, -1)?;
                let current = values
                    .iter()
                    .position(|v| *v == predecessor)
                    .ok_or("missing exact predecessor")?;
                values.swap(current, index - 1);
            }
        }
        let mut sorted = values.clone();
        sorted.sort_unstable_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
        let positions: HashMap<H, u32> = values
            .iter()
            .enumerate()
            .map(|(i, h)| (*h, (i + 1) as u32))
            .collect();
        let mut leaves = vec![NfLeaf::default(); count + 1];
        leaves[0].next_index = *positions.get(&sorted[0]).ok_or("first position")?;
        leaves[0].next_value = sorted[0];
        for (i, value) in sorted.iter().enumerate() {
            let (next_index, next_value) = sorted
                .get(i + 1)
                .map_or((0, [0; 32]), |v| (positions[v], *v));
            leaves[positions[value] as usize] = NfLeaf {
                value: *value,
                next_index,
                next_value,
            };
        }
        // Independent full linked-list consistency check, beyond PublicState's
        // structural count checks: every leaf occurs once in increasing LE order.
        let mut index = 0usize;
        let mut traversed = HashSet::new();
        for expected in &sorted {
            let leaf = &leaves[index];
            if !less(&leaf.value, expected)
                || leaf.next_value != *expected
                || leaves.get(leaf.next_index as usize).map(|x| x.value) != Some(*expected)
            {
                return Err("synthetic linked-set edge".into());
            }
            index = leaf.next_index as usize;
            if !traversed.insert(index) {
                return Err("synthetic linked-set cycle".into());
            }
        }
        if traversed.len() != count
            || leaves[index].next_index != 0
            || leaves[index].next_value != [0; 32]
        {
            return Err("synthetic linked-set terminal".into());
        }
        Ok(leaves)
    }

    fn context(
        prior: &PublicState,
        a: &Authorization,
        shape: &str,
        cm_count: usize,
        nf_count: usize,
    ) -> Result<PublicState> {
        if cm_count < prior.commitments.len() || cm_count % 2 != 1 {
            return Err("synthetic prefix count".into());
        }
        let mut commitments = prior.commitments.clone();
        for i in commitments.len()..cm_count {
            commitments.push(hash(
                &[
                    b"KPI-unfunded-native-budget-CM-v1\0".as_slice(),
                    &(i as u64).to_le_bytes(),
                ]
                .concat(),
            ));
        }
        let mut tree = Tree::new(Vec::new(), 16)?;
        let mut roots = Vec::with_capacity((cm_count + 1) / 2);
        for (i, cm) in commitments.iter().enumerate() {
            tree.append(cm_leaf(cm))?;
            if i % 2 == 0 {
                roots.push(tree.root());
            }
        }
        if roots.get((a.count as usize - 1) / 2) != Some(&a.anchor)
            || roots[..prior.roots.len()] != prior.roots
        {
            return Err("genuine historical CM prefix/anchor changed".into());
        }
        let state = PublicState {
            commitments,
            nullifiers: linked_set(a, shape, nf_count)?,
            roots,
        };
        state.compact()?;
        Ok(state)
    }

    fn limb_vector(a: &H, b: &H) -> Vec<&'static str> {
        LIMBS
            .iter()
            .map(
                |&(lo, hi)| match a[lo..hi].iter().rev().cmp(b[lo..hi].iter().rev()) {
                    std::cmp::Ordering::Less => "lt",
                    std::cmp::Ordering::Equal => "eq",
                    std::cmp::Ordering::Greater => "gt",
                },
            )
            .collect()
    }

    fn predecessors(witness: &[u8], a: &Authorization) -> Result<Vec<Value>> {
        (0..2).map(|slot|{
        let base=W_NF+slot*NF_WIT;
        let index=u32::from_le_bytes(witness[base..base+4].try_into()?);
        let value:H=witness[base+4..base+36].try_into()?;
        let next_index=u32::from_le_bytes(witness[base+36..base+40].try_into()?);
        let next:H=witness[base+40..base+72].try_into()?;
        if !less(&value,&a.nfs[slot]) || (next!=[0;32]&&!less(&a.nfs[slot],&next)) {
            return Err("witness predecessor comparison".into());
        }
        Ok(json!({"slot":slot,"predecessor_index":index,"predecessor_hex":hex::encode(value),
            "next_index":next_index,"next_hex":hex::encode(next),"sentinel_predecessor":index==0,
            "tail_insertion":next==[0;32],"predecessor_limb_comparisons":limb_vector(&value,&a.nfs[slot]),
            "successor_limb_comparisons":if next==[0;32]{None}else{Some(limb_vector(&a.nfs[slot],&next))}}))
    }).collect()
    }

    fn boundaries(input: &Input, out: &Path) -> Result<Value> {
        let shapes = [
            "sentinel_first",
            "tail_end",
            "middle_bracket",
            "limb_0",
            "limb_1",
            "limb_2",
            "limb_3",
            "limb_4",
            "mixed_all_limbs",
        ];
        let reference = input.spends[0].bundle.auth()?;
        let mut specs = Vec::new();
        for fork in 0..2 {
            for shape in shapes {
                specs.push((
                    fork,
                    shape,
                    5usize,
                    if shape == "sentinel_first" || shape == "tail_end" {
                        2
                    } else {
                        4
                    },
                ));
            }
            specs.extend([
                (fork, "index_127_128", 129, 254),
                (fork, "index_32767_32768", 32769, 65536),
                (fork, "near_capacity", 65533, 131064),
            ]);
        }
        specs.extend([
            (2, "middle_bracket", 5, 8),
            (2, "index_127_128", 129, 254),
            (2, "index_32767_32768", 32769, 65536),
            (2, "near_capacity", 65533, 131066),
        ]);
        if specs.len() != 28 {
            return Err("boundary family changed".into());
        }
        let mut rows = Vec::new();
        for (kind, shape, n, m) in specs {
            let name = format!(
                "{}-{shape}",
                if kind == 2 {
                    "admit".to_string()
                } else {
                    format!("spend-{kind}")
                }
            );
            let bundle = if kind == 2 {
                &input.admit.bundle
            } else {
                &input.spends[kind].bundle
            };
            let auth = bundle.auth()?;
            let old = context(
                &input.prior_state,
                if kind == 2 { &reference } else { &auth },
                shape,
                n,
                m,
            )?;
            let old_bytes = state_bytes(&old)?;
            let u = native::Utxo {
                txid: hex::encode(hash(
                    &[
                        b"KPI/s7/ordinary1600/synthetic-prior/".as_slice(),
                        name.as_bytes(),
                    ]
                    .concat(),
                )),
                index: 0,
                amount: 1_660_000_000,
                spk: hex::encode(native::encode_spk(&policy::reserve_spk(
                    &input.policy,
                    &old,
                )?)),
                daa: 0,
                is_coinbase: false,
            };
            let external = if kind == 2 {
                Some(
                    input
                        .admit
                        .utxos
                        .get(1)
                        .ok_or("ADMIT funding input missing")?,
                )
            } else {
                None
            };
            let (mut tx, e, next) =
                policy::ordinary_settle(&input.policy, &old, &u, bundle, external)?;
            if kind == 2 {
                // Public DO_NOT_FUND fixture derivation only. No private wallet material is read.
                let key = Wallet {
                    spending: [0; 32],
                    viewing: [0; 32],
                    native: profile::label_hash("wallet/bob/native"),
                }
                .funding_key(&input.policy.domain, 0);
                if native::p2pk(&key)? != e[1].script_public_key {
                    return Err("public fixture funding key/SPK mismatch".into());
                }
                native::sign(&mut tx, &e, 1, &key)?;
            }
            let next_bytes = state_bytes(&next)?;
            if next.commitments.len() != n + 2
                || next.nullifiers.len() - 1 != m + if kind == 2 { 0 } else { 2 }
                || tx.payload[AUTH..CIPHER] != auth.bytes()
                || tx.payload[CIPHER..NEXT] != bundle.ciphers()?
                || tx.inputs[0].signature_script[2..130] != hex::decode(&bundle.proof)?
            {
                return Err("boundary genuine proof/auth/cipher or count changed".into());
            }
            let positive = candidate_case(&name, &tx, &e, out, false)?;
            let mut wrong = native::parse_tx(&positive["candidate_transaction"])?;
            let negative = if kind == 2 {
                let proof = negated_a(&wrong.inputs[0].signature_script[2..130])?;
                wrong.inputs[0].signature_script[2..130].copy_from_slice(&proof);
                rejected(
                    "boundary_ADMIT_canonical_negated_A",
                    wrong,
                    &e,
                    Some(TxScriptError::ZkIntegrity(
                        Groth16Error::VerificationFailed.to_string(),
                    )),
                )?
            } else {
                wrong.payload[WITNESS] ^= 1;
                rejected(
                    "boundary_wrong_historical_anchor_path",
                    wrong,
                    &e,
                    Some(TxScriptError::VerifyError),
                )?
            };
            let predecessor = if kind == 2 {
                json!(null)
            } else {
                json!(predecessors(&tx.payload[WITNESS..], &auth)?)
            };
            let row = json!({"name":name,"synthetic_prior_context":true,"accepted_ancestry":false,"native_KAS_backing_verified":false,"old_n":n,"old_m":m,"new_n":next.commitments.len(),"new_m":next.nullifiers.len()-1,"old_state105":hex::encode(old_bytes),"next_state105":hex::encode(next_bytes),"full_public_state_sha256":hex::encode(hash(&serde_json::to_vec(&old)?)),"genuine_bundle_auth_sha256":hex::encode(hash(&auth.bytes())),"genuine_bundle_proof_sha256":hex::encode(hash(&hex::decode(&bundle.proof)?)),"predecessors":predecessor,"positive":positive,"typed_control":negative,"ADMIT_signature":if kind==2{"new synthetic-context signature using published DO_NOT_FUND fixture derivation"}else{"not applicable"}});
            fs::write(
                out.join(format!("{name}-boundary.json")),
                serde_json::to_vec_pretty(&row)?,
            )?;
            rows.push(row);
        }
        Ok(
            json!({"phase":"synthetic-public-boundaries","case_count":rows.len(),"typed_negative_count":rows.len(),"cases":rows,"accepted_ancestry":false,"backing_verified":false,"genuine_proofs_unchanged":true,"factory_default_changed":false,"DRAIN":"source-only bound; not executed"}),
        )
    }
    fn state_bytes(state: &PublicState) -> Result<Vec<u8>> {
        profile::state_bytes(state)
    }
    pub fn run() -> Result<()> {
        let args = std::env::args().collect::<Vec<_>>();
        if args.len() != 4 || !["actual", "boundaries"].contains(&args[3].as_str()) {
            return Err("usage: checker INPUT_JSON NEW_OUTPUT_DIRECTORY actual|boundaries".into());
        }
        let bytes = fs::read(&args[1])?;
        let input: Input = serde_json::from_slice(&bytes)?;
        input.policy.validate()?;
        input.profile.validate(&input.policy.inner_vk)?;
        for (key, actual) in [
            ("domain", hex::encode(input.policy.domain)),
            ("pool_id", hex::encode(input.policy.pool_id)),
            ("inner_vk_sha256", hex::encode(hash(&input.policy.inner_vk))),
            ("pair_image", hex::encode(input.policy.pair_image)),
        ] {
            if input.selected_tuple[key] != actual {
                return Err(format!("selected policy tuple mismatch:{key}").into());
            }
        }
        if policy::BUDGET != HISTORICAL
            || input.policy.domain != input.profile.domain
            || input.policy.pool_id != input.profile.pool_id
            || input.policy.inner_vk.len() != 328
            || policy::redeem(&input.policy, &state_bytes(&input.prior_state)?)?.len() != 24576
        {
            return Err("frozen policy/default/bound assumptions changed".into());
        }
        let out = Path::new(&args[2]);
        if out.exists() {
            return Err("output directory already exists".into());
        }
        fs::create_dir_all(out)?;
        let mut report = if args[3] == "actual" {
            actual(&input, out)?
        } else {
            boundaries(&input, out)?
        };
        report["consumed_input_sha256"] = json!(hex::encode(hash(&bytes)));
        report["input_provenance"] = input.provenance;
        report["native_revision"] = json!("01b532e8b553523216471682649693af92f0fd16");
        report["qualification_scope"] = json!(
            "offline supplied-public-context official isolation and Full plus per-input actual VM meter; source-adapted policy separately reported; no owner/replay workflow, no new setup/proving or funds"
        );
        fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
        println!(
            "{}",
            serde_json::to_string(
                &json!({"phase":report["phase"],"case_count":report.get("case_count").unwrap_or(&report["ordinary_case_count"]),"typed_negative_count":report["typed_negative_count"],"report":"report.json"})
            )?
        );
        Ok(())
    }
}
#[cfg(feature = "s7-native-policy")]
fn main() {
    if let Err(e) = qualification::run() {
        eprintln!("qualification failed: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(feature = "s7-native-policy"))]
fn main() {
    eprintln!("requires --features s7-native-policy");
    std::process::exit(2);
}
