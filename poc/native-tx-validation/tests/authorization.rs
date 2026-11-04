use kpi_native_tx_validation::{
    codec::{effect_bytes, Transaction, MAX_PACKET},
    fixtures::{self, NAMES},
    signing::{input_hash, signing_message, verify_inputs},
    verifier::{SyntheticView, Verifier},
    Error, MAX_SOMPI, PROOF_BYTES,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, sync::OnceLock};

fn folder() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}
fn packet(name: &str) -> Vec<u8> {
    fs::read(folder().join(format!("{name}.bin"))).unwrap()
}
fn tx(name: &str) -> Transaction {
    Transaction::decode(&packet(name)).unwrap()
}
fn view(name: &str) -> SyntheticView {
    fixtures::synthetic_view(name, &tx(name))
}
fn verifier() -> &'static Verifier {
    static V: OnceLock<Verifier> = OnceLock::new();
    V.get_or_init(|| Verifier::new().unwrap())
}
fn end(t: &Transaction) -> usize {
    effect_bytes(&t.effects, &t.bundle, true).unwrap().len()
}

#[test]
fn genuine_native_draft_authorizations_and_public_artifact_identities() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(folder().join("manifest.json")).unwrap()).unwrap();
    let mut spent = std::collections::BTreeSet::new();
    for (name, v) in NAMES
        .into_iter()
        .zip(manifest["vectors"].as_array().unwrap())
    {
        let bytes = packet(name);
        let t = tx(name);
        let mut context = view(name);
        context.spent = spent.clone();
        let before = context.clone();
        let r = verifier().verify_local(&bytes, &context).unwrap();
        assert_eq!(context, before); // This API cannot apply native state.
        assert_eq!(t.encode().unwrap(), bytes);
        assert_eq!(v["sha256"], hex::encode(Sha256::digest(&bytes)));
        assert_eq!(v["txid"], hex::encode(r.txid));
        assert_eq!(v["txhash"], hex::encode(r.txhash));
        assert_eq!(v["signing_message"], hex::encode(r.signing_message));
        assert_eq!(
            fs::read(folder().join(format!("{name}.q.bin"))).unwrap(),
            effect_bytes(&t.effects, &t.bundle, false).unwrap()
        );
        spent.extend(t.bundle.actions().iter().map(|a| a.nullifier().to_bytes()));
    }
    for key in [
        "native_acceptance",
        "chain_authenticated",
        "mass_validated",
        "portable_key_import",
    ] {
        assert_eq!(manifest[key], false);
    }
}

#[test]
fn earlier_serialization_vector_is_preserved_but_has_no_native_authorization() {
    let bytes = include_bytes!(
        "../../../docs/spec/native-shielded/artifacts/native-transaction-encoding.bin"
    );
    let t = Transaction::decode(bytes).unwrap();
    assert_eq!(t.encode().unwrap(), bytes);
    let v: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../docs/spec/native-shielded/artifacts/conformance.json"
    ))
    .unwrap();
    assert_eq!(v["native_txid"], hex::encode(t.txid().unwrap()));
    assert_eq!(v["native_txhash"], hex::encode(t.txhash().unwrap()));
    let s: [u8; 32] = hex::decode(v["shielded_signing_message"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(t.bundle.actions()[0]
        .rk()
        .verify(&s, t.bundle.actions()[0].authorization())
        .is_err());
}

#[test]
fn both_standard_funding_signature_algorithms_and_indices_are_required() {
    let t = tx("deposit");
    let v = view("deposit");
    assert_eq!(verify_inputs(&t, &v.utxos), Ok(()));
    for slot in 0..2 {
        let mut bad = t.clone();
        bad.effects.inputs[slot].signature_script[20] ^= 1;
        assert_eq!(verify_inputs(&bad, &v.utxos), Err(Error::InputSignature));
    }
    let mut swapped = t.clone();
    let a = swapped.effects.inputs[0].signature_script.clone();
    swapped.effects.inputs[0].signature_script = swapped.effects.inputs[1].signature_script.clone();
    swapped.effects.inputs[1].signature_script = a;
    assert_eq!(
        verify_inputs(&swapped, &v.utxos),
        Err(Error::InputSignature)
    );
    let s = signing_message(&t.effects, &t.bundle, &v.utxos).unwrap();
    assert_ne!(input_hash(s, 0, false), input_hash(s, 1, false));
    assert_ne!(input_hash(s, 0, false), input_hash(s, 0, true));
}

#[test]
fn funding_unlocking_policy_and_high_s_are_not_silently_normalized() {
    let t = tx("deposit");
    let v = view("deposit");
    for slot in 0..2 {
        for mode in [0, 2, 3, 0x81, 0xff] {
            let mut bad = t.clone();
            bad.effects.inputs[slot].signature_script[65] = mode;
            assert_eq!(verify_inputs(&bad, &v.utxos), Err(Error::InputSignature));
        }
        let mut bad = t.clone();
        bad.effects.inputs[slot].signature_script[0] = 0x40;
        assert_eq!(verify_inputs(&bad, &v.utxos), Err(Error::InputSignature));
        bad.effects.inputs[slot].signature_script.push(0);
        assert_eq!(verify_inputs(&bad, &v.utxos), Err(Error::InputSignature));
    }
    let mut high = t;
    let n =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let s = &mut high.effects.inputs[1].signature_script[33..65];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let value = i16::from(n[i]) - i16::from(s[i]) - borrow;
        s[i] = value.rem_euclid(256) as u8;
        borrow = i16::from(value < 0);
    }
    assert_eq!(verify_inputs(&high, &v.utxos), Err(Error::InputSignature));
}

#[test]
fn all_native_economic_fields_are_cryptographically_authorized() {
    let original = tx("deposit");
    let v = view("deposit");
    let mut cases = Vec::new();
    macro_rules! changed {
        ($body:expr) => {{
            let mut t = original.clone();
            $body(&mut t);
            cases.push(t);
        }};
    }
    changed!(|t: &mut Transaction| t.effects.domain[0] ^= 1);
    changed!(|t: &mut Transaction| t.effects.lock_time += 1);
    changed!(|t: &mut Transaction| t.effects.storage_mass += 1);
    changed!(|t: &mut Transaction| t.effects.fee += 1);
    changed!(|t: &mut Transaction| t.effects.payload.push(1));
    changed!(|t: &mut Transaction| t.effects.anchor_tree += 1);
    changed!(|t: &mut Transaction| t.effects.anchor_count += 2);
    changed!(|t: &mut Transaction| t.effects.inputs[0].sequence -= 1);
    changed!(|t: &mut Transaction| t.effects.inputs[1].compute_budget += 1);
    changed!(|t: &mut Transaction| t.effects.outputs[0].value += 1);
    changed!(|t: &mut Transaction| t.effects.outputs[0].script_version += 1);
    changed!(|t: &mut Transaction| t.effects.outputs[0].script[5] ^= 1);
    changed!(|t: &mut Transaction| t.effects.outputs[0].covenant = Some((0, [1; 32])));
    changed!(|t: &mut Transaction| t.effects.outputs.push(t.effects.outputs[0].clone()));
    changed!(|t: &mut Transaction| t.effects.inputs.swap(0, 1));
    for bad in cases {
        assert_eq!(
            verifier().verify_shielded_signatures(&bad, &v),
            Err(Error::SpendSignature)
        );
        assert_eq!(verify_inputs(&bad, &v.utxos), Err(Error::InputSignature));
    }
    for slot in 0..2 {
        let mut bad = original.clone();
        let mut context = v.clone();
        let old = bad.effects.inputs[slot].previous;
        bad.effects.inputs[slot].previous.index += 1;
        let u = context.utxos.remove(&old).unwrap();
        context.utxos.insert(bad.effects.inputs[slot].previous, u);
        assert_eq!(
            verifier().verify_shielded_signatures(&bad, &context),
            Err(Error::SpendSignature)
        );
        assert_eq!(
            verify_inputs(&bad, &context.utxos),
            Err(Error::InputSignature)
        );
    }
}

#[test]
fn actual_supplied_input_context_cannot_be_replaced_without_reauthorization() {
    let t = tx("deposit");
    let original = view("deposit");
    let p = t.effects.inputs[0].previous;
    let mut changed = original.clone();
    changed.utxos.get_mut(&p).unwrap().amount += 1;
    assert_eq!(
        verifier().verify_shielded_signatures(&t, &changed),
        Err(Error::SpendSignature)
    );
    assert_eq!(
        verify_inputs(&t, &changed.utxos),
        Err(Error::InputSignature)
    );
    // Compensate the second amount: same Tin/b/F still cannot substitute context.
    let q = t.effects.inputs[1].previous;
    changed.utxos.get_mut(&q).unwrap().amount -= 1;
    assert_eq!(verifier().check_synthetic_context(&t, &changed), Ok(()));
    assert_eq!(
        verifier()
            .verify_local(&packet("deposit"), &changed)
            .unwrap_err(),
        Error::InputSignature
    );
    let mut changed = original.clone();
    changed.utxos.get_mut(&p).unwrap().script = fixtures::script(true);
    assert_eq!(
        verifier().verify_shielded_signatures(&t, &changed),
        Err(Error::SpendSignature)
    );
    assert_eq!(
        verify_inputs(&t, &changed.utxos),
        Err(Error::InputSignature)
    );
    let mut missing = original;
    missing.utxos.remove(&p);
    assert_eq!(
        verifier()
            .verify_local(&packet("deposit"), &missing)
            .unwrap_err(),
        Error::MissingInput
    );
}

#[test]
fn proof_and_each_shielded_signature_role_fail_at_the_intended_layer() {
    let t = tx("transfer");
    let start = end(&t) + 8;
    let mut bytes = packet("transfer");
    bytes[start + 256] ^= 1;
    assert_eq!(
        verifier().verify_proof(&Transaction::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
    for slot in 0..2 {
        let mut bytes = packet("transfer");
        bytes[start + PROOF_BYTES + slot * 64] ^= 1;
        let bad = Transaction::decode(&bytes).unwrap();
        assert_eq!(verifier().verify_proof(&bad), Ok(()));
        assert_eq!(
            verifier().verify_shielded_signatures(&bad, &view("transfer")),
            Err(Error::SpendSignature)
        );
    }
    let mut bytes = packet("transfer");
    let at = bytes.len() - 64;
    bytes[at] ^= 1;
    let bad = Transaction::decode(&bytes).unwrap();
    assert_eq!(verifier().verify_proof(&bad), Ok(()));
    assert_eq!(
        verifier().verify_shielded_signatures(&bad, &view("transfer")),
        Err(Error::BindingSignature)
    );
}

#[test]
fn canonical_changed_action_inputs_reject_in_real_halo2() {
    let t = tx("transfer");
    let first = end(&t) - 8 - 1640;
    for offset in [0, 32, 64, 96] {
        let mut bytes = packet("transfer");
        let field = bytes[first + 820 + offset..first + 820 + offset + 32].to_vec();
        bytes[first + offset..first + offset + 32].copy_from_slice(&field);
        assert_eq!(
            verifier().verify_proof(&Transaction::decode(&bytes).unwrap()),
            Err(Error::Proof)
        );
    }
    let mut bytes = packet("transfer");
    bytes[first - 34..first - 2].fill(0);
    assert_eq!(
        verifier().verify_proof(&Transaction::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
    let wrong =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    assert!(t.bundle.verify_proof(&wrong).is_err());
}

#[test]
fn changed_public_balance_is_bound_without_inventing_a_halo2_range_gadget() {
    let t = tx("transfer");
    let original_s = signing_message(&t.effects, &t.bundle, &view("transfer").utxos).unwrap();
    let mut bytes = packet("transfer");
    let at = end(&t) - 8;
    bytes[at..at + 8].copy_from_slice(&2i64.to_le_bytes());
    let changed = Transaction::decode(&bytes).unwrap();
    assert_eq!(verifier().verify_proof(&changed), Ok(())); // aggregate b is not an Action public input
    assert_eq!(
        verifier().verify_shielded_signatures(&changed, &view("transfer")),
        Err(Error::SpendSignature)
    );
    assert!(changed
        .bundle
        .binding_validating_key()
        .verify(
            &original_s,
            changed.bundle.authorization().binding_signature()
        )
        .is_err());
}

#[test]
fn delivery_and_action_order_are_authorized() {
    let t = tx("transfer");
    let first = end(&t) - 8 - 1640;
    for offset in [160, 740] {
        let mut bytes = packet("transfer");
        bytes[first + offset] ^= 1;
        let bad = Transaction::decode(&bytes).unwrap();
        assert_eq!(verifier().verify_proof(&bad), Ok(()));
        assert_eq!(
            verifier().verify_shielded_signatures(&bad, &view("transfer")),
            Err(Error::SpendSignature)
        );
    }
    let mut bytes = packet("transfer");
    let a = bytes[first..first + 820].to_vec();
    let b = bytes[first + 820..first + 1640].to_vec();
    bytes[first..first + 820].copy_from_slice(&b);
    bytes[first + 820..first + 1640].copy_from_slice(&a);
    assert_eq!(
        verifier().verify_proof(&Transaction::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
}

#[test]
fn economic_id_excludes_authorizations_full_hash_includes_them() {
    let original = tx("deposit");
    let mut changed = original.clone();
    changed.effects.inputs[0].signature_script[12] ^= 1;
    assert_eq!(original.txid().unwrap(), changed.txid().unwrap());
    assert_ne!(original.txhash().unwrap(), changed.txhash().unwrap());
    let mut bytes = packet("deposit");
    let at = end(&original) + 8 + 256;
    bytes[at] ^= 1;
    let bad = Transaction::decode(&bytes).unwrap();
    assert_eq!(original.txid().unwrap(), bad.txid().unwrap());
    assert_ne!(original.txhash().unwrap(), bad.txhash().unwrap());
    let mut bytes = packet("deposit");
    let at = bytes.len() - 1;
    bytes[at] ^= 1;
    let bad = Transaction::decode(&bytes).unwrap();
    assert_eq!(original.txid().unwrap(), bad.txid().unwrap());
    assert_ne!(original.txhash().unwrap(), bad.txhash().unwrap());
}

#[test]
fn synthetic_current_state_rejects_stale_anchor_duplicate_and_replay() {
    let t = tx("transfer");
    let v = view("transfer");
    assert_eq!(verifier().verify_proof(&t), Ok(()));
    let mut bad = v.clone();
    bad.anchors.clear();
    assert_eq!(
        verifier()
            .verify_local(&packet("transfer"), &bad)
            .unwrap_err(),
        Error::Anchor
    );
    for a in t.bundle.actions() {
        let mut bad = v.clone();
        bad.spent.insert(a.nullifier().to_bytes());
        assert_eq!(
            verifier()
                .verify_local(&packet("transfer"), &bad)
                .unwrap_err(),
            Error::Spentness
        );
    }
    let mut bad = v.clone();
    bad.domain[0] ^= 1;
    assert_eq!(
        verifier()
            .verify_local(&packet("transfer"), &bad)
            .unwrap_err(),
        Error::Domain
    );
    let mut bad = view("withdraw");
    bad.balance = 0;
    assert_eq!(
        verifier()
            .verify_local(&packet("withdraw"), &bad)
            .unwrap_err(),
        Error::PoolBalance
    );
    let mut bytes = packet("transfer");
    let first = end(&t) - 8 - 1640;
    let nf = bytes[first + 32..first + 64].to_vec();
    bytes[first + 852..first + 884].copy_from_slice(&nf);
    assert_eq!(
        verifier().verify_local(&bytes, &v).unwrap_err(),
        Error::Spentness
    );
}

#[test]
fn unimplemented_chain_checks_are_refused_and_unsupported_scripts_reject() {
    let t = tx("deposit");
    let v = view("deposit");
    let mut bad = t.clone();
    bad.effects.lock_time = 1;
    assert_eq!(
        verifier().check_synthetic_context(&bad, &v),
        Err(Error::UnsupportedContext)
    );
    let mut bad = t.clone();
    bad.effects.inputs[0].sequence = 0;
    assert_eq!(
        verifier().check_synthetic_context(&bad, &v),
        Err(Error::UnsupportedContext)
    );
    let p = t.effects.inputs[0].previous;
    let mut context = v.clone();
    context.utxos.get_mut(&p).unwrap().coinbase = true;
    assert_eq!(
        verifier().check_synthetic_context(&t, &context),
        Err(Error::UnsupportedContext)
    );
    let mut context = v.clone();
    context.utxos.get_mut(&p).unwrap().covenant = true;
    assert_eq!(
        verifier().check_synthetic_context(&t, &context),
        Err(Error::UnsupportedScript)
    );
    for script in [
        vec![0x51],
        vec![0x20, 1, 0xac],
        [vec![0x20], vec![0xff; 32], vec![0xac]].concat(),
    ] {
        let mut context = v.clone();
        context.utxos.get_mut(&p).unwrap().script = script;
        assert_eq!(
            verifier().check_synthetic_context(&t, &context),
            Err(Error::UnsupportedScript)
        );
    }
    let mut bad = t.clone();
    bad.effects.outputs[0].covenant = Some((0, [1; 32]));
    assert_eq!(
        verifier().check_synthetic_context(&bad, &v),
        Err(Error::UnsupportedScript)
    );
    let mut bad = t;
    bad.effects.inputs.push(bad.effects.inputs[0].clone());
    assert_eq!(
        verifier().check_synthetic_context(&bad, &v),
        Err(Error::DuplicateInput)
    );
}

#[test]
fn parser_bounds_and_role_rules_reject_without_unbounded_allocation() {
    let bytes = packet("transfer");
    let t = tx("transfer");
    let first = end(&t) - 8 - 1640;
    for n in [
        0,
        1,
        2,
        9,
        10,
        first,
        end(&t),
        end(&t) + 7,
        bytes.len() - 193,
        bytes.len() - 129,
        bytes.len() - 65,
        bytes.len() - 1,
    ] {
        assert!(Transaction::decode(&bytes[..n]).is_err(), "truncation {n}");
    }
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(Transaction::decode(&padded).is_err());
    assert!(Transaction::decode(&vec![0; MAX_PACKET + 1]).is_err());
    let mut bad = bytes.clone();
    bad[2..10].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        Transaction::decode(&bad).unwrap_err(),
        Error::Decode("item bound")
    );
    for length in [0, 7263, 7265, u64::MAX] {
        let mut bad = bytes.clone();
        bad[end(&t)..end(&t) + 8].copy_from_slice(&length.to_le_bytes());
        assert_eq!(
            Transaction::decode(&bad).unwrap_err(),
            Error::Decode("proof length")
        );
    }
    for offset in [0, 32, 64, 96, 128] {
        let mut bad = bytes.clone();
        bad[first + offset..first + offset + 32].fill(255);
        assert!(Transaction::decode(&bad).is_err());
    }
    for offset in [64, 128] {
        let mut bad = bytes.clone();
        bad[first + offset..first + offset + 32].fill(0);
        assert!(Transaction::decode(&bad).is_err());
    }
    for offset in [0, 32] {
        let mut bad = bytes.clone();
        bad[first + offset..first + offset + 32].fill(0);
        assert_eq!(
            verifier().verify_proof(&Transaction::decode(&bad).unwrap()),
            Err(Error::Proof)
        );
    }
    let mut bad = bytes;
    bad[end(&t) - 8..end(&t)].copy_from_slice(&i64::MIN.to_le_bytes());
    assert_eq!(Transaction::decode(&bad).unwrap_err(), Error::Range);
}

#[test]
fn public_integer_ranges_and_zero_values_are_checked_on_supplied_context() {
    let t = tx("deposit");
    let v = view("deposit");
    let p = t.effects.inputs[0].previous;
    for value in [0, MAX_SOMPI + 1, u64::MAX] {
        let mut bad = v.clone();
        bad.utxos.get_mut(&p).unwrap().amount = value;
        assert_eq!(
            verifier().check_synthetic_context(&t, &bad),
            Err(Error::Range)
        );
        let mut bad = t.clone();
        bad.effects.outputs[0].value = value;
        assert_eq!(
            verifier().check_synthetic_context(&bad, &v),
            Err(Error::Range)
        );
    }
    let mut bad = v.clone();
    bad.utxos.get_mut(&p).unwrap().amount = MAX_SOMPI;
    assert_eq!(
        verifier().check_synthetic_context(&t, &bad),
        Err(Error::Range)
    ); // aggregate over maximum
    let mut bad = t.clone();
    bad.effects.fee = MAX_SOMPI + 1;
    assert_eq!(
        verifier().check_synthetic_context(&bad, &v),
        Err(Error::Range)
    );
    let mut bad = v;
    bad.balance = MAX_SOMPI + 1;
    assert_eq!(
        verifier().check_synthetic_context(&t, &bad),
        Err(Error::PoolBalance)
    );
}

#[test]
fn deterministic_bitflip_corpus_never_passes_local_authorization() {
    let bytes = packet("transfer");
    let context = view("transfer");
    for i in 0..96 {
        let mut bad = bytes.clone();
        let at = (i * 7919 + 37) % bytes.len();
        bad[at] ^= 1 << (i % 8);
        assert!(
            verifier().verify_local(&bad, &context).is_err(),
            "accepted bitflip {at}"
        );
    }
}
