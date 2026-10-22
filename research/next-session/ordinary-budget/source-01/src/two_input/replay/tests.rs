use super::*;

// Retained public bodies and verification key only. No secret, PK, fresh proof,
// generated setup, RPC or funded operation is needed by these integration tests.
struct Fixture {
    descriptor: Descriptor,
    vk: Vec<u8>,
    lineage: Vec<Value>,
    parents: Vec<Value>,
    expected_state: Value,
    expected_hashes: Vec<String>,
}

fn read(relative: &str) -> Value {
    serde_json::from_slice(&fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap())
        .unwrap()
}

fn fixture(run: &str) -> Fixture {
    let base = "evidence/2026-10-20-two-input-tn10";
    let old = read(&format!("{base}/{run}/descriptor.json"));
    let chain = read(&format!("{base}/{run}/chain-confirmed.json"));
    let rows = chain["transactions"].as_array().unwrap();
    let lineage: Vec<Value> = rows[1..].iter().map(|r| r["transaction"].clone()).collect();
    Fixture {
        descriptor: Descriptor {
            format: DESCRIPTOR_FORMAT.into(),
            network: old["network"].as_str().unwrap().into(),
            genesis: old["genesis"].as_str().unwrap().into(),
            domain: serde_json::from_value(old["domain"].clone()).unwrap(),
            initial_commitment: serde_json::from_value(old["initial_commitment"].clone()).unwrap(),
            initial_value_sompi: old["initial_value"].as_u64().unwrap().to_string(),
            vk_sha256: old["vk_sha256"].as_str().unwrap().into(),
            funding_txid: lineage[0]["id"].as_str().unwrap().into(),
            funding_full_hash: rows[1]["fullHash"].as_str().unwrap().into(),
        },
        vk: hex::decode(
            read(&format!("{base}/verification-key.json"))["hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
        parents: vec![rows[0]["transaction"].clone()],
        lineage,
        expected_state: read(&format!("{base}/{run}/result.json"))["checked"]["state"].clone(),
        expected_hashes: rows[1..]
            .iter()
            .map(|r| r["fullHash"].as_str().unwrap().into())
            .collect(),
    }
}

fn run(f: &Fixture) -> Result<Replay> {
    replay(&f.descriptor, &f.vk, &f.lineage, &f.parents)
}

fn rejected(f: &Fixture, cause: &str) {
    let error = run(f)
        .err()
        .expect("invalid fixture unexpectedly accepted")
        .to_string();
    assert!(error.contains(cause), "expected {cause:?}, got {error:?}");
}

fn change_tx(f: &mut Fixture, step: usize, mutate: impl FnOnce(&mut Transaction)) {
    let mut tx = native::parse_tx(&f.lineage[step]).unwrap();
    mutate(&mut tx);
    tx.finalize();
    f.lineage[step] = native::tx_json(&tx);
}

#[test]
fn retained_genuine_traces_replay_without_participant_roster() {
    for name in ["rehearsal", "trial"] {
        let f = fixture(name);
        let descriptor = serde_json::to_value(&f.descriptor).unwrap();
        assert!(descriptor.get("sources").is_none());
        let result = run(&f).unwrap();
        assert!(result.reserve.is_none());
        assert!(result.bootstrap_validated);
        assert!(!result.chain_acceptance_verified);
        assert_eq!(result.records.len(), 14);
        assert_eq!(
            serde_json::to_value(result.state.compact().unwrap()).unwrap(),
            f.expected_state
        );
        assert_eq!(result.accounting.initial_reserve_sompi, "2000000000");
        assert_eq!(result.accounting.admitted_sompi, "3600000000");
        assert_eq!(result.accounting.paid_sompi, "5080000000");
        assert_eq!(result.accounting.pool_fees_sompi, "520000000");
        assert_eq!(result.accounting.remaining_reserve_sompi, "0");
        assert_eq!(result.accounting.founding_fee_sompi, "1012600");
        assert_eq!(result.accounting.founding_input_sompi, "2100000000");
        assert_eq!(result.accounting.founding_change_sompi, "98987400");
        for (index, record) in result.records.iter().enumerate() {
            assert_eq!(record.transaction, f.lineage[index]);
            assert_eq!(record.full_hash, f.expected_hashes[index]);
            if index > 0 {
                let original = native::parse_tx(&f.lineage[index]).unwrap();
                assert_eq!(
                    record.proof_sha256.as_deref(),
                    Some(hex::encode(hash(&original.inputs[0].signature_script[2..130])).as_str())
                );
                assert_eq!(
                    record.authorization_sha256.as_deref(),
                    Some(hex::encode(hash(&original.payload[P_AUTH..P_CIPHER])).as_str())
                );
            }
        }
    }
}

#[test]
fn unrelated_public_parent_and_repeated_identical_body_do_not_change_replay() {
    let mut f = fixture("trial");
    let expected = run(&f).unwrap().summary().unwrap();
    f.parents.push(f.parents[0].clone());
    f.parents.extend(fixture("rehearsal").parents);
    assert_eq!(run(&f).unwrap().summary().unwrap(), expected);
}

#[test]
fn founding_prefix_reports_bootstrap_pending_and_full_hash_pin_is_checked() {
    let mut f = fixture("trial");
    f.lineage.truncate(1);
    let result = run(&f).unwrap();
    assert!(!result.bootstrap_validated);
    assert!(result.reserve.is_some());
    assert_eq!(result.accounting.pool_fees_sompi, "0");
    f.descriptor.funding_full_hash = hex::encode([1; 32]);
    rejected(&f, "pinned founding transaction");
}

#[test]
fn descriptor_rejects_roster_unknown_fields_wrong_identity_and_noncanonical_amount() {
    let mut f = fixture("trial");
    let mut encoded = serde_json::to_value(&f.descriptor).unwrap();
    encoded["sources"] = json!([]);
    assert!(serde_json::from_value::<Descriptor>(encoded).is_err());
    f.descriptor.initial_value_sompi = "02000000000".into();
    rejected(&f, "amount encoding/range");
    let mut f = fixture("trial");
    f.descriptor.network = "mainnet".into();
    rejected(&f, "descriptor/VK identity");
    let mut f = fixture("trial");
    f.vk[0] ^= 1;
    rejected(&f, "descriptor/VK identity");
    let mut f = fixture("trial");
    f.descriptor.domain[0] ^= 1;
    rejected(&f, "pinned founding transaction");
    let mut f = fixture("trial");
    f.descriptor.initial_commitment[0] ^= 1;
    rejected(&f, "pinned founding transaction");
}

#[test]
fn missing_parent_and_canonical_id_substitution_are_rejected() {
    let mut f = fixture("trial");
    f.parents.clear();
    rejected(&f, "missing funding parent body");
    for field in ["value", "scriptPublicKey"] {
        let mut f = fixture("trial");
        f.parents[0]["outputs"][1][field] = if field == "value" {
            json!("1100000001")
        } else {
            f.parents[0]["outputs"][0]["scriptPublicKey"].clone()
        };
        rejected(&f, "noncanonical funding parent");
    }
    let mut f = fixture("trial");
    f.parents[0]["id"] = json!(hex::encode([1; 32]));
    rejected(&f, "noncanonical funding parent");
}

#[test]
fn unsupported_parent_formats_cannot_be_relabelled_ordinary() {
    for (field, value) in [
        ("version", json!(0)),
        (
            "subnetworkId",
            json!("0100000000000000000000000000000000000000"),
        ),
        ("lockTime", json!("1")),
        ("gas", json!("1")),
        ("is_coinbase", json!(false)),
    ] {
        let mut f = fixture("trial");
        f.parents[0][field] = value;
        rejected(&f, "unsupported or noncanonical funding parent");
    }
    let mut f = fixture("trial");
    f.parents[0]["outputs"][0]["covenant"] = json!({"authorizingInput":0});
    rejected(&f, "unexpected covenant binding");
    let mut f = fixture("trial");
    let mut parent = native::parse_tx(&f.parents[0]).unwrap();
    parent.payload = vec![1];
    parent.finalize();
    f.parents[0] = native::tx_json(&parent);
    rejected(&f, "ordinary inputs/empty payload required");
    let mut f = fixture("trial");
    let mut parent = native::parse_tx(&f.parents[0]).unwrap();
    parent.inputs.clear();
    parent.finalize();
    f.parents[0] = native::tx_json(&parent);
    rejected(&f, "ordinary inputs/empty payload required");
}

#[test]
fn selected_parent_output_checks_are_exercised_after_canonical_id_validation() {
    // Isolated parser/context controls. These changed parents are not asserted
    // to be accepted chain transactions or validly signed alternative funding.
    for amount in [0, MAX_SOMPI + 1] {
        let f = fixture("trial");
        let mut parent = native::parse_tx(&f.parents[0]).unwrap();
        parent.outputs[0].value = amount;
        parent.finalize();
        let mut parents = Parents::new(&[native::tx_json(&parent)]).unwrap();
        let point = native::Utxo::output(&parent, 0, 0).outpoint().unwrap();
        assert!(
            parents
                .consume(&point)
                .err()
                .unwrap()
                .to_string()
                .contains("amount out of range")
        );
    }
    for spk in [
        "000051",
        "0001200000000000000000000000000000000000000000000000000000000000000000ac",
    ] {
        let f = fixture("trial");
        let mut parent = native::parse_tx(&f.parents[0]).unwrap();
        parent.outputs[0].script_public_key = native::decode_spk(spk).unwrap();
        parent.finalize();
        let mut parents = Parents::new(&[native::tx_json(&parent)]).unwrap();
        let point = native::Utxo::output(&parent, 0, 0).outpoint().unwrap();
        assert!(
            parents
                .consume(&point)
                .err()
                .unwrap()
                .to_string()
                .contains("ordinary P2PK required")
        );
    }
}

#[test]
fn conflicting_bodies_with_same_id_are_not_last_writer_wins() {
    let mut f = fixture("trial");
    let mut parent = native::parse_tx(&f.parents[0]).unwrap();
    let original_id = parent.id();
    parent.inputs[0].signature_script[1] ^= 1;
    parent.finalize();
    assert_eq!(
        parent.id(),
        original_id,
        "control relies on signatures being excluded from txid"
    );
    f.parents.push(native::tx_json(&parent));
    rejected(&f, "conflicting funding parent bodies");
}

#[test]
fn admission_context_comes_from_actual_parent_not_authorization() {
    // These are hostile mutation controls, not valid alternative proofs.
    for offset in [A_DEP, A_FUND + 32, A_FSPK] {
        let mut f = fixture("trial");
        f.lineage.truncate(3);
        change_tx(&mut f, 2, |tx| tx.payload[P_AUTH + offset] ^= 1);
        rejected(&f, "v6 funding binding");
    }
    let mut f = fixture("trial");
    f.lineage.truncate(3);
    change_tx(&mut f, 2, |tx| tx.inputs[1].previous_outpoint.index = 999);
    rejected(&f, "funding output index out of range");
    let mut f = fixture("trial");
    f.lineage.truncate(3);
    change_tx(&mut f, 2, |tx| tx.inputs[1].previous_outpoint.index = 4);
    rejected(&f, "v6 funding binding");
}

#[test]
fn funding_single_use_includes_founder_and_later_admissions() {
    let mut f = fixture("trial");
    f.lineage.truncate(3);
    change_tx(&mut f, 2, |tx| tx.inputs[1].previous_outpoint.index = 0);
    rejected(&f, "external funding outpoint already consumed");
    let mut f = fixture("trial");
    f.lineage.truncate(4);
    change_tx(&mut f, 3, |tx| tx.inputs[1].previous_outpoint.index = 1);
    rejected(&f, "external funding outpoint already consumed");
}

#[test]
fn admission_before_founders_bootstrap_is_not_ready() {
    let mut f = fixture("trial");
    let founding = native::parse_tx(&f.lineage[0]).unwrap();
    let reserve = native::Utxo::output(&founding, 0, 0).outpoint().unwrap();
    f.lineage = vec![f.lineage[0].clone(), f.lineage[2].clone()];
    // Point the existing admission at the initial reserve to reach the
    // bootstrap guard rather than merely failing reserve continuity.
    change_tx(&mut f, 1, |tx| tx.inputs[0].previous_outpoint = reserve);
    rejected(&f, "admission before bootstrap");
}

#[test]
fn native_validation_rejects_damaged_founding_and_depositor_signatures_and_proof() {
    let mut f = fixture("trial");
    f.lineage.truncate(1);
    change_tx(&mut f, 0, |tx| tx.inputs[0].signature_script[1] ^= 1);
    // Repin the hostile founding body to isolate native signature validation.
    // This is not the positive trace and does not authenticate a changed pool.
    let founding = native::parse_tx(&f.lineage[0]).unwrap();
    f.descriptor.funding_full_hash = kaspa_consensus_core::hashing::tx::hash(&founding).to_string();
    rejected(&f, "founding native validation");
    let mut f = fixture("trial");
    f.lineage.truncate(3);
    change_tx(&mut f, 2, |tx| tx.inputs[1].signature_script[1] ^= 1);
    rejected(&f, "pool native validation");
    let mut f = fixture("trial");
    f.lineage.truncate(2);
    change_tx(&mut f, 1, |tx| tx.inputs[0].signature_script[2] ^= 1);
    rejected(&f, "pool native validation");
    let mut f = fixture("trial");
    f.lineage.truncate(2);
    change_tx(&mut f, 1, |tx| tx.payload[P_AUTH + A_BOOT] ^= 1);
    rejected(&f, "pool native validation");
}

#[test]
fn ciphertext_state_and_lineage_cannot_be_substituted() {
    let mut f = fixture("trial");
    f.lineage.truncate(2);
    change_tx(&mut f, 1, |tx| tx.payload[P_CIPHER] ^= 1);
    rejected(&f, "domain/reserve/cipher binding");
    let mut f = fixture("trial");
    f.lineage.truncate(2);
    change_tx(&mut f, 1, |tx| tx.payload[P_STATE + 9] ^= 1);
    rejected(&f, "transaction reconstruction mismatch");
    let mut f = fixture("trial");
    f.lineage.remove(2);
    rejected(&f, "reserve lineage discontinuity");
    let mut f = fixture("trial");
    f.lineage.swap(2, 3);
    rejected(&f, "reserve lineage discontinuity");
}

#[test]
fn drained_pool_does_not_accept_more_history_or_duplicate_transactions() {
    let mut f = fixture("trial");
    f.lineage.push(fixture("rehearsal").lineage[1].clone());
    rejected(&f, "history continues after drainage");
    let mut f = fixture("trial");
    f.lineage.push(f.lineage.last().unwrap().clone());
    rejected(&f, "duplicate pool transaction");
    let mut f = fixture("trial");
    f.lineage.clear();
    rejected(&f, "missing pool lineage");
}

#[test]
fn malformed_terminal_payout_cannot_return_a_successful_partial_replay() {
    let mut f = fixture("trial");
    let last = f.lineage.len() - 1;
    change_tx(&mut f, last, |tx| tx.outputs[0].value += 1);
    rejected(&f, "transaction reconstruction mismatch");
}
