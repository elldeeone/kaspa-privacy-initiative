use super::*;
use kaspa_consensus_core::tx::TransactionOutput;

fn vk() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/2026-10-20-two-input-tn10/verification-key.json");
    let value: Value = read_json(&path).unwrap();
    hex::decode(value["hex"].as_str().unwrap()).unwrap()
}
fn pin() -> ParameterPin {
    ParameterPin {
        sha256: "6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593".into(),
        bytes: 962_197_520,
    }
}
fn parent(key: &H, value: u64) -> Transaction {
    // Explicit synthetic ancestry, with a genuinely signed ordinary parent.
    let signer = Wallet::fresh().payout_key(&random(), 0);
    let input = native::Utxo {
        txid: hex::encode(random()),
        index: 0,
        amount: value + 100_000_000,
        spk: hex::encode(native::encode_spk(&native::p2pk(&signer).unwrap())),
        daa: 0,
        is_coinbase: false,
    };
    native::ordinary(
        &input,
        &signer,
        vec![TransactionOutput::new(value, native::p2pk(key).unwrap())],
    )
    .unwrap()
    .0
}
fn initial() -> (Context, Backup) {
    initial_profile(false)
}
fn initial_profile(legacy: bool) -> (Context, Backup) {
    let wallet = Wallet::fresh();
    let domain = random();
    let note = wallet.receive(&domain).note(2_000_000_000).unwrap();
    let key = if legacy {
        wallet.payout_key(&domain, 0)
    } else {
        wallet.funding_key(&domain, 0)
    };
    let parent = parent(&key, 2_100_000_000);
    let vk = vk();
    let state = tree::PublicState::initial(note.commitment(&domain)).unwrap();
    let (founding, _) = native::ordinary(
        &native::Utxo::output(&parent, 0, 0),
        &key,
        vec![TransactionOutput::new(
            2_000_000_000,
            reserve_spk(&domain, &state, &vk).unwrap(),
        )],
    )
    .unwrap();
    let descriptor = replay::Descriptor {
        format: replay::DESCRIPTOR_FORMAT.into(),
        network: "testnet-10".into(),
        genesis: crate::protocol::GENESIS_HEX.into(),
        domain,
        initial_commitment: note.commitment(&domain),
        initial_value_sompi: "2000000000".into(),
        vk_sha256: hex::encode(hash(&vk)),
        funding_txid: founding.id().to_string(),
        funding_full_hash: kaspa_consensus_core::hashing::tx::hash(&founding).to_string(),
    };
    let head = Head {
        transaction_count: 1,
        last_full_hash: descriptor.funding_full_hash.clone(),
    };
    let backup = Backup::new(wallet, &descriptor, &vk, pin(), Some(note)).unwrap();
    let backup = if legacy {
        legacy_fixture(&backup)
    } else {
        backup
    };
    let context = Context::new(
        descriptor,
        vk,
        &[native::tx_json(&founding)],
        &[native::tx_json(&parent)],
        head,
    )
    .unwrap();
    (context, backup)
}
/// Build an explicit serialized pre-v2 fixture without adding a production
/// migration or legacy-creation API. No prior private wallet is read.
fn legacy_fixture(backup: &Backup) -> Backup {
    let mut stored = serde_json::to_value(backup).unwrap();
    stored["format"] = json!("kpi-v6-wallet-backup-v1");
    stored["native_derivation"] = json!("KPI/payout-key/v2");
    serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap()
}
fn rejected<T>(result: Result<T>, cause: &str) {
    let error = result.err().expect("unexpected success").to_string();
    assert!(error.contains(cause), "expected {cause:?}, got {error:?}");
}
fn pay(backup: &Backup, context: &Context, positions: Vec<u32>, value: u64) -> Action {
    Action::Pay {
        positions,
        recipient: backup.receive(&context.descriptor).unwrap(),
        amount_sompi: value.to_string(),
    }
}

/// Isolated scan/selection fixture only. This helper deliberately does NOT
/// generate/validate a proof and is unavailable outside this test module.
/// Production Context::new would reject these placeholder proofs. Genuine
/// proof/native replay coverage lives in replay tests and the lifecycle trace.
fn append_unproved(context: &mut Context, prepared: &Prepared) {
    let (tx, _, state) = settle(
        &context.descriptor.domain,
        &context.replay.state,
        context.replay.reserve.as_ref().unwrap(),
        &context.vk,
        &prepared.bundle,
        prepared.external.as_ref(),
    )
    .unwrap();
    let a = prepared.bundle.auth().unwrap();
    let remaining = context.replay.reserve.as_ref().unwrap().amount
        + prepared.external.as_ref().map_or(0, |u| u.amount)
        - a.payout
        - a.fee;
    context.replay.state = state;
    context.replay.reserve = if remaining == 0 {
        None
    } else {
        Some(native::Utxo::output(&tx, 0, 0))
    };
    context.replay.bootstrap_validated = true;
    context.replay.records.push(replay::PublicRecord {
        full_hash: kaspa_consensus_core::hashing::tx::hash(&tx).to_string(),
        transaction: native::tx_json(&tx),
        authorization_sha256: Some(hex::encode(hash(
            &hex::decode(&prepared.bundle.authorization).unwrap(),
        ))),
        proof_sha256: Some(hex::encode(hash(
            &hex::decode(&prepared.bundle.proof).unwrap(),
        ))),
    });
    context.head.transaction_count += 1;
    context.head.last_full_hash = context.replay.records.last().unwrap().full_hash.clone();
}
fn bootstrapped() -> (Context, Backup) {
    let (mut context, backup) = initial();
    let prepared = context
        .plan(&backup, &pay(&backup, &context, vec![0], 1_960_000_000))
        .unwrap();
    append_unproved(&mut context, &prepared);
    (context, backup)
}

#[test]
fn backup_and_receive_pin_the_typed_descriptor_without_linking_native_address() {
    let (context, backup) = initial();
    let public = serde_json::to_value(backup.receive(&context.descriptor).unwrap()).unwrap();
    assert_eq!(public.as_object().unwrap().len(), 3);
    assert!(public.get("native").is_none());
    assert!(public.get("address").is_none());
    assert_eq!(
        public["descriptor_sha256"],
        descriptor_hash(&context.descriptor).unwrap()
    );
    let before = serde_json::to_vec(&backup).unwrap();
    let inspect = context.inspect(&backup).unwrap();
    assert_eq!(inspect["balance_sompi"], "2000000000");
    assert_eq!(inspect["notes"][0]["position"], 0);
    assert_eq!(before, serde_json::to_vec(&backup).unwrap());
    let mut other = context.descriptor.clone();
    other.domain[0] ^= 1;
    rejected(backup.receive(&other), "pool");
    let mut bad = serde_json::to_value(&backup).unwrap();
    bad["native_derivation"] = json!("different");
    rejected(
        serde_json::from_value::<Backup>(bad)
            .unwrap()
            .check(&context.descriptor),
        "derivation",
    );
}

#[test]
fn backup_versions_accept_only_exact_profiles_without_rewriting() {
    let (context, fresh) = initial();
    assert_eq!(fresh.format, "kpi-v6-wallet-backup-v2");
    assert_eq!(
        fresh.native_derivation,
        "KPI/funding-key/v1+KPI/payout-key/v2"
    );
    let newcomer = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    assert_eq!(newcomer.format, fresh.format);
    assert_eq!(newcomer.native_derivation, fresh.native_derivation);
    let legacy = legacy_fixture(&fresh);
    for (backup, expected_tag) in [
        (&fresh, "KPI/funding-key/v1"),
        (&legacy, "KPI/payout-key/v2"),
    ] {
        let before = serde_json::to_vec(backup).unwrap();
        let restored: Backup = serde_json::from_slice(&before).unwrap();
        restored.check(&context.descriptor).unwrap();
        let display = restored.funding(&context.descriptor, 3).unwrap();
        assert_eq!(display["native_derivation"], expected_tag);
        assert_eq!(
            display["script_public_key"],
            hex::encode(native::encode_spk(
                &native::p2pk(&restored.funding_key(&context.descriptor, 3).unwrap()).unwrap()
            ))
        );
        assert_eq!(before, serde_json::to_vec(&restored).unwrap());
    }
    assert_eq!(
        serde_json::to_value(fresh.receive(&context.descriptor).unwrap()).unwrap(),
        serde_json::to_value(legacy.receive(&context.descriptor).unwrap()).unwrap()
    );
    for index in [0, 3, u32::MAX] {
        assert_eq!(
            legacy.funding_key(&context.descriptor, index).unwrap(),
            legacy.exit_key(&context.descriptor, index).unwrap()
        );
        assert_eq!(
            legacy.exit_key(&context.descriptor, index).unwrap(),
            fresh.exit_key(&context.descriptor, index).unwrap()
        );
        assert_ne!(
            legacy.funding_key(&context.descriptor, index).unwrap(),
            fresh.funding_key(&context.descriptor, index).unwrap()
        );
    }
    for format in [
        "kpi-v6-wallet-backup-v1",
        "kpi-v6-wallet-backup-v2",
        "kpi-v6-wallet-backup-v3",
        "",
    ] {
        for profile in [
            "KPI/payout-key/v2",
            "KPI/funding-key/v1+KPI/payout-key/v2",
            "KPI/funding-key/v1",
            "",
        ] {
            let supported = (format == "kpi-v6-wallet-backup-v1" && profile == "KPI/payout-key/v2")
                || (format == "kpi-v6-wallet-backup-v2"
                    && profile == "KPI/funding-key/v1+KPI/payout-key/v2");
            let mut stored = serde_json::to_value(&fresh).unwrap();
            stored["format"] = json!(format);
            stored["native_derivation"] = json!(profile);
            let loaded: Backup = serde_json::from_value(stored).unwrap();
            assert_eq!(
                loaded.funding_key(&context.descriptor, 0).is_ok(),
                supported
            );
            assert_eq!(loaded.exit_key(&context.descriptor, 0).is_ok(), supported);
            assert_eq!(loaded.receive(&context.descriptor).is_ok(), supported);
            assert_eq!(loaded.funding(&context.descriptor, 0).is_ok(), supported);
        }
    }
    for field in ["format", "native_derivation"] {
        let mut stored = serde_json::to_value(&fresh).unwrap();
        stored.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Backup>(stored).is_err());
    }
}

#[test]
fn restored_legacy_and_v2_backups_sign_actual_native_scripts() {
    for legacy in [true, false] {
        let (context, original) = initial_profile(legacy);
        let bytes = serde_json::to_vec(&original).unwrap();
        let funding = original.funding_key(&context.descriptor, 0).unwrap();
        let exit = original.exit_key(&context.descriptor, 0).unwrap();
        drop(original);
        let restored: Backup = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            restored.funding_key(&context.descriptor, 0).unwrap(),
            funding
        );
        assert_eq!(restored.exit_key(&context.descriptor, 0).unwrap(), exit);
        // Validate the actual founding signature against its public parent.
        let founding = native::parse_tx(&context.replay.records[0].transaction).unwrap();
        let source = native::parse_tx(&context.parents[0]).unwrap();
        assert_eq!(
            source.outputs[0].script_public_key,
            native::p2pk(&funding).unwrap()
        );
        native::validate(
            &founding,
            &[native::Utxo::output(&source, 0, 0).entry().unwrap()],
        )
        .unwrap();
        // Independently constructed ordinary funding/payout UTXOs. This tests
        // restored native control, not pool proof or chain acceptance.
        for key in [funding, exit] {
            let source = parent(&key, 1_000_000_000);
            let input = native::Utxo::output(&source, 0, 0);
            let (spend, entries) = native::ordinary(
                &input,
                &key,
                vec![TransactionOutput::new(
                    500_000_000,
                    native::p2pk(&restored.exit_key(&context.descriptor, 1).unwrap()).unwrap(),
                )],
            )
            .unwrap();
            assert!(native::validate(&spend, &entries).unwrap() > 0);
            if !legacy {
                let wrong = if key == funding { exit } else { funding };
                let mut wrong_signature = spend.clone();
                rejected(
                    native::sign(&mut wrong_signature, &entries, 0, &wrong),
                    "ownership",
                );
            }
        }
        assert_eq!(bytes, serde_json::to_vec(&restored).unwrap());
    }
}

#[test]
fn admission_uses_declared_purpose_without_ownership_fallback() {
    let (mut context, _) = bootstrapped();
    let fresh = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    let legacy = legacy_fixture(&fresh);
    for (key, fresh_accepts) in [
        (
            fresh.wallet.funding_key(&context.descriptor.domain, 3),
            true,
        ),
        (
            fresh.wallet.payout_key(&context.descriptor.domain, 3),
            false,
        ),
    ] {
        let funding = parent(&key, 1_200_000_000);
        context.parents.push(native::tx_json(&funding));
        let action = Action::Admit {
            txid: funding.id().to_string(),
            index: 0,
            native_key_index: 3,
        };
        for (backup, accepts) in [(&fresh, fresh_accepts), (&legacy, !fresh_accepts)] {
            if accepts {
                let plan = context.plan(backup, &action).unwrap();
                assert_eq!(plan.funding_key, Some(key));
            } else {
                rejected(context.plan(backup, &action), "not owned");
            }
        }
    }
}

#[test]
fn original_pre_admission_backup_recovers_receipts_and_exit_for_both_profiles() {
    for legacy in [true, false] {
        let (mut context, founder) = bootstrapped();
        let recipient = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
        let recipient = if legacy {
            legacy_fixture(&recipient)
        } else {
            recipient
        };
        let original_bytes = serde_json::to_vec(&recipient).unwrap();
        let funding = parent(
            &recipient.funding_key(&context.descriptor, 3).unwrap(),
            1_200_000_000,
        );
        context.parents.push(native::tx_json(&funding));
        let admitted = context
            .plan(
                &recipient,
                &Action::Admit {
                    txid: funding.id().to_string(),
                    index: 0,
                    native_key_index: 3,
                },
            )
            .unwrap();
        append_unproved(&mut context, &admitted);
        let address = recipient.receive(&context.descriptor).unwrap();
        drop(recipient);
        let payment = context
            .plan(
                &founder,
                &Action::Pay {
                    positions: vec![1],
                    recipient: address,
                    amount_sompi: "1920000000".into(),
                },
            )
            .unwrap();
        append_unproved(&mut context, &payment);
        drop(founder);
        let restored: Backup = serde_json::from_slice(&original_bytes).unwrap();
        assert_eq!(
            context.inspect(&restored).unwrap()["balance_sompi"],
            "3080000000"
        );
        let exit = context
            .plan(
                &restored,
                &Action::Exit {
                    positions: vec![3, 5],
                    native_key_index: 3,
                },
            )
            .unwrap();
        assert_eq!(exit.bundle.auth().unwrap().payout, 3_040_000_000);
        assert_eq!(
            exit.bundle.auth().unwrap().spk.as_slice(),
            native::encode_spk(
                &native::p2pk(&restored.exit_key(&context.descriptor, 3).unwrap()).unwrap()
            )
        );
        assert_eq!(original_bytes, serde_json::to_vec(&restored).unwrap());
        // Placeholder pool proofs are confined to this selection/scan fixture.
        // The separately frozen offline trial supplies genuine proof/replay.
    }
}

#[test]
fn founder_opening_must_match_owner_value_and_commitment() {
    let (context, backup) = initial();
    for field in ["owner", "incoming", "rho"] {
        let mut changed = serde_json::to_value(&backup).unwrap();
        changed["initial_note"][field][0] =
            json!(changed["initial_note"][field][0].as_u64().unwrap() ^ 1);
        rejected(
            serde_json::from_value::<Backup>(changed)
                .unwrap()
                .check(&context.descriptor),
            "founder",
        );
    }
    let mut changed = backup.clone();
    changed.initial_note.as_mut().unwrap().value -= 1;
    rejected(changed.check(&context.descriptor), "founder");
    let ordinary = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    assert!(ordinary.initial_note.is_none());
    assert_eq!(context.inspect(&ordinary).unwrap()["balance_sompi"], "0");
}

#[test]
fn context_rejects_wrong_head_pool_vk_and_injected_state() {
    let (context, _) = initial();
    let lineage: Vec<Value> = context
        .replay
        .records
        .iter()
        .map(|r| r.transaction.clone())
        .collect();
    let mut head = context.head.clone();
    head.transaction_count += 1;
    rejected(
        Context::new(
            context.descriptor.clone(),
            context.vk.clone(),
            &lineage,
            &context.parents,
            head,
        ),
        "count",
    );
    let mut head = context.head.clone();
    head.last_full_hash = hex::encode([0; 32]);
    rejected(
        Context::new(
            context.descriptor.clone(),
            context.vk.clone(),
            &lineage,
            &context.parents,
            head,
        ),
        "full hash",
    );
    let mut vk = context.vk.clone();
    vk[0] ^= 1;
    rejected(
        Context::new(
            context.descriptor.clone(),
            vk,
            &lineage,
            &context.parents,
            context.head.clone(),
        ),
        "VK",
    );
    let mut descriptor = context.descriptor.clone();
    descriptor.initial_value_sompi = "2000000001".into();
    rejected(
        Context::new(
            descriptor,
            context.vk.clone(),
            &lineage,
            &context.parents,
            context.head.clone(),
        ),
        "reserve",
    );
    let command = json!({"backup":"b","descriptor":"d","vk":"v","lineage":"l","parents":"p","head":"h",
        "action":{"action":"exit","positions":[0],"native_key_index":0}, "state":{}});
    assert!(serde_json::from_value::<Command>(command).is_err());
}

#[test]
fn receipt_validation_does_not_confuse_decryption_with_spendability() {
    let wallet = Wallet::fresh();
    let d = random();
    let good = wallet.receive(&d).note(NOTE_FLOOR).unwrap();
    assert_eq!(
        receipt(
            &wallet,
            &d,
            &good.encrypt(&d).unwrap(),
            &good.commitment(&d)
        )
        .unwrap()
        .unwrap()
        .value,
        NOTE_FLOOR
    );
    let other = Wallet::fresh().receive(&d).note(NOTE_FLOOR).unwrap();
    assert!(
        receipt(
            &wallet,
            &d,
            &other.encrypt(&d).unwrap(),
            &other.commitment(&d)
        )
        .unwrap()
        .is_none()
    );
    assert!(
        receipt(&wallet, &d, &[0; 185], &good.commitment(&d))
            .unwrap()
            .is_none()
    );
    for value in [1, NOTE_FLOOR - 1, MAX_SOMPI + 1] {
        let mut bad = good.clone();
        bad.value = value;
        assert!(receipt(&wallet, &d, &bad.encrypt(&d).unwrap(), &bad.commitment(&d)).is_err());
    }
    let mut zero = good.clone();
    zero.value = 0;
    assert!(
        receipt(
            &wallet,
            &d,
            &zero.encrypt(&d).unwrap(),
            &zero.commitment(&d)
        )
        .unwrap()
        .is_none()
    );
    let mut foreign_owner = good.clone();
    foreign_owner.owner[0] ^= 1;
    rejected(
        receipt(
            &wallet,
            &d,
            &foreign_owner.encrypt(&d).unwrap(),
            &foreign_owner.commitment(&d),
        ),
        "validation",
    );
    rejected(
        receipt(&wallet, &d, &good.encrypt(&d).unwrap(), &[0; 32]),
        "validation",
    );
    rejected(
        receipt(
            &wallet,
            &[0; 32],
            &good.encrypt(&d).unwrap(),
            &good.commitment(&d),
        ),
        "domain",
    );
}

#[test]
fn scanning_tracks_admission_spend_padding_and_positioned_spentness() {
    let (mut context, founder) = bootstrapped();
    let recipient = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    let original_backup = serde_json::to_vec(&recipient).unwrap();
    let funding = parent(
        &recipient.funding_key(&context.descriptor, 0).unwrap(),
        1_200_000_000,
    );
    context.parents.push(native::tx_json(&funding));
    let admission = Action::Admit {
        txid: funding.id().to_string(),
        index: 0,
        native_key_index: 0,
    };
    let prepared = context.plan(&recipient, &admission).unwrap();
    append_unproved(&mut context, &prepared);
    let payment = Action::Pay {
        positions: vec![1],
        recipient: recipient.receive(&context.descriptor).unwrap(),
        amount_sompi: "1920000000".into(),
    };
    let prepared = context.plan(&founder, &payment).unwrap();
    append_unproved(&mut context, &prepared);
    let inspected = context.inspect(&recipient).unwrap();
    assert_eq!(inspected["balance_sompi"], "3080000000");
    assert_eq!(
        inspected["notes"],
        json!([
            {"position":3,"value_sompi":"1160000000","spent":false},
            {"position":5,"value_sompi":"1920000000","spent":false},
        ])
    );
    let prepared = context
        .plan(
            &recipient,
            &pay(&recipient, &context, vec![3, 5], 1_000_000_000),
        )
        .unwrap();
    append_unproved(&mut context, &prepared);
    let inspected = context.inspect(&recipient).unwrap();
    assert_eq!(inspected["balance_sompi"], "3040000000");
    assert_eq!(inspected["notes"][0]["spent"], true);
    assert_eq!(inspected["notes"][1]["spent"], true);
    assert_eq!(inspected["notes"][2]["position"], 7);
    assert_eq!(inspected["notes"][3]["position"], 8);
    assert_eq!(original_backup, serde_json::to_vec(&recipient).unwrap());
    rejected(context.plan(&recipient, &admission), "already consumed");
    rejected(
        context.plan(&recipient, &pay(&recipient, &context, vec![3], NOTE_FLOOR)),
        "already spent",
    );
}

#[test]
fn membership_mismatch_fails_instead_of_crediting_decrypted_value() {
    let (mut context, founder) = bootstrapped();
    context.replay.state.commitments[1][0] ^= 1;
    rejected(context.inspect(&founder), "position");
}

#[test]
fn malformed_decryptable_delivery_cannot_block_existing_owned_notes() {
    let (mut context, founder) = bootstrapped();
    let recipient = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    let funding = parent(
        &recipient.funding_key(&context.descriptor, 0).unwrap(),
        1_200_000_000,
    );
    context.parents.push(native::tx_json(&funding));
    let admission = context
        .plan(
            &recipient,
            &Action::Admit {
                txid: funding.id().to_string(),
                index: 0,
                native_key_index: 0,
            },
        )
        .unwrap();
    append_unproved(&mut context, &admission);
    let mut payment = context
        .plan(
            &founder,
            &Action::Pay {
                positions: vec![1],
                recipient: recipient.receive(&context.descriptor).unwrap(),
                amount_sompi: "60000000".into(),
            },
        )
        .unwrap();
    // The relation binds the cipher digest, not encryption correctness. This
    // isolated fixture encrypts a different opening to the intended recipient;
    // the separate genuine-proof lifecycle fork checks native acceptance.
    let mut malformed = payment.circuit.outputs[0].clone();
    malformed.rho[0] ^= 1;
    payment.bundle.ciphertexts[0] =
        hex::encode(malformed.encrypt(&context.descriptor.domain).unwrap());
    payment.circuit.auth.cipher_hash = hash(&payment.bundle.ciphers().unwrap());
    payment.bundle.authorization = hex::encode(payment.circuit.auth.bytes());
    append_unproved(&mut context, &payment);
    let inspected = context.inspect(&recipient).unwrap();
    assert_eq!(inspected["balance_sompi"], "1160000000");
    assert_eq!(inspected["notes"].as_array().unwrap().len(), 1);
    assert!(
        context
            .plan(
                &recipient,
                &Action::Exit {
                    positions: vec![3],
                    native_key_index: 3,
                }
            )
            .is_ok()
    );
}

#[test]
fn equal_commitments_at_different_positions_have_independent_spentness() {
    let (mut context, founder) = bootstrapped();
    let recipient = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    let funding = parent(
        &recipient.funding_key(&context.descriptor, 0).unwrap(),
        1_200_000_000,
    );
    context.parents.push(native::tx_json(&funding));
    let admission = context
        .plan(
            &recipient,
            &Action::Admit {
                txid: funding.id().to_string(),
                index: 0,
                native_key_index: 0,
            },
        )
        .unwrap();
    append_unproved(&mut context, &admission);
    let received = context.owned(&recipient).unwrap()[0].note.clone();
    let mut payment = context
        .plan(
            &founder,
            &Action::Pay {
                positions: vec![1],
                recipient: recipient.receive(&context.descriptor).unwrap(),
                amount_sompi: "1160000000".into(),
            },
        )
        .unwrap();
    // Equal-valued duplicate note opening, appended at a different position.
    // This isolated fixture retains conservation but uses no generated proof.
    payment.circuit.outputs[0] = received.clone();
    payment.circuit.auth.outputs[0] = received.commitment(&context.descriptor.domain);
    payment.bundle.ciphertexts[0] =
        hex::encode(received.encrypt(&context.descriptor.domain).unwrap());
    payment.circuit.auth.cipher_hash = hash(&payment.bundle.ciphers().unwrap());
    payment.bundle.authorization = hex::encode(payment.circuit.auth.bytes());
    append_unproved(&mut context, &payment);
    assert_eq!(context.owned(&recipient).unwrap().len(), 2);
    let spend = context
        .plan(
            &recipient,
            &pay(&recipient, &context, vec![3], 1_120_000_000),
        )
        .unwrap();
    append_unproved(&mut context, &spend);
    let owned = context.owned(&recipient).unwrap();
    assert!(owned.iter().find(|n| n.position == 3).unwrap().spent);
    assert!(!owned.iter().find(|n| n.position == 5).unwrap().spent);
    assert!(
        context
            .plan(
                &recipient,
                &Action::Exit {
                    positions: vec![5],
                    native_key_index: 5
                }
            )
            .is_ok()
    );
}

#[test]
fn selection_rejects_duplicate_foreign_padding_missing_and_spent_positions() {
    let (context, backup) = bootstrapped();
    for positions in [
        vec![],
        vec![1, 1],
        vec![1, 2, 3],
        vec![2],
        vec![999],
        vec![0],
    ] {
        assert!(
            context
                .plan(&backup, &pay(&backup, &context, positions, NOTE_FLOOR))
                .is_err()
        );
    }
    let foreign = Backup::fresh(&context.descriptor, &context.vk, pin()).unwrap();
    rejected(
        context.plan(&foreign, &pay(&foreign, &context, vec![1], NOTE_FLOOR)),
        "not owned",
    );
}

#[test]
fn arithmetic_rejects_unsafe_change_and_noncanonical_amounts_before_constraints() {
    let (context, backup) = initial();
    for text in [
        "-1",
        "01",
        "1.0",
        "20000000000000000000",
        "0",
        "59999999",
        "2000000000",
        "1900000001",
    ] {
        let action = Action::Pay {
            positions: vec![0],
            recipient: backup.receive(&context.descriptor).unwrap(),
            amount_sompi: text.into(),
        };
        assert!(context.plan(&backup, &action).is_err(), "{text}");
    }
    for value in [NOTE_FLOOR, 1_900_000_000, 1_960_000_000] {
        assert!(
            context
                .plan(&backup, &pay(&backup, &context, vec![0], value))
                .is_ok()
        );
    }
    let mut receive = backup.receive(&context.descriptor).unwrap();
    receive.descriptor_sha256 = hex::encode([0; 32]);
    rejected(
        context.plan(
            &backup,
            &Action::Pay {
                positions: vec![0],
                recipient: receive,
                amount_sompi: "60000000".into(),
            },
        ),
        "recipient",
    );
}

#[test]
fn admission_requires_bootstrap_owned_actual_parent_and_fresh_outpoint() {
    let (context, backup) = initial();
    let point = native::parse_tx(&context.replay.records[0].transaction)
        .unwrap()
        .inputs[0]
        .previous_outpoint
        .clone();
    let action = Action::Admit {
        txid: point.transaction_id.to_string(),
        index: point.index,
        native_key_index: 0,
    };
    rejected(context.plan(&backup, &action), "before bootstrap");
    let (mut context, backup) = bootstrapped();
    let point = native::parse_tx(&context.replay.records[0].transaction)
        .unwrap()
        .inputs[0]
        .previous_outpoint
        .clone();
    rejected(
        context.plan(
            &backup,
            &Action::Admit {
                txid: point.transaction_id.to_string(),
                index: point.index,
                native_key_index: 0,
            },
        ),
        "already consumed",
    );
    rejected(
        context.plan(
            &backup,
            &Action::Admit {
                txid: hex::encode([0; 32]),
                index: 0,
                native_key_index: 0,
            },
        ),
        "missing funding parent",
    );
    let funding = parent(
        &backup.funding_key(&context.descriptor, 0).unwrap(),
        NOTE_FLOOR + FEE - 1,
    );
    context.parents.push(native::tx_json(&funding));
    rejected(
        context.plan(
            &backup,
            &Action::Admit {
                txid: funding.id().to_string(),
                index: 0,
                native_key_index: 0,
            },
        ),
        "floor",
    );
    let funding = parent(
        &backup.funding_key(&context.descriptor, 0).unwrap(),
        NOTE_FLOOR + FEE,
    );
    context.parents.push(native::tx_json(&funding));
    rejected(
        context.plan(
            &backup,
            &Action::Admit {
                txid: funding.id().to_string(),
                index: 0,
                native_key_index: 1,
            },
        ),
        "not owned",
    );
    assert!(
        context
            .plan(
                &backup,
                &Action::Admit {
                    txid: funding.id().to_string(),
                    index: 0,
                    native_key_index: 0
                }
            )
            .is_ok()
    );
}

#[test]
fn exit_destination_and_index_are_reconstructible_from_own_backup() {
    let (context, backup) = bootstrapped();
    rejected(
        context.plan(
            &backup,
            &Action::Exit {
                positions: vec![1],
                native_key_index: 0,
            },
        ),
        "lowest selected",
    );
    let exit = context
        .plan(
            &backup,
            &Action::Exit {
                positions: vec![1],
                native_key_index: 1,
            },
        )
        .unwrap();
    let expected = native::encode_spk(
        &native::p2pk(&backup.exit_key(&context.descriptor, 1).unwrap()).unwrap(),
    );
    assert_eq!(exit.bundle.auth().unwrap().spk.as_slice(), expected);
    assert_eq!(exit.bundle.auth().unwrap().payout, 1_920_000_000);
    let mut raw = serde_json::to_value(Action::Exit {
        positions: vec![1],
        native_key_index: 1,
    })
    .unwrap();
    raw["spk"] = json!(hex::encode(expected));
    assert!(serde_json::from_value::<Action>(raw).is_err());
}

fn private_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!("kpi-v6-wallet-test-{}", hex::encode(random())));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}

#[test]
fn private_backup_creation_is_restrictive_exclusive_and_immutable() {
    let (context, backup) = initial();
    let dir = private_dir();
    let path = dir.join("backup.json");
    backup.save_new(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = fs::read(&path).unwrap();
    assert!(backup.save_new(&path).is_err());
    let restored: Backup = read_json(&path).unwrap();
    assert_eq!(
        context.inspect(&restored).unwrap()["balance_sompi"],
        "2000000000"
    );
    assert_eq!(bytes, fs::read(&path).unwrap());
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(backup.save_new(&link).is_err());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    rejected(backup.save_new(&dir.join("unsafe.json")), "private");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parameters_reject_wrong_size_hash_vk_trailing_bytes_and_invalid_encoding() {
    // Tiny serialization fixture only, not a v6 proving key or new setup.
    let pk = ProvingKey::<Bn254> {
        vk: ark_groth16::VerifyingKey::default(),
        beta_g1: Default::default(),
        delta_g1: Default::default(),
        a_query: vec![],
        b_g1_query: vec![],
        b_g2_query: vec![],
        h_query: vec![],
        l_query: vec![],
    };
    let bytes = harness::compressed(&pk).unwrap();
    let vk = harness::compressed(&pk.vk).unwrap();
    let pin = ParameterPin {
        sha256: hex::encode(hash(&bytes)),
        bytes: bytes.len() as u64,
    };
    let dir = private_dir();
    let path = dir.join("fixture.bin");
    fs::write(&path, &bytes).unwrap();
    assert!(Prover::load(&path, &pin, &vk).is_ok());
    let mut wrong = pin.clone();
    wrong.bytes += 1;
    rejected(Prover::load(&path, &wrong, &vk), "byte length");
    wrong = pin.clone();
    wrong.sha256 = hex::encode([0; 32]);
    rejected(Prover::load(&path, &wrong, &vk), "SHA-256");
    rejected(Prover::load(&path, &pin, &[0; 328]), "VK");
    let mut extra = bytes.clone();
    extra.push(0);
    fs::write(&path, &extra).unwrap();
    rejected(
        Prover::load(
            &path,
            &ParameterPin {
                sha256: hex::encode(hash(&extra)),
                bytes: extra.len() as u64,
            },
            &vk,
        ),
        "trailing",
    );
    fs::write(&path, [0xff; 32]).unwrap();
    assert!(
        Prover::load(
            &path,
            &ParameterPin {
                sha256: hex::encode(hash(&[0xff; 32])),
                bytes: 32
            },
            &vk
        )
        .is_err()
    );
    fs::remove_dir_all(dir).unwrap();
}
