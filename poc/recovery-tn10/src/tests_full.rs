use super::*;
use std::path::PathBuf;

fn temp() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kpi-full-drainage-tn10-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    mkdir(&path).unwrap();
    path
}

fn participants(path: &Path) {
    let wallets = ["A", "B", "M", "S"]
        .iter()
        .enumerate()
        .map(|(index, label)| {
            (
                (*label).to_string(),
                json!({
                    "owner":hex::encode([index as u8 + 1;32]),
                    "incoming":hex::encode([index as u8 + 11;32])
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    report(
        path,
        &json!({
            "schema":"KPI_FULL_DRAINAGE_PUBLIC_PARTICIPANTS_V1",
            "domain":hex::encode(domain()),
            "wallets":wallets
        }),
    )
    .unwrap();
}

fn rpc_utxo(
    point: TransactionOutpoint,
    value: u64,
    spk: ScriptPublicKey,
    covenant: Option<Hash>,
) -> Value {
    serde_json::to_value(kaspa_rpc_core::RpcUtxosByAddressesEntry {
        address: None,
        outpoint: point.into(),
        utxo_entry: kaspa_rpc_core::RpcUtxoEntry::new(value, spk, 0, false, covenant),
    })
    .unwrap()
}

#[test]
fn fresh_identity_is_one_command_and_secret_scoped() {
    let root = temp();
    let input = root.join("participants.json");
    participants(&input);
    let trial = root.join("trial");
    init_full_drainage(&input, &trial).unwrap();
    let value = read(trial.join("trial.json")).unwrap();
    assert_eq!(value["schema"], "KPI_FULL_DRAINAGE_TN10_TRIAL_V1");
    assert_eq!(value["batches"].as_array().unwrap().len(), 7);
    assert_eq!(value["paidComputeAuthorized"], false);
    assert_eq!(value["mainnetAuthorized"], false);
    assert_eq!(value["testKasFundingAndBroadcastAuthorizedByOwner"], true);
    assert_eq!(
        fs::metadata(trial.join("sponsor/native.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn seven_frozen_accounting_checkpoints_and_resource_profiles_match() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../research/full-drainage-executed-lifecycle-2026-11-01/tn10-depth4-preparation/native-fixtures",
    );
    let targets = read(root.join("targets.json")).unwrap();
    let scratch = temp();
    for stage in CASES {
        let state = state(root.join(format!("{stage}.state.bin"))).unwrap();
        batch::lifecycle(stage, &state).unwrap();
        let source = &targets["batches"][stage];
        let pinned = source["segmentPo2"].as_u64().unwrap();
        let effective = if pinned == 20 { 19 } else { pinned };
        let target = json!({
            "schema":"KPI_RECOVERY_TN10_FROZEN_BATCH_V1",
            "trial":"11".repeat(32),
            "stage":stage,
            "image":IMAGE,
            "join":JOIN,
            "programSha256":PROGRAM_SHA,
            "inputSha256":source["inputSha256"],
            "journalHex":source["expectedJournalHex"],
            "journalSha256":source["expectedJournalSha256"],
            "stateSha256":trusted::sha(&fs::read(root.join(format!("{stage}.state.bin"))).unwrap()),
            "segmentPo2":effective,
            "pinnedSegmentPo2":pinned,
            "resourceProfileOverride":effective != pinned,
            "cycleLimit":160_000_000,
            "automaticRetry":false
        });
        let path = scratch.join(format!("{stage}.json"));
        report(&path, &target).unwrap();
        batch::target(&path, &trusted::sha(&fs::read(&path).unwrap())).unwrap();
    }
    fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn both_actual_deposit_layouts_bind_the_requested_owner_and_integer_sompi() {
    let root = temp();
    let participant_path = root.join("participants.json");
    participants(&participant_path);
    let trial_dir = root.join("trial");
    init_full_drainage(&participant_path, &trial_dir).unwrap();
    let trial_path = trial_dir.join("trial.json");
    let trial = read(&trial_path).unwrap();

    let covenant = [44; 32];
    let state = State::genesis(covenant, verifier().id(), [55; 32], 100);
    let checkpoint_dir = root.join("checkpoint");
    mkdir(&checkpoint_dir).unwrap();
    save(
        &checkpoint_dir.join("state.bin"),
        &bincode::serialize(&state).unwrap(),
    )
    .unwrap();
    let state_point = TransactionOutpoint::new(Hash::from_bytes([66; 32]), 0);
    report(
        &checkpoint_dir.join("checkpoint.json"),
        &json!({
            "schema":"KPI_RECOVERY_TN10_CHECKPOINT_V1",
            "status":"CAPTURED_NATIVE_ACCEPTANCE_OFFLINE_RECHECK_REQUIRED",
            "trial":trial["trial"],
            "completed":"initialize",
            "stateRoot":hex::encode(state.root()),
            "stateSha256":trusted::sha(&bincode::serialize(&state).unwrap()),
            "stateOutpoint":{"transactionId":state_point.transaction_id.to_string(),"index":0},
            "nextCaptureStart":hex::encode([77;32])
        }),
    )
    .unwrap();

    let sponsor_pubkey = h(&trial["sponsorNative"]["pubkey"]).unwrap();
    let sponsor_spk = kaspa_txscript::pay_to_address_script(&kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Testnet,
        kaspa_addresses::Version::PubKey,
        &sponsor_pubkey,
    ));
    for (index, label) in ["A", "B"].iter().enumerate() {
        let request_path = root.join(format!("deposit-{label}-request.json"));
        report(
            &request_path,
            &json!({
                "trial":trial["trial"],
                "kind":"deposit",
                "server":{"networkId":"testnet-10","isSynced":true,"virtualDaaScore":1_000_000},
                "feeRateSompiPerGram":100,
                "sponsorUtxo":rpc_utxo(
                    TransactionOutpoint::new(Hash::from_bytes([90 + index as u8;32]),0),
                    1_000_000_000,
                    sponsor_spk.clone(),
                    None
                ),
                "covenantId":hex::encode(covenant),
                "checkpointPath":checkpoint_dir.join("checkpoint.json"),
                "stateUtxo":rpc_utxo(
                    state_point,
                    app::STATE_RENT,
                    kaspa_txscript::standard::pay_to_script_hash_script(&state_script(&state)),
                    Some(Hash::from_bytes(covenant))
                ),
                "depositLabel":label,
                "depositAmountSompi":100_000_000u64
            }),
        )
        .unwrap();
        let output = root.join(format!("deposit-{label}"));
        transaction::build(
            &trial_path,
            &request_path,
            &trial_dir.join("sponsor/native.key"),
            &output,
        )
        .unwrap();
        let record = read(output.join("transaction.json")).unwrap();
        let rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(record["transaction"].clone()).unwrap();
        let tx: Transaction = rpc.try_into().unwrap();
        assert_eq!(tx.outputs[0].value, 100_000_000);
        let applied = app::apply(&state, &native::lane_tx(&tx), &verifier())
            .unwrap()
            .0;
        let deposit = applied.ledger.deposits.values().next().unwrap();
        assert_eq!(deposit.amount, 100_000_000);
        assert_eq!(
            deposit.owner,
            h(&trial["wallets"][*label]["owner"]).unwrap()
        );
        assert_eq!(applied.accounting().unwrap().pending_deposits, 100_000_000);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires the seven locally retained genuine receipts"]
fn all_five_permission_issuance_and_payout_layouts_use_genuine_receipts() {
    let supplied =
        PathBuf::from(std::env::var("KPI_FULL_DRAINAGE_RECEIPTS").expect("receipt directory"));
    let receipt_root = if supplied.is_absolute() {
        supplied
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(supplied)
    };
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../research/full-drainage-executed-lifecycle-2026-11-01/tn10-depth4-preparation/native-fixtures",
    );
    let source_targets = read(fixture_root.join("targets.json")).unwrap();
    let root = temp();
    let participant_path = root.join("participants.json");
    participants(&participant_path);
    let trial_dir = root.join("trial");
    init_full_drainage(&participant_path, &trial_dir).unwrap();
    let trial_path = trial_dir.join("trial.json");
    let trial = read(&trial_path).unwrap();
    let sponsor_pubkey = h(&trial["sponsorNative"]["pubkey"]).unwrap();
    let sponsor_spk = kaspa_txscript::pay_to_address_script(&kaspa_addresses::Address::new(
        kaspa_addresses::Prefix::Testnet,
        kaspa_addresses::Version::PubKey,
        &sponsor_pubkey,
    ));

    for (ordinal, stage) in CASES[1..6].iter().enumerate() {
        let input: Input = bincode::deserialize(
            &fs::read(fixture_root.join(format!("{stage}.input.bin"))).unwrap(),
        )
        .unwrap();
        let after: app::Output = bincode::deserialize(
            &fs::read(fixture_root.join(format!("{stage}.expected.bin"))).unwrap(),
        )
        .unwrap();
        let pending: Vec<_> = after
            .state
            .ledger
            .exits
            .iter()
            .filter(|(_, exit)| !exit.paid)
            .collect();
        assert_eq!(pending.len(), 1);
        let exit_id = *pending[0].0;
        let target_dir = root.join(format!("{stage}-target"));
        mkdir(&target_dir).unwrap();
        save(
            &target_dir.join("prior-state.bin"),
            &bincode::serialize(&input.state).unwrap(),
        )
        .unwrap();
        save(
            &target_dir.join("state.bin"),
            &bincode::serialize(&after.state).unwrap(),
        )
        .unwrap();
        let state_point = TransactionOutpoint::new(Hash::from_bytes([0xa0 + ordinal as u8; 32]), 0);
        let source = &source_targets["batches"][*stage];
        let endpoint = [0xb0 + ordinal as u8; 32];
        let target = json!({
            "schema":"KPI_RECOVERY_TN10_FROZEN_BATCH_V1",
            "trial":trial["trial"],
            "stage":stage,
            "image":IMAGE,
            "join":JOIN,
            "programSha256":PROGRAM_SHA,
            "inputSha256":source["inputSha256"],
            "priorStateSha256":trusted::sha(&bincode::serialize(&input.state).unwrap()),
            "stateSha256":trusted::sha(&bincode::serialize(&after.state).unwrap()),
            "stateOutpoint":{"transactionId":state_point.transaction_id.to_string(),"index":0},
            "endBlock":hex::encode(endpoint),
            "journalHex":source["expectedJournalHex"],
            "journalSha256":source["expectedJournalSha256"],
            "cycleLimit":160_000_000,
            "segmentPo2":19,
            "pinnedSegmentPo2":20,
            "resourceProfileOverride":true,
            "automaticRetry":false
        });
        let target_path = target_dir.join("target.json");
        report(&target_path, &target).unwrap();
        let target_sha = trusted::sha(&fs::read(&target_path).unwrap());
        let receipt_path = receipt_root.join(stage).join("receipt.bin");
        let request_path = root.join(format!("{stage}-settlement-request.json"));
        report(
            &request_path,
            &json!({
                "trial":trial["trial"],
                "kind":"settlement",
                "server":{"networkId":"testnet-10","isSynced":true,"virtualDaaScore":1_000_000},
                "feeRateSompiPerGram":100,
                "sponsorUtxo":rpc_utxo(
                    TransactionOutpoint::new(Hash::from_bytes([0xc0 + ordinal as u8;32]),0),
                    1_000_000_000,
                    sponsor_spk.clone(),
                    None
                ),
                "stateUtxo":rpc_utxo(
                    state_point,
                    app::STATE_RENT,
                    kaspa_txscript::standard::pay_to_script_hash_script(&state_script(&input.state)),
                    Some(Hash::from_bytes(input.state.covenant))
                ),
                "targetPath":target_path,
                "targetSha256":target_sha,
                "receiptPath":receipt_path,
                "anchorBlock":{"block":{"header":{"hash":hex::encode(endpoint),"acceptedIdMerkleRoot":hex::encode(&after.journal[128..160]),"blueScore":10_000},"verboseData":{"isChainBlock":true}}},
                "selectedParentBlock":{"block":{"header":{"blueScore":10_001}}}
            }),
        )
        .unwrap();
        let settlement_dir = root.join(format!("{stage}-settlement"));
        transaction::build(
            &trial_path,
            &request_path,
            &trial_dir.join("sponsor/native.key"),
            &settlement_dir,
        )
        .unwrap();
        let settlement_record = read(settlement_dir.join("transaction.json")).unwrap();
        let settlement_rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(settlement_record["transaction"].clone()).unwrap();
        let settlement: Transaction = settlement_rpc.try_into().unwrap();
        let registered = app::apply(&after.state, &native::lane_tx(&settlement), &verifier())
            .unwrap()
            .0;
        assert!(registered.permissions.contains_key(&exit_id));
        let reserve = registered.exit_reserves[&exit_id].clone();

        let payout_request = root.join(format!("{stage}-payout-request.json"));
        report(
            &payout_request,
            &json!({
                "trial":trial["trial"],
                "kind":"payout",
                "server":{"networkId":"testnet-10","isSynced":true,"virtualDaaScore":1_000_000},
                "feeRateSompiPerGram":100,
                "sponsorUtxo":rpc_utxo(
                    TransactionOutpoint::new(settlement.id(),2),
                    settlement.outputs[2].value,
                    sponsor_spk.clone(),
                    None
                ),
                "publicStatePath":target_dir.join("state.bin"),
                "exitId":hex::encode(exit_id),
                "permissionTransactionPath":settlement_dir.join("transaction.json"),
                "permissionUtxo":rpc_utxo(
                    TransactionOutpoint::new(settlement.id(),1),
                    app::PERMISSION_RENT,
                    settlement.outputs[1].script_public_key.clone(),
                    Some(Hash::from_bytes(registered.covenant))
                ),
                "reserveUtxo":rpc_utxo(
                    native::op(&reserve),
                    registered.reserves[&reserve],
                    ScriptPublicKey::new(0,app::delegate(&registered.covenant).into()),
                    None
                )
            }),
        )
        .unwrap();
        let payout_dir = root.join(format!("{stage}-payout"));
        transaction::build(
            &trial_path,
            &payout_request,
            &trial_dir.join("sponsor/native.key"),
            &payout_dir,
        )
        .unwrap();
        let payout_record = read(payout_dir.join("transaction.json")).unwrap();
        let payout_rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(payout_record["transaction"].clone()).unwrap();
        let payout: Transaction = payout_rpc.try_into().unwrap();
        let reconciled = app::apply(&registered, &native::lane_tx(&payout), &verifier())
            .unwrap()
            .0;
        assert_eq!(reconciled.accounting().unwrap().unpaid_exits, 0);
    }
    fs::remove_dir_all(root).unwrap();
}
