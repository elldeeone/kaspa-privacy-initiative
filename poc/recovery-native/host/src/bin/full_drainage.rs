//! Opt-in depth-four TN10-profile fixture compiler, CPU calibrator and local
//! receipt producer/verifier. It reuses the recovery-native relation and native
//! scripts; it cannot fund, broadcast or claim chain acceptance.
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_hashes::Hash;
use kpi_recovery_native::{
    self as app, chain, lane,
    wallet::{protocol::*, ProofVerifier},
    AcceleratedVerifier, Input, Output, State,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path, str::FromStr, time::Instant};

#[path = "../native.rs"]
mod native;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const STAGES: [&str; 7] = [
    "batch-01", "batch-02", "batch-03", "batch-04", "batch-05", "batch-06", "batch-07",
];
// Pinned risc0-zkp 3.0.4 supports segment powers 13 through 24. Keep the
// experiment's reviewed value as the upper bound; lower values change only the
// prover resource profile and must still pass the exact receipt checks below.
const MIN_SEGMENT_PO2: u32 = 13;

fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn h(value: &str) -> Result<H> {
    Ok(hex::decode(value)?.try_into().map_err(|_| "hash length")?)
}
fn verifier() -> AcceleratedVerifier {
    AcceleratedVerifier::checked(
        include_bytes!("../../../../private-note-chain/pins-full-drainage-depth4-v1/vk.bin"),
        *include_bytes!("../../../../private-note-chain/pins-full-drainage-depth4-v1/vk-id.bin"),
    )
    .unwrap()
}
fn covenant() -> H {
    hash(b"KPI/TN10/full-drainage-depth4-v1/synthetic-covenant")
}
fn save<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::write(path, bincode::serialize(value)?)?;
    Ok(())
}
fn report(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn deposit_tx(owner: H, amount: u64, seed: u8) -> Transaction {
    Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_bytes([seed; 32]), 0),
            vec![],
            0,
            1,
        )],
        vec![TransactionOutput::new(
            amount,
            ScriptPublicKey::new(0, app::delegate(&covenant()).into()),
        )],
        0,
        chain::LANE.into(),
        0,
        chain::deposit_payload(owner, 0),
    )
}

fn deposit(owner: &str, amount: u64, seed: u8, out: &Path) -> Result<()> {
    require(amount > 0, "positive deposit")?;
    let tx = deposit_tx(h(owner)?, amount, seed);
    let lane_tx = native::lane_tx(&tx);
    save(out, &lane_tx)?;
    println!(
        "{}",
        json!({
            "nativeTransactionId": tx.id().to_string(),
            "reference": hex::encode(chain::deposit_reference(tx.id().into(), 0)),
            "amountSompi": amount,
            "output": out,
            "broadcast": false
        })
    );
    Ok(())
}

fn deposit_reference(transaction_id: &str, index: u32) -> Result<()> {
    let id = Hash::from_str(transaction_id)?;
    println!(
        "{}",
        json!({
            "transactionId": transaction_id,
            "index": index,
            "reference": hex::encode(chain::deposit_reference(id.into(), index))
        })
    );
    Ok(())
}

fn encode_operation(operation: &Path, native_pubkey: &str, out: &Path) -> Result<()> {
    require(!out.exists(), "operation payload output exists")?;
    let raw = fs::read(operation)?;
    let operation: Operation = serde_json::from_slice(&raw)?;
    verifier().verify(&operation)?;
    let key = h(native_pubkey)?;
    if operation.statement.kind == EXIT {
        require(
            chain::destination(&key) == operation.statement.exit_destination,
            "exit native key does not match destination",
        )?;
    } else {
        require(
            key == [0; 32],
            "non-exit operation requires zero native key",
        )?;
    }
    report(
        out,
        &json!({
            "schema":"KPI_FULL_DRAINAGE_NATIVE_OPERATION_PAYLOAD_V1",
            "operationSha256":hex::encode(hash(&raw)),
            "operationId":hex::encode(operation.statement.id()),
            "operationPayloadHex":hex::encode(chain::operation_payload(&operation, key)?),
            "nativePubkey":native_pubkey,
            "broadcast":false
        }),
    )?;
    Ok(())
}

fn linked(state: State, mut txs: Vec<lane::Tx>, score: u64) -> Input {
    for (index, tx) in txs.iter_mut().enumerate() {
        tx.merge_idx = index as u32;
    }
    let start = lane::Anchor {
        parent_seq: [1; 32],
        payload_ctx: [2; 32],
        shortcut: [3; 32],
        blue_score: state.last_touch,
        bitmap: [0; 32],
        depth: 0,
        siblings: vec![],
    };
    let mut end = start.clone();
    end.blue_score = score;
    Input {
        lane: lane::Input {
            lane: chain::LANE,
            covenant: state.covenant,
            old_state: state.root(),
            old_tip: state.lane_tip,
            start_seq: lane::bytes(start.seq(
                kaspa_seq_commit::hashing::lane_key(&chain::LANE),
                lane::h(state.lane_tip),
            )),
            start,
            blocks: vec![lane::Block {
                prev_timestamp: score * 1000,
                daa_score: score * 10,
                blue_score: score,
                txs,
            }],
            end,
        },
        state,
    }
}

fn operation(op: &Operation, key: H, seed: u8) -> Result<lane::Tx> {
    Ok(native::lane_tx(&Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(Hash::from_bytes([seed; 32]), 0),
            vec![],
            0,
            1,
        )],
        vec![TransactionOutput::new(
            1,
            ScriptPublicKey::new(0, vec![0x51].into()),
        )],
        0,
        chain::LANE.into(),
        0,
        chain::operation_payload(op, key)?,
    )))
}

struct Prepared {
    cases: Vec<(String, Input, Output)>,
    templates: Vec<Transaction>,
    payouts: Vec<(State, H, Transaction)>,
}

fn read_operations(dir: &Path) -> Result<(Vec<Operation>, Vec<H>)> {
    let mut operations: Vec<Operation> = vec![];
    for index in 1..=10 {
        operations.push(serde_json::from_slice(&fs::read(
            dir.join(format!("operation-{index:02}.json")),
        )?)?);
    }
    let exits: Vec<Value> = serde_json::from_slice(&fs::read(dir.join("native-exits.json"))?)?;
    require(exits.len() == 5, "five native exit keys")?;
    let keys = exits
        .iter()
        .map(|row| h(row["nativePubkey"].as_str().ok_or("native pubkey")?))
        .collect::<Result<Vec<_>>>()?;
    for (op, key) in operations[5..].iter().zip(&keys) {
        require(
            chain::destination(key) == op.statement.exit_destination,
            "native exit key/destination",
        )?;
    }
    Ok((operations, keys))
}

fn exit_id(state: &State) -> Result<H> {
    let exits: Vec<_> = state
        .ledger
        .exits
        .iter()
        .filter(|(_, exit)| !exit.paid)
        .map(|(id, _)| *id)
        .collect();
    require(exits.len() == 1, "one pending exit")?;
    Ok(exits[0])
}

fn settlement(
    state: &State,
    exit: Option<H>,
    previous: TransactionOutpoint,
    seed: u8,
) -> Transaction {
    native::settlement_template(
        state,
        exit,
        previous,
        TransactionOutpoint::new(Hash::from_bytes([seed; 32]), 0),
    )
}

fn scenarios(dir: &Path) -> Result<Prepared> {
    let (ops, exit_keys) = read_operations(dir)?;
    let deposits: Vec<lane::Tx> = (1..=2)
        .map(|index| {
            Ok(bincode::deserialize(&fs::read(
                dir.join(format!("native-deposit-{index:02}.bin")),
            )?)?)
        })
        .collect::<Result<_>>()?;
    let v = verifier();
    let genesis = State::genesis(covenant(), v.id(), [0x11; 32], 10);
    let mut cases = vec![];
    let mut templates = vec![];
    let mut payouts = vec![];

    let mut first = deposits;
    first.extend(
        (0..3)
            .map(|index| operation(&ops[index], [0; 32], 0x30 + index as u8))
            .collect::<Result<Vec<_>>>()?,
    );
    let input = linked(genesis, first, 11);
    let output = app::execute(&input, &v);
    require(
        output.events.iter().all(|event| event.accepted),
        "batch 1 accepted",
    )?;
    cases.push((STAGES[0].into(), input, output));
    templates.push(settlement(
        &cases[0].2.state,
        None,
        TransactionOutpoint::new(Hash::from_bytes([0x70; 32]), 0),
        0x81,
    ));

    let input = linked(
        cases[0].2.state.clone(),
        vec![
            native::lane_tx(&templates[0]),
            operation(&ops[3], [0; 32], 0x33)?,
            operation(&ops[4], [0; 32], 0x34)?,
            operation(&ops[5], exit_keys[0], 0x35)?,
        ],
        12,
    );
    let output = app::execute(&input, &v);
    require(
        output.events.iter().skip(1).all(|event| event.accepted),
        "batch 2 wallet operations accepted",
    )?;
    require(
        output.events[0].error.as_deref() == Some("unrecognized lane operation"),
        "batch 2 prior settlement",
    )?;
    cases.push((STAGES[1].into(), input, output));
    let mut pending = exit_id(&cases[1].2.state)?;
    templates.push(settlement(
        &cases[1].2.state,
        Some(pending),
        TransactionOutpoint::new(templates[0].id(), 0),
        0x82,
    ));

    for next_exit in 1..5 {
        let state = cases.last().unwrap().2.state.clone();
        let registered = app::apply(&state, &native::lane_tx(templates.last().unwrap()), &v)?.0;
        let (payout, entries) = native::payout(&registered, pending, "")?;
        require(
            native::scripts(&payout, &entries)?.is_ok(),
            "native payout scripts",
        )?;
        payouts.push((registered, pending, payout.clone()));
        let stage = next_exit + 1;
        let input = linked(
            state,
            vec![
                native::lane_tx(templates.last().unwrap()),
                native::lane_tx(&payout),
                operation(
                    &ops[5 + next_exit],
                    exit_keys[next_exit],
                    0x35 + next_exit as u8,
                )?,
            ],
            11 + stage as u64,
        );
        let output = app::execute(&input, &v);
        require(
            output.events.iter().all(|event| event.accepted),
            "payout plus next exit",
        )?;
        cases.push((STAGES[stage].into(), input, output));
        pending = exit_id(&cases.last().unwrap().2.state)?;
        templates.push(settlement(
            &cases.last().unwrap().2.state,
            Some(pending),
            TransactionOutpoint::new(templates.last().unwrap().id(), 0),
            0x81 + cases.len() as u8,
        ));
    }

    let state = cases.last().unwrap().2.state.clone();
    let registered = app::apply(&state, &native::lane_tx(templates.last().unwrap()), &v)?.0;
    let (payout, entries) = native::payout(&registered, pending, "")?;
    require(
        native::scripts(&payout, &entries)?.is_ok(),
        "final native payout scripts",
    )?;
    payouts.push((registered, pending, payout.clone()));
    let input = linked(
        state,
        vec![
            native::lane_tx(templates.last().unwrap()),
            native::lane_tx(&payout),
        ],
        17,
    );
    let output = app::execute(&input, &v);
    require(
        output.events.iter().all(|event| event.accepted),
        "final payout",
    )?;
    require(
        output.state.accounting()?.reserve_principal == 0
            && output.state.accounting()?.private_liability == 0
            && output.state.accounting()?.pending_deposits == 0
            && output.state.accounting()?.unpaid_exits == 0
            && output
                .state
                .accounting()?
                .outstanding_permission_rent_excluded
                == 0,
        "zero terminal principal accounting",
    )?;
    cases.push((STAGES[6].into(), input, output));
    templates.push(settlement(
        &cases.last().unwrap().2.state,
        None,
        TransactionOutpoint::new(templates.last().unwrap().id(), 0),
        0x87,
    ));
    Ok(Prepared {
        cases,
        templates,
        payouts,
    })
}

fn native_history(cases: &[(String, Input, Output)]) -> Result<Value> {
    let mut spent = BTreeMap::new();
    let mut conflicts = vec![];
    let mut count = 0usize;
    for (stage, input, _) in cases {
        for block in &input.lane.blocks {
            for (index, tx) in block.txs.iter().enumerate() {
                let body = app::NativeTx::parse(&tx.rest)?;
                for outpoint in body.inputs {
                    count += 1;
                    let location = json!({"stage":stage,"transactionIndex":index});
                    if let Some(first) = spent.insert(outpoint.clone(), location.clone()) {
                        conflicts.push(json!({"outpoint":outpoint,"first":first,"again":location}));
                    }
                }
            }
        }
    }
    Ok(json!({"transactionInputs":count,"uniqueInputs":spent.len(),"conflicts":conflicts}))
}

fn prepare(operations: &Path, old_operation: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let prepared = scenarios(operations)?;
    let history = native_history(&prepared.cases)?;
    require(
        history["conflicts"].as_array().is_some_and(Vec::is_empty),
        "native input reuse",
    )?;
    report(&out.join("native-history.json"), &history)?;
    let mut targets = serde_json::Map::new();
    let mut accounting = vec![];
    for (index, (name, input, expected)) in prepared.cases.iter().enumerate() {
        save(&out.join(format!("{name}.input.bin")), input)?;
        save(&out.join(format!("{name}.expected.bin")), expected)?;
        save(&out.join(format!("{name}.state.bin")), &expected.state)?;
        fs::write(out.join(format!("{name}.journal.bin")), &expected.journal)?;
        save(
            &out.join(format!("{name}.template.bin")),
            &prepared.templates[index],
        )?;
        let raw = bincode::serialize(input)?;
        targets.insert(
            name.clone(),
            json!({
                "inputSha256":hex::encode(hash(&raw)),
                "expectedJournalHex":hex::encode(&expected.journal),
                "expectedJournalSha256":hex::encode(hash(&expected.journal)),
                "segmentPo2":if index == 6 {16} else {20},
                "accounting":expected.state.accounting()?
            }),
        );
        accounting.push(json!({"stage":name,"root":hex::encode(expected.state.root()),"tip":hex::encode(expected.state.lane_tip),"accounting":expected.state.accounting()?}));
    }

    let (operations, exit_keys) = read_operations(operations)?;
    let mut wrong_domain = operations[0].clone();
    wrong_domain.statement.domain[0] ^= 1;
    let mut wrong_root = operations[2].clone();
    wrong_root.statement.anchor[0] ^= 1;
    let old = AcceleratedVerifier::checked(
        include_bytes!("../../../../private-note-chain/pins/vk.bin"),
        *include_bytes!("../../../../private-note-chain/pins/vk-id.bin"),
    )?;
    let cross_profile = old.verify(&operations[0]).is_err();
    let old_operation: Operation = serde_json::from_slice(&fs::read(old_operation)?)?;
    let reverse_cross_profile = verifier().verify(&old_operation).is_err();
    require(
        verifier().verify(&wrong_domain).is_err(),
        "wrong domain rejected",
    )?;
    require(
        verifier().verify(&wrong_root).is_err(),
        "wrong root rejected",
    )?;
    require(cross_profile, "old verifier rejects new profile")?;
    require(reverse_cross_profile, "new verifier rejects local profile")?;

    let mut native_controls = vec![];
    for (index, (registered, exit, _)) in prepared.payouts.iter().enumerate() {
        let exit_state = &registered.ledger.exits[exit];
        let reserve_value = registered.reserves[&registered.exit_reserves[exit]];
        let mut attacks = vec!["underpay", "wrong-recipient"];
        if reserve_value > exit_state.amount {
            attacks.push("reserve-diversion");
        }
        for attack in attacks {
            let (tx, entries) = native::payout(registered, *exit, attack)?;
            let rejected = native::scripts(&tx, &entries)?.is_err();
            require(rejected, "mutated payout script rejected")?;
            native_controls.push(json!({"payout":index+1,"attack":attack,"rejected":rejected}));
        }
    }
    let replay = app::apply(
        &prepared.cases.last().unwrap().2.state,
        &operation(&operations[5], exit_keys[0], 0x7f)?,
        &verifier(),
    )
    .is_err();
    require(replay, "exit replay rejected")?;
    report(
        &out.join("controls.json"),
        &json!({"wrongDomainRejected":true,"wrongRootRejected":true,"oldVerifierRejectedNewProfile":cross_profile,"newVerifierRejectedLocalProfile":reverse_cross_profile,"exitReplayRejected":replay,"nativePayoutMutations":native_controls}),
    )?;
    report(
        &out.join("targets.json"),
        &json!({"scope":"SEVEN_EXACT_CPU_TARGETS_NO_OUTER_RECEIPTS_OR_CHAIN_ACCEPTANCE","expectedProgramImage":include_str!("../../../evidence-full-drainage-depth4-v1/expected-image.txt").trim(),"batches":targets}),
    )?;
    report(
        &out.join("lifecycle.json"),
        &json!({"scope":"FRESH_DEPTH4_WALLET_PROOFS_AND_LOCAL_NATIVE_SCRIPTS_NOT_TN10_ACCEPTANCE","stages":STAGES,"accounting":accounting,"walletVerifier":hex::encode(verifier().id()),"guestImage":include_str!("../../../evidence-full-drainage-depth4-v1/expected-image.txt").trim(),"outerReceipts":0,"broadcast":false,"funding":false}),
    )?;
    Ok(())
}

fn profile(program: &Path, fixtures: &Path, stage: &str, out: &Path) -> Result<()> {
    use risc0_zkvm::{compute_image_id, default_executor, ExecutorEnv};
    require(STAGES.contains(&stage), "known stage")?;
    fs::create_dir(out)?;
    let program = fs::read(program)?;
    let image = compute_image_id(&program)?.to_string();
    require(
        image
            == include_str!("../../../evidence-full-drainage-depth4-v1/expected-image.txt").trim(),
        "guest image",
    )?;
    let raw = fs::read(fixtures.join(format!("{stage}.input.bin")))?;
    let index = STAGES.iter().position(|value| *value == stage).unwrap();
    let po2 = if index == 6 { 16 } else { 20 };
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(&[raw.len() as u32])
        .write_slice(&raw)
        .segment_limit_po2(po2)
        .session_limit(Some(app::CYCLE_LIMIT));
    let started = Instant::now();
    let session = default_executor().execute(builder.build()?, &program)?;
    let expected: Output =
        bincode::deserialize(&fs::read(fixtures.join(format!("{stage}.expected.bin")))?)?;
    require(session.journal.bytes == expected.journal, "exact journal")?;
    report(
        &out.join("report.json"),
        &json!({"scope":"EXACT_GUEST_CPU_EXECUTION_NO_RECEIPT","stage":stage,"image":image,"userCycles":session.cycles(),"segments":session.segments.len(),"segmentPo2":po2,"seconds":started.elapsed().as_secs_f64(),"journalSha256":hex::encode(hash(&session.journal.bytes)),"cycleLimit":app::CYCLE_LIMIT,"exactExpectedJournalMatched":true}),
    )?;
    fs::write(out.join("journal.bin"), session.journal.bytes)?;
    Ok(())
}

#[cfg(feature = "proof")]
fn proof_target(
    program: &Path,
    fixtures: &Path,
    stage: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, u32, String)> {
    use kpi_private_note_proof as trusted;
    require(STAGES.contains(&stage), "known stage")?;
    let targets: Value = serde_json::from_slice(&fs::read(fixtures.join("targets.json"))?)?;
    let row = &targets["batches"][stage];
    let program = fs::read(program)?;
    let input = fs::read(fixtures.join(format!("{stage}.input.bin")))?;
    let journal = fs::read(fixtures.join(format!("{stage}.journal.bin")))?;
    let image = risc0_zkvm::compute_image_id(&program)?.to_string();
    require(
        image
            == targets["expectedProgramImage"]
                .as_str()
                .ok_or("image pin")?,
        "program image",
    )?;
    require(
        trusted::sha(&input) == row["inputSha256"].as_str().ok_or("input pin")?,
        "input hash",
    )?;
    require(
        trusted::sha(&journal) == row["expectedJournalSha256"].as_str().ok_or("journal pin")?,
        "journal hash",
    )?;
    let po2 = u32::try_from(row["segmentPo2"].as_u64().ok_or("segment profile")?)?;
    Ok((program, input, journal, po2, image))
}

#[cfg(feature = "proof")]
fn prove(
    program: &Path,
    fixtures: &Path,
    stage: &str,
    segment_po2_override: Option<u32>,
    out: &Path,
) -> Result<()> {
    use kpi_private_note_proof as trusted;
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
    let (program, input, journal, pinned_po2, image) = proof_target(program, fixtures, stage)?;
    let po2 = segment_po2_override.unwrap_or(pinned_po2);
    require(
        (MIN_SEGMENT_PO2..=pinned_po2).contains(&po2),
        "segment po2 override must be supported and no larger than the pinned profile",
    )?;
    fs::create_dir(out)?;
    report(
        &out.join("started.json"),
        &json!({"scope":"ONE_EXACT_FULL_DRAINAGE_SUCCINCT_PROOF","stage":stage,"image":image,"segmentPo2":po2,"pinnedSegmentPo2":pinned_po2,"resourceProfileOverride":segment_po2_override.is_some(),"cycleLimit":app::CYCLE_LIMIT,"developmentMode":false,"automaticRetry":false}),
    )?;
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(&[u32::try_from(input.len())?])
        .write_slice(&input)
        .segment_limit_po2(po2)
        .session_limit(Some(app::CYCLE_LIMIT));
    let started = Instant::now();
    let info =
        default_prover().prove_with_opts(builder.build()?, &program, &ProverOpts::succinct())?;
    let bytes = bincode::serialize(&info.receipt)?;
    fs::write(out.join("candidate-receipt.bin"), &bytes)?;
    trusted::verify_claim(
        &info.receipt,
        trusted::digest(&image)?,
        &journal,
        trusted::digest(trusted::JOIN)?,
    )?;
    require(
        info.stats.user_cycles <= app::CYCLE_LIMIT,
        "proof cycle limit",
    )?;
    fs::write(out.join("receipt.bin"), &bytes)?;
    report(&out.join("stats.json"), &serde_json::to_value(&info.stats)?)?;
    report(
        &out.join("complete.json"),
        &json!({"stage":stage,"image":image,"receiptSha256":trusted::sha(&bytes),"seconds":started.elapsed().as_secs_f64(),"segmentPo2":po2,"pinnedSegmentPo2":pinned_po2,"resourceProfileOverride":segment_po2_override.is_some(),"exactImageJournalAndJoinControlVerified":true,"independentCpuVerificationStillRequired":true,"actualTN10Settlement":false}),
    )
}

#[cfg(feature = "proof")]
fn verify_receipt(
    program: &Path,
    fixtures: &Path,
    stage: &str,
    receipt: &Path,
    out: &Path,
) -> Result<()> {
    use kpi_private_note_proof as trusted;
    let (_, _, journal, _, image) = proof_target(program, fixtures, stage)?;
    let receipt = trusted::read_receipt(receipt)?;
    trusted::verify_claim(
        &receipt,
        trusted::digest(&image)?,
        &journal,
        trusted::digest(trusted::JOIN)?,
    )?;
    let negatives = trusted::crypto_negatives(&receipt, trusted::digest(&image)?)?;
    fs::create_dir(out)?;
    report(
        &out.join("verification.json"),
        &json!({"scope":"INDEPENDENT_PROCESS_CPU_RECEIPT_VERIFICATION","stage":stage,"image":image,"exactJournalVerified":true,"developmentMode":false,"negativeControls":negatives}),
    )
}

#[cfg(feature = "proof")]
struct RehearsalAnchor(kaspa_hashes::Hash, kaspa_hashes::Hash);

#[cfg(feature = "proof")]
impl kaspa_txscript::seq_commit_accessor::SeqCommitAccessor for RehearsalAnchor {
    fn is_chain_ancestor_from_pov(&self, block: kaspa_hashes::Hash) -> Option<bool> {
        Some(block == self.0)
    }

    fn seq_commitment_within_depth(&self, block: kaspa_hashes::Hash) -> Option<kaspa_hashes::Hash> {
        (block == self.0).then_some(self.1)
    }
}

#[cfg(feature = "proof")]
fn receipt_backed_rehearsal(
    program: &Path,
    fixtures: &Path,
    receipts: &Path,
    out: &Path,
) -> Result<()> {
    use kaspa_consensus_core::tx::{PopulatedTransaction, UtxoEntry};
    use kaspa_txscript::{
        caches::Cache, covenants::CovenantsContext, engine_context::EngineContext,
        standard::pay_to_script_hash_script, EngineFlags, TxScriptEngine,
    };
    use kpi_private_note_proof as trusted;
    use risc0_zkvm::sha::Digestible;
    use vprogs_zk_backend_risc0_covenant::{
        script::{CommonPins, RedeemPins, SuccinctPins},
        Settlement, SettlementInput, SettlementWitness, SuccinctWitness,
    };

    fs::create_dir(out)?;
    let mut rows = vec![];
    for (index, stage) in STAGES.iter().enumerate() {
        let (_, _, journal, segment_po2, image) = proof_target(program, fixtures, stage)?;
        let input: Input =
            bincode::deserialize(&fs::read(fixtures.join(format!("{stage}.input.bin")))?)?;
        let output: Output =
            bincode::deserialize(&fs::read(fixtures.join(format!("{stage}.expected.bin")))?)?;
        let template: Transaction =
            bincode::deserialize(&fs::read(fixtures.join(format!("{stage}.template.bin")))?)?;
        require(output.journal == journal, "fixture journal")?;
        let fields: [[u8; 32]; 11] =
            std::array::from_fn(|n| journal[n * 32..n * 32 + 32].try_into().unwrap());
        require(
            input.state.root() == fields[0]
                && input.state.lane_tip == fields[1]
                && output.state.root() == fields[2]
                && output.state.lane_tip == fields[3]
                && output.state.covenant == fields[5],
            "exact settlement journal/state binding",
        )?;

        let receipt_path = receipts.join(stage).join("receipt.bin");
        let receipt = trusted::read_receipt(&receipt_path)?;
        trusted::verify_claim(
            &receipt,
            trusted::digest(&image)?,
            &journal,
            trusted::digest(trusted::JOIN)?,
        )?;
        trusted::crypto_negatives(&receipt, trusted::digest(&image)?)?;
        let succinct = receipt.inner.succinct()?;
        let seal: Vec<_> = succinct
            .seal
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let inclusion: Vec<_> = succinct
            .control_inclusion_proof
            .digests
            .iter()
            .flat_map(|value| <[u8; 32]>::from(*value))
            .collect();
        let lane_key = Hash::from_bytes(fields[10]);
        let covenant = Hash::from_bytes(fields[5]);
        let endpoint = Hash::from_bytes(hash(
            &[
                b"KPI/full-drainage/rehearsal-anchor/v1".as_slice(),
                stage.as_bytes(),
            ]
            .concat(),
        ));
        let image_bytes: H = hex::decode(&image)?
            .try_into()
            .map_err(|_| "image length")?;
        let pins = RedeemPins::SuccinctJoin(SuccinctPins {
            common: CommonPins {
                program_id: &image_bytes,
                tx_image_id: &fields[6],
                batch_image_id: &fields[7],
                lane_key: &lane_key,
                permission_output_value: app::PERMISSION_RENT,
            },
        });
        let claim: H = succinct.claim.digest().into();
        let mut built = Settlement::build(&SettlementInput {
            covenant_id: covenant,
            pins,
            prev_state: &fields[0],
            prev_lane_tip: &Hash::from_bytes(fields[1]),
            new_state: &fields[2],
            new_lane_tip: &Hash::from_bytes(fields[3]),
            block_prove_to: endpoint,
            prev_outpoint: template.inputs[0].previous_outpoint,
            value: app::STATE_RENT,
            witness: SettlementWitness::Succinct(SuccinctWitness {
                seal: &seal,
                claim: &claim,
                control_index: succinct.control_inclusion_proof.index,
                control_digests: &inclusion,
                deposit_spk_hash: &fields[9],
            }),
            permission_spk_hash: &fields[8],
        });
        native::restrict_settlement(
            &mut built,
            &fields[0],
            &Hash::from_bytes(fields[1]),
            &fields[2],
            &Hash::from_bytes(fields[3]),
            &pins,
        )?;
        built.transaction.inputs.push(template.inputs[1].clone());
        built.transaction.subnetwork_id = template.subnetwork_id.clone();
        built.transaction.payload = template.payload.clone();
        built.transaction.finalize();
        require(
            built.transaction.id() == template.id(),
            "receipt-backed settlement/template ID",
        )?;

        let sponsor_value = if fields[8] == [0; 32] {
            100_000
        } else {
            app::PERMISSION_RENT + 100_000
        };
        let entries = vec![
            UtxoEntry::new(
                app::STATE_RENT,
                pay_to_script_hash_script(&built.prev_redeem),
                0,
                false,
                Some(covenant),
            ),
            UtxoEntry::new(
                sponsor_value,
                ScriptPublicKey::new(0, vec![0x51].into()),
                0,
                false,
                None,
            ),
        ];
        let populated = PopulatedTransaction::new(&built.transaction, entries.clone());
        let covenant_context = CovenantsContext::from_tx(&populated)?;
        let cache = Cache::new(20);
        let reused = kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
        let anchor = RehearsalAnchor(endpoint, Hash::from_bytes(fields[4]));
        let mut issuance_units = vec![];
        for (input_index, entry) in entries.iter().enumerate() {
            let engine_context = EngineContext::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&covenant_context)
                .with_seq_commit_accessor(&anchor);
            let mut engine = TxScriptEngine::from_transaction_input(
                &populated,
                &built.transaction.inputs[input_index],
                input_index,
                entry,
                engine_context,
                EngineFlags::default(),
            );
            engine.execute()?;
            issuance_units.push(engine.used_script_units().0);
        }

        let mut payout_units = Value::Null;
        if fields[8] != [0; 32] {
            let registered = app::apply(
                &output.state,
                &native::lane_tx(&built.transaction),
                &verifier(),
            )?
            .0;
            let exit_id = exit_id(&registered)?;
            let (payout, payout_entries) = native::payout(&registered, exit_id, "")?;
            let units = native::scripts(&payout, &payout_entries)??;
            require(index + 1 < STAGES.len(), "payout reconciliation stage")?;
            let next_input: Input = bincode::deserialize(&fs::read(
                fixtures.join(format!("{}.input.bin", STAGES[index + 1])),
            )?)?;
            let expected_payout = &next_input.lane.blocks[0].txs[1];
            require(
                payout.id()
                    == vprogs_l1_utils::tx_id_v1(&expected_payout.payload, &expected_payout.rest)
                        .into(),
                "receipt-backed payout/frozen next batch ID",
            )?;
            payout_units = serde_json::to_value(units)?;
        }

        rows.push(json!({
            "stage":stage,
            "receiptSha256":trusted::sha(&fs::read(&receipt_path)?),
            "targetSegmentPo2":segment_po2,
            "exactReceiptVerified":true,
            "settlementTransactionId":built.transaction.id().to_string(),
            "frozenTemplateIdMatched":true,
            "issuanceScriptUnits":issuance_units,
            "payoutScriptUnits":payout_units
        }));
    }
    let terminal: Output =
        bincode::deserialize(&fs::read(fixtures.join("batch-07.expected.bin"))?)?;
    let accounting = terminal.state.accounting()?;
    require(
        accounting.reserve_principal == 0
            && accounting.private_liability == 0
            && accounting.pending_deposits == 0
            && accounting.unpaid_exits == 0
            && accounting.outstanding_permission_rent_excluded == 0,
        "receipt-backed terminal accounting",
    )?;
    report(
        &out.join("rehearsal.json"),
        &json!({"scope":"SEVEN_GENUINE_RECEIPTS_NATIVE_SETTLEMENT_AND_PAYOUT_LOCAL_CONTEXT_NOT_TN10","allReceiptsIndependentlyVerified":true,"allSettlementIdsMatchedFrozenTemplates":true,"allNativeIssuanceAndPayoutScriptsAccepted":true,"terminalAccounting":accounting,"nativeBroadcast":false,"stages":rows}),
    )
}

fn main() -> Result<()> {
    require(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "development mode forbidden",
    )?;
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("deposit") if args.len() == 6 => deposit(
            &args[2],
            args[3].parse()?,
            args[4].parse()?,
            Path::new(&args[5]),
        ),
        Some("deposit-reference") if args.len() == 4 => {
            deposit_reference(&args[2], args[3].parse().map_err(|_| "output index")?)
        }
        Some("encode-operation") if args.len() == 5 => {
            encode_operation(Path::new(&args[2]), &args[3], Path::new(&args[4]))
        }
        Some("prepare") if args.len() == 5 => prepare(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ),
        Some("profile") if args.len() == 6 => profile(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &args[4],
            Path::new(&args[5]),
        ),
        #[cfg(feature = "proof")]
        Some("prove") if args.len() == 6 => prove(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &args[4],
            None,
            Path::new(&args[5]),
        ),
        #[cfg(feature = "proof")]
        Some("prove-with-segment-po2") if args.len() == 7 => prove(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &args[4],
            Some(args[5].parse()?),
            Path::new(&args[6]),
        ),
        #[cfg(feature = "proof")]
        Some("verify-receipt") if args.len() == 7 => verify_receipt(
            Path::new(&args[2]),
            Path::new(&args[3]),
            &args[4],
            Path::new(&args[5]),
            Path::new(&args[6]),
        ),
        #[cfg(feature = "proof")]
        Some("rehearse-receipts") if args.len() == 6 => receipt_backed_rehearsal(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
            Path::new(&args[5]),
        ),
        _ => Err("usage: deposit OWNER AMOUNT SEED OUT | deposit-reference TXID INDEX | encode-operation OPERATION NATIVE_PUBKEY OUT | prepare OPERATIONS OLD_PROFILE_OPERATION OUT | profile PROGRAM FIXTURES STAGE OUT | prove PROGRAM FIXTURES STAGE OUT | prove-with-segment-po2 PROGRAM FIXTURES STAGE PO2 OUT | verify-receipt PROGRAM FIXTURES STAGE RECEIPT OUT | rehearse-receipts PROGRAM FIXTURES RECEIPTS OUT".into()),
    }
}
