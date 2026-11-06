mod circuit;
mod lifecycle;
mod native;
mod proof;
mod registration;
mod replay;
mod trials;
use rand::rngs::OsRng;
use serde_json::json;
use std::{fs, path::Path, time::Instant};
fn write(p: &Path, v: &serde_json::Value) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .unwrap();
    writeln!(f, "{}", serde_json::to_string_pretty(v).unwrap()).unwrap();
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("verify-public") {
        println!(
            "{}",
            replay::verify(Path::new(&std::env::args().nth(2).unwrap()))
        );
        return;
    }
    let out = std::env::args().nth(1).expect("fresh directory");
    let out = Path::new(&out);
    assert!(!out.exists());
    fs::create_dir_all(out.join("public")).unwrap();
    fs::create_dir(out.join("private")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let mut l = lifecycle::build();
    let secp = secp256k1::Secp256k1::new();
    let keys: [proof::H; 3] = std::array::from_fn(|_| {
        secp256k1::Keypair::new(&secp, &mut OsRng)
            .x_only_public_key()
            .0
            .serialize()
    });
    let original_exits = lifecycle::direct_exits(&mut l, &keys);
    assert_eq!(l.old_state.reserve, 0);
    assert_eq!(l.old_state.private_liability, 0);
    let claims = std::array::from_fn(|i| {
        kpi_private_note_wallet::protocol::nullifier(&l.witnesses[i].secret, &l.witnesses[i].input)
    });
    let anchor = l.state.tree.root();
    let registration = registration::run(&mut l.engine, &l.witnesses, anchor, claims, keys);
    let spks = std::array::from_fn(|i| {
        kaspa_consensus_core::tx::ScriptPublicKey::new(
            0,
            [vec![32], keys[i].to_vec(), vec![0xac]].concat().into(),
        )
    });
    let native = trials::run(
        &mut l.engine,
        &l.witnesses,
        &spks,
        anchor,
        &l.state.nullifiers,
        &original_exits[0],
    );
    // Reconcile only after successful native whole-set execution. These are
    // local supplied-state confirmations, never assertions of accepted ancestry.
    assert!(native::execute(&native.policy, 7, &native.joint).is_ok());
    for (i, op) in native.auth.iter().enumerate() {
        l.state.apply(&l.engine, op).unwrap();
        let key_index = native
            .joint
            .outputs
            .iter()
            .position(|o| o.script_public_key == spks[i])
            .unwrap();
        let output_id = proof::hash(
            &[
                native.joint.id().as_bytes().as_slice(),
                &(key_index as u64).to_le_bytes(),
            ]
            .concat(),
        );
        l.state
            .confirm_authenticated_fixture_payout(
                op.statement.id(),
                native::PRINCIPAL,
                op.statement.exit_destination,
                output_id,
            )
            .unwrap();
    }
    assert_eq!(l.state.reserve, 0);
    assert_eq!(l.state.private_liability, 0);
    assert!(l.state.exits.values().all(|e| e.paid));
    let mut candidate = registration.candidate;
    candidate["native"] = native.public_native.clone();
    candidate["walletHistory"] = json!({"operations":l.ops,"verifyingKey":hex::encode(proof::serialize(&l.engine.vk)),"anchor":hex::encode(anchor),"priorSpentNullifiers":l.ops.iter().skip(1).map(|op|hex::encode(op.statement.nullifier)).collect::<Vec<_>>(),"nativeAuthorizations":native.auth,"genesis":"actual wallet kernel; supplied native reserve"});
    let mut baseline = registration.baseline;
    baseline["native"] = native.public_native.clone();
    baseline["walletHistory"] = candidate["walletHistory"].clone();
    baseline["originalWalletHistory"] = json!({"operations":l.old_ops,"exits":original_exits,"verifyingKey":hex::encode(l.old.vk_bytes())});
    write(&out.join("public/candidate.json"), &candidate);
    write(&out.join("public/baseline.json"), &baseline);
    let links = (0..3)
        .map(|i| json!({"owner":format!("owner-{}",i+1),"recipientKey":hex::encode(keys[i])}))
        .collect::<Vec<_>>();
    for (name, indices) in [
        ("one-participant", vec![0]),
        ("all-but-one", vec![0, 1]),
        ("known-payout-owners", vec![0, 1, 2]),
    ] {
        let mut view = candidate.clone();
        view["explicitOwnerLinks"] = json!(
            indices
                .into_iter()
                .map(|i| links[i].clone())
                .collect::<Vec<_>>()
        );
        write(&out.join(format!("public/{name}.json")), &view);
    }
    let mut echo = candidate.clone();
    for e in echo["events"].as_array_mut().unwrap() {
        if e["kind"] == "redeem" {
            let i = keys
                .iter()
                .position(|k| hex::encode(k) == e["recipientKey"].as_str().unwrap())
                .unwrap();
            e["owner"] = json!(format!("owner-{}", i + 1));
        }
    }
    write(&out.join("public/echoed-origin.json"), &echo);
    let mut leak = candidate.clone();
    for e in leak["events"].as_array_mut().unwrap() {
        if e["kind"] == "issue" {
            let i = e["owner"]
                .as_str()
                .unwrap()
                .strip_prefix("owner-")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                - 1;
            e["leakedRandomizer"] = json!(hex::encode(registration.randomizers[i]));
        }
    }
    write(&out.join("public/leaked-issuance-randomizer.json"), &leak);
    let mut legacy = candidate.clone();
    legacy["previouslyPublishedIndividualExits"] = json!(links.clone());
    write(&out.join("public/legacy-public-exits.json"), &legacy);
    write(
        &out.join("private/truth.json"),
        &json!({"ownerToRecipient":links}),
    );
    fs::set_permissions(
        out.join("private/truth.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        out.join("public/verification-key.hex"),
        format!("{}\n", hex::encode(proof::serialize(&l.engine.vk))),
    )
    .unwrap();
    let base = kaspa_txscript::zk_precompiles::tags::ZkTag::Groth16
        .cost()
        .0;
    let per = kaspa_txscript::zk_precompiles::groth16::GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS;
    let units_per_mass = kaspa_consensus_core::mass::SCRIPT_UNITS_PER_GRAM;
    let old_floor = (base + 15 * per) / units_per_mass;
    let packed_floor = (base + 3 * per) / units_per_mass;
    let actual_withdraw_fee =
        native::reserve(7) - native.joint.outputs.iter().map(|o| o.value).sum::<u64>();
    let joint_quote = native.report["jointMassQuote"]["computeMass"]
        .as_u64()
        .unwrap()
        .max(
            native.report["jointMassQuote"]["transientMass"]
                .as_u64()
                .unwrap(),
        )
        .max(
            native.report["jointMassQuote"]["storageMass"]
                .as_u64()
                .unwrap(),
        );
    assert!(
        actual_withdraw_fee >= joint_quote * 100,
        "declared comparison withdrawal fee must cover quote"
    );
    let costs = json!({"scope":"withdrawal native quote plus optimistic direct-verification route LOWER BOUNDS; no paid fees or complete route","priceSompiPerMass":100,"usefulPaymentsSompi":3*native::PRINCIPAL,"originalVerificationMassPerOperationFloor":old_floor,"packedVerificationMassPerOperationFloor":packed_floor,"necessaryProofs":6,"originalRouteVerificationMassFloor":6*old_floor,"packedRouteVerificationMassFloor":6*packed_floor,"packedRouteFeeFloorAt100Sompi":600*packed_floor,"actualSyntheticWithdrawalFeeSompi":actual_withdraw_fee,"withdrawalQuotedMass":joint_quote,"routeFeeFloorIncludingActualWithdrawalAt100Sompi":actual_withdraw_fee+300*packed_floor,"completeRouteMeasured":false,"targetBasisPoints":200,"failsEvenVerificationFloorAt100":600*packed_floor*10000>3*native::PRINCIPAL*200,"feeRateSensitivity":[1,10,100],"noFeeWasPaid":true});
    assert!(costs["failsEvenVerificationFloorAt100"].as_bool().unwrap());
    write(
        &out.join("public/execution.json"),
        &json!({"schema":"real-wallet-common-set-execution-v1","lifecycle":l.timing,"checks":l.checks,"native":native.report,"registrationControls":registration.controls,"round":hex::encode(registration.round),"costs":costs,"packedProofsGenerated":l.engine.proofs,"originalProofsGenerated":6,"elapsedSeconds":started.elapsed().as_secs_f64(),"finalPrivateLiabilitySompi":l.state.private_liability,"finalReservePrincipalSompi":l.state.reserve,"finalUnpaidExits":l.state.exits.values().filter(|e|!e.paid).count(),"networkPrivacyMeasured":false,"fullNodeValidation":false,"chainAcceptance":false,"newConsensusRules":false,"setup":"fresh one-party experimental parameters; secrets/keys not published"}),
    );
    eprintln!(
        "Completed actual-wallet integration in {:.2}s",
        started.elapsed().as_secs_f64()
    );
}
