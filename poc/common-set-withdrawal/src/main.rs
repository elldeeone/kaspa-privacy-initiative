//! Unfunded finite current-rule native and registration diagnostic.
mod native;
mod proof;
mod registration;
mod replay;
mod trials;
use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use std::{fs, path::Path, time::Instant};
fn write(path: &Path, value: &serde_json::Value) {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    f.write_all(serde_json::to_string_pretty(value).unwrap().as_bytes())
        .unwrap();
    f.write_all(b"\n").unwrap();
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("verify-public") {
        let directory = std::env::args().nth(2).expect("public artifact directory");
        println!(
            "{}",
            serde_json::to_string_pretty(&replay::verify(Path::new(&directory))).unwrap()
        );
        return;
    }
    let out = std::env::args()
        .nth(1)
        .expect("new runtime output directory required");
    let out = Path::new(&out);
    assert!(!out.exists(), "refuse existing runtime");
    fs::create_dir_all(out.join("public")).unwrap();
    fs::create_dir(out.join("private")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let secrets: [proof::H; 3] = std::array::from_fn(|_| {
        let mut s = [0; 32];
        OsRng.fill_bytes(&mut s);
        s
    });
    let secp = secp256k1::Secp256k1::new();
    let keys: [proof::H; 3] = std::array::from_fn(|_| {
        let k = secp256k1::Keypair::new(&secp, &mut OsRng);
        k.x_only_public_key().0.serialize()
    });
    let claims = std::array::from_fn(|i| proof::hash(&secrets[i]));
    eprintln!(
        "Generating fresh experimental single-party Groth16 setup; never fund this policy..."
    );
    let mut engine = proof::Engine::setup();
    fs::write(
        out.join("public/verification-key.hex"),
        format!("{}\n", hex::encode(proof::serialize(&engine.vk))),
    )
    .unwrap();
    eprintln!("Exercising real blind output registration...");
    let registration = registration::run(&mut engine, &secrets, claims, keys);
    let spks = std::array::from_fn(|i| {
        kaspa_consensus_core::tx::ScriptPublicKey::new(
            0,
            [vec![32], keys[i].to_vec(), vec![0xac]].concat().into(),
        )
    });
    let native = trials::run(&mut engine, &secrets, &spks);
    let mut candidate = registration.candidate;
    candidate["native"] = native.public_native.clone();
    let mut baseline = registration.baseline;
    baseline["native"] = native.public_native;
    write(&out.join("public/candidate.json"), &candidate);
    write(&out.join("public/baseline.json"), &baseline);
    // Extra knowledge is supplied to separate observer views, not silently
    // injected into the base candidate's public transcript.
    let links = (0..3)
        .map(|i| json!({"owner":format!("owner-{}",i+1),"recipientKey":hex::encode(keys[i])}))
        .collect::<Vec<_>>();
    let mut one = candidate.clone();
    one["explicitOwnerLinks"] = json!([links[0].clone()]);
    write(&out.join("public/one-participant.json"), &one);
    let mut two = candidate.clone();
    two["explicitOwnerLinks"] = json!([links[0].clone(), links[1].clone()]);
    write(&out.join("public/all-but-one.json"), &two);
    let mut known = candidate.clone();
    known["explicitOwnerLinks"] = json!(links.clone());
    write(&out.join("public/known-payout-owners.json"), &known);
    let mut echo = candidate.clone();
    for event in echo["events"].as_array_mut().unwrap() {
        if event["kind"] == "redeem" {
            let key = event["recipientKey"].as_str().unwrap();
            let i = keys.iter().position(|k| hex::encode(k) == key).unwrap();
            event["owner"] = json!(format!("owner-{}", i + 1));
        }
    }
    write(&out.join("public/echoed-origin.json"), &echo);
    let mut leaked = candidate.clone();
    for event in leaked["events"].as_array_mut().unwrap() {
        if event["kind"] == "issue" {
            let i = event["owner"]
                .as_str()
                .unwrap()
                .strip_prefix("owner-")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                - 1;
            event["leakedRandomizer"] = json!(hex::encode(registration.randomizers[i]));
        }
    }
    write(&out.join("public/leaked-issuance-randomizer.json"), &leaked);
    let mut legacy = candidate.clone();
    legacy["previouslyPublishedIndividualExits"] = json!(links.clone());
    write(&out.join("public/legacy-public-exits.json"), &legacy);
    write(
        &out.join("private/truth.json"),
        &json!({"ownerToRecipient":links,"scope":"fresh synthetic controller truth, consulted only after prediction seal"}),
    );
    fs::set_permissions(
        out.join("private/truth.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    write(
        &out.join("public/execution.json"),
        &json!({"schema":"finite-common-set-execution-v1","native":native.report,"registrationControls":registration.controls,"proofsGenerated":engine.proofs,"constraintCount":engine.constraints,"publicInputsPerProof":6,"round":hex::encode(registration.round),"elapsedSeconds":started.elapsed().as_secs_f64(),"setup":"fresh single-party experimental setup; proving key and secrets not retained","cryptographicAssumptions":"Groth16 knowledge soundness/zero knowledge; SHA256/HMAC; RFC9474 blindness; no cryptographic audit","networkPrivacyMeasured":false,"fullNodeValidation":false,"fundedState":false,"chainAcceptance":false,"newConsensusRules":false}),
    );
    eprintln!(
        "Completed finite native and application-transcript run in {:.2}s",
        started.elapsed().as_secs_f64()
    );
}
