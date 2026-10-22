//! Public development fixture producer. Every wallet seed below is public.
//! NEVER FUND these keys or confuse this fresh setup with the old TN10 instance.
//! No RPC, transaction construction, native settlement or old parameters are used.
use ark_bn254::Bn254;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::{CanonicalSerialize, Compress};
use kpi_shared_pool::{
    Result, compact,
    protocol::{H, Note, Wallet, hash},
    two_input::{
        Authorization, Bundle, FEE,
        circuit::{Circuit, Input},
        dummy_nf,
        tree::{Tree, cm_leaf},
    },
};
use rand::rngs::OsRng;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Instant,
};

const EXPECTED_CONSTRAINTS: usize = 4_372_824;
const ORIGINAL_VK_SHA256: &str = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef";
const SOURCE_COMMIT: &str = "ec6aa15d586bcc8a90f7232b433fd48d8c73d509";

// These labels are public test seeds, not credentials or private user material.
fn seed(label: &str) -> H {
    hash(
        &[
            b"KPI/public-two-v6-fixture/DO-NOT-FUND/v1/".as_slice(),
            label.as_bytes(),
        ]
        .concat(),
    )
}

fn wallet(label: &str) -> Wallet {
    Wallet {
        spending: seed(&format!("{label}/spending")),
        viewing: seed(&format!("{label}/viewing")),
        native: seed(&format!("{label}/native")),
    }
}

fn note(w: &Wallet, d: &H, value: u64, label: &str) -> Note {
    let r = w.receive(d);
    Note {
        owner: r.owner,
        incoming: r.incoming,
        value,
        rho: seed(label),
    }
}

fn compressed(value: &impl CanonicalSerialize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn fresh_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn make_statement(
    d: H,
    tree: &Tree,
    owner: &Wallet,
    input: &Note,
    position: u32,
    outputs: [Note; 2],
    label: &str,
) -> Result<(Circuit, Bundle)> {
    let pad = Input {
        real: false,
        note: Note::dummy(),
        secret: [0; 32],
        position: 0,
        path: vec![[0; 32]; 16],
        dummy_key: seed(&format!("{label}/dummy-key")),
        dummy_seed: seed(&format!("{label}/dummy-seed")),
    };
    let inputs = [
        Input {
            real: true,
            note: input.clone(),
            secret: owner.spending,
            position,
            path: tree.path(position)?,
            dummy_key: [0; 32],
            dummy_seed: [0; 32],
        },
        pad,
    ];
    let ciphers = [outputs[0].encrypt(&d)?, outputs[1].encrypt(&d)?];
    if ciphers.iter().any(|c| c.len() != 185) {
        return Err("ciphertext dimensions".into());
    }
    let auth = Authorization {
        domain: d,
        count: 3,
        anchor: tree.root(),
        nfs: [
            compact::nullifier(&d, &owner.spending, &input.commitment(&d), position),
            dummy_nf(&d, &inputs[1].dummy_key, &inputs[1].dummy_seed, 1),
        ],
        outputs: outputs.each_ref().map(|n| n.commitment(&d)),
        mode: 1,
        payout: 0,
        fee: FEE,
        spk: [0; 36],
        deposit: 0,
        funding: [0; 36],
        funding_spk: [0; 36],
        bootstrap: 0,
        cipher_hash: hash(&ciphers.concat()),
    };
    let bundle = Bundle {
        authorization: hex::encode(auth.bytes()),
        proof: hex::encode([0; 128]),
        ciphertexts: ciphers.map(hex::encode),
    };
    Ok((
        Circuit {
            auth,
            inputs,
            outputs,
        },
        bundle,
    ))
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: public_two_v6_fixture NEW_PUBLIC_OUTPUT_DIRECTORY".into());
    }
    let output = Path::new(&args[1]);
    // Exclusivity prevents accidental replacement of any prior fixture/evidence.
    fs::create_dir(output)?;
    let started = Instant::now();
    let d = seed("new-independent-development-domain");
    let alice = wallet("independent-wallet-alice");
    let bob = wallet("independent-wallet-bob");
    let a_note = note(&alice, &d, 800_000_000, "alice/input/rho");
    let b_note = note(&bob, &d, 900_000_000, "bob/input/rho");
    // This is a synthetic membership context, not accepted historical state.
    // The unused first commitment supplies odd count 3; it carries no claim here.
    let commitments = [
        seed("synthetic-unused-commitment"),
        a_note.commitment(&d),
        b_note.commitment(&d),
    ];
    let tree = Tree::new(commitments.iter().map(cm_leaf).collect(), 16)?;
    let (ca, ba) = make_statement(
        d,
        &tree,
        &alice,
        &a_note,
        1,
        [
            note(&bob, &d, 400_000_000, "alice/pay-bob/rho"),
            note(&alice, &d, 360_000_000, "alice/change/rho"),
        ],
        "alice/spend",
    )?;
    let (cb, bb) = make_statement(
        d,
        &tree,
        &bob,
        &b_note,
        2,
        [
            note(&alice, &d, 500_000_000, "bob/pay-alice/rho"),
            note(&bob, &d, 360_000_000, "bob/change/rho"),
        ],
        "bob/spend",
    )?;
    if ca.auth.anchor != cb.auth.anchor || ca.auth.count != cb.auth.count {
        return Err("common membership context mismatch".into());
    }
    let nfs = ca
        .auth
        .nfs
        .into_iter()
        .chain(cb.auth.nfs)
        .collect::<BTreeSet<_>>();
    if nfs.len() != 4 || nfs.contains(&[0; 32]) {
        return Err("active nullifiers are not four distinct nonzero values".into());
    }
    let mut constraint_checks = Vec::new();
    for (i, c) in [&ca, &cb].into_iter().enumerate() {
        eprintln!("stage=constraint-check bundle={i}");
        let check_start = Instant::now();
        let (count, satisfied) = c.check()?;
        if !satisfied || count != EXPECTED_CONSTRAINTS {
            return Err(format!(
                "bundle {i} constraint qualification: count={count} satisfied={satisfied}"
            )
            .into());
        }
        constraint_checks.push(json!({"bundle": i, "constraints": count, "satisfied": true, "seconds": check_start.elapsed().as_secs_f64()}));
    }
    // A new, separate single-party test setup. No PK is read or serialized.
    eprintln!("stage=fresh-test-only-setup");
    let setup_start = Instant::now();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(ca.clone(), &mut OsRng)?;
    let setup_seconds = setup_start.elapsed().as_secs_f64();
    let vk = compressed(&pk.vk)?;
    let vk_hash = hex::encode(hash(&vk));
    if vk.len() != 328 || pk.vk.gamma_abc_g1.len() != 3 || vk_hash == ORIGINAL_VK_SHA256 {
        return Err("fresh development key identity/arity/dimensions".into());
    }
    let prepared = prepare_verifying_key(&pk.vk);
    let mut records = Vec::new();
    for (i, (c, mut b)) in [(ca, ba), (cb, bb)].into_iter().enumerate() {
        eprintln!("stage=prove bundle={i}");
        let proof_start = Instant::now();
        let inputs = c.auth.inputs();
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(c.clone(), &pk, &mut OsRng)?;
        let proof_seconds = proof_start.elapsed().as_secs_f64();
        if !Groth16::<Bn254>::verify_proof(&prepared, &proof, &inputs)? {
            return Err(format!("bundle {i} generated proof rejected").into());
        }
        let proof_bytes = compressed(&proof)?;
        if proof_bytes.len() != 128 {
            return Err("proof dimensions".into());
        }
        b.proof = hex::encode(&proof_bytes);
        let auth = hex::decode(&b.authorization)?;
        let ciphers = b.ciphers()?;
        if auth.len() != 377
            || hash(&ciphers) != c.auth.cipher_hash
            || auth[221..345].iter().any(|v| *v != 0)
        {
            return Err("authorization/ciphertext/profile binding".into());
        }
        // Independently validate each recipient's actual encrypted output.
        let recipients = if i == 0 {
            [&bob, &alice]
        } else {
            [&alice, &bob]
        };
        for (slot, recipient) in recipients.into_iter().enumerate() {
            let cipher = hex::decode(&b.ciphertexts[slot])?;
            let received = recipient.decrypt(&d, &cipher, &c.auth.outputs[slot])?;
            if received.plaintext(&d) != c.outputs[slot].plaintext(&d) {
                return Err("recipient validation mismatch".into());
            }
        }
        let bytes = [auth.as_slice(), proof_bytes.as_slice(), ciphers.as_slice()].concat();
        if bytes.len() != 875 {
            return Err("bundle framing".into());
        }
        let filename = format!("bundle-{i}.bin");
        fresh_file(output, &filename, &bytes)?;
        records.push(json!({
            "file": filename, "bytes": bytes.len(), "sha256": hex::encode(hash(&bytes)),
            "authorization_sha256": hex::encode(hash(&auth)), "proof_sha256": hex::encode(hash(&proof_bytes)),
            "ciphertext_sha256": b.ciphertexts.iter().map(|x| hex::decode(x).map(|raw| hex::encode(hash(&raw)))).collect::<std::result::Result<Vec<_>, _>>()?,
            "count": c.auth.count, "anchor": hex::encode(c.auth.anchor),
            "nullifiers": c.auth.nfs.map(hex::encode), "commitments": c.auth.outputs.map(hex::encode),
            "mode": c.auth.mode, "payout_sompi": c.auth.payout.to_string(), "fee_sompi": c.auth.fee.to_string(),
            "proof_seconds": proof_seconds, "arkworks_0_6_verified": true, "recipient_validation_passed": true,
        }));
    }
    fresh_file(output, "verification-key.bin", &vk)?;
    let manifest = json!({
        "format": "kpi-public-two-v6-development-fixture-v1", "public_test_only": true,
        "do_not_fund": true, "single_party_untrusted_test_setup": true,
        "original_instance_fixture": false, "accepted_native_history": false,
        "native_settlement_performed": false, "privacy_claim": false,
        "relation_source_commit": SOURCE_COMMIT,
        "relation": "unchanged two_input::circuit::Circuit; Arkworks 0.6.0 BN254 Groth16",
        "wallet_material": "public deterministic test labels in producer source; no real user keys or historical private inputs",
        "setup_entropy": "fresh OsRng; no entropy/trapdoor or proving key serialized",
        "domain": hex::encode(d), "vk_file": "verification-key.bin", "vk_bytes": vk.len(), "vk_sha256": vk_hash,
        "setup_seconds": setup_seconds, "in_memory_pk_compressed_bytes": pk.serialized_size(Compress::Yes),
        "common_membership_context": {"synthetic": true, "count": 3, "anchor": hex::encode(tree.root()), "commitments": commitments.map(hex::encode)},
        "constraint_checks": constraint_checks, "bundles": records, "total_seconds": started.elapsed().as_secs_f64(),
        "scope": "Two independently verified wallet proofs with shared synthetic anchor/count and disjoint active nullifiers. This supplies new host-binding positive fixtures only, under a fresh VK/domain. It does not replace the missing original-instance pair, prove accepted state/current spentness/backing, or qualify any zkVM/native receipt."
    });
    let encoded = [serde_json::to_vec_pretty(&manifest)?, vec![b'\n']].concat();
    fresh_file(output, "manifest.json", &encoded)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"completed": true, "manifest_sha256": hex::encode(hash(&encoded)), "total_seconds": started.elapsed().as_secs_f64()})
        )?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("public-two-v6-fixture: {error}");
        std::process::exit(1);
    }
}
