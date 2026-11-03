//! Deterministic PUBLIC synthetic fixtures. No live keys, funding or chain state.
use crate::{
    codec::{effect_bytes, effect_digest, Envelope},
    effects::{Effects, Input, Output},
    verifier::{key_fingerprint, SuppliedContext, Verifier},
    ORCHARD_REV,
};
use incrementalmerkletree::Hashable;
use orchard::{
    builder::{Builder, BundleType},
    bundle::BundleVersion,
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Anchor,
};
use rand::{rngs::ChaCha20Rng, SeedableRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fs, path::Path, time::Instant};

pub fn supplied_context(
    envelope: &Envelope,
    balance: u64,
    spent: BTreeSet<[u8; 32]>,
) -> SuppliedContext {
    let e = &envelope.effects;
    SuppliedContext {
        network: e.network,
        genesis: e.genesis,
        pool: e.pool,
        accepted_context: e.accepted_context,
        eligible_anchors: BTreeSet::from([envelope.bundle.anchor().to_bytes()]),
        spent,
        pool_balance: balance,
    }
}

fn base_effects() -> Effects {
    Effects {
        tx_version: 1,
        network: [0x10; 32],
        genesis: [0x20; 32],
        pool: [0x30; 32],
        accepted_context: [0x40; 32],
        lock_time: 0,
        subnetwork: [0; 20],
        gas: 0,
        storage_mass: 1000,
        fee: 1,
        inputs: vec![],
        outputs: vec![],
        payload: b"PUBLIC UNFUNDED FIXTURE".to_vec(),
    }
}

fn builder(anchor: Anchor) -> Builder {
    let version = BundleVersion::orchard_v2();
    Builder::new(
        BundleType::DEFAULT,
        version,
        version.default_flags(),
        anchor,
    )
    .unwrap()
}

fn path(leaves: &[MerkleHashOrchard], position: usize) -> MerklePath {
    let mut index = position;
    let mut nodes = leaves.to_vec();
    let siblings = std::array::from_fn(|level| {
        let empty = MerkleHashOrchard::empty_root((level as u8).into());
        if !nodes.len().is_multiple_of(2) {
            nodes.push(empty);
        }
        let sibling = nodes[index ^ 1];
        nodes = nodes
            .chunks_exact(2)
            .map(|p| MerkleHashOrchard::combine((level as u8).into(), &p[0], &p[1]))
            .collect();
        index /= 2;
        sibling
    });
    MerklePath::from_parts(position as u32, siblings)
}

fn finish(
    builder: Builder,
    effects: Effects,
    pk: &ProvingKey,
    rng: &mut ChaCha20Rng,
    keys: &[SpendAuthorizingKey],
) -> Result<Envelope, Box<dyn Error>> {
    let bundle = builder.build::<i64>(&mut *rng)?.unwrap().0;
    let digest = effect_digest(&effects, &bundle)?;
    let bundle = bundle
        .create_proof(pk, &mut *rng)?
        .apply_signatures(&mut *rng, digest, keys)?;
    Ok(Envelope { effects, bundle })
}

pub fn generate(folder: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(folder)?;
    let start = Instant::now();
    eprintln!("Building exact public Orchard V2 keys...");
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let verifier = Verifier::new();
    assert_eq!(
        key_fingerprint(&pk.verifying_key()),
        verifier.key_fingerprint()
    );
    let key_seconds = start.elapsed().as_secs_f64();
    let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
    let alice = SpendingKey::from_bytes([0x41; 32]).unwrap();
    let bob = SpendingKey::from_bytes([0x42; 32]).unwrap();
    let alice_fvk = FullViewingKey::from(&alice);
    let bob_fvk = FullViewingKey::from(&bob);
    let alice_address = alice_fvk.address_at(0u32, Scope::External);
    let bob_address = bob_fvk.address_at(0u32, Scope::External);
    let alice_ivk = alice_fvk.to_ivk(Scope::External);
    let bob_ivk = bob_fvk.to_ivk(Scope::External);

    eprintln!("Creating genuine deposit proof and signatures...");
    let proof_start = Instant::now();
    let mut b = builder(Anchor::empty_tree());
    b.add_output(
        Some(alice_fvk.to_ovk(Scope::External)),
        alice_address,
        NoteValue::from_raw(100),
        [0; 512],
    )?;
    let mut effects = base_effects();
    effects.inputs.push(Input {
        txid: [0x11; 32],
        index: 0,
        value: 101,
        sequence: 0,
        compute_kind: 1,
        compute: 1_000_000,
    });
    let deposit = finish(b, effects, &pk, &mut rng, &[])?;
    let (alice_index, _, alice_note, _, _) = deposit
        .bundle
        .decrypt_outputs_with_keys(std::slice::from_ref(&alice_ivk))
        .into_iter()
        .find(|(_, _, note, _, _)| note.value().inner() == 100)
        .unwrap();
    let mut leaves: Vec<_> = deposit
        .bundle
        .actions()
        .iter()
        .map(|a| MerkleHashOrchard::from_cmx(a.cmx()))
        .collect();

    eprintln!("Creating genuine real-spend transfer proof and signatures...");
    let membership = path(&leaves, alice_index);
    let mut b = builder(membership.root(alice_note.commitment().into()));
    b.add_spend(alice_fvk.clone(), alice_note, membership)?;
    b.add_output(
        Some(alice_fvk.to_ovk(Scope::External)),
        bob_address,
        NoteValue::from_raw(60),
        [0; 512],
    )?;
    b.add_output(
        Some(alice_fvk.to_ovk(Scope::External)),
        alice_address,
        NoteValue::from_raw(39),
        [0; 512],
    )?;
    let transfer = finish(
        b,
        base_effects(),
        &pk,
        &mut rng,
        &[SpendAuthorizingKey::from(&alice)],
    )?;
    let (bob_index, _, bob_note, _, _) = transfer
        .bundle
        .decrypt_outputs_with_keys(std::slice::from_ref(&bob_ivk))
        .into_iter()
        .find(|(_, _, note, _, _)| note.value().inner() == 60)
        .unwrap();
    assert!(transfer
        .bundle
        .decrypt_outputs_with_keys(&[alice_ivk])
        .iter()
        .any(|(_, _, n, _, _)| n.value().inner() == 39));
    leaves.extend(
        transfer
            .bundle
            .actions()
            .iter()
            .map(|a| MerkleHashOrchard::from_cmx(a.cmx())),
    );

    eprintln!("Creating genuine real-spend withdrawal proof and signatures...");
    let membership = path(&leaves, 2 + bob_index);
    let mut b = builder(membership.root(bob_note.commitment().into()));
    b.add_spend(bob_fvk, bob_note, membership)?;
    let mut effects = base_effects();
    effects.outputs.push(Output {
        value: 59,
        script_version: 0,
        script: vec![0x20, 0x22, 0xac],
        covenant: None,
    });
    let withdraw = finish(
        b,
        effects,
        &pk,
        &mut rng,
        &[SpendAuthorizingKey::from(&bob)],
    )?;
    let proof_seconds = proof_start.elapsed().as_secs_f64();

    let mut spent = BTreeSet::new();
    let mut balance = 0;
    let mut manifest = Vec::new();
    for (name, envelope, expected) in [
        ("deposit", deposit, 100),
        ("transfer", transfer, 99),
        ("withdraw", withdraw, 39),
    ] {
        let context = supplied_context(&envelope, balance, spent.clone());
        let bytes = envelope.encode()?;
        assert_eq!(verifier.verify(&bytes, &context)?, expected);
        let decoded = Envelope::decode(&bytes)?;
        assert_eq!(decoded.encode()?, bytes);
        let digest = effect_digest(&envelope.effects, &envelope.bundle)?;
        fs::write(folder.join(format!("{name}.bin")), &bytes)?;
        fs::write(
            folder.join(format!("{name}.context.json")),
            serde_json::to_string_pretty(&context)? + "\n",
        )?;
        fs::write(
            folder.join(format!("{name}.effects.hex")),
            hex::encode(effect_bytes(&envelope.effects, &envelope.bundle)?) + "\n",
        )?;
        manifest.push(json!({"name":name,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
            "effects_digest":hex::encode(digest),"public_balance":envelope.bundle.value_balance().to_string(),
            "expected_pool_next":expected.to_string()}));
        balance = expected;
        spent.extend(
            envelope
                .bundle
                .actions()
                .iter()
                .map(|a| a.nullifier().to_bytes()),
        );
    }
    let profile = json!({"schema":"kpi-orchard-interop-v1","classification":"PUBLIC UNFUNDED SYNTHETIC FIXTURES; not native acceptance or privacy qualification",
        "orchard_revision":ORCHARD_REV,"circuit":"FixedPostNu6_2","note_version":2,"actions":2,"proof_bytes":crate::PROOF_BYTES,
        "profile_id":hex::encode(crate::profile_id()),"vk_debug_sha256":verifier.key_fingerprint(),
        "key_fingerprint_scope":"SHA-256 of public upstream Rust Debug, exact locked build; not portable serialized VK",
        "cargo_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../Cargo.lock"))),
        "public_fixture_seed_hex":hex::encode([0x52;32]),"public_alice_key_hex":hex::encode([0x41;32]),"public_bob_key_hex":hex::encode([0x42;32]),
        "vectors":manifest});
    fs::write(
        folder.join("manifest.json"),
        serde_json::to_string_pretty(&profile)? + "\n",
    )?;
    eprintln!("Key construction {key_seconds:.2}s; 3 proof constructions {proof_seconds:.2}s. Local interoperability only.");
    Ok(())
}
