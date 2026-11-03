use kpi_orchard_interop::{
    codec::{effect_bytes, effect_digest, Envelope, MAX_PACKET},
    verifier::{SuppliedContext, Verifier},
    Error, MAX_SOMPI, PROOF_BYTES,
};
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::PathBuf, sync::OnceLock};

fn folder() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}
fn packet(name: &str) -> Vec<u8> {
    fs::read(folder().join(format!("{name}.bin"))).unwrap()
}
fn context(name: &str) -> SuppliedContext {
    serde_json::from_slice(&fs::read(folder().join(format!("{name}.context.json"))).unwrap())
        .unwrap()
}
fn fixture(name: &str) -> Envelope {
    Envelope::decode(&packet(name)).unwrap()
}
fn verifier() -> &'static Verifier {
    static V: OnceLock<Verifier> = OnceLock::new();
    V.get_or_init(Verifier::new)
}
fn prefix(envelope: &Envelope) -> usize {
    effect_bytes(&envelope.effects, &envelope.bundle)
        .unwrap()
        .len()
}

#[test]
fn genuine_bundles_roundtrip_proof_signatures_and_supplied_context() {
    for (name, next) in [("deposit", 100), ("transfer", 99), ("withdraw", 39)] {
        let bytes = packet(name);
        let env = Envelope::decode(&bytes).unwrap();
        assert_eq!(env.encode().unwrap(), bytes);
        assert_eq!(env.bundle.actions().len(), 2);
        assert_eq!(
            env.bundle.authorization().proof().as_ref().len(),
            PROOF_BYTES
        );
        assert_eq!(verifier().verify_crypto(&env), Ok(()));
        assert_eq!(verifier().verify(&bytes, &context(name)), Ok(next));
    }
}

#[test]
fn exact_artifact_and_key_identities() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(folder().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["vk_debug_sha256"], verifier().key_fingerprint());
    assert_eq!(
        manifest["cargo_lock_sha256"],
        hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")))
    );
    assert_eq!(
        manifest["profile_id"],
        hex::encode(kpi_orchard_interop::profile_id())
    );
    for vector in manifest["vectors"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        assert_eq!(vector["sha256"], hex::encode(Sha256::digest(packet(name))));
        let env = fixture(name);
        assert_eq!(
            vector["effects_digest"],
            hex::encode(effect_digest(&env.effects, &env.bundle).unwrap())
        );
    }
}

#[test]
fn all_modeled_economic_fields_are_signed_not_just_fixture_hash_checked() {
    let mut env = fixture("deposit");
    let mut cases = Vec::new();
    macro_rules! changed {
        ($body:expr) => {{
            let mut e = env.clone();
            $body(&mut e);
            cases.push(e);
        }};
    }
    changed!(|e: &mut Envelope| e.effects.network[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.genesis[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.pool[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.accepted_context[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.lock_time += 1);
    changed!(|e: &mut Envelope| e.effects.subnetwork[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.gas += 1);
    changed!(|e: &mut Envelope| e.effects.storage_mass += 1);
    changed!(|e: &mut Envelope| e.effects.fee += 1);
    changed!(|e: &mut Envelope| e.effects.payload.push(1));
    changed!(|e: &mut Envelope| e.effects.inputs[0].txid[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.inputs[0].index += 1);
    changed!(|e: &mut Envelope| e.effects.inputs[0].value += 1);
    changed!(|e: &mut Envelope| e.effects.inputs[0].sequence += 1);
    changed!(|e: &mut Envelope| e.effects.inputs[0].compute += 1);
    changed!(|e: &mut Envelope| {
        e.effects.inputs[0].compute_kind = 0;
        e.effects.inputs[0].compute = 1;
    });
    for changed in &cases {
        assert_eq!(
            verifier().verify_crypto(changed),
            Err(Error::SpendSignature)
        );
    }
    env = fixture("withdraw");
    cases.clear();
    changed!(|e: &mut Envelope| e.effects.outputs[0].value += 1);
    changed!(|e: &mut Envelope| e.effects.outputs[0].script_version += 1);
    changed!(|e: &mut Envelope| e.effects.outputs[0].script[0] ^= 1);
    changed!(|e: &mut Envelope| e.effects.outputs[0].covenant = Some((0, [1; 32])));
    changed!(|e: &mut Envelope| {
        let o = e.effects.outputs[0].clone();
        e.effects.outputs.push(o);
    });
    for changed in cases {
        assert_eq!(
            verifier().verify_crypto(&changed),
            Err(Error::SpendSignature)
        );
    }
    // Unknown version is a profile error, not a claimed signature rejection.
    let mut bytes = packet("deposit");
    bytes[40] = 2;
    assert!(matches!(Envelope::decode(&bytes), Err(Error::Profile)));
}

#[test]
fn delivery_bytes_and_action_order_are_authorized() {
    let env = fixture("transfer");
    let first = prefix(&env) - 1640;
    for field in [160, 740] {
        // recipient and outgoing ciphertext starts within Action
        let mut bytes = packet("transfer");
        bytes[first + field] ^= 1;
        let changed = Envelope::decode(&bytes).unwrap();
        assert_eq!(
            verifier().verify_crypto(&changed),
            Err(Error::SpendSignature)
        );
    }
    let mut bytes = packet("transfer");
    let (a, b) = (
        bytes[first..first + 820].to_vec(),
        bytes[first + 820..first + 1640].to_vec(),
    );
    bytes[first..first + 820].copy_from_slice(&b);
    bytes[first + 820..first + 1640].copy_from_slice(&a);
    // Full Halo2 proof commits ordered instances, so this rejects at proof layer.
    assert_eq!(
        verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
}

#[test]
fn real_changed_public_inputs_reject_in_halo2() {
    let env = fixture("transfer");
    let first = prefix(&env) - 1640;
    // Copy different canonical values from the other Action, not malformed bytes.
    for offset in [0, 32, 64, 96] {
        // cv, nf, rk, cmx
        let mut bytes = packet("transfer");
        let replacement = bytes[first + 820 + offset..first + 820 + offset + 32].to_vec();
        bytes[first + offset..first + offset + 32].copy_from_slice(&replacement);
        assert_eq!(
            verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
            Err(Error::Proof)
        );
    }
    let mut bytes = packet("transfer");
    let anchor = first - 33;
    bytes[anchor..anchor + 32].fill(0);
    assert_eq!(
        verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
}

#[test]
fn wrong_circuit_key_rejects_genuine_v2_proof() {
    let wrong = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    assert!(fixture("transfer").bundle.verify_proof(&wrong).is_err());
}

#[test]
fn proof_corruption_and_both_signature_roles_reject_at_expected_layers() {
    let env = fixture("transfer");
    let start = prefix(&env) + 4;
    let mut bytes = packet("transfer");
    bytes[start + 256] ^= 1;
    assert_eq!(
        verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
        Err(Error::Proof)
    );
    for slot in 0..2 {
        let mut bytes = packet("transfer");
        bytes[start + PROOF_BYTES + slot * 64] ^= 1;
        assert_eq!(
            verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
            Err(Error::SpendSignature)
        );
    }
    let mut bytes = packet("transfer");
    let last = bytes.len() - 64;
    bytes[last] ^= 1;
    assert_eq!(
        verifier().verify_crypto(&Envelope::decode(&bytes).unwrap()),
        Err(Error::BindingSignature)
    );
    // b is outside the Action circuit but bound by the signed effects and BVK.
    // Hold the original message fixed to isolate the aggregate binding key.
    let old_digest = effect_digest(&env.effects, &env.bundle).unwrap();
    let mut bytes = packet("transfer");
    let at = prefix(&env) - 1640 - 41;
    bytes[at..at + 8].copy_from_slice(&2i64.to_le_bytes());
    let changed = Envelope::decode(&bytes).unwrap();
    assert_eq!(
        verifier().verify_crypto(&changed),
        Err(Error::SpendSignature)
    );
    assert!(changed
        .bundle
        .binding_validating_key()
        .verify(
            &old_digest,
            changed.bundle.authorization().binding_signature()
        )
        .is_err());
}

#[test]
fn canonical_role_rules_do_not_blanket_reject_zero_or_identity() {
    let env = fixture("transfer");
    let first = prefix(&env) - 1640;
    for offset in [0, 32] {
        // identity cv or canonical zero NF: parse, then cryptographically reject
        let mut bytes = packet("transfer");
        bytes[first + offset..first + offset + 32].fill(0);
        let changed = Envelope::decode(&bytes).unwrap();
        assert_eq!(verifier().verify_crypto(&changed), Err(Error::Proof));
    }
    for offset in [64, 128] {
        // identity rk and epk are forbidden role encodings
        let mut bytes = packet("transfer");
        bytes[first + offset..first + offset + 32].fill(0);
        assert!(matches!(Envelope::decode(&bytes), Err(Error::Decode(_))));
    }
    for offset in [0, 32, 64, 96, 128] {
        let mut bytes = packet("transfer");
        bytes[first + offset..first + offset + 32].fill(255);
        assert!(matches!(Envelope::decode(&bytes), Err(Error::Decode(_))));
    }
}

#[test]
fn bounded_lengths_exact_consumption_and_profile_guards() {
    let bytes = packet("withdraw");
    let env = fixture("withdraw");
    let end = prefix(&env);
    for n in [
        0,
        1,
        8,
        39,
        40,
        41,
        169,
        221,
        223,
        bytes.len() - 1,
        end,
        end + 3,
        end + 4,
        end + 4 + PROOF_BYTES - 1,
    ] {
        assert!(
            Envelope::decode(&bytes[..n]).is_err(),
            "accepted truncation at {n}"
        );
    }
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(Envelope::decode(&padded).is_err());
    assert!(Envelope::decode(&vec![0; MAX_PACKET + 1]).is_err());
    for offset in [0, 8, 40, end - 1641] {
        let mut b = bytes.clone();
        b[offset] ^= 0x80;
        assert!(Envelope::decode(&b).is_err());
    }
    let mut count = bytes.clone();
    count[222..224].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        Envelope::decode(&count),
        Err(Error::Decode("item bound"))
    ));
    for length in [0, PROOF_BYTES - 1, PROOF_BYTES + 1, u32::MAX as usize] {
        let mut b = bytes.clone();
        b[end..end + 4].copy_from_slice(&(length as u32).to_le_bytes());
        assert!(matches!(
            Envelope::decode(&b),
            Err(Error::Decode("proof length"))
        ));
    }
    for at in [236, 244] {
        // independent v1 layout: script/payload length
        let mut b = bytes.clone();
        b[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Envelope::decode(&b),
            Err(Error::Decode("blob bound"))
        ));
    }
    let mut tag = bytes.clone();
    tag[243] = 2;
    assert!(matches!(
        Envelope::decode(&tag),
        Err(Error::Decode("covenant tag"))
    ));
    let first = end - 1640;
    for flags in [0, 1, 2, 4, 7, 255] {
        let mut b = bytes.clone();
        b[first - 42] = flags;
        assert!(matches!(Envelope::decode(&b), Err(Error::Profile)));
    }
    let mut minimum = bytes.clone();
    minimum[first - 41..first - 33].copy_from_slice(&i64::MIN.to_le_bytes());
    assert!(matches!(Envelope::decode(&minimum), Err(Error::Range)));
    let mut compute = packet("deposit");
    compute[276] = 2;
    assert!(matches!(
        Envelope::decode(&compute),
        Err(Error::Decode("compute tag/value"))
    ));
}

#[test]
fn current_context_rechecked_after_genuine_crypto_pass() {
    let bytes = packet("transfer");
    let env = fixture("transfer");
    assert_eq!(verifier().verify_crypto(&env), Ok(()));
    let original = context("transfer");
    let mut bad = original.clone();
    bad.eligible_anchors.clear();
    assert_eq!(verifier().verify(&bytes, &bad), Err(Error::Anchor));
    for action in env.bundle.actions() {
        let mut bad = original.clone();
        bad.spent.insert(action.nullifier().to_bytes());
        assert_eq!(verifier().verify(&bytes, &bad), Err(Error::Spentness));
    }
    let mut bad = original.clone();
    bad.pool[0] ^= 1;
    assert_eq!(verifier().verify(&bytes, &bad), Err(Error::Domain));
    let mut bad = context("withdraw");
    bad.pool_balance = 0;
    assert_eq!(
        verifier().verify(&packet("withdraw"), &bad),
        Err(Error::PoolBalance)
    );
    assert_eq!(original.spent, context("transfer").spent);
    assert_eq!(original.pool_balance, 100);
    // Reuse the same marker set regardless of a future verifier's display name.
    let mut replay = original.clone();
    replay.spent.extend(
        env.bundle
            .actions()
            .iter()
            .map(|a| a.nullifier().to_bytes()),
    );
    assert_eq!(verifier().verify(&bytes, &replay), Err(Error::Spentness));
    let mut duplicate = bytes.clone();
    let first = prefix(&env) - 1640;
    let nf = duplicate[first + 32..first + 64].to_vec();
    duplicate[first + 820 + 32..first + 820 + 64].copy_from_slice(&nf);
    assert_eq!(
        verifier().verify(&duplicate, &original),
        Err(Error::Spentness)
    );
}

#[test]
fn native_arithmetic_boundaries_do_not_claim_a_hidden_range_gadget() {
    let mut effects = fixture("deposit").effects;
    effects.inputs[0].value = MAX_SOMPI;
    effects.fee = 0;
    assert_eq!(effects.validate(-(MAX_SOMPI as i64)), Ok(()));
    effects.inputs[0].value = MAX_SOMPI + 1;
    assert_eq!(effects.validate(0), Err(Error::Range));
    effects.inputs.clear();
    effects.fee = MAX_SOMPI;
    assert_eq!(effects.validate(MAX_SOMPI as i64), Ok(()));
    assert_eq!(effects.validate(i64::MIN), Err(Error::Range));
    effects.fee = MAX_SOMPI + 1;
    assert_eq!(effects.validate(0), Err(Error::Range));
    effects.fee = 1;
    assert_eq!(effects.validate(0), Err(Error::Balance));
    effects.fee = 0;
    assert_eq!(effects.validate(0), Ok(()));
    let input = fixture("deposit").effects.inputs[0].clone();
    effects.inputs = vec![input.clone(), input];
    assert_eq!(effects.validate(0), Err(Error::DuplicateInput));
}

#[test]
fn context_json_uses_canonical_decimal_sompi() {
    let original = serde_json::to_value(context("deposit")).unwrap();
    for bad in [
        serde_json::json!(0),
        serde_json::json!("00"),
        serde_json::json!("-0"),
        serde_json::json!("+1"),
        serde_json::json!("1.0"),
        serde_json::json!("18446744073709551616"),
    ] {
        let mut v = original.clone();
        v["pool_balance"] = bad;
        assert!(serde_json::from_value::<SuppliedContext>(v).is_err());
    }
    let mut v = original;
    v["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SuppliedContext>(v).is_err());
    let _: BTreeSet<[u8; 32]> = context("deposit").spent;
}

#[test]
fn independent_upstream_key_note_known_answer() {
    use orchard::{
        keys::{FullViewingKey, Scope, SpendingKey},
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };
    let data: serde_json::Value =
        serde_json::from_slice(&fs::read(folder().join("upstream-key-note.json")).unwrap())
            .unwrap();
    let f = &data["fields"];
    let field = |name: &str| hex::decode(f[name].as_str().unwrap()).unwrap();
    let sk = SpendingKey::from_bytes(field("sk").try_into().unwrap()).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let expected_fvk = [field("ak"), field("nk"), field("rivk")].concat();
    assert_eq!(fvk.to_bytes().as_slice(), expected_fvk);
    let address = fvk.address_at(0u32, Scope::External);
    assert_eq!(
        address.to_raw_address_bytes().as_slice(),
        [field("default_d"), field("default_pk_d")].concat()
    );
    assert_eq!(
        fvk.to_ivk(Scope::External).to_bytes().as_slice(),
        [field("dk"), field("ivk")].concat()
    );
    let rho = Rho::from_bytes(&field("note_rho").try_into().unwrap()).unwrap();
    let seed = RandomSeed::from_bytes(field("note_rseed").try_into().unwrap(), &rho).unwrap();
    let note = Note::from_parts(
        address,
        NoteValue::from_raw(f["note_v"].as_str().unwrap().parse().unwrap()),
        rho,
        seed,
        NoteVersion::V2,
    )
    .unwrap();
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    assert_eq!(cmx.to_bytes().as_slice(), field("note_cmx"));
    assert_eq!(note.nullifier(&fvk).to_bytes().as_slice(), field("note_nf"));
    // This public u64 vector is deliberately NOT a native monetary-range fixture.
}

#[test]
fn recipient_uses_standard_decryption_and_rejects_malformed_delivery() {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    let key = SpendingKey::from_bytes([0x41; 32]).unwrap();
    let ivk = FullViewingKey::from(&key).to_ivk(Scope::External);
    let env = fixture("deposit");
    let outputs = env
        .bundle
        .decrypt_outputs_with_keys(std::slice::from_ref(&ivk));
    let (index, _, note, _, _) = outputs
        .iter()
        .find(|(_, _, n, _, _)| n.value().inner() == 100)
        .unwrap();
    assert_eq!(note.value().inner(), 100);
    let mut bytes = packet("deposit");
    let at = prefix(&env) - 1640 + index * 820 + 160;
    bytes[at] ^= 1;
    let changed = Envelope::decode(&bytes).unwrap();
    assert!(changed
        .bundle
        .decrypt_output_with_key(*index, &ivk)
        .is_none());
    assert_eq!(
        verifier().verify_crypto(&changed),
        Err(Error::SpendSignature)
    );
}

#[test]
fn deterministic_bitflip_corpus_never_accepted() {
    let bytes = packet("transfer");
    // Covers prefix, Action bytes, proof and signatures, not just parser errors.
    for i in 0..96 {
        let mut mutated = bytes.clone();
        let offset = (i * 7919 + 37) % bytes.len();
        mutated[offset] ^= 1 << (i % 8);
        if let Ok(env) = Envelope::decode(&mutated) {
            assert!(
                verifier().verify_crypto(&env).is_err(),
                "accepted mutation at {offset}"
            );
        }
    }
}
