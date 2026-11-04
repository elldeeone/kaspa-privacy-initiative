//! PUBLIC deterministic keys and fake outpoints. Never use these for live funds.
use crate::{
    codec::{effect_bytes, Effects, Input, OutPoint, Output, Transaction},
    hash,
    signing::{input_context, input_hash, signing_message, SyntheticUtxo},
    verifier::{SyntheticView, Verifier},
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
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
};

pub const NAMES: [&str; 3] = ["deposit", "transfer", "withdraw"];
pub fn domain() -> [u8; 32] {
    hash("Domain", b"PUBLIC SYNTHETIC NO NETWORK ACTIVATION")
}
pub fn funding_key(ecdsa: bool) -> SecretKey {
    SecretKey::from_slice(&[if ecdsa { 0x62 } else { 0x61 }; 32]).unwrap()
}
pub fn script(ecdsa: bool) -> Vec<u8> {
    let secp = Secp256k1::new();
    let sk = funding_key(ecdsa);
    if ecdsa {
        let mut out = vec![0x21];
        out.extend_from_slice(&PublicKey::from_secret_key(&secp, &sk).serialize());
        out.push(0xab);
        out
    } else {
        let mut out = vec![0x20];
        out.extend_from_slice(
            &Keypair::from_secret_key(&secp, &sk)
                .x_only_public_key()
                .0
                .serialize(),
        );
        out.push(0xac);
        out
    }
}
pub fn base_effects() -> Effects {
    Effects {
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        payload: b"PUBLIC UNFUNDED NATIVE DRAFT AUTHORIZATION".to_vec(),
        // Signed placeholder. This package deliberately makes no fee/mass claim.
        storage_mass: 1000,
        domain: domain(),
        fee: 1,
        anchor_tree: 0,
        anchor_count: 0,
    }
}
pub fn synthetic_utxos(name: &str) -> crate::signing::SyntheticUtxoView {
    if name == "deposit" {
        [(0x11, 70, false), (0x12, 42, true)]
            .into_iter()
            .map(|(id, amount, ecdsa)| {
                (
                    OutPoint {
                        txid: [id; 32],
                        index: 0,
                    },
                    SyntheticUtxo {
                        amount,
                        script_version: 0,
                        script: script(ecdsa),
                        covenant: false,
                        coinbase: false,
                    },
                )
            })
            .collect()
    } else {
        BTreeMap::new()
    }
}
pub fn synthetic_view(name: &str, tx: &Transaction) -> SyntheticView {
    SyntheticView {
        domain: domain(),
        utxos: synthetic_utxos(name),
        anchors: BTreeSet::from([(
            0,
            match name {
                "deposit" => 0,
                "transfer" => 2,
                _ => 4,
            },
            tx.bundle.anchor().to_bytes(),
        )]),
        spent: BTreeSet::new(),
        balance: match name {
            "deposit" => 0,
            "transfer" => 100,
            _ => 99,
        },
    }
}
fn builder(anchor: Anchor) -> Builder {
    let v = BundleVersion::orchard_v2();
    Builder::new(BundleType::DEFAULT, v, v.default_flags(), anchor).unwrap()
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
    name: &str,
    pk: &ProvingKey,
    rng: &mut ChaCha20Rng,
    keys: &[SpendAuthorizingKey],
) -> Result<Transaction, Box<dyn Error>> {
    let bundle = builder.build::<i64>(&mut *rng)?.unwrap().0;
    // The synthetic input map is independent of packet claims (there are none).
    let s = signing_message(&effects, &bundle, &synthetic_utxos(name))?;
    let mut tx = Transaction {
        effects,
        bundle: bundle
            .create_proof(pk, &mut *rng)?
            .apply_signatures(&mut *rng, s, keys)?,
    };
    let secp = Secp256k1::new();
    for (i, input) in tx.effects.inputs.iter_mut().enumerate() {
        let ecdsa = i == 1;
        let sk = funding_key(ecdsa);
        let message = Message::from_digest(input_hash(s, i as u32, ecdsa));
        let signature: [u8; 64] = if ecdsa {
            secp.sign_ecdsa(&message, &sk).serialize_compact()
        } else {
            *secp
                .sign_schnorr_no_aux_rand(&message, &Keypair::from_secret_key(&secp, &sk))
                .as_ref()
        };
        input.signature_script = vec![0x41];
        input.signature_script.extend_from_slice(&signature);
        input.signature_script.push(1);
    }
    Ok(tx)
}

pub fn generate(folder: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(folder)?;
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let verifier = Verifier::new()?;
    let mut rng = ChaCha20Rng::from_seed([0x75; 32]);
    let alice = SpendingKey::from_bytes([0x41; 32]).unwrap();
    let bob = SpendingKey::from_bytes([0x42; 32]).unwrap();
    let af = FullViewingKey::from(&alice);
    let bf = FullViewingKey::from(&bob);
    let ai = af.to_ivk(Scope::External);
    let bi = bf.to_ivk(Scope::External);
    let mut b = builder(Anchor::empty_tree());
    b.add_output(
        Some(af.to_ovk(Scope::External)),
        af.address_at(0u32, Scope::External),
        NoteValue::from_raw(100),
        [0; 512],
    )?;
    let mut effects = base_effects();
    effects.inputs = [0x11, 0x12]
        .into_iter()
        .map(|id| Input {
            previous: OutPoint {
                txid: [id; 32],
                index: 0,
            },
            signature_script: vec![],
            sequence: u64::MAX,
            compute_budget: 1000,
        })
        .collect();
    effects.outputs.push(Output {
        value: 11,
        script_version: 0,
        script: script(false),
        covenant: None,
    });
    let deposit = finish(b, effects, "deposit", &pk, &mut rng, &[])?;
    let (index, _, note, _, _) = deposit
        .bundle
        .decrypt_outputs_with_keys(std::slice::from_ref(&ai))
        .into_iter()
        .find(|(_, _, n, _, _)| n.value().inner() == 100)
        .unwrap();
    let mut leaves: Vec<_> = deposit
        .bundle
        .actions()
        .iter()
        .map(|a| MerkleHashOrchard::from_cmx(a.cmx()))
        .collect();
    let membership = path(&leaves, index);
    let mut b = builder(membership.root(note.commitment().into()));
    b.add_spend(af.clone(), note, membership)?;
    b.add_output(
        Some(af.to_ovk(Scope::External)),
        bf.address_at(0u32, Scope::External),
        NoteValue::from_raw(60),
        [0; 512],
    )?;
    b.add_output(
        Some(af.to_ovk(Scope::External)),
        af.address_at(0u32, Scope::External),
        NoteValue::from_raw(39),
        [0; 512],
    )?;
    let mut effects = base_effects();
    effects.anchor_count = 2;
    let transfer = finish(
        b,
        effects,
        "transfer",
        &pk,
        &mut rng,
        &[SpendAuthorizingKey::from(&alice)],
    )?;
    let (index, _, note, _, _) = transfer
        .bundle
        .decrypt_outputs_with_keys(&[bi])
        .into_iter()
        .find(|(_, _, n, _, _)| n.value().inner() == 60)
        .unwrap();
    assert!(transfer
        .bundle
        .decrypt_outputs_with_keys(&[ai])
        .iter()
        .any(|(_, _, n, _, _)| n.value().inner() == 39));
    leaves.extend(
        transfer
            .bundle
            .actions()
            .iter()
            .map(|a| MerkleHashOrchard::from_cmx(a.cmx())),
    );
    let membership = path(&leaves, 2 + index);
    let mut b = builder(membership.root(note.commitment().into()));
    b.add_spend(bf, note, membership)?;
    let mut effects = base_effects();
    effects.anchor_count = 4;
    effects.outputs.push(Output {
        value: 59,
        script_version: 0,
        script: script(true),
        covenant: None,
    });
    let withdraw = finish(
        b,
        effects,
        "withdraw",
        &pk,
        &mut rng,
        &[SpendAuthorizingKey::from(&bob)],
    )?;
    let mut markers = BTreeSet::new();
    let mut manifest = Vec::new();
    for (name, tx) in NAMES.into_iter().zip([deposit, transfer, withdraw]) {
        let mut view = synthetic_view(name, &tx);
        view.spent = markers.clone();
        let bytes = tx.encode()?;
        let result = verifier.verify_local(&bytes, &view)?;
        fs::write(folder.join(format!("{name}.bin")), &bytes)?;
        fs::write(
            folder.join(format!("{name}.q.bin")),
            effect_bytes(&tx.effects, &tx.bundle, false)?,
        )?;
        let utxos: Vec<_> = view.utxos.iter().map(|(p,u)| json!({
            "txid":hex::encode(p.txid), "index":p.index, "amount":u.amount.to_string(),
            "script_version":u.script_version,"script":hex::encode(&u.script),"covenant":false,"coinbase":false,
        })).collect();
        fs::write(
            folder.join(format!("{name}.synthetic-view.json")),
            serde_json::to_string_pretty(&json!({
                "classification":"PUBLIC SUPPLIED SYNTHETIC CONTEXT; no chain authentication",
                "utxos":utxos,"balance":view.balance.to_string(),"domain":hex::encode(view.domain),
                "anchors":view.anchors.iter().map(|(t,c,r)|json!({"tree":t.to_string(),"count":c.to_string(),"root":hex::encode(r)})).collect::<Vec<_>>(),
                "spent":view.spent.iter().map(hex::encode).collect::<Vec<_>>(),
                "input_context":hex::encode(input_context(&tx.effects,&view.utxos)?),
            }))? + "\n",
        )?;
        manifest.push(json!({"name":name,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
            "txid":hex::encode(result.txid),"txhash":hex::encode(result.txhash),"signing_message":hex::encode(result.signing_message),
            "b":tx.bundle.value_balance().to_string()}));
        markers.extend(tx.bundle.actions().iter().map(|a| a.nullifier().to_bytes()));
    }
    fs::write(
        folder.join("manifest.json"),
        serde_json::to_string_pretty(&json!({
            "schema":"native-draft-authorization-v1","native_acceptance":false,"chain_authenticated":false,
            "mass_validated":false,"portable_key_import":false,"profile_id":crate::PROFILE_ID,"key_id":crate::KEY_ID,
            "public_rng_seed":hex::encode([0x75;32]),"public_alice_key":hex::encode([0x41;32]),"public_bob_key":hex::encode([0x42;32]),
            "public_schnorr_key":hex::encode([0x61;32]),"public_ecdsa_key":hex::encode([0x62;32]),"vectors":manifest,
        }))? + "\n",
    )?;
    Ok(())
}
