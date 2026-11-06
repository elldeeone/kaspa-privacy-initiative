#[allow(dead_code)]
#[path = "../src/circuit.rs"]
mod circuit;
#[allow(dead_code)]
#[path = "../src/proof.rs"]
mod proof;
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use kpi_private_note_wallet::{
    circuit::WalletCircuit as Original,
    protocol::{Operation, Statement, TRANSFER, Tree, hash, nullifier},
    wallet::Wallet,
};

fn relation(input_value: u64, output_values: [u64; 2]) -> Original {
    let a = Wallet::new();
    let b = Wallet::new();
    let input = a.note(input_value);
    let outputs = [b.note(output_values[0]), a.note(output_values[1])];
    let mut tree = Tree::default();
    tree.append(input.commitment()).unwrap();
    let (siblings, directions) = tree.path(0).unwrap();
    let mut statement = Statement::new(TRANSFER, [7; 32], tree.root());
    statement.nullifier = a.nf(&input);
    for (i, n) in outputs.iter().enumerate() {
        let d = n.deliver().unwrap();
        statement.outputs[i] = d.commitment;
        statement.delivery[i] = hash(&d.ciphertext);
    }
    Original {
        statement,
        witness: a.witness(input, outputs, siblings, directions),
    }
}

#[test]
fn full_relation_preserves_zero_max_and_overflow_boundaries() {
    for (name, original, expected) in [
        (
            "maximum valid sum",
            relation(u64::MAX, [u64::MAX - 1, 1]),
            true,
        ),
        (
            "overflow cannot wrap",
            relation(u64::MAX, [u64::MAX, 1]),
            false,
        ),
        ("zero active output", relation(10, [0, 10]), false),
        ("zero spend", relation(0, [1, 1]), false),
    ] {
        assert_eq!(original.check().unwrap().1, expected, "original {name}");
        let packed = circuit::WalletCircuit {
            statement: original.statement,
            witness: original.witness,
        };
        assert_eq!(packed.check().unwrap().1, expected, "packed {name}");
    }
}

#[test]
fn saved_real_proof_rejects_changed_public_data_and_delivery() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/payment-set-withdrawal-2026-11-05/run");
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("candidate.json")).unwrap()).unwrap();
    let raw = hex::decode(v["walletHistory"]["verifyingKey"].as_str().unwrap()).unwrap();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&raw[..]).unwrap();
    let op: Operation =
        serde_json::from_value(v["walletHistory"]["operations"][1].clone()).unwrap();
    assert!(proof::verify(&vk, &op));
    for mode in 0..7 {
        let mut changed = op.clone();
        match mode {
            0 => changed.deliveries[0].ciphertext[0] ^= 1,
            1 => changed.deliveries[0].commitment[0] ^= 1,
            2 => changed.statement.nullifier[0] ^= 1,
            3 => changed.statement.anchor[0] ^= 1,
            4 => changed.statement.verifier[0] ^= 1,
            5 => changed.proof.push(0),
            _ => {
                changed.deliveries[0].ciphertext[0] ^= 1;
                changed.statement.delivery[0] = hash(&changed.deliveries[0].ciphertext);
            }
        }
        assert!(!proof::verify(&vk, &changed), "public mutation {mode}");
    }
    // Economic nullifiers use the actual original secret/note helper; they
    // have not become a public transaction index or a fresh replay nonce.
    let original = relation(10, [4, 6]);
    assert_eq!(
        original.statement.nullifier,
        nullifier(&original.witness.secret, &original.witness.input)
    );
}
