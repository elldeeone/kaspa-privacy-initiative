//! New-process verification from public artifacts only, with no setup/prover.
use crate::{
    native::{self, Policy},
    proof::{self, H},
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use blind_rsa_signatures::{MessageRandomizer, PSS, PublicKey, Randomized, Sha384, Signature};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use std::{fs, path::Path, str::FromStr};

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn h(v: &Value) -> H {
    bytes(v).try_into().unwrap()
}
pub fn verify(public: &Path) -> Value {
    let view: Value =
        serde_json::from_slice(&fs::read(public.join("candidate.json")).unwrap()).unwrap();
    let vk_bytes = hex::decode(
        fs::read_to_string(public.join("verification-key.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let mut reader = vk_bytes.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader).unwrap();
    assert!(reader.is_empty());
    let native = &view["native"];
    let claims = std::array::from_fn(|i| h(&native["activePublicClaims"][i]));
    let p = Policy::new(claims, &vk_bytes);
    assert_eq!(hex::encode(&p.scripts[7]), native["policyRedeemScript"]);
    let inputs = native["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            assert!(i["sigOpCount"].is_null());
            TransactionInput::new_with_compute_budget(
                TransactionOutpoint::new(
                    Hash::from_str(i["transactionId"].as_str().unwrap()).unwrap(),
                    u32::try_from(i["index"].as_u64().unwrap()).unwrap(),
                ),
                bytes(&i["signatureScript"]),
                i["sequence"].as_u64().unwrap(),
                u16::try_from(i["computeBudget"].as_u64().unwrap()).unwrap(),
            )
        })
        .collect();
    let outputs = native["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            assert!(o["covenant"].is_null());
            let spk = bytes(&o["scriptPublicKey"]);
            TransactionOutput::new(
                o["valueSompi"].as_u64().unwrap(),
                ScriptPublicKey::new(
                    u16::from_be_bytes(spk[..2].try_into().unwrap()),
                    spk[2..].to_vec().into(),
                ),
            )
        })
        .collect();
    let mut tx = Transaction::new(
        u16::try_from(native["version"].as_u64().unwrap()).unwrap(),
        inputs,
        outputs,
        native["lockTime"].as_u64().unwrap(),
        Default::default(),
        native["gas"].as_u64().unwrap(),
        bytes(&native["payload"]),
    );
    assert_eq!(
        native["subnetwork"],
        hex::encode(tx.subnetwork_id.as_bytes())
    );
    tx.finalize();
    let units = native::execute(&p, 7, &tx).expect("public native replay");
    let mut changed = tx.clone();
    changed.outputs[0].script_public_key = ScriptPublicKey::new(
        0,
        [
            vec![32],
            secp256k1::Keypair::new(&secp256k1::Secp256k1::new(), &mut rand::rngs::OsRng)
                .x_only_public_key()
                .0
                .serialize()
                .to_vec(),
            vec![0xac],
        ]
        .concat()
        .into(),
    );
    changed.finalize();
    let recipient_rejection = native::execute(&p, 7, &changed).unwrap_err();
    assert!(recipient_rejection.contains("Groth16"));
    let issuer =
        PublicKey::<Sha384, PSS, Randomized>::from_der(&bytes(&view["issuerDer"])).unwrap();
    let mut credential_count = 0;
    let mut authorization_count = 0;
    for event in view["events"].as_array().unwrap() {
        if event["kind"] == "redeem" {
            let signature = Signature(bytes(&event["signature"]));
            let randomizer = Some(MessageRandomizer(h(&event["randomizer"])));
            let message = bytes(&event["message"]);
            issuer.verify(&signature, randomizer, &message).unwrap();
            let mut wrong = message.clone();
            wrong[0] ^= 1;
            assert!(issuer.verify(&signature, randomizer, &wrong).is_err());
            credential_count += 1;
        } else {
            let mut b = b"KPI-registration-eligibility-v1\0".to_vec();
            b.extend(h(&view["round"]));
            b.extend(h(&view["issuerFingerprint"]));
            b.extend(h(&event["claim"]));
            b.extend(bytes(&event["blindMessage"]));
            let expected = proof::hash(&b);
            assert_eq!(expected, h(&event["context"]));
            let raw = bytes(&event["proof"]);
            let mut cursor = raw.as_slice();
            let proof = Proof::<Bn254>::deserialize_compressed(&mut cursor).unwrap();
            assert!(cursor.is_empty());
            let fields = proof::fields(&h(&event["claim"]), &expected, &h(&event["tag"]));
            assert!(Groth16::<Bn254>::verify(&vk, &fields, &proof).unwrap());
            let mut wrong = fields;
            wrong[2] += Fr::from(1u64);
            assert!(!Groth16::<Bn254>::verify(&vk, &wrong, &proof).unwrap());
            authorization_count += 1;
        }
    }
    assert_eq!(credential_count, 3);
    assert_eq!(authorization_count, 3);
    json!({"schema":"finite-common-set-public-replay-v1","nativeJointReverified":true,"nativeScriptUnits":units,"registrationAuthorizationsReverified":authorization_count,"blindCredentialsReverified":credential_count,"changedNativeRecipientRejected":true,"changedEligibilityContextsRejected":true,"changedCredentialMessagesRejected":true,"privateFilesRead":false,"freshProofOrSetup":false,"fullNodeOrChainValidation":false})
}
