//! Explicit heavy test using the already selected NEW setup, never new setup per control.
#![cfg(feature = "prover")]
use kpi_owner_private_lifecycle_relation::*;
use std::path::Path;

fn selected(role: Role) -> ark_groth16::ProvingKey<ark_bn254::Bn254> {
    let prefix = match role {
        Role::Spend => "KPX8_TEST_SPEND",
        Role::Output => "KPX8_TEST_OUTPUT",
        Role::Exit => "KPX8_TEST_EXIT",
    };
    let root =
        std::env::var(format!("{prefix}_DIR")).expect("explicit new test-only parameter directory");
    let manifest_pin =
        std::env::var(format!("{prefix}_MANIFEST_SHA256")).expect("external manifest selection");
    let pk_pin = std::env::var(format!("{prefix}_PK_SHA256")).expect("external PK selection");
    keys::load(
        role,
        &Path::new(&root).join("parameters.pk"),
        &pk_pin,
        &Path::new(&root).join("manifest.json"),
        &manifest_pin,
    )
    .expect("new selected parameter bytes")
    .0
}

#[test]
#[ignore = "run under the serialized heavy window with explicitly pinned NEW parameter directories"]
fn genuine_proofs_reject_changed_financial_claims_and_role_replays() {
    let (spend, output) = circuit::fixture();
    let spend_pk = selected(Role::Spend);
    let spend_vk = vk_bytes(&spend_pk.vk).unwrap();
    let spend_proof = keys::prove_spend(&spend_pk, spend.clone()).unwrap();
    let verifier = Verifier::new(&spend_vk, Role::Spend).unwrap();
    assert!(
        verifier
            .verify_spend(&spend.statement, &spend_proof)
            .unwrap()
    );
    for field in 0..5 {
        let mut changed = spend.statement.clone();
        match field {
            0 => changed.effects_digest[31] ^= 1,
            1 => changed.anchor[0] ^= 1,
            2 => changed.nf[0] ^= 1,
            3 => {
                let mut r = spend.witness.blinding;
                r[0] += 1;
                changed.cv = value_commitment(spend.witness.note.value, &r).unwrap();
            }
            _ => changed.domain[0] ^= 1,
        }
        assert_ne!(verifier.verify_spend(&changed, &spend_proof), Ok(true));
    }
    // Changed proof bytes are rejected unless they remain a genuine same-statement proof.
    let mut malformed = spend_proof;
    malformed[0] ^= 0x80;
    assert_ne!(
        verifier.verify_spend(&spend.statement, &malformed),
        Ok(true)
    );
    assert!(checked_proof(&spend_proof[..127]).is_err());
    assert!(checked_vk(&[spend_vk.as_slice(), &[0]].concat()).is_err());
    drop(spend_pk);

    let output_pk = selected(Role::Output);
    let output_vk = vk_bytes(&output_pk.vk).unwrap();
    let output_proof = keys::prove_output(&output_pk, output.clone()).unwrap();
    let out = Verifier::new(&output_vk, Role::Output).unwrap();
    assert!(out.verify_output(&output.statement, &output_proof).unwrap());
    for field in 0..4 {
        let mut changed = output.statement.clone();
        match field {
            0 => changed.cf_hash[0] ^= 1,
            1 => changed.cm[0] ^= 1,
            2 => {
                let mut r = output.witness.blinding;
                r[0] += 1;
                changed.cv = value_commitment(output.witness.note.value, &r).unwrap();
            }
            _ => changed.domain[0] ^= 1,
        }
        assert_ne!(out.verify_output(&changed, &output_proof), Ok(true));
    }
    assert_ne!(
        Verifier::new(&output_vk, Role::Spend)
            .unwrap()
            .verify_spend(&spend.statement, &spend_proof),
        Ok(true)
    );
    assert_ne!(
        Verifier::new(&spend_vk, Role::Output)
            .unwrap()
            .verify_output(&output.statement, &output_proof),
        Ok(true)
    );
    assert_eq!(
        verifier.verify_output(&output.statement, &output_proof),
        Err(Error::Role)
    );
}

#[test]
#[ignore = "run under the serialized heavy window with explicitly pinned NEW parameter directories"]
fn genuine_exit_rejects_changed_effects_value_root_nf_domain_and_role() {
    let exit = circuit::exit_fixture();
    let pk = selected(Role::Exit);
    let vk = vk_bytes(&pk.vk).unwrap();
    let p = keys::prove_exit(&pk, exit.clone()).unwrap();
    let v = Verifier::new(&vk, Role::Exit).unwrap();
    assert!(v.verify_exit(&exit.statement, &p).unwrap());
    for field in 0..6 {
        let mut changed = exit.statement.clone();
        match field {
            0 => changed.effects_digest[0] ^= 1,
            1 => changed.anchor[0] ^= 1,
            2 => changed.nf[0] ^= 1,
            3 => changed.payout -= 1,
            4 => changed.fee += 1,
            _ => changed.domain[0] ^= 1,
        }
        assert_ne!(v.verify_exit(&changed, &p), Ok(true));
    }
    let mut preserving_gross = exit.statement.clone();
    preserving_gross.payout -= 1;
    preserving_gross.fee += 1;
    assert!(preserving_gross.validate().is_ok());
    assert_ne!(v.verify_exit(&preserving_gross, &p), Ok(true));
    let mut malformed = p;
    malformed[0] ^= 0x80;
    assert_ne!(v.verify_exit(&exit.statement, &malformed), Ok(true));
    assert_eq!(
        Verifier::new(&vk, Role::Spend)
            .unwrap()
            .verify_exit(&exit.statement, &p),
        Err(Error::Role),
    );
    let (spend, output) = circuit::fixture();
    assert_eq!(v.verify_spend(&spend.statement, &p), Err(Error::Role));
    assert_eq!(v.verify_output(&output.statement, &p), Err(Error::Role));
    drop(pk);
    // Bypass the role enum guard deliberately: even when a caller labels an
    // unrelated selected key "exit", its proof equation must reject this seal.
    for wrong_role in [Role::Spend, Role::Output] {
        let wrong_pk = selected(wrong_role);
        let wrong = Verifier::new(&vk_bytes(&wrong_pk.vk).unwrap(), Role::Exit).unwrap();
        assert_ne!(wrong.verify_exit(&exit.statement, &p), Ok(true));
    }
}
