//! Canonical public curve encodings without setup, witnesses or proof claims.
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::{Proof, VerifyingKey};
use kpi_local_private_payment_relation::*;

#[test]
fn proof_codec_rejects_each_identity_component_and_nonexact_lengths() {
    let valid_encoding = Proof::<Bn254> {
        a: G1Affine::generator(),
        b: G2Affine::generator(),
        c: G1Affine::generator(),
    };
    // These are public generators, not a genuine proof of any statement.
    let bytes = proof_bytes(&valid_encoding).unwrap();
    assert!(checked_proof(&bytes).is_ok());
    for component in 0..3 {
        let mut bad = valid_encoding.clone();
        match component {
            0 => bad.a = G1Affine::zero(),
            1 => bad.b = G2Affine::zero(),
            _ => bad.c = G1Affine::zero(),
        }
        assert_eq!(
            checked_proof(&proof_bytes(&bad).unwrap()).unwrap_err(),
            Error::Identity
        );
    }
    assert_eq!(checked_proof(&bytes[..127]).unwrap_err(), Error::Length);
    assert_eq!(
        checked_proof(&[bytes.as_slice(), &[0]].concat()).unwrap_err(),
        Error::Length
    );
    assert!(checked_proof(&[0xff; 128]).is_err());
}

#[test]
fn vk_codec_rejects_each_identity_component_and_nonexact_lengths() {
    let valid_encoding = VerifyingKey::<Bn254> {
        alpha_g1: G1Affine::generator(),
        beta_g2: G2Affine::generator(),
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        gamma_abc_g1: vec![G1Affine::generator(); 3],
    };
    // Encoding validation grants no authority to this deliberately artificial VK.
    let bytes = vk_bytes(&valid_encoding).unwrap();
    assert!(checked_vk(&bytes).is_ok());
    for component in 0..7 {
        let mut bad = valid_encoding.clone();
        match component {
            0 => bad.alpha_g1 = G1Affine::zero(),
            1 => bad.beta_g2 = G2Affine::zero(),
            2 => bad.gamma_g2 = G2Affine::zero(),
            3 => bad.delta_g2 = G2Affine::zero(),
            _ => bad.gamma_abc_g1[component - 4] = G1Affine::zero(),
        }
        assert_eq!(
            checked_vk(&vk_bytes(&bad).unwrap()).unwrap_err(),
            Error::Identity
        );
    }
    assert_eq!(checked_vk(&bytes[..327]).unwrap_err(), Error::Length);
    assert_eq!(
        checked_vk(&[bytes.as_slice(), &[0]].concat()).unwrap_err(),
        Error::Length
    );
    assert!(checked_vk(&[0xff; 328]).is_err());
}
