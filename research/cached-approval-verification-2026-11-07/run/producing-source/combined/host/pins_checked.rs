//! Host compilation gate: validate every embedded point before guest build.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub fn check() {
    #[cfg(feature="offline")]
    let compressed = include_bytes!("../../reusable-withdrawal-approvals/pins/vk-compressed.bin");
    #[cfg(feature="testnet")]
    let compressed = include_bytes!("../testnet-pins/vk-compressed.bin");
    #[cfg(feature="offline")]
    let full = include_bytes!("../../reusable-withdrawal-approvals/pins/vk-uncompressed.bin");
    #[cfg(feature="testnet")]
    let full = include_bytes!("../testnet-pins/vk-uncompressed.bin");
    println!("cargo:rerun-if-changed=../../reusable-withdrawal-approvals/pins/vk-compressed.bin");
    println!("cargo:rerun-if-changed=../testnet-pins/vk-compressed.bin");
    println!("cargo:rerun-if-changed=../../reusable-withdrawal-approvals/pins/vk-uncompressed.bin");
    println!("cargo:rerun-if-changed=../testnet-pins/vk-uncompressed.bin");
    let mut r = compressed.as_slice();
    let a = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&mut r).unwrap();
    assert!(r.is_empty());
    assert_eq!(a.gamma_abc_g1.len(), 3);
    let mut r = full.as_slice();
    let b =
        ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_uncompressed(&mut r).unwrap();
    assert!(r.is_empty());
    assert_eq!(a, b);
    let mut canonical = vec![];
    a.serialize_compressed(&mut canonical).unwrap();
    assert_eq!(canonical, compressed);
    let mut canonical = vec![];
    a.serialize_uncompressed(&mut canonical).unwrap();
    assert_eq!(canonical, full);
}
