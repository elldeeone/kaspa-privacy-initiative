//! Official RISC Zero3.0.3 receipt constants; adapted from public-state-native-check.
//! vProgs f9b84a8 witness/key mappings retain the ISC notice in ../NOTICE.
use crate::Result;
use kaspa_txscript::zk_deps::{
    ark_bn254::Bn254,
    ark_groth16::VerifyingKey,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
};
use risc0_zkvm::{
    sha::{Digest, Digestible, Sha256},
    Groth16ReceiptVerifierParameters, SystemState,
};
fn hash(bytes: &[u8]) -> [u8; 32] {
    (*risc0_zkvm::sha::Impl::hash_bytes(bytes)).into()
}
pub struct Constants {
    pub vk: Vec<u8>,
    pub root: [[u8; 32]; 2],
    pub id: [u8; 32],
    pub output_tag: [u8; 32],
    pub claim_tag: [u8; 32],
    pub post: [u8; 32],
}
pub fn constants() -> Result<Constants> {
    let params = Groth16ReceiptVerifierParameters::default();
    let envelope = bincode::serialize(&risc0_groth16::verifying_key())?;
    let raw: Vec<u8> = bincode::deserialize(&envelope)?;
    let mut reader = raw.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)?;
    if !reader.is_empty() || vk.gamma_abc_g1.len() != 6 {
        return Err("fixed key shape".into());
    }
    let mut canonical = Vec::new();
    vk.serialize_uncompressed(&mut canonical)?;
    if canonical != raw {
        return Err("fixed key canonical encoding".into());
    }
    let mut key = Vec::new();
    vk.serialize_compressed(&mut key)?;
    if key.len() != 424 {
        return Err("fixed key compressed length".into());
    }
    let root = std::array::from_fn(|i| {
        let mut x = [0; 32];
        x[..16].copy_from_slice(&params.control_root.as_bytes()[16 * i..16 * i + 16]);
        x
    });
    Ok(Constants {
        vk: key,
        root,
        id: params.bn254_control_id.into(),
        output_tag: hash(b"risc0.Output"),
        claim_tag: hash(b"risc0.ReceiptClaim"),
        post: SystemState {
            pc: 0,
            merkle_root: Digest::ZERO,
        }
        .digest()
        .into(),
    })
}
