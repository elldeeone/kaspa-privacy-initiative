//! Exact established official wrapper constant conversion, no new arithmetic.
use crate::h::{self, Result};
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use risc0_zkvm::{
    sha::{Digest, Digestible},
    Groth16ReceiptVerifierParameters, SystemState,
};
use std::{fs, path::Path};

pub fn dump(out: &Path) -> Result<()> {
    let params = Groth16ReceiptVerifierParameters::default();
    let envelope = bincode::serialize(&risc0_groth16::verifying_key())?;
    let raw: Vec<u8> = bincode::deserialize(&envelope)?;
    let mut reader = raw.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)?;
    if !reader.is_empty() || vk.gamma_abc_g1.len() != 6 {
        return Err("fixed outer key shape".into());
    }
    let mut canonical = Vec::new();
    vk.serialize_uncompressed(&mut canonical)?;
    if canonical != raw {
        return Err("fixed outer key canonical encoding".into());
    }
    let mut key = Vec::new();
    vk.serialize_compressed(&mut key)?;
    if key.len() != 424
        || h::sha(&key) != "78886245c5d55b850f2ac26af823802cd128eb4a43d6c52c8a62af46d54306a4"
    {
        return Err("qualified official outer key mismatch".into());
    }
    let root: [[u8; 32]; 2] = std::array::from_fn(|i| {
        let mut x = [0; 32];
        x[..16].copy_from_slice(&params.control_root.as_bytes()[16 * i..16 * i + 16]);
        x
    });
    let id: [u8; 32] = params.bn254_control_id.into();
    let post: [u8; 32] = SystemState {
        pc: 0,
        merkle_root: Digest::ZERO,
    }
    .digest()
    .into();
    let value = serde_json::json!({"vk":hex::encode(&key),"root":root.map(hex::encode),
        "id":hex::encode(id),"output_tag":h::sha(b"risc0.Output"),
        "claim_tag":h::sha(b"risc0.ReceiptClaim"),"post":hex::encode(post)});
    fs::create_dir(out)?;
    h::save(
        out,
        "outer-constants.json",
        &serde_json::to_vec_pretty(&value)?,
    )?;
    h::save(out, "vk.compressed.bin", &key)?;
    h::save(
        out,
        "provenance.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "source":"exact established public-state-native-check/receipt.rs constants conversion",
            "sdk":"3.0.3","groth16_crate":"3.0.4","native_vk_sha256":h::sha(&key),
            "verifier_parameters_digest":params.digest().to_string(),"fresh_pair_image_not_in_constants":true,
            "proof_generation":false,"native_execution":false
        }))?,
    )?;
    Ok(())
}
