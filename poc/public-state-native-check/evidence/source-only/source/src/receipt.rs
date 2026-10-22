//! Existing vProgs witness conversion and official RISC0 constants. See NOTICE.
use crate::Result;
use bincode::Options;
use kaspa_txscript::zk_deps::{
    ark_bn254::{Bn254, G1Affine, G2Affine},
    ark_groth16::{Proof, VerifyingKey},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
};
use risc0_zkvm::{
    sha::{Digest, Digestible, Sha256},
    Groth16ReceiptVerifierParameters, Receipt, SystemState,
};
use std::{fs, path::Path};

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    (*risc0_zkvm::sha::Impl::hash_bytes(bytes)).into()
}
pub fn load(path: &Path) -> Result<(Receipt, Vec<u8>)> {
    const MAX: u64 = 24 * 1024 * 1024;
    if fs::metadata(path)?.len() > MAX {
        return Err("receipt parser bound".into());
    }
    let raw = fs::read(path)?;
    Ok((
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX)
            .reject_trailing_bytes()
            .deserialize(&raw)?,
        raw,
    ))
}
fn g1(p: &[Vec<u8>]) -> Result<G1Affine> {
    if p.len() != 2 || p.iter().any(|x| x.len() != 32) {
        return Err("G1 shape".into());
    }
    let b: Vec<u8> = p[0]
        .iter()
        .rev()
        .chain(p[1].iter().rev())
        .copied()
        .collect();
    Ok(G1Affine::deserialize_uncompressed(b.as_slice())?)
}
fn g2(p: &[Vec<Vec<u8>>]) -> Result<G2Affine> {
    if p.len() != 2
        || p.iter()
            .any(|x| x.len() != 2 || x.iter().any(|y| y.len() != 32))
    {
        return Err("G2 shape".into());
    }
    let b: Vec<u8> = p[0][1]
        .iter()
        .rev()
        .chain(p[0][0].iter().rev())
        .chain(p[1][1].iter().rev())
        .chain(p[1][0].iter().rev())
        .copied()
        .collect();
    Ok(G2Affine::deserialize_uncompressed(b.as_slice())?)
}
pub fn proof(receipt: &Receipt) -> Result<Vec<u8>> {
    let s = risc0_groth16::Seal::decode(&receipt.inner.groth16()?.seal)?;
    let p = Proof::<Bn254> {
        a: g1(&s.a)?,
        b: g2(&s.b)?,
        c: g1(&s.c)?,
    };
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)?;
    if bytes.len() != 128 {
        return Err("native proof length".into());
    }
    Ok(bytes)
}
pub fn negate_proof_a(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut p = Proof::<Bn254>::deserialize_compressed(bytes)?;
    p.a = -p.a;
    let mut out = Vec::new();
    p.serialize_compressed(&mut out)?;
    Ok(out)
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
