//! Existing vProgs/RISC0 seal conversion, adapted from public-state-native-check.
//! Called only after genuine receipt, selected image and exact journal checks.
use crate::Result;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use risc0_zkvm::Receipt;

fn g1(p: &[Vec<u8>]) -> Result<G1Affine> {
    if p.len() != 2 || p.iter().any(|v| v.len() != 32) {
        return Err("native G1 shape".into());
    }
    let raw: Vec<_> = p[0]
        .iter()
        .rev()
        .chain(p[1].iter().rev())
        .copied()
        .collect();
    let point = G1Affine::deserialize_uncompressed(raw.as_slice())?;
    let mut canonical = Vec::new();
    point.serialize_uncompressed(&mut canonical)?;
    if canonical != raw || point == G1Affine::identity() {
        return Err("native G1 canonical nonidentity encoding".into());
    }
    Ok(point)
}

fn g2(p: &[Vec<Vec<u8>>]) -> Result<G2Affine> {
    if p.len() != 2
        || p.iter()
            .any(|x| x.len() != 2 || x.iter().any(|v| v.len() != 32))
    {
        return Err("native G2 shape".into());
    }
    let raw: Vec<_> = p[0][1]
        .iter()
        .rev()
        .chain(p[0][0].iter().rev())
        .chain(p[1][1].iter().rev())
        .chain(p[1][0].iter().rev())
        .copied()
        .collect();
    let point = G2Affine::deserialize_uncompressed(raw.as_slice())?;
    let mut canonical = Vec::new();
    point.serialize_uncompressed(&mut canonical)?;
    if canonical != raw || point == G2Affine::identity() {
        return Err("native G2 canonical nonidentity encoding".into());
    }
    Ok(point)
}

pub fn encode(receipt: &Receipt) -> Result<Vec<u8>> {
    let seal = risc0_groth16::Seal::decode(&receipt.inner.groth16()?.seal)?;
    let proof = Proof::<Bn254> {
        a: g1(&seal.a)?,
        b: g2(&seal.b)?,
        c: g1(&seal.c)?,
    };
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)?;
    if bytes.len() != 128 {
        return Err("native compressed proof length".into());
    }
    // This is the standard conversion, with no experimental A negation.
    Ok(bytes)
}
