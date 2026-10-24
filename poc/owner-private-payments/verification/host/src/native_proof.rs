//! Existing vProgs/RISC0 seal conversion, adapted from public-state-native-check.
//! Called only after genuine receipt, selected image and exact journal checks.
use crate::Result;
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
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
    let (x, y) = point.xy().ok_or("native G1 identity")?;
    // SDK seals contain field coordinates, not Ark affine SW sign flags.
    x.serialize_uncompressed(&mut canonical)?;
    y.serialize_uncompressed(&mut canonical)?;
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
    let (x, y) = point.xy().ok_or("native G2 identity")?;
    x.serialize_uncompressed(&mut canonical)?;
    y.serialize_uncompressed(&mut canonical)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinates<P: AffineRepr>(point: P) -> Vec<u8> {
        let (x, y) = point.xy().unwrap();
        let mut raw = Vec::new();
        x.serialize_uncompressed(&mut raw).unwrap();
        y.serialize_uncompressed(&mut raw).unwrap();
        raw
    }

    #[test]
    fn field_coordinates_accept_both_y_signs_and_reject_injected_flags() {
        for point in [G1Affine::generator(), -G1Affine::generator()] {
            let raw = coordinates(point);
            let mut sdk: Vec<Vec<u8>> = raw
                .chunks_exact(32)
                .map(|x| x.iter().rev().copied().collect())
                .collect();
            assert_eq!(g1(&sdk).unwrap(), point);
            let reversed: Vec<Vec<u8>> = sdk
                .iter()
                .map(|v| v.iter().rev().copied().collect())
                .collect();
            assert!(g1(&reversed).is_err(), "wrong coordinate endianness");
            sdk[1][0] |= 0x80;
            assert!(g1(&sdk).is_err(), "SDK coordinates cannot contain SW flags");
        }
        for point in [G2Affine::generator(), -G2Affine::generator()] {
            let raw = coordinates(point);
            let c: Vec<Vec<u8>> = raw
                .chunks_exact(32)
                .map(|x| x.iter().rev().copied().collect())
                .collect();
            let mut sdk = vec![
                vec![c[1].clone(), c[0].clone()],
                vec![c[3].clone(), c[2].clone()],
            ];
            assert_eq!(g2(&sdk).unwrap(), point);
            let mut swapped = sdk.clone();
            swapped[0].swap(0, 1);
            assert!(
                g2(&swapped).is_err(),
                "wrong extension-field component order"
            );
            sdk[1][0][0] |= 0x80;
            assert!(g2(&sdk).is_err(), "SDK coordinates cannot contain SW flags");
        }
        assert!(g1(&[vec![0; 31], vec![0; 32]]).is_err());
        assert!(g1(&[vec![0; 32], vec![0; 32]]).is_err());
        let mut one = vec![0; 32];
        one[31] = 1;
        let mut three = vec![0; 32];
        three[31] = 3;
        assert!(
            g1(&[one, three]).is_err(),
            "canonical field coordinates off curve"
        );
        assert!(
            g1(&[vec![0xff; 32], vec![0; 32]]).is_err(),
            "noncanonical field"
        );
        let zero: [Vec<Vec<u8>>; 2] = std::array::from_fn(|_| vec![vec![0; 32]; 2]);
        assert!(g2(&zero).is_err());
    }
}
