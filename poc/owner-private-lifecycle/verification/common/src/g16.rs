//! Adapted from accelerated-bn254/common (ff8ef9d2…), using coherent Arkworks0.6.
//! Established substrate-bn field/group/pairing only; no new arithmetic or format.
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use substrate_bn::{pairing_batch, Group, Gt, G1, G2};
fn be<F: PrimeField>(f: F) -> Vec<u8> {
    let v = f.into_bigint().to_bytes_be();
    assert!(v.len() <= 32);
    let mut out = vec![0; 32 - v.len()];
    out.extend(v);
    out
}
fn fq(f: Fq) -> substrate_bn::Fq {
    substrate_bn::Fq::from_slice(&be(f)).expect("validated base field")
}
fn fr(f: Fr) -> substrate_bn::Fr {
    substrate_bn::Fr::new(substrate_bn::arith::U256::from_slice(&be(f)).unwrap())
        .expect("validated scalar")
}
// Only checked submitted points and validated program-pinned key points enter.
fn g1(p: &G1Affine) -> G1 {
    if p.is_zero() {
        G1::zero()
    } else {
        G1::new(fq(p.x), fq(p.y), substrate_bn::Fq::one())
    }
}
fn g2(p: &G2Affine) -> G2 {
    if p.is_zero() {
        G2::zero()
    } else {
        G2::new(
            substrate_bn::Fq2::new(fq(p.x.c0), fq(p.x.c1)),
            substrate_bn::Fq2::new(fq(p.y.c0), fq(p.y.c1)),
            substrate_bn::Fq2::one(),
        )
    }
}
fn stage(label: &str) {
    #[cfg(target_os = "zkvm")]
    println!("G16 {label} {}", risc0_zkvm::guest::env::cycle_count());
    #[cfg(not(target_os = "zkvm"))]
    let _ = label;
}
pub struct Verifier {
    alpha: G1,
    beta: G2,
    gamma: G2,
    delta: G2,
    ic: Vec<G1>,
}
impl Verifier {
    /// Caller must check canonical decoding, arity, subgroup and key pin first.
    pub fn from_validated_key(vk: &VerifyingKey<Bn254>) -> Self {
        Self {
            alpha: g1(&vk.alpha_g1),
            beta: g2(&vk.beta_g2),
            gamma: g2(&vk.gamma_g2),
            delta: g2(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1).collect(),
        }
    }
    pub fn verify_inputs(&self, raw: &[u8], inputs: &[Fr]) -> Result<(), &'static str> {
        if raw.len() != 128 || self.ic.len() != inputs.len() + 1 {
            return Err("g16_encoding_or_arity");
        }
        let mut rest = raw;
        let p = Proof::<Bn254>::deserialize_compressed(&mut rest).map_err(|_| "g16_decode")?;
        let mut encoded = Vec::new();
        p.serialize_compressed(&mut encoded)
            .map_err(|_| "g16_encode")?;
        if !rest.is_empty() || encoded != raw || p.a.is_zero() || p.b.is_zero() || p.c.is_zero() {
            return Err("g16_canonical_nonidentity");
        }
        stage("checked_decode");
        let mut acc = self.ic[0];
        for (base, value) in self.ic[1..].iter().zip(inputs) {
            acc = acc + *base * fr(*value);
        }
        stage("public_inputs");
        let ok = pairing_batch(&[
            (g1(&p.a), g2(&p.b)),
            (-self.alpha, self.beta),
            (-acc, self.gamma),
            (-g1(&p.c), self.delta),
        ]) == Gt::one();
        stage("pairing");
        if ok {
            Ok(())
        } else {
            Err("g16_invalid")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    #[test]
    fn field_and_group_conversions_preserve_orders() {
        assert!(g1(&G1Affine::generator()) == G1::one());
        assert!(g2(&G2Affine::generator()) == G2::one());
        for v in [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(u64::MAX),
            -Fr::from(1u64),
        ] {
            assert!(G1::one() * fr(v) == g1(&(G1Affine::generator() * v).into_affine()));
        }
    }
}
