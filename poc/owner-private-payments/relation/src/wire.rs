//! Existing canonical BN254 G16 conventions, independent trusted role keys.
use crate::{Error, OutputStatement, Result, SpendStatement};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub const PROOF_LEN: usize = 128;
pub const VK_LEN: usize = 328;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Spend,
    Output,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Spend => "spend",
            Self::Output => "output",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "spend" => Ok(Self::Spend),
            "output" => Ok(Self::Output),
            _ => Err(Error::Role),
        }
    }
}
pub fn checked_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    if bytes.len() != VK_LEN {
        return Err(Error::Length);
    }
    let mut rem = bytes;
    let vk =
        VerifyingKey::<Bn254>::deserialize_compressed(&mut rem).map_err(|_| Error::Encoding)?;
    if !rem.is_empty() || vk_bytes(&vk)?.as_slice() != bytes {
        return Err(Error::Encoding);
    }
    if vk.gamma_abc_g1.len() != 3 {
        return Err(Error::Arity);
    }
    if vk.alpha_g1.is_zero()
        || vk.beta_g2.is_zero()
        || vk.gamma_g2.is_zero()
        || vk.delta_g2.is_zero()
        || vk.gamma_abc_g1.iter().any(AffineRepr::is_zero)
    {
        return Err(Error::Identity);
    }
    Ok(vk)
}
pub fn checked_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    if bytes.len() != PROOF_LEN {
        return Err(Error::Length);
    }
    let mut rem = bytes;
    let p = Proof::<Bn254>::deserialize_compressed(&mut rem).map_err(|_| Error::Encoding)?;
    if !rem.is_empty() || proof_bytes(&p)?.as_slice() != bytes {
        return Err(Error::Encoding);
    }
    if p.a.is_zero() || p.b.is_zero() || p.c.is_zero() {
        return Err(Error::Identity);
    }
    Ok(p)
}
pub fn vk_bytes(vk: &VerifyingKey<Bn254>) -> Result<[u8; VK_LEN]> {
    let mut b = Vec::new();
    vk.serialize_compressed(&mut b)
        .map_err(|_| Error::Encoding)?;
    b.try_into().map_err(|_| Error::Length)
}
pub fn proof_bytes(p: &Proof<Bn254>) -> Result<[u8; PROOF_LEN]> {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b)
        .map_err(|_| Error::Encoding)?;
    b.try_into().map_err(|_| Error::Length)
}
pub struct Verifier {
    prepared: PreparedVerifyingKey<Bn254>,
    role: Role,
}
impl Verifier {
    pub fn new(trusted_vk: &[u8], role: Role) -> Result<Self> {
        Ok(Self {
            prepared: prepare_verifying_key(&checked_vk(trusted_vk)?),
            role,
        })
    }
    pub fn verify_spend(&self, s: &SpendStatement, p: &[u8]) -> Result<bool> {
        if self.role != Role::Spend {
            return Err(Error::Role);
        }
        s.validate()?;
        Groth16::<Bn254>::verify_proof(&self.prepared, &checked_proof(p)?, &s.public_inputs())
            .map_err(|_| Error::Verification)
    }
    pub fn verify_output(&self, s: &OutputStatement, p: &[u8]) -> Result<bool> {
        if self.role != Role::Output {
            return Err(Error::Role);
        }
        s.validate()?;
        Groth16::<Bn254>::verify_proof(&self.prepared, &checked_proof(p)?, &s.public_inputs())
            .map_err(|_| Error::Verification)
    }
}
