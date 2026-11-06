//! Standard SHA256 preimage + RFC2104 HMAC relation, one VK for every claimant.
//! Finite public claims deliberately avoid claiming private note membership.
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    uint8::UInt8,
};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub type H = [u8; 32];
pub const AUTH_DOMAIN: &[u8] = b"KPI-common-set-authorization-v1\0";
pub fn hash(b: &[u8]) -> H {
    Sha256::digest(b).into()
}
pub fn tag(secret: &H, context: &H) -> H {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(AUTH_DOMAIN);
    mac.update(context);
    mac.finalize().into_bytes().into()
}
pub fn serialize<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize_compressed(&mut b).unwrap();
    b
}
pub fn fields(commitment: &H, context: &H, auth: &H) -> Vec<Fr> {
    [commitment, context, auth]
        .into_iter()
        .flat_map(|v| v.chunks(16).map(Fr::from_le_bytes_mod_order))
        .collect()
}
#[derive(Clone)]
pub struct Circuit {
    pub secret: H,
    pub commitment: H,
    pub context: H,
    pub auth: H,
}
fn public(cs: ConstraintSystemRef<Fr>, bytes: &H) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut all = vec![];
    for chunk in bytes.chunks(16) {
        let p = FpVar::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(chunk)))?;
        let bits = p.to_bits_le()?;
        for b in &bits[128..] {
            b.enforce_equal(&Boolean::FALSE)?;
        }
        all.extend(bits[..128].chunks(8).map(UInt8::from_bits_le));
    }
    Ok(all)
}
impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let commitment = public(cs.clone(), &self.commitment)?;
        let context = public(cs.clone(), &self.context)?;
        let auth = public(cs.clone(), &self.auth)?;
        let secret = UInt8::new_witness_vec(cs, &self.secret)?;
        Sha256Gadget::digest(&secret)?
            .0
            .enforce_equal(&commitment)?;
        let mut padded = secret;
        padded.extend(UInt8::constant_vec(&[0; 32]));
        let mut inner = padded
            .iter()
            .map(|v| v ^ UInt8::constant(0x36))
            .collect::<Vec<_>>();
        inner.extend(UInt8::constant_vec(AUTH_DOMAIN));
        inner.extend(context);
        let mut outer = padded
            .iter()
            .map(|v| v ^ UInt8::constant(0x5c))
            .collect::<Vec<_>>();
        outer.extend(Sha256Gadget::digest(&inner)?.0);
        Sha256Gadget::digest(&outer)?.0.enforce_equal(&auth)
    }
}
pub struct Engine {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
    pub proofs: usize,
    pub constraints: usize,
}
#[derive(Clone)]
pub struct Authorization {
    pub commitment: H,
    pub context: H,
    pub auth: H,
    pub proof: Proof<Bn254>,
}
impl Engine {
    pub fn setup() -> Self {
        let sample = Circuit {
            secret: [1; 32],
            commitment: hash(&[1; 32]),
            context: [2; 32],
            auth: tag(&[1; 32], &[2; 32]),
        };
        let cs = ConstraintSystem::new_ref();
        sample.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(sample, &mut OsRng).unwrap();
        Self {
            pk,
            vk,
            proofs: 0,
            constraints: cs.num_constraints(),
        }
    }
    pub fn prove(&mut self, secret: H, context: H) -> Authorization {
        let commitment = hash(&secret);
        let auth = tag(&secret, &context);
        let proof = Groth16::<Bn254>::prove(
            &self.pk,
            Circuit {
                secret,
                commitment,
                context,
                auth,
            },
            &mut OsRng,
        )
        .unwrap();
        let a = Authorization {
            commitment,
            context,
            auth,
            proof,
        };
        assert!(self.verify(&a));
        self.proofs += 1;
        a
    }
    pub fn verify(&self, a: &Authorization) -> bool {
        Groth16::<Bn254>::verify(
            &self.vk,
            &fields(&a.commitment, &a.context, &a.auth),
            &a.proof,
        )
        .unwrap_or(false)
    }
}
