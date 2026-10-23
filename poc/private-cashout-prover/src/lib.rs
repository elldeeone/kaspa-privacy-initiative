//! ADR0053: private owner-local proving, fresh trial source template.
//! This module does not authenticate chain state, update native roots or encrypt
//! delivery records. Those obligations remain at their contract-defined seams.
pub mod circuit;
mod exact_sha256;
pub mod parameters;
pub mod request;

use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey, prepare_verifying_key,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;

pub type H = [u8; 32];
pub const NOTE_LEN: usize = 168;
pub const STATE_LEN: usize = 112;
pub const AUTH_LEN: usize = 528;
pub const PROOF_LEN: usize = 128;
pub const VK_LEN: usize = 328;
pub const CM_DEPTH: usize = 16;
pub const NOTE_FLOOR: u64 = 60_000_000;
pub const PAYOUT_FLOOR: u64 = 10_000_000;
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const MAX_NOTES: u32 = 65_535;
pub const MAX_NF_LEAVES: u32 = 131_071;
pub const STATE_MAGIC: &[u8; 8] = b"KPX2ST01";
pub const AUTH_MAGIC: &[u8; 8] = b"KPX3AU01";
pub const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
pub const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
pub const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
pub const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
pub const DUMMY_TAG: &[u8; 8] = b"KPX2DMY\0";
pub const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
pub const CM_EMPTY: &[u8; 8] = b"KPX1CME\0";
/// Root-selected fresh development instance, independent of the future VK/policy.
pub const DOMAIN: H = [
    0xaa, 0x39, 0xad, 0x5d, 0x2d, 0xa8, 0x5d, 0xfd, 0x16, 0x95, 0xcc, 0x74, 0xce, 0x3e, 0x0f, 0x23,
    0xe7, 0x13, 0xf3, 0x15, 0xd6, 0xe5, 0x34, 0x1b, 0xcc, 0xc8, 0xa0, 0x60, 0x11, 0x13, 0x54, 0xc2,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    Domain,
    Range,
    Encoding,
    IdentityPoint,
    KeyArity,
    Synthesis,
    Verification,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub fn hash(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p)
    }
    h.finalize().into()
}
pub fn owner(domain: &H, s: &H, incoming: &H) -> H {
    hash(&[OWNER_TAG, domain, s, incoming])
}
pub fn key_commitment(domain: &H, k: &H) -> H {
    hash(&[KEY_TAG, domain, k])
}
pub fn hmac(key: &H, parts: &[&[u8]]) -> H {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts32-byte keys");
    for p in parts {
        h.update(p)
    }
    h.finalize().into_bytes().into()
}
pub fn nullifier(domain: &H, k: &H, cm: &H, position: u32) -> H {
    hmac(k, &[NF_TAG, domain, cm, &position.to_le_bytes()])
}
pub fn dummy_nullifier(domain: &H, key: &H, seed: &H, slot: u8) -> H {
    hmac(key, &[DUMMY_TAG, domain, seed, &[slot]])
}

/// Public receive fields/opening. It deliberately contains neither s nor k.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub owner: H,
    pub incoming: H,
    pub value: u64,
    pub rho: H,
    pub key_commitment: H,
    pub native_pk: H,
}
impl Note {
    pub fn zero() -> Self {
        Self {
            owner: [0; 32],
            incoming: [0; 32],
            value: 0,
            rho: [0; 32],
            key_commitment: [0; 32],
            native_pk: [0; 32],
        }
    }
    pub fn dummy_output<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut n = Self::zero();
        rng.fill_bytes(&mut n.rho);
        n
    }
    pub fn bytes(&self) -> [u8; NOTE_LEN] {
        let mut b = [0; NOTE_LEN];
        b[..32].copy_from_slice(&self.owner);
        b[32..64].copy_from_slice(&self.incoming);
        b[64..72].copy_from_slice(&self.value.to_le_bytes());
        b[72..104].copy_from_slice(&self.rho);
        b[104..136].copy_from_slice(&self.key_commitment);
        b[136..].copy_from_slice(&self.native_pk);
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != NOTE_LEN {
            return Err(Error::Length);
        }
        Ok(Self {
            owner: b[..32].try_into().unwrap(),
            incoming: b[32..64].try_into().unwrap(),
            value: u64::from_le_bytes(b[64..72].try_into().unwrap()),
            rho: b[72..104].try_into().unwrap(),
            key_commitment: b[104..136].try_into().unwrap(),
            native_pk: b[136..].try_into().unwrap(),
        })
    }
    pub fn commitment(&self, domain: &H) -> H {
        hash(&[NOTE_TAG, domain, &self.bytes()])
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub domain: H,
    pub cm_root: H,
    pub n: u32,
    pub nf_root: H,
    pub m: u32,
}
impl State {
    pub fn bytes(&self) -> [u8; STATE_LEN] {
        let mut b = [0; STATE_LEN];
        b[..8].copy_from_slice(STATE_MAGIC);
        b[8..40].copy_from_slice(&self.domain);
        b[40..72].copy_from_slice(&self.cm_root);
        b[72..76].copy_from_slice(&self.n.to_le_bytes());
        b[76..108].copy_from_slice(&self.nf_root);
        b[108..].copy_from_slice(&self.m.to_le_bytes());
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != STATE_LEN {
            return Err(Error::Length);
        }
        if &b[..8] != STATE_MAGIC {
            return Err(Error::Magic);
        }
        Ok(Self {
            domain: b[8..40].try_into().unwrap(),
            cm_root: b[40..72].try_into().unwrap(),
            n: u32::from_le_bytes(b[72..76].try_into().unwrap()),
            nf_root: b[76..108].try_into().unwrap(),
            m: u32::from_le_bytes(b[108..].try_into().unwrap()),
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        if self.n == 0
            || self.n > MAX_NOTES
            || self.m == 0
            || u64::from(self.m) > 2 * u64::from(self.n) + 1
        {
            return Err(Error::Range);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub domain: H,
    pub previous_outpoint: [u8; 36],
    pub prior: State,
    pub reserve: u64,
    pub fee: u64,
    pub nfs: [H; 2],
    pub outputs: [H; 2],
    pub cipher_hash: H,
    pub next: State,
    pub reserve_after: u64,
    pub payout: u64,
    pub payout_spk: [u8; 36],
}
impl Authorization {
    pub fn bytes(&self) -> [u8; AUTH_LEN] {
        let mut b = [0; AUTH_LEN];
        b[..8].copy_from_slice(AUTH_MAGIC);
        b[8..40].copy_from_slice(&self.domain);
        b[40..76].copy_from_slice(&self.previous_outpoint);
        b[76..188].copy_from_slice(&self.prior.bytes());
        b[188..196].copy_from_slice(&self.reserve.to_le_bytes());
        b[196..204].copy_from_slice(&self.fee.to_le_bytes());
        b[204..236].copy_from_slice(&self.nfs[0]);
        b[236..268].copy_from_slice(&self.nfs[1]);
        b[268..300].copy_from_slice(&self.outputs[0]);
        b[300..332].copy_from_slice(&self.outputs[1]);
        b[332..364].copy_from_slice(&self.cipher_hash);
        b[364..476].copy_from_slice(&self.next.bytes());
        b[476..484].copy_from_slice(&self.reserve_after.to_le_bytes());
        b[484..492].copy_from_slice(&self.payout.to_le_bytes());
        b[492..528].copy_from_slice(&self.payout_spk);
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != AUTH_LEN {
            return Err(Error::Length);
        }
        if &b[..8] != AUTH_MAGIC {
            return Err(Error::Magic);
        }
        Ok(Self {
            domain: b[8..40].try_into().unwrap(),
            previous_outpoint: b[40..76].try_into().unwrap(),
            prior: State::parse(&b[76..188])?,
            reserve: u64::from_le_bytes(b[188..196].try_into().unwrap()),
            fee: u64::from_le_bytes(b[196..204].try_into().unwrap()),
            nfs: [
                b[204..236].try_into().unwrap(),
                b[236..268].try_into().unwrap(),
            ],
            outputs: [
                b[268..300].try_into().unwrap(),
                b[300..332].try_into().unwrap(),
            ],
            cipher_hash: b[332..364].try_into().unwrap(),
            next: State::parse(&b[364..476])?,
            reserve_after: u64::from_le_bytes(b[476..484].try_into().unwrap()),
            payout: u64::from_le_bytes(b[484..492].try_into().unwrap()),
            payout_spk: b[492..528].try_into().unwrap(),
        })
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        let digest = hash(&[&self.bytes()]);
        std::array::from_fn(|i| Fr::from_le_bytes_mod_order(&digest[16 * i..16 * (i + 1)]))
    }
    pub fn validate_public(&self) -> Result<()> {
        self.prior.validate()?;
        self.next.validate()?;
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        if !(1..=MAX).contains(&self.reserve)
            || !(1..=MAX).contains(&self.fee)
            || self.payout > MAX
            || (self.reserve_after != 0 && !(NOTE_FLOOR..=MAX).contains(&self.reserve_after))
            || self
                .reserve
                .checked_sub(self.payout)
                .and_then(|r| r.checked_sub(self.fee))
                != Some(self.reserve_after)
            || self
                .prior
                .n
                .checked_add(if self.reserve_after == 0 { 0 } else { 2 })
                != Some(self.next.n)
            || self.prior.m.checked_add(2) != Some(self.next.m)
            || self.next.m > MAX_NF_LEAVES
            || self.nfs.iter().any(|h| *h == [0; 32])
            || self.nfs[0] == self.nfs[1]
        {
            return Err(Error::Range);
        }
        if self.payout == 0 {
            if self.payout_spk != [0; 36] || self.reserve_after == 0 {
                return Err(Error::Encoding);
            }
        } else if self.payout < PAYOUT_FLOOR
            || self.payout_spk[..3] != [0, 0, 0x20]
            || self.payout_spk[35] != 0xac
        {
            return Err(Error::Encoding);
        }
        if self.reserve_after == 0 {
            if self.outputs != [[0; 32]; 2]
                || self.cipher_hash != terminal_cipher_hash()
                || self.next.cm_root != self.prior.cm_root
            {
                return Err(Error::Encoding);
            }
        } else if self.outputs[0] == self.outputs[1] {
            return Err(Error::Range);
        }
        Ok(())
    }
}

/// Terminal private actions publish no phantom delivery records.
pub fn terminal_cipher_hash() -> H {
    hash(&[&[0; 528]])
}

fn checked_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    if bytes.len() != VK_LEN {
        return Err(Error::Length);
    }
    let mut rem = bytes;
    let vk =
        VerifyingKey::<Bn254>::deserialize_compressed(&mut rem).map_err(|_| Error::Encoding)?;
    let mut encoded = vec![];
    vk.serialize_compressed(&mut encoded)
        .map_err(|_| Error::Encoding)?;
    if !rem.is_empty() || encoded != bytes {
        return Err(Error::Encoding);
    }
    if vk.gamma_abc_g1.len() != 3 {
        return Err(Error::KeyArity);
    }
    if vk.alpha_g1.is_zero()
        || vk.beta_g2.is_zero()
        || vk.gamma_g2.is_zero()
        || vk.delta_g2.is_zero()
        || vk.gamma_abc_g1.iter().any(AffineRepr::is_zero)
    {
        return Err(Error::IdentityPoint);
    }
    Ok(vk)
}
fn checked_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    if bytes.len() != PROOF_LEN {
        return Err(Error::Length);
    }
    let mut rem = bytes;
    let q = Proof::<Bn254>::deserialize_compressed(&mut rem).map_err(|_| Error::Encoding)?;
    let mut encoded = vec![];
    q.serialize_compressed(&mut encoded)
        .map_err(|_| Error::Encoding)?;
    if !rem.is_empty() || encoded != bytes {
        return Err(Error::Encoding);
    }
    if q.a.is_zero() || q.b.is_zero() || q.c.is_zero() {
        return Err(Error::IdentityPoint);
    }
    Ok(q)
}
/// The caller selects this key from trusted configuration, never from a proof.
pub struct Verifier {
    prepared: PreparedVerifyingKey<Bn254>,
}
impl Verifier {
    pub fn new(trusted_vk: &[u8]) -> Result<Self> {
        Ok(Self {
            prepared: prepare_verifying_key(&checked_vk(trusted_vk)?),
        })
    }
    pub fn verify(&self, auth: &Authorization, proof: &[u8]) -> Result<bool> {
        auth.validate_public()?;
        Groth16::<Bn254>::verify_proof(
            &self.prepared,
            &checked_proof(proof)?,
            &auth.public_inputs(),
        )
        .map_err(|_| Error::Verification)
    }
}
/// Fresh development setup only; this module neither loads nor stores a PK.
pub fn setup<R: RngCore + CryptoRng>(
    shape: circuit::ActionCircuit,
    rng: &mut R,
) -> Result<ProvingKey<Bn254>> {
    Groth16::<Bn254>::generate_random_parameters_with_reduction(shape, rng)
        .map_err(|_| Error::Synthesis)
}
pub fn verification_key(pk: &ProvingKey<Bn254>) -> Result<[u8; VK_LEN]> {
    let mut b = vec![];
    pk.vk
        .serialize_compressed(&mut b)
        .map_err(|_| Error::Encoding)?;
    checked_vk(&b)?;
    b.try_into().map_err(|_| Error::Length)
}
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circuit: circuit::ActionCircuit,
    rng: &mut R,
) -> Result<[u8; PROOF_LEN]> {
    let auth = circuit.authorization.clone();
    auth.validate_public()?;
    let q = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
        .map_err(|_| Error::Synthesis)?;
    let mut b = vec![];
    q.serialize_compressed(&mut b)
        .map_err(|_| Error::Encoding)?;
    if !Verifier::new(&verification_key(pk)?)?.verify(&auth, &b)? {
        return Err(Error::Verification);
    }
    b.try_into().map_err(|_| Error::Length)
}
