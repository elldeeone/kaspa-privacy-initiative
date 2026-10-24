//! ADR0058: new-domain compact no-append full-input private exits at capacity.
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
pub const AUTH_MAGIC: &[u8; 8] = b"KPX4AU01";
pub const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
pub const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
pub const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
pub const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
pub const DUMMY_TAG: &[u8; 8] = b"KPX2DMY\0";
pub const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
pub const CM_EMPTY: &[u8; 8] = b"KPX1CME\0";
/// Root-selected fresh development instance, independent of the future VK/policy.
pub const DOMAIN: H = [
    38, 48, 237, 74, 51, 138, 250, 96, 211, 225, 116, 122, 13, 136, 117, 186, 5, 244, 182, 105, 78, 239, 195, 69, 169, 119, 222, 248, 0, 196, 184, 158,
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
    Role,
    OutputArity,
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
            || self.m > MAX_NF_LEAVES
            || u64::from(self.m) > 2 * u64::from(self.n) + 1
        {
            return Err(Error::Range);
        }
        Ok(())
    }
}
/// Installed public configuration selects a fixed relation before private bytes.
/// Neither the private request nor Auth mode can change the allocation count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Compact,
    Wide,
}
impl Role {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "compact2" => Ok(Self::Compact),
            "wide32" => Ok(Self::Wide),
            _ => Err(Error::Role),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Compact => "compact2",
            Self::Wide => "wide32",
        }
    }
    pub const fn output_count(self) -> usize {
        match self {
            Self::Compact => 2,
            Self::Wide => 32,
        }
    }
    pub const fn continuing_mode(self) -> u8 {
        self.output_count() as u8
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
    pub outputs_digest: H,
    pub mode: u8,
    pub cm_start: u32,
    /// Three bytes at301..304 followed by24 at308..332. They must all be zero.
    /// Stored explicitly so direct constraint controls can test the zero gates.
    pub reserved: [u8; 27],
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
        b[268..300].copy_from_slice(&self.outputs_digest);
        b[300] = self.mode;
        b[301..304].copy_from_slice(&self.reserved[..3]);
        b[304..308].copy_from_slice(&self.cm_start.to_le_bytes());
        b[308..332].copy_from_slice(&self.reserved[3..]);
        b[332..364].copy_from_slice(&self.cipher_hash);
        b[364..476].copy_from_slice(&self.next.bytes());
        b[476..484].copy_from_slice(&self.reserve_after.to_le_bytes());
        b[484..492].copy_from_slice(&self.payout.to_le_bytes());
        b[492..528].copy_from_slice(&self.payout_spk);
        b
    }
    /// Parse exact public syntax. Semantic role/range validation is separate;
    /// constraints independently enforce every public semantic condition below.
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != AUTH_LEN {
            return Err(Error::Length);
        }
        if &b[..8] != AUTH_MAGIC {
            return Err(Error::Magic);
        }
        let mut reserved = [0; 27];
        reserved[..3].copy_from_slice(&b[301..304]);
        reserved[3..].copy_from_slice(&b[308..332]);
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
            outputs_digest: b[268..300].try_into().unwrap(),
            mode: b[300],
            cm_start: u32::from_le_bytes(b[304..308].try_into().unwrap()),
            reserved,
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
    pub fn validate_public_for_role(&self, role: Role) -> Result<()> {
        self.prior.validate()?;
        self.next.validate()?;
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        if self.reserved != [0; 27] {
            return Err(Error::Encoding);
        }
        let terminal = self.reserve_after == 0;
        let no_append = self.mode == 0;
        if (terminal && !no_append)
            || match role {
                Role::Compact => self.mode != 0 && self.mode != 2,
                Role::Wide => self.mode != 32 || self.payout != 0,
            }
        {
            return Err(Error::Role);
        }
        if !(1..=MAX).contains(&self.reserve)
            || !(1..=MAX).contains(&self.fee)
            || self.payout > MAX
            || (!terminal && !(NOTE_FLOOR..=MAX).contains(&self.reserve_after))
            || self
                .reserve
                .checked_sub(self.payout)
                .and_then(|r| r.checked_sub(self.fee))
                != Some(self.reserve_after)
            || self.prior.m.checked_add(2) != Some(self.next.m)
            || self.next.m > MAX_NF_LEAVES
            || self.nfs.iter().any(|nf| *nf == [0; 32])
            || self.nfs[0] == self.nfs[1]
        {
            return Err(Error::Range);
        }
        if self.payout == 0 {
            if self.payout_spk != [0; 36] || no_append {
                return Err(Error::Encoding);
            }
        } else if self.payout < PAYOUT_FLOOR
            || self.payout_spk[..3] != [0, 0, 0x20]
            || self.payout_spk[35] != 0xac
        {
            return Err(Error::Encoding);
        }
        if no_append {
            if self.outputs_digest != [0; 32]
                || self.cm_start != 0
                || self.cipher_hash != terminal_cipher_hash()
                || self.next.cm_root != self.prior.cm_root
                || self.next.n != self.prior.n
            {
                return Err(Error::Encoding);
            }
        } else {
            let n = role.output_count() as u32;
            let start = self
                .prior
                .n
                .checked_add(n - 1)
                .map(|v| (v / n) * n)
                .ok_or(Error::Range)?;
            if self.cm_start != start || start.checked_add(n) != Some(self.next.n) {
                return Err(Error::Range);
            }
        }
        Ok(())
    }
}

/// Exact ordered physical-output digest; no additional tag, sorting or omission.
pub fn output_array_digest(domain: &H, outputs: &[Note]) -> H {
    let mut digest = Sha256::new();
    for output in outputs {
        digest.update(output.commitment(domain));
    }
    digest.finalize().into()
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
    role: Role,
}
impl Verifier {
    pub fn new(trusted_vk: &[u8], role: Role) -> Result<Self> {
        Ok(Self {
            prepared: prepare_verifying_key(&checked_vk(trusted_vk)?),
            role,
        })
    }
    pub fn verify(&self, auth: &Authorization, proof: &[u8]) -> Result<bool> {
        auth.validate_public_for_role(self.role)?;
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
    let role = circuit.role;
    auth.validate_public_for_role(role)?;
    let q = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, rng)
        .map_err(|_| Error::Synthesis)?;
    let mut b = vec![];
    q.serialize_compressed(&mut b)
        .map_err(|_| Error::Encoding)?;
    if !Verifier::new(&verification_key(pk)?, role)?.verify(&auth, &b)? {
        return Err(Error::Verification);
    }
    b.try_into().map_err(|_| Error::Length)
}

#[cfg(test)]
mod public_encoding_tests {
    use super::*;

    fn auth(role: Role, n: u32, terminal: bool) -> Authorization {
        let width = role.output_count() as u32;
        let start = ((n + width - 1) / width) * width;
        let prior = State {
            domain: DOMAIN,
            cm_root: [11; 32],
            n,
            nf_root: [12; 32],
            m: 1,
        };
        let next = State {
            domain: DOMAIN,
            cm_root: if terminal { prior.cm_root } else { [13; 32] },
            n: if terminal { n } else { start + width },
            nf_root: [14; 32],
            m: 3,
        };
        let mut spk = [0; 36];
        if terminal {
            spk[..3].copy_from_slice(&[0, 0, 0x20]);
            spk[3..35].fill(9);
            spk[35] = 0xac;
        }
        Authorization {
            domain: DOMAIN,
            previous_outpoint: [4; 36],
            prior,
            reserve: 1_000_000_000,
            fee: 1_000,
            nfs: [[5; 32], [6; 32]],
            outputs_digest: if terminal { [0; 32] } else { [7; 32] },
            mode: if terminal { 0 } else { role.continuing_mode() },
            cm_start: if terminal { 0 } else { start },
            reserved: [0; 27],
            cipher_hash: if terminal {
                terminal_cipher_hash()
            } else {
                [8; 32]
            },
            next,
            reserve_after: if terminal { 0 } else { 999_999_000 },
            payout: if terminal { 999_999_000 } else { 0 },
            payout_spk: spk,
        }
    }

    #[test]
    fn exact_role_names_and_metadata_roundtrip() {
        assert_eq!(Role::parse("compact2"), Ok(Role::Compact));
        assert_eq!(Role::parse("wide32"), Ok(Role::Wide));
        for bad in ["compact", "wide", "Compact2", " wide32", "wide32\n", ""] {
            assert!(Role::parse(bad).is_err());
        }
        for role in [Role::Compact, Role::Wide] {
            let mut value = auth(role, 1, false);
            value.reserved = std::array::from_fn(|i| i as u8 + 1);
            let bytes = value.bytes();
            assert_eq!(bytes[300], role.continuing_mode());
            assert_eq!(&bytes[301..304], &value.reserved[..3]);
            assert_eq!(&bytes[304..308], &value.cm_start.to_le_bytes());
            assert_eq!(&bytes[308..332], &value.reserved[3..]);
            assert_eq!(Authorization::parse(&bytes).unwrap(), value);
            assert!(value.validate_public_for_role(role).is_err());
        }
    }

    #[test]
    fn integer_alignment_and_capacity_boundaries() {
        for role in [Role::Compact, Role::Wide] {
            for old_n in [1, 2, 3, 31, 32, 33, 63, 64, 65, 65_470] {
                let value = auth(role, old_n, false);
                assert!(value.validate_public_for_role(role).is_ok());
                for wrong_start in [old_n - 1, value.cm_start + 1, u32::MAX] {
                    let mut wrong = value.clone();
                    wrong.cm_start = wrong_start;
                    assert!(wrong.validate_public_for_role(role).is_err());
                }
                let mut wrong = value.clone();
                wrong.next.n += 1;
                assert!(wrong.validate_public_for_role(role).is_err());
            }
            let beyond = auth(role, 65_535, false);
            assert!(beyond.validate_public_for_role(role).is_err());
        }
    }

    #[test]
    fn no_append_full_cashout_can_leave_other_owners_backing() {
        let mut value = auth(Role::Compact, MAX_NOTES, true);
        value.reserve = 2_000_000_000;
        value.reserve_after = 1_000_000_000;
        value.prior.m = MAX_NF_LEAVES - 4;
        value.next.m = MAX_NF_LEAVES - 2;
        assert!(value.validate_public_for_role(Role::Compact).is_ok());
        for mutation in 0..5 {
            let mut wrong = value.clone();
            match mutation {
                0 => {
                    wrong.payout = 0;
                    wrong.payout_spk = [0; 36];
                    wrong.reserve_after = wrong.reserve - wrong.fee;
                }
                1 => wrong.next.n -= 1,
                2 => wrong.next.cm_root[0] ^= 1,
                3 => wrong.next.m += 1,
                _ => wrong.cm_start = 2,
            }
            assert!(wrong.validate_public_for_role(Role::Compact).is_err());
        }
        value.prior.m += 2;
        value.next.m += 2;
        assert_eq!(value.next.m, MAX_NF_LEAVES);
        assert!(value.validate_public_for_role(Role::Compact).is_ok());
        value.prior.m += 1;
        value.next.m += 1;
        assert!(value.validate_public_for_role(Role::Compact).is_err());
    }

    #[test]
    fn canonical_terminal_role_and_cipher_sentinels() {
        let terminal = auth(Role::Compact, 1, true);
        assert!(terminal.validate_public_for_role(Role::Compact).is_ok());
        assert!(terminal.validate_public_for_role(Role::Wide).is_err());
        for mutate in 0..6 {
            let mut wrong = terminal.clone();
            match mutate {
                0 => wrong.cipher_hash = hash(&[&[]]),
                1 => wrong.outputs_digest = hash(&[&[]]),
                2 => wrong.cm_start = 2,
                3 => wrong.next.n += 2,
                4 => wrong.next.cm_root[0] ^= 1,
                _ => wrong.mode = 2,
            }
            assert!(wrong.validate_public_for_role(Role::Compact).is_err());
        }
        let compact = auth(Role::Compact, 1, false);
        let wide = auth(Role::Wide, 1, false);
        assert!(compact.validate_public_for_role(Role::Wide).is_err());
        assert!(wide.validate_public_for_role(Role::Compact).is_err());
        let mut wrong = wide;
        wrong.payout = PAYOUT_FLOOR;
        wrong.reserve_after -= PAYOUT_FLOOR;
        assert!(wrong.validate_public_for_role(Role::Wide).is_err());
    }
}
