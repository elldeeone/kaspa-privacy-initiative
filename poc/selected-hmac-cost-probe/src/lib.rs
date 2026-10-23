//! ADR0041: new-format, DO_NOT_FUND private ownership/conservation experiment.
//! This module does not authenticate chain state, update native roots or encrypt
//! delivery records. Those obligations remain at their contract-defined seams.
pub mod circuit;
mod exact_sha256;

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
pub const AUTH_LEN: usize = 484;
pub const PROOF_LEN: usize = 128;
pub const VK_LEN: usize = 328;
pub const CM_DEPTH: usize = 16;
pub const NOTE_FLOOR: u64 = 60_000_000;
pub const MAX: u64 = 2_870_000_000_000_000_000;
pub const MAX_NOTES: u32 = 65_535;
pub const MAX_NF_LEAVES: u32 = 131_071;
pub const STATE_MAGIC: &[u8; 8] = b"KPX2ST01";
pub const AUTH_MAGIC: &[u8; 8] = b"KPX2AU01";
pub const OWNER_TAG: &[u8; 8] = b"KPX1OWN\0";
pub const KEY_TAG: &[u8; 8] = b"KPX1KEY\0";
pub const NOTE_TAG: &[u8; 8] = b"KPX1NOT\0";
pub const NF_TAG: &[u8; 8] = b"KPX1NF\0\0";
pub const DUMMY_TAG: &[u8; 8] = b"KPX2DMY\0";
pub const CM_NODE: &[u8; 8] = b"KPX1CMN\0";
pub const CM_EMPTY: &[u8; 8] = b"KPX1CME\0";
/// Root-selected fresh development instance, independent of the future VK/policy.
pub const DOMAIN: H = [
    0x9d, 0xe4, 0xf8, 0x4d, 0xbd, 0xae, 0xc6, 0x25, 0x0d, 0x00, 0x29, 0xca, 0x4b, 0x38, 0xae, 0x12,
    0xb9, 0x08, 0x1a, 0x54, 0x9e, 0x23, 0x1e, 0xb5, 0x29, 0x07, 0x5a, 0xf7, 0xfe, 0x59, 0xe8, 0x5c,
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
        b[476..].copy_from_slice(&self.reserve_after.to_le_bytes());
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
            reserve_after: u64::from_le_bytes(b[476..].try_into().unwrap()),
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
            || !(NOTE_FLOOR..=MAX).contains(&self.reserve_after)
            || self.reserve.checked_sub(self.fee) != Some(self.reserve_after)
            || self.prior.n.checked_add(2) != Some(self.next.n)
            || self.prior.m.checked_add(2) != Some(self.next.m)
            || self.next.m > MAX_NF_LEAVES
            || self.nfs.iter().any(|h| *h == [0; 32])
            || self.nfs[0] == self.nfs[1]
            || self.outputs[0] == self.outputs[1]
        {
            return Err(Error::Range);
        }
        Ok(())
    }
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
    shape: circuit::TransferCircuit,
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
    circuit: circuit::TransferCircuit,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_selected_domain() {
        assert_eq!(
            hash(&[b"KPI/future-private-native-integration/DO-NOT-FUND/v1/2026-10-23"]),
            DOMAIN
        );
    }
    #[test]
    fn note_wire_and_domains() {
        let n = Note {
            owner: [1; 32],
            incoming: [2; 32],
            value: 60_000_000,
            rho: [3; 32],
            key_commitment: [4; 32],
            native_pk: [5; 32],
        };
        assert_eq!(Note::parse(&n.bytes()).unwrap(), n);
        assert_eq!(&n.bytes()[64..72], &60_000_000u64.to_le_bytes());
        assert!(Note::parse(&n.bytes()[..167]).is_err());
        let mut d = DOMAIN;
        d[0] ^= 1;
        assert_ne!(n.commitment(&d), n.commitment(&DOMAIN));
    }
    #[test]
    fn positioned_rfc2104() {
        let k = [9; 32];
        let cm = [7; 32];
        let msg = [
            NF_TAG.as_slice(),
            DOMAIN.as_slice(),
            cm.as_slice(),
            17u32.to_le_bytes().as_slice(),
        ]
        .concat();
        let mut reference = Hmac::<Sha256>::new_from_slice(&k).unwrap();
        reference.update(&msg);
        let expected: H = reference.finalize().into_bytes().into();
        assert_eq!(expected, nullifier(&DOMAIN, &k, &cm, 17));
        assert_ne!(expected, nullifier(&DOMAIN, &k, &cm, 18));
        assert_ne!(expected, dummy_nullifier(&DOMAIN, &k, &cm, 0));
    }
    #[test]
    fn state_has_no_nf_parity_rule() {
        let s = State {
            domain: DOMAIN,
            cm_root: [1; 32],
            n: 2,
            nf_root: [2; 32],
            m: 4,
        };
        s.validate().unwrap();
        assert_eq!(State::parse(&s.bytes()).unwrap(), s);
        let mut bad = s.clone();
        bad.m = 6;
        assert_eq!(bad.validate(), Err(Error::Range));
        bad = s;
        bad.n = 65_536;
        assert_eq!(bad.validate(), Err(Error::Range));
    }
    #[test]
    fn canonical_key_and_proof_framing() {
        assert!(Verifier::new(&[0; VK_LEN - 1]).is_err());
        assert!(Verifier::new(&[0; VK_LEN]).is_err());
        assert!(checked_proof(&[0; PROOF_LEN - 1]).is_err());
        assert!(checked_proof(&[0; PROOF_LEN]).is_err());
    }
}

#[cfg(test)]
mod cross_language {
    use super::*;
    fn vector_v1() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/public/recipient-v1-core-hash-known-answer.json"
        ))
        .unwrap()
    }
    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/public/recipient-v2-known-answer.json"
        ))
        .unwrap()
    }
    fn h(v: &serde_json::Value, k: &str) -> H {
        hex::decode(v[k].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    #[test]
    fn recipient_v1_core_hash_known_answer() {
        let v = vector_v1();
        let receipt = hex::decode(v["receipt216"].as_str().unwrap()).unwrap();
        let note = Note::parse(&receipt[48..]).unwrap();
        assert_eq!(h(&v, "domain"), DOMAIN);
        assert_eq!(owner(&DOMAIN, &h(&v, "s"), &note.incoming), note.owner);
        assert_eq!(key_commitment(&DOMAIN, &h(&v, "k")), note.key_commitment);
        assert_eq!(note.commitment(&DOMAIN), h(&v, "CM"));
        assert_eq!(
            nullifier(&DOMAIN, &h(&v, "k"), &note.commitment(&DOMAIN), 0),
            h(&v, "NF")
        );
        assert_eq!(receipt.len(), 216);
        assert_eq!(
            hex::decode(v["invoice176"].as_str().unwrap())
                .unwrap()
                .len(),
            176
        );
    }

    #[test]
    fn recipient_v2_known_answer() {
        let v = vector();
        let receipt = hex::decode(v["receipt216"].as_str().unwrap()).unwrap();
        let note = Note::parse(&receipt[48..]).unwrap();
        assert_eq!(h(&v, "domain"), DOMAIN);
        assert_eq!(owner(&DOMAIN, &h(&v, "s"), &note.incoming), note.owner);
        assert_eq!(key_commitment(&DOMAIN, &h(&v, "k")), note.key_commitment);
        assert_eq!(note.commitment(&DOMAIN), h(&v, "CM"));
        assert_eq!(
            nullifier(&DOMAIN, &h(&v, "k"), &note.commitment(&DOMAIN), 0),
            h(&v, "NF")
        );
        assert_ne!(note.incoming, h(&v, "deliveryPK"));
        assert_eq!(
            hex::decode(v["invoice208"].as_str().unwrap())
                .unwrap()
                .len(),
            208
        );
    }

    // Sizing-only public vector: one real input plus padding, two positive self
    // outputs. It is not the separately selected two-recipient/native trace.
    pub(crate) fn sizing_fixture() -> circuit::TransferCircuit {
        let v = vector();
        let receipt = hex::decode(v["receipt216"].as_str().unwrap()).unwrap();
        let mut input = Note::parse(&receipt[48..]).unwrap();
        input.value = 130_000_000;
        let mut empty_path = [[0; 32]; CM_DEPTH];
        let mut empty = hash(&[CM_EMPTY]);
        for item in &mut empty_path {
            *item = empty;
            empty = hash(&[CM_NODE, &empty, &empty]);
        }
        let cm = input.commitment(&DOMAIN);
        let mut root = cm;
        for sibling in &empty_path {
            root = hash(&[CM_NODE, &root, sibling]);
        }
        let first = circuit::InputWitness {
            real: true,
            note: input.clone(),
            owner_secret: h(&v, "s"),
            nullifier_secret: h(&v, "k"),
            position: 0,
            path: empty_path,
            dummy_key: [0; 32],
            dummy_seed: [0; 32],
        };
        let second = circuit::InputWitness {
            real: false,
            note: Note::zero(),
            owner_secret: [0; 32],
            nullifier_secret: [0; 32],
            position: 0,
            path: [[0; 32]; CM_DEPTH],
            dummy_key: [0x73; 32],
            dummy_seed: [0x74; 32],
        };
        let mut outputs = [input.clone(), input];
        for (i, n) in outputs.iter_mut().enumerate() {
            n.value = NOTE_FLOOR;
            n.rho = hash(&[b"PUBLIC-sizing-output", &[i as u8]]);
        }
        let prior = State {
            domain: DOMAIN,
            cm_root: root,
            n: 1,
            nf_root: [0x31; 32],
            m: 1,
        };
        // These root bytes are transcript-bound placeholders only. Actual native
        // root-update integration uses independently derived public witnesses.
        let next = State {
            domain: DOMAIN,
            cm_root: [0x41; 32],
            n: 3,
            nf_root: [0x42; 32],
            m: 3,
        };
        let auth = Authorization {
            domain: DOMAIN,
            previous_outpoint: [0x51; 36],
            prior,
            reserve: 130_000_000,
            fee: 10_000_000,
            nfs: [
                nullifier(&DOMAIN, &h(&v, "k"), &cm, 0),
                dummy_nullifier(&DOMAIN, &second.dummy_key, &second.dummy_seed, 1),
            ],
            outputs: outputs.each_ref().map(|n| n.commitment(&DOMAIN)),
            cipher_hash: hash(&[b"PUBLIC-sizing-only-cipher-placeholder"]),
            next,
            reserve_after: 120_000_000,
        };
        circuit::TransferCircuit {
            authorization: auth,
            inputs: [first, second],
            outputs,
        }
    }
    #[test]
    fn auth_exact_wire() {
        let c = sizing_fixture();
        let a = &c.authorization;
        a.validate_public().unwrap();
        let bytes = a.bytes();
        assert_eq!(bytes.len(), 484);
        assert_eq!(Authorization::parse(&bytes).unwrap(), *a);
        assert_eq!(&bytes[40..76], &a.previous_outpoint);
        assert_eq!(&bytes[76..188], &a.prior.bytes());
        assert_eq!(&bytes[364..476], &a.next.bytes());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(Authorization::parse(&trailing), Err(Error::Length));
        let mut bad = bytes;
        bad[0] ^= 1;
        assert_eq!(Authorization::parse(&bad), Err(Error::Magic));
        let digest = hash(&[&bytes]);
        assert_eq!(
            a.public_inputs(),
            [
                Fr::from_le_bytes_mod_order(&digest[..16]),
                Fr::from_le_bytes_mod_order(&digest[16..])
            ]
        );
    }
    #[test]
    #[ignore = "large complete relation synthesis requires reviewed resource release"]
    fn measure_contract_synthesis() {
        let c = sizing_fixture();
        let start = std::time::Instant::now();
        let stats = c.check().unwrap();
        println!(
            "constraints={} instance_variables={} witness_variables={} satisfied={} seconds={}",
            stats.constraints,
            stats.instance_variables,
            stats.witness_variables,
            stats.satisfied,
            start.elapsed().as_secs_f64()
        );
        assert!(stats.satisfied);
        assert_eq!(stats.instance_variables, 3);
        assert!(
            stats.constraints + stats.instance_variables <= (1usize << 22),
            "frozen target: supported FFT domain must remain <=2^22"
        );
        assert!(
            stats.constraints < 3_497_893,
            "frozen target: fewer constraints than the closed exact-SHA circuit"
        );
    }
    #[test]
    #[ignore = "complete relation controls require measured resources and review"]
    fn constraint_authority_and_boundaries() {
        for case in [
            "wrong_s",
            "wrong_k",
            "copied_k_no_s",
            "all_dummy",
            "dummy_nonzero_s",
            "real_nonzero_dummy_seed",
            "wrong_path",
            "high_position",
            "wrong_real_nf",
            "wrong_dummy_slot_nf",
            "output_cm_substitution",
            "subfloor_output",
            "out_of_range_value",
            "wrong_domain",
            "wrong_state_domain",
            "fee_reserve_mismatch",
            "count_capacity",
        ] {
            let mut c = sizing_fixture();
            match case {
                "wrong_s" => c.inputs[0].owner_secret[0] ^= 1,
                "wrong_k" => c.inputs[0].nullifier_secret[0] ^= 1,
                "copied_k_no_s" => c.inputs[0].owner_secret = [0; 32],
                "all_dummy" => {
                    c.inputs[0] = c.inputs[1].clone();
                    c.authorization.nfs[0] = dummy_nullifier(
                        &DOMAIN,
                        &c.inputs[0].dummy_key,
                        &c.inputs[0].dummy_seed,
                        0,
                    );
                }
                "dummy_nonzero_s" => c.inputs[1].owner_secret[0] = 1,
                "real_nonzero_dummy_seed" => c.inputs[0].dummy_seed[0] = 1,
                "wrong_path" => c.inputs[0].path[0][0] ^= 1,
                "high_position" => c.inputs[0].position = 65536,
                "wrong_real_nf" => c.authorization.nfs[0][0] ^= 1,
                "wrong_dummy_slot_nf" => {
                    c.authorization.nfs[1] =
                        dummy_nullifier(&DOMAIN, &c.inputs[1].dummy_key, &c.inputs[1].dummy_seed, 0)
                }
                "output_cm_substitution" => c.authorization.outputs[0][0] ^= 1,
                "subfloor_output" => {
                    c.outputs[0].value = NOTE_FLOOR - 1;
                    c.outputs[1].value = NOTE_FLOOR + 1;
                    c.authorization.outputs = c.outputs.each_ref().map(|n| n.commitment(&DOMAIN));
                }
                "out_of_range_value" => c.inputs[0].note.value = MAX + 1,
                "wrong_domain" => c.authorization.domain[0] ^= 1,
                "wrong_state_domain" => c.authorization.prior.domain[0] ^= 1,
                "fee_reserve_mismatch" => c.authorization.reserve_after += 1,
                "count_capacity" => {
                    c.authorization.prior.n = 65534;
                    c.authorization.next.n = 65536;
                }
                _ => unreachable!(),
            }
            let stats = c.check().unwrap();
            println!(
                "case={case} constraints={} satisfied={}",
                stats.constraints, stats.satisfied
            );
            assert!(!stats.satisfied, "{case}");
        }
    }
}
