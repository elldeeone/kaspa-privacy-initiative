//! Experimental bounded shared native-KAS domain. All amounts are integer sompi.
use crate::Result;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use crypto_box::{PublicKey, SecretKey};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type H = [u8; 32];
pub const CAP: usize = 24;
pub const NF_START: usize = 3 + 32 * CAP;
pub const STATE_LEN: usize = 3 + 64 * CAP;
pub const CIPHER_START: usize = 9 + STATE_LEN;
pub const PAYLOAD_LEN: usize = CIPHER_START + 370;
pub const T_PREV: usize = 40 + STATE_LEN;
pub const T_RIN: usize = T_PREV + 40;
pub const T_ROUT: usize = T_RIN + 8;
pub const T_PAYOUT: usize = T_ROUT + 8;
pub const T_PSPK: usize = T_PAYOUT + 8;
pub const T_DEP: usize = T_PSPK + 36;
pub const T_HASH: usize = T_DEP + 84;
pub const TRANSCRIPT_LEN: usize = T_HASH + 32;
pub const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
// Version-3 immutable economic floors, at the bounded trial's 100 sompi/gram.
// 16_713_000 covers the larger full-exit fee for this fixed native layout.
// These constants are constrained in the relation, hence bound by its VK.
pub const MIN_NATIVE_PAYOUT: u64 = 10_000_000;
pub const MIN_NOTE: u64 = 26_713_000;
pub const RESERVE: u64 = 1_000_000_000;
pub const PAYMENT: u64 = 400_000_000;
pub const GENESIS_HEX: &str = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370";
pub const OWNER_TAG: &[u8] = b"KPI-owner-v1\0";
pub const NOTE_TAG: &[u8] = b"KPI-note-v1\0";
pub const NF_TAG: &[u8] = b"KPI-nullifier-v1\0";
pub fn hash(bytes: &[u8]) -> H {
    Sha256::digest(bytes).into()
}
pub fn random() -> H {
    let mut out = [0; 32];
    OsRng.fill_bytes(&mut out);
    out
}
pub fn new_domain() -> H {
    hash(
        &[
            b"KPI/SHARED-POOL/TN10/v3\0".as_slice(),
            &hex::decode(GENESIS_HEX).unwrap(),
            &random(),
        ]
        .concat(),
    )
}
pub fn tagged(tag: &[u8], domain: &H, fields: &[&[u8]]) -> H {
    let mut bytes = [tag, domain].concat();
    for field in fields {
        bytes.extend(*field);
    }
    hash(&bytes)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    pub owner: H,
    pub incoming: H,
    pub value: u64,
    pub rho: H,
}
impl Note {
    pub fn dummy() -> Self {
        Self {
            owner: [0; 32],
            incoming: [0; 32],
            value: 0,
            rho: [0; 32],
        }
    }
    pub fn commitment(&self, d: &H) -> H {
        tagged(
            NOTE_TAG,
            d,
            &[
                &self.owner,
                &self.incoming,
                &self.value.to_le_bytes(),
                &self.rho,
            ],
        )
    }
    pub fn plaintext(&self, d: &H) -> Vec<u8> {
        [
            &[1],
            d.as_slice(),
            &self.owner,
            &self.incoming,
            &self.value.to_le_bytes(),
            &self.rho,
        ]
        .concat()
    }
    pub fn encrypt(&self, d: &H) -> Result<Vec<u8>> {
        PublicKey::from(self.incoming)
            .seal(&mut OsRng, &self.plaintext(d))
            .map_err(|_| "note encryption failed".into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receive {
    pub owner: H,
    pub incoming: H,
}
impl Receive {
    pub fn note(&self, value: u64) -> Result<Note> {
        if value == 0 || value > MAX_SOMPI {
            return Err("note value range".into());
        }
        Ok(Note {
            owner: self.owner,
            incoming: self.incoming,
            value,
            rho: random(),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wallet {
    pub spending: H,
    pub viewing: H,
    pub native: H,
}
impl Wallet {
    pub fn fresh() -> Self {
        Self {
            spending: random(),
            viewing: random(),
            native: random(),
        }
    }
    pub fn payout_key(&self, d: &H, step: u32) -> H {
        for retry in 0u32.. {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.native).expect("HMAC accepts 32-byte key");
            mac.update(b"KPI/payout-key/v2\0");
            mac.update(d);
            mac.update(&step.to_le_bytes());
            mac.update(&retry.to_le_bytes());
            let candidate: H = mac.finalize().into_bytes().into();
            if secp256k1::SecretKey::from_slice(&candidate).is_ok() {
                return candidate;
            }
        }
        unreachable!("valid secp256k1 scalar sampling exhausted")
    }
    /// Fresh-wallet funding purpose. The legacy payout derivation above stays
    /// unchanged so historical funding and exit keys remain recoverable.
    pub fn funding_key(&self, d: &H, index: u32) -> H {
        for retry in 0u32.. {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.native).expect("HMAC accepts 32-byte key");
            mac.update(b"KPI/funding-key/v1\0");
            mac.update(d);
            mac.update(&index.to_le_bytes());
            mac.update(&retry.to_le_bytes());
            let candidate: H = mac.finalize().into_bytes().into();
            if secp256k1::SecretKey::from_slice(&candidate).is_ok() {
                return candidate;
            }
        }
        unreachable!("valid secp256k1 scalar sampling exhausted")
    }
    pub fn receive(&self, d: &H) -> Receive {
        let incoming = *SecretKey::from(self.viewing).public_key().as_bytes();
        Receive {
            owner: tagged(OWNER_TAG, d, &[&self.spending, &incoming]),
            incoming,
        }
    }
    pub fn decrypt(&self, d: &H, cipher: &[u8], cm: &H) -> Result<Note> {
        let plain = SecretKey::from(self.viewing)
            .unseal(cipher)
            .map_err(|_| "note decryption failed")?;
        if plain.len() != 137 || plain[0] != 1 || plain[1..33] != *d {
            return Err("note framing/domain".into());
        }
        let note = Note {
            owner: plain[33..65].try_into()?,
            incoming: plain[65..97].try_into()?,
            value: u64::from_le_bytes(plain[97..105].try_into()?),
            rho: plain[105..137].try_into()?,
        };
        let address = self.receive(d);
        if note.owner != address.owner
            || note.incoming != address.incoming
            || note.value == 0
            || note.value > MAX_SOMPI
            || note.commitment(d) != *cm
        {
            return Err("received note validation".into());
        }
        Ok(note)
    }
}
pub fn nullifier(d: &H, secret: &H, cm: &H) -> H {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(NF_TAG);
    mac.update(d);
    mac.update(cm);
    mac.finalize().into_bytes().into()
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub commitments: Vec<H>,
    pub nullifiers: Vec<H>,
}
impl State {
    pub fn check(&self) -> Result<()> {
        if self.commitments.is_empty()
            || self.commitments.len() > CAP
            || self.nullifiers.len() > self.commitments.len()
        {
            return Err("state capacity/counts".into());
        }
        for values in [&self.commitments, &self.nullifiers] {
            for (i, x) in values.iter().enumerate() {
                if *x == [0; 32] || values[..i].contains(x) {
                    return Err("zero/duplicate state member".into());
                }
            }
        }
        Ok(())
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![3, self.commitments.len() as u8, self.nullifiers.len() as u8];
        for values in [&self.commitments, &self.nullifiers] {
            for i in 0..CAP {
                bytes.extend(values.get(i).copied().unwrap_or([0; 32]));
            }
        }
        bytes
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != STATE_LEN
            || bytes[0] != 3
            || usize::from(bytes[1]) > CAP
            || usize::from(bytes[2]) > CAP
        {
            return Err("state encoding".into());
        }
        let mut groups = [Vec::new(), Vec::new()];
        for (g, start) in [3, NF_START].into_iter().enumerate() {
            let count = bytes[g + 1] as usize;
            for i in 0..CAP {
                let x: H = bytes[start + 32 * i..start + 32 * (i + 1)].try_into()?;
                if i < count {
                    groups[g].push(x);
                } else if x != [0; 32] {
                    return Err("nonzero inactive state slot".into());
                }
            }
        }
        let result = Self {
            commitments: groups[0].clone(),
            nullifiers: groups[1].clone(),
        };
        result.check()?;
        Ok(result)
    }
    pub fn spend(&self, d: &H, secret: &H, note: &Note, outputs: &[Note]) -> Result<Self> {
        self.check()?;
        let cm = note.commitment(d);
        let nf = nullifier(d, secret, &cm);
        if !self.commitments.contains(&cm) || self.nullifiers.contains(&nf) {
            return Err("absent/already spent note".into());
        }
        let mut next = self.clone();
        next.nullifiers.push(nf);
        for output in outputs {
            next.commitments.push(output.commitment(d));
        }
        next.check()?;
        Ok(next)
    }
}
pub fn output_count(mode: u8) -> Result<usize> {
    match mode {
        0 | 4 => Ok(1),
        1 => Ok(2),
        2 | 3 => Ok(0),
        _ => Err("unknown mode".into()),
    }
}
pub fn payload(mode: u8, state: &State, ciphertexts: &[Vec<u8>; 2]) -> Result<Vec<u8>> {
    state.check()?;
    let count = output_count(mode)?;
    if ciphertexts.iter().any(|x| x.len() != 185)
        || ciphertexts[count..].iter().flatten().any(|x| *x != 0)
    {
        return Err("ciphertext shape/padding".into());
    }
    Ok([
        b"KPISP03\0".as_slice(),
        &[mode],
        &state.bytes(),
        &ciphertexts[0],
        &ciphertexts[1],
    ]
    .concat())
}
pub fn parse_payload(b: &[u8]) -> Result<(u8, State, [Vec<u8>; 2])> {
    if b.len() != PAYLOAD_LEN || &b[..8] != b"KPISP03\0" {
        return Err("payload framing".into());
    }
    let state = State::parse(&b[9..CIPHER_START])?;
    let cipher = [
        b[CIPHER_START..CIPHER_START + 185].to_vec(),
        b[CIPHER_START + 185..].to_vec(),
    ];
    if payload(b[8], &state, &cipher)? != b {
        return Err("noncanonical payload".into());
    }
    Ok((b[8], state, cipher))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub domain: H,
    pub old: State,
    pub txid: H,
    pub index: u32,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub payout: u64,
    pub payout_spk: Vec<u8>,
    pub deposit: Vec<u8>, // txid32 | indexLE64 | amountLE64 | P2PK SPK36, or zero84
    pub payload: Vec<u8>,
}
impl Transition {
    pub fn bytes(&self) -> Vec<u8> {
        [
            b"KPIBN03\0".as_slice(),
            &self.domain,
            &self.old.bytes(),
            &self.txid,
            &u64::from(self.index).to_le_bytes(),
            &self.reserve_in.to_le_bytes(),
            &self.reserve_out.to_le_bytes(),
            &self.payout.to_le_bytes(),
            &self.payout_spk,
            &self.deposit,
            &hash(&self.payload),
        ]
        .concat()
    }
    pub fn inputs(&self) -> [Fr; 2] {
        let h = hash(&self.bytes());
        [
            Fr::from_le_bytes_mod_order(&h[..16]),
            Fr::from_le_bytes_mod_order(&h[16..]),
        ]
    }
}

#[cfg(test)]
mod native_derivation_tests {
    use super::*;

    #[test]
    fn independent_legacy_and_funding_known_answers() {
        // Public fixture values, computed independently with Python stdlib
        // hmac/hashlib and checked against the secp256k1 scalar order. Each
        // vector accepts retry 0; this is not rejection-path coverage.
        let wallet = Wallet {
            spending: [0; 32],
            viewing: [0; 32],
            native: [0x11; 32],
        };
        let vectors = [
            (
                0x22,
                0,
                "9ec39f5a7bff3f8cbbcd8e7226baeff2566f60bd227f7f3838300e3bda8e174c",
                "4e6140ecaa4fa441cb0f97ca494a305f998773982bc16dc19917ea6f47ac1d25",
            ),
            (
                0x22,
                1,
                "7fe888d648d0ecb42cb9644e3aef37108c4d1826798c63de6bd4618b992f57ef",
                "7f1191842f8b4db20c4b97aa7ff013a1a0b744acb3e2bdc2a18ac142fac64d0b",
            ),
            (
                0x22,
                3,
                "06fd1553e12f0d480d6a224a2c08eb82707f3b11e76fb4e1590049e1d49babbb",
                "5316e177a941dd19e324bd8c64271938637aa9113cd0f889d8446009631eb7fb",
            ),
            (
                0x22,
                0x01020304,
                "57d00183773f133ac61aac483380dcdc1e22bac6de6f1ae7ae3b14ffc98b60a0",
                "d5bce2fd363c65b087647c26714a9b8d4cc42a4840195b7e2324f34953b3d6bf",
            ),
            (
                0x22,
                u32::MAX,
                "a26fa30bdf4e2eb2dbaf5fdd64dcf33ded4e04448a8809bbaa0d8d5fe1cf4765",
                "76bea26182e1b9bc74cd141fad7cd71152eb19ed2da4d55a2bb4e141f18c3b8c",
            ),
            (
                0x23,
                0,
                "7fcf70cac7663ca4098e3e2f9b3830da8930b24920c80c08a0bc03056b50d59a",
                "eade61a6f688ff098e60916c3144ac7aad44f961eb218d32f560f4554ab4ab19",
            ),
        ];
        let mut scripts = std::collections::HashSet::new();
        for (domain_byte, index, payout, funding) in vectors {
            let domain = [domain_byte; 32];
            let payout_key = wallet.payout_key(&domain, index);
            let funding_key = wallet.funding_key(&domain, index);
            assert_eq!(hex::encode(payout_key), payout);
            assert_eq!(hex::encode(funding_key), funding);
            for key in [payout_key, funding_key] {
                let spk = crate::native::p2pk(&key).unwrap();
                assert!(scripts.insert(crate::native::encode_spk(&spk)));
            }
        }
        let zero = Wallet {
            native: [0; 32],
            ..wallet
        };
        assert_eq!(
            hex::encode(zero.payout_key(&[0; 32], 0)),
            "c61f12011768e8dc75e0413448e4d15c9b2f9ae60cc25246d7fb03ef123f6f2c"
        );
        assert_eq!(
            hex::encode(zero.funding_key(&[0; 32], 0)),
            "7b92e61e79df83cca08d692cb3100f4e86621bfe9e0c1701c216c0ba0d3c69c8"
        );
    }

    #[test]
    fn native_derivation_depends_on_native_master_not_note_keys() {
        let wallet = Wallet {
            spending: [1; 32],
            viewing: [2; 32],
            native: [3; 32],
        };
        let note_keys = Wallet {
            spending: [4; 32],
            viewing: [5; 32],
            ..wallet.clone()
        };
        let native_key = Wallet {
            native: [6; 32],
            ..wallet.clone()
        };
        let d = [7; 32];
        assert_eq!(wallet.payout_key(&d, 3), note_keys.payout_key(&d, 3));
        assert_eq!(wallet.funding_key(&d, 3), note_keys.funding_key(&d, 3));
        assert_ne!(wallet.payout_key(&d, 3), native_key.payout_key(&d, 3));
        assert_ne!(wallet.funding_key(&d, 3), native_key.funding_key(&d, 3));
    }
}
