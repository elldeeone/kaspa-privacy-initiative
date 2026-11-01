//! Evidence-only loader/verifier for the offline two-round W1 fixture.
//!
//! Compiled only by the non-default `offline-w1-verifier` feature. It consumes
//! complete clear-witness leaves and writes a create-new evidence receipt. It
//! never constructs a production source authority, verified closure, capture,
//! Close, setup, or admission capability.

use super::{
    AGGREGATE_CONSTRAINTS, AGGREGATE_MATRIX, AGGREGATE_VARIABLES, AGGREGATE_VK, FullW1RoundSource,
    SIGNATURE_MATRIX_RAW_SHA256, SelectedAggregateProof, SignatureWitnessSource, W0PhysicalGraph,
    append_signature_witnesses, check_cross_round, check_graph, check_outputs, check_public_close,
    check_signatures, collect, verify_groth16,
};
use crate::{
    BatchCircuit, BatchWitness, Context, EFFECT_BYTES, Effects, H, Note, NullifierWitness, OUTPUTS,
    OWNERS, OutputWitness, OwnerWitness, Profile, wire,
};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "offline-w1-preparer")]
mod frozen_assignment;
#[cfg(feature = "offline-w1-prover")]
pub use frozen_assignment::{
    FROZEN_W1_PROOF_RECEIPT_MAX_BYTES, FrozenRound1ProofReceiptCommitment,
    FrozenRound1ProofRefused, FrozenRound1ProofVerificationRefused,
    verify_frozen_round1_proof_receipt, write_frozen_round1_proof_receipt,
};
#[cfg(feature = "offline-w1-preparer")]
pub use frozen_assignment::{
    FrozenRound1AssignmentRefused, write_frozen_round1_assignment_receipt,
};

const REQUEST_SCHEMA: &str = "kpb-offline-w1-rust-aggregate-verifier-request/v1";
const RECEIPT_SCHEMA: &str = "kpb-offline-w1-rust-aggregate-verification/v1";
const CLASSIFICATION: &str = "CALLER_SUPPLIED_CLEAR_WITNESS_RELATION_EVIDENCE_ONLY";
const SIGNATURE_MAP: &str = "dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712";
const OUTPUT_VK: &str = "8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119";

type R<T> = Result<T, OfflineError>;

#[derive(Clone, Copy)]
enum OfflineError {
    Input,
    Shape,
    Binding,
    Relation,
    Proof,
    Output,
}

/// One deliberately opaque public failure shape.
pub struct OfflineVerificationRefused {
    _private: (),
}

impl From<OfflineError> for OfflineVerificationRefused {
    fn from(_: OfflineError) -> Self {
        Self { _private: () }
    }
}

fn need(value: bool, error: OfflineError) -> R<()> {
    if value { Ok(()) } else { Err(error) }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical(value: &Value) -> R<Vec<u8>> {
    let mut raw = serde_json::to_vec(value).map_err(|_| OfflineError::Input)?;
    raw.push(b'\n');
    Ok(raw)
}

struct Unique(Value);
struct UniqueVisitor;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON with unique keys")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(value)
            .map(|number| Unique(Value::Number(number)))
            .ok_or_else(|| E::custom("finite JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<Unique>()? {
            values.push(value.0);
        }
        Ok(Unique(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON key"));
            }
            values.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(values)))
    }
}

fn unique_json(raw: &[u8]) -> R<Value> {
    serde_json::from_slice::<Unique>(raw)
        .map(|value| value.0)
        .map_err(|_| OfflineError::Input)
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => {
            for value in values.iter_mut() {
                zeroize_json(value);
            }
            values.clear();
        }
        Value::Object(values) => {
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    *value = Value::Null;
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

fn exact_keys(value: &Value, keys: &[&str]) -> R<()> {
    let object = value.as_object().ok_or(OfflineError::Shape)?;
    need(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        OfflineError::Shape,
    )
}

fn at<'a>(value: &'a Value, key: &str) -> R<&'a Value> {
    value.get(key).ok_or(OfflineError::Shape)
}
fn text<'a>(value: &'a Value, key: &str) -> R<&'a str> {
    at(value, key)?.as_str().ok_or(OfflineError::Shape)
}
fn uint(value: &Value, key: &str) -> R<u64> {
    at(value, key)?.as_u64().ok_or(OfflineError::Shape)
}

fn canonical_hex<const N: usize>(value: &Value, key: &str) -> R<[u8; N]> {
    let value = text(value, key)?;
    need(
        value.len() == N * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        OfflineError::Shape,
    )?;
    hex::decode(value)
        .map_err(|_| OfflineError::Shape)?
        .try_into()
        .map_err(|_| OfflineError::Shape)
}

fn canonical_sha(value: &str) -> R<&str> {
    need(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        OfflineError::Shape,
    )?;
    Ok(value)
}

fn safe_path(value: &str, base: &Path) -> R<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        need(
            path.components()
                .all(|component| !matches!(component, Component::ParentDir | Component::CurDir)),
            OfflineError::Input,
        )?;
        Ok(path)
    } else {
        let components = path.components().collect::<Vec<_>>();
        need(
            components.len() == 1 && matches!(components[0], Component::Normal(_)),
            OfflineError::Input,
        )?;
        Ok(base.join(path))
    }
}

struct LoadedRef {
    raw: Vec<u8>,
    sha256: String,
}

impl Drop for LoadedRef {
    fn drop(&mut self) {
        self.raw.zeroize();
        self.sha256.zeroize();
    }
}

fn load_ref(value: &Value, expected_bytes: Option<usize>, base: &Path) -> R<LoadedRef> {
    exact_keys(value, &["bytes", "path", "sha256"])?;
    let path = safe_path(text(value, "path")?, base)?;
    let expected_sha = canonical_sha(text(value, "sha256")?)?;
    let expected_size: usize = uint(value, "bytes")?
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    need(
        expected_bytes.map_or(true, |width| width == expected_size),
        OfflineError::Shape,
    )?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| OfflineError::Input)?;
    need(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        OfflineError::Input,
    )?;
    #[cfg(unix)]
    need(metadata.nlink() == 1, OfflineError::Input)?;
    let mut file = fs::File::open(&path).map_err(|_| OfflineError::Input)?;
    let opened = file.metadata().map_err(|_| OfflineError::Input)?;
    need(opened.is_file(), OfflineError::Input)?;
    #[cfg(unix)]
    need(
        opened.dev() == metadata.dev() && opened.ino() == metadata.ino() && opened.nlink() == 1,
        OfflineError::Input,
    )?;
    let mut raw = Zeroizing::new(Vec::with_capacity(expected_size));
    file.read_to_end(&mut raw)
        .map_err(|_| OfflineError::Input)?;
    need(
        raw.len() == expected_size && sha256(&raw) == expected_sha,
        OfflineError::Binding,
    )?;
    Ok(LoadedRef {
        raw: core::mem::take(&mut raw),
        sha256: expected_sha.to_owned(),
    })
}

fn context(raw: &[u8]) -> R<Context> {
    need(raw.len() == 276, OfflineError::Shape)?;
    let value = Context {
        profile: Profile {
            chain_genesis: raw[0..32].try_into().unwrap(),
            pool_lineage: raw[32..64].try_into().unwrap(),
            wallet_profile: raw[64..96].try_into().unwrap(),
            domain: raw[96..128].try_into().unwrap(),
            service_policy: raw[128..160].try_into().unwrap(),
        },
        reserve_outpoint: raw[160..196].try_into().unwrap(),
        old_cm_root: raw[196..228].try_into().unwrap(),
        old_nf_root: raw[228..260].try_into().unwrap(),
        old_cm_count: u32::from_le_bytes(raw[260..264].try_into().unwrap()),
        old_nf_count: u32::from_le_bytes(raw[264..268].try_into().unwrap()),
        old_reserve: u64::from_le_bytes(raw[268..276].try_into().unwrap()),
    };
    need(value.bytes() == raw, OfflineError::Shape)?;
    Ok(value)
}

fn h32(raw: &[u8]) -> H {
    raw.try_into().expect("fixed offset")
}

fn parse_nf_witness(raw: &[u8]) -> R<NullifierWitness> {
    need(raw.len() == 1160, OfflineError::Shape)?;
    let predecessor_path = (0..17)
        .map(|index| h32(&raw[72 + 32 * index..104 + 32 * index]))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let append_path = (0..17)
        .map(|index| h32(&raw[616 + 32 * index..648 + 32 * index]))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let value = NullifierWitness {
        predecessor_index: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        predecessor: h32(&raw[4..36]),
        successor: h32(&raw[36..68]),
        successor_index: u32::from_le_bytes(raw[68..72].try_into().unwrap()),
        predecessor_path,
        append_path,
    };
    need(value.bytes() == raw, OfflineError::Shape)?;
    Ok(value)
}

fn effects(raw: &[u8]) -> R<Effects> {
    need(
        raw.len() == EFFECT_BYTES && &raw[..8] == b"KPBAEF01",
        OfflineError::Shape,
    )?;
    let ctx = context(&raw[8..284])?;
    let inputs = (0..OWNERS)
        .map(|index| {
            let at = 404 + 96 * index;
            (
                h32(&raw[at..at + 32]),
                raw[at + 32..at + 96].try_into().unwrap(),
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let outputs = (0..OUTPUTS)
        .map(|index| {
            raw[692 + 520 * index..1212 + 520 * index]
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let nf_witnesses = (0..OWNERS)
        .map(|index| parse_nf_witness(&raw[3812 + 1160 * index..4972 + 1160 * index]))
        .collect::<R<Vec<_>>>()?
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let cm_paths = (0..OUTPUTS)
        .map(|output| {
            (0..16)
                .map(|level| {
                    let at = 7292 + 512 * output + 32 * level;
                    h32(&raw[at..at + 32])
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("fixed CM path")
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let value = Effects {
        context: ctx,
        new_cm_root: h32(&raw[284..316]),
        new_nf_root: h32(&raw[316..348]),
        new_cm_count: u32::from_le_bytes(raw[348..352].try_into().unwrap()),
        new_nf_count: u32::from_le_bytes(raw[352..356].try_into().unwrap()),
        new_reserve: u64::from_le_bytes(raw[356..364].try_into().unwrap()),
        total_fee: u64::from_le_bytes(raw[364..372].try_into().unwrap()),
        delta: h32(&raw[372..404]),
        inputs,
        outputs,
        nf_witnesses,
        cm_paths,
    };
    need(value.bytes() == raw, OfflineError::Shape)?;
    Ok(value)
}

fn state_bytes(
    profile: &Profile,
    cm_root: H,
    cm_count: u32,
    nf_root: H,
    nf_count: u32,
) -> [u8; 112] {
    let mut raw = Vec::with_capacity(112);
    raw.extend_from_slice(b"KPBAST01");
    raw.extend_from_slice(&profile.domain);
    raw.extend_from_slice(&cm_root);
    raw.extend_from_slice(&cm_count.to_le_bytes());
    raw.extend_from_slice(&nf_root);
    raw.extend_from_slice(&nf_count.to_le_bytes());
    raw.try_into().expect("fixed state")
}

fn state_spk(state: &[u8; 112], tail: &[u8]) -> R<[u8; 37]> {
    need(
        !tail.is_empty() && tail.len() <= 65_421,
        OfflineError::Shape,
    )?;
    let mut digest = Blake2bVar::new(32).map_err(|_| OfflineError::Relation)?;
    digest.update(b"\x4c\x70");
    digest.update(state);
    digest.update(tail);
    let mut out = [0u8; 37];
    out[..4].copy_from_slice(b"\0\0\xaa\x20");
    digest
        .finalize_variable(&mut out[4..36])
        .map_err(|_| OfflineError::Relation)?;
    out[36] = 0x87;
    Ok(out)
}

fn expected_projection_prefix(effect: &Effects, tail: &[u8]) -> R<[u8; 193]> {
    let old_state = state_bytes(
        &effect.context.profile,
        effect.context.old_cm_root,
        effect.context.old_cm_count,
        effect.context.old_nf_root,
        effect.context.old_nf_count,
    );
    let new_state = state_bytes(
        &effect.context.profile,
        effect.new_cm_root,
        effect.new_cm_count,
        effect.new_nf_root,
        effect.new_nf_count,
    );
    let mut raw = Vec::with_capacity(193);
    raw.extend_from_slice(b"KPBAFX01\x01\0\x01\0");
    raw.extend_from_slice(&effect.context.reserve_outpoint);
    raw.extend_from_slice(&u64::MAX.to_le_bytes());
    raw.extend_from_slice(&effect.context.old_reserve.to_le_bytes());
    raw.extend_from_slice(&37u16.to_le_bytes());
    raw.extend_from_slice(&state_spk(&old_state, tail)?);
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&effect.new_reserve.to_le_bytes());
    raw.extend_from_slice(&37u16.to_le_bytes());
    raw.extend_from_slice(&state_spk(&new_state, tail)?);
    raw.push(0);
    raw.extend_from_slice(&[0; 36]);
    raw.extend_from_slice(&(10_492u32).to_le_bytes());
    raw.try_into().map_err(|_| OfflineError::Shape)
}

fn validate_projection(raw: &[u8], effect: &Effects, tail: &[u8]) -> R<[u8; 128]> {
    need(raw.len() == 10_685, OfflineError::Shape)?;
    need(
        raw[..193] == expected_projection_prefix(effect, tail)?,
        OfflineError::Binding,
    )?;
    need(raw[193..10_557] == effect.bytes(), OfflineError::Binding)?;
    raw[10_557..].try_into().map_err(|_| OfflineError::Shape)
}

fn expected_public_inputs(effect: &Effects) -> [Fr; 2] {
    let digest = effect.digest();
    [
        Fr::from_le_bytes_mod_order(&digest[..16]),
        Fr::from_le_bytes_mod_order(&digest[16..]),
    ]
}

fn array<'a>(value: &'a Value, key: &str, length: usize) -> R<&'a Vec<Value>> {
    let values = at(value, key)?.as_array().ok_or(OfflineError::Shape)?;
    need(values.len() == length, OfflineError::Shape)?;
    Ok(values)
}

fn canonical_decimal_byte(value: &Value) -> Option<u8> {
    let text = value.as_str()?;
    let byte = text.parse::<u8>().ok()?;
    (byte.to_string() == text).then_some(byte)
}

fn parse_owner_record(value: &Value, ctx: &Context, owner_component: usize) -> R<OwnerWitness> {
    exact_keys(
        value,
        &[
            "fee_sompi",
            "input",
            "intent_hex1460",
            "nonce_hex32",
            "outputs",
            "owner_component",
            "private_delta_hex32",
            "schema",
            "signature",
            "signature_inputs",
        ],
    )?;
    need(
        text(value, "schema")? == "kpb-private-original-owner-record/v1",
        OfflineError::Shape,
    )?;
    need(
        uint(value, "owner_component")? == owner_component as u64,
        OfflineError::Binding,
    )?;
    let input = at(value, "input")?;
    exact_keys(
        input,
        &[
            "ak_hex64",
            "blind_hex32",
            "cv_hex64",
            "nf_hex32",
            "nk_hex32",
            "note_hex168",
            "path_hex32",
            "position",
        ],
    )?;
    let path = array(input, "path_hex32", 16)?
        .iter()
        .map(|value| {
            let wrapper = json!({"value": value});
            canonical_hex::<32>(&wrapper, "value")
        })
        .collect::<R<Vec<_>>>()?
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let outputs = array(value, "outputs", 2)?
        .iter()
        .map(|item| {
            exact_keys(item, &["blind_hex32", "note_hex168", "tuple_hex520"])?;
            Ok(OutputWitness {
                note: Note::parse(&canonical_hex::<168>(item, "note_hex168")?)
                    .map_err(|_| OfflineError::Shape)?,
                blinding: canonical_hex(item, "blind_hex32")?,
                tuple: canonical_hex(item, "tuple_hex520")?,
            })
        })
        .collect::<R<Vec<_>>>()?
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    let owner = OwnerWitness {
        input_nf: canonical_hex(input, "nf_hex32")?,
        input_cv: canonical_hex(input, "cv_hex64")?,
        note: Note::parse(&canonical_hex::<168>(input, "note_hex168")?)
            .map_err(|_| OfflineError::Shape)?,
        nullifier_secret: canonical_hex(input, "nk_hex32")?,
        position: uint(input, "position")?
            .try_into()
            .map_err(|_| OfflineError::Shape)?,
        path,
        blinding: canonical_hex(input, "blind_hex32")?,
        private_delta: canonical_hex(value, "private_delta_hex32")?,
        authorization_key: canonical_hex(input, "ak_hex64")?,
        fee_sompi: uint(value, "fee_sompi")?,
        intent_nonce: canonical_hex(value, "nonce_hex32")?,
        outputs,
    };
    let tuples = core::array::from_fn(|index| owner.outputs[index].tuple);
    need(
        wire::intent_bytes(
            ctx,
            &owner.input_nf,
            &owner.input_cv,
            owner.fee_sompi,
            &owner.intent_nonce,
            &tuples,
        ) == canonical_hex::<1460>(value, "intent_hex1460")?,
        OfflineError::Binding,
    )?;
    let signature = at(value, "signature")?;
    exact_keys(signature, &["R8", "S", "owner_key_hex64"])?;
    need(
        canonical_hex::<64>(signature, "owner_key_hex64")? == owner.authorization_key,
        OfflineError::Binding,
    )?;
    // The exact normalized witness parser below binds R8/S/matrix/map. Keep
    // the owner record's full source fields exact rather than accepting extras.
    let signature_inputs = at(value, "signature_inputs")?;
    exact_keys(
        signature_inputs,
        &[
            "digestLimbs",
            "ownerKeyBytes",
            "preimageA",
            "preimageR8",
            "sigR8",
            "sigS",
        ],
    )?;
    need(
        at(signature_inputs, "sigR8")? == at(signature, "R8")?
            && at(signature_inputs, "sigS")? == at(signature, "S")?,
        OfflineError::Binding,
    )?;
    let key_bytes = array(signature_inputs, "ownerKeyBytes", 64)?;
    need(
        key_bytes.iter().enumerate().all(|(index, value)| {
            canonical_decimal_byte(value) == Some(owner.authorization_key[index])
        }),
        OfflineError::Binding,
    )?;
    Ok(owner)
}

fn parse_signature(
    matrix_ref: &Value,
    witness_ref: &Value,
    base: &Path,
) -> R<(SignatureWitnessSource, String)> {
    let matrix = load_ref(matrix_ref, None, base)?;
    let witness = load_ref(witness_ref, None, base)?;
    unique_json(&matrix.raw)?;
    let _witness_document = SensitiveJson(unique_json(&witness.raw)?);
    need(
        matrix.sha256 == SIGNATURE_MATRIX_RAW_SHA256,
        OfflineError::Binding,
    )?;
    let relation = auth::interchange::signature_matrix(
        &matrix.raw,
        SIGNATURE_MATRIX_RAW_SHA256,
        SIGNATURE_MAP,
    )
    .map_err(|_| OfflineError::Relation)?;
    let variables = relation.variables().map_err(|_| OfflineError::Relation)?;
    let assignment = auth::interchange::signature_witness(
        &witness.raw,
        &witness.sha256,
        SIGNATURE_MATRIX_RAW_SHA256,
        SIGNATURE_MAP,
        variables,
    )
    .map_err(|_| OfflineError::Relation)?;
    Ok((
        SignatureWitnessSource::new(relation, assignment),
        witness.sha256.clone(),
    ))
}

fn permutation<const N: usize, T: PartialEq>(private: &[T; N], public: &[T; N]) -> R<[[Fr; N]; N]> {
    let mut seen = [false; N];
    let mut result = core::array::from_fn(|_| [Fr::ZERO; N]);
    for source in 0..N {
        let destinations = (0..N)
            .filter(|destination| private[source] == public[*destination])
            .collect::<Vec<_>>();
        need(destinations.len() == 1, OfflineError::Binding)?;
        let destination = destinations[0];
        need(!seen[destination], OfflineError::Binding)?;
        seen[destination] = true;
        result[source][destination] = Fr::ONE;
    }
    need(seen.into_iter().all(|value| value), OfflineError::Binding)?;
    Ok(result)
}

fn limbs(value: &[u8; 32]) -> [u64; 5] {
    let mut out = [0u64; 5];
    for (index, slot) in out[..4].iter_mut().enumerate() {
        *slot = u64::from_le_bytes(value[8 * index..8 * (index + 1)].try_into().unwrap());
    }
    out
}

fn add_limbs(left: [u64; 5], right: [u64; 5]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;
    for index in 0..5 {
        let sum = left[index] as u128 + right[index] as u128 + carry;
        out[index] = sum as u64;
        carry = sum >> 64;
    }
    out
}

fn scale_limbs(value: [u64; 5], scalar: u8) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry = 0u128;
    for index in 0..5 {
        let product = value[index] as u128 * scalar as u128 + carry;
        out[index] = product as u64;
        carry = product >> 64;
    }
    out
}

fn delta_quotient(owners: &[OwnerWitness; OWNERS], effect: &Effects) -> R<u8> {
    const Q_BYTES: [u8; 32] = [
        0xf1, 0x26, 0x21, 0x39, 0xdc, 0x97, 0x72, 0x67, 0x0a, 0xee, 0x20, 0x39, 0xb8, 0xed, 0x3e,
        0xab, 0x0b, 0x2b, 0x30, 0xd0, 0xb6, 0x08, 0x0a, 0x37, 0x05, 0x34, 0x26, 0x5c, 0xce, 0x89,
        0x0c, 0x06,
    ];
    let q = limbs(&Q_BYTES);
    let mut sum = [0u64; 5];
    for owner in owners {
        let value = limbs(&owner.private_delta);
        need(
            (0..5)
                .rev()
                .find_map(|index| (value[index] != q[index]).then_some(value[index] < q[index]))
                == Some(true),
            OfflineError::Shape,
        )?;
        sum = add_limbs(sum, value);
    }
    let remainder = limbs(&effect.delta);
    for quotient in 0..=2 {
        if add_limbs(scale_limbs(q, quotient), remainder) == sum {
            return Ok(quotient);
        }
    }
    Err(OfflineError::Binding)
}

fn usize_array<const N: usize>(value: &Value, key: &str) -> R<[usize; N]> {
    array(value, key, N)?
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or(OfflineError::Shape)?
                .try_into()
                .map_err(|_| OfflineError::Shape)
        })
        .collect::<R<Vec<_>>>()?
        .try_into()
        .map_err(|_| OfflineError::Shape)
}

fn w0_graph(value: &Value, round: usize, base: &Path) -> R<(W0PhysicalGraph, String)> {
    let loaded = load_ref(value, None, base)?;
    let document = SensitiveJson(unique_json(&loaded.raw)?);
    exact_keys(
        &document.0,
        &[
            "caller_digest_is_common_origin_authority",
            "fixed_rewire_identity_sha256",
            "round",
            "schema",
            "w0_graph",
            "w1_graph",
        ],
    )?;
    need(
        text(&document.0, "schema")? == "kpb-offline-w1-selected-w0/v1"
            && uint(&document.0, "round")? == round as u64
            && at(&document.0, "caller_digest_is_common_origin_authority")? == &Value::Bool(false),
        OfflineError::Binding,
    )?;
    canonical_sha(text(&document.0, "fixed_rewire_identity_sha256")?)?;
    let graph = at(&document.0, "w0_graph")?;
    exact_keys(graph, &["change", "input", "payment"])?;
    // The public W1 graph is not trusted: check_graph derives and compares it
    // to the circuit permutation. Exact fields are retained for substitution
    // controls and the source digest.
    let target = at(&document.0, "w1_graph")?;
    exact_keys(target, &["change", "input", "payment"])?;
    let w0 = W0PhysicalGraph::new(
        usize_array(graph, "input")?,
        usize_array(graph, "payment")?,
        usize_array(graph, "change")?,
    );
    let (_, derived) = super::graph(&w0).map_err(|_| OfflineError::Binding)?;
    need(
        usize_array::<OWNERS>(target, "input")? == derived.input
            && usize_array::<OWNERS>(target, "payment")? == derived.payment
            && usize_array::<OWNERS>(target, "change")? == derived.change,
        OfflineError::Binding,
    )?;
    Ok((w0, loaded.sha256.clone()))
}

struct LoadedRound {
    source: FullW1RoundSource,
    w0: W0PhysicalGraph,
    context_sha256: String,
    effects_sha256: String,
    projection_sha256: String,
    proof_sha256: String,
    w0_sha256: String,
    signature_witness_sha256: [String; OWNERS],
}

fn load_round(
    value: &Value,
    expected_round: usize,
    aggregate_vk: [u8; 328],
    tail: &[u8],
    base: &Path,
) -> R<LoadedRound> {
    exact_keys(
        value,
        &[
            "context",
            "effects_core",
            "owners",
            "projection",
            "round",
            "w0_selection",
        ],
    )?;
    need(
        uint(value, "round")? == expected_round as u64,
        OfflineError::Binding,
    )?;
    let context_leaf = load_ref(at(value, "context")?, Some(276), base)?;
    let effects_leaf = load_ref(at(value, "effects_core")?, Some(EFFECT_BYTES), base)?;
    let projection_leaf = load_ref(at(value, "projection")?, Some(10_685), base)?;
    let ctx = context(&context_leaf.raw)?;
    let effect = effects(&effects_leaf.raw)?;
    need(effect.context == ctx, OfflineError::Binding)?;
    effect
        .validate_public_fields(&ctx, &ctx.profile)
        .map_err(|_| OfflineError::Relation)?;
    let proof = validate_projection(&projection_leaf.raw, &effect, tail)?;
    let owner_values = array(value, "owners", OWNERS)?;
    let mut owners = Vec::with_capacity(OWNERS);
    let mut signatures = Vec::with_capacity(OWNERS);
    let mut signature_witness_sha256 = Vec::with_capacity(OWNERS);
    for (owner_component, owner) in owner_values.iter().enumerate() {
        exact_keys(owner, &["record", "signature_matrix", "signature_witness"])?;
        let record = load_ref(at(owner, "record")?, None, base)?;
        let record_value = SensitiveJson(unique_json(&record.raw)?);
        owners.push(parse_owner_record(&record_value.0, &ctx, owner_component)?);
        let (signature, witness_sha) = parse_signature(
            at(owner, "signature_matrix")?,
            at(owner, "signature_witness")?,
            base,
        )?;
        signatures.push(signature);
        signature_witness_sha256.push(witness_sha);
    }
    let owners: [OwnerWitness; OWNERS] = owners.try_into().map_err(|_| OfflineError::Shape)?;
    let private_inputs =
        core::array::from_fn(|owner| (owners[owner].input_nf, owners[owner].input_cv));
    let private_outputs =
        core::array::from_fn(|source| owners[source / 2].outputs[source % 2].tuple);
    let input_permutation = permutation(&private_inputs, &effect.inputs)?;
    let output_permutation = permutation(&private_outputs, &effect.outputs)?;
    let quotient = delta_quotient(&owners, &effect)?;
    let circuit = BatchCircuit {
        profile: ctx.profile.clone(),
        effects: effect,
        witness: BatchWitness {
            owners,
            input_permutation,
            output_permutation,
            delta_quotient: quotient,
        },
    };
    let signatures: [SignatureWitnessSource; OWNERS] =
        signatures.try_into().map_err(|_| OfflineError::Shape)?;
    let (w0, w0_sha256) = w0_graph(at(value, "w0_selection")?, expected_round, base)?;
    Ok(LoadedRound {
        source: FullW1RoundSource::new(
            circuit,
            signatures,
            SelectedAggregateProof::new(aggregate_vk, proof),
        ),
        w0,
        context_sha256: context_leaf.sha256.clone(),
        effects_sha256: effects_leaf.sha256.clone(),
        projection_sha256: projection_leaf.sha256.clone(),
        proof_sha256: sha256(&proof),
        w0_sha256,
        signature_witness_sha256: signature_witness_sha256
            .try_into()
            .map_err(|_| OfflineError::Shape)?,
    })
}

struct BuildBinding {
    binary_sha256: String,
    dep_info_sha256: String,
    source_closure_sha256: String,
    rustc_vv_sha256: String,
    cargo_version: String,
    build_command_sha256: String,
}

fn validate_build_binding(value: &Value, base: &Path) -> R<BuildBinding> {
    exact_keys(
        value,
        &[
            "binary_sha256",
            "build_command_sha256",
            "cargo_version",
            "dep_info",
            "feature",
            "rustc_vv_sha256",
            "source_closure_sha256",
        ],
    )?;
    need(
        text(value, "feature")? == "offline-w1-verifier",
        OfflineError::Binding,
    )?;
    let binary_expected = canonical_sha(text(value, "binary_sha256")?)?;
    // This pinned verifier build is Linux-only. Reading /proc/self/exe binds
    // the hash to the executing inode even if its launch pathname is replaced.
    #[cfg(not(target_os = "linux"))]
    return Err(OfflineError::Input);
    #[cfg(target_os = "linux")]
    let binary_raw = fs::read("/proc/self/exe").map_err(|_| OfflineError::Input)?;
    need(
        sha256(&binary_raw) == binary_expected,
        OfflineError::Binding,
    )?;
    let dep_info = load_ref(at(value, "dep_info")?, None, base)?;
    let dep_text = std::str::from_utf8(&dep_info.raw).map_err(|_| OfflineError::Input)?;
    for required in [
        "counterfactual_w1.rs",
        "counterfactual_w1/offline_verifier.rs",
        "examples/verify_offline_w1_aggregate.rs",
        "src/circuit.rs",
        "src/wire.rs",
    ] {
        need(dep_text.contains(required), OfflineError::Binding)?;
    }
    let source_closure = canonical_sha(text(value, "source_closure_sha256")?)?.to_owned();
    let rustc = canonical_sha(text(value, "rustc_vv_sha256")?)?.to_owned();
    let build_command = canonical_sha(text(value, "build_command_sha256")?)?.to_owned();
    let compiled_rustc = option_env!("KPB_RUSTC_VV_SHA256").unwrap_or("UNSET");
    let compiled_source = option_env!("KPB_SOURCE_CLOSURE_SHA256").unwrap_or("UNSET");
    let compiled_command = option_env!("KPB_BUILD_COMMAND_SHA256").unwrap_or("UNSET");
    let cargo = text(value, "cargo_version")?.to_owned();
    let compiled_cargo = option_env!("KPB_CARGO_VERSION").unwrap_or("UNSET");
    need(
        rustc == compiled_rustc
            && cargo == compiled_cargo
            && source_closure == compiled_source
            && build_command == compiled_command,
        OfflineError::Binding,
    )?;
    Ok(BuildBinding {
        binary_sha256: binary_expected.to_owned(),
        dep_info_sha256: dep_info.sha256.clone(),
        source_closure_sha256: source_closure,
        rustc_vv_sha256: rustc,
        cargo_version: cargo,
        build_command_sha256: build_command,
    })
}

fn uuid4(value: &str) -> R<&str> {
    need(
        value.len() == 36
            && value.as_bytes()[8] == b'-'
            && value.as_bytes()[13] == b'-'
            && value.as_bytes()[18] == b'-'
            && value.as_bytes()[23] == b'-'
            && value.as_bytes()[14] == b'4'
            && matches!(value.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
            && value.bytes().enumerate().all(|(index, byte)| {
                [8, 13, 18, 23].contains(&index)
                    || byte.is_ascii_digit()
                    || (b'a'..=b'f').contains(&byte)
            }),
        OfflineError::Shape,
    )?;
    Ok(value)
}

struct AggregateEvidence {
    public_inputs_decimal: [String; 2],
    matrix_sha256: String,
    rows: usize,
    variables: usize,
}

fn verify_aggregate(source: &FullW1RoundSource) -> R<AggregateEvidence> {
    need(
        sha256(&source.aggregate.verification_key) == AGGREGATE_VK,
        OfflineError::Binding,
    )?;
    need(source.aggregate.proof != [0; 128], OfflineError::Proof)?;
    check_signatures(&source.signatures).map_err(|_| OfflineError::Relation)?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    source
        .circuit
        .clone()
        .generate_internalized(cs.clone())
        .map_err(|_| OfflineError::Relation)?;
    let core_variables = cs.num_variables();
    append_signature_witnesses(cs.clone(), core_variables, &source.signatures)
        .map_err(|_| OfflineError::Relation)?;
    need(
        cs.is_satisfied().map_err(|_| OfflineError::Relation)?,
        OfflineError::Relation,
    )?;
    let instances = cs
        .instance_assignment()
        .map_err(|_| OfflineError::Relation)?;
    need(
        instances.len() == 3 && instances[0] == Fr::ONE,
        OfflineError::Relation,
    )?;
    let expected = expected_public_inputs(&source.circuit.effects);
    need(
        instances[1] == expected[0] && instances[2] == expected[1],
        OfflineError::Binding,
    )?;
    let matrix = collect(&cs).map_err(|_| OfflineError::Relation)?;
    let variables = matrix.variables().map_err(|_| OfflineError::Relation)?;
    let matrix_sha = auth::join::fingerprint(&matrix).map_err(|_| OfflineError::Relation)?;
    need(
        matrix.instances == 3
            && variables == AGGREGATE_VARIABLES
            && matrix.constraints() == AGGREGATE_CONSTRAINTS
            && matrix_sha == AGGREGATE_MATRIX,
        OfflineError::Relation,
    )?;
    need(
        verify_groth16(
            &source.aggregate.verification_key,
            &source.aggregate.proof,
            &expected,
        ) == Ok(true),
        OfflineError::Proof,
    )?;
    Ok(AggregateEvidence {
        public_inputs_decimal: [expected[0].to_string(), expected[1].to_string()],
        matrix_sha256: matrix_sha,
        rows: matrix.constraints(),
        variables,
    })
}

fn request(value: &Value, request_sha256: &str, base: &Path) -> R<Value> {
    exact_keys(
        value,
        &[
            "aggregate_verification_key",
            "authorization",
            "build",
            "classification",
            "old_setup_privacy_assumption_eligible",
            "output_verification_key_hex328",
            "rounds",
            "run_id",
            "schema",
            "selected_round",
            "source_instance_epoch_id",
            "tail",
        ],
    )?;
    need(
        text(value, "schema")? == REQUEST_SCHEMA
            && text(value, "classification")? == CLASSIFICATION
            && at(value, "authorization")? == &Value::Bool(false)
            && at(value, "old_setup_privacy_assumption_eligible")? == &Value::Bool(false),
        OfflineError::Binding,
    )?;
    let selected_round: usize = uint(value, "selected_round")?
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    need((1..=2).contains(&selected_round), OfflineError::Shape)?;
    let run_id = uuid4(text(value, "run_id")?)?.to_owned();
    let epoch_id = uuid4(text(value, "source_instance_epoch_id")?)?.to_owned();
    need(run_id != epoch_id, OfflineError::Binding)?;
    let build = validate_build_binding(at(value, "build")?, base)?;
    let aggregate_vk_leaf = load_ref(at(value, "aggregate_verification_key")?, Some(328), base)?;
    need(
        aggregate_vk_leaf.sha256 == AGGREGATE_VK,
        OfflineError::Binding,
    )?;
    let aggregate_vk: [u8; 328] = aggregate_vk_leaf
        .raw
        .as_slice()
        .try_into()
        .map_err(|_| OfflineError::Shape)?;
    native::checked_vk(&aggregate_vk).map_err(|_| OfflineError::Proof)?;
    let output_vk = canonical_hex::<328>(value, "output_verification_key_hex328")?;
    need(sha256(&output_vk) == OUTPUT_VK, OfflineError::Binding)?;
    native::checked_vk(&output_vk).map_err(|_| OfflineError::Proof)?;
    let tail = load_ref(at(value, "tail")?, None, base)?;
    need(!tail.raw.is_empty(), OfflineError::Shape)?;
    let rounds = array(value, "rounds", 2)?;
    let first = load_round(&rounds[0], 1, aggregate_vk, &tail.raw, base)?;
    let second = load_round(&rounds[1], 2, aggregate_vk, &tail.raw, base)?;
    check_cross_round(&first.source, &second.source).map_err(|_| OfflineError::Binding)?;
    check_graph(&first.source.circuit, &first.w0).map_err(|_| OfflineError::Binding)?;
    check_graph(&second.source.circuit, &second.w0).map_err(|_| OfflineError::Binding)?;
    check_public_close(&first.source, &first.source.circuit.effects)
        .map_err(|_| OfflineError::Relation)?;
    check_public_close(&second.source, &second.source.circuit.effects)
        .map_err(|_| OfflineError::Relation)?;
    let selected = if selected_round == 1 { &first } else { &second };
    native::checked_proof(&selected.source.aggregate.proof).map_err(|_| OfflineError::Proof)?;
    check_outputs(&selected.source, &output_vk).map_err(|_| OfflineError::Proof)?;
    let evidence = verify_aggregate(&selected.source)?;
    let receipt_rounds = [&first, &second]
        .into_iter()
        .enumerate()
        .map(|(index, round)| {
            json!({
                "round": index + 1,
                "context_sha256": round.context_sha256,
                "effects_sha256": round.effects_sha256,
                "projection_sha256": round.projection_sha256,
                "aggregate_proof_sha256": round.proof_sha256,
                "w0_selection_sha256": round.w0_sha256,
                "signature_witness_sha256": round.signature_witness_sha256,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": RECEIPT_SCHEMA,
        "classification": CLASSIFICATION,
        "run_id": run_id,
        "source_instance_epoch_id": epoch_id,
        "selected_round": selected_round,
        "request_sha256": request_sha256,
        "rounds": receipt_rounds,
        "aggregate_verification_key_sha256": aggregate_vk_leaf.sha256,
        "output_verification_key_sha256": OUTPUT_VK,
        "selected_round_output_proofs_verified": 6,
        "signature_relations_satisfied": 3,
        "instances": 3,
        "rows": evidence.rows,
        "variables": evidence.variables,
        "matrix_sha256": evidence.matrix_sha256,
        "effects_digest_public_inputs_decimal": evidence.public_inputs_decimal,
        "aggregate_cryptographic_verification": "ACCEPTED",
        "cross_round_note_state_continuity_rederived": true,
        "build": {
            "feature": "offline-w1-verifier",
            "binary_sha256": build.binary_sha256,
            "dep_info_sha256": build.dep_info_sha256,
            "source_closure_sha256": build.source_closure_sha256,
            "rustc_vv_sha256": build.rustc_vv_sha256,
            "cargo_version": build.cargo_version,
            "build_command_sha256": build.build_command_sha256,
        },
        "authorization": false,
        "receipt_is_authority": false,
        "fixture_possession_authorizes_v4": false,
        "offline_synthetic_provenance_enforced": false,
        "build_bundle_reverified": false,
        "old_setup_privacy_assumption_eligible": false,
        "production_source_authority_or_closure_minted": false,
    }))
}

/// Strictly verify one selected round and create one evidence-only receipt.
///
/// This path API exists only in the non-default offline module. It is not an
/// overload of `PinnedFullW1VerifierBridge` and cannot return its authority.
pub fn verify_request_file(
    request_path: &Path,
    receipt_path: &Path,
) -> Result<(), OfflineVerificationRefused> {
    (|| -> R<()> {
        need(!receipt_path.exists(), OfflineError::Output)?;
        let request_raw = fs::read(request_path).map_err(|_| OfflineError::Input)?;
        let request_sha = sha256(&request_raw);
        let value = unique_json(&request_raw)?;
        need(canonical(&value)? == request_raw, OfflineError::Input)?;
        let base = request_path.parent().ok_or(OfflineError::Input)?;
        let mut receipt = request(&value, &request_sha, base)?;
        let identity = sha256(&canonical(&receipt)?);
        receipt
            .as_object_mut()
            .ok_or(OfflineError::Output)?
            .insert("receipt_identity_sha256".into(), identity.into());
        let raw = canonical(&receipt)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o400);
        let mut output = options
            .open(receipt_path)
            .map_err(|_| OfflineError::Output)?;
        output.write_all(&raw).map_err(|_| OfflineError::Output)?;
        output.sync_all().map_err(|_| OfflineError::Output)?;
        if let Some(parent) = receipt_path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| OfflineError::Output)?;
        }
        Ok(())
    })()
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_context() -> Context {
        Context {
            profile: Profile {
                chain_genesis: [1; 32],
                pool_lineage: [2; 32],
                wallet_profile: [3; 32],
                domain: [4; 32],
                service_policy: [5; 32],
            },
            reserve_outpoint: [6; 36],
            old_cm_root: [7; 32],
            old_nf_root: [8; 32],
            old_cm_count: 3,
            old_nf_count: 1,
            old_reserve: 6_000_000_000,
        }
    }

    fn model_effects() -> Effects {
        let context = model_context();
        Effects {
            context,
            new_cm_root: [9; 32],
            new_nf_root: [10; 32],
            new_cm_count: 9,
            new_nf_count: 4,
            new_reserve: 5_979_000_000,
            total_fee: 21_000_000,
            delta: [0; 32],
            inputs: core::array::from_fn(|index| ([20 + index as u8; 32], [30 + index as u8; 64])),
            outputs: core::array::from_fn(|index| [40 + index as u8; 520]),
            nf_witnesses: core::array::from_fn(|_| NullifierWitness {
                predecessor_index: 0,
                predecessor: [0; 32],
                successor: [0; 32],
                successor_index: 0,
                predecessor_path: [[0; 32]; 17],
                append_path: [[0; 32]; 17],
            }),
            cm_paths: [[[0; 32]; 16]; OUTPUTS],
        }
    }

    #[test]
    fn canonical_decimal_owner_key_bytes_reject_coercion_and_overflow() {
        assert_eq!(canonical_decimal_byte(&Value::String("0".into())), Some(0));
        assert_eq!(
            canonical_decimal_byte(&Value::String("255".into())),
            Some(255)
        );
        for rejected in ["00", "01", "+1", "-1", " 1", "1 ", "256", "1.0", ""] {
            assert_eq!(
                canonical_decimal_byte(&Value::String(rejected.into())),
                None
            );
        }
        assert_eq!(canonical_decimal_byte(&Value::from(0)), None);
        assert_ne!(
            canonical_decimal_byte(&Value::String("254".into())),
            Some(255)
        );
    }

    #[test]
    fn effects_digest_instances_are_derived_not_caller_supplied() {
        let effect = model_effects();
        let expected = expected_public_inputs(&effect);
        let mut changed = effect;
        changed.total_fee += 1;
        assert_ne!(expected_public_inputs(&changed), expected);
    }

    #[test]
    fn effects_and_projection_substitutions_are_rejected() {
        let effect = model_effects();
        let tail = b"OFFLINE TEST TAIL";
        let Ok(prefix) = expected_projection_prefix(&effect, tail) else {
            panic!("fixed projection prefix")
        };
        let mut projection = Vec::from(prefix);
        projection.extend_from_slice(&effect.bytes());
        projection.extend_from_slice(&[11; 128]);
        assert!(validate_projection(&projection, &effect, tail).is_ok());
        projection[193] ^= 1;
        assert!(validate_projection(&projection, &effect, tail).is_err());
        projection[193] ^= 1;
        projection[80] ^= 1;
        assert!(validate_projection(&projection, &effect, tail).is_err());
    }

    #[test]
    fn malformed_vk_and_proof_are_not_verification() {
        assert!(native::checked_vk(&[0; 328]).is_err());
        assert!(native::checked_proof(&[0; 128]).is_err());
        assert_ne!(
            verify_groth16(&[0; 328], &[0; 128], &[Fr::ZERO, Fr::ZERO]),
            Ok(true)
        );
    }

    #[test]
    fn signature_substitution_fails_before_aggregate_synthesis() {
        let bad = SignatureWitnessSource::new(
            auth::join::R1cs {
                instances: 67,
                witnesses: 0,
                matrices: [vec![], vec![], vec![]],
            },
            vec![Fr::ONE; 67],
        );
        assert!(
            check_signatures(&[
                bad,
                SignatureWitnessSource::new(
                    auth::join::R1cs {
                        instances: 67,
                        witnesses: 0,
                        matrices: [vec![], vec![], vec![]]
                    },
                    vec![Fr::ONE; 67]
                ),
                SignatureWitnessSource::new(
                    auth::join::R1cs {
                        instances: 67,
                        witnesses: 0,
                        matrices: [vec![], vec![], vec![]]
                    },
                    vec![Fr::ONE; 67]
                )
            ])
            .is_err()
        );
    }

    #[test]
    fn duplicate_round_context_is_not_cross_round_continuity() {
        fn signature() -> SignatureWitnessSource {
            SignatureWitnessSource::new(
                auth::join::R1cs {
                    instances: 67,
                    witnesses: 0,
                    matrices: [vec![], vec![], vec![]],
                },
                vec![Fr::ONE; 67],
            )
        }
        let circuit = crate::owner_local::public_source_template(model_context()).unwrap();
        let first = FullW1RoundSource::new(
            circuit.clone(),
            [signature(), signature(), signature()],
            SelectedAggregateProof::new([0; 328], [0; 128]),
        );
        let second = FullW1RoundSource::new(
            circuit,
            [signature(), signature(), signature()],
            SelectedAggregateProof::new([0; 328], [0; 128]),
        );
        assert!(check_cross_round(&first, &second).is_err());
    }
}
