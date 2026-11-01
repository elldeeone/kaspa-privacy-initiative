//! Fixed nondefault bridge from the source-owned round-1 assignment to the
//! reviewed streamed Groth16 core and one private proof receipt.
//!
//! Proof-generation callers can select only the create-new receipt path in an
//! existing private directory. They cannot supply assignment slices, artifact
//! paths, identities, a round, public inputs, or randomness. A separate
//! verification-only call accepts bounded exact-canonical receipt bytes and
//! opens only an owned snapshot of the fixed VK. The parameter opener accepts
//! only the fixed, already decoded PK descriptor after relation checking; it
//! never creates or replaces an artifact.

#![allow(dead_code)]

use super::super::{OfflineError, R, at, exact_keys, need, text, uint};
use super::PreparedAssignment;
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{One, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

// Compile the reviewed source as a private path module. Its public synthetic
// surface remains nested below this private module and is not a crate API.
#[path = "../../../../private_batch_trial/low_memory_w1_prover/src/lib.rs"]
mod reviewed_low_memory;

use reviewed_low_memory::algebraic_controls::{
    ExpectedIdentity, ProvingGeometry, R1csGeometry, StreamedProof, StreamedWitnessMap,
    create_proof_from_compressed_pk, stream_r1cs_witness_map,
};

const R1CS_PATH: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/r1cs-aggregate-export-c023-20261029-02/aggregate.r1cs";
const R1CS_BYTES: u64 = 2_840_345_392;
const R1CS_SHA256_HEX: &str = "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc";
const R1CS_SHA256: [u8; 32] = hex32(R1CS_SHA256_HEX);
const DECODED_PK_BYTES: u64 = 2_608_842_576;
const DECODED_PK_SHA256_HEX: &str =
    "170431eee45f57ff6a3dc278d96f8a824145b8ca9ded04088a662983a449e945";
const DECODED_PK_SHA256: [u8; 32] = hex32(DECODED_PK_SHA256_HEX);
const VK_BYTES: usize = 328;
const VK_SHA256_HEX: &str = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102";
const VK_SHA256: [u8; 32] = hex32(VK_SHA256_HEX);
const DECODED_PK_PATH: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-w1-decoded-pk-20261029-01/AGGREGATE-PK.bin";
const DECODE_RECEIPT_PATH: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-w1-decoded-pk-20261029-01/DECODE-RECEIPT.json";
const DECODE_RECEIPT_BYTES: u64 = 1_810;
const DECODE_RECEIPT_SHA256_HEX: &str =
    "023171d9ff4328e9fd0653f0a9c7455f11c9da4600e0835231b439b79ba6c40c";
const DECODE_RECEIPT_SHA256: [u8; 32] = hex32(DECODE_RECEIPT_SHA256_HEX);
const COMPRESSED_PK_PATH: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-stock-setup-20261028-02/artifact/AGGREGATE-PK.bin.gz";
const COMPRESSED_PK_BYTES: u64 = 1_749_414_110;
const COMPRESSED_PK_SHA256_HEX: &str =
    "4a3d0ac3143ecc32a875af8107c923b851036363a68a8a744b97c74d0a3879ff";
const COMPRESSED_PK_SHA256: [u8; 32] = hex32(COMPRESSED_PK_SHA256_HEX);
const VK_PATH: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-stock-setup-20261028-02/artifact/AGGREGATE-VK.bin";
const O_NOFOLLOW: i32 = 0o400_000;
const WIRES: usize = 12_949_821;
const INSTANCES: usize = 3;
const WITNESSES: usize = WIRES - INSTANCES;
const CONSTRAINTS: usize = 13_093_029;
const CONSTRAINT_SECTION_BYTES: u64 = 2_736_746_712;
const DOMAIN_SIZE: usize = 16_777_216;
const PROOF_BYTES: usize = 128;
const PROOF_SCHEMA: &str = "kpb-frozen-w1-round1-proof/v1";
pub const FROZEN_W1_PROOF_RECEIPT_MAX_BYTES: usize = 4_096;
const CLASSIFICATION: &str = "OFFLINE_SYNTHETIC_UNBACKED_FIXED_W1_GROTH16_PROOF_EVIDENCE_ONLY";
const PUBLIC_INPUTS_DECIMAL: [&str; 2] = [
    "13917591994071772114488105153423377273",
    "33826997814916552742078018202966096202",
];
static PROOF_AVAILABLE: AtomicBool = AtomicBool::new(true);

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("non-lowercase-hex"),
    }
}

const fn hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64);
    let mut output = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateProverBoundaryStatus {
    reviewed_core_compiled_privately: bool,
    relation_owned_assignment_bridge: bool,
    fixed_round_and_geometry: bool,
    internal_osrng: bool,
    decoded_pk_descriptor_opener: bool,
    independent_vk_descriptor_opener: bool,
    full_secret_zeroization: bool,
    fixed_nondefault_receipt_entry: bool,
    private_create_new_receipt_sink: bool,
    outer_build_and_launch_selected: bool,
    production_authority: bool,
}

const STATUS: PrivateProverBoundaryStatus = PrivateProverBoundaryStatus {
    reviewed_core_compiled_privately: true,
    relation_owned_assignment_bridge: true,
    fixed_round_and_geometry: true,
    internal_osrng: true,
    decoded_pk_descriptor_opener: true,
    independent_vk_descriptor_opener: true,
    full_secret_zeroization: false,
    fixed_nondefault_receipt_entry: true,
    private_create_new_receipt_sink: true,
    outer_build_and_launch_selected: false,
    production_authority: false,
};

/// Private type proof that the exact R1CS accepted the source-owned assignment.
struct SatisfiedRound1 {
    assignment: Zeroizing<Vec<Fr>>,
    witness_map: StreamedWitnessMap,
}

/// Private descriptor authority. Its only constructor requires the
/// relation-satisfaction type above.
struct FixedProofParameterArtifacts {
    decoded_pk: File,
    independent_vk: [u8; VK_BYTES],
}

/// Only this verified public result may reach the private receipt constructor.
struct VerifiedRound1Proof {
    proof: Proof<Bn254>,
    public_inputs: [Fr; 2],
}

/// One deliberately opaque public failure shape for the fixed proof entry.
pub struct FrozenRound1ProofRefused {
    _private: (),
}

/// One deliberately opaque public failure shape for verification-only use.
pub struct FrozenRound1ProofVerificationRefused {
    _private: (),
}

/// Public-safe commitment to the exact canonical receipt bytes successfully
/// written and fsynced by the fixed entry. It contains no assignment material.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrozenRound1ProofReceiptCommitment {
    sha256: [u8; 32],
}

impl fmt::Display for FrozenRound1ProofReceiptCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.sha256))
    }
}

fn receipt_commitment(raw: &[u8]) -> FrozenRound1ProofReceiptCommitment {
    FrozenRound1ProofReceiptCommitment {
        sha256: Sha256::digest(raw).into(),
    }
}

fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn open_fixed(path: &'static str, bytes: u64, mode: u32) -> R<File> {
    let path = Path::new(path);
    let before = path.symlink_metadata().map_err(|_| OfflineError::Input)?;
    let owner = fs::metadata("/proc/self")
        .map_err(|_| OfflineError::Input)?
        .uid();
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner
        || before.nlink() != 1
        || before.len() != bytes
        || before.mode() & 0o7777 != mode
    {
        return Err(OfflineError::Input);
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_NOFOLLOW);
    let file = options.open(path).map_err(|_| OfflineError::Input)?;
    let opened = file.metadata().map_err(|_| OfflineError::Input)?;
    let after = path.symlink_metadata().map_err(|_| OfflineError::Input)?;
    if !same_file_state(&before, &opened) || !same_file_state(&opened, &after) {
        return Err(OfflineError::Input);
    }
    Ok(file)
}

fn authenticate(mut file: File, path: &'static str, expected: [u8; 32]) -> R<File> {
    let before = file.metadata().map_err(|_| OfflineError::Input)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineError::Input)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| OfflineError::Input)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        total = total.checked_add(count as u64).ok_or(OfflineError::Input)?;
    }
    buffer.fill(0);
    let after = file.metadata().map_err(|_| OfflineError::Input)?;
    let after_path = Path::new(path)
        .symlink_metadata()
        .map_err(|_| OfflineError::Input)?;
    let actual: [u8; 32] = digest.finalize().into();
    if total != before.len()
        || actual != expected
        || !same_file_state(&before, &after)
        || !same_file_state(&after, &after_path)
    {
        return Err(OfflineError::Input);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineError::Input)?;
    Ok(file)
}

fn read_authenticated_exact<const N: usize>(
    mut file: File,
    path: &Path,
    expected: [u8; 32],
) -> R<[u8; N]> {
    let before = file.metadata().map_err(|_| OfflineError::Input)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineError::Input)?;
    let mut bytes = [0_u8; N];
    file.read_exact(&mut bytes)
        .map_err(|_| OfflineError::Input)?;
    let mut tail = [0_u8; 1];
    let eof = file.read(&mut tail).map_err(|_| OfflineError::Input)? == 0;
    let after = file.metadata().map_err(|_| OfflineError::Input)?;
    let after_path = path.symlink_metadata().map_err(|_| OfflineError::Input)?;
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if before.len() != N as u64
        || !eof
        || actual != expected
        || !same_file_state(&before, &after)
        || !same_file_state(&after, &after_path)
    {
        return Err(OfflineError::Input);
    }
    Ok(bytes)
}

fn fixed_r1cs_geometry() -> R1csGeometry {
    R1csGeometry {
        wires: WIRES,
        public_outputs: 0,
        public_inputs: 2,
        private_inputs: WITNESSES,
        labels: WIRES as u64,
        constraints: CONSTRAINTS,
        constraint_section_bytes: CONSTRAINT_SECTION_BYTES,
        identity: ExpectedIdentity {
            bytes: R1CS_BYTES,
            sha256: R1CS_SHA256,
        },
    }
}

fn fixed_proving_geometry() -> ProvingGeometry {
    ProvingGeometry {
        instance_variables: INSTANCES,
        witness_variables: WITNESSES,
        domain_size: DOMAIN_SIZE,
        identity: ExpectedIdentity {
            bytes: DECODED_PK_BYTES,
            sha256: DECODED_PK_SHA256,
        },
        vk_identity: ExpectedIdentity {
            bytes: VK_BYTES as u64,
            sha256: VK_SHA256,
        },
    }
}

fn satisfy_exact_r1cs(prepared: PreparedAssignment) -> R<SatisfiedRound1> {
    if prepared.instances.len() != INSTANCES
        || prepared.witnesses.len() != WITNESSES
        || prepared.instances.first() != Some(&Fr::one())
    {
        return Err(OfflineError::Relation);
    }
    // Copy into one owned proving buffer, then let PreparedAssignment erase
    // both complete source vectors. Vec::append/mem::take would leave the
    // moved-from witness allocation full of secret bytes while its length is
    // zero, preventing its Drop implementation from erasing that storage.
    let mut assignment = Zeroizing::new(Vec::new());
    assignment
        .try_reserve_exact(WIRES)
        .map_err(|_| OfflineError::Relation)?;
    assignment.extend_from_slice(&prepared.instances);
    assignment.extend_from_slice(&prepared.witnesses);
    drop(prepared);
    if assignment.len() != WIRES {
        return Err(OfflineError::Relation);
    }
    let r1cs = open_fixed(R1CS_PATH, R1CS_BYTES, 0o400)?;
    let witness_map = stream_r1cs_witness_map(r1cs, fixed_r1cs_geometry(), &assignment)
        .map_err(|_| OfflineError::Relation)?;
    if witness_map.domain_size != DOMAIN_SIZE || witness_map.h.len() != DOMAIN_SIZE {
        return Err(OfflineError::Relation);
    }
    Ok(SatisfiedRound1 {
        assignment,
        witness_map,
    })
}

fn open_proof_parameter_descriptors_after_relation(
    _satisfied: &SatisfiedRound1,
) -> R<FixedProofParameterArtifacts> {
    // The exact decode receipt and its compressed source are authenticated
    // only after relation satisfaction. The low-memory core independently
    // rehashes the decoded PK again before decoding any point or starting an
    // MSM. No caller path or digest enters this boundary.
    let receipt = open_fixed(DECODE_RECEIPT_PATH, DECODE_RECEIPT_BYTES, 0o400)?;
    drop(authenticate(
        receipt,
        DECODE_RECEIPT_PATH,
        DECODE_RECEIPT_SHA256,
    )?);
    let compressed = open_fixed(COMPRESSED_PK_PATH, COMPRESSED_PK_BYTES, 0o444)?;
    drop(authenticate(
        compressed,
        COMPRESSED_PK_PATH,
        COMPRESSED_PK_SHA256,
    )?);
    let decoded_pk = open_fixed(DECODED_PK_PATH, DECODED_PK_BYTES, 0o400)?;
    let independent_vk = read_authenticated_exact::<VK_BYTES>(
        open_fixed(VK_PATH, VK_BYTES as u64, 0o444)?,
        Path::new(VK_PATH),
        VK_SHA256,
    )?;
    Ok(FixedProofParameterArtifacts {
        decoded_pk,
        independent_vk,
    })
}

fn nonzero_blinding() -> Zeroizing<Fr> {
    let mut rng = OsRng;
    loop {
        let candidate = Fr::rand(&mut rng);
        if !candidate.is_zero() {
            return Zeroizing::new(candidate);
        }
    }
}

fn read_independent_vk(input: &[u8; VK_BYTES]) -> R<VerifyingKey<Bn254>> {
    let mut cursor = Cursor::new(input.as_slice());
    let value = VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|_| OfflineError::Proof)?;
    let mut tail = [0_u8; 1];
    if cursor.read(&mut tail).map_err(|_| OfflineError::Input)? != 0 {
        return Err(OfflineError::Input);
    }
    Ok(value)
}

fn verify_proof_with_hostile_controls(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; 2],
) -> R<()> {
    let prepared_vk = prepare_verifying_key(vk);
    let accepted = Groth16::<Bn254>::verify_proof(&prepared_vk, proof, public_inputs)
        .map_err(|_| OfflineError::Proof)?;
    if !accepted {
        return Err(OfflineError::Proof);
    }
    let mut wrong_inputs = Zeroizing::new(public_inputs.to_vec());
    wrong_inputs[0] += Fr::one();
    if Groth16::<Bn254>::verify_proof(&prepared_vk, proof, &wrong_inputs)
        .map_err(|_| OfflineError::Proof)?
    {
        return Err(OfflineError::Proof);
    }
    let mut mutated = proof.clone();
    mutated.a = (mutated.a.into_group() + G1Projective::generator()).into_affine();
    if Groth16::<Bn254>::verify_proof(&prepared_vk, &mutated, public_inputs)
        .map_err(|_| OfflineError::Proof)?
    {
        return Err(OfflineError::Proof);
    }
    Ok(())
}

fn independently_verify(
    streamed: StreamedProof,
    independent_vk: [u8; VK_BYTES],
    public_inputs: &[Fr],
) -> R<VerifiedRound1Proof> {
    let vk = read_independent_vk(&independent_vk)?;
    if vk != streamed.vk || public_inputs.len() != 2 {
        return Err(OfflineError::Proof);
    }
    let public_inputs = [public_inputs[0], public_inputs[1]];
    verify_proof_with_hostile_controls(&vk, &streamed.proof, &public_inputs)?;
    Ok(VerifiedRound1Proof {
        proof: streamed.proof,
        public_inputs,
    })
}

fn prove_satisfied_round1(
    satisfied: SatisfiedRound1,
    mut artifacts: FixedProofParameterArtifacts,
) -> R<VerifiedRound1Proof> {
    let r = nonzero_blinding();
    let s = nonzero_blinding();
    let streamed = create_proof_from_compressed_pk(
        &mut artifacts.decoded_pk,
        fixed_proving_geometry(),
        &satisfied.assignment[..INSTANCES],
        &satisfied.assignment[INSTANCES..],
        &satisfied.witness_map.h,
        *r,
        *s,
    )
    .map_err(|_| OfflineError::Proof)?;
    independently_verify(
        streamed,
        artifacts.independent_vk,
        &satisfied.assignment[1..INSTANCES],
    )
}

/// Fixed private phase order. No caller can inject an assignment, round,
/// artifact descriptor, public input, or randomness.
fn fixed_round1_entry() -> R<VerifiedRound1Proof> {
    let prepared = super::prepare::<1>()?;
    let satisfied = satisfy_exact_r1cs(prepared)?;
    let artifacts = open_proof_parameter_descriptors_after_relation(&satisfied)?;
    prove_satisfied_round1(satisfied, artifacts)
}

fn proof_receipt(proof: &[u8; PROOF_BYTES], public_inputs: [String; 2]) -> Value {
    let Value::Object(mut receipt) = json!({
        "schema": PROOF_SCHEMA,
        "classification": CLASSIFICATION,
        "selected_round": 1,
        "prepared_instances": INSTANCES,
        "prepared_witnesses": WITNESSES,
        "prepared_variables": WIRES,
        "prepared_constraints": CONSTRAINTS,
        "public_inputs_decimal": public_inputs,
        "proof_ark_compressed_hex": hex::encode(proof),
        "proof_bytes": PROOF_BYTES,
        "proof_sha256": hex::encode(Sha256::digest(proof)),
        "r1cs_bytes": R1CS_BYTES,
        "r1cs_sha256": R1CS_SHA256_HEX,
        "decoded_pk_bytes": DECODED_PK_BYTES,
        "decoded_pk_sha256": DECODED_PK_SHA256_HEX,
        "compressed_pk_bytes": COMPRESSED_PK_BYTES,
        "compressed_pk_sha256": COMPRESSED_PK_SHA256_HEX,
        "decode_receipt_bytes": DECODE_RECEIPT_BYTES,
        "decode_receipt_sha256": DECODE_RECEIPT_SHA256_HEX,
        "vk_bytes": VK_BYTES,
        "vk_sha256": VK_SHA256_HEX,
    }) else {
        unreachable!()
    };
    let Value::Object(controls) = json!({
        "historical_sources_rehashed": true,
        "r1cs_satisfaction_checked": true,
        "proof_parameter_descriptors_opened_after_satisfaction": true,
        "historical_source_vk_opened_during_assignment_preparation": true,
        "decoded_pk_rehashed_before_deserialization": true,
        "internal_osrng_nonzero_blinding": true,
        "proof_generated": true,
        "independent_vk_rehashed": true,
        "independent_verification": true,
        "wrong_public_inputs_rejected": true,
        "mutated_proof_rejected": true,
        "assignment_serialized": false,
        "secret_fingerprint_emitted": false,
        "setup_executed": false,
        "network_communication": false,
        "funds": false,
        "testnet": false,
        "full_secret_zeroization": false,
        "error_path_source_zeroization_complete": false,
        "abort_oom_zeroization": false,
        "receipt_is_authority": false,
        "public_or_production_authority": false,
    }) else {
        unreachable!()
    };
    receipt.extend(controls);
    Value::Object(receipt)
}

fn validate_proof_receipt(receipt: &Value) -> R<()> {
    exact_keys(
        receipt,
        &[
            "abort_oom_zeroization",
            "assignment_serialized",
            "classification",
            "compressed_pk_bytes",
            "compressed_pk_sha256",
            "decode_receipt_bytes",
            "decode_receipt_sha256",
            "decoded_pk_bytes",
            "decoded_pk_rehashed_before_deserialization",
            "decoded_pk_sha256",
            "error_path_source_zeroization_complete",
            "full_secret_zeroization",
            "funds",
            "historical_source_vk_opened_during_assignment_preparation",
            "historical_sources_rehashed",
            "independent_verification",
            "independent_vk_rehashed",
            "internal_osrng_nonzero_blinding",
            "mutated_proof_rejected",
            "network_communication",
            "proof_parameter_descriptors_opened_after_satisfaction",
            "prepared_constraints",
            "prepared_instances",
            "prepared_variables",
            "prepared_witnesses",
            "proof_ark_compressed_hex",
            "proof_bytes",
            "proof_generated",
            "proof_sha256",
            "public_inputs_decimal",
            "public_or_production_authority",
            "r1cs_bytes",
            "r1cs_satisfaction_checked",
            "r1cs_sha256",
            "receipt_is_authority",
            "schema",
            "secret_fingerprint_emitted",
            "selected_round",
            "setup_executed",
            "testnet",
            "vk_bytes",
            "vk_sha256",
            "wrong_public_inputs_rejected",
        ],
    )?;
    let proof_hex = text(receipt, "proof_ark_compressed_hex")?;
    let proof = hex::decode(proof_hex).map_err(|_| OfflineError::Shape)?;
    let public_inputs = at(receipt, "public_inputs_decimal")?
        .as_array()
        .ok_or(OfflineError::Shape)?;
    let [Value::String(public_input_0), Value::String(public_input_1)] = public_inputs.as_slice()
    else {
        return Err(OfflineError::Shape);
    };
    need(
        text(receipt, "schema")? == PROOF_SCHEMA
            && text(receipt, "classification")? == CLASSIFICATION
            && uint(receipt, "selected_round")? == 1
            && uint(receipt, "prepared_instances")? == INSTANCES as u64
            && uint(receipt, "prepared_witnesses")? == WITNESSES as u64
            && uint(receipt, "prepared_variables")? == WIRES as u64
            && uint(receipt, "prepared_constraints")? == CONSTRAINTS as u64
            && uint(receipt, "proof_bytes")? == PROOF_BYTES as u64
            && proof.len() == PROOF_BYTES
            && proof_hex == hex::encode(&proof)
            && text(receipt, "proof_sha256")? == hex::encode(Sha256::digest(&proof))
            && public_input_0 == PUBLIC_INPUTS_DECIMAL[0]
            && public_input_1 == PUBLIC_INPUTS_DECIMAL[1]
            && uint(receipt, "r1cs_bytes")? == R1CS_BYTES
            && text(receipt, "r1cs_sha256")? == R1CS_SHA256_HEX
            && uint(receipt, "decoded_pk_bytes")? == DECODED_PK_BYTES
            && text(receipt, "decoded_pk_sha256")? == DECODED_PK_SHA256_HEX
            && uint(receipt, "compressed_pk_bytes")? == COMPRESSED_PK_BYTES
            && text(receipt, "compressed_pk_sha256")? == COMPRESSED_PK_SHA256_HEX
            && uint(receipt, "decode_receipt_bytes")? == DECODE_RECEIPT_BYTES
            && text(receipt, "decode_receipt_sha256")? == DECODE_RECEIPT_SHA256_HEX
            && uint(receipt, "vk_bytes")? == VK_BYTES as u64
            && text(receipt, "vk_sha256")? == VK_SHA256_HEX,
        OfflineError::Binding,
    )?;
    for key in [
        "historical_sources_rehashed",
        "historical_source_vk_opened_during_assignment_preparation",
        "r1cs_satisfaction_checked",
        "proof_parameter_descriptors_opened_after_satisfaction",
        "decoded_pk_rehashed_before_deserialization",
        "internal_osrng_nonzero_blinding",
        "proof_generated",
        "independent_vk_rehashed",
        "independent_verification",
        "wrong_public_inputs_rejected",
        "mutated_proof_rejected",
    ] {
        need(
            at(receipt, key)? == &Value::Bool(true),
            OfflineError::Binding,
        )?;
    }
    for key in [
        "assignment_serialized",
        "secret_fingerprint_emitted",
        "setup_executed",
        "network_communication",
        "funds",
        "testnet",
        "full_secret_zeroization",
        "error_path_source_zeroization_complete",
        "abort_oom_zeroization",
        "receipt_is_authority",
        "public_or_production_authority",
    ] {
        need(
            at(receipt, key)? == &Value::Bool(false),
            OfflineError::Binding,
        )?;
    }
    Ok(())
}

fn deserialize_receipt_proof_and_inputs(receipt: &Value) -> R<(Proof<Bn254>, [Fr; 2])> {
    let proof_bytes =
        hex::decode(text(receipt, "proof_ark_compressed_hex")?).map_err(|_| OfflineError::Shape)?;
    let mut proof_cursor = Cursor::new(proof_bytes.as_slice());
    let proof = Proof::<Bn254>::deserialize_compressed(&mut proof_cursor)
        .map_err(|_| OfflineError::Proof)?;
    let mut proof_tail = [0_u8; 1];
    if proof_cursor
        .read(&mut proof_tail)
        .map_err(|_| OfflineError::Input)?
        != 0
    {
        return Err(OfflineError::Input);
    }

    let values = at(receipt, "public_inputs_decimal")?
        .as_array()
        .ok_or(OfflineError::Shape)?;
    let [Value::String(value_0), Value::String(value_1)] = values.as_slice() else {
        return Err(OfflineError::Shape);
    };
    let input_0 = value_0.parse::<Fr>().map_err(|_| OfflineError::Shape)?;
    let input_1 = value_1.parse::<Fr>().map_err(|_| OfflineError::Shape)?;
    need(
        input_0.to_string() == *value_0 && input_1.to_string() == *value_1,
        OfflineError::Binding,
    )?;
    Ok((proof, [input_0, input_1]))
}

fn verify_fixed_round1_proof_receipt_bytes(raw: &[u8]) -> R<FrozenRound1ProofReceiptCommitment> {
    need(
        !raw.is_empty() && raw.len() <= FROZEN_W1_PROOF_RECEIPT_MAX_BYTES,
        OfflineError::Shape,
    )?;
    let receipt = super::super::unique_json(raw)?;
    validate_proof_receipt(&receipt)?;
    need(
        super::super::canonical(&receipt)? == raw,
        OfflineError::Binding,
    )?;
    let (proof, public_inputs) = deserialize_receipt_proof_and_inputs(&receipt)?;
    let owned_vk = read_authenticated_exact::<VK_BYTES>(
        open_fixed(VK_PATH, VK_BYTES as u64, 0o444)?,
        Path::new(VK_PATH),
        VK_SHA256,
    )?;
    let vk = read_independent_vk(&owned_vk)?;
    verify_proof_with_hostile_controls(&vk, &proof, &public_inputs)?;
    Ok(receipt_commitment(raw))
}

#[cfg(target_os = "linux")]
fn write_canonical_receipt_and_commit(
    private_target: super::PrivateReceiptTarget,
    raw: &[u8],
) -> R<FrozenRound1ProofReceiptCommitment> {
    let commitment = receipt_commitment(raw);
    super::write_private_receipt(private_target, raw)?;
    Ok(commitment)
}

fn write_fixed_round1_proof_receipt(receipt_path: &Path) -> R<FrozenRound1ProofReceiptCommitment> {
    #[cfg(target_os = "linux")]
    let private_target = super::open_private_receipt_target(receipt_path)?;
    #[cfg(not(target_os = "linux"))]
    return Err(OfflineError::Output);

    let verified = fixed_round1_entry()?;
    let public_inputs = [
        verified.public_inputs[0].to_string(),
        verified.public_inputs[1].to_string(),
    ];
    let mut serialized = Vec::new();
    serialized
        .try_reserve_exact(PROOF_BYTES)
        .map_err(|_| OfflineError::Output)?;
    verified
        .proof
        .serialize_compressed(&mut serialized)
        .map_err(|_| OfflineError::Proof)?;
    let proof: [u8; PROOF_BYTES] = serialized.try_into().map_err(|_| OfflineError::Proof)?;
    let receipt = proof_receipt(&proof, public_inputs);
    validate_proof_receipt(&receipt)?;
    let raw = super::super::canonical(&receipt).map_err(|_| OfflineError::Output)?;
    #[cfg(target_os = "linux")]
    return write_canonical_receipt_and_commit(private_target, &raw);
    #[cfg(not(target_os = "linux"))]
    Err(OfflineError::Output)
}

/// Generate and independently verify the one fixed offline W1 round-1 proof,
/// then write only its create-new mode-0400 private evidence receipt. The caller
/// selects no assignment, round, artifact, public input, randomness, network,
/// funds, setup, or authority. Success returns only the SHA-256 commitment to
/// the exact canonical bytes already written and fsynced.
pub fn write_frozen_round1_proof_receipt(
    receipt_path: &Path,
) -> Result<FrozenRound1ProofReceiptCommitment, FrozenRound1ProofRefused> {
    PROOF_AVAILABLE
        .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| FrozenRound1ProofRefused { _private: () })?;
    write_fixed_round1_proof_receipt(receipt_path)
        .map_err(|_| FrozenRound1ProofRefused { _private: () })
}

/// Verify one bounded, exact-canonical frozen proof receipt against an owned
/// snapshot of the fixed VK. This opens no assignment, R1CS, proving key,
/// network, funds, or output path. Success returns only the SHA-256 commitment
/// to the exact input bytes after valid-proof, wrong-input, and mutated-proof
/// controls all complete.
pub fn verify_frozen_round1_proof_receipt(
    raw: &[u8],
) -> Result<FrozenRound1ProofReceiptCommitment, FrozenRound1ProofVerificationRefused> {
    verify_fixed_round1_proof_receipt_bytes(raw)
        .map_err(|_| FrozenRound1ProofVerificationRefused { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn private_test_directory(label: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let mut attempt = 0_u64;
        loop {
            let candidate = std::env::temp_dir().join(format!(
                "kpb-frozen-w1-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                        .unwrap_or_else(|_| panic!("seal private test directory"));
                    return candidate;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempt += 1;
                }
                Err(_) => panic!("create private test directory"),
            }
        }
    }

    #[test]
    fn fixed_source_boundary_is_non_authorizing() {
        assert!(STATUS.reviewed_core_compiled_privately);
        assert!(STATUS.relation_owned_assignment_bridge);
        assert!(STATUS.fixed_round_and_geometry);
        assert!(STATUS.internal_osrng);
        assert!(STATUS.decoded_pk_descriptor_opener);
        assert!(STATUS.independent_vk_descriptor_opener);
        assert!(!STATUS.full_secret_zeroization);
        assert!(STATUS.fixed_nondefault_receipt_entry);
        assert!(STATUS.private_create_new_receipt_sink);
        assert!(!STATUS.outer_build_and_launch_selected);
        assert!(!STATUS.production_authority);
        assert_eq!(fixed_r1cs_geometry().identity.sha256, R1CS_SHA256);
        assert_eq!(fixed_proving_geometry().identity.sha256, DECODED_PK_SHA256);
        assert_eq!(fixed_proving_geometry().vk_identity.sha256, VK_SHA256);
    }

    #[test]
    fn parameter_authority_cannot_be_minted_before_satisfaction() {
        let signature: fn(&SatisfiedRound1) -> R<FixedProofParameterArtifacts> =
            open_proof_parameter_descriptors_after_relation;
        let entry: fn() -> R<VerifiedRound1Proof> = fixed_round1_entry;
        let public_entry: fn(
            &Path,
        ) -> Result<
            FrozenRound1ProofReceiptCommitment,
            FrozenRound1ProofRefused,
        > = write_frozen_round1_proof_receipt;
        let verifier_entry: fn(
            &[u8],
        ) -> Result<
            FrozenRound1ProofReceiptCommitment,
            FrozenRound1ProofVerificationRefused,
        > = verify_frozen_round1_proof_receipt;
        let _ = (signature, entry, public_entry, verifier_entry);
        assert!(!STATUS.outer_build_and_launch_selected);
    }

    #[test]
    fn exact_receipt_schema_accepts_only_honest_public_shape() {
        let proof = [0x5a_u8; PROOF_BYTES];
        let receipt = proof_receipt(
            &proof,
            [
                PUBLIC_INPUTS_DECIMAL[0].into(),
                PUBLIC_INPUTS_DECIMAL[1].into(),
            ],
        );
        assert!(validate_proof_receipt(&receipt).is_ok());
        let canonical = super::super::super::canonical(&receipt)
            .unwrap_or_else(|_| panic!("canonicalize synthetic proof receipt"));
        assert!(canonical.len() <= FROZEN_W1_PROOF_RECEIPT_MAX_BYTES);
        assert_eq!(
            receipt["proof_sha256"],
            Value::String(hex::encode(Sha256::digest(proof)))
        );
        assert!(receipt.get("assignment_sha256").is_none());
        assert!(receipt.get("secret_fingerprint").is_none());

        for (key, value) in [
            ("prepared_constraints", Value::from(CONSTRAINTS as u64 - 1)),
            ("r1cs_satisfaction_checked", Value::Bool(false)),
            (
                "proof_parameter_descriptors_opened_after_satisfaction",
                Value::Bool(false),
            ),
            (
                "historical_source_vk_opened_during_assignment_preparation",
                Value::Bool(false),
            ),
            ("independent_verification", Value::Bool(false)),
            ("full_secret_zeroization", Value::Bool(true)),
            ("receipt_is_authority", Value::Bool(true)),
        ] {
            let mut changed = receipt.clone();
            changed[key] = value;
            assert!(validate_proof_receipt(&changed).is_err(), "{key}");
        }

        let mut changed = receipt.clone();
        changed["proof_ark_compressed_hex"] = Value::String("00".repeat(PROOF_BYTES));
        assert!(validate_proof_receipt(&changed).is_err());

        let mut changed = receipt.clone();
        changed["public_inputs_decimal"][0] = Value::String("0".into());
        assert!(validate_proof_receipt(&changed).is_err());

        let mut changed = receipt.clone();
        changed["public_inputs_decimal"][0] = Value::from(0);
        assert!(validate_proof_receipt(&changed).is_err());

        let mut changed = receipt.clone();
        changed["public_inputs_decimal"] = json!([
            PUBLIC_INPUTS_DECIMAL[0],
            PUBLIC_INPUTS_DECIMAL[1],
            PUBLIC_INPUTS_DECIMAL[0]
        ]);
        assert!(validate_proof_receipt(&changed).is_err());

        let mut changed = receipt;
        changed["unexpected_secret_fingerprint"] = Value::String("0".repeat(64));
        assert!(validate_proof_receipt(&changed).is_err());
    }

    #[test]
    fn ark_compressed_proof_encoding_is_exactly_128_bytes() {
        let mut raw = Vec::new();
        Proof::<Bn254>::default()
            .serialize_compressed(&mut raw)
            .unwrap_or_else(|_| panic!("serialize default proof control"));
        assert_eq!(raw.len(), PROOF_BYTES);
    }

    #[test]
    fn verification_input_bounds_and_shape_refuse_before_fixed_vk_access() {
        let oversized = vec![0_u8; FROZEN_W1_PROOF_RECEIPT_MAX_BYTES + 1];
        assert!(verify_frozen_round1_proof_receipt(&oversized).is_err());
        assert!(verify_frozen_round1_proof_receipt(b"{}\n").is_err());
        assert!(verify_frozen_round1_proof_receipt(b"").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_authenticated_bytes_survive_held_writer_mutation() {
        use std::io::Write;

        const SYNTHETIC_BYTES: usize = VK_BYTES;
        let directory = private_test_directory("owned-vk-snapshot");
        let path = directory.join("synthetic-vk.bin");
        let original = [0x39_u8; SYNTHETIC_BYTES];
        let replacement = [0xa7_u8; SYNTHETIC_BYTES];
        let expected: [u8; 32] = Sha256::digest(original).into();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap_or_else(|_| panic!("create synthetic held-writer control"));
        writer
            .write_all(&original)
            .unwrap_or_else(|_| panic!("write synthetic original"));
        writer
            .sync_all()
            .unwrap_or_else(|_| panic!("sync synthetic original"));

        let reader = File::open(&path).unwrap_or_else(|_| panic!("open synthetic reader"));
        let owned = read_authenticated_exact::<SYNTHETIC_BYTES>(reader, &path, expected)
            .unwrap_or_else(|_| panic!("authenticate synthetic snapshot"));

        writer
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|_| panic!("rewind held synthetic writer"));
        writer
            .write_all(&replacement)
            .unwrap_or_else(|_| panic!("mutate through held synthetic writer"));
        writer
            .sync_all()
            .unwrap_or_else(|_| panic!("sync held-writer mutation"));

        assert_eq!(owned, original);
        assert_ne!(owned, replacement);
        let changed = File::open(&path).unwrap_or_else(|_| panic!("reopen mutated synthetic"));
        assert!(read_authenticated_exact::<SYNTHETIC_BYTES>(changed, &path, expected).is_err());

        drop(writer);
        fs::remove_file(&path).unwrap_or_else(|_| panic!("remove synthetic control"));
        fs::remove_dir(&directory).unwrap_or_else(|_| panic!("remove synthetic control directory"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returned_commitment_binds_exact_written_canonical_bytes() {
        let directory = private_test_directory("receipt-commitment");
        let path = directory.join("PROOF.json");
        let target = super::super::open_private_receipt_target(&path)
            .unwrap_or_else(|_| panic!("open synthetic proof receipt target"));
        let raw = b"{\"schema\":\"synthetic-proof-receipt-control\"}\n";
        let expected = hex::encode(Sha256::digest(raw));
        let commitment = write_canonical_receipt_and_commit(target, raw)
            .unwrap_or_else(|_| panic!("write synthetic proof receipt"));

        assert_eq!(commitment.to_string(), expected);
        assert_eq!(commitment.to_string().len(), 64);
        assert!(
            commitment
                .to_string()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            fs::read(&path).unwrap_or_else(|_| panic!("read synthetic proof receipt")),
            raw
        );

        fs::remove_file(&path).unwrap_or_else(|_| panic!("remove synthetic proof receipt"));
        fs::remove_dir(&directory).unwrap_or_else(|_| panic!("remove synthetic receipt directory"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_receipt_parent_refuses_before_any_proof_work() {
        assert!(
            write_frozen_round1_proof_receipt(Path::new("/proc/self/fd/-1/PROOF.json")).is_err()
        );
    }
}
