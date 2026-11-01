//! Exact, no-argument W1 round-1 assignment preparation.
//!
//! This is deliberately tied to one retained seven-checkpoint offline run.
//! It does not accept an input/artifact path, digest, round, public input,
//! boolean, proving key, or proof-launch authority from its caller. Its sole
//! caller-selected value is the output receipt path, whose existing parent is
//! required to be owner-only. Assignment slices never cross this module's
//! boundary; its only public operation writes a private, create-new,
//! non-authoritative measurement receipt.

use super::super::{
    AGGREGATE_CONSTRAINTS, AGGREGATE_MATRIX, AGGREGATE_VARIABLES, FEE, FullW1RoundSource,
    OUTPUT_VK, ROUND1_CHANGE, ROUND1_INPUT, ROUND1_PAYMENT, ROUND2_COLLUDER_CHANGE,
    ROUND2_COLLUDER_INPUT, ROUND2_HONEST_CHANGE, ROUND2_HONEST_INPUT, ROUND2_PAYMENT,
    append_signature_witnesses,
};
use super::{
    OfflineError, R, array, at, canonical, canonical_hex, canonical_sha, check_cross_round,
    check_graph, check_outputs, check_public_close, check_signatures, exact_keys,
    expected_public_inputs, load_ref, load_round, need, safe_path, sha256, text, uint, unique_json,
};
use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, OpenOptions},
    io::{BufReader, ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "offline-w1-prover")]
#[path = "frozen_prover.rs"]
mod frozen_prover;
#[cfg(feature = "offline-w1-prover")]
pub use frozen_prover::{
    FROZEN_W1_PROOF_RECEIPT_MAX_BYTES, FrozenRound1ProofReceiptCommitment,
    FrozenRound1ProofRefused, FrozenRound1ProofVerificationRefused,
    verify_frozen_round1_proof_receipt, write_frozen_round1_proof_receipt,
};

const ROOT: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-offline-w1-components-20261029-01";
const HISTORICAL_SOURCE_ROOT: &str = "/home/luke/projects/kpi-intensive-2026-10-22/continuation/.local/private-batch-w1-historical-reconstruction-private-20261029-01/private-batch-w1-historical-reconstructed-nonfinal-20261029-01";
const PLAN_SHA256: &str = "8b24a987f87d2bd9dca0b04f4622022eac0e04724af06ff761141169f0853482";
const PLAN_IDENTITY: &str = "f9ac4a37df9e50867eb01e282cf9a8c9f6ce9ff56891aa27d909a71877c7bd80";
const RUN_ID: &str = "2904ab69-cc9e-40ce-834f-07a56cd15bbc";
const EPOCH_ID: &str = "d3d47403-5350-414d-a133-2447bb28da5a";
const SOURCE_CLOSURE: &str = "8fcca654b4eb03b38a62c22648cd14323919279dc49d841751d3802683c66aae";
const SELECTED_BUILD: &str = "eee5536d5bcab041c7f98476ba6a5b8c4e8632373cc51b7087a568866072a55a";
const AGGREGATE_VK: &str = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102";
const PLAN_BYTES: u64 = 30_403;
const OWNER_SOURCE_CLOSURE_BYTES: u64 = 8_916;
const OWNER_SOURCE_CLOSURE_SHA256: &str =
    "e100f1f244a7c14b9e8d771d54c37a99ba7b7f75f7c6b9402e010844fddd7051";
const HISTORICAL_MANIFEST_BYTES: u64 = 82_856;
const HISTORICAL_MANIFEST_SHA256: &str =
    "8db2a202c0c2547af841bade48f49168d093fa74ff18620573f041f6fcfbcfbd";
const HISTORICAL_RECEIPT_BYTES: u64 = 5_616;
const HISTORICAL_RECEIPT_SHA256: &str =
    "14fcfa0ddeaa3f8bfc6eede6b571be9d9f555be2977c1e79c0e81b0b485d8e26";
const HISTORICAL_GENERATOR_BYTES: u64 = 43_242;
const HISTORICAL_GENERATOR_SHA256: &str =
    "cacd8dbc153263a5cd2a477d9340337bbc5531e30805cc79ee035de4ae530975";
#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200_000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2_000_000;
static AVAILABLE: AtomicBool = AtomicBool::new(true);

struct CheckpointContract {
    directory: &'static str,
    stage: &'static str,
    bytes: u64,
    raw_sha256: &'static str,
    identity: &'static str,
}

const CHECKPOINTS: [CheckpointContract; 7] = [
    CheckpointContract {
        directory: "01-bootstrap",
        stage: "bootstrap",
        bytes: 2_790,
        raw_sha256: "eee34d50f0876c500700ebf90d99c30c735ff5e601c6696c38e47320d8139763",
        identity: "8b0c5eddd851ae5f7f5d50f7d13af06208b3ca5f37da62cb0ed26a45d200ed97",
    },
    CheckpointContract {
        directory: "02-round-1-inputs",
        stage: "round-1-inputs",
        bytes: 2_152,
        raw_sha256: "9acb95ae0e2b901918951392b5415903e760dd513a11581a84eba20f76bb5516",
        identity: "f5fdffa1e2c45294e4a4487572dc944b6c3b53fa873bcc09c91adf4195551770",
    },
    CheckpointContract {
        directory: "03-round-1-components",
        stage: "round-1-components",
        bytes: 9_201,
        raw_sha256: "4c5e4155a9d6b41c6a79b8dc278a0fcd93b258a7653bac4f9f1b516de2daa264",
        identity: "b097192b11b0c0928db7fcb30a4c72577fcc1bd2eb578e2b2efa3f1d1d16a9e3",
    },
    CheckpointContract {
        directory: "04-round-1-close",
        stage: "round-1-close",
        bytes: 3_059,
        raw_sha256: "a9a4c0c741e9f3f6c05c735c3f6e9e261815c8be8307a0d17543180b99cb49eb",
        identity: "f5bde450fd7e9a1f386d4a014deb18bcb2729e0e404e8def76e59b07dd5a0a3d",
    },
    CheckpointContract {
        directory: "05-round-2-inputs",
        stage: "round-2-inputs",
        bytes: 2_156,
        raw_sha256: "1caff42c40cad980df71d4fc7df58029a622ae5765a9b2fc6c1a62c1cd564588",
        identity: "2ab4d30f1148b931da776df328c7653a961d43dab755236b164f8d946f1c56b3",
    },
    CheckpointContract {
        directory: "06-round-2-components",
        stage: "round-2-components",
        bytes: 9_201,
        raw_sha256: "d11d815e42e1ef892e247f83fd237251edb787f8420976511cbc683bc11fb2a1",
        identity: "3332832e9b2b51baae20ff972d2a1cb335d1cef43edcb2bd65a573319cac4cdd",
    },
    CheckpointContract {
        directory: "07-round-2-close",
        stage: "round-2-close",
        bytes: 3_060,
        raw_sha256: "d787de9f71e206850f3d30c45628d5f0affbbc0d55149605117a9fec2a9abdd2",
        identity: "ba7508c02391fa7583cb70e6c9efd5da5210164b1f9cb9da2f88d9c825e837b5",
    },
];

/// One deliberately opaque public failure shape.
pub struct FrozenRound1AssignmentRefused {
    _private: (),
}

struct PreparedAssignment {
    instances: Vec<Fr>,
    witnesses: Vec<Fr>,
}

impl Drop for PreparedAssignment {
    fn drop(&mut self) {
        self.instances.zeroize();
        self.witnesses.zeroize();
    }
}

struct ConstraintAssignmentScrubber {
    constraint_system: ConstraintSystemRef<Fr>,
    armed: bool,
}

impl ConstraintAssignmentScrubber {
    fn new(constraint_system: ConstraintSystemRef<Fr>) -> Self {
        Self {
            constraint_system,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConstraintAssignmentScrubber {
    fn drop(&mut self) {
        if self.armed {
            if let Some(mut system) = self.constraint_system.borrow_mut() {
                system.assignments.instance_assignment.zeroize();
                system.assignments.witness_assignment.zeroize();
            }
        }
    }
}

#[cfg(unix)]
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

fn exact_file_before(path: &Path, expected_bytes: u64) -> R<fs::Metadata> {
    let before = fs::symlink_metadata(path).map_err(|_| OfflineError::Input)?;
    need(
        before.file_type().is_file()
            && !before.file_type().is_symlink()
            && before.len() == expected_bytes,
        OfflineError::Input,
    )?;
    #[cfg(unix)]
    need(before.nlink() == 1, OfflineError::Input)?;
    Ok(before)
}

fn exact_regular(path: &Path, expected_bytes: u64, expected_sha: &str) -> R<Vec<u8>> {
    let before = exact_file_before(path, expected_bytes)?;
    let mut file = fs::File::open(path).map_err(|_| OfflineError::Input)?;
    let opened = file.metadata().map_err(|_| OfflineError::Input)?;
    #[cfg(unix)]
    need(same_file_state(&opened, &before), OfflineError::Input)?;
    let mut raw =
        Vec::with_capacity(usize::try_from(expected_bytes).map_err(|_| OfflineError::Input)?);
    file.read_to_end(&mut raw)
        .map_err(|_| OfflineError::Input)?;
    let after = file.metadata().map_err(|_| OfflineError::Input)?;
    let after_path = fs::symlink_metadata(path).map_err(|_| OfflineError::Input)?;
    #[cfg(unix)]
    need(
        same_file_state(&after, &opened) && same_file_state(&after_path, &opened),
        OfflineError::Input,
    )?;
    need(
        raw.len() as u64 == expected_bytes && sha256(&raw) == expected_sha,
        OfflineError::Binding,
    )?;
    Ok(raw)
}

fn exact_json(path: &Path, expected_bytes: u64, expected_sha: &str) -> R<(Value, Vec<u8>)> {
    let raw = exact_regular(path, expected_bytes, expected_sha)?;
    let value = unique_json(&raw)?;
    need(canonical(&value)? == raw, OfflineError::Input)?;
    Ok((value, raw))
}

fn self_identity(value: &Value, key: &str, expected: &str) -> R<()> {
    need(text(value, key)? == expected, OfflineError::Binding)?;
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(OfflineError::Shape)?
        .remove(key)
        .ok_or(OfflineError::Shape)?;
    need(
        sha256(&canonical(&unsigned)?) == expected,
        OfflineError::Binding,
    )
}

fn nested<'a>(value: &'a Value, keys: &[&str]) -> R<&'a Value> {
    keys.iter().try_fold(value, |current, key| at(current, key))
}

fn verify_exact_streamed(path: &Path, expected_bytes: u64, expected_sha: &str) -> R<()> {
    let before = exact_file_before(path, expected_bytes)?;
    let file = fs::File::open(&path).map_err(|_| OfflineError::Input)?;
    let opened = file.metadata().map_err(|_| OfflineError::Input)?;
    #[cfg(unix)]
    need(same_file_state(&opened, &before), OfflineError::Input)?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = Zeroizing::new(vec![0u8; 1 << 20]);
    loop {
        let count = reader.read(&mut *buffer).map_err(|_| OfflineError::Input)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        bytes = bytes.checked_add(count as u64).ok_or(OfflineError::Input)?;
        need(bytes <= expected_bytes, OfflineError::Input)?;
    }
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| OfflineError::Input)?;
    let after_path = fs::symlink_metadata(path).map_err(|_| OfflineError::Input)?;
    #[cfg(unix)]
    need(
        same_file_state(&after, &opened) && same_file_state(&after_path, &opened),
        OfflineError::Input,
    )?;
    need(
        bytes == expected_bytes && hex::encode(digest.finalize()) == expected_sha,
        OfflineError::Binding,
    )
}

fn verify_ref_streamed(value: &Value, base: &Path) -> R<()> {
    exact_keys(value, &["bytes", "path", "sha256"])?;
    let path = safe_path(text(value, "path")?, base)?;
    let expected_sha = canonical_sha(text(value, "sha256")?)?;
    let expected_bytes = uint(value, "bytes")?;
    verify_exact_streamed(&path, expected_bytes, expected_sha)
}

fn validate_plan_semantics(plan: &Value) -> R<()> {
    need(
        text(plan, "schema")? == "kpb-offline-w1-plan/v1"
            && text(plan, "classification")?
                == "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_FEASIBILITY_ONLY"
            && text(plan, "run_id")? == RUN_ID
            && text(plan, "source_instance_epoch_id")? == EPOCH_ID
            && text(plan, "source_closure_sha256")? == SOURCE_CLOSURE,
        OfflineError::Binding,
    )?;
    self_identity(plan, "plan_identity_sha256", PLAN_IDENTITY)?;
    let build = at(plan, "selected_build")?;
    self_identity(build, "build_identity_sha256", SELECTED_BUILD)?;
    need(
        text(
            nested(build, &["aggregate_feasibility_only"])?,
            "matrix_sha256",
        )? == AGGREGATE_MATRIX
            && text(
                nested(build, &["aggregate_feasibility_only", "verification_key"])?,
                "sha256",
            )? == AGGREGATE_VK
            && text(nested(build, &["output", "verification_key"])?, "sha256")? == OUTPUT_VK,
        OfflineError::Binding,
    )?;
    let boundaries = at(plan, "boundaries")?;
    need(
        at(boundaries, "network_enabled")? == &Value::Bool(false)
            && at(boundaries, "funding_or_real_funds")? == &Value::Bool(false)
            && at(boundaries, "backing_or_chain_acceptance")? == &Value::Bool(false)
            && at(boundaries, "aggregate_proof_generation_authorized")? == &Value::Bool(false)
            && at(
                boundaries,
                "aggregate_pk_content_read_during_plan_selection",
            )? == &Value::Bool(false),
        OfflineError::Binding,
    )?;
    let stages = array(plan, "stage_order", 10)?;
    let expected = [
        "bootstrap",
        "round-1-inputs",
        "round-1-components",
        "round-1-close",
        "round-2-inputs",
        "round-2-components",
        "round-2-close",
        "round-1-aggregate",
        "round-2-aggregate",
        "handoff",
    ];
    need(
        stages
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_str() == Some(expected)),
        OfflineError::Binding,
    )?;
    let members = at(plan, "source_members")?;
    need(
        members.as_array().map(Vec::len) == Some(81)
            && sha256(&canonical(members)?) == SOURCE_CLOSURE,
        OfflineError::Binding,
    )
}

fn validate_checkpoint_semantics(checkpoint: &Value, index: usize) -> R<()> {
    let contract = CHECKPOINTS.get(index).ok_or(OfflineError::Shape)?;
    need(
        text(checkpoint, "schema")? == "kpb-offline-w1-checkpoint/v1"
            && text(checkpoint, "classification")?
                == "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_FEASIBILITY_ONLY"
            && text(checkpoint, "run_id")? == RUN_ID
            && text(checkpoint, "source_instance_epoch_id")? == EPOCH_ID
            && text(checkpoint, "stage")? == contract.stage
            && uint(checkpoint, "ordinal")? == (index + 1) as u64,
        OfflineError::Binding,
    )?;
    self_identity(checkpoint, "checkpoint_identity_sha256", contract.identity)?;
    let previous = at(checkpoint, "previous")?;
    if index == 0 {
        need(previous.is_null(), OfflineError::Binding)?;
    } else {
        need(
            text(previous, "sha256")? == CHECKPOINTS[index - 1].raw_sha256,
            OfflineError::Binding,
        )?;
    }
    at(checkpoint, "artifacts")?
        .as_object()
        .filter(|artifacts| !artifacts.is_empty())
        .ok_or(OfflineError::Shape)?;
    Ok(())
}

fn artifact(checkpoint: &Value, key: &str) -> R<Value> {
    at(at(checkpoint, "artifacts")?, key).cloned()
}

fn round_value(checkpoint: &Value, round: usize) -> R<Value> {
    Ok(json!({
        "round": round,
        "context": artifact(checkpoint, "context.bin")?,
        "effects_core": artifact(checkpoint, "effects-core.bin")?,
        "projection": artifact(checkpoint, "projection.bin")?,
        "w0_selection": artifact(checkpoint, "w0-selection.json")?,
        "owners": (0..3).map(|owner| -> R<Value> {
            Ok(json!({
                "record": artifact(checkpoint, &format!("owner-{owner}-record.json"))?,
                "signature_matrix": artifact(checkpoint, &format!("owner-{owner}-signature-matrix.json"))?,
                "signature_witness": artifact(checkpoint, &format!("owner-{owner}-signature-witness.json"))?,
            }))
        }).collect::<R<Vec<_>>>()?,
    }))
}

fn check_offline_workload(round: usize, source: &FullW1RoundSource) -> R<()> {
    let (inputs, payments, changes) = if round == 1 {
        ([ROUND1_INPUT; 3], [ROUND1_PAYMENT; 3], [ROUND1_CHANGE; 3])
    } else if round == 2 {
        (
            [
                ROUND2_HONEST_INPUT,
                ROUND2_COLLUDER_INPUT,
                ROUND2_HONEST_INPUT,
            ],
            [ROUND2_PAYMENT; 3],
            [
                ROUND2_HONEST_CHANGE,
                ROUND2_COLLUDER_CHANGE,
                ROUND2_HONEST_CHANGE,
            ],
        )
    } else {
        return Err(OfflineError::Shape);
    };
    need(
        source.circuit.effects.total_fee == FEE * 3,
        OfflineError::Binding,
    )?;
    for owner in 0..3 {
        let witness = &source.circuit.witness.owners[owner];
        need(
            witness.note.value == inputs[owner]
                && witness.outputs[0].note.value == payments[owner]
                && witness.outputs[1].note.value == changes[owner]
                && witness.fee_sompi == FEE
                && witness
                    .note
                    .value
                    .checked_sub(witness.outputs[0].note.value)
                    .and_then(|value| value.checked_sub(witness.outputs[1].note.value))
                    == Some(FEE),
            OfflineError::Binding,
        )?;
    }
    Ok(())
}

fn validate_public_instances(instances: &[Fr], source: &FullW1RoundSource) -> R<()> {
    let expected = expected_public_inputs(&source.circuit.effects);
    validate_public_instance_values(instances, expected)
}

fn validate_public_instance_values(instances: &[Fr], expected: [Fr; 2]) -> R<()> {
    need(
        instances.len() == 3
            && instances[0] == Fr::ONE
            && instances[1] == expected[0]
            && instances[2] == expected[1],
        OfflineError::Binding,
    )
}

fn exact_directory_entries(path: &Path, expected: &[String], expected_mode: u32) -> R<()> {
    let before = fs::symlink_metadata(path).map_err(|_| OfflineError::Input)?;
    need(
        before.file_type().is_dir() && !before.file_type().is_symlink(),
        OfflineError::Input,
    )?;
    #[cfg(unix)]
    need(before.mode() & 0o777 == expected_mode, OfflineError::Input)?;
    let mut actual = fs::read_dir(path)
        .map_err(|_| OfflineError::Input)?
        .map(|entry| {
            entry
                .map_err(|_| OfflineError::Input)?
                .file_name()
                .into_string()
                .map_err(|_| OfflineError::Input)
        })
        .collect::<R<Vec<_>>>()?;
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    let after = fs::symlink_metadata(path).map_err(|_| OfflineError::Input)?;
    #[cfg(unix)]
    need(same_file_state(&after, &before), OfflineError::Input)?;
    need(actual == expected, OfflineError::Binding)
}

fn verify_historical_source_bundle(plan: &Value) -> R<()> {
    let root = Path::new(HISTORICAL_SOURCE_ROOT);
    exact_directory_entries(
        root,
        &[
            "MANIFEST.json".into(),
            "OWNER-AUX-SOURCE-CLOSURE.json".into(),
            "PLAN.json".into(),
            "RECONSTRUCTION-SOURCE.py".into(),
            "TRANSFORMATION-RECEIPT.json".into(),
            "members".into(),
        ],
        0o500,
    )?;
    let (manifest, _) = exact_json(
        &root.join("MANIFEST.json"),
        HISTORICAL_MANIFEST_BYTES,
        HISTORICAL_MANIFEST_SHA256,
    )?;
    need(
        text(&manifest, "schema")? == "kpb-historical-w1-source-closure-snapshot/v1"
            && text(&manifest, "classification")? == "HISTORICAL_RECONSTRUCTED_NONFINAL"
            && text(&manifest, "source_members_identity_sha256")? == SOURCE_CLOSURE
            && uint(&manifest, "member_count")? == 81,
        OfflineError::Binding,
    )?;
    let boundaries = at(&manifest, "boundaries")?;
    for key in [
        "current_source",
        "build_reproduced",
        "binary_reproduced",
        "authorization",
        "assignment_or_proof_generated",
        "setup_network_or_funds",
    ] {
        need(
            at(boundaries, key)? == &Value::Bool(false),
            OfflineError::Binding,
        )?;
    }
    let (receipt, _) = exact_json(
        &root.join("TRANSFORMATION-RECEIPT.json"),
        HISTORICAL_RECEIPT_BYTES,
        HISTORICAL_RECEIPT_SHA256,
    )?;
    need(
        text(&receipt, "schema")? == "kpb-historical-w1-source-reconstruction/v1"
            && text(&receipt, "classification")? == "HISTORICAL_RECONSTRUCTED_NONFINAL"
            && text(&receipt, "source_members_identity_sha256")? == SOURCE_CLOSURE,
        OfflineError::Binding,
    )?;
    for key in [
        "current_source",
        "build_reproduced",
        "binary_reproduced",
        "authorization",
        "assignment_or_proof_generated",
        "setup_network_or_funds",
    ] {
        need(
            at(&receipt, key)? == &Value::Bool(false),
            OfflineError::Binding,
        )?;
    }
    verify_exact_streamed(
        &root.join("OWNER-AUX-SOURCE-CLOSURE.json"),
        OWNER_SOURCE_CLOSURE_BYTES,
        OWNER_SOURCE_CLOSURE_SHA256,
    )?;
    verify_exact_streamed(
        &root.join("RECONSTRUCTION-SOURCE.py"),
        HISTORICAL_GENERATOR_BYTES,
        HISTORICAL_GENERATOR_SHA256,
    )?;
    let members = at(plan, "source_members")?
        .as_array()
        .ok_or(OfflineError::Shape)?;
    need(members.len() == 81, OfflineError::Binding)?;
    let mut names = Vec::with_capacity(members.len());
    for (ordinal, member) in members.iter().enumerate() {
        exact_keys(member, &["bytes", "path", "sha256"])?;
        let expected_bytes = uint(member, "bytes")?;
        let expected_sha = canonical_sha(text(member, "sha256")?)?;
        let name = format!("{ordinal:03}-{expected_sha}");
        verify_exact_streamed(
            &root.join("members").join(&name),
            expected_bytes,
            expected_sha,
        )?;
        names.push(name);
    }
    exact_directory_entries(&root.join("members"), &names, 0o500)
}

fn load_frozen_sources() -> R<(FullW1RoundSource, FullW1RoundSource)> {
    let root = Path::new(ROOT);
    let metadata = fs::symlink_metadata(root).map_err(|_| OfflineError::Input)?;
    need(metadata.is_dir(), OfflineError::Input)?;
    #[cfg(unix)]
    need(metadata.mode() & 0o777 == 0o700, OfflineError::Input)?;

    let historical_root = Path::new(HISTORICAL_SOURCE_ROOT);
    let (plan, _) = exact_json(&historical_root.join("PLAN.json"), PLAN_BYTES, PLAN_SHA256)?;
    validate_plan_semantics(&plan)?;
    verify_historical_source_bundle(&plan)?;
    verify_ref_streamed(at(&plan, "profile")?, root)?;
    verify_ref_streamed(at(&plan, "rehearsal")?, root)?;

    let mut checkpoints = Vec::with_capacity(CHECKPOINTS.len());
    for (index, contract) in CHECKPOINTS.iter().enumerate() {
        let path = root.join(contract.directory).join("CHECKPOINT.json");
        let (checkpoint, _) = exact_json(&path, contract.bytes, contract.raw_sha256)?;
        validate_checkpoint_semantics(&checkpoint, index)?;
        for value in at(&checkpoint, "artifacts")?
            .as_object()
            .ok_or(OfflineError::Shape)?
            .values()
        {
            verify_ref_streamed(value, root)?;
        }
        checkpoints.push(checkpoint);
    }
    need(
        nested(&checkpoints[2], &["facts", "aggregate_proof_present"])? == &Value::Bool(false)
            && nested(&checkpoints[5], &["facts", "aggregate_proof_present"])?
                == &Value::Bool(false),
        OfflineError::Binding,
    )?;

    let aggregate_vk_ref = nested(
        &plan,
        &[
            "selected_build",
            "aggregate_feasibility_only",
            "verification_key",
        ],
    )?;
    let aggregate_vk_leaf = load_ref(aggregate_vk_ref, Some(328), root)?;
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
    let output_vk = canonical_hex::<328>(
        nested(&plan, &["selected_build", "output", "verification_key"])?,
        "hex328",
    )?;
    need(sha256(&output_vk) == OUTPUT_VK, OfflineError::Binding)?;
    native::checked_vk(&output_vk).map_err(|_| OfflineError::Proof)?;
    let tail = load_ref(
        nested(
            &plan,
            &[
                "selected_build",
                "aggregate_feasibility_only",
                "native_tail",
            ],
        )?,
        None,
        root,
    )?;
    need(!tail.raw.is_empty(), OfflineError::Shape)?;

    let first_value = round_value(&checkpoints[2], 1)?;
    let second_value = round_value(&checkpoints[5], 2)?;
    let first = load_round(&first_value, 1, aggregate_vk, &tail.raw, root)?;
    let second = load_round(&second_value, 2, aggregate_vk, &tail.raw, root)?;
    need(
        first.source.aggregate.proof == [0; 128] && second.source.aggregate.proof == [0; 128],
        OfflineError::Binding,
    )?;
    check_cross_round(&first.source, &second.source).map_err(|_| OfflineError::Binding)?;
    check_graph(&first.source.circuit, &first.w0).map_err(|_| OfflineError::Binding)?;
    check_graph(&second.source.circuit, &second.w0).map_err(|_| OfflineError::Binding)?;
    check_public_close(&first.source, &first.source.circuit.effects)
        .map_err(|_| OfflineError::Relation)?;
    check_public_close(&second.source, &second.source.circuit.effects)
        .map_err(|_| OfflineError::Relation)?;
    check_offline_workload(1, &first.source)?;
    check_offline_workload(2, &second.source)?;
    check_signatures(&first.source.signatures).map_err(|_| OfflineError::Relation)?;
    check_signatures(&second.source.signatures).map_err(|_| OfflineError::Relation)?;
    check_outputs(&first.source, &output_vk).map_err(|_| OfflineError::Proof)?;
    check_outputs(&second.source, &output_vk).map_err(|_| OfflineError::Proof)?;
    Ok((first.source, second.source))
}

// The selected round is a source constant at each fixed entry point. Keeping
// selection private allows a later fixed round-2 entry without ever accepting
// a caller-supplied round selector.
fn prepare<const SELECTED_ROUND: usize>() -> R<PreparedAssignment> {
    need(
        SELECTED_ROUND == 1 || SELECTED_ROUND == 2,
        OfflineError::Binding,
    )?;
    let (first, second) = load_frozen_sources()?;
    let selected = if SELECTED_ROUND == 1 {
        drop(second);
        first
    } else {
        drop(first);
        second
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    let mut assignment_scrubber = ConstraintAssignmentScrubber::new(cs.clone());
    selected
        .circuit
        .clone()
        .generate_internalized(cs.clone())
        .map_err(|_| OfflineError::Relation)?;
    let core_variables = cs.num_variables();
    append_signature_witnesses(cs.clone(), core_variables, &selected.signatures)
        .map_err(|_| OfflineError::Relation)?;
    cs.finalize();
    // Arkworks 0.6 only records predicate rows when matrix construction is
    // enabled. In this assignment-only mode every enforce-constraint path is
    // deliberately skipped, so num_constraints() must be zero. The retained
    // historical matrix contract remains reference evidence; this preparer
    // checks assignment shape, not current constraint rows or satisfaction.
    let no_lc_assignments = cs
        .borrow()
        .is_some_and(|inner| !inner.should_generate_lc_assignments());
    need(
        !cs.should_construct_matrices()
            && no_lc_assignments
            && cs.num_constraints() == 0
            && cs.num_instance_variables() == 3
            && cs.num_variables() == AGGREGATE_VARIABLES
            && cs.num_witness_variables() == AGGREGATE_VARIABLES - 3,
        OfflineError::Relation,
    )?;
    let prepared = {
        let mut inner = cs.borrow_mut().ok_or(OfflineError::Relation)?;
        PreparedAssignment {
            instances: core::mem::take(&mut inner.assignments.instance_assignment),
            witnesses: core::mem::take(&mut inner.assignments.witness_assignment),
        }
    };
    assignment_scrubber.disarm();
    drop(assignment_scrubber);
    drop(cs);
    need(
        prepared.instances.len() == 3 && prepared.witnesses.len() == AGGREGATE_VARIABLES - 3,
        OfflineError::Relation,
    )?;
    validate_public_instances(&prepared.instances, &selected)?;
    Ok(prepared)
}

fn process_status_kib(key: &str) -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key)
                .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
}

fn assignment_receipt<const SELECTED_ROUND: usize>(
    derived_public_inputs_decimal: [String; 2],
    elapsed_seconds: f64,
    peak_rss_kib: Option<u64>,
    current_swap_kib: Option<u64>,
) -> Value {
    let Value::Object(mut receipt) = json!({
        "schema": if SELECTED_ROUND == 1 {
            "kpb-frozen-w1-round1-assignment-preparation/v3"
        } else {
            "kpb-frozen-w1-round2-assignment-preparation/v3"
        },
        "classification": "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_PREPARATION_ONLY",
        "historical_component_run_id": RUN_ID,
        "historical_component_source_instance_epoch_id": EPOCH_ID,
        "historical_component_source_closure_sha256": SOURCE_CLOSURE,
        "historical_component_selected_build_identity_sha256": SELECTED_BUILD,
        "historical_component_plan_sha256": PLAN_SHA256,
        "historical_source_bundle_manifest_sha256": HISTORICAL_MANIFEST_SHA256,
        "selected_round": SELECTED_ROUND,
        "prepared_instances": 3,
        "prepared_witnesses": AGGREGATE_VARIABLES - 3,
        "prepared_variables": AGGREGATE_VARIABLES,
        "historical_component_expected_constraints": AGGREGATE_CONSTRAINTS,
        "current_preparer_observed_constraints": 0,
        "derived_public_inputs_decimal": derived_public_inputs_decimal,
        "elapsed_seconds": elapsed_seconds,
        "peak_rss_kib": peak_rss_kib,
        "current_swap_kib": current_swap_kib,
    }) else {
        unreachable!()
    };
    let Value::Object(controls) = json!({
        "current_preparer_matrix_constructed": false,
        "historical_component_expected_matrix_sha256": AGGREGATE_MATRIX,
        "historical_component_expected_matrix_identity_recomputed": false,
        "historical_component_expected_matrix_rows_materialized": false,
        "current_preparer_assignment_shape_matches_historical_contract": true,
        "current_preparer_constraint_rows_recorded": false,
        "current_preparer_constraint_satisfaction_checked": false,
        "current_preparer_lc_assignments_generated": false,
        "historical_component_seven_checkpoints_and_artifacts_rehashed": true,
        "historical_component_source_members_rehashed": true,
        "rounds_validated": 2,
        "output_proofs_verified": 12,
        "signature_relations_satisfied": 6,
        "aggregate_proof_generated": false,
        "proving_key_opened": false,
        "setup_network_or_funds": false,
        "assignment_serialized": false,
        "assignment_callback_exposed": false,
        "one_shot_process_operation": true,
        "private_local_evidence_only": true,
        "full_secret_zeroization": false,
        "error_path_source_zeroization_complete": false,
        "abort_oom_zeroization": false,
        "core_dump_disabled_by_external_launcher_required": true,
        "current_preparer_source_closure_bound": false,
        "current_preparer_binary_identity_bound": false,
        "assignment_receipt_binds_current_preparer_identity": false,
        "external_launch_receipt_required_for_current_preparer_identity": true,
        "receipt_is_authority": false,
        "public_or_production_authority": false,
        "public_input_selector": false,
        "allocator_abort_can_return_receipt": false,
    }) else {
        unreachable!()
    };
    receipt.extend(controls);
    Value::Object(receipt)
}

fn validate_assignment_receipt<const SELECTED_ROUND: usize>(receipt: &Value) -> R<()> {
    need(
        SELECTED_ROUND == 1 || SELECTED_ROUND == 2,
        OfflineError::Binding,
    )?;
    exact_keys(
        receipt,
        &[
            "abort_oom_zeroization",
            "aggregate_proof_generated",
            "allocator_abort_can_return_receipt",
            "assignment_callback_exposed",
            "assignment_receipt_binds_current_preparer_identity",
            "assignment_serialized",
            "classification",
            "current_preparer_assignment_shape_matches_historical_contract",
            "core_dump_disabled_by_external_launcher_required",
            "current_preparer_binary_identity_bound",
            "current_preparer_constraint_rows_recorded",
            "current_preparer_constraint_satisfaction_checked",
            "current_preparer_lc_assignments_generated",
            "current_preparer_matrix_constructed",
            "current_preparer_observed_constraints",
            "current_preparer_source_closure_bound",
            "current_swap_kib",
            "derived_public_inputs_decimal",
            "elapsed_seconds",
            "error_path_source_zeroization_complete",
            "external_launch_receipt_required_for_current_preparer_identity",
            "full_secret_zeroization",
            "historical_component_expected_matrix_identity_recomputed",
            "historical_component_expected_matrix_rows_materialized",
            "historical_component_expected_matrix_sha256",
            "historical_component_expected_constraints",
            "historical_component_plan_sha256",
            "historical_component_run_id",
            "historical_component_selected_build_identity_sha256",
            "historical_component_seven_checkpoints_and_artifacts_rehashed",
            "historical_component_source_closure_sha256",
            "historical_component_source_instance_epoch_id",
            "historical_component_source_members_rehashed",
            "historical_source_bundle_manifest_sha256",
            "one_shot_process_operation",
            "output_proofs_verified",
            "peak_rss_kib",
            "prepared_instances",
            "prepared_variables",
            "prepared_witnesses",
            "private_local_evidence_only",
            "proving_key_opened",
            "public_input_selector",
            "public_or_production_authority",
            "receipt_is_authority",
            "rounds_validated",
            "schema",
            "selected_round",
            "setup_network_or_funds",
            "signature_relations_satisfied",
        ],
    )?;
    let expected_schema = if SELECTED_ROUND == 1 {
        "kpb-frozen-w1-round1-assignment-preparation/v3"
    } else {
        "kpb-frozen-w1-round2-assignment-preparation/v3"
    };
    let public_inputs = array(receipt, "derived_public_inputs_decimal", 2)?;
    let canonical_public_inputs = public_inputs.iter().all(|value| {
        let Some(decimal) = value.as_str() else {
            return false;
        };
        decimal
            .parse::<Fr>()
            .ok()
            .is_some_and(|field| field.to_string() == decimal)
    });
    let optional_uint =
        |key| at(receipt, key).is_ok_and(|value| value.is_null() || value.as_u64().is_some());
    need(
        text(receipt, "schema")? == expected_schema
            && text(receipt, "classification")?
                == "OFFLINE_SYNTHETIC_UNBACKED_CLEAR_WITNESS_PREPARATION_ONLY"
            && text(receipt, "historical_component_run_id")? == RUN_ID
            && text(receipt, "historical_component_source_instance_epoch_id")? == EPOCH_ID
            && text(receipt, "historical_component_source_closure_sha256")? == SOURCE_CLOSURE
            && text(
                receipt,
                "historical_component_selected_build_identity_sha256",
            )? == SELECTED_BUILD
            && text(receipt, "historical_component_plan_sha256")? == PLAN_SHA256
            && text(receipt, "historical_source_bundle_manifest_sha256")?
                == HISTORICAL_MANIFEST_SHA256
            && text(receipt, "historical_component_expected_matrix_sha256")? == AGGREGATE_MATRIX
            && uint(receipt, "selected_round")? == SELECTED_ROUND as u64
            && uint(receipt, "prepared_instances")? == 3
            && uint(receipt, "prepared_witnesses")? == (AGGREGATE_VARIABLES - 3) as u64
            && uint(receipt, "prepared_variables")? == AGGREGATE_VARIABLES as u64
            && uint(receipt, "historical_component_expected_constraints")?
                == AGGREGATE_CONSTRAINTS as u64
            && uint(receipt, "current_preparer_observed_constraints")? == 0
            && uint(receipt, "rounds_validated")? == 2
            && uint(receipt, "output_proofs_verified")? == 12
            && uint(receipt, "signature_relations_satisfied")? == 6
            && canonical_public_inputs
            && at(receipt, "elapsed_seconds")?
                .as_f64()
                .is_some_and(|value| value.is_finite() && value >= 0.0)
            && optional_uint("peak_rss_kib")
            && optional_uint("current_swap_kib"),
        OfflineError::Binding,
    )?;
    for key in [
        "current_preparer_matrix_constructed",
        "current_preparer_constraint_rows_recorded",
        "current_preparer_constraint_satisfaction_checked",
        "current_preparer_lc_assignments_generated",
        "historical_component_expected_matrix_identity_recomputed",
        "historical_component_expected_matrix_rows_materialized",
        "aggregate_proof_generated",
        "proving_key_opened",
        "setup_network_or_funds",
        "assignment_serialized",
        "assignment_callback_exposed",
        "full_secret_zeroization",
        "error_path_source_zeroization_complete",
        "abort_oom_zeroization",
        "current_preparer_source_closure_bound",
        "current_preparer_binary_identity_bound",
        "assignment_receipt_binds_current_preparer_identity",
        "receipt_is_authority",
        "public_or_production_authority",
        "public_input_selector",
        "allocator_abort_can_return_receipt",
    ] {
        need(
            at(receipt, key)? == &Value::Bool(false),
            OfflineError::Binding,
        )?;
    }
    for key in [
        "current_preparer_assignment_shape_matches_historical_contract",
        "historical_component_seven_checkpoints_and_artifacts_rehashed",
        "historical_component_source_members_rehashed",
        "one_shot_process_operation",
        "private_local_evidence_only",
        "core_dump_disabled_by_external_launcher_required",
        "external_launch_receipt_required_for_current_preparer_identity",
    ] {
        need(
            at(receipt, key)? == &Value::Bool(true),
            OfflineError::Binding,
        )?;
    }
    need(
        receipt.get("source_closure_sha256").is_none()
            && receipt.get("selected_build_identity_sha256").is_none()
            && receipt.get("matrices_constructed").is_none()
            && receipt.get("prepared_constraints").is_none()
            && receipt
                .get("current_preparer_counts_match_historical_contract")
                .is_none()
            && receipt.get("all_source_members_rehashed").is_none()
            && receipt.get("instance_assignment_sha256").is_none()
            && receipt.get("witness_assignment_sha256").is_none()
            && receipt.get("assignment_sha256").is_none()
            && receipt.get("secret_fingerprint").is_none(),
        OfflineError::Binding,
    )
}

#[cfg(target_os = "linux")]
struct PrivateReceiptTarget {
    directory: fs::File,
    parent_path: PathBuf,
    descriptor_path: PathBuf,
    requested_path: PathBuf,
    owner: u32,
}

#[cfg(target_os = "linux")]
fn same_object(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(target_os = "linux")]
fn open_private_receipt_target(receipt_path: &Path) -> R<PrivateReceiptTarget> {
    let parent_path = receipt_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let file_name = receipt_path.file_name().ok_or(OfflineError::Output)?;
    let mut components = Path::new(file_name).components();
    need(
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
        OfflineError::Output,
    )?;

    let owner = fs::metadata("/proc/self")
        .map_err(|_| OfflineError::Output)?
        .uid();
    let before = fs::symlink_metadata(&parent_path).map_err(|_| OfflineError::Output)?;
    need(
        before.file_type().is_dir()
            && !before.file_type().is_symlink()
            && before.uid() == owner
            && before.mode() & 0o777 == 0o700,
        OfflineError::Output,
    )?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    let directory = options
        .open(&parent_path)
        .map_err(|_| OfflineError::Output)?;
    let opened = directory.metadata().map_err(|_| OfflineError::Output)?;
    let after = fs::symlink_metadata(&parent_path).map_err(|_| OfflineError::Output)?;
    need(
        same_file_state(&before, &opened) && same_file_state(&opened, &after),
        OfflineError::Output,
    )?;

    let descriptor_path =
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(file_name);
    for path in [&descriptor_path, receipt_path] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(OfflineError::Output),
        }
    }
    Ok(PrivateReceiptTarget {
        directory,
        parent_path,
        descriptor_path,
        requested_path: receipt_path.to_path_buf(),
        owner,
    })
}

#[cfg(target_os = "linux")]
fn write_private_receipt(target: PrivateReceiptTarget, raw: &[u8]) -> R<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC);
    let mut output = options
        .open(&target.descriptor_path)
        .map_err(|_| OfflineError::Output)?;
    let opened = output.metadata().map_err(|_| OfflineError::Output)?;
    let parent_after_create = target
        .directory
        .metadata()
        .map_err(|_| OfflineError::Output)?;
    need(
        opened.file_type().is_file()
            && opened.uid() == target.owner
            && opened.mode() & 0o777 == 0o400
            && opened.nlink() == 1,
        OfflineError::Output,
    )?;
    output.write_all(raw).map_err(|_| OfflineError::Output)?;
    output.sync_all().map_err(|_| OfflineError::Output)?;

    let final_fd = output.metadata().map_err(|_| OfflineError::Output)?;
    let final_descriptor =
        fs::symlink_metadata(&target.descriptor_path).map_err(|_| OfflineError::Output)?;
    let final_requested =
        fs::symlink_metadata(&target.requested_path).map_err(|_| OfflineError::Output)?;
    need(
        same_object(&opened, &final_fd)
            && same_file_state(&final_fd, &final_descriptor)
            && same_file_state(&final_fd, &final_requested)
            && final_fd.file_type().is_file()
            && final_fd.uid() == target.owner
            && final_fd.mode() & 0o777 == 0o400
            && final_fd.nlink() == 1
            && final_fd.len() == raw.len() as u64,
        OfflineError::Output,
    )?;

    target
        .directory
        .sync_all()
        .map_err(|_| OfflineError::Output)?;
    let final_parent_fd = target
        .directory
        .metadata()
        .map_err(|_| OfflineError::Output)?;
    let final_parent_path =
        fs::symlink_metadata(&target.parent_path).map_err(|_| OfflineError::Output)?;
    need(
        same_file_state(&parent_after_create, &final_parent_fd)
            && same_file_state(&final_parent_fd, &final_parent_path)
            && final_parent_fd.file_type().is_dir()
            && final_parent_fd.uid() == target.owner
            && final_parent_fd.mode() & 0o777 == 0o700,
        OfflineError::Output,
    )
}

fn write_receipt<const SELECTED_ROUND: usize>(receipt_path: &Path) -> R<()> {
    need(
        SELECTED_ROUND == 1 || SELECTED_ROUND == 2,
        OfflineError::Binding,
    )?;
    #[cfg(target_os = "linux")]
    let private_target = open_private_receipt_target(receipt_path)?;
    #[cfg(not(target_os = "linux"))]
    return Err(OfflineError::Output);
    let started = Instant::now();
    let prepared = prepare::<SELECTED_ROUND>()?;
    let public_inputs_decimal = [
        prepared.instances[1].to_string(),
        prepared.instances[2].to_string(),
    ];
    let elapsed_seconds = started.elapsed().as_secs_f64();
    drop(prepared);

    let receipt = assignment_receipt::<SELECTED_ROUND>(
        public_inputs_decimal,
        elapsed_seconds,
        process_status_kib("VmHWM"),
        process_status_kib("VmSwap"),
    );
    validate_assignment_receipt::<SELECTED_ROUND>(&receipt)?;
    let mut raw = serde_json::to_vec(&receipt).map_err(|_| OfflineError::Output)?;
    raw.push(b'\n');
    #[cfg(target_os = "linux")]
    return write_private_receipt(private_target, &raw);
    #[cfg(not(target_os = "linux"))]
    Err(OfflineError::Output)
}

/// Perform the fixed, one-shot, assignment-only measurement and write its
/// create-new mode-0400 receipt. Assignment fields never cross this API. The
/// receipt is private local evidence, never an authority or a public-input
/// selector. No proving key is opened and no proof is generated.
pub fn write_frozen_round1_assignment_receipt(
    receipt_path: &Path,
) -> Result<(), FrozenRound1AssignmentRefused> {
    AVAILABLE
        .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| FrozenRound1AssignmentRefused { _private: () })?;
    write_receipt::<1>(receipt_path).map_err(|_| FrozenRound1AssignmentRefused { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T>(result: R<T>, label: &str) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("{label}"),
        }
    }

    fn plan() -> Value {
        let Ok((value, _)) =
            exact_json(&Path::new(ROOT).join("PLAN.json"), PLAN_BYTES, PLAN_SHA256)
        else {
            panic!("frozen plan")
        };
        value
    }

    #[test]
    fn constraint_assignment_scrubber_clears_error_path_assignments() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let _ = cs.new_input_variable(|| Ok(Fr::from(7_u64))).unwrap();
        let _ = cs.new_witness_variable(|| Ok(Fr::from(11_u64))).unwrap();
        let scrubber = ConstraintAssignmentScrubber::new(cs.clone());
        {
            let assignments = cs.borrow().unwrap();
            assert!(
                assignments
                    .assignments
                    .instance_assignment
                    .iter()
                    .any(|value| *value != Fr::from(0_u64))
            );
            assert!(
                assignments
                    .assignments
                    .witness_assignment
                    .iter()
                    .any(|value| *value != Fr::from(0_u64))
            );
        }
        drop(scrubber);
        let assignments = cs.borrow().unwrap();
        assert!(
            assignments
                .assignments
                .instance_assignment
                .iter()
                .all(|value| *value == Fr::from(0_u64))
        );
        assert!(
            assignments
                .assignments
                .witness_assignment
                .iter()
                .all(|value| *value == Fr::from(0_u64))
        );
    }

    #[test]
    fn retained_owner_key_decimal_strings_parse_without_coercion() {
        let root = Path::new(ROOT);
        let Ok((checkpoint, _)) = exact_json(
            &root.join(CHECKPOINTS[2].directory).join("CHECKPOINT.json"),
            CHECKPOINTS[2].bytes,
            CHECKPOINTS[2].raw_sha256,
        ) else {
            panic!("frozen checkpoint")
        };
        let round = ok(round_value(&checkpoint, 1), "frozen round");
        let context_ref = ok(at(&round, "context"), "frozen context reference");
        let context_leaf = ok(load_ref(context_ref, Some(276), root), "frozen context");
        let context = ok(super::super::context(&context_leaf.raw), "parsed context");
        let owners = ok(array(&round, "owners", 3), "frozen owners");
        let owner_ref = &owners[0];
        let record_ref = ok(at(owner_ref, "record"), "frozen owner record reference");
        let record = ok(load_ref(record_ref, None, root), "frozen owner record");
        let original = ok(unique_json(&record.raw), "parsed owner record");
        let parsed = ok(
            super::super::parse_owner_record(&original, &context, 0),
            "validated owner record",
        );
        let expected = parsed.authorization_key[0];

        for changed_byte in [
            Value::from(expected),
            Value::String(format!("0{expected}")),
            Value::String(format!("+{expected}")),
            Value::String(format!(" {expected}")),
            Value::String("256".into()),
            Value::String(expected.wrapping_add(1).to_string()),
        ] {
            let mut changed = original.clone();
            changed["signature_inputs"]["ownerKeyBytes"][0] = changed_byte;
            assert!(super::super::parse_owner_record(&changed, &context, 0).is_err());
        }
        let mut changed = original;
        changed["signature_inputs"]["ownerKeyBytes"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(super::super::parse_owner_record(&changed, &context, 0).is_err());
    }

    #[test]
    fn frozen_sources_validate_before_assignment_synthesis() {
        match load_frozen_sources() {
            Ok((first, second)) => {
                assert!(check_offline_workload(1, &first).is_ok());
                assert!(check_offline_workload(2, &second).is_ok());
                for signature in first.signatures.iter().chain(second.signatures.iter()) {
                    let fingerprint = auth::join::fingerprint(&signature.matrix)
                        .unwrap_or_else(|_| panic!("canonical signature R1CS fingerprint"));
                    assert_eq!(fingerprint, super::super::super::SIGNATURE_R1CS_FINGERPRINT);
                    assert_ne!(fingerprint, super::super::SIGNATURE_MATRIX_RAW_SHA256);
                }
            }
            Err(error) => panic!(
                "frozen source validation failed: {}",
                match error {
                    OfflineError::Input => "input",
                    OfflineError::Shape => "shape",
                    OfflineError::Binding => "binding",
                    OfflineError::Relation => "relation",
                    OfflineError::Proof => "proof",
                    OfflineError::Output => "output",
                }
            ),
        }
    }

    #[test]
    fn genuine_round1_assignment_preparation_succeeds() {
        match prepare::<1>() {
            Ok(prepared) => {
                assert_eq!(prepared.instances.len(), 3);
                assert_eq!(prepared.witnesses.len(), AGGREGATE_VARIABLES - 3);
            }
            Err(error) => panic!(
                "round-1 assignment preparation failed: {}",
                match error {
                    OfflineError::Input => "input",
                    OfflineError::Shape => "shape",
                    OfflineError::Binding => "binding",
                    OfflineError::Relation => "relation",
                    OfflineError::Proof => "proof",
                    OfflineError::Output => "output",
                }
            ),
        }
    }

    #[test]
    fn genuine_round1_assignment_stage_shape_matches_no_matrix_contract() {
        let (first, second) =
            load_frozen_sources().unwrap_or_else(|_| panic!("load frozen sources"));
        drop(second);
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
            generate_lc_assignments: false,
        });
        assert!(!cs.should_construct_matrices(), "matrix construction mode");
        assert!(
            cs.borrow()
                .is_some_and(|inner| !inner.should_generate_lc_assignments()),
            "linear-combination assignment mode"
        );
        first
            .circuit
            .clone()
            .generate_internalized(cs.clone())
            .unwrap_or_else(|_| panic!("generate internalized core"));
        let core_variables = cs.num_variables();
        append_signature_witnesses(cs.clone(), core_variables, &first.signatures)
            .unwrap_or_else(|_| panic!("append signature witnesses"));
        cs.finalize();
        assert!(
            !cs.should_construct_matrices(),
            "final matrix construction mode"
        );
        assert!(
            cs.borrow()
                .is_some_and(|inner| !inner.should_generate_lc_assignments()),
            "final linear-combination assignment mode"
        );
        assert_eq!(cs.num_instance_variables(), 3, "instance count");
        assert_eq!(cs.num_variables(), AGGREGATE_VARIABLES, "variable count");
        assert_eq!(
            cs.num_witness_variables(),
            AGGREGATE_VARIABLES - 3,
            "witness count"
        );
        assert!(AGGREGATE_CONSTRAINTS > 0, "historical expected constraints");
        assert_eq!(cs.num_constraints(), 0, "matrix-free recorded constraints");
    }

    #[test]
    fn plan_run_source_build_and_network_substitutions_are_rejected() {
        let original = plan();
        assert!(validate_plan_semantics(&original).is_ok());
        let Ok((historical, _)) = exact_json(
            &Path::new(HISTORICAL_SOURCE_ROOT).join("PLAN.json"),
            PLAN_BYTES,
            PLAN_SHA256,
        ) else {
            panic!("sealed historical plan")
        };
        assert_eq!(historical, original);
        assert!(verify_historical_source_bundle(&historical).is_ok());
        for keys in [
            &["run_id"][..],
            &["source_closure_sha256"][..],
            &["selected_build", "build_identity_sha256"][..],
        ] {
            let mut changed = original.clone();
            let mut target = &mut changed;
            for key in &keys[..keys.len() - 1] {
                target = target.get_mut(*key).unwrap();
            }
            target
                .as_object_mut()
                .unwrap()
                .insert(keys[keys.len() - 1].into(), Value::String("0".repeat(64)));
            assert!(validate_plan_semantics(&changed).is_err());
        }
        let mut changed = original;
        changed["boundaries"]["network_enabled"] = Value::Bool(true);
        assert!(validate_plan_semantics(&changed).is_err());
    }

    #[test]
    fn checkpoint_stage_run_and_previous_substitutions_are_rejected() {
        let root = Path::new(ROOT);
        let Ok((original, _)) = exact_json(
            &root.join(CHECKPOINTS[2].directory).join("CHECKPOINT.json"),
            CHECKPOINTS[2].bytes,
            CHECKPOINTS[2].raw_sha256,
        ) else {
            panic!("frozen checkpoint")
        };
        assert!(validate_checkpoint_semantics(&original, 2).is_ok());
        for (key, value) in [
            ("stage", Value::String("round-2-components".into())),
            (
                "run_id",
                Value::String("00000000-0000-4000-8000-000000000000".into()),
            ),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(validate_checkpoint_semantics(&changed, 2).is_err());
        }
        let mut changed = original;
        changed["previous"]["sha256"] = Value::String("0".repeat(64));
        assert!(validate_checkpoint_semantics(&changed, 2).is_err());
    }

    #[test]
    fn artifact_path_hash_and_size_substitutions_are_rejected() {
        let document = plan();
        let Ok(original) = at(&document, "profile").cloned() else {
            panic!("frozen profile reference")
        };
        assert!(verify_ref_streamed(&original, Path::new(ROOT)).is_ok());

        let mut changed = original.clone();
        changed["path"] = Value::String("../PLAN.json".into());
        assert!(verify_ref_streamed(&changed, Path::new(ROOT)).is_err());

        let mut changed = original.clone();
        changed["sha256"] = Value::String("0".repeat(64));
        assert!(verify_ref_streamed(&changed, Path::new(ROOT)).is_err());

        let mut changed = original;
        changed["bytes"] = Value::from(changed["bytes"].as_u64().unwrap() + 1);
        assert!(verify_ref_streamed(&changed, Path::new(ROOT)).is_err());
    }

    #[test]
    fn round_substitution_and_non_frozen_selection_are_rejected() {
        let root = Path::new(ROOT);
        let Ok((checkpoint, _)) = exact_json(
            &root.join(CHECKPOINTS[2].directory).join("CHECKPOINT.json"),
            CHECKPOINTS[2].bytes,
            CHECKPOINTS[2].raw_sha256,
        ) else {
            panic!("frozen checkpoint")
        };
        let Ok(mut changed) = round_value(&checkpoint, 1) else {
            panic!("frozen round reference")
        };
        changed["round"] = Value::from(2);
        assert!(load_round(&changed, 1, [0; 328], &[], root).is_err());
        assert!(prepare::<3>().is_err());
    }

    #[test]
    fn public_inputs_are_derived_from_effects() {
        let expected = [Fr::from(7u64), Fr::from(11u64)];
        assert!(
            validate_public_instance_values(&[Fr::ONE, expected[0], expected[1]], expected).is_ok()
        );
        assert!(
            validate_public_instance_values(
                &[Fr::ONE, expected[0] + Fr::ONE, expected[1]],
                expected
            )
            .is_err()
        );
    }

    #[test]
    fn hostile_receipt_identity_and_matrix_claims_are_rejected() {
        let original = assignment_receipt::<1>(["7".into(), "11".into()], 1.0, Some(1), Some(0));
        assert!(validate_assignment_receipt::<1>(&original).is_ok());
        assert!(original.get("source_closure_sha256").is_none());
        assert!(original.get("selected_build_identity_sha256").is_none());
        for (key, value) in [
            (
                "historical_component_source_closure_sha256",
                Value::String("0".repeat(64)),
            ),
            (
                "historical_component_selected_build_identity_sha256",
                Value::String("0".repeat(64)),
            ),
            (
                "historical_component_expected_matrix_sha256",
                Value::String("0".repeat(64)),
            ),
            (
                "historical_component_expected_matrix_identity_recomputed",
                Value::Bool(true),
            ),
            ("current_preparer_source_closure_bound", Value::Bool(true)),
            ("current_preparer_binary_identity_bound", Value::Bool(true)),
            ("full_secret_zeroization", Value::Bool(true)),
            ("error_path_source_zeroization_complete", Value::Bool(true)),
            ("abort_oom_zeroization", Value::Bool(true)),
            (
                "core_dump_disabled_by_external_launcher_required",
                Value::Bool(false),
            ),
            ("private_local_evidence_only", Value::Bool(false)),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(validate_assignment_receipt::<1>(&changed).is_err());
        }
        let mut changed = original.clone();
        changed["source_closure_sha256"] = Value::String(SOURCE_CLOSURE.into());
        assert!(validate_assignment_receipt::<1>(&changed).is_err());

        let mut changed = original.clone();
        changed["derived_public_inputs_decimal"][0] = Value::String("07".into());
        assert!(validate_assignment_receipt::<1>(&changed).is_err());

        let mut changed = original.clone();
        changed["unexpected_secret_fingerprint_v2"] = Value::String("0".repeat(64));
        assert!(validate_assignment_receipt::<1>(&changed).is_err());

        let mut changed = original.clone();
        changed.as_object_mut().unwrap().remove("schema");
        assert!(validate_assignment_receipt::<1>(&changed).is_err());

        for key in [
            "instance_assignment_sha256",
            "witness_assignment_sha256",
            "assignment_sha256",
            "secret_fingerprint",
        ] {
            let mut changed =
                assignment_receipt::<1>(["7".into(), "11".into()], 1.0, Some(1), Some(0));
            changed[key] = Value::String("0".repeat(64));
            assert!(validate_assignment_receipt::<1>(&changed).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_output_requires_private_parent_and_seals_exact_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let mut attempt = 0_u64;
        let base = loop {
            let candidate = std::env::temp_dir().join(format!(
                "kpb-frozen-w1-receipt-test-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => attempt += 1,
                Err(_) => panic!("create private receipt test root"),
            }
        };
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("seal private receipt test root"));
        let private = base.join("private");
        fs::create_dir(&private).unwrap_or_else(|_| panic!("create private receipt parent"));
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("seal private receipt parent"));
        let receipt = private.join("RECEIPT.json");
        let target = open_private_receipt_target(&receipt)
            .unwrap_or_else(|_| panic!("open private receipt target"));
        let raw = b"{\"private_local_evidence_only\":true}\n";
        write_private_receipt(target, raw).unwrap_or_else(|_| panic!("write private receipt"));
        let metadata =
            fs::symlink_metadata(&receipt).unwrap_or_else(|_| panic!("inspect private receipt"));
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o400);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), raw.len() as u64);
        assert!(open_private_receipt_target(&receipt).is_err());

        let symlink_leaf = private.join("SYMLINK.json");
        symlink(&receipt, &symlink_leaf)
            .unwrap_or_else(|_| panic!("create receipt leaf symlink control"));
        assert!(open_private_receipt_target(&symlink_leaf).is_err());
        assert!(open_private_receipt_target(&private.join("nested").join("RECEIPT.json")).is_err());

        let public = base.join("public");
        fs::create_dir(&public).unwrap_or_else(|_| panic!("create public receipt parent"));
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|_| panic!("set public receipt parent mode"));
        assert!(open_private_receipt_target(&public.join("RECEIPT.json")).is_err());

        let linked = base.join("linked-private");
        symlink(&private, &linked).unwrap_or_else(|_| panic!("create parent symlink control"));
        assert!(open_private_receipt_target(&linked.join("OTHER.json")).is_err());

        let substituted = base.join("substituted");
        let moved = base.join("substituted-original");
        fs::create_dir(&substituted)
            .unwrap_or_else(|_| panic!("create substitution receipt parent"));
        fs::set_permissions(&substituted, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("seal substitution receipt parent"));
        let substituted_receipt = substituted.join("RECEIPT.json");
        let substituted_target = open_private_receipt_target(&substituted_receipt)
            .unwrap_or_else(|_| panic!("open substitution receipt target"));
        fs::rename(&substituted, &moved)
            .unwrap_or_else(|_| panic!("move substitution receipt parent"));
        fs::create_dir(&substituted)
            .unwrap_or_else(|_| panic!("replace substitution receipt parent"));
        fs::set_permissions(&substituted, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("seal replacement receipt parent"));
        assert!(write_private_receipt(substituted_target, raw).is_err());
        let moved_receipt = moved.join("RECEIPT.json");
        let moved_metadata = fs::symlink_metadata(&moved_receipt)
            .unwrap_or_else(|_| panic!("inspect refused substituted receipt"));
        assert_eq!(moved_metadata.mode() & 0o777, 0o400);
        assert_eq!(moved_metadata.nlink(), 1);

        fs::remove_file(&linked).unwrap_or_else(|_| panic!("remove parent symlink control"));
        fs::remove_file(&symlink_leaf)
            .unwrap_or_else(|_| panic!("remove receipt leaf symlink control"));
        fs::remove_file(&receipt).unwrap_or_else(|_| panic!("remove private receipt"));
        fs::remove_file(&moved_receipt)
            .unwrap_or_else(|_| panic!("remove refused substituted receipt"));
        fs::remove_dir(&moved)
            .unwrap_or_else(|_| panic!("remove original substitution receipt parent"));
        fs::remove_dir(&substituted)
            .unwrap_or_else(|_| panic!("remove replacement receipt parent"));
        fs::remove_dir(&private).unwrap_or_else(|_| panic!("remove private receipt parent"));
        fs::remove_dir(&public).unwrap_or_else(|_| panic!("remove public receipt parent"));
        fs::remove_dir(&base).unwrap_or_else(|_| panic!("remove private receipt test root"));
    }
}
