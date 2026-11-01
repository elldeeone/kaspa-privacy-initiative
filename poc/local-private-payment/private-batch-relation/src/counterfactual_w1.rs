//! Source-owned verification of the fixed two-round W1 graph rewire.
//!
//! This module accepts complete private round witnesses, reconstructs the
//! current aggregate and Output constraint systems, checks every assignment,
//! checks the exact matrix identities, verifies all twelve Output proofs and
//! both aggregate proofs, and closes the relation's public CM/NF/context
//! descendants.  It also consumes opaque selected-W0, authenticated-C1 and
//! accepted-public-lineage authorities.  Raw arrays and caller-selected
//! descriptors cannot mint those authorities.  It returns only an opaque
//! capability and is deliberately not connected to a runtime, MPC input path,
//! receipt, digest, boolean, or public serializer.
//!
//! The source object is allowed only inside a future selected one-shot private
//! process.  It is not a clear-witness MPC dealer and must never be added to the
//! public setup/export paths.

#[cfg(feature = "offline-w1-verifier")]
pub mod offline_verifier;

use crate::{
    BatchCircuit, EFFECT_BYTES, H, OUTPUTS, OWNERS, Profile, joined_source::canonical_terms,
};
use ark_bn254::{Bn254, Fr};
use ark_ff::{AdditiveGroup, Field};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, LinearCombination, OptimizationGoal,
    R1CS_PREDICATE_LABEL, SynthesisError, Variable,
};
use auth::join::R1cs;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const ROUNDS: usize = 2;
const SIGNATURE_VARIABLES: usize = 10_049;
const SIGNATURE_CONSTRAINTS: usize = 10_065;
const AGGREGATE_VARIABLES: usize = 12_949_821;
const AGGREGATE_CONSTRAINTS: usize = 13_093_029;
const OUTPUT_VARIABLES: usize = 215_001;
const OUTPUT_CONSTRAINTS: usize = 217_807;

// These are intentionally separate identity domains. The normalized JSON
// artifact digest is not the canonical in-memory R1CS fingerprint.
const SIGNATURE_MATRIX_RAW_SHA256: &str =
    "b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11";
const SIGNATURE_R1CS_FINGERPRINT: &str =
    "bbebbd002ea7f8fcd5ec44b8faf1a6540920696346f1765ec782bc93df5611cd";
const AGGREGATE_MATRIX: &str = "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab";
const OUTPUT_MATRIX: &str = "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31";
const AGGREGATE_VK: &str = "2ca01e24f64b764e0470e67ff4fe183ed9e6d4a2d0b17e77887499c7ed0de102";
const OUTPUT_VK: &str = "8d5738e3726611b07bedec944dc26d8458b728a7d18c1fecf2ad6638aa1cd119";

const FEE: u64 = 7_000_000;
const ROUND1_INPUT: u64 = 2_000_000_000;
const ROUND1_PAYMENT: u64 = 500_000_000;
const ROUND1_CHANGE: u64 = 1_493_000_000;
const ROUND2_HONEST_INPUT: u64 = 500_000_000;
const ROUND2_COLLUDER_INPUT: u64 = 1_493_000_000;
const ROUND2_PAYMENT: u64 = 200_000_000;
const ROUND2_HONEST_CHANGE: u64 = 293_000_000;
const ROUND2_COLLUDER_CHANGE: u64 = 1_286_000_000;

/// Internal refusal classes.  They are collapsed to one opaque public refusal
/// so a future caller cannot use the verifier as a private-witness oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckError {
    Source,
    Graph,
    Workload,
    CrossRound,
    PublicClose,
    OutputRelation,
    OutputProof,
    SignatureRelation,
    AggregateRelation,
    AggregateProof,
}

type CheckResult<T> = core::result::Result<T, CheckError>;

/// The only public failure shape.  It intentionally carries no category,
/// value, key, graph, digest, row, proof, mapping, boolean, Debug or Display.
pub struct FullW1Refused {
    _private: (),
}

/// Complete selected signature component.  Matrix and assignment stay inside
/// the source process; neither type implements Debug or Serialize.
pub struct SignatureWitnessSource {
    matrix: R1cs,
    assignment: Vec<Fr>,
}

impl SignatureWitnessSource {
    fn new(matrix: R1cs, assignment: Vec<Fr>) -> Self {
        Self { matrix, assignment }
    }
}

impl Drop for SignatureWitnessSource {
    fn drop(&mut self) {
        self.assignment.zeroize();
    }
}

/// Public invoice descriptor fields needed to check the fixed recipient and
/// change topology.  The descriptor is consumed inside the private source and
/// is never exposed by the resulting authority.
pub struct RecipientDescriptor {
    owner: H,
    incoming: H,
    key_commitment: H,
    native_pk: H,
}

impl RecipientDescriptor {
    fn new(owner: H, incoming: H, key_commitment: H, native_pk: H) -> Self {
        Self {
            owner,
            incoming,
            key_commitment,
            native_pk,
        }
    }
}

/// Per-round invoice descriptors. `payment[recipient]` is the authenticated
/// incoming-payment invoice and `change[owner]` is that owner's change invoice.
pub struct RoundRecipientSource {
    payment: [RecipientDescriptor; OWNERS],
    change: [RecipientDescriptor; OWNERS],
}

impl RoundRecipientSource {
    fn new(payment: [RecipientDescriptor; OWNERS], change: [RecipientDescriptor; OWNERS]) -> Self {
        Self { payment, change }
    }
}

/// Private W0 owner-to-public-slot graph used only to apply the precommitted
/// coupling rule.  Values are destinations in the sorted public arrays.
pub struct W0PhysicalGraph {
    input: [usize; OWNERS],
    payment: [usize; OWNERS],
    change: [usize; OWNERS],
}

impl W0PhysicalGraph {
    fn new(input: [usize; OWNERS], payment: [usize; OWNERS], change: [usize; OWNERS]) -> Self {
        Self {
            input,
            payment,
            change,
        }
    }
}

/// Exact selected Groth16 proof bytes.  Verification keys are supplied as
/// complete canonical bytes and must match the frozen research key identities.
pub struct SelectedAggregateProof {
    verification_key: [u8; 328],
    proof: [u8; 128],
}

impl SelectedAggregateProof {
    fn new(verification_key: [u8; 328], proof: [u8; 128]) -> Self {
        Self {
            verification_key,
            proof,
        }
    }
}

/// One complete W1 round.  The `BatchCircuit` contains the real private native
/// witness and public effects; signature sources contain all three real EdDSA
/// assignments.  No field is publicly readable after construction.
pub struct FullW1RoundSource {
    circuit: BatchCircuit,
    signatures: [SignatureWitnessSource; OWNERS],
    aggregate: SelectedAggregateProof,
}

impl FullW1RoundSource {
    fn new(
        circuit: BatchCircuit,
        signatures: [SignatureWitnessSource; OWNERS],
        aggregate: SelectedAggregateProof,
    ) -> Self {
        Self {
            circuit,
            signatures,
            aggregate,
        }
    }
}

impl Drop for FullW1RoundSource {
    fn drop(&mut self) {
        self.aggregate.verification_key.zeroize();
        self.aggregate.proof.zeroize();
    }
}

/// Complete two-round source plus the selected Output verification key.  It is
/// intentionally move-only (no Clone) and has no getters.
pub struct FullW1WitnessSource {
    rounds: [FullW1RoundSource; ROUNDS],
    output_verification_key: [u8; 328],
}

impl FullW1WitnessSource {
    fn new(rounds: [FullW1RoundSource; ROUNDS], output_verification_key: [u8; 328]) -> Self {
        Self {
            rounds,
            output_verification_key,
        }
    }
}

/// One source-owned instance created by an atomic future fanout from the sole
/// live W0/C1/accepted-lineage join.  These identities never leave opaque
/// capabilities and cannot be supplied as a public digest receipt.
struct SourceInstance {
    epoch: H,
    accepted_history: H,
    effects: [H; ROUNDS],
}

/// Opaque selected-W0 truth.  There is intentionally no public constructor,
/// graph getter, serializer or raw-array overload.  A future selected source
/// owner must mint it from the live post-barrier truth residual.
pub struct SelectedW0TruthAuthority {
    rounds: [W0PhysicalGraph; ROUNDS],
}

struct C1CreatedOutputFact {
    tuple_sha256: H,
    value: u64,
}

struct C1OriginalFact {
    source_operation: H,
    input_nf: H,
    input_value: u64,
    created: [C1CreatedOutputFact; 2],
}

struct C1InvoiceFact {
    source_operation: H,
    invoice_operation: H,
    source_owner: usize,
    target_owner: usize,
    value: u64,
}

struct C1ReceiptFact {
    source_operation: H,
    receipt_index: u32,
    creator_owner: usize,
    tuple_sha256: H,
    cm: H,
    value: u64,
}

struct C1RetryFact {
    attempt: H,
    outcome: u8,
}

struct AuthenticatedC1RoundFact {
    capture_attempt: H,
    contact_value_authority: H,
    stage_operations: [H; 3],
    stage_configs: [H; 3],
    contact_owners: [usize; 3],
    original: C1OriginalFact,
    invoices: [C1InvoiceFact; 2],
    receipts: [C1ReceiptFact; 2],
    incoming_key_commitment: H,
    incoming_ciphertext: [u8; 264],
    retry_history_closed: bool,
    retries: Vec<C1RetryFact>,
    artifact: H,
    round_attempt: H,
    capture_plan: H,
    projection: H,
    stage_plan: H,
    route_manifest: H,
    route_source: H,
    process: H,
    child_exit: H,
}

/// Opaque authenticated C1 facts. The private descriptors plus exact
/// operation, attempt, invoice index, creator, contact, key, ciphertext,
/// decrypted-CM and value facts must come from the live C1 residual;
/// caller-provided descriptors are not an authority and there is intentionally
/// no public constructor.
pub struct AuthenticatedC1ResidualAuthority {
    recipients: [RoundRecipientSource; ROUNDS],
    rounds: [AuthenticatedC1RoundFact; ROUNDS],
}

/// Opaque accepted starting lineage plus exact counterfactual public effects.
/// A future Close owner must authenticate the selected accepted head/history
/// and all runtime descendants before minting the corresponding C++ closure.
/// This Rust authority only binds the exact relation effects and their public
/// round-to-round state lineage; it does not replace runtime Close.
pub struct AcceptedPublicLineageAuthority {
    accepted_history_identity: H,
    accepted_initial_context: crate::Context,
    counterfactual_effects: [crate::Effects; ROUNDS],
}

/// Sole input to the public verification bridge.  Its fields and constructor
/// are private so independently reconstructed arms with merely equal bytes
/// cannot be joined.  A future source owner must atomically derive this one
/// move-only instance from consumed live W0 truth, C1 and accepted-lineage
/// authorities before observation/truth is released elsewhere.
pub struct FullW1SourceInstanceAuthority {
    instance: SourceInstance,
    witness: FullW1WitnessSource,
    selected_w0: SelectedW0TruthAuthority,
    authenticated_c1: AuthenticatedC1ResidualAuthority,
    accepted_lineage: AcceptedPublicLineageAuthority,
}

/// Opaque successful closure.  It has no Clone, Debug, Serialize, receipt,
/// digest, boolean, value, key, graph or candidate accessor.
#[must_use]
pub struct FullW1WitnessClosure {
    instance: SourceInstance,
}

/// Crate-private verifier entry used only by the separate pinned typed bridge.
/// Keeping this non-public prevents a second minting surface from bypassing
/// the bridge's exact owned input/output contract.
pub(crate) fn verify_pinned_source(
    source_instance: FullW1SourceInstanceAuthority,
) -> core::result::Result<FullW1WitnessClosure, FullW1Refused> {
    let instance = verify_source(source_instance).map_err(|_| FullW1Refused { _private: () })?;
    Ok(FullW1WitnessClosure { instance })
}

#[derive(Clone, Copy)]
struct Graph {
    input: [usize; OWNERS],
    payment: [usize; OWNERS],
    change: [usize; OWNERS],
}

fn sha256_bytes(bytes: &[u8]) -> H {
    Sha256::digest(bytes).into()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha256_bytes(bytes))
}

fn permutation<const N: usize>(values: &[usize; N]) -> bool {
    let mut seen = [false; N];
    for &value in values {
        if value >= N || seen[value] {
            return false;
        }
        seen[value] = true;
    }
    true
}

fn graph(w0: &W0PhysicalGraph) -> CheckResult<(Graph, Graph)> {
    if !permutation(&w0.input) {
        return Err(CheckError::Graph);
    }
    let mut seen = [false; OUTPUTS];
    for owner in 0..OWNERS {
        let p = w0.payment[owner];
        let c = w0.change[owner];
        if p >= OUTPUTS || c >= OUTPUTS || p == c || seen[p] || seen[c] {
            return Err(CheckError::Graph);
        }
        seen[p] = true;
        seen[c] = true;
    }
    if !seen.into_iter().all(|value| value) {
        return Err(CheckError::Graph);
    }
    let original = Graph {
        input: w0.input,
        payment: w0.payment,
        change: w0.change,
    };
    let mut target = original;
    target.input.swap(0, 2);
    target.change.swap(0, 2);
    Ok((original, target))
}

fn pair_for_input(value: &Graph, slot: usize) -> CheckResult<(usize, usize)> {
    let owner = value
        .input
        .iter()
        .position(|candidate| *candidate == slot)
        .ok_or(CheckError::Graph)?;
    Ok((value.payment[owner], value.change[owner]))
}

fn check_different_pair(original: &Graph, target: &Graph) -> CheckResult<()> {
    for owner in [0usize, 2] {
        let slot = original.input[owner];
        if pair_for_input(original, slot)? == pair_for_input(target, slot)? {
            return Err(CheckError::Graph);
        }
    }
    // Owner 1 and every creator-indexed payment edge are fixed.  Round-specific
    // C1-created/C1-received payment facts are checked by recipient topology.
    if target.input[1] != original.input[1]
        || target.change[1] != original.change[1]
        || target.payment != original.payment
    {
        return Err(CheckError::Graph);
    }
    Ok(())
}

fn one_hot_destination<const N: usize>(row: &[Fr; N]) -> CheckResult<usize> {
    let mut found = None;
    for (index, value) in row.iter().enumerate() {
        if *value == Fr::ONE {
            if found.replace(index).is_some() {
                return Err(CheckError::Graph);
            }
        } else if *value != Fr::ZERO {
            return Err(CheckError::Graph);
        }
    }
    found.ok_or(CheckError::Graph)
}

fn check_graph(circuit: &BatchCircuit, w0: &W0PhysicalGraph) -> CheckResult<()> {
    let (original, target) = graph(w0)?;
    check_different_pair(&original, &target)?;
    for owner in 0..OWNERS {
        if one_hot_destination(&circuit.witness.input_permutation[owner])? != target.input[owner]
            || one_hot_destination(&circuit.witness.output_permutation[2 * owner])?
                != target.payment[owner]
            || one_hot_destination(&circuit.witness.output_permutation[2 * owner + 1])?
                != target.change[owner]
        {
            return Err(CheckError::Graph);
        }
    }
    Ok(())
}

fn descriptor_matches(note: &crate::Note, descriptor: &RecipientDescriptor) -> bool {
    note.owner == descriptor.owner
        && note.incoming == descriptor.incoming
        && note.key_commitment == descriptor.key_commitment
        && note.native_pk == descriptor.native_pk
}

fn check_round_workload(
    round: usize,
    source: &FullW1RoundSource,
    recipients: &RoundRecipientSource,
    c1: &AuthenticatedC1RoundFact,
) -> CheckResult<()> {
    let owners = &source.circuit.witness.owners;
    let (inputs, payments, changes) = if round == 0 {
        (
            [ROUND1_INPUT; OWNERS],
            [ROUND1_PAYMENT; OWNERS],
            [ROUND1_CHANGE; OWNERS],
        )
    } else {
        (
            [
                ROUND2_HONEST_INPUT,
                ROUND2_COLLUDER_INPUT,
                ROUND2_HONEST_INPUT,
            ],
            [ROUND2_PAYMENT; OWNERS],
            [
                ROUND2_HONEST_CHANGE,
                ROUND2_COLLUDER_CHANGE,
                ROUND2_HONEST_CHANGE,
            ],
        )
    };
    let offset = if round == 0 { 1 } else { 2 };
    for owner in 0..OWNERS {
        let value = &owners[owner];
        if value.note.value != inputs[owner]
            || value.outputs[0].note.value != payments[owner]
            || value.outputs[1].note.value != changes[owner]
            || value.fee_sompi != FEE
            || value
                .note
                .value
                .checked_sub(value.outputs[0].note.value)
                .and_then(|rest| rest.checked_sub(value.outputs[1].note.value))
                != Some(FEE)
            || !descriptor_matches(
                &value.outputs[0].note,
                &recipients.payment[(owner + offset) % OWNERS],
            )
            || !descriptor_matches(&value.outputs[1].note, &recipients.change[owner])
        {
            return Err(CheckError::Workload);
        }
    }
    // C1 is owner 1. Bind its complete frozen direct view, not only the
    // incoming payment edge: three distinct stages/operations, its Original,
    // both invoices, both decrypted receipts, both created outputs and an
    // explicitly closed empty retry history for this fixed workload.
    let creator = if round == 0 { 0 } else { 2 };
    let outgoing = if round == 0 { 2 } else { 0 };
    let operations = &c1.stage_operations;
    let configurations = &c1.stage_configs;
    let all_distinct_nonzero = |values: &[H]| {
        values.iter().all(|value| *value != [0; 32])
            && (0..values.len())
                .all(|index| values[..index].iter().all(|value| *value != values[index]))
    };
    let lineage = [
        c1.artifact,
        c1.round_attempt,
        c1.capture_plan,
        c1.projection,
        c1.stage_plan,
        c1.route_manifest,
        c1.route_source,
        c1.process,
        c1.child_exit,
    ];
    let incoming_output = &owners[creator].outputs[0];
    let c1_owner = &owners[1];
    let c1_payment = &c1_owner.outputs[0];
    let c1_change = &c1_owner.outputs[1];
    let incoming_tuple_hash = sha256_bytes(&incoming_output.tuple);
    let c1_payment_tuple_hash = sha256_bytes(&c1_payment.tuple);
    let c1_change_tuple_hash = sha256_bytes(&c1_change.tuple);
    let incoming_cm = incoming_output
        .note
        .commitment(&source.circuit.profile.domain);
    let change_cm = c1_change.note.commitment(&source.circuit.profile.domain);
    let issued = &c1.invoices[0];
    let accepted = &c1.invoices[1];
    let incoming = &c1.receipts[0];
    let change = &c1.receipts[1];
    let retry_rows_valid = c1
        .retries
        .iter()
        .all(|retry| retry.attempt != [0; 32] && (1..=3).contains(&retry.outcome));
    if c1.capture_attempt == [0; 32]
        || c1.contact_value_authority == [0; 32]
        || !all_distinct_nonzero(operations)
        || !all_distinct_nonzero(configurations)
        || !lineage.iter().all(|value| *value != [0; 32])
        || c1.contact_owners != [creator, outgoing, creator]
        || !c1.retry_history_closed
        || !retry_rows_valid
        || !c1.retries.is_empty()
        || c1.original.source_operation != operations[1]
        || c1.original.input_nf != c1_owner.input_nf
        || c1.original.input_value != c1_owner.note.value
        || c1.original.created[0].tuple_sha256 != c1_payment_tuple_hash
        || c1.original.created[0].value != c1_payment.note.value
        || c1.original.created[1].tuple_sha256 != c1_change_tuple_hash
        || c1.original.created[1].value != c1_change.note.value
        || issued.source_operation != operations[0]
        || issued.invoice_operation != operations[0]
        || issued.source_owner != creator
        || issued.target_owner != 1
        || issued.value != incoming_output.note.value
        || accepted.source_operation != operations[1]
        || accepted.invoice_operation != operations[0]
        || accepted.source_owner != 1
        || accepted.target_owner != outgoing
        || accepted.value != c1_payment.note.value
        || incoming.source_operation != operations[2]
        || incoming.receipt_index != (2 * round + 1) as u32
        || incoming.creator_owner != creator
        || incoming.tuple_sha256 != incoming_tuple_hash
        || incoming.cm != incoming_output.tuple[..32]
        || incoming.cm != incoming_cm
        || incoming.value != incoming_output.note.value
        || change.source_operation != operations[2]
        || change.receipt_index != (2 * round + 2) as u32
        || change.creator_owner != 1
        || change.tuple_sha256 != c1_change_tuple_hash
        || change.cm != c1_change.tuple[..32]
        || change.cm != change_cm
        || change.value != c1_change.note.value
        || c1.incoming_key_commitment != recipients.payment[1].key_commitment
        || c1.incoming_ciphertext.as_slice() != &incoming_output.tuple[96..360]
        || !descriptor_matches(&incoming_output.note, &recipients.payment[1])
        || source.circuit.effects.total_fee != FEE * OWNERS as u64
    {
        return Err(CheckError::Workload);
    }
    Ok(())
}

fn selected_output<'a>(
    round1: &'a FullW1RoundSource,
    round2_owner: usize,
) -> &'a crate::OutputWitness {
    match round2_owner {
        // Round-1 offset1: owner0 received creator2's payment; owner1 spends
        // its own change; owner2 received creator1's payment.
        0 => &round1.circuit.witness.owners[2].outputs[0],
        1 => &round1.circuit.witness.owners[1].outputs[1],
        2 => &round1.circuit.witness.owners[1].outputs[0],
        _ => unreachable!("fixed owner count"),
    }
}

fn check_cross_round(round1: &FullW1RoundSource, round2: &FullW1RoundSource) -> CheckResult<()> {
    let first = &round1.circuit.effects;
    let second = &round2.circuit.effects.context;
    if round1.circuit.profile != round2.circuit.profile
        || second.profile != round1.circuit.profile
        || second.old_cm_root != first.new_cm_root
        || second.old_nf_root != first.new_nf_root
        || second.old_cm_count != first.new_cm_count
        || second.old_nf_count != first.new_nf_count
        || second.old_reserve != first.new_reserve
        || second.reserve_outpoint[..32] == [0; 32]
        || second.reserve_outpoint == first.context.reserve_outpoint
    {
        return Err(CheckError::CrossRound);
    }
    for owner in 0..OWNERS {
        let selected = selected_output(round1, owner);
        let input = &round2.circuit.witness.owners[owner];
        // The lifecycle deliberately rerandomizes the spent input CV, so its
        // blinding/CV must not equal the creating Output CV.  Exact note/CM
        // equality plus the round-2 membership and value-CV constraints are
        // the source-valid cross-round selection check.
        if input.note != selected.note
            || input
                .note
                .commitment(&round2.circuit.profile.domain)
                .as_slice()
                != &selected.tuple[..32]
        {
            return Err(CheckError::CrossRound);
        }
    }
    Ok(())
}

fn check_public_close(source: &FullW1RoundSource, expected: &crate::Effects) -> CheckResult<()> {
    let effects = &source.circuit.effects;
    effects
        .validate_public_fields(&effects.context, &source.circuit.profile)
        .map_err(|_| CheckError::PublicClose)?;
    if effects.bytes().len() != EFFECT_BYTES
        || effects.bytes() != expected.bytes()
        || effects.context.profile != source.circuit.profile
    {
        return Err(CheckError::PublicClose);
    }
    Ok(())
}

fn r1cs_satisfied(matrix: &R1cs, assignment: &[Fr]) -> bool {
    if matrix.validate().is_err()
        || matrix.variables().ok() != Some(assignment.len())
        || assignment.first() != Some(&Fr::ONE)
    {
        return false;
    }
    let dot = |row: &auth::join::Row| {
        row.iter().fold(Fr::ZERO, |sum, (coefficient, index)| {
            sum + *coefficient * assignment[*index]
        })
    };
    (0..matrix.constraints()).all(|row| {
        dot(&matrix.matrices[0][row]) * dot(&matrix.matrices[1][row])
            == dot(&matrix.matrices[2][row])
    })
}

fn check_signatures(signatures: &[SignatureWitnessSource; OWNERS]) -> CheckResult<()> {
    for signature in signatures {
        if signature.matrix.instances != 67
            || signature.matrix.variables().ok() != Some(SIGNATURE_VARIABLES)
            || signature.matrix.constraints() != SIGNATURE_CONSTRAINTS
            || auth::join::fingerprint(&signature.matrix).ok().as_deref()
                != Some(SIGNATURE_R1CS_FINGERPRINT)
            || !r1cs_satisfied(&signature.matrix, &signature.assignment)
        {
            return Err(CheckError::SignatureRelation);
        }
    }
    Ok(())
}

fn append_signature_witnesses(
    cs: ConstraintSystemRef<Fr>,
    core_variables: usize,
    signatures: &[SignatureWitnessSource; OWNERS],
) -> core::result::Result<(), SynthesisError> {
    if cs.num_instance_variables() != 3 || cs.num_variables() != core_variables {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut starts = [0usize; OWNERS];
    for (owner, signature) in signatures.iter().enumerate() {
        signature
            .matrix
            .validate()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        let variables = signature
            .matrix
            .variables()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        if signature.matrix.instances != 67
            || signature.assignment.len() != variables
            || signature.assignment.first() != Some(&Fr::ONE)
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        starts[owner] = cs.num_variables();
        let mut columns = Vec::with_capacity(variables);
        columns.push(Variable::One);
        for value in &signature.assignment[1..] {
            columns.push(cs.new_witness_variable(|| Ok(*value))?);
        }
        for row in 0..signature.matrix.constraints() {
            let mut axes = Vec::with_capacity(3);
            for matrix in &signature.matrix.matrices {
                let terms = canonical_terms(&matrix[row])?;
                axes.push(LinearCombination(
                    terms
                        .iter()
                        .map(|(coefficient, index)| (*coefficient, columns[*index]))
                        .collect(),
                ));
            }
            cs.enforce_r1cs_constraint(|| axes[0].clone(), || axes[1].clone(), || axes[2].clone())?;
        }
    }
    for (owner, start) in starts.into_iter().enumerate() {
        for edge in 0..66 {
            // `start` and the native prefix below are total R1CS columns;
            // Ark's `Variable::witness` takes an index into the witness-only
            // assignment.  Convert explicitly by subtracting the exact three
            // final-relation instance columns.  This is the same mapping used
            // by compose::join and by joined_source's equivalence control.
            let witness_at_column = |column: usize| {
                column
                    .checked_sub(cs.num_instance_variables())
                    .map(Variable::witness)
                    .ok_or(SynthesisError::Unsatisfiable)
            };
            let native = witness_at_column(3 + owner * 66 + edge)?;
            let signature = witness_at_column(start + edge)?;
            cs.enforce_r1cs_constraint(
                || LinearCombination(vec![(Fr::ONE, native), (-Fr::ONE, signature)]),
                || LinearCombination::from(Variable::One),
                LinearCombination::zero,
            )?;
        }
    }
    Ok(())
}

fn collect(cs: &ConstraintSystemRef<Fr>) -> CheckResult<R1cs> {
    cs.finalize();
    let mut groups = cs
        .to_matrices()
        .map_err(|_| CheckError::AggregateRelation)?;
    if groups.len() != 1 || !groups.contains_key(R1CS_PREDICATE_LABEL) {
        return Err(CheckError::AggregateRelation);
    }
    let matrices = groups
        .remove(R1CS_PREDICATE_LABEL)
        .ok_or(CheckError::AggregateRelation)?
        .try_into()
        .map_err(|_| CheckError::AggregateRelation)?;
    let result = R1cs {
        instances: cs.num_instance_variables(),
        witnesses: cs.num_witness_variables(),
        matrices,
    };
    result
        .validate()
        .map_err(|_| CheckError::AggregateRelation)?;
    Ok(result)
}

fn output_statement(profile: &Profile, tuple: &[u8; 520]) -> output::OutputStatement {
    output::OutputStatement {
        domain: profile.domain,
        cm: tuple[..32].try_into().expect("fixed tuple CM"),
        cv: tuple[32..96].try_into().expect("fixed tuple CV"),
        cf_hash: tuple[360..392].try_into().expect("fixed tuple CF hash"),
    }
}

fn verify_groth16(
    vk_bytes: &[u8; 328],
    proof_bytes: &[u8; 128],
    inputs: &[Fr; 2],
) -> core::result::Result<bool, ()> {
    let vk = native::checked_vk(vk_bytes).map_err(|_| ())?;
    let proof = native::checked_proof(proof_bytes).map_err(|_| ())?;
    Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&vk), &proof, inputs).map_err(|_| ())
}

fn check_outputs(source: &FullW1RoundSource, output_vk: &[u8; 328]) -> CheckResult<()> {
    if sha256(output_vk) != OUTPUT_VK {
        return Err(CheckError::Source);
    }
    for owner in 0..OWNERS {
        for output_index in 0..2 {
            let witness = &source.circuit.witness.owners[owner].outputs[output_index];
            let statement = output_statement(&source.circuit.profile, &witness.tuple);
            let circuit = output::OutputCircuit {
                profile: output::Profile {
                    domain: source.circuit.profile.domain,
                    profile_id: source.circuit.profile.wallet_profile,
                },
                statement: statement.clone(),
                witness: output::OutputWitness {
                    note: witness.note.clone(),
                    blinding: witness.blinding,
                },
            };
            let (matrix, assignment) =
                auth::collect::collect(circuit, 3).map_err(|_| CheckError::OutputRelation)?;
            if matrix.variables().ok() != Some(OUTPUT_VARIABLES)
                || matrix.constraints() != OUTPUT_CONSTRAINTS
                || auth::join::fingerprint(&matrix).ok().as_deref() != Some(OUTPUT_MATRIX)
                || !r1cs_satisfied(&matrix, &assignment)
            {
                return Err(CheckError::OutputRelation);
            }
            let proof: [u8; 128] = witness.tuple[392..520]
                .try_into()
                .expect("fixed tuple proof");
            if verify_groth16(output_vk, &proof, &statement.public_inputs()) != Ok(true) {
                return Err(CheckError::OutputProof);
            }
        }
    }
    Ok(())
}

fn check_aggregate(source: &FullW1RoundSource) -> CheckResult<()> {
    if sha256(&source.aggregate.verification_key) != AGGREGATE_VK {
        return Err(CheckError::Source);
    }
    check_signatures(&source.signatures)?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    source
        .circuit
        .clone()
        .generate_internalized(cs.clone())
        .map_err(|_| CheckError::AggregateRelation)?;
    let core_variables = cs.num_variables();
    append_signature_witnesses(cs.clone(), core_variables, &source.signatures)
        .map_err(|_| CheckError::AggregateRelation)?;
    if !cs
        .is_satisfied()
        .map_err(|_| CheckError::AggregateRelation)?
    {
        return Err(CheckError::AggregateRelation);
    }
    let instances = cs
        .instance_assignment()
        .map_err(|_| CheckError::AggregateRelation)?;
    if instances.len() != 3 || instances[0] != Fr::ONE {
        return Err(CheckError::AggregateRelation);
    }
    let matrix = collect(&cs)?;
    if matrix.variables().ok() != Some(AGGREGATE_VARIABLES)
        || matrix.constraints() != AGGREGATE_CONSTRAINTS
        || auth::join::fingerprint(&matrix).ok().as_deref() != Some(AGGREGATE_MATRIX)
    {
        return Err(CheckError::AggregateRelation);
    }
    let public = [instances[1], instances[2]];
    if verify_groth16(
        &source.aggregate.verification_key,
        &source.aggregate.proof,
        &public,
    ) != Ok(true)
    {
        return Err(CheckError::AggregateProof);
    }
    Ok(())
}

fn verify_source(source_instance: FullW1SourceInstanceAuthority) -> CheckResult<SourceInstance> {
    let FullW1SourceInstanceAuthority {
        instance,
        witness: source,
        selected_w0,
        authenticated_c1,
        accepted_lineage,
    } = source_instance;
    if sha256(&source.output_verification_key) != OUTPUT_VK {
        return Err(CheckError::Source);
    }
    let c1_first = &authenticated_c1.rounds[0];
    let c1_second = &authenticated_c1.rounds[1];
    let first_distinct_lineage = [
        c1_first.artifact,
        c1_first.round_attempt,
        c1_first.capture_plan,
        c1_first.projection,
        c1_first.stage_plan,
        c1_first.route_manifest,
        c1_first.route_source,
        c1_first.process,
        c1_first.child_exit,
    ];
    let second_distinct_lineage = [
        c1_second.artifact,
        c1_second.round_attempt,
        c1_second.capture_plan,
        c1_second.projection,
        c1_second.stage_plan,
        c1_second.route_manifest,
        c1_second.route_source,
        c1_second.process,
        c1_second.child_exit,
    ];
    if instance.epoch == [0; 32]
        || instance.accepted_history == [0; 32]
        || instance.effects.into_iter().any(|value| value == [0; 32])
        || instance.accepted_history != accepted_lineage.accepted_history_identity
        || c1_first.capture_attempt == c1_second.capture_attempt
        || c1_first.contact_value_authority == c1_second.contact_value_authority
        || c1_first
            .stage_operations
            .iter()
            .any(|operation| c1_second.stage_operations.contains(operation))
        || c1_first
            .stage_configs
            .iter()
            .any(|config| c1_second.stage_configs.contains(config))
        || first_distinct_lineage
            .iter()
            .zip(second_distinct_lineage)
            .any(|(first, second)| *first == second)
        || source.rounds[0].circuit.effects.context != accepted_lineage.accepted_initial_context
    {
        return Err(CheckError::Source);
    }
    for round in 0..ROUNDS {
        if instance.effects[round]
            != sha256_bytes(&accepted_lineage.counterfactual_effects[round].bytes())
        {
            return Err(CheckError::Source);
        }
    }
    let [round1, round2] = &source.rounds;
    for (round, item) in source.rounds.iter().enumerate() {
        check_graph(&item.circuit, &selected_w0.rounds[round])?;
        check_round_workload(
            round,
            item,
            &authenticated_c1.recipients[round],
            &authenticated_c1.rounds[round],
        )?;
        check_public_close(item, &accepted_lineage.counterfactual_effects[round])?;
        check_outputs(item, &source.output_verification_key)?;
        check_aggregate(item)?;
    }
    check_cross_round(round1, round2)?;
    Ok(instance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::COMPONENT_INSTANCES;

    #[test]
    fn fixed_rewire_changes_both_honest_physical_pairs() {
        let w0 = W0PhysicalGraph::new([0, 1, 2], [0, 2, 4], [1, 3, 5]);
        let (original, target) = graph(&w0).unwrap();
        assert_eq!(target.input, [2, 1, 0]);
        assert_eq!(target.payment, [0, 2, 4]);
        assert_eq!(target.change, [5, 3, 1]);
        check_different_pair(&original, &target).unwrap();
        assert_eq!(pair_for_input(&target, 0).unwrap(), (4, 1));
        assert_eq!(pair_for_input(&target, 2).unwrap(), (0, 5));
    }

    #[test]
    fn malformed_w0_graph_is_not_a_coupling_authority() {
        let duplicate_input = W0PhysicalGraph::new([0, 0, 2], [0, 2, 4], [1, 3, 5]);
        assert!(matches!(graph(&duplicate_input), Err(CheckError::Graph)));
        let duplicate_output = W0PhysicalGraph::new([0, 1, 2], [0, 2, 4], [1, 3, 4]);
        assert!(matches!(graph(&duplicate_output), Err(CheckError::Graph)));
    }

    #[test]
    fn opaque_closure_retains_an_unexposed_instance_binding() {
        assert_eq!(
            core::mem::size_of::<FullW1WitnessClosure>(),
            core::mem::size_of::<SourceInstance>()
        );
        assert!(!core::any::type_name::<FullW1WitnessClosure>().is_empty());
    }

    fn tiny_signature(owner: usize, edge: Fr) -> SignatureWitnessSource {
        let matrix = R1cs {
            instances: 67,
            witnesses: 1,
            matrices: [
                vec![vec![(Fr::ONE, 1)]],
                vec![vec![(Fr::ONE, 0)]],
                vec![vec![(Fr::ONE, 67)]],
            ],
        };
        let mut assignment = vec![Fr::ONE; 68];
        assignment[1..67].fill(edge);
        assignment[67] = edge;
        assert!(r1cs_satisfied(&matrix, &assignment), "owner {owner}");
        SignatureWitnessSource::new(matrix, assignment)
    }

    #[test]
    fn signature_append_uses_exact_total_column_to_witness_index_map() {
        let core = R1cs {
            instances: COMPONENT_INSTANCES,
            witnesses: 1,
            matrices: [
                vec![vec![(Fr::ONE, 3)]],
                vec![vec![(Fr::ONE, 0)]],
                vec![vec![(Fr::ONE, COMPONENT_INSTANCES)]],
            ],
        };
        let signatures = [
            tiny_signature(0, Fr::from(5u64)),
            tiny_signature(1, Fr::from(6u64)),
            tiny_signature(2, Fr::from(7u64)),
        ];
        let signature_matrices = core::array::from_fn(|owner| signatures[owner].matrix.clone());
        let joined = crate::compose::join(&core, &signature_matrices).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        let _ = cs.new_input_variable(|| Ok(Fr::from(11u64))).unwrap();
        let _ = cs.new_input_variable(|| Ok(Fr::from(12u64))).unwrap();
        for owner in 0..OWNERS {
            for _ in 0..66 {
                let value = signatures[owner].assignment[1];
                let _ = cs.new_witness_variable(|| Ok(value)).unwrap();
            }
        }
        let core_aux = cs.new_witness_variable(|| Ok(Fr::from(5u64))).unwrap();
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(Variable::witness(0)),
            || LinearCombination::from(Variable::One),
            || LinearCombination::from(core_aux),
        )
        .unwrap();
        // The direct source has only three instances, so the 198 former owner
        // component inputs are already the first 198 witnesses.
        assert_eq!(cs.num_variables(), core.variables().unwrap());
        append_signature_witnesses(cs.clone(), cs.num_variables(), &signatures).unwrap();
        assert!(cs.is_satisfied().unwrap());
        let direct = collect(&cs).unwrap();
        assert_eq!(direct.matrices, joined.cs.matrices);
        assert_eq!(
            auth::join::fingerprint(&direct).unwrap(),
            auth::join::fingerprint(&joined.cs).unwrap()
        );
    }
}
