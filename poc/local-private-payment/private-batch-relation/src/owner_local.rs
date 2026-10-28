//! Wallet-local native auxiliary generation with no other owner's secret.
//!
//! Other records and the unknown future effect core use fixed PUBLIC INVALID
//! filler. Only this wallet's independent native edges/auxiliaries are returned.
//! The full assignment is never returned, serialized, or used as an MPC dealer.
use crate::{
    BatchCircuit, BatchLayout, BatchWitness, Context, Effects, Note, NullifierWitness,
    OutputWitness, OwnerWitness, Profile, cv,
};
use ark_bn254::Fr;
use ark_ed_on_bn254::Fr as Scalar;
use ark_ff::Field;
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode};
use sha2::{Digest, Sha256};

/// Deliberately not Debug/Serialize. These values may go only into this wallet's
/// authenticated masked-input process. No signing seed/scalar/nonce is present.
pub struct OwnerAuxiliary {
    pub owner_component: usize,
    pub core_variables: usize,
    pub layout: BatchLayout,
    native_edges: Vec<Fr>,
    native_auxiliary: Vec<Fr>,
}
impl OwnerAuxiliary {
    pub fn native_edges(&self) -> &[Fr] {
        &self.native_edges
    }
    pub fn native_auxiliary(&self) -> &[Fr] {
        &self.native_auxiliary
    }
    /// The selected EdDSA matrix/map/source closure must be authenticated by the
    /// owner process before this call. Matching edges do not verify a signature;
    /// all real matrix rows still require checked MPC validation before egress.
    pub fn ordered_inputs_with_signature(
        &self,
        signature: &[Fr],
        expected_variables: usize,
    ) -> Result<Vec<Fr>, SynthesisError> {
        if expected_variables < 67
            || signature.len() != expected_variables
            || signature[0] != Fr::ONE
            || signature[1..67] != self.native_edges
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut values = Vec::with_capacity(66 + self.native_auxiliary.len() + signature.len() - 1);
        values.extend_from_slice(&self.native_edges);
        values.extend_from_slice(&self.native_auxiliary);
        values.extend_from_slice(&signature[1..]);
        Ok(values)
    }
}

fn public_filler(profile: &Profile, index: usize) -> OwnerWitness {
    let outputs = core::array::from_fn(|j| {
        let note = Note {
            owner: [10 + index as u8; 32],
            incoming: [20 + j as u8; 32],
            value: if j == 0 { 100_000_000 } else { 190_000_000 },
            rho: [30 + index as u8; 32],
            key_commitment: [40 + j as u8; 32],
            native_pk: [50 + index as u8; 32],
        };
        let blinding = cv::scalar_bytes(&Scalar::from((2 * index + j + 1) as u64));
        let mut tuple = [0; 520];
        tuple[..32].copy_from_slice(&note.commitment(&profile.domain));
        tuple[32..96].copy_from_slice(
            &cv::value_commitment(note.value, &blinding).expect("fixed public filler scalar"),
        );
        tuple[96..360].fill(60 + (2 * index + j) as u8);
        let cfh: [u8; 32] = Sha256::digest(&tuple[96..360]).into();
        tuple[360..392].copy_from_slice(&cfh);
        OutputWitness {
            note,
            blinding,
            tuple,
        }
    });
    let note = Note {
        owner: [70 + index as u8; 32],
        incoming: [80 + index as u8; 32],
        value: 300_000_000,
        rho: [90 + index as u8; 32],
        key_commitment: [100 + index as u8; 32],
        native_pk: [110 + index as u8; 32],
    };
    let blinding = cv::scalar_bytes(&Scalar::from(9 + index as u64));
    OwnerWitness {
        input_nf: [1 + index as u8; 32],
        input_cv: cv::value_commitment(note.value, &blinding).expect("fixed public filler scalar"),
        note,
        nullifier_secret: [120 + index as u8; 32],
        position: index as u32 + 1,
        path: [[0; 32]; 16],
        blinding,
        private_delta: cv::scalar_bytes(&Scalar::from((6 - 3 * index) as u64)),
        authorization_key: [130 + index as u8; 64],
        fee_sompi: 10_000_000,
        intent_nonce: [140 + index as u8; 32],
        outputs,
    }
}

fn public_effects(context: &Context, owners: &[OwnerWitness; 3]) -> Effects {
    let total_fee = owners
        .iter()
        .fold(0u64, |sum, owner| sum.wrapping_add(owner.fee_sompi));
    Effects {
        context: context.clone(),
        new_cm_root: [150; 32],
        new_nf_root: [151; 32],
        new_cm_count: context.old_cm_count + 6,
        new_nf_count: context.old_nf_count + 3,
        new_reserve: context.old_reserve.wrapping_sub(total_fee),
        total_fee,
        delta: cv::scalar_bytes(&Scalar::from(9u64)),
        inputs: core::array::from_fn(|i| (owners[i].input_nf, owners[i].input_cv)),
        outputs: core::array::from_fn(|i| owners[i / 2].outputs[i % 2].tuple),
        nf_witnesses: core::array::from_fn(|_| NullifierWitness {
            predecessor_index: 0,
            predecessor: [0; 32],
            successor: [0; 32],
            successor_index: 0,
            predecessor_path: [[0; 32]; 17],
            append_path: [[0; 32]; 17],
        }),
        cm_paths: [[[0; 32]; 16]; 6],
    }
}

/// Fixed PUBLIC invalid source template. No caller-owned witness is accepted.
pub(crate) fn public_source_template(context: Context) -> Result<BatchCircuit, SynthesisError> {
    if context.old_cm_count == 0
        || context.old_cm_count > 65536 - 6
        || context.old_nf_count == 0
        || context.old_nf_count > 131072 - 3
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let profile = context.profile.clone();
    let owners = core::array::from_fn(|i| public_filler(&profile, i));
    let effects = public_effects(&context, &owners);
    Ok(BatchCircuit {
        profile,
        effects,
        witness: BatchWitness {
            owners,
            input_permutation: core::array::from_fn(|i| {
                core::array::from_fn(|j| Fr::from((i == j) as u64))
            }),
            output_permutation: core::array::from_fn(|i| {
                core::array::from_fn(|j| Fr::from((i == j) as u64))
            }),
            delta_quotient: 0,
        },
    })
}

/// This entry accepts exactly ONE owner witness and authenticated PUBLIC head.
/// Public invalid filler for the other slots is constructed internally; callers
/// cannot pass another owner's witness or a clear globally combined assignment.
pub fn generate(
    profile: Profile,
    context: Context,
    owner_component: usize,
    owner: OwnerWitness,
) -> Result<OwnerAuxiliary, SynthesisError> {
    if owner_component >= 3
        || context.profile != profile
        || context.old_cm_count == 0
        || context.old_cm_count > 65536 - 6
        || context.old_nf_count == 0
        || context.old_nf_count > 131072 - 3
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut owners = core::array::from_fn(|i| public_filler(&profile, i));
    owners[owner_component] = owner;
    let effects = public_effects(&context, &owners);
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    let layout = BatchCircuit {
        profile,
        effects,
        witness: BatchWitness {
            owners,
            input_permutation: core::array::from_fn(|i| {
                core::array::from_fn(|j| Fr::from((i == j) as u64))
            }),
            output_permutation: core::array::from_fn(|i| {
                core::array::from_fn(|j| Fr::from((i == j) as u64))
            }),
            delta_quotient: 0,
        },
    }
    .generate_with_layout(cs.clone())?;
    let core_variables = cs.num_variables();
    let instances = cs.num_instance_variables();
    let native_edges = cs.instance_assignment()?
        [3 + owner_component * 66..3 + (owner_component + 1) * 66]
        .to_vec();
    let range = layout.owner_local_columns[owner_component];
    let native_auxiliary = cs
        .borrow()
        .ok_or(SynthesisError::MissingCS)?
        .witness_assignment()?[range.start - instances..range.end - instances]
        .to_vec();
    Ok(OwnerAuxiliary {
        owner_component,
        core_variables,
        layout,
        native_edges,
        native_auxiliary,
    })
}
