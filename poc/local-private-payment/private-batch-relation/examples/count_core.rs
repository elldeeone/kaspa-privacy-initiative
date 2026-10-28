//! Resource probe only. Public invalid filler paths/signatures are deliberate;
//! this produces no matrices, satisfaction claim, setup, proof or MPC witness.
use ark_bn254::Fr;
use ark_ed_on_bn254::Fr as Scalar;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use kpi_private_batch_relation::{
    BatchCircuit, BatchWitness, Context, Effects, Note, NullifierWitness, OutputWitness,
    OwnerWitness, Profile, cv,
};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile {
        chain_genesis: [1; 32],
        pool_lineage: [2; 32],
        wallet_profile: [3; 32],
        domain: [0xa7; 32],
        service_policy: [5; 32],
    };
    let context = Context {
        profile: profile.clone(),
        reserve_outpoint: [6; 36],
        old_cm_root: [7; 32],
        old_nf_root: [8; 32],
        old_cm_count: 4,
        old_nf_count: 1,
        old_reserve: 900_000_000,
    };
    let owners: [OwnerWitness; 3] = core::array::from_fn(|i| {
        let outputs = core::array::from_fn(|j| {
            let note = Note {
                owner: [10 + i as u8; 32],
                incoming: [20 + j as u8; 32],
                value: if j == 0 { 100_000_000 } else { 190_000_000 },
                rho: [30 + i as u8; 32],
                key_commitment: [40 + j as u8; 32],
                native_pk: [50 + i as u8; 32],
            };
            let blinding = cv::scalar_bytes(&Scalar::from((2 * i + j + 1) as u64));
            let mut tuple = [0u8; 520];
            tuple[..32].copy_from_slice(&note.commitment(&profile.domain));
            tuple[32..96].copy_from_slice(&cv::value_commitment(note.value, &blinding).unwrap());
            tuple[96..360].fill(60 + (2 * i + j) as u8);
            let cfh: [u8; 32] = Sha256::digest(&tuple[96..360]).into();
            tuple[360..392].copy_from_slice(&cfh);
            OutputWitness {
                note,
                blinding,
                tuple,
            }
        });
        let note = Note {
            owner: [70 + i as u8; 32],
            incoming: [80 + i as u8; 32],
            value: 300_000_000,
            rho: [90 + i as u8; 32],
            key_commitment: [100 + i as u8; 32],
            native_pk: [110 + i as u8; 32],
        };
        let blinding = cv::scalar_bytes(&Scalar::from(9 + i as u64));
        OwnerWitness {
            input_nf: [1 + i as u8; 32],
            input_cv: cv::value_commitment(note.value, &blinding).unwrap(),
            note,
            nullifier_secret: [120 + i as u8; 32],
            position: i as u32 + 1,
            path: [[0; 32]; 16],
            blinding,
            private_delta: cv::scalar_bytes(&Scalar::from((6-3*i)as u64)),
            authorization_key: [130 + i as u8; 64],
            fee_sompi: 10_000_000,
            intent_nonce: [140 + i as u8; 32],
            outputs,
        }
    });
    let nf_witnesses = core::array::from_fn(|_| NullifierWitness {
        predecessor_index: 0,
        predecessor: [0; 32],
        successor: [0; 32],
        successor_index: 0,
        predecessor_path: [[0; 32]; 17],
        append_path: [[0; 32]; 17],
    });
    let effects = Effects {
        context,
        new_cm_root: [150; 32],
        new_nf_root: [151; 32],
        new_cm_count: 10,
        new_nf_count: 4,
        new_reserve: 870_000_000,
        total_fee: 30_000_000,
        delta: cv::scalar_bytes(&Scalar::from(9u64)),
        inputs: core::array::from_fn(|i| (owners[i].input_nf, owners[i].input_cv)),
        outputs: core::array::from_fn(|i| owners[i / 2].outputs[i % 2].tuple),
        nf_witnesses,
        cm_paths: [[[0; 32]; 16]; 6],
    };
    let u = core::array::from_fn(|i| core::array::from_fn(|j| Fr::from(u64::from(i == j))));
    let v = core::array::from_fn(|i| core::array::from_fn(|j| Fr::from(u64::from(i == j))));
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    let start = std::time::Instant::now();
    BatchCircuit {
        profile,
        effects,
        witness: BatchWitness {
            owners,
            input_permutation: u,
            output_permutation: v,
            delta_quotient: 0,
        },
    }
    .generate_constraints(cs.clone())?;
    println!(
        "{{\"scope\":\"actual_core_matrix_free_count_only_invalid_public_filler\",\"instances\":{},\"witnesses\":{},\"pre_finalization_constraints\":{},\"elapsed_seconds\":{},\"matrix_constructed\":false,\"satisfaction_checked\":false,\"proof_or_MPC\":false}}",
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
