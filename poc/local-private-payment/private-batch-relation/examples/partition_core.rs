//! Matrix-free route-independence probe using PUBLIC INVALID fillers only.
//! Does not check satisfaction, create a proof/setup, or produce an MPC dealer.
#[path = "support/public_fixture.rs"]
mod public_fixture;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use kpi_private_batch_relation::{BatchCircuit, BatchLayout, ColumnRange};
use sha2::{Digest, Sha256};

fn hash(values: &[Fr]) -> String {
    let mut h = Sha256::new();
    for value in values {
        h.update(value.into_bigint().to_bytes_le());
    }
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}
struct Sample {
    layout: BatchLayout,
    local: [Vec<Fr>; 3],
    edges: [Vec<Fr>; 3],
    variables: usize,
}
fn synth(circuit: BatchCircuit) -> Result<Sample, Box<dyn std::error::Error>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    let layout = circuit.generate_with_layout(cs.clone())?;
    let instances = cs.num_instance_variables();
    let local = {
        let borrow = cs.borrow().ok_or("missingCS")?;
        let values = borrow.witness_assignment()?;
        core::array::from_fn(|i| {
            let ColumnRange { start, end } = layout.owner_local_columns[i];
            values[start - instances..end - instances].to_vec()
        })
    };
    let instance = cs.instance_assignment()?;
    let edges = core::array::from_fn(|i| instance[3 + 66 * i..3 + 66 * (i + 1)].to_vec());
    Ok(Sample {
        layout,
        local,
        edges,
        variables: cs.num_variables(),
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let initial = public_fixture::fixture();
    let baseline = synth(initial.clone())?;
    for held in 0..3 {
        let mut changed = initial.clone();
        for i in 0..3 {
            if i != held {
                let owner = &mut changed.witness.owners[i];
                owner.note.rho[0] ^= 0xa5;
                owner.nullifier_secret[0] ^= 0x31;
                owner.input_nf[1] ^= 0x92;
                owner.intent_nonce[7] ^= 0x66;
                owner.outputs[0].note.rho[3] ^= 0x71;
                owner.outputs[0].tuple[100] ^= 0x5c;
            }
        }
        // These global fields and unrelated owner data are unknown to the held
        // wallet. Their content changes, while public authenticated old head,
        // profile, shape and the held owner's complete record stay identical.
        changed.effects.new_cm_root[0] ^= 0x51;
        changed.effects.new_nf_root[0] ^= 0x18;
        changed.effects.inputs = core::array::from_fn(|i| {
            (
                changed.witness.owners[i].input_nf,
                changed.witness.owners[i].input_cv,
            )
        });
        changed.effects.outputs =
            core::array::from_fn(|i| changed.witness.owners[i / 2].outputs[i % 2].tuple);
        changed.effects.inputs.swap(0, 2);
        changed.effects.outputs.rotate_left(3);
        let candidate = synth(changed)?;
        if candidate.layout != baseline.layout || candidate.variables != baseline.variables {
            return Err("input-dependent physical layout".into());
        }
        if candidate.local[held] != baseline.local[held]
            || candidate.edges[held] != baseline.edges[held]
        {
            return Err("owner-local aux depends on unrelated secret fillers".into());
        }
        println!(
            "{{\"owner_component\":{held},\"owner_local_auxiliaries\":{},\"aux_sha256\":\"{}\",\"edge_sha256\":\"{}\",\"equal_across_unrelated_fillers\":true}}",
            baseline.local[held].len(),
            hash(&baseline.local[held]),
            hash(&baseline.edges[held])
        );
    }
    println!(
        "{{\"scope\":\"PUBLIC_INVALID_MATRIX_FREE_OWNER_PARTITION_ONLY\",\"variables\":{},\"elapsed_seconds\":{},\"matrices_or_satisfaction_or_proof_or_MPC\":false}}",
        baseline.variables,
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
