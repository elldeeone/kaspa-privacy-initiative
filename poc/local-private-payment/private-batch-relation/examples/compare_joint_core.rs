//! PUBLIC INVALID core-only value differential. Never a private input dealer,
//! signature assignment, matrix check, setup, proof or financial acceptance.
#[path = "qualify_joint_core.rs"]
mod qualifier;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};
use kpi_private_batch_relation::{
    BatchCircuit, COMPONENT_INSTANCES, Effects, NullifierWitness, joint_trace,
    state_trace::{PublicHistory, PublicNullifierLeaf},
    trace::{Lc, TraceBuilder},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path, time::Instant};
fn new_cs(lcs: bool) -> ConstraintSystemRef<Fr> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: lcs,
    });
    cs
}
fn eval(lc: &Lc, z: &[Option<Fr>]) -> Fr {
    lc.0.iter().fold(Fr::ZERO, |v, (c, i)| {
        v + *c * z[*i].expect("PUBLIC reference assignment")
    })
}
fn byte(b: &[Lc], z: &[Option<Fr>]) -> u8 {
    assert_eq!(b.len(), 8);
    b.iter().enumerate().fold(0, |v, (i, b)| {
        let x = eval(b, z);
        assert!(x == Fr::ZERO || x == Fr::ONE);
        v | ((x == Fr::ONE) as u8) << i
    })
}
fn effects(b: &[u8], context: kpi_private_batch_relation::Context) -> Effects {
    assert_eq!(b.len(), 10_364);
    let h = |i: usize| b[i..i + 32].try_into().unwrap();
    let u32at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let u64at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    Effects {
        context,
        new_cm_root: h(284),
        new_nf_root: h(316),
        new_cm_count: u32at(348),
        new_nf_count: u32at(352),
        new_reserve: u64at(356),
        total_fee: u64at(364),
        delta: h(372),
        inputs: core::array::from_fn(|i| {
            (
                h(404 + i * 96),
                b[436 + i * 96..500 + i * 96].try_into().unwrap(),
            )
        }),
        outputs: core::array::from_fn(|i| b[692 + i * 520..1212 + i * 520].try_into().unwrap()),
        nf_witnesses: core::array::from_fn(|i| {
            let at = 3812 + i * 1160;
            NullifierWitness {
                predecessor_index: u32at(at),
                predecessor: h(at + 4),
                successor: h(at + 36),
                successor_index: u32at(at + 68),
                predecessor_path: core::array::from_fn(|j| h(at + 72 + j * 32)),
                append_path: core::array::from_fn(|j| h(at + 616 + j * 32)),
            }
        }),
        cm_paths: core::array::from_fn(|i| core::array::from_fn(|j| h(7292 + i * 512 + j * 32))),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.len() > 2 || (args.len() == 2 && args[1] != "changed") {
        return Err("usage: compare_joint_core PUBLIC-CONTEXT-HISTORY.json".into());
    }
    let v: Value = serde_json::from_slice(&fs::read(Path::new(&args[0]))?)?;
    let context = qualifier::context(
        hex::decode(v["context_hex"].as_str().ok_or("public context")?)?
            .try_into()
            .map_err(|_| "public context length")?,
    );
    let h = |v: &Value| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Ok(hex::decode(v.as_str().ok_or("public hash")?)?
            .try_into()
            .map_err(|_| "public hash length")?)
    };
    let history = PublicHistory {
        commitments: v["commitments_hex32"]
            .as_array()
            .ok_or("public commitments")?
            .iter()
            .map(h)
            .collect::<Result<_, _>>()?,
        nullifiers: v["nullifiers"]
            .as_array()
            .ok_or("public nullifiers")?
            .iter()
            .map(|n| {
                Ok(PublicNullifierLeaf {
                    value: h(&n["value_hex32"])?,
                    successor: h(&n["successor_hex32"])?,
                    successor_index: u32::try_from(
                        n["successor_index"].as_u64().ok_or("public index")?,
                    )?,
                })
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?,
    };
    history.validate(&context)?;
    let began = Instant::now();
    let changed = args.len() == 2;
    let mut fixture = qualifier::source_fixture(&context);
    if changed {
        fixture.witness.owners[0].input_nf = [9; 32];
    }
    let baseline = new_cs(false);
    let layout = fixture.clone().generate_with_layout(baseline.clone())?;
    let core = baseline.num_variables();
    let mut inputs = BTreeMap::new();
    let instances = baseline.instance_assignment()?;
    for i in 3..COMPONENT_INSTANCES {
        inputs.insert(i, instances[i]);
    }
    {
        let borrowed = baseline.borrow().ok_or("public CS")?;
        let values = borrowed.witness_assignment()?;
        for r in layout.owner_local_columns {
            for i in r.start..r.end {
                inputs.insert(i, values[i - COMPONENT_INSTANCES]);
            }
        }
    }
    drop(baseline);
    // All fixture values and random tape are PUBLIC, fixed for this test only.
    let tape = (0..6)
        .flat_map(|i| (0..128).map(move |bit| !changed && bit < 3 && (((6 - i) >> bit) & 1) != 0))
        .collect();
    let mut builder = TraceBuilder::new_public_fixture_with_random_tape(core, 3, inputs, tape)?;
    builder.input_range(3, COMPONENT_INSTANCES)?;
    for r in layout.owner_local_columns {
        builder.input_range(r.start, r.end)?;
    }
    let prepared = joint_trace::construct(&mut builder, &context, &history, &layout.owner_fields)?;
    let (normal_fixture, normal_effect_bytes) = {
        let z = builder.finish_public_fixture_values()?;
        let body = prepared
            .effect_bytes
            .iter()
            .map(|b| byte(b, z))
            .collect::<Vec<_>>();
        let mut normal = fixture.clone();
        normal.effects = effects(&body, context.clone());
        normal.witness.input_permutation = core::array::from_fn(|i| {
            core::array::from_fn(|j| eval(&prepared.input_permutation[i][j], z))
        });
        normal.witness.output_permutation = core::array::from_fn(|i| {
            core::array::from_fn(|j| eval(&prepared.output_permutation[i][j], z))
        });
        normal.witness.delta_quotient = byte(&prepared.delta_quotient_bits, z);
        (normal, body)
    };
    let traced = new_cs(true);
    let actual_layout =
        normal_fixture
            .clone()
            .generate_with_trace(traced.clone(), &mut builder, &prepared)?;
    if actual_layout != layout || traced.num_variables() != core {
        return Err("core graph changed".into());
    }
    drop(traced);
    builder.require_complete_model()?;
    let normal = new_cs(false);
    let normal_layout = normal_fixture.generate_with_layout(normal.clone())?;
    if normal_layout != layout || normal.num_variables() != core {
        return Err("reference core graph changed".into());
    }
    let z = builder.finish_public_fixture_values()?;
    let instances = normal.instance_assignment()?;
    for (i, value) in instances.iter().enumerate() {
        if z[i] != Some(*value) {
            return Err(format!("PUBLIC core instance mismatch at column{i}").into());
        }
    }
    {
        let borrowed = normal.borrow().ok_or("public CS")?;
        for (j, value) in borrowed.witness_assignment()?.iter().enumerate() {
            let i = COMPONENT_INSTANCES + j;
            if z[i] != Some(*value) {
                return Err(format!("PUBLIC core auxiliary mismatch at column{i}").into());
            }
        }
    }
    use sha2::{Digest, Sha256};
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"kpb-complete-core-value-differential/v1","scope":"PUBLIC_INVALID_CORE_ONLY_ORACLE_NO_PRIVATE_BODY","model_core_variables_compared":core,"every_core_instance_and_auxiliary_equal":true,"effect_bytes":normal_effect_bytes.len(),"effect_sha256":hex::encode(Sha256::digest(&normal_effect_bytes)),"active_random_bit_instructions":768,"graph_sha256":hex::encode(builder.graph_sha256()?),"trace_variables":builder.variables(),"trace_operations":builder.operation_count(),"elapsed_seconds":began.elapsed().as_secs_f64(),"matrices_signature_assignment_setup_proof_mpc_or_financial_acceptance":false})
        )?
    );
    Ok(())
}
