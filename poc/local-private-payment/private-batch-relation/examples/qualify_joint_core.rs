//! PUBLIC INVALID structural filler only. Counts every financial trace recipe
//! and requires every model column assigned. No matrices/setup/proof/MPC claim.
#[path = "support/public_fixture.rs"]
mod public_fixture;
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use kpi_private_batch_relation::{
    BatchCircuit, COMPONENT_INSTANCES, Context, Profile, joint_trace,
    state_trace::{PublicHistory, PublicNullifierLeaf},
    trace::TraceBuilder,
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let s = v.as_str().ok_or("public hex string")?;
    if s.len() != 2 * N
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("public canonical hex".into());
    }
    Ok(hex::decode(s)?
        .try_into()
        .map_err(|_| "public hex length")?)
}
pub(crate) fn context(raw: [u8; 276]) -> Context {
    Context {
        profile: Profile {
            chain_genesis: raw[..32].try_into().unwrap(),
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
        old_reserve: u64::from_le_bytes(raw[268..].try_into().unwrap()),
    }
}
pub(crate) fn source_fixture(context: &Context) -> BatchCircuit {
    let mut f = public_fixture::fixture();
    f.profile = context.profile.clone();
    f.effects.context = context.clone();
    f.effects.new_cm_count = context.old_cm_count + 6;
    f.effects.new_nf_count = context.old_nf_count + 3;
    f
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err(
            "usage: qualify_joint_core PUBLIC-CONTEXT-HISTORY.json SIGNATURE_VARIABLES".into(),
        );
    }
    let v: Value = serde_json::from_slice(&fs::read(Path::new(&args[0]))?)?;
    if v["schema"] != "kpb-public-context-history/v1" {
        return Err("public context/history schema".into());
    }
    let context = context(bytes(&v["context_hex"])?);
    let history = PublicHistory {
        commitments: v["commitments_hex32"]
            .as_array()
            .ok_or("public commitments")?
            .iter()
            .map(bytes::<32>)
            .collect::<Result<_, _>>()?,
        nullifiers: v["nullifiers"]
            .as_array()
            .ok_or("public nullifiers")?
            .iter()
            .map(|n| {
                Ok(PublicNullifierLeaf {
                    value: bytes(&n["value_hex32"])?,
                    successor: bytes(&n["successor_hex32"])?,
                    successor_index: u32::try_from(
                        n["successor_index"]
                            .as_u64()
                            .ok_or("public successor index")?,
                    )?,
                })
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?,
    };
    history.validate(&context)?;
    let signature_variables: usize = args[1].to_str().ok_or("signature variables")?.parse()?;
    if signature_variables < 67 {
        return Err("signature component shape".into());
    }
    let began = Instant::now();
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: false,
    });
    let layout = source_fixture(&context).generate_with_layout(cs.clone())?;
    let core_variables = cs.num_variables();
    drop(cs);
    let model_variables = core_variables
        .checked_add(3 * (signature_variables - 1))
        .ok_or("model variable overflow")?;
    let mut builder = TraceBuilder::new_counting(model_variables, 3)?;
    builder.input_range(3, COMPONENT_INSTANCES)?;
    for range in layout.owner_local_columns {
        builder.input_range(range.start, range.end)?;
    }
    builder.input_range(core_variables, model_variables)?;
    let prepared = joint_trace::construct(&mut builder, &context, &history, &layout.owner_fields)?;
    let replay = ConstraintSystem::<Fr>::new_ref();
    replay.set_optimization_goal(OptimizationGoal::Constraints);
    replay.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        // Exact typed recipes expand Ark symbolic LCs. Retain their source
        // definitions, while still avoiding all constraint-row matrices.
        generate_lc_assignments: true,
    });
    let actual_layout =
        source_fixture(&context).generate_with_trace(replay.clone(), &mut builder, &prepared)?;
    if actual_layout != layout || replay.num_variables() != core_variables {
        return Err("actual financial model layout changed".into());
    }
    builder.require_complete_model()?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"kpb-full-financial-column-qualification/v1","scope":"PUBLIC_INVALID_SOURCE_GRAPH_ONLY","core_variables":core_variables,"model_variables":model_variables,"model_instances":3,"signature_variables_each":signature_variables,"owner_auxiliaries_each":layout.owner_local_columns.map(|r|r.end-r.start),"all_model_columns_assigned":true,"trace_total_variables":builder.variables(),"trace_operations":builder.operation_count(),"trace_operation_bytes":builder.operation_text_bytes()?,"trace_graph_sha256":hex::encode(builder.graph_sha256()?),"elapsed_seconds":began.elapsed().as_secs_f64(),"matrices_setup_proof_mpc_or_financial_acceptance":false})
        )?
    );
    Ok(())
}
