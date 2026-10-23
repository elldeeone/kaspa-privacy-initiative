//! Fixed public reproducer for Arkworks LC assignment caching. No file inputs.
use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint8::UInt8};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};
use kpi_private_capacity_prover::circuit::matrix_fingerprint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn probe(kind: &str, cache: bool) -> Result<Value, &'static str> {
    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: cache,
    });
    let began = Instant::now();
    match kind {
        "public-LC" => {
            let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64)))
                .map_err(|_| "probe_allocate")?;
            let mut sum = a.clone();
            for _ in 0..32 {
                sum += &a;
            }
            sum.enforce_equal(&FpVar::Constant(Fr::from(99u64)))
                .map_err(|_| "probe_constraint")?;
        }
        "public-SHA256" => {
            let public = [0x5au8; 32];
            let input =
                UInt8::new_witness_vec(cs.clone(), &public).map_err(|_| "probe_allocate")?;
            let digest = Sha256Gadget::<Fr>::digest(&input).map_err(|_| "probe_sha")?;
            let expected = Sha256::digest(public);
            digest
                .0
                .enforce_equal(&UInt8::constant_vec(&expected))
                .map_err(|_| "probe_constraint")?;
        }
        _ => return Err("probe_kind"),
    }
    let synthesis_seconds = began.elapsed().as_secs_f64();
    let began = Instant::now();
    cs.finalize();
    let finalize_seconds = began.elapsed().as_secs_f64();
    let began = Instant::now();
    let satisfied = cs.is_satisfied().map_err(|_| "probe_satisfaction")?;
    let satisfaction_seconds = began.elapsed().as_secs_f64();
    let began = Instant::now();
    let fingerprint = matrix_fingerprint(&cs).map_err(|_| "probe_matrix")?;
    let matrix_seconds = began.elapsed().as_secs_f64();
    Ok(
        json!({"kind":kind,"generate_lc_assignments":cache,"satisfied":satisfied,
        "constraints":cs.num_constraints(),"witness_variables":cs.num_witness_variables(),"instances_including_one":cs.num_instance_variables(),
        "matrix_sha256":fingerprint,"seconds":{"synthesis":synthesis_seconds,"finalize":finalize_seconds,"satisfaction":satisfaction_seconds,"matrix_hash":matrix_seconds}}),
    )
}
fn main() {
    let requested = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);
    if ![1, 14].contains(&requested) {
        eprintln!("probe_thread_pool");
        std::process::exit(1)
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(requested)
        .build()
        .unwrap();
    std::panic::set_hook(Box::new(|_| eprintln!("probe_internal_failure")));
    let result = pool.install(|| -> Result<Value, &'static str> {
        let mut rows = Vec::new();
        for kind in ["public-LC", "public-SHA256"] {
            let off = probe(kind, false)?;
            let on = probe(kind, true)?;
            if off["satisfied"] != true
                || on["satisfied"] != true
                || off["matrix_sha256"] != on["matrix_sha256"]
                || off["constraints"] != on["constraints"]
                || off["witness_variables"] != on["witness_variables"]
            {
                return Err("probe_equivalence_failed");
            }
            rows.extend([off, on]);
        }
        Ok(
            json!({"schema":"kpx4-public-lc-cache-probe/v1","all_equivalence_checks_passed":true,"executed_inside_selected_pool":true,"requested_rayon_workers":requested,"actual_rayon_workers":rayon::current_num_threads(),"rows":rows,"private_inputs_or_setup_proof_network_execution":false}),
        )
    });
    match result {
        Ok(value) => println!("{value}"),
        Err(code) => {
            println!("{}", json!({"event":"error","code":code}));
            std::process::exit(1)
        }
    }
}
