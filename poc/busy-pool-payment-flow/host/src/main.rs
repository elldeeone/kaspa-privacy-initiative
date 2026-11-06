#[allow(dead_code)]
mod bench {
    include!("../../../reusable-withdrawal-approvals/host/src/legacy_bench.rs");
    include!("../../../reusable-withdrawal-approvals/host/src/experiment.rs");
    include!("campaign.rs");
}
mod actor;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/circuit.rs"]
mod circuit;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/native.rs"]
mod native;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/proof.rs"]
mod proof;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/prover.rs"]
mod prover;
mod queue;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/registration.rs"]
mod registration;
fn main() -> prover::Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("controls") => bench::preflight_controls(std::path::Path::new(&a[2]))?,
 Some("actor")=>actor::run(std::path::Path::new(&a[2]), std::path::Path::new(&a[3]))?,
 Some("prove")=>{let p=std::fs::read(&a[2])?; let i=bincode::deserialize(&std::fs::read(&a[3])?)?; prover::prove(&p,&i,std::path::Path::new(&a[4]))?;},
 Some("run")=>bench::run_busy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),false)?,
 Some("preflight")=>bench::run_busy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),true)?,
 Some("replay")=>bench::replay_busy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]))?,
 _=>return Err("actor DIR PARAMS | prove PROGRAM INPUT OUT | run PROGRAM PARAMS OUT | preflight PROGRAM PARAMS OUT | replay PROGRAM RUN".into())
 }
    Ok(())
}
