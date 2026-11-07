#[allow(dead_code)]
mod bench {
 include!("../../../reusable-withdrawal-approvals/host/src/legacy_bench.rs");
 include!("../../../reusable-withdrawal-approvals/host/src/experiment.rs");
 include!("diagnostic.rs");
}

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
mod original_prover;
mod prover;

#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/registration.rs"]
mod registration;
fn main()->prover::Result<()>{
 let a=std::env::args().collect::<Vec<_>>();
 match a.get(1).map(String::as_str){
 Some("wrap")=>{let p=risc0_binfmt::ProgramBinary::new(&std::fs::read(&a[2])?,risc0_zkos_v1compat::V1COMPAT_ELF).encode();prover::write(std::path::Path::new(&a[3]),&p)?;let id=risc0_zkvm::compute_image_id(&p)?;if let Some(pin)=a.get(4){prover::write(std::path::Path::new(pin),id.as_bytes())?;}println!("{id}");},
 Some("cases")=>bench::prepare_cases(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
 Some("direct")=>{prover::direct(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?;},
 Some("authorize")=>{prover::authorize(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?;},
 Some("settle")=>{prover::settle(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),std::path::Path::new(&a[5]),std::path::Path::new(&a[6]))?;},
 Some("native")=>bench::check_case(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
 _=>return Err("wrap ELF PROGRAM [PIN] | cases PROGRAM PRIOR OUT | authorize PROGRAM INPUT OUT | settle AUTH_PROGRAM PROGRAM INPUT CACHE OUT | native PROGRAM CASE PROOF".into())
 };Ok(())
}
