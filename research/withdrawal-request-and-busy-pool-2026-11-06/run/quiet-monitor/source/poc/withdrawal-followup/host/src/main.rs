mod anonymous;
#[allow(dead_code)]
mod bench;
#[path = "../../../batched-payment-costs/host/src/circuit.rs"]
mod circuit;
#[path = "../../../batched-payment-costs/host/src/native.rs"]
mod native;
#[path = "../../../batched-payment-costs/host/src/proof.rs"]
mod proof;
#[path = "../../../batched-payment-costs/host/src/prover.rs"]
mod prover;
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
#[path = "../../../batched-payment-costs/host/src/registration.rs"]
#[allow(dead_code)]
mod registration;
fn main() -> prover::Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("wrap") => { let raw=std::fs::read(&a[2])?; let p=risc0_binfmt::ProgramBinary::new(&raw,risc0_zkos_v1compat::V1COMPAT_ELF).encode(); prover::write(std::path::Path::new(&a[3]), &p)?; println!("{}",risc0_zkvm::compute_image_id(&p)?); },
        Some("serve") => anonymous::serve(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),a[5].parse()?)?,
        Some("finalize") => anonymous::finalize(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),std::path::Path::new(&a[5]))?,
        Some("unequal") => bench::unequal(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]))?,
        Some("replay-busy") => bench::replay_busy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
        Some("verify-logs") => anonymous::verify_logs(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
        Some("verify-unequal") => bench::verify_unequal(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]))?,
        Some("pinned-negatives") => bench::pinned_negatives(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
        Some("quiet") => bench::quiet(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),std::path::Path::new(&a[5]),std::path::Path::new(&a[6]))?,
        Some("verify-quiet") => bench::verify_quiet(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),std::path::Path::new(&a[5]),std::path::Path::new(&a[6]))?,
        Some("transfer-check") => bench::transfer_check(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
        Some("dropout") => bench::dropout(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]))?,
        Some("pin") => bench::pin(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]))?,
        Some("busy") => bench::busy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),std::path::Path::new(&a[4]),std::path::Path::new(&a[5]))?,
        Some("privacy") => bench::privacy(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]))?,
        _ => return Err("wrap ELF PROGRAM | pin STATE PINS | busy PIN_PROGRAM DYNAMIC_PROGRAM OLD_CORE OUT | privacy OLD_CORE OUT".into()),
    }
    Ok(())
}
