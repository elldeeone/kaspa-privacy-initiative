#[allow(dead_code)]
mod bench;
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
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
#[allow(dead_code)]
#[path = "../../../batched-payment-costs/host/src/registration.rs"]
mod registration;
fn main() -> prover::Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("wrap") => {
            let raw = std::fs::read(&a[2])?;
            let p =
                risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            prover::write(std::path::Path::new(&a[3]), &p)?;
            println!("{}", risc0_zkvm::compute_image_id(&p)?);
        }
        Some("preflight") => bench::preflight(
            std::path::Path::new(&a[2]),
            std::path::Path::new(&a[3]),
            std::path::Path::new(&a[4]),
        )?,
        Some("run") => bench::experiment(
            std::path::Path::new(&a[2]),
            std::path::Path::new(&a[3]),
            std::path::Path::new(&a[4]),
        )?,
        Some("replay") => bench::replay_new(
            std::path::Path::new(&a[2]),
            std::path::Path::new(&a[3]),
            std::path::Path::new(&a[4]),
        )?,
        _ => return Err("wrap ELF PROGRAM | run PROGRAM CORE OUT | replay PROGRAM RUN OUT".into()),
    }
    Ok(())
}
