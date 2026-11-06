mod bench;
mod circuit;
mod native;
mod proof;
mod prover;
mod receipt_script;
mod registration;
fn main() -> prover::Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("wrap") => {
            let raw = std::fs::read(&a[2])?;
            let program =
                risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            prover::write(std::path::Path::new(&a[3]), &program)?;
            println!("{}", risc0_zkvm::compute_image_id(&program)?);
        }
        Some("run") => bench::run(std::path::Path::new(&a[2]), std::path::Path::new(&a[3]))?,
        _ => return Err("wrap RAW_ELF NEW_PROGRAM | run PROGRAM NEW_DIRECTORY".into()),
    }
    Ok(())
}
