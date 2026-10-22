//! Ordinary-host NONSETTLING gate. Never produces a zkVM receipt or transaction.
use kpi_takeover_host::two_v6_binding::{assemble, Bundle, Gate, BUNDLE_LEN, INPUT_LEN};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::ExitCode,
};

fn read_exact_file(path: &Path, expected: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() != expected as u64 {
        return Err(format!("expected exactly {expected} bytes in a regular file").into());
    }
    let mut bytes = Vec::with_capacity(expected);
    file.take(expected as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err("file changed while reading".into());
    }
    Ok(bytes)
}
fn create(path: &Path, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // The complete input carries otherwise hidden grouping/auth/fee/anchor
    // handles. Never let the process umask make it world-readable.
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    if private {
        return Err("private witness creation requires Unix file permissions".into());
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    match args.get(1).and_then(|x| x.to_str()) {
        Some("assemble") if args.len() == 5 => {
            let a = Bundle::parse(&read_exact_file(Path::new(&args[2]), BUNDLE_LEN)?)?;
            let b = Bundle::parse(&read_exact_file(Path::new(&args[3]), BUNDLE_LEN)?)?;
            let witness = assemble([a, b])?;
            create(Path::new(&args[4]), &witness.bytes()?, true)?;
            println!("Assembled unverified input; both cryptographic proofs still require verify.");
        }
        Some("verify") if args.len() == 4 => {
            let bytes = read_exact_file(Path::new(&args[2]), INPUT_LEN)?;
            let accepted = Gate::new()?.verify(&bytes)?;
            let output = Path::new(&args[3]);
            // Validate all input before creating any result. Existing outputs
            // are preserved. No witness/grouping/proof/auth bytes are exported.
            fs::create_dir(output)?;
            create(&output.join("projection.bin"), &accepted.projection, false)?;
            create(&output.join("journal.bin"), &accepted.journal, false)?;
            let report = json!({
                "schema": "kpi-two-v6-host-binding-v1",
                "scope": "ORDINARY_HOST_NONSETTLING_BINDING_ONLY",
                "status": "host_binding_verified",
                "projection_bytes": accepted.projection.len(),
                "journal_bytes": accepted.journal.len(),
                "projection_sha256": hex::encode(accepted.projection_digest),
                "journal_sha256": hex::encode(accepted.journal_digest),
                "inner_proofs_verified": 2,
                "receipt_generated": false,
                "accepted_state_verified": false,
                "settlement_authorized": false,
                "privacy_benefit_measured": false
            });
            create(&output.join("report.json"), &serde_json::to_vec_pretty(&report)?, false)?;
            println!("{}", serde_json::to_string(&report)?);
        }
        _ => return Err("usage: two_v6_binding assemble BUNDLE0 BUNDLE1 NEW_INPUT | verify INPUT NEW_PUBLIC_OUTPUT_DIR".into()),
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn witness_files_are_owner_only_and_never_overwritten() {
        let path = std::env::temp_dir().join(format!(
            "kpi-two-v6-private-input-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        create(&path, b"test grouping handles", true).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(create(&path, b"replacement", true).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"test grouping handles");
        fs::remove_file(path).unwrap();
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("two-v6 host gate rejected: {error}");
            ExitCode::FAILURE
        }
    }
}
