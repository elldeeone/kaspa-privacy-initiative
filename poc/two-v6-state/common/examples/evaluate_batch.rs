//! Read-only differential-test adapter. No expected results are read here.
//! Each path produces one tab-separated line: OK,inputSHA,Jhex,nextShex or
//! ERR,inputSHA,typedError. I/O/process failures fail the process separately.
use kpi_two_v6_binding::sha256;
use kpi_two_v6_state::StateGate;
use std::{fmt::Write, path::PathBuf};

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gate = StateGate::new()?;
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        return Err("supply one or more input paths".into());
    }
    for path in paths {
        let input = std::fs::read(path)?;
        let digest = hex(&sha256(&input));
        match gate.evaluate(&input) {
            Ok(assertion) => println!(
                "OK\t{digest}\t{}\t{}",
                hex(&assertion.journal),
                hex(&assertion.next_state.bytes())
            ),
            Err(error) => println!("ERR\t{digest}\t{error:?}"),
        }
    }
    Ok(())
}
