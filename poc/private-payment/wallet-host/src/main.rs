mod adversarial;
mod fixture;
mod history;
mod proof;
mod recovery;
mod scan;
mod state;
use anyhow::{ensure, Result};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() >= 2,
        "prepare PROGRAM NEW_DIR | profile/prove CASE NEW_OUT | verify CASE RECEIPT NEW_OUT"
    );
    match a[1].as_str() {
        "verify-history" if a.len() == 6 => {
            recovery::verify_history(Path::new(&a[2]), &a[3], Path::new(&a[4]), Path::new(&a[5]))
        }
        "exercise" if a.len() == 5 => {
            recovery::exercise(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))
        }
        "restore" if a.len() == 7 => recovery::command(
            Path::new(&a[2]),
            &a[3],
            Path::new(&a[4]),
            Path::new(&a[5]),
            Path::new(&a[6]),
        ),
        "finalize" if a.len() == 5 => {
            recovery::finalize(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))
        }
        "check-wire" if a.len() == 4 => adversarial::wire(Path::new(&a[2]), Path::new(&a[3])),
        "check-native" if a.len() == 4 => adversarial::run(Path::new(&a[2]), Path::new(&a[3])),
        "prepare" if a.len() == 4 => fixture::prepare(Path::new(&a[2]), Path::new(&a[3])),
        "profile" | "prove" | "execute-negative" if a.len() == 4 => {
            proof::run(&a[1], Path::new(&a[2]), None, Path::new(&a[3]))
        }
        "verify" if a.len() == 5 => proof::run(
            "verify",
            Path::new(&a[2]),
            Some(Path::new(&a[3])),
            Path::new(&a[4]),
        ),
        _ => anyhow::bail!("invalid command"),
    }
}
