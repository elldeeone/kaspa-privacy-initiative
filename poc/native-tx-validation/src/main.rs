use kpi_native_tx_validation::{
    codec::Transaction,
    fixtures::{self, NAMES},
    verifier::Verifier,
};
use std::{error::Error, fs::File, io::Read, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, folder] if command == "generate" => fixtures::generate(Path::new(folder))?,
        [command, folder] if command == "check-fixtures" => {
            let verifier = Verifier::new()?;
            let mut spent = std::collections::BTreeSet::new();
            for name in NAMES {
                let mut bytes = Vec::new();
                File::open(Path::new(folder).join(format!("{name}.bin")))?
                    .take(kpi_native_tx_validation::codec::MAX_PACKET as u64 + 1)
                    .read_to_end(&mut bytes)?;
                let tx = Transaction::decode(&bytes)?;
                let mut view = fixtures::synthetic_view(name, &tx);
                view.spent = spent.clone();
                let report = verifier.verify_local(&bytes, &view)?;
                println!(
                    "{}",
                    serde_json::json!({"fixture":name,"result":"local draft authorization verified",
                    "txid":hex::encode(report.txid),"native_acceptance":false,"chain_authenticated":false,
                    "mass_validated":false,"portable_key_import":false})
                );
                spent.extend(tx.bundle.actions().iter().map(|a| a.nullifier().to_bytes()));
            }
        }
        _ => return Err(
            "usage: kpi-native-tx-validation generate DIR | check-fixtures DIR (synthetic only)"
                .into(),
        ),
    }
    Ok(())
}
