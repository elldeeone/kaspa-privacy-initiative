//! Fixed, NONFUNDABLE public experiment expectations. No native transaction.
use kpi_private_note_proof as receipt_checks;
use kpi_two_v6_binding as binding;
use kpi_two_v6_state::{StateAssertion, StateGate, JOURNAL_LEN, POOL_ID};
use risc0_zkvm::{compute_image_id, Receipt};
use std::{error::Error, fs, io::Write, path::Path};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const JOIN: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
pub const PUBLIC: &[u8] = include_bytes!("../pins/projection.bin");
const JOURNAL: &[u8] = include_bytes!("../pins/journal.bin");
pub const CYCLE_LIMIT: u64 = 400_000_000;

pub struct Context {
    pub name: &'static str,
    pub input_sha256: String,
    pub journal: &'static [u8],
    pub prior: &'static [u8],
    pub next: &'static [u8],
}
pub fn context(name: &str) -> Result<Context> {
    if name != "initial-pair" {
        return Err("only the fresh initial-pair publication is selected".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("../pins/selection.json"))?;
    let input = value["input_sha256"].as_str().ok_or("missing input pin")?;
    if input.len() != 64
        || value["projection_sha256"].as_str() != Some(sha(PUBLIC).as_str())
        || value["journal_sha256"].as_str() != Some(sha(JOURNAL).as_str())
    {
        return Err("fresh initial-pair publication has not been selected".into());
    }
    if JOURNAL.len() != JOURNAL_LEN {
        return Err("selected journal length".into());
    }
    Ok(Context {
        name: "initial-pair",
        input_sha256: input.into(),
        journal: JOURNAL,
        prior: &JOURNAL[110..215],
        next: &JOURNAL[215..320],
    })
}
pub fn sha(bytes: &[u8]) -> String {
    hex::encode(binding::sha256(bytes))
}
pub fn no_dev_mode() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode must be absent".into());
    }
    Ok(())
}
pub fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
pub fn selection() -> Result<(String, String)> {
    let value: serde_json::Value =
        serde_json::from_slice(include_bytes!("../pins/selection.json"))?;
    let image = value["image"].as_str().ok_or("missing selected image")?;
    let program = value["program_sha256"]
        .as_str()
        .ok_or("missing selected program")?;
    if image.len() != 64 || program.len() != 64 {
        return Err("fresh initial-pair guest identity has not been selected".into());
    }
    receipt_checks::digest(image)?;
    if hex::decode(program)?.len() != 32 {
        return Err("invalid selected program hash".into());
    }
    Ok((image.into(), program.into()))
}
pub fn program(dir: &Path) -> Result<Vec<u8>> {
    let (image, expected_sha) = selection()?;
    let program = fs::read(dir.join("guest.program.bin"))?;
    if sha(&program) != expected_sha || compute_image_id(&program)?.to_string() != image {
        return Err("independently selected state guest/program mismatch".into());
    }
    Ok(program)
}
pub fn check_journal(journal: &[u8], expected: &[u8]) -> Result<()> {
    if journal.len() != JOURNAL_LEN
        || journal != expected
        || &journal[..8] != b"KPI2V6S1"
        || journal[8..10] != 1u16.to_le_bytes()
        || journal[10..42] != binding::sha256(PUBLIC)
        || journal[42..74] != POOL_ID
    {
        return Err("exact independently expected state journal mismatch".into());
    }
    Ok(())
}
pub fn check_source(bytes: &[u8], expected: &Context) -> Result<StateAssertion> {
    if bytes.len() != kpi_two_v6_state::INPUT_LEN || sha(bytes) != expected.input_sha256 {
        return Err("independently pinned public state input mismatch".into());
    }
    let assertion = StateGate::new()?.evaluate(bytes)?;
    check_journal(&assertion.journal, expected.journal)?;
    if assertion.projection != PUBLIC
        || assertion.prior_state.bytes() != expected.prior
        || assertion.next_state.bytes() != expected.next
    {
        return Err("independent projection/prior/successor oracle mismatch".into());
    }
    Ok(assertion)
}
pub fn check_receipt(receipt: &Receipt, expected: &Context) -> Result<()> {
    let (image, _) = selection()?;
    // Same established SDK + official decoded-control/allowed-root callback.
    // Native transaction context authentication is a separate obligation.
    receipt_checks::verify_claim(
        receipt,
        receipt_checks::digest(&image)?,
        expected.journal,
        receipt_checks::digest(JOIN)?,
    )?;
    check_journal(&receipt.journal.bytes, expected.journal)?;
    Ok(())
}
