use kpi_orchard_interop::{
    codec::{Envelope, MAX_PACKET},
    verifier::{SuppliedContext, Verifier},
};
use std::{error::Error, fs::File, io::Read, path::Path};

fn bounded_read(path: &str, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds file bound".into());
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, folder] if command == "generate" => kpi_orchard_interop::fixtures::generate(Path::new(folder))?,
        [command] if command == "fingerprint" => println!("{}", Verifier::new().key_fingerprint()),
        [command, packet, supplied] if command == "verify" => {
            let bytes = bounded_read(packet, MAX_PACKET)?;
            let _: Envelope = Envelope::decode(&bytes)?;
            let context: SuppliedContext = serde_json::from_slice(&bounded_read(supplied, 64_000)?)?;
            let verifier = Verifier::new();
            let next = verifier.verify(&bytes, &context)?;
            println!("{}", serde_json::json!({"result":"local interoperability verified","modeled_pool_next":next.to_string(),
                "vk_debug_sha256":verifier.key_fingerprint(),"native_acceptance":false,"funding_authenticated":false}));
        },
        _ => return Err("usage: kpi-orchard-interop generate DIR | fingerprint | verify PACKET SUPPLIED_CONTEXT_JSON".into()),
    }
    Ok(())
}
