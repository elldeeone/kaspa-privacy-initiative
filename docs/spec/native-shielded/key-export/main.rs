use orchard::circuit::{OrchardCircuitVersion,VerifyingKey};
use sha2::{Digest,Sha256};
use std::{fs,path::Path,error::Error};
use kpi_orchard_interop::verifier::{Verifier,SuppliedContext};

fn main() -> Result<(),Box<dyn Error>> {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.len()!=2 { return Err("usage: exporter ARTIFACT_DIR EXISTING_VECTOR_DIR".into()); }
    let dest=Path::new(&args[0]); let vectors=Path::new(&args[1]);fs::create_dir_all(dest)?;
    let key=VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let mut capsule=Vec::new();key.write_portable_key_diagnostic(&mut capsule)?;
    fs::write(dest.join("fixed-post-nu6-2.vk-capsule.bin"),&capsule)?;
    fs::write(dest.join("upstream-pinned-key-description.txt"),key.portable_diagnostic_upstream_description())?;
    let debug_hash=hex::encode(Sha256::digest(format!("{key:?}").as_bytes()));
    let original:serde_json::Value=serde_json::from_slice(&fs::read(vectors.join("manifest.json"))?)?;
    if original["vk_debug_sha256"].as_str()!=Some(debug_hash.as_str()) { return Err("original unpatched diagnostic key identity changed".into()); }
    let verifier=Verifier::new();
    let mut checks=Vec::new();
    for name in ["deposit","transfer","withdraw"] {
        let packet=fs::read(vectors.join(format!("{name}.bin")))?;
        let context:SuppliedContext=serde_json::from_slice(&fs::read(vectors.join(format!("{name}.context.json")))?)?;
        let next=verifier.verify(&packet,&context)?;
        checks.push(serde_json::json!({"fixture":name,"verified_existing_complete_bundle":true,"modeled_pool_next":next.to_string()}));
    }
    let report=serde_json::json!({"scope":"diagnostic read-only source export; existing synthetic proofs reverified; no new proof or native acceptance", "capsule_bytes":capsule.len(),"capsule_sha256":hex::encode(Sha256::digest(&capsule)),"original_debug_sha256_unchanged":debug_hash,"existing_bundle_checks":checks});
    fs::write(dest.join("export-result.json"),serde_json::to_vec_pretty(&report)?)?;
    println!("{}",report);Ok(())
}
