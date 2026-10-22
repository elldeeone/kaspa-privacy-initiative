//! Checked/compiled verifier equivalence for the independently pinned fresh pair.
//! No guest, outer proof, native transaction or owner workflow.
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_s7_lifecycle_proof_host as h;
use kpi_two_v6_binding::{self as binding, compiled, compiled::CompiledResearchGate};
use serde_json::json;
use std::{fs, path::Path};

fn main() -> h::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("check_fresh_pair INDEPENDENT_PAIR_INPUT NEW_OUTPUT".into());
    }
    let input = fs::read(&args[1])?;
    if h::sha(&input) != "2822ce58c2527f48183fad3593b4147c4821f903da6752d57fb293cb1f5648e4" {
        return Err("independently expected fresh pair input mismatch".into());
    }
    let key = include_bytes!("../../../../binding/pins/compiled-research-vk.bin");
    let checked = binding::ConfiguredResearchGate::with_trusted_key(
        compiled::COMPILED_DOMAIN, key, compiled::COMPILED_KEY_SHA256,
    )?;
    let compiled = CompiledResearchGate::new()?;
    let expected = checked.verify(&input)?;
    let actual = compiled.verify(&input)?;
    if actual != expected
        || h::sha(&actual.projection) != "70d89b257a6ec611db4775b4c8b0c0db2372cf8f75d084325be89d7d455c6cca"
    {
        return Err("fresh checked/compiled or independent projection mismatch".into());
    }
    let mut changed = input.clone();
    changed[binding::PROJECTION_LEN + 40] ^= 1;
    changed[binding::PROJECTION_LEN + binding::BUNDLE_LEN + 40] ^= 1;
    for error in [checked.verify(&changed).unwrap_err(), compiled.verify(&changed).unwrap_err()] {
        if error != binding::Error::InnerProof("invalid proof") {
            return Err("genuine altered authorization failed at an unexpected layer".into());
        }
    }
    let start = binding::PROJECTION_LEN + binding::AUTH_LEN;
    for identity in [false, true] {
        let mut changed = input.clone();
        if identity {
            let mut proof = Proof::<Bn254>::deserialize_compressed(&changed[start..start + binding::PROOF_LEN])?;
            proof.a = Default::default();
            let mut encoded = Vec::new();
            proof.serialize_compressed(&mut encoded)?;
            changed[start..start + binding::PROOF_LEN].copy_from_slice(&encoded);
        } else {
            changed[start..start + binding::PROOF_LEN].fill(255);
        }
        if checked.verify(&changed).is_ok() {
            return Err("checked reference accepted malformed/identity proof".into());
        }
        let reason = if identity { "proof encoding/identity" } else { "malformed proof" };
        if compiled.verify(&changed).unwrap_err() != binding::Error::InnerProof(reason) {
            return Err("compiled submitted-proof rejection changed".into());
        }
    }
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    h::save(out, "projection.bin", &actual.projection)?;
    h::save(out, "binding-journal42.bin", &actual.journal)?;
    let report = json!({"fresh_checked_and_compiled_equivalent":true,
        "input_sha256":h::sha(&input),"projection_sha256":h::sha(&actual.projection),
        "genuine_changed_authorization_rejected":"invalid proof",
        "malformed_and_identity_submitted_proofs_rejected":true,
        "native_context_checked":false,"guest_execution":false,"outer_proof":false});
    h::save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
