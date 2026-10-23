//! One explicitly selected development PK; never a general unchecked prover.
mod selected_key;

use kpi_future_private_payment::{
    self as payment,
    circuit::{InputWitness, TransferCircuit},
};
use selected_key::{Result, digest};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    real: bool,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    dummy_key_hex32: String,
    dummy_seed_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    note_hex168: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    classification: String,
    auth_hex484: String,
    inputs: [Input; 2],
    outputs: [Output; 2],
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s)?;
    if hex::encode(&bytes) != s {
        return Err("noncanonical hex".into());
    }
    bytes.try_into().map_err(|_| "fixed width".into())
}

// Same deny_unknown_fields and exact widths as the frozen baseline schema.
// There is no S7, old PK, native VM, wallet or network dependency here.
fn circuit_from_bytes(bytes: &[u8]) -> Result<TransferCircuit> {
    let fixture: Fixture = serde_json::from_slice(bytes)?;
    if fixture.classification != "PUBLIC_SYNTHETIC_DO_NOT_FUND" {
        return Err("public synthetic identity required".into());
    }
    let mut inputs = Vec::new();
    for i in fixture.inputs {
        let mut path = [[0; 32]; 16];
        for (to, from) in path.iter_mut().zip(&i.cm_path_hex) {
            *to = fixed(from)?;
        }
        inputs.push(InputWitness {
            real: i.real,
            note: payment::Note::parse(&fixed::<168>(&i.note_hex168)?)?,
            owner_secret: fixed(&i.s_hex32)?,
            nullifier_secret: fixed(&i.k_hex32)?,
            position: i.position,
            path,
            dummy_key: fixed(&i.dummy_key_hex32)?,
            dummy_seed: fixed(&i.dummy_seed_hex32)?,
        });
    }
    Ok(TransferCircuit {
        authorization: payment::Authorization::parse(&fixed::<484>(&fixture.auth_hex484)?)?,
        inputs: inputs.try_into().map_err(|_| "input count")?,
        outputs: [
            payment::Note::parse(&fixed::<168>(&fixture.outputs[0].note_hex168)?)?,
            payment::Note::parse(&fixed::<168>(&fixture.outputs[1].note_hex168)?)?,
        ],
    })
}

fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn parse_args() -> Result<(String, PathBuf, Option<PathBuf>, PathBuf)> {
    let args: Vec<_> = std::env::args_os().collect();
    let mode = args
        .get(1)
        .and_then(|s| s.to_str())
        .ok_or("mode loader-only/prove")?;
    match (mode, args.len()) {
        ("loader-only", 4) => Ok((mode.into(), (&args[2]).into(), None, (&args[3]).into())),
        ("prove", 5) => Ok((
            mode.into(),
            (&args[2]).into(),
            Some((&args[3]).into()),
            (&args[4]).into(),
        )),
        _ => Err(
            "usage: loader-only SELECTION_JSON NEW_OUT | prove SELECTION_JSON FIXTURE_JSON NEW_OUT"
                .into(),
        ),
    }
}

fn main() -> Result<()> {
    let total = Instant::now();
    let (mode, selection, fixture, out) = parse_args()?;
    // Atomically refuse an existing output path, including prior failed stages.
    fs::create_dir(&out)?;
    let mut times = Map::<String, Value>::new();
    let mut report = json!({
        "schema": "kpx2-selected-development-prover-result/v1",
        "identity": selected_key::IDENTITY,
        "classification": "PUBLIC_SYNTHETIC_DO_NOT_FUND",
        "mode": mode,
        "selected_metadata_sha256": selected_key::SELECTION_SHA256,
        "selected_pk_sha256": selected_key::PK_SHA256,
        "selected_pk_bytes": selected_key::PK_LEN,
        "selected_vk_sha256": selected_key::VK_SHA256,
        "pk_serialization": "arkworks0.6 compressed",
        "trusted_pk_validation": "exact full-byte compiled root pin after retained checked baseline",
        "untrusted_proof_and_vk_checks": "original fully checked payment library unchanged",
        "accepted_chain_backing": false,
        "native_context_checked_here": false,
        "privacy_qualified": false,
        "R8_qualified": false,
    });
    let outcome: Result<()> = (|| {
        let circuit = if let Some(path) = fixture {
            let started = Instant::now();
            let bytes = fs::read(path)?;
            let circuit = circuit_from_bytes(&bytes)?;
            report["fixture_sha256"] = digest(&bytes).into();
            report["authorization_sha256"] = digest(&circuit.authorization.bytes()).into();
            times.insert(
                "fixture_read_parse_seconds".into(),
                started.elapsed().as_secs_f64().into(),
            );
            Some(circuit)
        } else {
            None
        };
        let load_started = Instant::now();
        let pk = selected_key::load(&selection, &mut times)?;
        times.insert(
            "total_selected_pk_load_seconds".into(),
            load_started.elapsed().as_secs_f64().into(),
        );
        report["owned_encoded_pk_buffer_dropped_before_proving"] = true.into();
        report["selected_pk_loaded"] = true.into();

        save_new(&out.join("verification-key.bin"), selected_key::SELECTED_VK)?;
        if let Some(circuit) = circuit {
            let auth = circuit.authorization.clone();
            let started = Instant::now();
            // This API includes its own original fully checked proof verification.
            // Report it honestly as proving PLUS library verification, not pure MSM.
            let proof = payment::prove(&pk, circuit, &mut rand::rngs::OsRng)?;
            times.insert(
                "prove_and_library_verification_seconds".into(),
                started.elapsed().as_secs_f64().into(),
            );
            let started = Instant::now();
            // Persist genuine returned bytes before the separate final check.
            save_new(&out.join("proof128.bin"), &proof)?;
            save_new(&out.join("authorization484.bin"), &auth.bytes())?;
            fs::File::open(&out)?.sync_all()?;
            times.insert(
                "proof_candidate_save_fsync_seconds".into(),
                started.elapsed().as_secs_f64().into(),
            );
            let started = Instant::now();
            if !payment::Verifier::new(selected_key::SELECTED_VK)?.verify(&auth, &proof)? {
                return Err("fixed native VK genuine proof verification failed".into());
            }
            times.insert(
                "additional_checked_fixed_vk_verification_seconds".into(),
                started.elapsed().as_secs_f64().into(),
            );
            report["proof_sha256"] = digest(&proof).into();
            report["proof_hex128"] = hex::encode(proof).into();
            report["vk_hex328"] = hex::encode(selected_key::SELECTED_VK).into();
            report["genuine_Groth16_verified"] = true.into();
        }
        let started = Instant::now();
        drop(pk);
        times.insert(
            "decoded_pk_drop_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        Ok(())
    })();
    report["status"] = if outcome.is_ok() { "pass" } else { "fail" }.into();
    if let Err(ref error) = outcome {
        report["error"] = error.to_string().into();
    }
    report["phase_wall_seconds"] = times.into();
    report["total_before_report_save_seconds"] = total.elapsed().as_secs_f64().into();
    let encoded = serde_json::to_vec_pretty(&report)?;
    save_new(&out.join("report.json"), &encoded)?;
    fs::File::open(&out)?.sync_all()?;
    println!("{}", serde_json::to_string(&report)?);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_schema_and_hex_remain_strict() {
        assert!(fixed::<1>("AA").is_err());
        assert!(fixed::<1>("0000").is_err());
        assert_eq!(fixed::<1>("aa").unwrap(), [0xaa]);
        assert!(
            circuit_from_bytes(br#"{"classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND","extra":0}"#)
                .is_err()
        );
    }
}
