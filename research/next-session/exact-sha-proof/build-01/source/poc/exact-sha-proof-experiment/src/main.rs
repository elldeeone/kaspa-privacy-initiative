//! Isolated ADR0047 performance experiment: fresh parameters only, no key loader.
mod fixture;
use ark_serialize::CanonicalSerialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const FIXTURE_SHA: &str = "e59a1dd7f93c1bbe7c6176e589accc558efa97907411508a12f6cbdfbf704a06";
const OLD_VK_SHA: &str = "5f551fa7b0cbeb9ec89ccf0e198575b1803db4c8012919166436af625e0136bc";

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn selected_fixture(bytes: &[u8]) -> Result<payment::circuit::TransferCircuit> {
    if digest(bytes) != FIXTURE_SHA {
        return Err("primary public fixture identity mismatch".into());
    }
    fixture::circuit_from_bytes(bytes)
}
fn source_identity() -> Result<Value> {
    let inputs = [
        (
            "lib.rs",
            include_bytes!("../../exact-sha-cost-probe/src/lib.rs").as_slice(),
            "0e9c0e025c06d99d12c2a2b50d0f38161dee8b68880a28af1174c6438aa3c353",
        ),
        (
            "circuit.rs",
            include_bytes!("../../exact-sha-cost-probe/src/circuit.rs").as_slice(),
            "479146d51f3f20460d86867e45d9e14e1479f28e7bfcb584d0cab04117e83bf0",
        ),
        (
            "exact_sha256.rs",
            include_bytes!("../../exact-sha-cost-probe/src/exact_sha256.rs").as_slice(),
            "0f156c8611b64814b2b84de369bc03ab134992b8cd22831267b0d4c0c3a42751",
        ),
    ];
    let mut map = Map::new();
    for (name, bytes, expected) in inputs {
        if digest(bytes) != expected {
            return Err(format!("candidate source mismatch {name}").into());
        }
        map.insert(name.into(), expected.into());
    }
    Ok(map.into())
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
fn memory_snapshot() -> Result<Value> {
    let text = fs::read_to_string("/proc/self/status")?;
    let mut map = Map::new();
    for line in text.lines() {
        if line.starts_with("VmRSS:") || line.starts_with("VmHWM:") {
            let mut words = line.split_whitespace();
            let key = words.next().unwrap().trim_end_matches(':');
            let kib: u64 = words.next().ok_or("RSS field")?.parse()?;
            map.insert(format!("{key}_KiB"), kib.into());
        }
    }
    Ok(map.into())
}
fn main() -> Result<()> {
    let total = Instant::now();
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: kpi-exact-sha-proof-experiment PRIMARY_PUBLIC_FIXTURE NEW_OUT".into());
    }
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    let mut report = json!({"schema":"exact-sha-fresh-setup-proof-result/v1","classification":"PUBLIC_SYNTHETIC_DO_NOT_FUND",
        "source_identity":source_identity()?,"setup_rng":"OsRng","existing_PK_or_matrix_loaded":false,
        "native_checked_here":false,"accepted_chain_backing":false,"privacy_qualified":false,"p95_qualified":false,
        "warm_target_seconds":10,"wallet_memory_target_bytes":4294967296u64});
    let mut times = Map::new();
    let outcome: Result<()> = (|| {
        let raw = fs::read(&args[1])?;
        let circuit = selected_fixture(&raw)?;
        let auth = circuit.authorization.clone();
        report["fixture_sha256"] = FIXTURE_SHA.into();
        report["authorization_sha256"] = digest(&auth.bytes()).into();
        let mut fingerprint = Sha256::new();
        fingerprint.update(b"KPX2/fresh-optimized-source-and-shape/v1\0");
        fingerprint.update(serde_json::to_vec(&report["source_identity"])?);
        fingerprint.update(&raw);
        report["source_fixture_shape_fingerprint_sha256"] =
            hex::encode(fingerprint.finalize()).into();

        save_new(
            &out.join("phase-setup"),
            b"fresh setup starts; no imported PK/matrices\n",
        )?;
        let started = Instant::now();
        let pk = payment::setup(circuit.clone(), &mut rand::rngs::OsRng)?;
        times.insert(
            "fresh_setup_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        report["after_setup_memory"] = memory_snapshot()?;
        // These dimensions distinguish the optimized matrices from the old
        // 4,650,533-constraint parameters. No raw matrix digest is claimed.
        if pk.a_query.len() != 3_459_644
            || pk.b_g1_query.len() != 3_459_644
            || pk.b_g2_query.len() != 3_459_644
            || pk.l_query.len() != 3_459_641
            || pk.h_query.len() != 4_194_303
            || pk.vk.gamma_abc_g1.len() != 3
        {
            return Err("fresh optimized matrix/query shape mismatch".into());
        }
        report["matrix_construction_identity"] = json!({"prior_measured_constraints":3497893,
            "instances_including_one":3,"witness_variables":3459641,"fft_domain":4194304,
            "a_query":pk.a_query.len(),"b_g1_query":pk.b_g1_query.len(),"b_g2_query":pk.b_g2_query.len(),
            "l_query":pk.l_query.len(),"h_query":pk.h_query.len(),"raw_matrix_digest":null,
            "identity_scope":"Pinned source+fixture+fresh setup construction and actual query dimensions; no imported or saved matrix input"});
        let vk = payment::verification_key(&pk)?;
        if digest(&vk) == OLD_VK_SHA {
            return Err("refuse old parameter VK".into());
        }
        report["fresh_vk_sha256"] = digest(&vk).into();
        save_new(&out.join("verification-key.bin"), &vk)?;
        save_new(
            &out.join("phase-proof"),
            b"one genuine proof from resident fresh PK\n",
        )?;
        let started = Instant::now();
        let proof = payment::prove(&pk, circuit, &mut rand::rngs::OsRng)?;
        times.insert(
            "resident_prove_and_original_verification_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        report["after_proof_memory"] = memory_snapshot()?;
        save_new(&out.join("proof128.bin"), &proof)?;
        save_new(&out.join("authorization484.bin"), &auth.bytes())?;
        let started = Instant::now();
        if !payment::Verifier::new(&vk)?.verify(&auth, &proof)? {
            return Err("genuine fresh VK verification failed".into());
        }
        times.insert(
            "additional_checked_verification_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        report["genuine_Groth16_verified"] = true.into();
        report["proof_sha256"] = digest(&proof).into();

        save_new(
            &out.join("phase-serialize"),
            b"official uncompressed output after proof\n",
        )?;
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(out.join("fresh-optimized.pk"))?;
        let started = Instant::now();
        let mut writer = BufWriter::new(file);
        pk.serialize_uncompressed(&mut writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        let mut file = writer.into_inner()?;
        times.insert(
            "official_uncompressed_serialize_fsync_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let pk_bytes = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;
        let started = Instant::now();
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut consumed = 0;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            consumed += n as u64;
        }
        if consumed != pk_bytes {
            return Err("fresh PK complete hash length mismatch".into());
        }
        times.insert(
            "full_uncompressed_pk_sha256_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        report["local_only_uncompressed_pk_sha256"] = hex::encode(hasher.finalize()).into();
        report["local_only_uncompressed_pk_bytes"] = pk_bytes.into();
        report["after_serialization_memory"] = memory_snapshot()?;
        drop(pk);
        Ok(())
    })();
    report["status"] = if outcome.is_ok() { "pass" } else { "fail" }.into();
    if let Err(ref error) = outcome {
        report["error"] = error.to_string().into();
    }
    report["phase_wall_seconds"] = times.into();
    report["total_seconds"] = total.elapsed().as_secs_f64().into();
    save_new(
        &out.join("report.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    fs::File::open(out)?.sync_all()?;
    println!("{}", serde_json::to_string(&report)?);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_candidate_sources_match() {
        source_identity().unwrap();
    }
    #[test]
    fn wrong_fixture_rejects_before_json_parsing() {
        assert_eq!(
            selected_fixture(b"not JSON").err().unwrap().to_string(),
            "primary public fixture identity mismatch"
        );
    }
    #[test]
    fn selected_primary_both_real_fixture_has_expected_transcript() {
        let circuit = selected_fixture(include_bytes!("../../../research/next-session/private-integration/lifecycle/materialized-01/private-fixture.json")).unwrap();
        assert!(circuit.inputs.iter().all(|i| i.real));
        assert!(circuit.outputs.iter().all(|o| o.value == 1_000_000_000));
        assert_eq!(
            digest(&circuit.authorization.bytes()),
            "f686cf1ce6d66f7a5c65a04890b0dcadbf293eb35b9fd9c33962e508269c318a"
        );
    }
}
