//! Fixed public fixture only. No RPC, setup, private inputs, funding or proving.
use kpi_v6_guest_compat as compat;
use risc0_zkvm::{compute_image_id, default_executor, ExecutorEnv};
use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FIXTURE_DIR: &str = "poc/shared-pool/evidence/2026-10-20-two-input-tn10";
const SOURCE_TXID: &str = "aa87d613bf36c6da5dfda60dd371360f5b4cfdf455f5ce74ce9795ec996db0e7";
// Filled only after the first reviewed guest build, before any execution.
// This lives in the verifier executable, independently of the supplied program
// directory; replacing a program and its adjacent text file is insufficient.
const EXPECTED_GUEST_IMAGE: &str = "1f3b9b1785a11268432ffdd484b83ce5025315e23fc3aa9cf74e3c06e56026de";
const SOURCES: [(&str, &str); 3] = [
    (
        "rehearsal/descriptor.json",
        "795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac",
    ),
    (
        "verification-key.json",
        "4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf",
    ),
    (
        "rehearsal/chain-confirmed.json",
        "75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8",
    ),
];
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}
fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))?
        .write_all(bytes)?;
    Ok(())
}
fn original_bundle() -> Result<Vec<u8>> {
    let root = root().canonicalize()?;
    let mut sources = Vec::new();
    for (name, expected) in SOURCES {
        let path = root.join(FIXTURE_DIR).join(name);
        if path.canonicalize()? != path || !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err("public source path is not a regular unsymlinked file".into());
        }
        let raw = fs::read(path)?;
        if hex::encode(compat::sha256(&raw)) != expected {
            return Err("source digest mismatch".into());
        }
        sources.push(serde_json::from_slice::<Value>(&raw)?);
    }
    let descriptor = &sources[0];
    if descriptor["network"] != "testnet-10"
        || descriptor["vk_sha256"] != hex::encode(compat::VK_SHA256)
        || descriptor["genesis"]
            != "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370"
    {
        return Err("descriptor identity".into());
    }
    let key = hex::decode(sources[1]["hex"].as_str().ok_or("key hex")?)?;
    if compat::sha256(&key) != compat::VK_SHA256 || key.len() != 328 {
        return Err("key identity".into());
    }
    let rows = sources[2]["transactions"]
        .as_array()
        .ok_or("transaction rows")?;
    if rows.len() != 15 {
        return Err("row count".into());
    }
    let tx = &rows[6]["transaction"];
    if tx["id"] != SOURCE_TXID {
        return Err("source supplied transaction identity".into());
    }
    let payload = hex::decode(tx["payload"].as_str().ok_or("payload")?)?;
    let signature = hex::decode(
        tx["inputs"][0]["signatureScript"]
            .as_str()
            .ok_or("signatureScript")?,
    )?;
    if payload.len() != 5228
        || &payload[..8] != b"KPICR06\0"
        || signature.len() != 24709
        || signature[..2] != [0x4c, 0x80]
    {
        return Err("source framing".into());
    }
    let bundle = [&payload[8..385], &signature[2..130], &payload[385..755]].concat();
    for (bytes, expected) in [
        (
            &bundle[..377],
            "04beb1a621fc1c2a96da05e9eeda47cdc0b44c1b088ccdc677b908b93987a2af",
        ),
        (
            &bundle[377..505],
            "01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b",
        ),
    ] {
        if hex::encode(compat::sha256(bytes)) != expected {
            return Err("component identity".into());
        }
    }
    Ok(bundle)
}
fn prepare(out: &Path) -> Result<()> {
    let bundle = original_bundle()?;
    let journal =
        compat::verify_bundle(&bundle).map_err(|e| format!("native compatibility: {e}"))?;
    fs::create_dir(out)?;
    save(out, "bundle.bin", &bundle)?;
    save(out, "expected-journal.bin", &journal)?;
    save(
        out,
        "source.json",
        &serde_json::to_vec_pretty(&json!({
            "scope":"one public v6 bundle; host verification only", "source_commit":"6fdc5fc61ddd9b33c254acbc47316348d7d84503",
            "sources":SOURCES, "transaction_pointer":"/transactions/6/transaction", "source_supplied_txid":SOURCE_TXID,
            "consensus_id_recomputed":false, "bundle_sha256":hex::encode(compat::sha256(&bundle)),
            "vk_sha256":hex::encode(compat::VK_SHA256), "journal_hex":hex::encode(journal), "proof_generation":false
        }))?,
    )?;
    Ok(())
}
fn wrap(raw: &Path, out: &Path) -> Result<()> {
    let raw = fs::read(raw)?;
    let program =
        risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image = compute_image_id(&program)?;
    fs::create_dir(out)?;
    save(out, "guest.raw.elf", &raw)?;
    save(out, "guest.program.bin", &program)?;
    save(out, "expected-image.txt", format!("{image}\n").as_bytes())?;
    println!("{image}");
    Ok(())
}
fn execute(programs: &Path, out: &Path, case: &str) -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("RISC0_DEV_MODE must be absent".into());
    }
    let program = fs::read(programs.join("guest.program.bin"))?;
    let expected_image = fs::read_to_string(programs.join("expected-image.txt"))?;
    let image = compute_image_id(&program)?;
    if image.to_string() != expected_image.trim() || image.to_string() != EXPECTED_GUEST_IMAGE {
        return Err("expected image mismatch".into());
    }
    let mut bundle = original_bundle()?;
    let expected =
        compat::expected_journal(&bundle).map_err(|e| format!("expected journal: {e}"))?;
    let expected_error = match case {
        "valid" => None,
        "trailing" => {
            bundle.push(0);
            Some("bundle length")
        }
        "truncated" => {
            bundle.pop();
            Some("bundle length")
        }
        "wrong-domain" => {
            bundle[8] ^= 1;
            Some("authorization magic/domain")
        }
        "wrong-ciphertext" => {
            bundle[505] ^= 1;
            Some("ordered ciphertext digest")
        }
        "changed-count" => {
            bundle[40] ^= 1;
            Some("invalid proof")
        }
        _ => return Err("unknown execution case".into()),
    };
    fs::create_dir(out)?;
    save(out, "input.bin", &bundle)?;
    let mut builder = ExecutorEnv::builder();
    // Generous diagnostic limit. Exceeding it is an infrastructure/resource
    // failure, never cryptographic or malformed-input rejection evidence.
    builder
        .write_slice(&bundle)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(Some(160_000_000));
    let started = Instant::now();
    let result = default_executor().execute(builder.build()?, &program);
    let mut report = json!({"schema":"kpi-one-public-v6-guest-execution-v1", "case":case,
        "scope":"EXECUTION_ONLY_NOT_RECEIPT_OR_SETTLEMENT", "expected_image":image.to_string(),
        "seconds":started.elapsed().as_secs_f64(), "input_sha256":hex::encode(compat::sha256(&bundle)),
        "cycle_limit":160_000_000, "segment_po2":19, "proof_generation":false,
        "native_chain_acceptance":false, "expected_rejection":expected_error });
    let passed = match result {
        Ok(session) => {
            save(out, "journal.bin", &session.journal.bytes)?;
            report["cycles"] = json!(session.cycles());
            report["segments"] = json!(session.segments.iter().map(|s| s.po2).collect::<Vec<_>>());
            report["journal_hex"] = json!(hex::encode(&session.journal.bytes));
            report["journal_matches"] = json!(session.journal.bytes == expected);
            expected_error.is_none() && session.journal.bytes == expected
        }
        Err(error) => {
            let message = format!("{error:#}");
            report["error"] = json!(message);
            expected_error.is_some_and(|expected| {
                message.contains(&format!("v6 compatibility rejection: {expected}"))
            })
        }
    };
    report["passed"] = json!(passed);
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    if !passed {
        return Err("guest execution did not match the declared outcome".into());
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prepare") if args.len() == 3 => prepare(Path::new(&args[2])),
        Some("wrap") if args.len() == 4 => wrap(Path::new(&args[2]), Path::new(&args[3])),
        Some("execute") if args.len() == 5 => {
            execute(Path::new(&args[2]), Path::new(&args[3]), &args[4])
        }
        _ => Err(
            "prepare NEW_OUTPUT | wrap RAW_ELF NEW_PROGRAMS | execute PROGRAMS NEW_OUTPUT CASE"
                .into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    #[test]
    fn retained_public_proof_accepts_and_changed_public_input_rejects() {
        let bundle = original_bundle().unwrap();
        compat::verify_bundle(&bundle).unwrap();
        let mut inputs = compat::public_inputs(&bundle[..377]).unwrap();
        inputs[0] += ark_bn254::Fr::from(1u64);
        assert_eq!(
            compat::checked_key()
                .unwrap()
                .verify_inputs(&bundle[377..505], &inputs),
            Err("invalid proof")
        );
    }
    #[test]
    fn framing_profile_and_ordered_delivery_fail_closed() {
        let bundle = original_bundle().unwrap();
        for len in [0, 376, 377, 504, 505, 874] {
            assert!(compat::verify_bundle(&bundle[..len]).is_err());
        }
        let mut trailing = bundle.clone();
        trailing.push(0);
        assert_eq!(compat::verify_bundle(&trailing), Err("bundle length"));
        for byte in [
            0, 8, 204, 205, 212, 221, 256, 257, 264, 265, 300, 301, 336, 337, 344,
        ] {
            let mut altered = bundle.clone();
            altered[byte] ^= 1;
            assert!(
                compat::verify_bundle(&altered).is_err(),
                "changed byte {byte}"
            );
        }
        let mut swapped = bundle.clone();
        swapped[505..690].copy_from_slice(&bundle[690..875]);
        swapped[690..875].copy_from_slice(&bundle[505..690]);
        assert_eq!(
            compat::verify_bundle(&swapped),
            Err("ordered ciphertext digest")
        );
        for fee in [0, compat::MAX_SOMPI + 1, u64::MAX] {
            let mut changed = bundle.clone();
            changed[213..221].copy_from_slice(&fee.to_le_bytes());
            assert_eq!(compat::verify_bundle(&changed), Err("fee range"));
        }
    }
    #[test]
    fn identity_or_malformed_proof_cannot_qualify_as_pairing_rejection() {
        let bundle = original_bundle().unwrap();
        let key = compat::checked_key().unwrap();
        let inputs = compat::public_inputs(&bundle[..377]).unwrap();
        let original =
            Proof::<ark_bn254::Bn254>::deserialize_compressed(&bundle[377..505]).unwrap();
        for slot in 0..3 {
            let mut proof = original.clone();
            match slot {
                0 => proof.a = Default::default(),
                1 => proof.b = Default::default(),
                _ => proof.c = Default::default(),
            };
            let mut encoded = vec![];
            proof.serialize_compressed(&mut encoded).unwrap();
            assert_eq!(
                key.verify_inputs(&encoded, &inputs),
                Err("proof encoding/identity")
            );
        }
        assert_eq!(
            key.verify_inputs(&[0xff; 128], &inputs),
            Err("malformed proof")
        );
        assert_eq!(
            key.verify_inputs(&bundle[377..504], &inputs),
            Err("encoding/arity")
        );
        assert_eq!(
            key.verify_inputs(&bundle[377..505], &inputs[..1]),
            Err("encoding/arity")
        );
    }
}
