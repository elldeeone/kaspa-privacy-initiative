//! One separately frozen public development instance. No native settlement.
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kpi_private_note_proof as receipt_checks;
use kpi_two_v6_binding::{
    self as binding,
    compiled::{self, CompiledResearchGate},
};
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ExitCode, ProverOpts, Receipt,
};
use serde_json::json;
use std::{error::Error, fs, io::Write, path::Path, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Selected and frozen before execution, independently of program/output files.
const IMAGE: &str = "50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832";
const PROGRAM_SHA256: &str = "fa367c2d887a1a86ce23919f664af46dc418db0a2c79c2c62040c1526e8354cf";
const INPUT_SHA256: &str = "7771a2e610d37fdb12b1d668b8e229bd3cd1e5fe83c5993847daa0fef8c93b36";
const PUBLIC: &[u8] = include_bytes!("../pins/expected-public.bin");
const JOURNAL: &[u8] = include_bytes!("../pins/expected-journal.bin");
const JOIN: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
const CYCLE_LIMIT: u64 = 240_000_000;

fn sha(bytes: &[u8]) -> String {
    hex::encode(binding::sha256(bytes))
}
fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}
fn no_dev_mode() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("development mode must be absent".into());
    }
    Ok(())
}
fn host_key_preflight() -> Result<()> {
    CompiledResearchGate::new()?; // host cfg always fully checked key decoding
    Ok(())
}
fn public_input(path: &Path) -> Result<Vec<u8>> {
    let input = fs::read(path)?;
    if input.len() != binding::INPUT_LEN || sha(&input) != INPUT_SHA256 {
        return Err("compiled public fixture identity mismatch".into());
    }
    if PUBLIC.len() != binding::PROJECTION_LEN || JOURNAL.len() != binding::JOURNAL_LEN {
        return Err("compiled public projection/journal size".into());
    }
    let gate = CompiledResearchGate::new()?;
    let checked = gate.verify(&input)?;
    if checked.projection != PUBLIC || checked.journal != JOURNAL {
        return Err("compiled exact public projection/journal mismatch".into());
    }
    gate.check_publication(PUBLIC, JOURNAL)?;
    Ok(input)
}
fn program(path: &Path) -> Result<Vec<u8>> {
    let program = fs::read(path.join("guest.program.bin"))?;
    if sha(&program) != PROGRAM_SHA256 || compute_image_id(&program)?.to_string() != IMAGE {
        return Err("compiled expected guest/program mismatch".into());
    }
    Ok(program)
}
fn wrap(raw: &Path, out: &Path) -> Result<()> {
    host_key_preflight()?;
    let raw = fs::read(raw)?;
    let program =
        risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image = compute_image_id(&program)?;
    fs::create_dir(out)?;
    save(out, "guest.raw.elf", &raw)?;
    save(out, "guest.program.bin", &program)?;
    save(out, "derived-image.txt", format!("{image}\n").as_bytes())?;
    println!(
        "{}",
        json!({"derived_image":image.to_string(),"program_sha256":sha(&program),"raw_elf_sha256":sha(&raw),"trusted_image_selected":false})
    );
    Ok(())
}
fn env(input: &[u8]) -> Result<ExecutorEnv<'static>> {
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(input)
        .stdout(std::io::stdout())
        .segment_limit_po2(19)
        .session_limit(Some(CYCLE_LIMIT));
    Ok(builder.build()?)
}
fn mutate(input: &mut Vec<u8>, case: &str) -> Result<Option<String>> {
    let expected = match case {
        "valid" => return Ok(None),
        "trailing" => {
            input.push(0);
            "Length(\"complete input\")"
        }
        "truncated" => {
            input.pop();
            "Length(\"complete input\")"
        }
        "wrong-domain" => {
            input[12] ^= 1;
            "Profile(\"public projection\")"
        }
        "wrong-fee" => {
            input[76] ^= 1;
            "PublicBinding(\"aggregate fee\")"
        }
        "duplicate-output-index" => {
            input[binding::INPUT_LEN - 3] = input[binding::INPUT_LEN - 4];
            "Permutation(\"outputs\")"
        }
        "wrong-ciphertext" => {
            input[binding::PROJECTION_LEN + binding::AUTH_LEN + binding::PROOF_LEN] ^= 1;
            "CiphertextDigest"
        }
        "changed-count-both" => {
            input[binding::PROJECTION_LEN + 40] ^= 1;
            input[binding::PROJECTION_LEN + binding::BUNDLE_LEN + 40] ^= 1;
            "InnerProof(\"invalid proof\")"
        }
        "malformed-proof" => {
            input[binding::PROJECTION_LEN + binding::AUTH_LEN
                ..binding::PROJECTION_LEN + binding::AUTH_LEN + binding::PROOF_LEN]
                .fill(255);
            "InnerProof(\"malformed proof\")"
        }
        "identity-proof" => {
            let start = binding::PROJECTION_LEN + binding::AUTH_LEN;
            let mut proof =
                Proof::<Bn254>::deserialize_compressed(&input[start..start + binding::PROOF_LEN])?;
            proof.a = Default::default();
            let mut bytes = Vec::new();
            proof.serialize_compressed(&mut bytes)?;
            input[start..start + binding::PROOF_LEN].copy_from_slice(&bytes);
            "InnerProof(\"proof encoding/identity\")"
        }
        _ => return Err("unknown case".into()),
    };
    Ok(Some(expected.to_string()))
}
fn execute(programs: &Path, source: &Path, out: &Path, case: &str) -> Result<()> {
    no_dev_mode()?;
    let program = program(programs)?;
    let mut input = public_input(source)?;
    let expected_rejection = mutate(&mut input, case)?;
    fs::create_dir(out)?;
    save(out, "input.bin", &input)?;
    let start = Instant::now();
    let result = default_executor().execute(env(&input)?, &program);
    let mut report = json!({"schema":"kpi-two-v6-guest-execution-v1","scope":"NONSETTLING_EXECUTION_ONLY_NO_RECEIPT",
        "instance":compiled::INSTANCE_LABEL,"case":case,"image":IMAGE,"input_sha256":sha(&input),
        "seconds":start.elapsed().as_secs_f64(),"cycle_limit":CYCLE_LIMIT,"segment_po2":19,
        "expected_rejection":expected_rejection,"proof_generation":false,"native_settlement":false});
    let passed = match result {
        Ok(session) => {
            let journal_matches = session.journal.bytes == JOURNAL;
            report["cycles"] = json!(session.cycles());
            report["segments"] = json!(session.segments.iter().map(|s| s.po2).collect::<Vec<_>>());
            report["journal_matches"] = json!(journal_matches);
            report["exit_code"] = json!(format!("{:?}", session.exit_code));
            save(out, "journal.bin", &session.journal.bytes)?;
            expected_rejection.is_none()
                && journal_matches
                && session.exit_code == ExitCode::Halted(0)
        }
        Err(error) => {
            let message = format!("{error:#}");
            let matched = expected_rejection.as_ref().is_some_and(|expected| {
                message.contains(&format!("two-v6 binding rejection: {expected}"))
            });
            report["error"] = json!(message);
            matched
        }
    };
    report["passed"] = json!(passed);
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    if !passed {
        return Err("execution did not match declared result".into());
    }
    Ok(())
}
fn check_receipt(receipt: &Receipt) -> Result<()> {
    // Reuse the established SDK+official STARK callback. It authenticates the
    // decoded seal control against the independently expected join identity,
    // checks official allowed-root inclusion, successful claim, image, exact
    // journal and no unresolved assumptions, with development mode disabled.
    receipt_checks::verify_claim(
        receipt,
        receipt_checks::digest(IMAGE)?,
        JOURNAL,
        receipt_checks::digest(JOIN)?,
    )?;
    CompiledResearchGate::new()?.check_publication(PUBLIC, &receipt.journal.bytes)?;
    Ok(())
}
fn prove(programs: &Path, source: &Path, out: &Path) -> Result<()> {
    no_dev_mode()?;
    let program = program(programs)?;
    let input = public_input(source)?;
    fs::create_dir(out)?;
    save(
        out,
        "proof-started.json",
        &serde_json::to_vec_pretty(&json!({"scope":"NONSETTLING_TWO_V6_SUCCINCT_PROOF_ATTEMPT",
        "instance":compiled::INSTANCE_LABEL,"image":IMAGE,"program_sha256":PROGRAM_SHA256,"input_sha256":INPUT_SHA256,
        "projection_sha256":sha(PUBLIC),"journal_sha256":sha(JOURNAL),"expected_control":JOIN,
        "development_mode":false,"assumptions_supplied":0,"segment_po2":19,"cycle_limit":CYCLE_LIMIT}))?,
    )?;
    let start = Instant::now();
    let result = default_prover().prove_with_opts(env(&input)?, &program, &ProverOpts::succinct());
    let info = match result {
        Ok(info) => info,
        Err(error) => {
            save(
                out,
                "prover-error.json",
                &serde_json::to_vec_pretty(
                    &json!({"seconds":start.elapsed().as_secs_f64(),"error":format!("{error:#}")}),
                )?,
            )?;
            return Err(error.into());
        }
    };
    // Durably retain a returned candidate before verification or further checks.
    let bytes = bincode::serialize(&info.receipt)?;
    save(out, "candidate-receipt.bin", &bytes)?;
    save(
        out,
        "proof-stats.json",
        &serde_json::to_vec_pretty(&info.stats)?,
    )?;
    check_receipt(&info.receipt)?;
    save(out, "receipt.bin", &bytes)?;
    save(out, "public.bin", PUBLIC)?;
    save(out, "journal.bin", JOURNAL)?;
    save(
        out,
        "proof-complete.json",
        &serde_json::to_vec_pretty(&json!({"scope":"REAL_NONSETTLING_TWO_V6_SUCCINCT_RECEIPT",
        "instance":compiled::INSTANCE_LABEL,"image":IMAGE,"expected_control":JOIN,"proof_seconds":start.elapsed().as_secs_f64(),
        "receipt_sha256":sha(&bytes),"receipt_bytes":bytes.len(),"stats":info.stats,"native_settlement":false,
        "independent_verification_still_required":true}))?,
    )?;
    Ok(())
}
fn verify(path: &Path, out: &Path) -> Result<()> {
    no_dev_mode()?;
    let receipt = receipt_checks::read_receipt(path)?;
    check_receipt(&receipt)?;
    let negatives = receipt_checks::crypto_negatives(&receipt, receipt_checks::digest(IMAGE)?)?;
    fs::create_dir(out)?;
    save(out, "public.bin", PUBLIC)?;
    save(out, "journal.bin", JOURNAL)?;
    save(
        out,
        "verified.json",
        &serde_json::to_vec_pretty(
            &json!({"scope":"INDEPENDENT_SOFTWARE_NONSETTLING_RECEIPT_VERIFICATION",
        "instance":compiled::INSTANCE_LABEL,"image":IMAGE,"expected_control":JOIN,"journal_bytes":JOURNAL.len(),
        "projection_bytes":PUBLIC.len(),"receipt_sha256":sha(&fs::read(path)?),"negatives":negatives,
        "native_settlement":false,"development_mode":false,"no_unresolved_assumptions":true}),
        )?,
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("validate-key") if args.len()==2=>{
            host_key_preflight()?;
            println!("{}",json!({"checked_compiled_key":true,"instance":compiled::INSTANCE_LABEL,
                "domain":hex::encode(compiled::COMPILED_DOMAIN),"vk_sha256":hex::encode(compiled::COMPILED_KEY_SHA256)}));Ok(())
        },
        Some("check-target") if args.len()==4=>{
            program(Path::new(&args[2]))?;public_input(Path::new(&args[3]))?;
            println!("{}",json!({"target_verified":true,"image":IMAGE,"input_sha256":INPUT_SHA256,"journal_sha256":sha(JOURNAL),"proof_started":false}));Ok(())
        },
        Some("wrap") if args.len()==4=>wrap(Path::new(&args[2]),Path::new(&args[3])),
        Some("execute") if args.len()==6=>execute(Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4]),&args[5]),
        Some("prove") if args.len()==5=>prove(Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4])),
        Some("verify") if args.len()==4=>verify(Path::new(&args[2]),Path::new(&args[3])),
        _=>Err("validate-key | check-target PROGRAMS INPUT | wrap RAW_ELF NEW_PROGRAMS | execute PROGRAMS INPUT NEW_OUTPUT CASE | prove PROGRAMS INPUT NEW_OUTPUT | verify RECEIPT NEW_OUTPUT".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const INPUT: &[u8] = include_bytes!("../../evidence/public-development/expected-input.bin");
    const KEY: &[u8] = include_bytes!("../../common/pins/compiled-research-vk.bin");

    #[test]
    fn original_checked_and_compiled_gates_agree_on_fresh_public_pair() {
        let reference = binding::ConfiguredResearchGate::with_trusted_key(
            compiled::COMPILED_DOMAIN,
            KEY,
            compiled::COMPILED_KEY_SHA256,
        )
        .unwrap();
        let compiled = CompiledResearchGate::new().unwrap();
        let expected = reference.verify(INPUT).unwrap();
        let actual = compiled.verify(INPUT).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.projection, PUBLIC);
        assert_eq!(actual.journal, JOURNAL);
        assert_eq!(sha(INPUT), INPUT_SHA256);
        let mut altered = INPUT.to_vec();
        mutate(&mut altered, "changed-count-both").unwrap();
        assert_eq!(
            reference.verify(&altered).unwrap_err(),
            binding::Error::InnerProof("invalid proof")
        );
        assert_eq!(
            compiled.verify(&altered).unwrap_err(),
            binding::Error::InnerProof("invalid proof")
        );
        for (case, expected) in [
            ("malformed-proof", "malformed proof"),
            ("identity-proof", "proof encoding/identity"),
        ] {
            let mut altered = INPUT.to_vec();
            mutate(&mut altered, case).unwrap();
            assert!(reference.verify(&altered).is_err());
            assert_eq!(
                compiled.verify(&altered).unwrap_err(),
                binding::Error::InnerProof(expected)
            );
        }
    }

    #[test]
    fn every_declared_guest_mutation_has_its_exact_native_rejection() {
        let compiled = CompiledResearchGate::new().unwrap();
        for case in [
            "trailing",
            "truncated",
            "wrong-domain",
            "wrong-fee",
            "duplicate-output-index",
            "wrong-ciphertext",
            "changed-count-both",
            "malformed-proof",
            "identity-proof",
        ] {
            let mut altered = INPUT.to_vec();
            let expected = mutate(&mut altered, case).unwrap().unwrap();
            assert_eq!(
                compiled.verify(&altered).unwrap_err().to_string(),
                expected,
                "case {case}"
            );
        }
    }

    #[test]
    fn fake_receipt_rejects_and_join_control_is_the_official_pinned_one() {
        let fake = Receipt::new(
            risc0_zkvm::InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(
                risc0_zkvm::ReceiptClaim::ok(
                    receipt_checks::digest(IMAGE).unwrap(),
                    JOURNAL.to_vec(),
                ),
            )),
            JOURNAL.to_vec(),
        );
        assert!(check_receipt(&fake).is_err());
        let control = risc0_circuit_recursion::control_id::POSEIDON2_CONTROL_IDS
            .iter()
            .find(|(name, _)| *name == "join.zkr")
            .unwrap()
            .1;
        assert_eq!(control, receipt_checks::digest(JOIN).unwrap());
    }
}
