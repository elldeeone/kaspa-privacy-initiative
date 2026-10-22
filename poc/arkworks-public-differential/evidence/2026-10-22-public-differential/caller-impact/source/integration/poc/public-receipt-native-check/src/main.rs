//! Offline native predicate qualification. No transaction, UTXO, covenant or network acceptance.
use bincode::Options;
use kaspa_consensus_core::{hashing::sighash::SigHashReusedValuesUnsync, tx::PopulatedTransaction};
use kaspa_txscript::{
    caches::Cache,
    opcodes::codes::{OpTrue, OpVerify, OpZkPrecompile},
    script_builder::ScriptBuilder,
    zk_deps::{
        ark_bn254::{Bn254, G1Affine, G2Affine},
        ark_groth16::{Proof, VerifyingKey},
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    },
    zk_precompiles::{groth16::Groth16Error, risc0::R0Error},
    EngineFlags, TxScriptEngine,
};
use kaspa_txscript_errors::TxScriptError;
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::{
    sha::{Digest, Digestible, Sha256},
    Groth16ReceiptVerifierParameters, Receipt, ReceiptClaim,
};
use serde_json::{json, Value};
use std::{error::Error, fs, io::Write, path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NATIVE_REV: &str = "01b532e8b553523216471682649693af92f0fd16";
const IMAGE: &str = "50ceec8ebb91edd01028c4aec9b495e7d77eb9e3b39e065910c0600f7693d832";
const PROGRAM_SHA: &str = "fa367c2d887a1a86ce23919f664af46dc418db0a2c79c2c62040c1526e8354cf";
const JOURNAL_SHA: &str = "5d667b709f35191c6fc98e6aa0b79bd934e39a40ef4edfea582fcef3b06d4ac7";
const JOIN: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
const LIFT20: &str = "34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734";
const HISTORICAL_IMAGE: &str = "52c214c2a4789cb882ac7f4c25996bcba3e0693dec1c8c0c1c093f262dcc6cf0";
const HISTORICAL_RECEIPT_SHA: &str =
    "3097795146ed147c2b4c3710b6ad4bcb52291a4ec65c473bdb92aaae0480ab2a";
const JOURNAL: &[u8; 42] = include_bytes!("../pins/expected-journal.bin");
const HISTORICAL_JOURNAL: &[u8; 352] = include_bytes!("../pins/historical-journal.bin");
const MAX_RECEIPT_BYTES: u64 = 24 * 1024 * 1024;

fn hash(bytes: &[u8]) -> String {
    risc0_zkvm::sha::Impl::hash_bytes(bytes).to_string()
}
fn digest(text: &str) -> Result<Digest> {
    Ok(hex::decode(text)?.as_slice().try_into()?)
}
fn bytes32(text: &str) -> Result<[u8; 32]> {
    Ok(digest(text)?.into())
}
fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(name))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn read_receipt(path: &Path) -> Result<(Receipt, Vec<u8>)> {
    if fs::metadata(path)?.len() > MAX_RECEIPT_BYTES {
        return Err("receipt exceeds 24 MiB parser bound".into());
    }
    let raw = fs::read(path)?;
    let receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES)
        .reject_trailing_bytes()
        .deserialize(&raw)?;
    Ok((receipt, raw))
}

/// Adapted from kaspanet/vprogs f9b84a8 api/src/witness.rs (ISC; see NOTICE).
/// Expected image/control/journal are separately compiled pins, never receipt metadata.
#[derive(Clone)]
struct OwnedSuccinctWitness {
    seal: Vec<u8>,
    claim: [u8; 32],
    index: u32,
    inclusion: Vec<u8>,
}
impl OwnedSuccinctWitness {
    fn from_receipt(receipt: &Receipt) -> Result<Self> {
        let s = receipt.inner.succinct()?;
        Ok(Self {
            seal: s.seal.iter().flat_map(|w| w.to_le_bytes()).collect(),
            claim: s.claim.digest().into(),
            index: s.control_inclusion_proof.index,
            inclusion: s
                .control_inclusion_proof
                .digests
                .iter()
                .flat_map(|d| <[u8; 32]>::from(*d))
                .collect(),
        })
    }
}

/// The upstream witness point conversion, with fallible checked decoding and shape checks.
fn g1_from_bytes(p: &[Vec<u8>]) -> Result<G1Affine> {
    if p.len() != 2 || p.iter().any(|x| x.len() != 32) {
        return Err("malformed RISC0 G1 coordinate shape".into());
    }
    let bytes: Vec<u8> = p[0]
        .iter()
        .rev()
        .chain(p[1].iter().rev())
        .copied()
        .collect();
    Ok(G1Affine::deserialize_uncompressed(bytes.as_slice())?)
}
fn g2_from_bytes(p: &[Vec<Vec<u8>>]) -> Result<G2Affine> {
    if p.len() != 2
        || p.iter()
            .any(|x| x.len() != 2 || x.iter().any(|y| y.len() != 32))
    {
        return Err("malformed RISC0 G2 coordinate shape".into());
    }
    let bytes: Vec<u8> = p[0][1]
        .iter()
        .rev()
        .chain(p[0][0].iter().rev())
        .chain(p[1][1].iter().rev())
        .chain(p[1][0].iter().rev())
        .copied()
        .collect();
    Ok(G2Affine::deserialize_uncompressed(bytes.as_slice())?)
}
struct OwnedGroth16Witness {
    compressed_proof: Vec<u8>,
}
impl OwnedGroth16Witness {
    fn from_receipt(receipt: &Receipt) -> Result<Self> {
        let seal = risc0_groth16::Seal::decode(&receipt.inner.groth16()?.seal)?;
        let proof = Proof::<Bn254> {
            a: g1_from_bytes(&seal.a)?,
            b: g2_from_bytes(&seal.b)?,
            c: g1_from_bytes(&seal.c)?,
        };
        let mut compressed_proof = Vec::new();
        proof.serialize_compressed(&mut compressed_proof)?;
        if compressed_proof.len() != 128 {
            return Err("unexpected native proof size".into());
        }
        Ok(Self { compressed_proof })
    }
}

fn split_digest(d: Digest) -> [[u8; 32]; 2] {
    // Exact covenant/build.rs encoding; not modular reduction or a new claim hash.
    std::array::from_fn(|i| {
        let mut scalar = [0u8; 32];
        scalar[..16].copy_from_slice(&d.as_bytes()[i * 16..i * 16 + 16]);
        scalar
    })
}
fn expected_claim(image: [u8; 32], journal: &[u8]) -> Digest {
    ReceiptClaim::ok(Digest::from(image), journal.to_vec()).digest()
}
fn groth16_inputs(image: [u8; 32], journal: &[u8], wrong_control: bool) -> [[u8; 32]; 5] {
    let p = Groth16ReceiptVerifierParameters::default();
    let [a0, a1] = split_digest(p.control_root);
    let [c0, c1] = split_digest(expected_claim(image, journal));
    let mut id: [u8; 32] = p.bn254_control_id.into();
    if wrong_control {
        id[0] ^= 1;
    }
    [a0, a1, c0, c1, id]
}
fn fixed_groth16_key() -> Result<Vec<u8>> {
    // Official fixed VK: serde newtype contains canonical uncompressed Arkworks bytes.
    // Decode its Vec envelope rather than depending on an unchecked eight-byte skip.
    let envelope = bincode::serialize(&risc0_groth16::verifying_key())?;
    let raw: Vec<u8> = bincode::deserialize(&envelope)?;
    let mut reader = raw.as_slice();
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader)?;
    if !reader.is_empty() || vk.gamma_abc_g1.len() != 6 {
        return Err("unexpected fixed RISC0 Groth16 key shape".into());
    }
    let mut roundtrip = Vec::new();
    vk.serialize_uncompressed(&mut roundtrip)?;
    if roundtrip != raw {
        return Err("noncanonical fixed key encoding".into());
    }
    let mut compressed = Vec::new();
    vk.serialize_compressed(&mut compressed)?;
    if compressed.len() != 424 {
        return Err("unexpected fixed key size".into());
    }
    Ok(compressed)
}

fn succinct_script(
    w: &OwnedSuccinctWitness,
    image: [u8; 32],
    journal: [u8; 32],
    control: [u8; 32],
) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    for d in [
        &w.claim[..],
        &w.index.to_le_bytes(),
        &w.inclusion,
        &w.seal,
        &journal,
        &image,
        &control,
        &[1],
        &[0x21],
    ] {
        b.add_data(d)?;
    }
    b.add_ops(&[OpZkPrecompile, OpVerify, OpTrue])?;
    Ok(b.drain())
}
fn groth16_script(proof: &[u8], vk: &[u8], inputs: &[[u8; 32]; 5]) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    for input in inputs.iter().rev() {
        b.add_data(input)?;
    }
    b.add_i64(5)?
        .add_data(proof)?
        .add_data(vk)?
        .add_data(&[0x20])?
        .add_ops(&[OpZkPrecompile, OpVerify, OpTrue])?;
    Ok(b.drain())
}
fn native_case(
    label: &str,
    layer: &str,
    script: &[u8],
    expected_error: Option<TxScriptError>,
) -> (Value, bool) {
    let cache = Cache::new(1);
    let reused = SigHashReusedValuesUnsync::new();
    let mut vm = TxScriptEngine::<PopulatedTransaction<'_>, _>::from_script(
        script,
        &reused,
        &cache,
        EngineFlags::default(),
    );
    let start = Instant::now();
    let outcome = vm.execute();
    let seconds = start.elapsed().as_secs_f64();
    let units = vm.used_script_units().0;
    let accepted = outcome.is_ok();
    // Match the exact source-derived variant and inner error per control. A nested
    // meter/setup failure inside ZkIntegrity must not count as proof rejection.
    let matched = match (&outcome, &expected_error) {
        (Ok(()), None) => true,
        (Err(actual), Some(expected)) => actual == expected,
        _ => false,
    };
    (
        json!({"case":label,"verification_layer":layer,"expected_accept":expected_error.is_none(),"accepted":accepted,
        "expected_error":expected_error.map(|e|e.to_string()),
        "matched_expectation":matched,"native_script_bytes":script.len(),
        "native_script_sha256":hash(script),"used_script_units":units,
        "script_units_rounded_to_grams":units.div_ceil(100),
        "bare_predicate_min_covering_compute_budget":units / 10_000,
        "bare_predicate_committed_budget_grams":(units / 10_000) * 100,
        "seconds":seconds,"error":outcome.err().map(|e|e.to_string())}),
        matched,
    )
}

fn run() -> Result<()> {
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("RISC0_DEV_MODE must be absent".into());
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: kpi-public-receipt-native-check verify-succinct|verify-groth16|qualify-historical-succinct RECEIPT NEW_OUTPUT_DIR".into());
    }
    if hash(JOURNAL) != JOURNAL_SHA {
        return Err("compiled J42 pin mismatch".into());
    }
    let historical = args[1] == "qualify-historical-succinct";
    let groth16 = args[1] == "verify-groth16";
    if !historical && !groth16 && args[1] != "verify-succinct" {
        return Err("unknown command".into());
    }
    let (receipt, raw) = read_receipt(Path::new(&args[2]))?;
    let expected_journal: &[u8] = if historical {
        HISTORICAL_JOURNAL
    } else {
        JOURNAL
    };
    let image_text = if historical { HISTORICAL_IMAGE } else { IMAGE };
    let control_text = if historical { LIFT20 } else { JOIN };
    if historical && hash(&raw) != HISTORICAL_RECEIPT_SHA {
        return Err("historical qualification requires the exact retained public receipt".into());
    }
    if receipt.journal.bytes != expected_journal {
        return Err("receipt journal differs from compiled expected bytes".into());
    }
    let image = bytes32(image_text)?;
    let mut results = Vec::new();
    let mut matched = true;
    let out = Path::new(&args[3]);
    fs::create_dir(out)?; // Refuse to reuse any result identity.
    let labels: &[&str] = if groth16 {
        &[
            "valid",
            "wrong-image",
            "wrong-journal",
            "wrong-control",
            "bad-proof",
            "truncated-proof",
            "trailing-proof",
            "trailing-vk",
        ]
    } else {
        &[
            "valid",
            "wrong-image",
            "wrong-journal",
            "wrong-control",
            "bad-seal",
            "bad-inclusion",
            "truncated-inclusion",
            "wrong-control-index",
            "wrong-claim",
        ]
    };
    let mut fields = json!({});
    if groth16 {
        let w = OwnedGroth16Witness::from_receipt(&receipt)?;
        let vk = fixed_groth16_key()?;
        save(out, "proof.compressed.bin", &w.compressed_proof)?;
        save(out, "vk.compressed.bin", &vk)?;
        let inputs = groth16_inputs(image, expected_journal, false);
        save(out, "public-inputs.le.bin", &inputs.concat())?;
        fields = json!({"compressed_proof_bytes":w.compressed_proof.len(),
            "compressed_proof_sha256":hash(&w.compressed_proof),"compressed_vk_bytes":vk.len(),
            "compressed_vk_sha256":hash(&vk),"public_inputs_le":inputs.map(hex::encode),
            "fixed_verifier_parameters_digest":Groth16ReceiptVerifierParameters::default().digest().to_string(),
            "receipt_claim_digest":expected_claim(image, expected_journal).to_string()});
        for label in labels {
            let mut proof = w.compressed_proof.clone();
            let mut key = vk.clone();
            let mut changed_image = image;
            let mut journal = expected_journal.to_vec();
            match *label {
                "wrong-image" => changed_image[0] ^= 1,
                "wrong-journal" => journal[0] ^= 1,
                "bad-proof" => {
                    // Established group operation: keep a valid canonical point,
                    // change the pairing relation instead of failing point parsing.
                    let mut p = Proof::<Bn254>::deserialize_compressed(proof.as_slice())?;
                    p.a = -p.a;
                    proof.clear();
                    p.serialize_compressed(&mut proof)?;
                }
                "truncated-proof" => {
                    proof.pop();
                }
                "trailing-proof" => proof.push(0),
                "trailing-vk" => key.push(0),
                "valid" | "wrong-control" => {}
                _ => unreachable!(),
            }
            let inputs = groth16_inputs(changed_image, &journal, *label == "wrong-control");
            let script = groth16_script(&proof, &key, &inputs)?;
            let expected = match *label {
                "valid" => None,
                "truncated-proof" => Some(Groth16Error::ArkSerialization(
                    Proof::<Bn254>::deserialize_compressed(proof.as_slice())
                        .expect_err("truncated proof must fail checked framing"),
                )),
                "trailing-proof" => Some(Groth16Error::TrailingProofBytes),
                "trailing-vk" => Some(Groth16Error::TrailingVerifyingKeyBytes),
                _ => Some(Groth16Error::VerificationFailed),
            }
            .map(|e| TxScriptError::ZkIntegrity(e.to_string()));
            let layer = if matches!(*label, "truncated-proof" | "trailing-proof" | "trailing-vk") {
                "native-canonical-framing"
            } else {
                "native-pairing-relation"
            };
            if *label == "valid" {
                save(out, "valid-native-script.bin", &script)?;
            }
            let (result, ok) = native_case(label, layer, &script, expected);
            matched &= ok;
            results.push(result);
        }
    } else {
        let base = OwnedSuccinctWitness::from_receipt(&receipt)?;
        fields["seal_bytes"] = json!(base.seal.len());
        fields["control_inclusion_bytes"] = json!(base.inclusion.len());
        fields["receipt_control_metadata"] =
            json!(receipt.inner.succinct()?.control_id.to_string());
        fields["receipt_hashfn_metadata"] = json!(receipt.inner.succinct()?.hashfn);
        for label in labels {
            let mut w = base.clone();
            let mut im = image;
            let mut journal: [u8; 32] =
                (*risc0_zkvm::sha::Impl::hash_bytes(expected_journal)).into();
            let mut control = bytes32(control_text)?;
            match *label {
                "wrong-image" => im[0] ^= 1,
                "wrong-journal" => journal[0] ^= 1,
                "wrong-control" => control[0] ^= 1,
                "bad-seal" => *w.seal.first_mut().ok_or("empty seal")? ^= 1,
                "bad-inclusion" => *w.inclusion.first_mut().ok_or("empty inclusion")? ^= 1,
                "truncated-inclusion" => {
                    w.inclusion.pop();
                }
                "wrong-control-index" => w.index ^= 1,
                "wrong-claim" => w.claim[0] ^= 1,
                "valid" => {}
                _ => unreachable!(),
            }
            let script = succinct_script(&w, im, journal, control)?;
            let expected = match *label {
                "valid" => None,
                "wrong-image" | "wrong-journal" => Some(R0Error::VerificationFailed),
                "wrong-control" | "bad-inclusion" | "wrong-control-index" => {
                    Some(R0Error::R0(VerificationError::ControlVerificationError {
                        control_id: digest(control_text)?,
                    }))
                }
                "bad-seal" => Some(R0Error::R0(VerificationError::InvalidProof)),
                "truncated-inclusion" => Some(R0Error::InvalidDigestListLength(w.inclusion.len())),
                "wrong-claim" => Some(R0Error::R0(VerificationError::JournalDigestMismatch)),
                _ => unreachable!(),
            }
            .map(|e| TxScriptError::ZkIntegrity(e.to_string()));
            let layer = match *label {
                "wrong-image" | "wrong-journal" => "native-expected-successful-claim",
                "truncated-inclusion" => "native-canonical-framing",
                "wrong-control" | "bad-inclusion" | "wrong-control-index" => {
                    "native-control-authentication"
                }
                _ => "native-seal-and-claim-integrity",
            };
            if *label == "valid" {
                save(out, "valid-native-script.bin", &script)?;
            }
            let (result, ok) = native_case(label, layer, &script, expected);
            matched &= ok;
            results.push(result);
        }
    }
    let report = json!({"scope":"OFFLINE_BARE_KASPA_NATIVE_OPCODE_PREDICATE_ONLY",
        "historical_harness_qualification":historical,"paired_statement_profile":!historical,
        "paired_receipt_result":!historical && matched,
        "transaction_or_covenant_acceptance_tested":false,"chain_or_network_used":false,
        "native_kaspa_revision":NATIVE_REV,"risc0_sdk":"3.0.3",
        "risc0_native_zkp_binfmt_groth16":"3.0.4","risc0_native_recursion":"4.0.4",
        "proving_features_enabled":false,"native_opcode_tag":if groth16 {"0x20"} else {"0x21"},
        "expected_image":image_text,"expected_control":if groth16 {Value::Null} else {json!(control_text)},
        "paired_program_sha256":if historical {Value::Null} else {json!(PROGRAM_SHA)},
        "expected_journal_bytes":expected_journal.len(),"expected_journal_sha256":hash(expected_journal),
        "receipt_file_sha256":hash(&raw),"receipt_file_bytes":raw.len(),"fields":fields,
        "checker_binary_sha256":hash(&fs::read(std::env::current_exe()?)?),
        "all_expectations_met":matched,"cases":results,
        "limitations":["No reserve, transaction, covenant, backing, nullifier, or exit validation",
            "Predicate script size and script-unit floor are not transaction compute/transient/storage mass",
            "Groth16 compression uses the official RISC0 setup key and inherits its setup trust",
            "Passing controls do not prove cryptographic correctness or production safety"]});
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    fs::File::open(out)?.sync_all()?;
    println!(
        "{}",
        serde_json::to_string(&json!({"output":out,"all_expectations_met":matched,
        "native_opcode_tag":report["native_opcode_tag"],"cases":labels.len()}))?
    );
    if !matched {
        return Err("one or more native expectations failed; retained report.json".into());
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn immutable_pair_statement_and_claim() {
        assert_eq!(hash(JOURNAL), JOURNAL_SHA);
        assert_eq!(JOURNAL.len(), 42);
        let image = bytes32(IMAGE).unwrap();
        let claim = expected_claim(image, JOURNAL);
        let mut changed = JOURNAL.to_vec();
        changed[41] ^= 1;
        assert_ne!(claim, expected_claim(image, &changed));
        let mut changed_image = image;
        changed_image[31] ^= 1;
        assert_ne!(claim, expected_claim(changed_image, JOURNAL));
    }
    #[test]
    fn fixed_key_and_public_scalar_encoding() {
        let key = fixed_groth16_key().unwrap();
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(key.as_slice()).unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 6);
        let inputs = groth16_inputs(bytes32(IMAGE).unwrap(), JOURNAL, false);
        for x in &inputs[..4] {
            assert_eq!(&x[16..], &[0u8; 16]);
        }
        let d = Groth16ReceiptVerifierParameters::default().control_root;
        assert_eq!(&inputs[0][..16], &d.as_bytes()[..16]);
        assert_eq!(&inputs[1][..16], &d.as_bytes()[16..]);
        assert_eq!(key.len(), 424);
    }
    #[test]
    fn malformed_coordinate_shapes_are_rejected() {
        assert!(g1_from_bytes(&[]).is_err());
        assert!(g1_from_bytes(&[vec![0; 31], vec![0; 32]]).is_err());
        assert!(g2_from_bytes(&[vec![vec![0; 32]], vec![vec![0; 32]]]).is_err());
    }
}
