//! Checked software conversion only. No native VM or proving features.
mod receipt;
use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use receipt::hash;
use risc0_zkvm::sha::Digestible;
use serde_json::json;
use std::{error::Error, fs, io::Write, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn digest(s: &str) -> Result<[u8; 32]> {
    Ok(hex::decode(s)?
        .try_into()
        .map_err(|_| "expected 32-byte hex digest")?)
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
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 8 || a[1] != "extract" {
        return Err("usage: extract RECEIPT EXPECTED_IMAGE EXPECTED_J336 EXPECTED_CLAIM EXPECTED_RECEIPT_SHA NEW_OUTPUT".into());
    }
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        return Err("RISC0_DEV_MODE forbidden".into());
    }
    // Every expected value is caller-selected before decode, never taken from
    // receipt metadata. The launch record must freeze these inputs independently.
    let image = digest(&a[3])?;
    let expected_claim = digest(&a[5])?;
    let expected_receipt = digest(&a[6])?;
    let journal_path = Path::new(&a[4]);
    if fs::metadata(journal_path)?.len() != 336 {
        return Err("expected journal must be exact J336".into());
    }
    let journal = fs::read(journal_path)?;
    if &journal[..10] != b"KPI2V6S1\x01\x00" {
        return Err("expected J336 framing".into());
    }
    let receipt_path = Path::new(&a[2]);
    if fs::metadata(receipt_path)?.len() > 24 * 1024 * 1024 {
        return Err("receipt bound".into());
    }
    let (r, raw) = receipt::load(receipt_path, expected_receipt)?;
    if r.journal.bytes != journal {
        return Err("receipt journal differs from independently selected J336".into());
    }
    let g = r.inner.groth16()?;
    let actual_claim: [u8; 32] = g.claim.digest().into();
    if actual_claim != expected_claim {
        return Err("claim differs from independent selection".into());
    }
    r.verify(image)?; // Software verification, never labelled native verification.
    let proof = receipt::proof(&r)?;
    let checked = Proof::<Bn254>::deserialize_compressed(proof.as_slice())?;
    let mut roundtrip = Vec::new();
    checked.serialize_compressed(&mut roundtrip)?;
    if roundtrip != proof || proof.len() != 128 || g.seal.len() != 256 {
        return Err("canonical proof/seal dimensions".into());
    }
    let c = receipt::constants()?;
    if hex::encode(hash(&c.vk))
        != "78886245c5d55b850f2ac26af823802cd128eb4a43d6c52c8a62af46d54306a4"
    {
        return Err("official native outer VK pin".into());
    }
    let mut low = [0; 32];
    low[..16].copy_from_slice(&actual_claim[..16]);
    let mut high = [0; 32];
    high[..16].copy_from_slice(&actual_claim[16..]);
    let inputs = [c.root[0], c.root[1], low, high, c.id];
    let out = Path::new(&a[7]);
    fs::create_dir(out)?;
    save(out, "proof.compressed.bin", &proof)?;
    save(out, "vk.compressed.bin", &c.vk)?;
    save(out, "public-inputs.le.bin", &inputs.concat())?;
    save(out, "journal.bin", &journal)?;
    save(out, "sdk-seal.bin", &g.seal)?;
    let report = json!({"scope":"CHECKED_SDK_RECEIPT_TO_CANONICAL_NATIVE_PROOF_CONVERSION_ONLY",
        "sdk_verification_passed":true,"native_vm_executed":false,"proof_generation":false,
        "expected_image":hex::encode(image),"expected_journal_sha256":hex::encode(hash(&journal)),
        "expected_claim_digest":hex::encode(expected_claim),"actual_claim_digest":hex::encode(actual_claim),
        "receipt_sha256":hex::encode(hash(&raw)),"receipt_bytes":raw.len(),"sdk_seal_bytes":g.seal.len(),"sdk_seal_sha256":hex::encode(hash(&g.seal)),
        "native_proof_bytes":proof.len(),"native_proof_sha256":hex::encode(hash(&proof)),"native_vk_bytes":c.vk.len(),"native_vk_sha256":hex::encode(hash(&c.vk)),
        "native_public_inputs_le":inputs.iter().map(hex::encode).collect::<Vec<_>>(),
        "official_outer":{"root":c.root.iter().map(hex::encode).collect::<Vec<_>>(),"control_id":hex::encode(c.id),"poststate":hex::encode(c.post),"output_tag":hex::encode(c.output_tag),"claim_tag":hex::encode(c.claim_tag)},
        "checker_binary_sha256":hex::encode(hash(&fs::read(std::env::current_exe()?)?)),
        "selection":"image, complete J336, claim and receipt SHA were independently supplied before decode; no historical image or journal is built in",
        "limitations":["Software verification/conversion only; actual native opcode/transaction validation remains a separate gate.","No claim of accepted ancestry, funding, backing, owner exit, privacy or production safety."]});
    save(out, "report.json", &serde_json::to_vec_pretty(&report)?)?;
    fs::File::open(out)?.sync_all()?;
    println!(
        "{}",
        json!({"output":out,"native_proof_sha256":hex::encode(hash(&proof)),"sdk_verification_passed":true,"native_vm_executed":false})
    );
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
    fn expected_digest_has_exact_width() {
        assert!(digest("00").is_err());
        assert!(digest(&"00".repeat(32)).is_ok());
    }
    #[test]
    fn noncanonical_curve_coordinate_rejected() {
        let mut p = [0u8; 64];
        p[..32].fill(0xff);
        assert!(ark_bn254::G1Affine::deserialize_uncompressed(p.as_slice()).is_err());
    }
}
