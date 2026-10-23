//! The only unchecked decoder is private to one root-selected, already checked
//! development parameter file. Untrusted proof and VK decoders are unchanged.
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use kpi_future_private_payment as payment;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::Instant};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const IDENTITY: &str = "kpx2-selected-development-compressed-loader/v1";
pub const SELECTION_SHA256: &str =
    "8c207d6e1220601c91a3eed3955e968949b46d9550c449b66bbd414df75027b9";
pub const PK_SHA256: &str = "e95202462feaeeeed6761ae0ae137c86c9730c54612df42252d3b3c085e86bfb";
pub const PK_LEN: usize = 1_006_401_200;
pub const VK_SHA256: &str = "5f551fa7b0cbeb9ec89ccf0e198575b1803db4c8012919166436af625e0136bc";
const CIRCUIT_SHA256: &str = "e1e3e3e6201ef817516fda2c48fa6dbefb275fecf56632c10c4d7fe915798bd3";
const LIBRARY_SHA256: &str = "fc38cee6232d35b5685f8e78c097dbe9f749acddb91111b22991146ec08cecf2";
const DOMAIN: &str = "9de4f84dbdaec6250d0029ca4b38ae12b9081a549e231eb529075af7fe59e85c";
const SELECTED_JSON: &[u8] = include_bytes!("../pins/new-key-selection.json");
pub const SELECTED_VK: &[u8; 328] = include_bytes!("../pins/verification-key.bin");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySelection {
    schema: String,
    classification: String,
    domain_hex32: String,
    local_only_pk_path: String,
    local_only_pk_sha256: String,
    vk_hex328: String,
    circuit_source_sha256: String,
    library_source_sha256: String,
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_digest(bytes: &[u8], expected: &str, error: &'static str) -> Result<()> {
    if digest(bytes) != expected {
        return Err(error.into());
    }
    Ok(())
}

pub fn check_compiled_pins() -> Result<()> {
    require_digest(
        SELECTED_JSON,
        SELECTION_SHA256,
        "compiled selection mismatch",
    )?;
    require_digest(SELECTED_VK, VK_SHA256, "compiled VK mismatch")?;
    require_digest(
        include_bytes!("../../future-private-payment/src/circuit.rs"),
        CIRCUIT_SHA256,
        "compiled circuit mismatch",
    )?;
    require_digest(
        include_bytes!("../../future-private-payment/src/lib.rs"),
        LIBRARY_SHA256,
        "compiled library mismatch",
    )?;
    if hex::encode(payment::DOMAIN) != DOMAIN {
        return Err("compiled domain mismatch".into());
    }
    // Fully checked canonical/subgroup/nonidentity/arity validation remains.
    payment::Verifier::new(SELECTED_VK)?;
    Ok(())
}

fn selected_metadata(bytes: &[u8]) -> Result<KeySelection> {
    // This digest is compiled authority. Adjacent metadata is never authority.
    require_digest(bytes, SELECTION_SHA256, "selection digest mismatch")?;
    let selected: KeySelection = serde_json::from_slice(bytes)?;
    if selected.schema != "kpx2-new-development-key-selection/v1"
        || selected.classification != "PUBLIC_SYNTHETIC_DO_NOT_FUND"
        || selected.domain_hex32 != DOMAIN
        || selected.local_only_pk_sha256 != PK_SHA256
        || selected.vk_hex328 != hex::encode(SELECTED_VK)
        || selected.circuit_source_sha256 != CIRCUIT_SHA256
        || selected.library_source_sha256 != LIBRARY_SHA256
    {
        return Err("selected metadata fields mismatch".into());
    }
    Ok(selected)
}

fn authenticate_pk(bytes: &[u8]) -> Result<()> {
    if bytes.len() != PK_LEN {
        return Err("PK length mismatch".into());
    }
    require_digest(bytes, PK_SHA256, "PK digest mismatch")
}

// No public bytes constructor, generic expected-hash constructor, or unchecked
// flag exists. Only this private exact-identity constructor can mint the type.
struct VerifiedDevelopmentPkBytes {
    bytes: Vec<u8>,
}
impl VerifiedDevelopmentPkBytes {
    fn read(selection_path: &Path, times: &mut Map<String, Value>) -> Result<Self> {
        let started = Instant::now();
        let mut selection_bytes = Vec::new();
        fs::File::open(selection_path)?
            .take(16 * 1024 + 1)
            .read_to_end(&mut selection_bytes)?;
        times.insert(
            "selection_read_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        let selected = selected_metadata(&selection_bytes)?;
        times.insert(
            "selection_authenticate_parse_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );

        let started = Instant::now();
        let file = fs::File::open(&selected.local_only_pk_path)?;
        if file.metadata()?.len() != PK_LEN as u64 {
            return Err("PK file length mismatch".into());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(PK_LEN + 1)?;
        file.take(PK_LEN as u64 + 1).read_to_end(&mut bytes)?;
        times.insert(
            "pk_read_owned_bytes_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        // Complete owned buffer is authenticated BEFORE the unchecked decoder.
        authenticate_pk(&bytes)?;
        times.insert(
            "pk_full_sha256_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        Ok(Self { bytes })
    }

    fn decode(self, times: &mut Map<String, Value>) -> Result<ProvingKey<Bn254>> {
        let Self { bytes } = self;
        let started = Instant::now();
        let mut remaining = bytes.as_slice();
        // Arkworks' supported trusted-input API. This still decompresses every
        // compressed point; it does not skip the y-coordinate square roots.
        let pk = ProvingKey::<Bn254>::deserialize_compressed_unchecked(&mut remaining)?;
        if !remaining.is_empty() {
            return Err("trailing PK bytes".into());
        }
        times.insert(
            "pk_compressed_unchecked_decode_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        drop(bytes);
        times.insert(
            "encoded_buffer_drop_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        // The extracted VK goes through the original FULLY CHECKED helper.
        let vk = payment::verification_key(&pk)?;
        if &vk != SELECTED_VK || digest(&vk) != VK_SHA256 {
            return Err("checked extracted VK identity mismatch".into());
        }
        times.insert(
            "vk_checked_extract_compare_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        Ok(pk)
    }
}

pub fn load(selection_path: &Path, times: &mut Map<String, Value>) -> Result<ProvingKey<Bn254>> {
    let started = Instant::now();
    check_compiled_pins()?;
    times.insert(
        "compiled_pins_and_vk_check_seconds".into(),
        started.elapsed().as_secs_f64().into(),
    );
    VerifiedDevelopmentPkBytes::read(selection_path, times)?.decode(times)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_root_pins_and_selected_metadata_match() {
        check_compiled_pins().unwrap();
        selected_metadata(SELECTED_JSON).unwrap();
    }

    #[test]
    fn malformed_selection_rejects_before_json_parse() {
        let error = selected_metadata(b"not JSON").err().unwrap();
        assert_eq!(error.to_string(), "selection digest mismatch");
    }

    #[test]
    fn self_provided_adjacent_selection_cannot_change_key() {
        let mut selected: Value = serde_json::from_slice(SELECTED_JSON).unwrap();
        selected["local_only_pk_sha256"] = "00".repeat(32).into();
        let bytes = serde_json::to_vec(&selected).unwrap();
        assert_eq!(
            selected_metadata(&bytes).err().unwrap().to_string(),
            "selection digest mismatch"
        );
    }

    #[test]
    fn tiny_wrong_key_rejects_before_decoder() {
        assert_eq!(
            authenticate_pk(b"not a key").err().unwrap().to_string(),
            "PK length mismatch"
        );
    }

    #[test]
    fn full_hash_check_rejects_changed_bytes_and_pin() {
        // Exercise the SHA boundary with tiny data, without a 1 GB allocation or
        // any unchecked decoder. Production callers always use fixed constants.
        let bytes = b"PUBLIC synthetic hash boundary";
        let expected = digest(bytes);
        require_digest(bytes, &expected, "digest mismatch").unwrap();
        assert_eq!(
            require_digest(b"changed", &expected, "digest mismatch")
                .err()
                .unwrap()
                .to_string(),
            "digest mismatch"
        );
        assert!(require_digest(bytes, &"00".repeat(32), "digest mismatch").is_err());
    }
}
