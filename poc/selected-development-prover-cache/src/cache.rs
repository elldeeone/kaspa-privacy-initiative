//! Only a separately root-selected exact uncompressed artifact may reach No.
use crate::original_key;
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use kpi_future_private_payment as payment;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{fs, io::Read, path::Path, time::Instant};

pub use original_key::{Result, SELECTED_VK, VK_SHA256, digest};
pub const IDENTITY: &str = "kpx2-root-selected-uncompressed-loader/v1";
pub const CACHE_LEN: usize = 2_012_802_352;
const COMPILED_IDENTITY: &[u8] = include_bytes!("../pins/cache-identity.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheIdentity {
    schema: String,
    selected: bool,
    format: String,
    pub cache_sha256: String,
    cache_bytes: usize,
    originating_pk_sha256: String,
    originating_selection_sha256: String,
    vk_sha256: String,
    conversion_provenance_sha256: String,
}

fn canonical_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parse_identity(bytes: &[u8]) -> Result<CacheIdentity> {
    // Only compiled bytes enter this private function in production. No caller
    // supplies a replacement identity/expected hash or metadata sidecar.
    let selected: CacheIdentity = serde_json::from_slice(bytes)?;
    if !selected.selected {
        return Err("cache identity UNSELECTED".into());
    }
    if selected.schema != "kpx2-root-selected-uncompressed-cache/v1"
        || selected.format != "arkworks0.6-uncompressed"
        || selected.cache_bytes != CACHE_LEN
        || selected.originating_pk_sha256 != original_key::PK_SHA256
        || selected.originating_selection_sha256 != original_key::SELECTION_SHA256
        || selected.vk_sha256 != VK_SHA256
        || !canonical_hash(&selected.cache_sha256)
        || !canonical_hash(&selected.conversion_provenance_sha256)
    {
        return Err("compiled cache identity fields mismatch".into());
    }
    Ok(selected)
}

pub fn identity() -> Result<CacheIdentity> {
    parse_identity(COMPILED_IDENTITY)
}

pub fn identity_digest() -> String {
    digest(COMPILED_IDENTITY)
}

fn authenticate(bytes: &[u8], selected: &CacheIdentity) -> Result<()> {
    if bytes.len() != selected.cache_bytes {
        return Err("cache length mismatch".into());
    }
    if digest(bytes) != selected.cache_sha256 {
        return Err("cache full-byte digest mismatch".into());
    }
    Ok(())
}

struct VerifiedSelectedCacheBytes {
    bytes: Vec<u8>,
}
impl VerifiedSelectedCacheBytes {
    fn read(path: &Path, times: &mut Map<String, Value>) -> Result<Self> {
        let selected = identity()?; // Reject UNSELECTED before file IO/allocation.
        let started = Instant::now();
        let file = fs::File::open(path)?;
        if file.metadata()?.len() != selected.cache_bytes as u64 {
            return Err("cache file length mismatch".into());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(CACHE_LEN + 1)?;
        file.take(CACHE_LEN as u64 + 1).read_to_end(&mut bytes)?;
        times.insert(
            "cache_read_owned_bytes_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        authenticate(&bytes, &selected)?;
        times.insert(
            "cache_complete_sha256_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        Ok(Self { bytes })
    }

    fn decode(self, times: &mut Map<String, Value>) -> Result<ProvingKey<Bn254>> {
        let Self { bytes } = self;
        let started = Instant::now();
        let mut remaining = bytes.as_slice();
        // This exact owned complete buffer was authenticated before No; neither
        // a caller-side hash nor matching embedded VK can authorize this call.
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut remaining)?;
        if !remaining.is_empty() {
            return Err("trailing cache bytes".into());
        }
        times.insert(
            "cache_uncompressed_decode_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        drop(bytes);
        times.insert(
            "encoded_cache_drop_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        let started = Instant::now();
        if &payment::verification_key(&pk)? != SELECTED_VK {
            return Err("checked extracted cache VK mismatch".into());
        }
        times.insert(
            "checked_cache_vk_compare_seconds".into(),
            started.elapsed().as_secs_f64().into(),
        );
        Ok(pk)
    }
}

pub fn load(path: &Path, times: &mut Map<String, Value>) -> Result<ProvingKey<Bn254>> {
    identity()?;
    let started = Instant::now();
    original_key::check_compiled_pins()?;
    times.insert(
        "compiled_origin_and_vk_check_seconds".into(),
        started.elapsed().as_secs_f64().into(),
    );
    VerifiedSelectedCacheBytes::read(path, times)?.decode(times)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn draft() -> Value {
        serde_json::json!({"schema":"kpx2-root-selected-uncompressed-cache/v1","selected":false,
            "format":"arkworks0.6-uncompressed","cache_sha256":"UNSELECTED","cache_bytes":CACHE_LEN,
            "originating_pk_sha256":original_key::PK_SHA256,"originating_selection_sha256":original_key::SELECTION_SHA256,
            "vk_sha256":VK_SHA256,"conversion_provenance_sha256":"UNSELECTED"})
    }
    #[test]
    fn unselected_cannot_authorize_decode() {
        assert_eq!(
            parse_identity(&serde_json::to_vec(&draft()).unwrap())
                .err()
                .unwrap()
                .to_string(),
            "cache identity UNSELECTED"
        );
    }
    #[test]
    fn wrong_format_origin_and_hash_shape_reject() {
        let mut value = draft();
        value["selected"] = true.into();
        value["cache_sha256"] = "01".repeat(32).into();
        value["conversion_provenance_sha256"] = "02".repeat(32).into();
        parse_identity(&serde_json::to_vec(&value).unwrap()).unwrap();
        for (field, bad) in [
            ("format", "compressed"),
            ("originating_pk_sha256", "00"),
            ("cache_sha256", "AA"),
        ] {
            let mut changed = value.clone();
            changed[field] = bad.into();
            assert!(parse_identity(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
    }
    #[test]
    fn tiny_content_mutation_and_trailing_byte_fail_before_decode() {
        // Tiny test-only identity exercises the same pure hash/length gate. No
        // production constructor accepts it; no unchecked decoder is invoked.
        let mut value = draft();
        value["selected"] = true.into();
        value["cache_sha256"] = digest(b"tiny").into();
        value["conversion_provenance_sha256"] = "02".repeat(32).into();
        let mut selected = parse_identity(&serde_json::to_vec(&value).unwrap()).unwrap();
        selected.cache_bytes = 4;
        authenticate(b"tiny", &selected).unwrap();
        assert_eq!(
            authenticate(b"Tiny", &selected).err().unwrap().to_string(),
            "cache full-byte digest mismatch"
        );
        assert_eq!(
            authenticate(b"tiny!", &selected).err().unwrap().to_string(),
            "cache length mismatch"
        );
    }
}
