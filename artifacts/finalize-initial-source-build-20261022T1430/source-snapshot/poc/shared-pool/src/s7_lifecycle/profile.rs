use crate::{
    Result,
    protocol::{H, hash},
    two_input::tree::PublicState,
};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "kpi-s7-initial-four-proof-public-test-v1";
pub const RELATION: &str = "unchanged-v6-KPICU06-two-digest-limbs";
pub const LABEL: &[u8] = b"KPI/s7-offline-owner-lifecycle/DO-NOT-FUND/v1/";

pub fn label_hash(label: &str) -> H {
    hash(&[LABEL, label.as_bytes()].concat())
}
pub fn domain() -> H {
    label_hash("domain")
}
pub fn pool_id() -> H {
    label_hash("pool-id")
}
pub fn state_bytes(state: &PublicState) -> Result<Vec<u8>> {
    let mut bytes = state.compact()?.bytes();
    bytes[0] = 7;
    Ok(bytes)
}

pub mod hex32 {
    use crate::protocol::H;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &H, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<H, D::Error> {
        let text = String::deserialize(d)?;
        let raw = hex::decode(&text).map_err(serde::de::Error::custom)?;
        if hex::encode(&raw) != text {
            return Err(serde::de::Error::custom("noncanonical hex32"));
        }
        raw.try_into()
            .map_err(|_| serde::de::Error::custom("hex32 length"))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format: String,
    pub relation: String,
    #[serde(with = "hex32")]
    pub domain: H,
    #[serde(with = "hex32")]
    pub pool_id: H,
    #[serde(with = "hex32")]
    pub initial_commitment: H,
    pub initial_value_sompi: String,
    pub vk_sha256: String,
    pub pk_sha256: String,
    pub pk_bytes: u64,
}
impl Profile {
    pub fn validate(&self, vk: &[u8]) -> Result<()> {
        if self.format != FORMAT
            || self.relation != RELATION
            || self.domain != domain()
            || self.pool_id != pool_id()
            || self.initial_value_sompi != "800000000"
            || vk.len() != 328
            || self.vk_sha256 != hex::encode(hash(vk))
            || self.pk_bytes == 0
        {
            return Err("S7 initial fixture profile/VK identity".into());
        }
        for text in [&self.vk_sha256, &self.pk_sha256] {
            let raw = hex::decode(text)?;
            if raw.len() != 32 || hex::encode(raw) != *text {
                return Err("S7 profile hash encoding".into());
            }
        }
        Ok(())
    }
}
