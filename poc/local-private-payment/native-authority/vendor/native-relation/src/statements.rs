use crate::{CV, DOMAIN, Error, H, MAX, NOTE_FLOOR, PAYOUT_FLOOR, Result, hash, point_from_bytes};
use ark_bn254::Fr;
use ark_ff::PrimeField;
pub const SPEND_TAG: &[u8; 8] = b"KPXASP01";
pub const OUTPUT_TAG: &[u8; 8] = b"KPXAOU01";
pub const EXIT_TAG: &[u8; 8] = b"KPXAEX01";
pub fn digest_fields(d: &H) -> [Fr; 2] {
    // Only128-bit limbs, never reduction of a full256-bit hash.
    [
        Fr::from_le_bytes_mod_order(&d[..16]),
        Fr::from_le_bytes_mod_order(&d[16..]),
    ]
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendStatement {
    pub domain: H,
    pub anchor: H,
    pub nf: H,
    pub cv: CV,
    pub effects_digest: H,
}
impl SpendStatement {
    pub fn validate(&self) -> Result<()> {
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        if self.nf == [0; 32] {
            return Err(Error::Encoding);
        }
        let _ = point_from_bytes(&self.cv)?;
        Ok(())
    }
    pub fn bytes(&self) -> [u8; 200] {
        let mut b = [0; 200];
        b[..8].copy_from_slice(SPEND_TAG);
        b[8..40].copy_from_slice(&self.domain);
        b[40..72].copy_from_slice(&self.anchor);
        b[72..104].copy_from_slice(&self.nf);
        b[104..168].copy_from_slice(&self.cv);
        b[168..].copy_from_slice(&self.effects_digest);
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != 200 {
            return Err(Error::Length);
        }
        if &b[..8] != SPEND_TAG {
            return Err(Error::Encoding);
        }
        let s = Self {
            domain: b[8..40].try_into().unwrap(),
            anchor: b[40..72].try_into().unwrap(),
            nf: b[72..104].try_into().unwrap(),
            cv: b[104..168].try_into().unwrap(),
            effects_digest: b[168..].try_into().unwrap(),
        };
        s.validate()?;
        Ok(s)
    }
    pub fn digest(&self) -> H {
        hash(&[&self.bytes()])
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        digest_fields(&self.digest())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputStatement {
    pub domain: H,
    pub cm: H,
    pub cv: CV,
    pub cf_hash: H,
}
impl OutputStatement {
    pub fn validate(&self) -> Result<()> {
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        let _ = point_from_bytes(&self.cv)?;
        Ok(())
    }
    pub fn bytes(&self) -> [u8; 168] {
        let mut b = [0; 168];
        b[..8].copy_from_slice(OUTPUT_TAG);
        b[8..40].copy_from_slice(&self.domain);
        b[40..72].copy_from_slice(&self.cm);
        b[72..136].copy_from_slice(&self.cv);
        b[136..].copy_from_slice(&self.cf_hash);
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != 168 {
            return Err(Error::Length);
        }
        if &b[..8] != OUTPUT_TAG {
            return Err(Error::Encoding);
        }
        let s = Self {
            domain: b[8..40].try_into().unwrap(),
            cm: b[40..72].try_into().unwrap(),
            cv: b[72..136].try_into().unwrap(),
            cf_hash: b[136..].try_into().unwrap(),
        };
        s.validate()?;
        Ok(s)
    }
    pub fn digest(&self) -> H {
        hash(&[&self.bytes()])
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        digest_fields(&self.digest())
    }
}

/// Owner-authorized full-note redemption. The native policy separately verifies
/// current indexed-NF insertion, unchanged CM state and exact transaction effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitStatement {
    pub domain: H,
    pub anchor: H,
    pub nf: H,
    pub effects_digest: H,
    pub payout: u64,
    pub fee: u64,
}
impl ExitStatement {
    pub fn validate(&self) -> Result<()> {
        if self.domain != DOMAIN {
            return Err(Error::Domain);
        }
        if self.nf == [0; 32] {
            return Err(Error::Encoding);
        }
        let gross = self.payout.checked_add(self.fee).ok_or(Error::Range)?;
        if !(PAYOUT_FLOOR..=MAX).contains(&self.payout)
            || !(1..=MAX).contains(&self.fee)
            || !(NOTE_FLOOR..=MAX).contains(&gross)
        {
            return Err(Error::Range);
        }
        Ok(())
    }
    pub fn bytes(&self) -> [u8; 152] {
        let mut b = [0; 152];
        b[..8].copy_from_slice(EXIT_TAG);
        b[8..40].copy_from_slice(&self.domain);
        b[40..72].copy_from_slice(&self.anchor);
        b[72..104].copy_from_slice(&self.nf);
        b[104..136].copy_from_slice(&self.effects_digest);
        b[136..144].copy_from_slice(&self.payout.to_le_bytes());
        b[144..152].copy_from_slice(&self.fee.to_le_bytes());
        b
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != 152 {
            return Err(Error::Length);
        }
        if &b[..8] != EXIT_TAG {
            return Err(Error::Encoding);
        }
        let s = Self {
            domain: b[8..40].try_into().unwrap(),
            anchor: b[40..72].try_into().unwrap(),
            nf: b[72..104].try_into().unwrap(),
            effects_digest: b[104..136].try_into().unwrap(),
            payout: u64::from_le_bytes(b[136..144].try_into().unwrap()),
            fee: u64::from_le_bytes(b[144..152].try_into().unwrap()),
        };
        s.validate()?;
        Ok(s)
    }
    pub fn digest(&self) -> H {
        hash(&[&self.bytes()])
    }
    pub fn public_inputs(&self) -> [Fr; 2] {
        digest_fields(&self.digest())
    }
}
