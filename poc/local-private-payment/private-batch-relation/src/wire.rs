//! Canonical RFC-0030 effect/intent bytes. Encoding alone validates no proof.
use crate::{CV, H, OUTPUTS, OWNERS};
use sha2::{Digest, Sha256};

pub const CONTEXT_BYTES: usize = 276;
pub const INTENT_BYTES: usize = 1460;
pub const EFFECT_BYTES: usize = 10_364;
pub const INTENT_TAG: &[u8; 8] = b"KPBINT01";
pub const EFFECT_TAG: &[u8; 8] = b"KPBAEF01";

/// Values are fixed into the circuit and therefore its setup identity. A JSON
/// label is never a substitute for a verification key bound to this profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub chain_genesis: H,
    pub pool_lineage: H,
    pub wallet_profile: H,
    pub domain: H,
    pub service_policy: H,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub reserve_outpoint: [u8; 36],
    pub old_cm_root: H,
    pub old_nf_root: H,
    pub old_cm_count: u32,
    pub old_nf_count: u32,
    pub old_reserve: u64,
}

impl Context {
    pub fn bytes(&self) -> [u8; CONTEXT_BYTES] {
        let mut out = Vec::with_capacity(CONTEXT_BYTES);
        for h in [
            &self.profile.chain_genesis,
            &self.profile.pool_lineage,
            &self.profile.wallet_profile,
            &self.profile.domain,
            &self.profile.service_policy,
        ] {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&self.reserve_outpoint);
        out.extend_from_slice(&self.old_cm_root);
        out.extend_from_slice(&self.old_nf_root);
        out.extend(self.old_cm_count.to_le_bytes());
        out.extend(self.old_nf_count.to_le_bytes());
        out.extend(self.old_reserve.to_le_bytes());
        out.try_into().expect("fixed context shape")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierWitness {
    pub predecessor_index: u32,
    pub predecessor: H,
    pub successor: H,
    pub successor_index: u32,
    pub predecessor_path: [H; 17],
    pub append_path: [H; 17],
}

impl NullifierWitness {
    pub fn bytes(&self) -> [u8; 1160] {
        let mut out = Vec::with_capacity(1160);
        out.extend(self.predecessor_index.to_le_bytes());
        out.extend(self.predecessor);
        out.extend(self.successor);
        out.extend(self.successor_index.to_le_bytes());
        for h in self.predecessor_path.iter().chain(&self.append_path) {
            out.extend(h);
        }
        out.try_into().expect("fixed indexed-NF witness shape")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effects {
    pub context: Context,
    pub new_cm_root: H,
    pub new_nf_root: H,
    pub new_cm_count: u32,
    pub new_nf_count: u32,
    pub new_reserve: u64,
    pub total_fee: u64,
    pub delta: H,
    pub inputs: [(H, CV); OWNERS],
    pub outputs: [[u8; 520]; OUTPUTS],
    pub nf_witnesses: [NullifierWitness; OWNERS],
    pub cm_paths: [[H; 16]; OUTPUTS],
}

impl Effects {
    pub fn bytes(&self) -> [u8; EFFECT_BYTES] {
        let mut out = Vec::with_capacity(EFFECT_BYTES);
        out.extend(EFFECT_TAG);
        out.extend(self.context.bytes());
        out.extend(self.new_cm_root);
        out.extend(self.new_nf_root);
        out.extend(self.new_cm_count.to_le_bytes());
        out.extend(self.new_nf_count.to_le_bytes());
        out.extend(self.new_reserve.to_le_bytes());
        out.extend(self.total_fee.to_le_bytes());
        out.extend(self.delta);
        for (nf, cv) in &self.inputs {
            out.extend(nf);
            out.extend(cv);
        }
        for row in &self.outputs {
            out.extend(row);
        }
        for witness in &self.nf_witnesses {
            out.extend(witness.bytes());
        }
        for path in &self.cm_paths {
            for node in path {
                out.extend(node);
            }
        }
        out.try_into().expect("fixed three-owner effect shape")
    }
    pub fn digest(&self) -> H {
        Sha256::digest(self.bytes()).into()
    }
}

pub fn intent_bytes(
    context: &Context,
    nf: &H,
    cv: &CV,
    fee: u64,
    nonce: &H,
    outputs: &[[u8; 520]; 2],
) -> [u8; INTENT_BYTES] {
    let mut out = Vec::with_capacity(INTENT_BYTES);
    out.extend(INTENT_TAG);
    out.extend(context.bytes());
    out.extend(nf);
    out.extend(cv);
    out.extend(fee.to_le_bytes());
    out.extend(nonce);
    for row in outputs {
        out.extend(row);
    }
    out.try_into().expect("fixed restricted-intent shape")
}

/// Public payload errors only. No private opening or diagnostic is formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicError {
    Length,
    Identity,
    Context,
    Range,
    Replay,
    Path,
    Amount,
    Encoding,
    Ciphertext,
}
type Result<T> = core::result::Result<T, PublicError>;
fn sha(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn fold(leaf: &H, index: u32, path: &[H], tag: &[u8]) -> Result<H> {
    if path.len() > 31 || index >= 1u32 << path.len() {
        return Err(PublicError::Range);
    }
    let mut root = *leaf;
    for (level, sibling) in path.iter().enumerate() {
        root = if (index >> level) & 1 == 0 {
            sha(&[tag, &root, sibling])
        } else {
            sha(&[tag, sibling, &root])
        };
    }
    Ok(root)
}
fn nf_leaf(nf: &H, successor: &H, index: u32) -> H {
    sha(&[b"KPX1NFL\0", nf, successor, &index.to_le_bytes()])
}
fn less(a: &H, b: &H) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}
fn insert_nf(root: &H, count: u32, nf: &H, w: &NullifierWitness) -> Result<H> {
    let zero = [0; 32];
    if count == 0
        || count >= 1 << 17
        || w.predecessor_index >= count
        || w.successor_index >= count
        || *nf == zero
        || (w.predecessor_index == 0) != (w.predecessor == zero)
        || (w.successor_index == 0) != (w.successor == zero)
        || !less(&w.predecessor, nf)
        || (w.successor != zero && !less(nf, &w.successor))
    {
        return Err(PublicError::Range);
    }
    if fold(
        &nf_leaf(&w.predecessor, &w.successor, w.successor_index),
        w.predecessor_index,
        &w.predecessor_path,
        b"KPX1NFN\0",
    )? != *root
    {
        return Err(PublicError::Path);
    }
    let middle = fold(
        &nf_leaf(&w.predecessor, nf, count),
        w.predecessor_index,
        &w.predecessor_path,
        b"KPX1NFN\0",
    )?;
    if fold(&sha(&[b"KPX1NFE\0"]), count, &w.append_path, b"KPX1NFN\0")? != middle {
        return Err(PublicError::Path);
    }
    fold(
        &nf_leaf(nf, &w.successor, w.successor_index),
        count,
        &w.append_path,
        b"KPX1NFN\0",
    )
}

impl Effects {
    /// This is the actual public-field/path check the selected R0 guest must
    /// execute. Calling it on an ordinary host does NOT prove native acceptance.
    /// The R0 guest must additionally verify the aggregate and all six genuine
    /// Output proofs; its selected image/journal must be checked by the covenant.
    pub fn validate_public_fields(&self, current: &Context, profile: &Profile) -> Result<()> {
        if &self.context != current || &self.context.profile != profile {
            return Err(PublicError::Context);
        }
        if self.context.reserve_outpoint[..32] == [0; 32] {
            return Err(PublicError::Identity);
        }
        let old = &self.context;
        if old.old_cm_count == 0
            || old.old_cm_count > (1 << 16) - OUTPUTS as u32
            || old.old_nf_count == 0
            || old.old_nf_count > (1 << 17) - OWNERS as u32
            || self.new_cm_count != old.old_cm_count + OUTPUTS as u32
            || self.new_nf_count != old.old_nf_count + OWNERS as u32
        {
            return Err(PublicError::Range);
        }
        if !(crate::NOTE_FLOOR..=crate::MAX).contains(&old.old_reserve)
            || !(crate::NOTE_FLOOR..=crate::MAX).contains(&self.new_reserve)
            || !(1..=crate::MAX).contains(&self.total_fee)
            || self.new_reserve.checked_add(self.total_fee) != Some(old.old_reserve)
        {
            return Err(PublicError::Amount);
        }
        let empty = sha(&[b"KPX1CME\0"]);
        for (i, (nf, _)) in self.inputs.iter().enumerate() {
            if *nf == [0; 32] || self.inputs[..i].iter().any(|(previous, _)| previous == nf) {
                return Err(PublicError::Replay);
            }
            if i > 0 && !less(&self.inputs[i - 1].0, nf) {
                return Err(PublicError::Replay);
            }
        }
        for (i, row) in self.outputs.iter().enumerate() {
            if row[..32] == [0; 32]
                || row[..32] == empty
                || self.outputs[..i]
                    .iter()
                    .any(|previous| previous[..32] == row[..32])
            {
                return Err(PublicError::Replay);
            }
            if sha(&[&row[96..360]]) != row[360..392] {
                return Err(PublicError::Ciphertext);
            }
        }
        let input_cv = self.inputs.iter().map(|(_, cv)| *cv).collect::<Vec<_>>();
        let output_cv = self
            .outputs
            .iter()
            .map(|row| row[32..96].try_into().expect("fixed tuple width"))
            .collect::<Vec<CV>>();
        if !crate::cv::check_balance(&input_cv, &output_cv, self.total_fee, &self.delta)
            .map_err(|_| PublicError::Encoding)?
        {
            return Err(PublicError::Amount);
        }
        let mut root = old.old_nf_root;
        for i in 0..OWNERS {
            root = insert_nf(
                &root,
                old.old_nf_count + i as u32,
                &self.inputs[i].0,
                &self.nf_witnesses[i],
            )?;
        }
        if root != self.new_nf_root {
            return Err(PublicError::Path);
        }
        root = old.old_cm_root;
        for i in 0..OUTPUTS {
            let index = old.old_cm_count + i as u32;
            if fold(&empty, index, &self.cm_paths[i], b"KPX1CMN\0")? != root {
                return Err(PublicError::Path);
            }
            root = fold(
                &self.outputs[i][..32].try_into().expect("fixed CM width"),
                index,
                &self.cm_paths[i],
                b"KPX1CMN\0",
            )?;
        }
        if root != self.new_cm_root {
            return Err(PublicError::Path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context {
        Context {
            profile: Profile {
                chain_genesis: [1; 32],
                pool_lineage: [2; 32],
                wallet_profile: [3; 32],
                domain: [4; 32],
                service_policy: [5; 32],
            },
            reserve_outpoint: [6; 36],
            old_cm_root: [7; 32],
            old_nf_root: [8; 32],
            old_cm_count: 9,
            old_nf_count: 10,
            old_reserve: 11,
        }
    }
    #[test]
    fn canonical_intent_offsets_match_python_contract() {
        let c = context();
        let rows = [[12; 520], [13; 520]];
        let b = intent_bytes(&c, &[14; 32], &[15; 64], 16, &[17; 32], &rows);
        assert_eq!(&b[..8], b"KPBINT01");
        assert_eq!(&b[8..284], &c.bytes());
        assert_eq!(&b[284..316], &[14; 32]);
        assert_eq!(&b[316..380], &[15; 64]);
        assert_eq!(&b[380..388], &16u64.to_le_bytes());
        assert_eq!(&b[388..420], &[17; 32]);
        assert_eq!(&b[420..940], &rows[0]);
        assert_eq!(&b[940..1460], &rows[1]);
    }
    #[test]
    fn nf_integer_order_is_full_little_endian_256_bits() {
        let mut a = [0; 32];
        let mut b = [0; 32];
        a[0] = 255;
        b[31] = 1;
        assert!(less(&a, &b));
        assert!(!less(&b, &a));
        assert!(!less(&b, &b));
    }
    #[test]
    fn capacity_and_empty_path_indices_refuse() {
        assert_eq!(
            fold(&[0; 32], 1, &[], b"KPX1CMN\0"),
            Err(PublicError::Range)
        );
        assert_eq!(
            fold(&[0; 32], 1 << 16, &[[0; 32]; 16], b"KPX1CMN\0"),
            Err(PublicError::Range)
        );
    }
}
