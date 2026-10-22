//! NONFUNDABLE synthetic state assertion for one immutable development pair.
//!
//! This proves a local transition conditional on a well-formed predecessor.
//! The caller must separately authenticate the predecessor outpoint, state,
//! reserve, policy and exact journal against actual transaction context. No
//! genesis, native backing, exit path or reserve release is established here.
//! The original pair gate, P1088, J42 and v6 state format remain unchanged.
use kpi_two_v6_binding::{compiled::CompiledResearchGate, sha256, Hash, MAX_SOMPI};

pub const INPUT_LEN: usize = 11_219;
pub const JOURNAL_LEN: usize = 336;
pub const STATE_LEN: usize = 105;
pub const STATE_VERSION: u8 = 7;
pub const PAIR_LEN: usize = kpi_two_v6_binding::INPUT_LEN;
pub const OUTPOINT_OFFSET: usize = PAIR_LEN;
pub const STATE_OFFSET: usize = OUTPOINT_OFFSET + 36;
pub const RESERVE_OFFSET: usize = STATE_OFFSET + STATE_LEN;
pub const ANCHOR_PATH_OFFSET: usize = RESERVE_OFFSET + 8;
pub const NF_OFFSET: usize = ANCHOR_PATH_OFFSET + 512;
pub const NF_WITNESS_LEN: usize = 1_160;
pub const CM_PATH_OFFSET: usize = NF_OFFSET + 4 * NF_WITNESS_LEN;
pub const HISTORY_PATH_OFFSET: usize = CM_PATH_OFFSET + 4 * 512;
pub const POOL_ID: Hash = kpi_two_v6_binding::compiled::COMPILED_POOL_ID;
const ZERO: Hash = [0; 32];
const CM_LIMIT: u32 = 1 << 16;
const NF_LIMIT: u32 = (1 << 17) - 1;

#[derive(Debug)]
pub enum StateError {
    Length { expected: usize, actual: usize },
    Binding(kpi_two_v6_binding::Error),
    StateVersion,
    StateCounts,
    Uninitialized,
    Capacity,
    HistoricalCount,
    HistoricalRoot,
    CurrentAnchor,
    NullifierIndex(usize),
    NullifierOrder(usize),
    NullifierLink(usize),
    NullifierRoot(usize),
    NullifierOccupied(usize),
    CommitmentOccupied(usize),
    HistoryOccupied(usize),
    Fee,
    Reserve,
}
impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StateError {}
impl From<kpi_two_v6_binding::Error> for StateError {
    fn from(value: kpi_two_v6_binding::Error) -> Self {
        Self::Binding(value)
    }
}
pub type Result<T> = std::result::Result<T, StateError>;

/// Separate version7 encoding. Fields are declarations until authenticated by
/// native context; parsing checks ranges, not whole-tree/genesis correctness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub cm_count: u32,
    pub nf_count: u32,
    pub cm_root: Hash,
    pub nf_root: Hash,
    pub history_root: Hash,
}
impl State {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        exact_len(bytes, STATE_LEN)?;
        if bytes[0] != STATE_VERSION {
            return Err(StateError::StateVersion);
        }
        let state = Self {
            cm_count: u32_at(bytes, 1),
            nf_count: u32_at(bytes, 5),
            cm_root: hash_at(bytes, 9),
            nf_root: hash_at(bytes, 41),
            history_root: hash_at(bytes, 73),
        };
        state.check()?;
        Ok(state)
    }
    fn check(&self) -> Result<()> {
        if self.cm_count == 0
            || self.cm_count >= CM_LIMIT
            || self.cm_count % 2 != 1
            || self.nf_count >= NF_LIMIT
            || self.nf_count % 2 != 0
            || self.nf_count > 2 * self.cm_count
        {
            return Err(StateError::StateCounts);
        }
        // No v6 bootstrap branch: this assertion is initialized SPEND only.
        if self.nf_count < 2 {
            return Err(StateError::Uninitialized);
        }
        Ok(())
    }
    pub fn bytes(&self) -> [u8; STATE_LEN] {
        let mut bytes = [0; STATE_LEN];
        bytes[0] = STATE_VERSION;
        bytes[1..5].copy_from_slice(&self.cm_count.to_le_bytes());
        bytes[5..9].copy_from_slice(&self.nf_count.to_le_bytes());
        bytes[9..41].copy_from_slice(&self.cm_root);
        bytes[41..73].copy_from_slice(&self.nf_root);
        bytes[73..105].copy_from_slice(&self.history_root);
        bytes
    }
    fn successor_counts(&self) -> Result<(u32, u32)> {
        self.check()?;
        let n = self.cm_count.checked_add(4).ok_or(StateError::Capacity)?;
        let m = self.nf_count.checked_add(4).ok_or(StateError::Capacity)?;
        if n >= CM_LIMIT || m >= NF_LIMIT || m > 2 * n {
            return Err(StateError::Capacity);
        }
        Ok((n, m))
    }
}

/// Output bytes, not an independently constructible proof of verification.
#[derive(Clone, Debug)]
pub struct StateAssertion {
    pub projection: [u8; kpi_two_v6_binding::PROJECTION_LEN],
    pub journal: [u8; JOURNAL_LEN],
    pub prior_state: State,
    pub next_state: State,
    pub reserve_before: u64,
    pub reserve_after: u64,
}

/// No caller-selected key/domain or caller-supplied proof-verification result.
pub struct StateGate {
    pair: CompiledResearchGate,
}
impl StateGate {
    pub fn new() -> Result<Self> {
        Ok(Self {
            pair: CompiledResearchGate::new()?,
        })
    }
    pub fn evaluate(&self, input: &[u8]) -> Result<StateAssertion> {
        exact_len(input, INPUT_LEN)?;
        let prior = State::parse(&input[STATE_OFFSET..RESERVE_OFFSET])?;
        let (n, m) = prior.successor_counts()?;
        let verified = self.pair.verify(&input[..PAIR_LEN])?;
        let p = &verified.projection;
        let r = u64::from_le_bytes(
            input[RESERVE_OFFSET..ANCHOR_PATH_OFFSET]
                .try_into()
                .unwrap(),
        );
        let fee = u128::from_le_bytes(p[76..92].try_into().unwrap());
        let remaining = reserve_after(r, fee)?;
        // Both original authorizations have already been proved and their
        // common count/anchor bound by the unchanged compiled pair gate.
        let a = u32_at(input, kpi_two_v6_binding::PROJECTION_LEN + 40);
        let anchor = hash_at(input, kpi_two_v6_binding::PROJECTION_LEN + 44);
        if a == 0 || a % 2 != 1 || a > prior.cm_count {
            return Err(StateError::HistoricalCount);
        }
        let historical = history_leaf(a, anchor);
        if fold(
            historical,
            (a - 1) / 2,
            &input[ANCHOR_PATH_OFFSET..NF_OFFSET],
        ) != prior.history_root
        {
            return Err(StateError::HistoricalRoot);
        }
        // A current anchor must be the declared current commitment root too.
        // Historical membership alone cannot certify global prior coherence.
        if a == prior.cm_count && anchor != prior.cm_root {
            return Err(StateError::CurrentAnchor);
        }
        let mut nf_root = prior.nf_root;
        for i in 0..4 {
            let nf = hash_at(p, 92 + i * 32);
            let begin = NF_OFFSET + i * NF_WITNESS_LEN;
            nf_root = insert_nf(
                nf_root,
                prior.nf_count + i as u32 + 1,
                nf,
                &input[begin..begin + NF_WITNESS_LEN],
                i,
            )?;
        }
        let mut cm_root = prior.cm_root;
        let mut prefix_two = ZERO;
        for i in 0..4 {
            let cm = hash_at(p, 220 + i * kpi_two_v6_binding::RECORD_LEN);
            let begin = CM_PATH_OFFSET + i * 512;
            cm_root = append(
                cm_root,
                prior.cm_count + i as u32,
                cm_leaf(cm),
                &input[begin..begin + 512],
                StateError::CommitmentOccupied(i),
            )?;
            if i == 1 {
                prefix_two = cm_root;
            }
        }
        let mut history_root = prior.history_root;
        for (i, root) in [prefix_two, cm_root].into_iter().enumerate() {
            let count = prior.cm_count + 2 * (i as u32 + 1);
            let index = (prior.cm_count + 1) / 2 + i as u32;
            let begin = HISTORY_PATH_OFFSET + i * 512;
            history_root = append(
                history_root,
                index,
                history_leaf(count, root),
                &input[begin..begin + 512],
                StateError::HistoryOccupied(i),
            )?;
        }
        let next = State {
            cm_count: n,
            nf_count: m,
            cm_root,
            nf_root,
            history_root,
        };
        next.check()?;
        let mut journal = [0; JOURNAL_LEN];
        journal[..8].copy_from_slice(b"KPI2V6S1");
        journal[8..10].copy_from_slice(&1u16.to_le_bytes());
        journal[10..42].copy_from_slice(&verified.projection_digest);
        journal[42..74].copy_from_slice(&POOL_ID);
        journal[74..110].copy_from_slice(&input[OUTPOINT_OFFSET..STATE_OFFSET]);
        journal[110..215].copy_from_slice(&prior.bytes());
        journal[215..320].copy_from_slice(&next.bytes());
        journal[320..328].copy_from_slice(&r.to_le_bytes());
        journal[328..336].copy_from_slice(&remaining.to_le_bytes());
        Ok(StateAssertion {
            projection: verified.projection,
            journal,
            prior_state: prior,
            next_state: next,
            reserve_before: r,
            reserve_after: remaining,
        })
    }
}

fn exact_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() != expected {
        return Err(StateError::Length {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}
fn hash_at(bytes: &[u8], at: usize) -> Hash {
    bytes[at..at + 32].try_into().unwrap()
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn tagged(tag: u8, bytes: &[u8]) -> Hash {
    let mut preimage = Vec::with_capacity(1 + bytes.len());
    preimage.push(tag);
    preimage.extend_from_slice(bytes);
    sha256(&preimage)
}
fn node(left: Hash, right: Hash) -> Hash {
    let mut preimage = [0; 65];
    preimage[0] = 1;
    preimage[1..33].copy_from_slice(&left);
    preimage[33..].copy_from_slice(&right);
    sha256(&preimage)
}
fn cm_leaf(cm: Hash) -> Hash {
    tagged(0, &cm)
}
fn history_leaf(count: u32, root: Hash) -> Hash {
    let mut bytes = [0; 36];
    bytes[..4].copy_from_slice(&count.to_le_bytes());
    bytes[4..].copy_from_slice(&root);
    tagged(3, &bytes)
}
// All callers pass exact fixed-depth slices, with indices range checked by
// state counts or indexed-set checks. An empty tree slot is raw ZERO, never a
// hash of an all-zero commitment/leaf.
fn fold(mut root: Hash, index: u32, path: &[u8]) -> Hash {
    debug_assert!(path.len() == 512 || path.len() == 544);
    for (level, sibling) in path.chunks_exact(32).enumerate() {
        let sibling = sibling.try_into().unwrap();
        root = if (index >> level) & 1 == 0 {
            node(root, sibling)
        } else {
            node(sibling, root)
        };
    }
    root
}
fn append(root: Hash, index: u32, leaf: Hash, path: &[u8], error: StateError) -> Result<Hash> {
    if fold(ZERO, index, path) != root {
        return Err(error);
    }
    Ok(fold(leaf, index, path))
}
fn less_le(a: Hash, b: Hash) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}
fn insert_nf(root: Hash, index: u32, nf: Hash, witness: &[u8], slot: usize) -> Result<Hash> {
    let pred_index = u32_at(witness, 0);
    let value = hash_at(witness, 4);
    let next_index = u32_at(witness, 36);
    let next_value = hash_at(witness, 40);
    if pred_index >= index {
        return Err(StateError::NullifierIndex(slot));
    }
    // Explicitly stricter local sentinel convention than old v6: index0 iff
    // zero-valued predecessor. This holds for every reachable indexed set, but
    // does not certify unrelated leaves or genesis validity.
    if (pred_index == 0) != (value == ZERO) {
        return Err(StateError::NullifierLink(slot));
    }
    if !less_le(value, nf) || (next_value != ZERO && !less_le(nf, next_value)) {
        return Err(StateError::NullifierOrder(slot));
    }
    if (next_value == ZERO && next_index != 0)
        || (next_value != ZERO && (next_index == 0 || next_index >= index))
    {
        return Err(StateError::NullifierLink(slot));
    }
    let pred_path = &witness[72..616];
    let append_path = &witness[616..1160];
    let old_leaf = &witness[4..72];
    if fold(tagged(2, old_leaf), pred_index, pred_path) != root {
        return Err(StateError::NullifierRoot(slot));
    }
    let mut updated = [0; 68];
    updated[..32].copy_from_slice(&value);
    updated[32..36].copy_from_slice(&index.to_le_bytes());
    updated[36..].copy_from_slice(&nf);
    let mid = fold(tagged(2, &updated), pred_index, pred_path);
    let mut inserted = [0; 68];
    inserted[..32].copy_from_slice(&nf);
    inserted[32..36].copy_from_slice(&next_index.to_le_bytes());
    inserted[36..].copy_from_slice(&next_value);
    append(
        mid,
        index,
        tagged(2, &inserted),
        append_path,
        StateError::NullifierOccupied(slot),
    )
}
fn reserve_after(reserve: u64, fee: u128) -> Result<u64> {
    if fee == 0 || fee > MAX_SOMPI as u128 {
        return Err(StateError::Fee);
    }
    let fee = u64::try_from(fee).map_err(|_| StateError::Fee)?;
    if reserve > MAX_SOMPI || reserve <= fee {
        return Err(StateError::Reserve);
    }
    reserve.checked_sub(fee).ok_or(StateError::Reserve)
}

#[cfg(test)]
mod tests;
