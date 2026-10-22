//! Standard fixed-depth SHA-256 Merkle trees and indexed set insertion.
//! Full public leaves are reconstructible wallet data, never trusted by script.
use super::*;
use crate::compact::tree::{NfLeaf, less};
pub const DEPTH: usize = 16;
pub const NF_DEPTH: usize = 17;
pub const LIMIT: usize = 1 << DEPTH;
pub type Path = Vec<H>;
pub fn node(l: &H, r: &H) -> H {
    hash(&[&[1][..], l, r].concat())
}
pub fn cm_leaf(cm: &H) -> H {
    hash(&[&[0][..], cm].concat())
}
pub fn history_leaf(count: u32, root: &H) -> H {
    hash(&[&[3][..], &count.to_le_bytes(), root].concat())
}
pub fn root_from(mut h: H, index: u32, path: &Path) -> H {
    for (i, s) in path.iter().enumerate() {
        h = if index & (1 << i) == 0 {
            node(&h, s)
        } else {
            node(s, &h)
        };
    }
    h
}
pub fn empty_path(depth: usize) -> Path {
    let mut p = vec![[0; 32]; depth];
    for i in 1..depth {
        p[i] = node(&p[i - 1], &p[i - 1]);
    }
    p
}
#[derive(Clone)]
pub struct Tree {
    levels: Vec<Vec<H>>,
    empty: Path,
    depth: usize,
}
impl Tree {
    pub fn new(leaves: Vec<H>, depth: usize) -> Result<Self> {
        if leaves.len() > (1 << depth) {
            return Err("Merkle capacity".into());
        }
        let empty = empty_path(depth);
        let mut levels = vec![leaves];
        for level in 0..depth {
            let next = levels[level]
                .chunks(2)
                .map(|c| node(&c[0], c.get(1).unwrap_or(&empty[level])))
                .collect();
            levels.push(next);
        }
        Ok(Self {
            levels,
            empty,
            depth,
        })
    }
    /// Public-data construction only; native script still verifies every path.
    pub fn append(&mut self, leaf: H) -> Result<()> {
        if self.levels[0].len() >= (1 << self.depth) {
            return Err("Merkle capacity".into());
        }
        let mut index = self.levels[0].len();
        self.levels[0].push(leaf);
        for level in 0..self.depth {
            let left = index & !1;
            let h = node(
                &self.levels[level][left],
                self.levels[level]
                    .get(left + 1)
                    .unwrap_or(&self.empty[level]),
            );
            index >>= 1;
            if index == self.levels[level + 1].len() {
                self.levels[level + 1].push(h);
            } else {
                self.levels[level + 1][index] = h;
            }
        }
        Ok(())
    }
    pub fn root(&self) -> H {
        self.levels[self.depth]
            .first()
            .copied()
            .unwrap_or_else(|| node(&self.empty[self.depth - 1], &self.empty[self.depth - 1]))
    }
    pub fn path(&self, index: u32) -> Result<Path> {
        if index as usize >= (1 << self.depth) {
            return Err("Merkle position".into());
        }
        Ok((0..self.depth)
            .map(|i| {
                self.levels[i]
                    .get(((index as usize) >> i) ^ 1)
                    .copied()
                    .unwrap_or(self.empty[i])
            })
            .collect())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub cm_count: u32,
    pub nf_count: u32,
    pub cm_root: H,
    pub nf_root: H,
    pub history_root: H,
}
impl State {
    pub fn check(&self) -> Result<()> {
        if self.cm_count == 0
            || self.cm_count as usize >= LIMIT
            || self.cm_count % 2 != 1
            || self.nf_count > 2 * self.cm_count
            || self.nf_count % 2 != 0
        {
            return Err("compact state counts".into());
        }
        Ok(())
    }
    pub fn bytes(&self) -> Vec<u8> {
        [
            &[6][..],
            &self.cm_count.to_le_bytes(),
            &self.nf_count.to_le_bytes(),
            &self.cm_root,
            &self.nf_root,
            &self.history_root,
        ]
        .concat()
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() != STATE_LEN || b[0] != 6 {
            return Err("compact state framing".into());
        }
        let s = Self {
            cm_count: u32::from_le_bytes(b[1..5].try_into()?),
            nf_count: u32::from_le_bytes(b[5..9].try_into()?),
            cm_root: b[9..41].try_into()?,
            nf_root: b[41..73].try_into()?,
            history_root: b[73..105].try_into()?,
        };
        s.check()?;
        Ok(s)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicState {
    pub commitments: Vec<H>,
    pub nullifiers: Vec<NfLeaf>,
    pub roots: Vec<H>,
}
impl PublicState {
    pub fn initial(cm: H) -> Result<Self> {
        let root = Tree::new(vec![cm_leaf(&cm)], 16)?.root();
        Ok(Self {
            commitments: vec![cm],
            nullifiers: vec![NfLeaf::default()],
            roots: vec![root],
        })
    }
    pub fn cm_tree(&self) -> Result<Tree> {
        Tree::new(self.commitments.iter().map(cm_leaf).collect(), 16)
    }
    pub fn nf_tree(&self) -> Result<Tree> {
        Tree::new(self.nullifiers.iter().map(NfLeaf::digest).collect(), 17)
    }
    pub fn history_tree(&self) -> Result<Tree> {
        Tree::new(
            self.roots
                .iter()
                .enumerate()
                .map(|(i, r)| history_leaf((2 * i + 1) as u32, r))
                .collect(),
            16,
        )
    }
    pub fn compact(&self) -> Result<State> {
        let s = State {
            cm_count: self.commitments.len().try_into()?,
            nf_count: self
                .nullifiers
                .len()
                .checked_sub(1)
                .ok_or("missing sentinel")?
                .try_into()?,
            cm_root: self.cm_tree()?.root(),
            nf_root: self.nf_tree()?.root(),
            history_root: self.history_tree()?.root(),
        };
        s.check()?;
        if self.roots.len() != (self.commitments.len() + 1) / 2
            || self.roots.last() != Some(&s.cm_root)
        {
            return Err("public root history".into());
        }
        Ok(s)
    }
    pub fn spent(&self, nf: &H) -> bool {
        self.nullifiers.iter().any(|l| l.value == *nf)
    }

    pub fn witness(&self, a: &Authorization) -> Result<(Self, Vec<u8>)> {
        self.compact()?;
        let mut next = self.clone();
        let mut w = vec![0; W_LEN];
        fn put(w: &mut [u8], off: usize, p: Path) {
            for (i, h) in p.iter().enumerate() {
                w[off + 32 * i..off + 32 * (i + 1)].copy_from_slice(h);
            }
        }
        if a.mode == 0 {
            if self.nullifiers.len() == 1 {
                return Err("admission before bootstrap".into());
            }
        } else {
            if a.mode > 2
                || a.count == 0
                || a.count % 2 != 1
                || self.roots.get((a.count as usize - 1) / 2) != Some(&a.anchor)
            {
                return Err("historical anchor".into());
            }
            put(
                &mut w,
                W_ANCHOR,
                self.history_tree()?.path((a.count - 1) / 2)?,
            );
            for (slot, nf) in a.nfs.iter().enumerate() {
                if *nf == [0; 32] || next.spent(nf) {
                    return Err("nullifier spent/zero".into());
                }
                let base = W_NF + slot * NF_WIT;
                let pred = next
                    .nullifiers
                    .iter()
                    .position(|l| {
                        less(&l.value, nf) && (l.next_value == [0; 32] || less(nf, &l.next_value))
                    })
                    .ok_or("NF predecessor")?;
                let old = next.nullifiers[pred].clone();
                let index = next.nullifiers.len() as u32;
                w[base..base + 4].copy_from_slice(&(pred as u32).to_le_bytes());
                w[base + 4..base + 72].copy_from_slice(&old.bytes());
                put(&mut w, base + 72, next.nf_tree()?.path(pred as u32)?);
                next.nullifiers[pred].next_index = index;
                next.nullifiers[pred].next_value = *nf;
                put(&mut w, base + 616, next.nf_tree()?.path(index)?);
                next.nullifiers.push(NfLeaf {
                    value: *nf,
                    next_index: old.next_index,
                    next_value: old.next_value,
                });
            }
        }
        if a.mode != 2 {
            if next.commitments.len() + 2 >= LIMIT
                || a.outputs.contains(&[0; 32])
                || a.outputs[0] == a.outputs[1]
            {
                return Err("CM capacity/output".into());
            }
            for (i, cm) in a.outputs.iter().enumerate() {
                put(
                    &mut w,
                    W_CM_APPEND + i * 512,
                    next.cm_tree()?.path(next.commitments.len() as u32)?,
                );
                next.commitments.push(*cm);
            }
            put(
                &mut w,
                W_HISTORY_APPEND,
                self.history_tree()?.path(self.roots.len() as u32)?,
            );
            next.roots.push(next.cm_tree()?.root());
        } else if a.outputs != [[0; 32]; 2] {
            return Err("drain outputs".into());
        }
        next.compact()?;
        Ok((next, w))
    }
}
