//! Six finite production-depth capacity boundaries; no circuit or proof APIs.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, path::Path, time::{Duration, Instant}};
type H = [u8; 32];
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
include!(concat!(env!("OUT_DIR"), "/production-hash.rs"));
#[derive(PartialEq, Eq)]
struct Snapshot {
    levels: Vec<Vec<H>>,
    empty: Vec<H>,
    depth: usize,
    // Capture original allocation metadata as well as every stored value.
    // No pointers are written to the public output.
    allocation: Vec<(usize, usize, usize)>,
}
mod production {
    #![allow(dead_code)]
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/production-tree.rs"));
    pub(super) fn snapshot(t: &Tree) -> Snapshot {
        let mut allocation = vec![(t.levels.as_ptr() as usize, t.levels.len(), t.levels.capacity()),
            (t.empty.as_ptr() as usize, t.empty.len(), t.empty.capacity())];
        allocation.extend(t.levels.iter().map(|row| (row.as_ptr() as usize, row.len(), row.capacity())));
        Snapshot { levels: t.levels.clone(), empty: t.empty.clone(), depth: t.depth, allocation }
    }
}
struct DenseReference { levels: Vec<Vec<H>>, empty: Vec<H>, count: usize, depth: usize }
fn reference_parent(left: &H, right: &H) -> H {
    // Independent bulk reference: no production node/append/new/root/path call.
    let mut h = Sha256::new(); h.update([1]); h.update(left); h.update(right); h.finalize().into()
}
impl DenseReference {
    fn build(leaves: &[H], count: usize, depth: usize) -> Self {
        let capacity = 1usize << depth;
        let mut bottom = vec![[0; 32]; capacity];
        bottom[..count].copy_from_slice(&leaves[..count]);
        let mut levels = vec![bottom];
        for level in 0..depth {
            let width = levels[level].len() / 2;
            let mut next = Vec::with_capacity(width);
            for index in 0..width { next.push(reference_parent(&levels[level][2 * index], &levels[level][2 * index + 1])); }
            levels.push(next);
        }
        let mut empty = vec![[0; 32]];
        for level in 1..depth { empty.push(reference_parent(&empty[level - 1], &empty[level - 1])); }
        Self { levels, empty, count, depth }
    }
    fn check_complete_stored_state(&self, tree: &production::Tree) -> Result<()> {
        let s = production::snapshot(tree);
        ensure(s.depth == self.depth && s.empty == self.empty, "depth/empty subtree state differs from reference")?;
        ensure(s.levels.len() == self.depth + 1, "stored level count differs")?;
        for level in 0..=self.depth {
            let length = self.count.div_ceil(1usize << level);
            ensure(s.levels[level].as_slice() == &self.levels[level][..length], "a complete stored level differs from dense reference")?;
        }
        ensure(tree.root() == self.levels[self.depth][0], "root differs from dense reference")?;
        let capacity = 1usize << self.depth;
        let mut positions = vec![0, capacity / 2 - 1, capacity / 2, self.count - 2, self.count - 1];
        if self.count < capacity { positions.push(self.count); }
        positions.sort_unstable(); positions.dedup();
        for position in positions {
            let expected = (0..self.depth).map(|level| self.levels[level][(position >> level) ^ 1]).collect::<Vec<_>>();
            ensure(tree.path(position as u32)? == expected, "path differs from dense reference")?;
        }
        Ok(())
    }
}
fn ensure(ok: bool, message: &str) -> Result<()> { if ok { Ok(()) } else { Err(message.into()) } }
fn state_digest(s: &Snapshot) -> String {
    let mut h = Sha256::new(); h.update(b"KPI/tree-capacity/state/v1\0");
    h.update((s.depth as u64).to_le_bytes()); h.update((s.levels.len() as u64).to_le_bytes());
    for row in &s.levels { h.update((row.len() as u64).to_le_bytes()); for node in row { h.update(node); } }
    h.update((s.empty.len() as u64).to_le_bytes()); for node in &s.empty { h.update(node); }
    hex::encode(h.finalize())
}
fn footprint() -> Value {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let get = |key: &str| status.lines().find(|line| line.starts_with(key)).unwrap().split_whitespace().nth(1).unwrap().parse::<u64>().unwrap();
    json!({"rss_kib":get("VmRSS:"),"hwm_kib":get("VmHWM:")})
}
fn row(out: &mut File, value: Value) -> Result<()> { writeln!(out, "{value}")?; out.flush()?; Ok(()) }
fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let depth: usize = args.next().ok_or("depth required")?.parse()?;
    let lane_arg = args.next().ok_or("exclusive lane path required")?;
    ensure(args.next().is_none(), "unexpected arguments")?;
    ensure([production::DEPTH, production::NF_DEPTH].contains(&depth), "only production depths16 and17 are selected")?;
    let lane = Path::new(&lane_arg); let results = lane.join("results");
    let mut out = OpenOptions::new().write(true).create_new(true).open(results.join(format!("depth{depth}.jsonl")))?;
    let start = Instant::now(); let capacity = 1usize << depth;
    let leaves = (0..capacity).map(|i| {
        let mut h = Sha256::new(); h.update(b"KPI/public-tree-capacity-control/v1\0");
        h.update((depth as u32).to_le_bytes()); h.update((i as u32).to_le_bytes()); h.finalize().into()
    }).collect::<Vec<H>>();
    let mut tree = production::Tree::new(leaves[..capacity - 2].to_vec(), depth)?;
    DenseReference::build(&leaves, capacity - 2, depth).check_complete_stored_state(&tree)?;
    let ready = json!({"phase":"initial_reference_baseline","depth":depth,"capacity":capacity,
        "leaf_count":capacity-2,"passed":true,"elapsed_ms":start.elapsed().as_millis(),"footprint":footprint(),
        "state_sha256":state_digest(&production::snapshot(&tree)),"root":hex::encode(tree.root())});
    row(&mut out, ready.clone())?;
    let temp = results.join(format!("depth{depth}-ready.tmp"));
    fs::write(&temp, ready.to_string())?; fs::rename(temp, results.join(format!("depth{depth}-ready.json")))?;
    while !lane.join("RUN_BOUNDARIES").exists() || lane.join("HOLD").exists() { std::thread::sleep(Duration::from_millis(100)); }
    for (label, index) in [("penultimate_append", capacity - 2), ("exact_full_append", capacity - 1)] {
        while lane.join("HOLD").exists() { std::thread::sleep(Duration::from_millis(100)); }
        let t = Instant::now(); tree.append(leaves[index])?;
        DenseReference::build(&leaves, index + 1, depth).check_complete_stored_state(&tree)?;
        row(&mut out, json!({"phase":label,"depth":depth,"leaf_count":index+1,"expected":"success",
            "passed":true,"complete_stored_state_matches_dense_reference":true,"elapsed_ms":t.elapsed().as_millis(),
            "state_sha256":state_digest(&production::snapshot(&tree)),"root":hex::encode(tree.root()),"footprint":footprint()}))?;
    }
    while lane.join("HOLD").exists() { std::thread::sleep(Duration::from_millis(100)); }
    let t = Instant::now(); let before = production::snapshot(&tree); let before_root = tree.root();
    let refusal = tree.append([0xa5; 32]).err().ok_or("over-capacity append unexpectedly succeeded")?;
    ensure(refusal.to_string() == "Merkle capacity", "wrong capacity-refusal error")?;
    let after = production::snapshot(&tree);
    ensure(before == after, "capacity refusal changed complete state or allocation metadata")?;
    ensure(before_root == tree.root(), "capacity refusal changed root")?;
    DenseReference::build(&leaves, capacity, depth).check_complete_stored_state(&tree)?;
    row(&mut out, json!({"phase":"over_capacity_refusal","depth":depth,"leaf_count":capacity,
        "expected":"Merkle capacity","observed_error":refusal.to_string(),"passed":true,
        "all_levels_empty_depth_and_allocation_metadata_unchanged":true,
        "before_state_sha256":state_digest(&before),"after_state_sha256":state_digest(&after),
        "elapsed_ms":t.elapsed().as_millis(),"footprint":footprint(),"proof_or_chain_result":false}))?;
    Ok(())
}
fn main() {
    if let Err(error) = run() { eprintln!("{}", json!({"passed":false,"error":error.to_string(),"scope":"ordinary_tree_capacity"})); std::process::exit(1); }
}
