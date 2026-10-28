//! Public framing/tree tests only. Fixture CVs/proofs are deliberately opaque
//! invalid cryptographic bytes and are never evidence of financial acceptance.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

struct Tree {
    depth: usize,
    tag: &'static [u8],
    empty: Vec<H>,
    leaves: BTreeMap<u32, H>,
}
impl Tree {
    fn new(depth: usize, empty: H, tag: &'static [u8]) -> Self {
        let mut empties = vec![empty];
        for level in 0..depth {
            empties.push(sha(&[tag, &empties[level], &empties[level]]));
        }
        Self {
            depth,
            tag,
            empty: empties,
            leaves: BTreeMap::new(),
        }
    }
    fn levels(&self) -> Vec<BTreeMap<u32, H>> {
        let mut levels = vec![self.leaves.clone()];
        for level in 0..self.depth {
            let parents: BTreeSet<u32> = levels[level].keys().map(|index| index / 2).collect();
            let mut next = BTreeMap::new();
            for parent in parents {
                let left = levels[level]
                    .get(&(parent * 2))
                    .unwrap_or(&self.empty[level]);
                let right = levels[level]
                    .get(&(parent * 2 + 1))
                    .unwrap_or(&self.empty[level]);
                next.insert(parent, sha(&[self.tag, left, right]));
            }
            levels.push(next);
        }
        levels
    }
    fn root(&self) -> H {
        *self.levels()[self.depth]
            .get(&0)
            .unwrap_or(&self.empty[self.depth])
    }
    fn path(&self, mut index: u32) -> Vec<u8> {
        let levels = self.levels();
        let mut bytes = Vec::new();
        for level in 0..self.depth {
            bytes.extend(
                levels[level]
                    .get(&(index ^ 1))
                    .unwrap_or(&self.empty[level]),
            );
            index >>= 1;
        }
        bytes
    }
}
fn leaf(value: H, next: H, index: u32) -> H {
    sha(&[b"KPX1NFL\0", &value, &next, &index.to_le_bytes()])
}
fn context() -> Context {
    Context {
        chain_genesis: [0x11; 32],
        pool_lineage: [0x22; 32],
        profile_id: [0x33; 32],
        domain: [0x44; 32],
        service_policy: [0x55; 32],
    }
}
fn fixture() -> Vec<u8> {
    let ctx = context();
    let mut cm = Tree::new(16, sha(&[b"KPX1CME\0"]), b"KPX1CMN\0");
    for index in 0..3 {
        cm.leaves.insert(
            index,
            sha(&[b"public fictional original CM", &index.to_le_bytes()]),
        );
    }
    let old_cm = cm.root();
    let mut nf = Tree::new(17, sha(&[b"KPX1NFE\0"]), b"KPX1NFN\0");
    nf.leaves.insert(0, leaf([0; 32], [0; 32], 0));
    let old_nf = nf.root();
    let mut rows = Vec::new();
    let mut nf_witnesses = Vec::new();
    for index in 0u32..3 {
        let count = index + 1;
        let mut value = [0; 32];
        value[0] = (index + 1) as u8;
        let mut previous = [0; 32];
        previous[0] = index as u8;
        let before = nf.path(index);
        nf.leaves.insert(index, leaf(previous, value, count));
        let append = nf.path(count);
        nf.leaves.insert(count, leaf(value, [0; 32], 0));
        nf_witnesses.extend(index.to_le_bytes());
        nf_witnesses.extend(previous);
        nf_witnesses.extend([0; 32]);
        nf_witnesses.extend(0u32.to_le_bytes());
        nf_witnesses.extend(before);
        nf_witnesses.extend(append);
        rows.extend(value);
        rows.extend([0; 64]);
    }
    let mut outputs = Vec::new();
    let mut cm_paths = Vec::new();
    for index in 0u32..6 {
        let cm_value = sha(&[b"public fictional output CM", &index.to_le_bytes()]);
        let ciphertext = [index as u8 + 1; 264];
        let ciphertext_hash = sha(&[&ciphertext]);
        cm_paths.extend(cm.path(index + 3));
        cm.leaves.insert(index + 3, cm_value);
        outputs.extend(cm_value);
        outputs.extend([0; 64]);
        outputs.extend(ciphertext);
        outputs.extend(ciphertext_hash);
        outputs.extend([0; 128]);
    }
    let mut core = Vec::new();
    core.extend(b"KPBAEF01");
    for id in [
        ctx.chain_genesis,
        ctx.pool_lineage,
        ctx.profile_id,
        ctx.domain,
        ctx.service_policy,
    ] {
        core.extend(id);
    }
    let mut point = [0x66; 36];
    point[32..].copy_from_slice(&2u32.to_le_bytes());
    core.extend(point);
    core.extend(old_cm);
    core.extend(old_nf);
    core.extend(3u32.to_le_bytes());
    core.extend(1u32.to_le_bytes());
    core.extend(6_000_000_000u64.to_le_bytes());
    core.extend(cm.root());
    core.extend(nf.root());
    core.extend(9u32.to_le_bytes());
    core.extend(4u32.to_le_bytes());
    core.extend(5_970_000_000u64.to_le_bytes());
    core.extend(30_000_000u64.to_le_bytes());
    core.extend([0; 32]);
    core.extend(rows);
    core.extend(outputs);
    core.extend(nf_witnesses);
    core.extend(cm_paths);
    assert_eq!(core.len(), BODY_CORE_LEN);
    core.extend([0; 128]);
    assert_eq!(core.len(), BODY_LEN);
    let spk = [&[0, 0, 0xaa, 0x20][..], &[0x77; 32], &[0x87]].concat();
    let mut prefix = Vec::new();
    prefix.extend(b"KPBAFX01\x01\0\x01\0");
    prefix.extend(point);
    prefix.extend([255; 8]);
    prefix.extend(6_000_000_000u64.to_le_bytes());
    prefix.extend(37u16.to_le_bytes());
    prefix.extend(&spk);
    prefix.extend(1u16.to_le_bytes());
    prefix.extend(5_970_000_000u64.to_le_bytes());
    prefix.extend(37u16.to_le_bytes());
    prefix.extend(&spk);
    prefix.extend([0; 37]);
    prefix.extend((BODY_LEN as u32).to_le_bytes());
    assert_eq!(prefix.len(), PREFIX_LEN);
    prefix.extend(core);
    prefix
}
fn frame_ok(raw: &[u8]) -> bool {
    Projection::parse(raw, &context())
        .and_then(|p| wire::validate_transition(&p))
        .is_ok()
}

#[test]
fn established_public_tree_updates_match_new_codec() {
    let raw = fixture();
    let projection = Projection::parse(&raw, &context()).unwrap();
    wire::validate_transition(&projection).unwrap();
    assert_eq!(raw.len(), 10685);
    assert_eq!(projection.body.old.n, 3);
    assert_eq!(projection.body.new.n, 9);
    assert_eq!(&projection.body.old.raw[..8], b"KPBAST01");
    assert_eq!(
        wire::effects_digest(&projection),
        sha(&[&raw[PREFIX_LEN..PREFIX_LEN + BODY_CORE_LEN]])
    );
}
#[test]
fn all_contexts_and_actual_head_binding_reject_changes() {
    let raw = fixture();
    for offset in [8, 40, 72, 104, 136, 168, 200, 276, 356, 364] {
        let mut changed = raw.clone();
        changed[PREFIX_LEN + offset] ^= 1;
        assert!(!frame_ok(&changed), "offset {offset}");
    }
    for offset in [12, 56, 105, 189] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert!(!frame_ok(&changed));
    }
}
#[test]
fn malformed_framing_and_legacy_tags_reject() {
    let raw = fixture();
    assert!(!frame_ok(&raw[..raw.len() - 1]));
    let mut changed = raw.clone();
    changed.push(0);
    assert!(!frame_ok(&changed));
    for (offset, tag) in [(0, b"KPXAFX01"), (PREFIX_LEN, b"KPXAPB01")] {
        let mut changed = raw.clone();
        changed[offset..offset + 8].copy_from_slice(tag);
        assert!(!frame_ok(&changed));
    }
}
#[test]
fn wrong_stale_roots_and_merkle_paths_reject() {
    let raw = fixture();
    for offset in [
        204,
        236,
        284,
        316,
        3812,
        3812 + 72,
        3812 + 616,
        3812 + 1160,
        7292,
        7292 + 512,
    ] {
        let mut changed = raw.clone();
        changed[PREFIX_LEN + offset] ^= 1;
        assert!(!frame_ok(&changed), "offset {offset}");
    }
}
#[test]
fn nullifier_replay_and_public_order_tags_reject() {
    let raw = fixture();
    let mut changed = raw.clone();
    let first = changed[PREFIX_LEN + 404..PREFIX_LEN + 500].to_vec();
    changed[PREFIX_LEN + 500..PREFIX_LEN + 596].copy_from_slice(&first);
    assert!(!frame_ok(&changed));
    let mut changed = raw.clone();
    let first = changed[PREFIX_LEN + 404..PREFIX_LEN + 500].to_vec();
    let second = changed[PREFIX_LEN + 500..PREFIX_LEN + 596].to_vec();
    changed[PREFIX_LEN + 404..PREFIX_LEN + 500].copy_from_slice(&second);
    changed[PREFIX_LEN + 500..PREFIX_LEN + 596].copy_from_slice(&first);
    assert!(!frame_ok(&changed));
}
#[test]
fn altered_output_ciphertext_and_duplicate_commitment_reject() {
    let raw = fixture();
    let mut changed = raw.clone();
    changed[PREFIX_LEN + 692 + 96] ^= 1;
    assert!(!frame_ok(&changed));
    let mut changed = raw.clone();
    let first = changed[PREFIX_LEN + 692..PREFIX_LEN + 692 + 32].to_vec();
    changed[PREFIX_LEN + 1212..PREFIX_LEN + 1244].copy_from_slice(&first);
    assert!(!frame_ok(&changed));
}
#[test]
fn overflow_and_capacity_boundaries_reject() {
    let raw = fixture();
    for offset in [268, 272, 348, 352] {
        let mut changed = raw.clone();
        changed[PREFIX_LEN + offset..PREFIX_LEN + offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!frame_ok(&changed));
    }
    for offset in [276, 356, 364] {
        let mut changed = raw.clone();
        changed[PREFIX_LEN + offset..PREFIX_LEN + offset + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(!frame_ok(&changed));
    }
}
#[test]
fn proof_is_outside_effects_but_inside_projection_journal_commitment() {
    let raw = fixture();
    let original = wire::effects_digest(&Projection::parse(&raw, &context()).unwrap());
    let mut changed = raw.clone();
    changed[PROJECTION_LEN - 1] ^= 1;
    assert!(frame_ok(&changed));
    assert_eq!(
        wire::effects_digest(&Projection::parse(&changed, &context()).unwrap()),
        original
    );
    assert_ne!(sha(&[&raw]), sha(&[&changed]));
    // This framing pass cannot validate the intentionally all-zero proofs/CVs.
    assert_eq!(&raw[PREFIX_LEN + BODY_CORE_LEN..], &[0; 128]);
}
