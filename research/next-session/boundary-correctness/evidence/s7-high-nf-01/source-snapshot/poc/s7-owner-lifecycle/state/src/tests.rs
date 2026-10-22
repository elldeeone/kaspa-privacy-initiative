use super::*;
#[test]
fn state_ranges_and_native_fee_narrowing_remain_checked() {
    let s = State {
        cm_count: 5,
        nf_count: 2,
        cm_root: [1; 32],
        nf_root: [2; 32],
        history_root: [3; 32],
    };
    assert_eq!(State::parse(&s.bytes()).unwrap(), s);
    let mut bad = s.bytes();
    bad[0] = 6;
    assert!(matches!(State::parse(&bad), Err(StateError::StateVersion)));
    for n in [0, 2, 65536, u32::MAX] {
        let mut bad = s.bytes();
        bad[1..5].copy_from_slice(&n.to_le_bytes());
        assert!(State::parse(&bad).is_err());
    }
    assert!(matches!(
        reserve_after(80_000_000, 80_000_000),
        Err(StateError::Reserve)
    ));
    assert!(reserve_after(MAX_SOMPI + 1, 80_000_000).is_err());
    assert!(reserve_after(1_660_000_000, u128::MAX).is_err());
    assert_eq!(
        reserve_after(1_660_000_000, 80_000_000).unwrap(),
        1_580_000_000
    );
}

// PUBLIC test fixtures only. No producer openings, PK or wallet files are read.
const FRESH: &[u8] = include_bytes!("../../proof/evidence/publication/input.bin");
const BOOT: &[u8] = include_bytes!(
    "../../../../artifacts/initial-four-public-fixture-20261022T1415/public/bootstrap.bin"
);
const ADMIT: &[u8] = include_bytes!(
    "../../../../artifacts/initial-four-public-fixture-20261022T1415/public/admit.bin"
);

fn public_hex32(text: &str) -> Hash {
    assert_eq!(text.len(), 64);
    let nibble = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => panic!("public hex"),
    };
    std::array::from_fn(|i| {
        (nibble(text.as_bytes()[2 * i]) << 4) | nibble(text.as_bytes()[2 * i + 1])
    })
}
fn oracle_hash(parts: &[&[u8]]) -> Hash {
    sha256(&parts.concat())
}
fn oracle_cm(cm: Hash) -> Hash {
    oracle_hash(&[&[0], &cm])
}
fn oracle_history(count: u32, root: Hash) -> Hash {
    oracle_hash(&[&[3], &count.to_le_bytes(), &root])
}
fn numeric_key(h: Hash) -> (u128, u128) {
    (
        u128::from_le_bytes(h[16..].try_into().unwrap()),
        u128::from_le_bytes(h[..16].try_into().unwrap()),
    )
}

/// Independent full-array tree oracle. Production verifies one supplied path;
/// this helper maintains all nodes and derives paths from the complete tree.
#[derive(Clone)]
struct OracleTree {
    depth: usize,
    nodes: Vec<Hash>,
}
impl OracleTree {
    fn new(depth: usize) -> Self {
        let mut tree = Self {
            depth,
            nodes: vec![[0; 32]; 2 << depth],
        };
        for i in (1..1 << depth).rev() {
            tree.rehash(i);
        }
        tree
    }
    fn rehash(&mut self, i: usize) {
        self.nodes[i] = oracle_hash(&[&[1], &self.nodes[2 * i], &self.nodes[2 * i + 1]]);
    }
    fn set(&mut self, index: usize, leaf: Hash) {
        assert!(index < 1 << self.depth);
        let mut p = (1 << self.depth) + index;
        self.nodes[p] = leaf;
        while p > 1 {
            p /= 2;
            self.rehash(p);
        }
    }
    fn root(&self) -> Hash {
        self.nodes[1]
    }
    fn path(&self, index: usize) -> Vec<u8> {
        assert!(index < 1 << self.depth);
        let mut p = (1 << self.depth) + index;
        let mut path = Vec::new();
        while p > 1 {
            path.extend_from_slice(&self.nodes[p ^ 1]);
            p /= 2;
        }
        path
    }
}
#[derive(Clone)]
struct OracleNf {
    value: Hash,
    next: u32,
    next_value: Hash,
}
impl OracleNf {
    fn bytes(&self) -> Vec<u8> {
        [&self.value[..], &self.next.to_le_bytes(), &self.next_value].concat()
    }
    fn digest(&self) -> Hash {
        oracle_hash(&[&[2], &self.bytes()])
    }
}
fn nf_witness(
    tree: &OracleTree,
    leaves: &[OracleNf],
    index: u32,
    nf: Hash,
) -> (Vec<u8>, usize, OracleNf) {
    let pred = leaves
        .iter()
        .position(|l| {
            numeric_key(l.value) < numeric_key(nf)
                && (l.next_value == ZERO || numeric_key(nf) < numeric_key(l.next_value))
        })
        .unwrap();
    let old = &leaves[pred];
    let mut w = Vec::new();
    w.extend_from_slice(&(pred as u32).to_le_bytes());
    w.extend(old.bytes());
    w.extend(tree.path(pred));
    let mut mid = tree.clone();
    mid.set(
        pred,
        OracleNf {
            value: old.value,
            next: index,
            next_value: nf,
        }
        .digest(),
    );
    w.extend(mid.path(index as usize));
    assert_eq!(w.len(), NF_WITNESS_LEN);
    (
        w,
        pred,
        OracleNf {
            value: nf,
            next: old.next,
            next_value: old.next_value,
        },
    )
}
fn oracle_state(n: u32, m: u32, cm: Hash, nf: Hash, history: Hash) -> Vec<u8> {
    [
        &[7][..],
        &n.to_le_bytes(),
        &m.to_le_bytes(),
        &cm,
        &nf,
        &history,
    ]
    .concat()
}
struct PublicContext {
    input: Vec<u8>,
    journal: Vec<u8>,
    old_second_nf: Vec<u8>,
    old_second_cm: Vec<u8>,
    old_second_history: Vec<u8>,
}
fn public_context(n: u32) -> PublicContext {
    assert!(n >= 5 && n % 2 == 1 && n <= 65_531);
    let mut cms = vec![public_hex32(
        "0a2a024097fdf9397429c3af1a9338ed0694f865b7b38d15e58fbe524efc2b51",
    )];
    for bundle in [BOOT, ADMIT] {
        for slot in 0..2 {
            cms.push(hash_at(bundle, 140 + 32 * slot));
        }
    }
    for i in 5..n {
        cms.push(oracle_hash(&[
            b"PUBLIC synthetic predecessor extra CM/",
            &i.to_le_bytes(),
        ]));
    }
    let mut cm = OracleTree::new(16);
    let mut history = OracleTree::new(16);
    for (i, value) in cms.into_iter().enumerate() {
        cm.set(i, oracle_cm(value));
        if i % 2 == 0 {
            history.set(i / 2, oracle_history(i as u32 + 1, cm.root()));
        }
    }
    let values = [ZERO, hash_at(BOOT, 76), hash_at(BOOT, 108)];
    let mut order = [0usize, 1, 2];
    order.sort_by_key(|i| numeric_key(values[*i]));
    assert_eq!(order[0], 0);
    let mut leaves: Vec<_> = values
        .into_iter()
        .map(|value| OracleNf {
            value,
            next: 0,
            next_value: ZERO,
        })
        .collect();
    for rank in 0..2 {
        leaves[order[rank]].next = order[rank + 1] as u32;
        leaves[order[rank]].next_value = values[order[rank + 1]];
    }
    let mut nf = OracleTree::new(17);
    for (i, l) in leaves.iter().enumerate() {
        nf.set(i, l.digest());
    }
    let prior = oracle_state(n, 2, cm.root(), nf.root(), history.root());
    if n == 5 {
        assert_eq!(&prior, &FRESH[STATE_OFFSET..RESERVE_OFFSET]);
    }
    let mut input = FRESH.to_vec();
    input[STATE_OFFSET..RESERVE_OFFSET].copy_from_slice(&prior);
    input[ANCHOR_PATH_OFFSET..NF_OFFSET].copy_from_slice(&history.path(2));
    let old_second_nf = nf_witness(&nf, &leaves, 4, hash_at(FRESH, 92 + 32)).0;
    for i in 0..4 {
        let value = hash_at(FRESH, 92 + 32 * i);
        let index = leaves.len() as u32;
        let (w, pred, leaf) = nf_witness(&nf, &leaves, index, value);
        input[NF_OFFSET + i * NF_WITNESS_LEN..NF_OFFSET + (i + 1) * NF_WITNESS_LEN]
            .copy_from_slice(&w);
        leaves[pred].next = index;
        leaves[pred].next_value = value;
        nf.set(pred, leaves[pred].digest());
        nf.set(index as usize, leaf.digest());
        leaves.push(leaf);
    }
    let old_second_cm = cm.path(n as usize + 1);
    let mut prefix = ZERO;
    for i in 0..4 {
        let path = cm.path(n as usize + i);
        input[CM_PATH_OFFSET + i * 512..CM_PATH_OFFSET + (i + 1) * 512].copy_from_slice(&path);
        cm.set(
            n as usize + i,
            oracle_cm(hash_at(FRESH, 220 + i * kpi_two_v6_binding::RECORD_LEN)),
        );
        if i == 1 {
            prefix = cm.root();
        }
    }
    let hi = (n as usize + 1) / 2;
    let old_second_history = history.path(hi + 1);
    for (i, root) in [prefix, cm.root()].into_iter().enumerate() {
        input[HISTORY_PATH_OFFSET + i * 512..HISTORY_PATH_OFFSET + (i + 1) * 512]
            .copy_from_slice(&history.path(hi + i));
        history.set(hi + i, oracle_history(n + 2 * (i as u32 + 1), root));
    }
    let next = oracle_state(n + 4, 6, cm.root(), nf.root(), history.root());
    let r = u64::from_le_bytes(
        input[RESERVE_OFFSET..ANCHOR_PATH_OFFSET]
            .try_into()
            .unwrap(),
    );
    let fee = u128::from_le_bytes(FRESH[76..92].try_into().unwrap());
    assert_eq!(fee, 80_000_000);
    let journal = [
        b"KPI2V6S1\x01\x00".as_slice(),
        &sha256(&FRESH[..kpi_two_v6_binding::PROJECTION_LEN]),
        &POOL_ID,
        &input[OUTPOINT_OFFSET..STATE_OFFSET],
        &prior,
        &next,
        &r.to_le_bytes(),
        &(r - 80_000_000).to_le_bytes(),
    ]
    .concat();
    assert_eq!(journal.len(), JOURNAL_LEN);
    PublicContext {
        input,
        journal,
        old_second_nf,
        old_second_cm,
        old_second_history,
    }
}

#[test]
fn genuine_bundle_order_is_hidden_witness_only_and_duplicate_rejects() {
    use kpi_two_v6_binding::{compiled::CompiledResearchGate, Bundle, BUNDLE_LEN, PROJECTION_LEN};
    let pair = CompiledResearchGate::new().unwrap();
    let b0 = Bundle::parse(&FRESH[PROJECTION_LEN..PROJECTION_LEN + BUNDLE_LEN]).unwrap();
    let b1 = Bundle::parse(&FRESH[PROJECTION_LEN + BUNDLE_LEN..PROJECTION_LEN + 2 * BUNDLE_LEN])
        .unwrap();
    let swapped = pair.assemble([b1, b0.clone()]).unwrap().bytes().unwrap();
    let mut changed = FRESH.to_vec();
    changed[..PAIR_LEN].copy_from_slice(&swapped);
    let gate = StateGate::new().unwrap();
    let original = gate.evaluate(FRESH).unwrap();
    let reversed = gate.evaluate(&changed).unwrap();
    assert_eq!(original.projection, reversed.projection);
    assert_eq!(original.journal, reversed.journal);
    assert_eq!(original.next_state, reversed.next_state);
    assert!(matches!(
        pair.assemble([b0.clone(), b0]),
        Err(kpi_two_v6_binding::Error::Nullifiers)
    ));
}

#[test]
fn complete_public_trees_match_current_historical_and_capacity_edge() {
    let gate = StateGate::new().unwrap();
    for n in [5, 7, 65_531] {
        let context = public_context(n);
        if n == 5 {
            assert_eq!(context.input, FRESH);
        }
        let verified = gate.evaluate(&context.input).unwrap();
        assert_eq!(verified.journal.as_slice(), context.journal);
        assert_eq!(
            (verified.next_state.cm_count, verified.next_state.nf_count),
            (n + 4, 6)
        );
    }
}

#[test]
fn second_witnesses_from_authentic_old_roots_reject_at_exact_stage() {
    let gate = StateGate::new().unwrap();
    let context = public_context(7);
    let mut bad = context.input.clone();
    bad[NF_OFFSET + NF_WITNESS_LEN..NF_OFFSET + 2 * NF_WITNESS_LEN]
        .copy_from_slice(&context.old_second_nf);
    assert!(matches!(
        gate.evaluate(&bad),
        Err(StateError::NullifierRoot(1))
    ));
    let mut bad = context.input.clone();
    bad[CM_PATH_OFFSET + 512..CM_PATH_OFFSET + 1024].copy_from_slice(&context.old_second_cm);
    assert!(matches!(
        gate.evaluate(&bad),
        Err(StateError::CommitmentOccupied(1))
    ));
    let mut bad = context.input;
    bad[HISTORY_PATH_OFFSET + 512..HISTORY_PATH_OFFSET + 1024]
        .copy_from_slice(&context.old_second_history);
    assert!(matches!(
        gate.evaluate(&bad),
        Err(StateError::HistoryOccupied(1))
    ));
}

#[test]
fn every_short_frame_and_trailing_bytes_reject_before_pair_verification() {
    let gate = StateGate::new().unwrap();
    for n in 0..INPUT_LEN {
        assert!(
            matches!(gate.evaluate(&FRESH[..n]),Err(StateError::Length { expected:INPUT_LEN,actual }) if actual==n)
        );
    }
    let mut longer = FRESH.to_vec();
    longer.push(0);
    assert!(
        matches!(gate.evaluate(&longer),Err(StateError::Length { expected:INPUT_LEN,actual }) if actual==INPUT_LEN+1)
    );
}

#[test]
fn legal_count_frontier_agrees_with_wider_integer_oracle() {
    for n in (1u32..65_536).step_by(2) {
        for m in [0, 2, 2 * n - 2, 2 * n] {
            let state = State {
                cm_count: n,
                nf_count: m,
                cm_root: ZERO,
                nf_root: ZERO,
                history_root: ZERO,
            };
            let parsed = State::parse(&state.bytes());
            if m == 0 {
                assert!(matches!(parsed, Err(StateError::Uninitialized)));
                continue;
            }
            assert!(parsed.is_ok());
            let expected = u64::from(n) + 4 < 65_536 && u64::from(m) + 4 < 131_071;
            assert_eq!(state.successor_counts().is_ok(), expected);
        }
    }
    for n in [0, 2, 65_536, u32::MAX] {
        let state = State {
            cm_count: n,
            nf_count: 2,
            cm_root: ZERO,
            nf_root: ZERO,
            history_root: ZERO,
        };
        assert!(matches!(
            State::parse(&state.bytes()),
            Err(StateError::StateCounts)
        ));
    }
}

#[test]
fn numeric_nf_comparator_matches_two_u128_oracle_at_every_bit() {
    for bit in 0..256 {
        let mut single = ZERO;
        single[bit / 8] = 1 << (bit % 8);
        for other in [ZERO, [0xff; 32], single] {
            assert_eq!(
                less_le(single, other),
                numeric_key(single) < numeric_key(other)
            );
            assert_eq!(
                less_le(other, single),
                numeric_key(other) < numeric_key(single)
            );
        }
        for second in 0..256 {
            let mut other = ZERO;
            other[second / 8] = 1 << (second % 8);
            assert_eq!(
                less_le(single, other),
                numeric_key(single) < numeric_key(other)
            );
        }
    }
}

#[test]
fn full_seventeenth_bit_nf_paths_accept_and_16_bit_aliases_reject() {
    // Path geometry only: this supplied public context is not a proved or
    // accepted ledger lineage. Keep the previous small-NF contexts unchanged.
    let n = 65_531u32;
    let m = 2 * (n - 4);
    let mut context = public_context(n);
    let pair_nfs: Vec<_> = (0..4).map(|i| hash_at(FRESH, 92 + 32 * i)).collect();
    let mut predecessor = *pair_nfs.iter().min_by_key(|v| numeric_key(**v)).unwrap();
    for byte in &mut predecessor {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    assert!(numeric_key(predecessor).0 > 0);
    let mut values = vec![ZERO, hash_at(BOOT, 76), hash_at(BOOT, 108)];
    for value in &values[1..] {
        assert!(numeric_key(*value).0 > 0);
    }
    assert!(!values.contains(&predecessor) && !pair_nfs.contains(&predecessor));
    for i in 1..=m - 3 {
        let mut value = ZERO;
        value[..4].copy_from_slice(&i.to_le_bytes());
        values.push(value);
    }
    values.push(predecessor);
    assert_eq!(values.len(), m as usize + 1);
    assert!(pair_nfs.iter().all(|v| !values.contains(v)));
    let mut order: Vec<_> = (0..values.len()).collect();
    order.sort_by_key(|i| numeric_key(values[*i]));
    assert!(order.windows(2).all(|w| values[w[0]] != values[w[1]]));
    let mut leaves: Vec<_> = values
        .iter()
        .map(|value| OracleNf {
            value: *value,
            next: 0,
            next_value: ZERO,
        })
        .collect();
    for rank in 0..order.len() - 1 {
        leaves[order[rank]].next = order[rank + 1] as u32;
        leaves[order[rank]].next_value = values[order[rank + 1]];
    }
    let mut nf = OracleTree::new(17);
    for (i, leaf) in leaves.iter().enumerate() {
        nf.set(i, leaf.digest());
    }
    context.input[STATE_OFFSET + 5..STATE_OFFSET + 9].copy_from_slice(&m.to_le_bytes());
    context.input[STATE_OFFSET + 41..STATE_OFFSET + 73].copy_from_slice(&nf.root());
    let prior = context.input[STATE_OFFSET..RESERVE_OFFSET].to_vec();
    let mut append_alias = None;
    let mut predecessor_alias = None;
    for (slot, value) in pair_nfs.into_iter().enumerate() {
        let index = leaves.len() as u32;
        assert!(index > 65_535);
        let (w, pred, leaf) = nf_witness(&nf, &leaves, index, value);
        if pred > 65_535 && predecessor_alias.is_none() {
            let aliased = pred & 0xffff;
            assert!(aliased > 0);
            let mut bad = w.clone();
            bad[..4].copy_from_slice(&(aliased as u32).to_le_bytes());
            bad[72..616].copy_from_slice(&nf.path(aliased));
            predecessor_alias = Some((slot, bad));
        }
        context.input[NF_OFFSET + slot * NF_WITNESS_LEN..NF_OFFSET + (slot + 1) * NF_WITNESS_LEN]
            .copy_from_slice(&w);
        leaves[pred].next = index;
        leaves[pred].next_value = value;
        nf.set(pred, leaves[pred].digest());
        if slot == 0 {
            append_alias = Some(nf.path(index as usize & 0xffff));
        }
        nf.set(index as usize, leaf.digest());
        leaves.push(leaf);
    }
    let mut next = context.journal[215..320].to_vec();
    next[5..9].copy_from_slice(&(m + 4).to_le_bytes());
    next[41..73].copy_from_slice(&nf.root());
    let r = u64::from_le_bytes(
        context.input[RESERVE_OFFSET..ANCHOR_PATH_OFFSET]
            .try_into()
            .unwrap(),
    );
    let expected = [
        b"KPI2V6S1\x01\x00".as_slice(),
        &sha256(&FRESH[..kpi_two_v6_binding::PROJECTION_LEN]),
        &POOL_ID,
        &context.input[OUTPOINT_OFFSET..STATE_OFFSET],
        &prior,
        &next,
        &r.to_le_bytes(),
        &(r - 80_000_000).to_le_bytes(),
    ]
    .concat();
    let gate = StateGate::new().unwrap();
    let accepted = gate.evaluate(&context.input).unwrap();
    assert_eq!(accepted.journal.as_slice(), expected);
    assert_eq!(accepted.next_state.nf_count, 131_058);
    let mut bad = context.input.clone();
    bad[NF_OFFSET + 616..NF_OFFSET + 1160].copy_from_slice(&append_alias.unwrap());
    assert!(matches!(
        gate.evaluate(&bad),
        Err(StateError::NullifierOccupied(0))
    ));
    let (slot, witness) =
        predecessor_alias.expect("at least one actual17th-bit predecessor must be exercised");
    let mut bad = context.input;
    bad[NF_OFFSET + slot * NF_WITNESS_LEN..NF_OFFSET + (slot + 1) * NF_WITNESS_LEN]
        .copy_from_slice(&witness);
    assert!(matches!(gate.evaluate(&bad),Err(StateError::NullifierRoot(i)) if i==slot));
}
