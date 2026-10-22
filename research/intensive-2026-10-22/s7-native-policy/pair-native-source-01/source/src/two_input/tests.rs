use super::*;
use tree::{PublicState, Tree};

#[test]
fn declared_binary_layout_has_no_field_overlap() {
    let d = [9; 32];
    let a = Authorization {
        domain: d,
        count: 3,
        anchor: [1; 32],
        nfs: [[2; 32], [3; 32]],
        outputs: [[4; 32], [5; 32]],
        mode: 1,
        payout: 10_000_000,
        fee: FEE,
        spk: [6; 36],
        deposit: 7,
        funding: [8; 36],
        funding_spk: [9; 36],
        bootstrap: 10,
        cipher_hash: [11; 32],
    };
    let b = a.bytes();
    assert_eq!(b.len(), 377);
    assert_eq!(Authorization::parse(&b).unwrap().bytes(), b);
    assert!(Authorization::parse(&b[..376]).is_err());
    let mut longer = b.clone();
    longer.push(0);
    assert!(Authorization::parse(&longer).is_err());
    assert_eq!(P_WITNESS + W_LEN, PAYLOAD_SIZE);
    assert_eq!(W_NF + 2 * NF_WIT, W_CM_APPEND);
    assert_eq!(W_CM_APPEND + 2 * PATH_LEN, W_HISTORY_APPEND);
    assert_eq!(W_HISTORY_APPEND + PATH_LEN, W_LEN);
}
#[test]
fn depth_seventeen_merkle_positions_and_empty_append_are_authenticated() {
    for depth in [16, 17] {
        let leaves = (0u32..37)
            .map(|i| hash(&i.to_le_bytes()))
            .collect::<Vec<_>>();
        let t = Tree::new(leaves.clone(), depth).unwrap();
        for i in [0, 1, 16, 36] {
            let p = t.path(i).unwrap();
            assert_eq!(tree::root_from(leaves[i as usize], i, &p), t.root());
            assert_ne!(tree::root_from(leaves[i as usize], i ^ 1, &p), t.root());
        }
        assert_eq!(tree::root_from([0; 32], 37, &t.path(37).unwrap()), t.root());
        assert!(t.path(1 << depth).is_err());
    }
}
#[test]
fn nullifier_headroom_covers_one_note_exits_without_new_commitments() {
    // Exhaust all allowed CM counts and boundary histories. Counts alone cannot
    // prove monetary solvency; the circuit's at-least-one-real-input rule is needed.
    for c in (1u32..65536).step_by(2) {
        for t in [0, c / 2, c - 1, c] {
            let n = 2 * t;
            let remaining = c - t;
            assert!(1 + n + 2 * remaining < (1 << 17));
        }
    }
    let mut s = PublicState::initial([7; 32]).unwrap().compact().unwrap();
    s.nf_count = 1;
    assert!(s.check().is_err());
    s.nf_count = 2;
    assert!(s.check().is_ok());
    s.nf_count = 4;
    assert!(s.check().is_err());
}
#[test]
fn sequential_nullifier_insertion_rejects_duplicate_and_preserves_prior_set() {
    let mut s = PublicState::initial([8; 32]).unwrap();
    let initial = s.clone();
    for i in 0u8..24 {
        let a = Authorization {
            domain: [9; 32],
            count: s.commitments.len() as u32,
            anchor: s.cm_tree().unwrap().root(),
            nfs: [hash(&[i, 0]), hash(&[i, 1])],
            outputs: [hash(&[i, 2]), hash(&[i, 3])],
            mode: 1,
            payout: 0,
            fee: FEE,
            spk: [0; 36],
            deposit: 0,
            funding: [0; 36],
            funding_spk: [0; 36],
            bootstrap: 0,
            cipher_hash: [0; 32],
        };
        let (next, w) = s.witness(&a).unwrap();
        assert_eq!(w.len(), W_LEN);
        assert!(next.spent(&a.nfs[0]) && next.spent(&a.nfs[1]));
        for old in &s.nullifiers {
            assert!(next.spent(&old.value));
        }
        assert!(next.witness(&a).is_err());
        s = next;
    }
    assert_eq!(s.roots[0], initial.roots[0]);
    assert_eq!(s.nullifiers.len(), 49);
}

#[test]
fn incremental_public_tree_matches_reconstruction() {
    for depth in [16, 17] {
        let mut t = Tree::new(vec![], depth).unwrap();
        let mut leaves = Vec::new();
        for i in 0u32..65 {
            let h = hash(&i.to_le_bytes());
            t.append(h).unwrap();
            leaves.push(h);
            let rebuilt = Tree::new(leaves.clone(), depth).unwrap();
            assert_eq!(t.root(), rebuilt.root());
            assert_eq!(t.path(i).unwrap(), rebuilt.path(i).unwrap());
        }
    }
}
