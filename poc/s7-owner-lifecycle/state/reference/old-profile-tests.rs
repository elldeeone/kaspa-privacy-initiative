use super::*;

const CURRENT: &[u8] = include_bytes!("../../public-fixtures/current-anchor/input.bin");
const HISTORICAL: &[u8] = include_bytes!("../../public-fixtures/historical-anchor/input.bin");
const CURRENT_J: &[u8] =
    include_bytes!("../../public-fixtures/current-anchor/expected-journal.bin");
const HISTORICAL_J: &[u8] =
    include_bytes!("../../public-fixtures/historical-anchor/expected-journal.bin");
const CURRENT_NEXT: &[u8] =
    include_bytes!("../../public-fixtures/current-anchor/expected-next-state.bin");
const HISTORICAL_NEXT: &[u8] =
    include_bytes!("../../public-fixtures/historical-anchor/expected-next-state.bin");

fn mutate(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[at] ^= 1;
    changed
}
fn set_count(bytes: &[u8], at: usize, count: u32) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[at..at + 4].copy_from_slice(&count.to_le_bytes());
    changed
}

#[test]
fn genuine_current_and_historical_pairs_match_independent_all_bytes() {
    let gate = StateGate::new().unwrap();
    for (input, journal, next, n) in [
        (CURRENT, CURRENT_J, CURRENT_NEXT, 7),
        (HISTORICAL, HISTORICAL_J, HISTORICAL_NEXT, 9),
    ] {
        let actual = gate.evaluate(input).unwrap();
        assert_eq!(actual.journal, journal);
        assert_eq!(actual.next_state.bytes(), next);
        assert_eq!(actual.projection, input[..1088]);
        assert_eq!(actual.next_state.cm_count, n);
        assert_eq!(actual.next_state.nf_count, 6);
        assert_eq!(actual.reserve_before, 1_700_000_000);
        assert_eq!(actual.reserve_after, 1_620_000_000);
        assert_eq!(&actual.journal[10..42], &sha256(&actual.projection));
        assert_ne!(sha256(&actual.journal), sha256(&actual.projection));
        assert_eq!(
            State::parse(&actual.next_state.bytes()).unwrap(),
            actual.next_state
        );
    }
}

#[test]
fn exact_lengths_magic_version_and_initialized_state() {
    let gate = StateGate::new().unwrap();
    assert!(matches!(
        gate.evaluate(&CURRENT[..INPUT_LEN - 1]),
        Err(StateError::Length { .. })
    ));
    let mut extra = CURRENT.to_vec();
    extra.push(0);
    assert!(matches!(
        gate.evaluate(&extra),
        Err(StateError::Length { .. })
    ));
    let mut old_version = CURRENT.to_vec();
    old_version[STATE_OFFSET] = 6;
    assert!(matches!(
        gate.evaluate(&old_version),
        Err(StateError::StateVersion)
    ));
    let bootstrap = set_count(CURRENT, STATE_OFFSET + 5, 0);
    assert!(matches!(
        gate.evaluate(&bootstrap),
        Err(StateError::Uninitialized)
    ));
    for n in [0, 2, 65_536, u32::MAX] {
        assert!(matches!(
            gate.evaluate(&set_count(CURRENT, STATE_OFFSET + 1, n)),
            Err(StateError::StateCounts)
        ));
    }
    for m in [1, 7, 131_071, u32::MAX] {
        assert!(matches!(
            gate.evaluate(&set_count(CURRENT, STATE_OFFSET + 5, m)),
            Err(StateError::StateCounts)
        ));
    }
}

#[test]
fn count_capacity_and_two_prefix_room_boundaries() {
    let mut s = State::parse(&CURRENT[STATE_OFFSET..RESERVE_OFFSET]).unwrap();
    s.cm_count = 65_531;
    s.nf_count = 131_062;
    assert_eq!(s.successor_counts().unwrap(), (65_535, 131_066));
    assert!((s.cm_count + 1) / 2 + 1 < 65_536);
    s.cm_count = 65_533;
    assert!(matches!(s.successor_counts(), Err(StateError::Capacity)));
    s.cm_count = 65_535;
    s.nf_count = 131_070;
    assert!(s.check().is_ok());
    assert!(matches!(s.successor_counts(), Err(StateError::Capacity)));
}

#[test]
fn fee_narrowing_checked_sompi_and_positive_successor() {
    assert_eq!(reserve_after(80_000_001, 80_000_000).unwrap(), 1);
    assert_eq!(reserve_after(MAX_SOMPI, 1).unwrap(), MAX_SOMPI - 1);
    assert!(matches!(reserve_after(MAX_SOMPI, 0), Err(StateError::Fee)));
    for fee in [MAX_SOMPI as u128 + 1, u64::MAX as u128 + 1, u128::MAX] {
        assert!(matches!(
            reserve_after(MAX_SOMPI, fee),
            Err(StateError::Fee)
        ));
    }
    for reserve in [0, 79_999_999, 80_000_000, MAX_SOMPI + 1, u64::MAX] {
        assert!(matches!(
            reserve_after(reserve, 80_000_000),
            Err(StateError::Reserve)
        ));
    }
    // Helper boundary coverage is arithmetic only. Genuine pair fees are fixed
    // by proofs; it does not create valid maximum-fee proof fixtures.
}

#[test]
fn wrong_or_stale_roots_and_cross_context_paths_reject() {
    let gate = StateGate::new().unwrap();
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, ANCHOR_PATH_OFFSET)),
        Err(StateError::HistoricalRoot)
    ));
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, STATE_OFFSET + 73)),
        Err(StateError::HistoricalRoot)
    ));
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, STATE_OFFSET + 9)),
        Err(StateError::CurrentAnchor)
    ));
    assert!(matches!(
        gate.evaluate(&mutate(HISTORICAL, STATE_OFFSET + 9)),
        Err(StateError::CommitmentOccupied(0))
    ));
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, STATE_OFFSET + 41)),
        Err(StateError::NullifierRoot(0))
    ));
    let mut cross = HISTORICAL.to_vec();
    cross[ANCHOR_PATH_OFFSET..NF_OFFSET].copy_from_slice(&CURRENT[ANCHOR_PATH_OFFSET..NF_OFFSET]);
    assert!(matches!(
        gate.evaluate(&cross),
        Err(StateError::HistoricalRoot)
    ));
    let stale_count = set_count(CURRENT, STATE_OFFSET + 1, 1);
    assert!(matches!(
        gate.evaluate(&stale_count),
        Err(StateError::HistoricalCount)
    ));
}

#[test]
fn every_sequential_nf_path_and_empty_slot_is_authenticated() {
    let gate = StateGate::new().unwrap();
    for slot in 0..4 {
        let base = NF_OFFSET + slot * NF_WITNESS_LEN;
        assert!(
            matches!(gate.evaluate(&mutate(CURRENT, base + 72)), Err(StateError::NullifierRoot(i)) if i == slot)
        );
        assert!(
            matches!(gate.evaluate(&mutate(CURRENT, base + 616)), Err(StateError::NullifierOccupied(i)) if i == slot)
        );
        let bad_index = set_count(CURRENT, base, 3 + slot as u32);
        assert!(
            matches!(gate.evaluate(&bad_index), Err(StateError::NullifierIndex(i)) if i == slot)
        );
    }
    let mut reordered = CURRENT.to_vec();
    let first = CURRENT[NF_OFFSET..NF_OFFSET + NF_WITNESS_LEN].to_vec();
    reordered[NF_OFFSET..NF_OFFSET + NF_WITNESS_LEN]
        .copy_from_slice(&CURRENT[NF_OFFSET + NF_WITNESS_LEN..NF_OFFSET + 2 * NF_WITNESS_LEN]);
    reordered[NF_OFFSET + NF_WITNESS_LEN..NF_OFFSET + 2 * NF_WITNESS_LEN].copy_from_slice(&first);
    assert!(gate.evaluate(&reordered).is_err());
    let mut replay = CURRENT.to_vec();
    replay[NF_OFFSET + NF_WITNESS_LEN..NF_OFFSET + 2 * NF_WITNESS_LEN].copy_from_slice(&first);
    assert!(gate.evaluate(&replay).is_err());
}

#[test]
fn predecessor_terminal_sentinel_and_double_spend_rules() {
    let mut witness = vec![0; NF_WITNESS_LEN];
    let nf = {
        let mut n = ZERO;
        n[0] = 3;
        n
    };
    // These malformed controls stop before tree authentication.
    witness[36..40].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierLink(0))
    ));
    witness[36..40].fill(0);
    witness[4] = 1;
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierLink(0))
    ));
    witness[4] = 0;
    witness[40] = 4;
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierLink(0))
    ));
    witness[36..40].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierLink(0))
    ));
    witness[36..40].copy_from_slice(&1u32.to_le_bytes());
    witness[40] = 3;
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierOrder(0))
    ));
    witness[40] = 4;
    witness[4..36].copy_from_slice(&nf);
    witness[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        insert_nf(ZERO, 3, nf, &witness, 0),
        Err(StateError::NullifierOrder(0))
    ));
}

#[test]
fn complete_record_duplicate_commitments_append_with_multiplicity() {
    // Encoding/tree-only control. No synthetic proof is accepted. Two equal
    // committed records are two leaves at distinct physical positions.
    let empty = {
        let mut p = Vec::new();
        let mut h = ZERO;
        for _ in 0..16 {
            p.extend_from_slice(&h);
            h = node(h, h);
        }
        p
    };
    let root0 = fold(ZERO, 0, &empty);
    let leaf = cm_leaf([9; 32]);
    let root1 = append(root0, 0, leaf, &empty, StateError::CommitmentOccupied(0)).unwrap();
    let mut second_path = empty.clone();
    second_path[..32].copy_from_slice(&leaf);
    let root2 = append(
        root1,
        1,
        leaf,
        &second_path,
        StateError::CommitmentOccupied(1),
    )
    .unwrap();
    let mut expected = node(leaf, leaf);
    for sibling in empty[32..].chunks_exact(32) {
        expected = node(expected, sibling.try_into().unwrap());
    }
    assert_eq!(root2, expected);
    assert_ne!(root1, root2);
    assert!(matches!(
        append(root1, 0, leaf, &empty, StateError::CommitmentOccupied(0)),
        Err(StateError::CommitmentOccupied(0))
    ));
}

#[test]
fn four_cm_and_both_history_paths_are_sequential() {
    let gate = StateGate::new().unwrap();
    for i in 0..4 {
        assert!(
            matches!(gate.evaluate(&mutate(CURRENT, CM_PATH_OFFSET + i * 512)), Err(StateError::CommitmentOccupied(slot)) if slot == i)
        );
    }
    for i in 0..2 {
        assert!(
            matches!(gate.evaluate(&mutate(CURRENT, HISTORY_PATH_OFFSET + i * 512)), Err(StateError::HistoryOccupied(slot)) if slot == i)
        );
    }
    let mut skipped_prefix = CURRENT.to_vec();
    skipped_prefix[HISTORY_PATH_OFFSET..HISTORY_PATH_OFFSET + 512]
        .copy_from_slice(&CURRENT[HISTORY_PATH_OFFSET + 512..]);
    assert!(matches!(
        gate.evaluate(&skipped_prefix),
        Err(StateError::HistoryOccupied(0))
    ));
}

#[test]
fn numeric_nf_order_differs_from_public_raw_sort() {
    let mut a = ZERO;
    a[0] = 1;
    let mut b = ZERO;
    b[1] = 1;
    assert!(a > b);
    assert!(less_le(a, b));
    let nfs: Vec<Hash> = (0..4).map(|i| hash_at(CURRENT, 92 + 32 * i)).collect();
    assert!(nfs.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(nfs.windows(2).any(|pair| !less_le(pair[0], pair[1])));
}

#[test]
fn declared_outpoint_and_reserve_bind_journal_without_claiming_native_authentication() {
    let gate = StateGate::new().unwrap();
    let original = gate.evaluate(CURRENT).unwrap();
    let mut context = CURRENT.to_vec();
    context[OUTPOINT_OFFSET..OUTPOINT_OFFSET + 32].fill(0x77);
    context[OUTPOINT_OFFSET + 32..STATE_OFFSET].copy_from_slice(&u32::MAX.to_le_bytes());
    let changed = gate.evaluate(&context).unwrap();
    assert_ne!(changed.journal, original.journal);
    assert_eq!(changed.next_state, original.next_state);
    assert_eq!(
        &changed.journal[74..110],
        &context[OUTPOINT_OFFSET..STATE_OFFSET]
    );
    for reserve in [80_000_001, MAX_SOMPI] {
        context[RESERVE_OFFSET..ANCHOR_PATH_OFFSET].copy_from_slice(&reserve.to_le_bytes());
        let changed = gate.evaluate(&context).unwrap();
        assert_eq!(changed.reserve_after, reserve - 80_000_000);
        assert_ne!(changed.journal, original.journal);
    }
}

#[test]
fn unchanged_pair_gate_rejects_mutated_proof_and_publication() {
    let gate = StateGate::new().unwrap();
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, 1088 + 377)),
        Err(StateError::Binding(_))
    ));
    assert!(matches!(
        gate.evaluate(&mutate(CURRENT, 76)),
        Err(StateError::Binding(_))
    ));
    // A successor substituted as predecessor with old paths cannot replay.
    let result = gate.evaluate(CURRENT).unwrap();
    let mut replay = CURRENT.to_vec();
    replay[STATE_OFFSET..RESERVE_OFFSET].copy_from_slice(&result.next_state.bytes());
    assert!(matches!(
        gate.evaluate(&replay),
        Err(StateError::HistoricalRoot)
    ));
}

#[test]
fn independently_rebuilt_current_set_already_spent_nf_rejects_at_gap_check() {
    // Independent reviewer rebuilt a locally consistent NF tree containing the
    // first genuine pair NF, with authentic predecessor/path and unchanged CM,
    // history, pair and reserve. Rejection therefore tests current spentness,
    // rather than merely stale history or a malformed Merkle path.
    let spent = include_bytes!("../fixtures/already-spent-first-nf.bin");
    assert_eq!(&spent[..PAIR_LEN], &CURRENT[..PAIR_LEN]);
    let gate = StateGate::new().unwrap();
    assert!(matches!(
        gate.evaluate(spent),
        Err(StateError::NullifierOrder(0))
    ));
}

#[test]
fn domain_separator_and_wire_offsets_are_pinned() {
    assert_eq!(POOL_ID, sha256(b"KPI/public-two-v6-state/DO-NOT-FUND/v1"));
    assert_eq!(HISTORY_PATH_OFFSET + 2 * 512, INPUT_LEN);
    assert_eq!(&CURRENT_J[..10], b"KPI2V6S1\x01\0");
    assert_eq!(&CURRENT_J[42..74], &POOL_ID);
    assert_eq!(&CURRENT_J[110..215], &CURRENT[STATE_OFFSET..RESERVE_OFFSET]);
}
