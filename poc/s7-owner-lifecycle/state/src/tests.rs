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
