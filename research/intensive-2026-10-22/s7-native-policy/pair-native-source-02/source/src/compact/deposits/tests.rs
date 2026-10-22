use super::*;
fn state() -> (PublicState, Authorization) {
    let old = PublicState::initial([1; 32]).unwrap();
    let mut a = Authorization {
        domain: [9; 32],
        count: 1,
        anchor: old.cm_tree().unwrap().root(),
        nullifier: [2; 32],
        outputs: [[3; 32], [4; 32]],
        mode: 1,
        payout: 0,
        fee: 1,
        spk: [0; 36],
        bootstrap: CONTRIBUTION,
        cipher_hash: hash(&[0; 370]),
    };
    let old = old.witness(&a).unwrap().0;
    a.outputs = [[5; 32], [6; 32]];
    (old, a)
}
#[test]
fn admission_retains_spentness_and_every_old_anchor() {
    let (mut old, a) = state();
    let nf = old.nullifiers.clone();
    for i in 0..32u8 {
        let roots = old.roots.clone();
        let mut a = a.clone();
        a.outputs = [[i + 10; 32], [i + 60; 32]];
        let (next, w) = admission(&old, &a).unwrap();
        assert_eq!(next.nullifiers, nf);
        assert_eq!(next.roots[..roots.len()], roots);
        assert_eq!(next.commitments[..old.commitments.len()], old.commitments);
        assert_eq!(w[..W_CM_APPEND], vec![0; W_CM_APPEND]);
        assert_eq!(
            next.compact().unwrap().cm_count,
            old.compact().unwrap().cm_count + 2
        );
        old = next;
    }
}
#[test]
fn admission_boundaries_and_state_version() {
    let (old, a) = state();
    let initial = PublicState::initial([1; 32]).unwrap();
    assert!(admission(&initial, &a).is_err());
    let mut a = a.clone();
    a.bootstrap = 2 * NOTE_FLOOR + a.fee;
    assert!(admission(&old, &a).is_ok());
    a.bootstrap -= 1;
    assert!(admission(&old, &a).is_err());
    a.bootstrap = MAX_SOMPI + 1;
    assert!(admission(&old, &a).is_err());
    a.bootstrap = CONTRIBUTION;
    a.count = 3;
    assert!(admission(&old, &a).is_err());
    let s = old.compact().unwrap();
    assert!(parse_state(&s.bytes()).is_err());
    assert!(State::parse(&state_bytes(&s)).is_err());
    assert_eq!(parse_state(&state_bytes(&s)).unwrap(), s);
}
#[test]
fn fee_floor_and_fixed_framing() {
    let f = fees().unwrap();
    assert!(f.exit + PAYOUT_FLOOR <= NOTE_FLOOR);
    assert!(f.deposit > f.transfer);
    let (old, _) = state();
    let redeem = covenant::redeem(&[1; 32], &old.compact().unwrap(), &[0; 328]).unwrap();
    let sig = covenant::signature(&[0; 128], &redeem).unwrap();
    assert_eq!(sig.len(), covenant::WITNESS_LEN);
    assert_eq!(&sig[130..133], &[0x4d, 0, 56]);
}
