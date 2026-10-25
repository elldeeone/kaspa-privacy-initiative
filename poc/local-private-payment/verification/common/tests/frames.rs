//! Independently serialized synthetic public frames. CV/proof bytes are invalid.
//! These tests assert framing/state/hash agreement, never financial acceptance.
use kpi_local_private_payment_verifier::wire::{self, Projection};
const PAYMENT: &[u8] = include_bytes!("fixtures/payment.projection.bin");
const EXIT_CONTINUING: &[u8] = include_bytes!("fixtures/exit-continuing.projection.bin");
const EXIT_TERMINAL: &[u8] = include_bytes!("fixtures/exit-terminal.projection.bin");
#[test]
fn independent_payment_frame_state_and_effects_agree() {
    let p = Projection::parse(PAYMENT).unwrap();
    wire::validate_transition(&p).unwrap();
    assert_eq!(hex::encode(wire::effects_digest(&p)), "150fe0a551a72d7262227c86cea4c2cefc0f635997a74a1cb2cac1654f19ee14");
    assert_eq!(p.body.spends.len(), 1);
    assert_eq!(p.body.outputs.len(), 2);
    assert_eq!(p.body.old.n + 2, p.body.new.n);
    assert_eq!(p.body.old.m + 1, p.body.new.m);
}
#[test]
fn independent_continuing_and_terminal_exit_frames_agree() {
    for (raw, expected) in [(EXIT_CONTINUING, "e20f5e85ab8ca3a699e295cf2b3735873bdf709f8e7eca9dcae9da8e76de8e48"), (EXIT_TERMINAL, "f16a6b465c7b67498955d25d5055327809dc63ed312c73b2644fc67b9615ca57")] {
        let p = wire::ExitProjection::parse(raw).unwrap();
        wire::validate_exit_transition(&p).unwrap();
        assert_eq!(hex::encode(wire::exit_effects_digest(&p)), expected);
    }
}
fn mutated(at: usize, value: &[u8]) -> Vec<u8> {
    let mut b = PAYMENT.to_vec();
    b[wire::PREFIX_LEN + at..wire::PREFIX_LEN + at + value.len()].copy_from_slice(value);
    b
}
#[test]
fn missing_extra_old_shape_domain_reserved_and_zero_nf_refuse() {
    assert!(Projection::parse(&PAYMENT[..PAYMENT.len()-1]).is_err());
    let mut extra = PAYMENT.to_vec(); extra.push(0);
    assert!(Projection::parse(&extra).is_err());
    for (at, value) in [(8, vec![1,0,3,0,6,0,0,0]), (0, b"KPX8PB01".to_vec()), (16, vec![0;32]), (80, vec![1;32]), (436, vec![0;32])] {
        assert!(Projection::parse(&mutated(at,&value)).is_err());
    }
}
#[test]
fn zero_empty_and_duplicate_output_commitments_refuse() {
    for cm in [[0;32], kpi_local_private_payment_verifier::sha(&[b"KPX1CME\0"])] {
        assert!(Projection::parse(&mutated(532,&cm)).is_err());
    }
    let first_cm = PAYMENT[wire::PREFIX_LEN+532..wire::PREFIX_LEN+564].to_vec();
    assert!(Projection::parse(&mutated(1052,&first_cm)).is_err());
}
#[test]
fn wrong_paths_stale_roots_ciphertext_fee_and_capacities_refuse() {
    for at in [1572+72, 1572+616, 2732, 2732+512, 148+76] {
        let mut b = PAYMENT.to_vec(); b[wire::PREFIX_LEN+at] ^= 1;
        let p = Projection::parse(&b).unwrap();
        assert!(wire::validate_transition(&p).is_err());
    }
    for at in [388,532+96] {
        let mut b = PAYMENT.to_vec(); b[wire::PREFIX_LEN+at] ^= 1;
        assert!(Projection::parse(&b).is_err());
    }
    for at in [148+72,268+72,148+108,268+108] {
        assert!(Projection::parse(&mutated(at,&u32::MAX.to_le_bytes())).is_err());
    }
}
#[test]
fn synthetic_frames_have_no_financial_authority() {
    assert!(kpi_local_private_payment_verifier::evaluate(PAYMENT).is_err());
    assert!(kpi_local_private_payment_verifier::evaluate_exit(EXIT_TERMINAL,&[0;128]).is_err());
}
