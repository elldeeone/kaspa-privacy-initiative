//! Offline new-format experiment only. Genuine native private/reveal union;
//! no old wallet, proof parameter, replay or owner workflow imports.
pub mod native;
pub mod policy;

#[cfg(test)]
mod tests {
    use super::{native, policy};
    use kaspa_consensus_core::{
        hashing::sighash::SigHashReusedValuesUnsync, tx::PopulatedTransaction,
    };
    use kaspa_txscript::{opcodes::codes::*, parse_script};
    fn state() -> [u8; 112] {
        let mut s = [0; 112];
        s[..8].copy_from_slice(policy::STATE_MAGIC);
        s[8..40].copy_from_slice(&policy::DOMAIN);
        s[72..76].copy_from_slice(&1u32.to_le_bytes());
        s[108..112].copy_from_slice(&1u32.to_le_bytes());
        s
    }
    #[test]
    fn actual_opcode_branches_and_no_padding() {
        let r = policy::redeem(&state(), &[0; 328]).unwrap();
        let parsed = parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(&r)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut depth = 0;
        let mut zk = 0;
        let mut schnorr = 0;
        let mut nop = 0;
        for op in parsed {
            match op.value() {
                OpIf | OpNotIf => depth += 1,
                OpEndIf => {
                    assert!(depth > 0);
                    depth -= 1
                }
                OpZkPrecompile => {
                    assert_eq!(depth, 1, "G16 must execute in only one outer branch");
                    zk += 1
                }
                OpCheckSig => {
                    assert_eq!(
                        depth, 2,
                        "Schnorr belongs only to reveal, below private/admission selection"
                    );
                    schnorr += 1
                }
                OpNop => nop += 1,
                _ => {}
            }
        }
        assert_eq!((zk, schnorr, nop, depth), (1, 1, 0, 0));
    }
    #[test]
    fn successor_state_change_cannot_change_policy_suffix() {
        let a = state();
        let mut b = a;
        b[40..72].fill(4);
        b[72..76].copy_from_slice(&65535u32.to_le_bytes());
        b[76..108].fill(5);
        b[108..112].copy_from_slice(&131071u32.to_le_bytes());
        let x = policy::redeem(&a, &[3; 328]).unwrap();
        let y = policy::redeem(&b, &[3; 328]).unwrap();
        assert_eq!(x.len(), y.len());
        assert_eq!(&x[114..], &y[114..]);
        assert_ne!(&x[..114], &y[..114]);
        let z = policy::redeem(&a, &[7; 328]).unwrap();
        assert_ne!(&x[114..], &z[114..], "VK is part of immutable policy");
    }
    #[test]
    fn exact_common_witness_and_new_profile_boundary() {
        let mut s = state();
        let r = policy::redeem(&s, &[0; 328]).unwrap();
        let w = policy::witness(&[0; 65], &[0; 128], &r).unwrap();
        assert_eq!(w[0], 65);
        assert_eq!(&w[66..68], &[OpPushData1, 128]);
        assert_eq!(w[196], OpPushData2);
        assert_eq!(
            u16::from_le_bytes(w[197..199].try_into().unwrap()) as usize,
            r.len()
        );
        assert_eq!(&w[199..], r.as_slice());
        s[8] ^= 1;
        assert!(policy::redeem(&s, &[0; 328]).is_err());
        assert!(policy::redeem(&state(), &[0; 327]).is_err());
    }
    fn preparation() -> native::FundingPrepVector {
        let secret = [7; 32];
        let pair = secp256k1::Keypair::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&secret).unwrap(),
        );
        native::FundingPrepVector {
            source_previous_txid_raw_hex: hex::encode([9; 32]),
            source_previous_index: 3,
            source_amount_sompi: 4_000_000_000,
            source_secret_hex: hex::encode(secret),
            outputs: vec![native::FundingPrepOutput {
                value_sompi: 120_000_000,
                xonly_public_key_hex: hex::encode(pair.x_only_public_key().0.serialize()),
            }],
            fee_sompi: 1_000_000,
            source_change_sompi: 3_879_000_000,
            funding_sighash_type: 2,
        }
    }
    #[test]
    fn ordinary_preparation_conserves_and_checks_boundaries() {
        let mut v = preparation();
        let (tx, entries) = native::funding_prep_body(&v).unwrap();
        assert_eq!(entries[0].amount, 4_000_000_000);
        assert_eq!(
            tx.outputs.iter().map(|o| o.value).sum::<u64>() + v.fee_sompi,
            entries[0].amount
        );
        assert_eq!(tx.outputs.len(), 2);
        v.source_change_sompi += 1;
        assert!(native::funding_prep_body(&v).is_err());
        v.source_change_sompi = u64::MAX;
        assert!(native::funding_prep_body(&v).is_err());
        v = preparation();
        v.outputs[0].xonly_public_key_hex = hex::encode([255; 32]);
        assert!(native::funding_prep_body(&v).is_err());
        v = preparation();
        v.outputs[0].value_sompi = 0;
        assert!(native::funding_prep_body(&v).is_err());
    }
    #[test]
    fn weak_sighash_control_is_cryptographically_signed_as_none() {
        use kaspa_consensus_core::hashing::{
            sighash::calc_schnorr_signature_hash, sighash_type::SigHashType,
        };
        let v = preparation();
        let (tx, entries) = native::funding_prep_body(&v).unwrap();
        let pop = PopulatedTransaction::new(&tx, entries);
        let sig = &tx.inputs[0].signature_script;
        assert_eq!((sig.len(), sig[0], sig[65]), (66, 65, 2));
        let secp = secp256k1::Secp256k1::new();
        let pair = secp256k1::Keypair::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
        );
        let signature = secp256k1::schnorr::Signature::from_slice(&sig[1..65]).unwrap();
        for (kind, expected) in [(2, true), (1, false)] {
            let hash = calc_schnorr_signature_hash(
                &pop,
                0,
                SigHashType::from_u8(kind).unwrap(),
                &SigHashReusedValuesUnsync::new(),
            );
            let message = secp256k1::Message::from_digest_slice(&hash.as_bytes()).unwrap();
            assert_eq!(
                secp.verify_schnorr(&signature, &message, &pair.x_only_public_key().0)
                    .is_ok(),
                expected
            );
        }
    }
}
