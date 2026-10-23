//! Offline new-format experiment only. Genuine native private/reveal union;
//! no old wallet, proof parameter, replay or owner workflow imports.
pub mod native;
pub mod policy;

#[cfg(test)]
mod tests {
    use super::policy;
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
                        depth, 1,
                        "Schnorr must execute in only the reveal outer branch"
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
}
