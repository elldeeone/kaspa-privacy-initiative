//! Owner consent stays fixed; the final transition still binds current effects.
use crate::{EXIT, H, MAX_SOMPI, NativeOutput, Operation, State, domain, ensure, hash};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct WithdrawalIntent {
    pub protocol_domain: H,
    pub pool: H,
    pub verifier: H,
    pub reference_anchor: H,
    pub nonce: H,
    pub refund_key_hash: H,
    pub denomination: u64,
    pub fee_cap: u64,
    pub claims: Vec<H>,
    pub payouts: Vec<Vec<u8>>,
}
impl WithdrawalIntent {
    pub fn commitment(&self) -> H {
        hash(
            &[
                b"KPI-fixed-native-withdrawal-intent-v1\0".as_slice(),
                &bincode::serialize(self).unwrap(),
            ]
            .concat(),
        )
    }
    pub fn validate(&self, state: &State, operations: &[Operation]) -> Result<(), String> {
        ensure(self.protocol_domain == domain(), "intent domain")?;
        ensure(
            self.pool == state.pool && self.pool != [0; 32],
            "intent pool",
        )?;
        ensure(self.verifier == state.ledger.verifier, "intent verifier")?;
        ensure(
            self.refund_key_hash == hash(&state.fee_refund_spk),
            "intent refund policy",
        )?;
        ensure(self.nonce != [0; 32], "intent nonce")?;
        ensure(
            self.fee_cap > 0 && self.fee_cap <= 50_000_000,
            "intent fee bound",
        )?;
        ensure(
            self.denomination > 0 && self.denomination <= MAX_SOMPI,
            "intent denomination",
        )?;
        ensure(
            (2..=7).contains(&self.claims.len()) && self.payouts.len() == self.claims.len(),
            "intent cohort count",
        )?;
        ensure(
            self.denomination
                .checked_mul(self.claims.len() as u64)
                .is_some_and(|v| v <= MAX_SOMPI),
            "intent aggregate range",
        )?;
        ensure(
            self.claims.iter().all(|n| *n != [0; 32])
                && self.claims.windows(2).all(|p| p[0] < p[1]),
            "intent canonical distinct claims",
        )?;
        ensure(
            self.payouts.windows(2).all(|p| p[0] < p[1]),
            "intent canonical distinct payouts",
        )?;
        ensure(
            self.payouts
                .iter()
                .all(|s| s.len() == 36 && s[..3] == [0, 0, 32] && s[35] == 0xac),
            "intent standard payouts",
        )?;
        ensure(
            state.ledger.anchors.contains(&self.reference_anchor),
            "intent accepted reference anchor",
        )?;
        ensure(
            operations.len() == self.claims.len(),
            "intent complete cohort",
        )?;
        let mut actual = vec![];
        for op in operations {
            let s = &op.statement;
            ensure(
                s.kind == EXIT && s.exit_value == self.denomination,
                "intent operation kind/value",
            )?;
            ensure(
                s.anchor == self.reference_anchor,
                "intent reference anchor binding",
            )?;
            actual.push(s.nullifier);
        }
        actual.sort();
        ensure(actual == self.claims, "intent exact claim set")?;
        Ok(())
    }
    pub fn check_actual_payouts(&self, outputs: &[NativeOutput]) -> Result<(), String> {
        ensure(
            outputs.len() == self.payouts.len(),
            "intent exact payout count",
        )?;
        for (actual, approved) in outputs.iter().zip(&self.payouts) {
            ensure(
                actual.value == self.denomination && actual.spk == *approved,
                "intent actual payout set",
            )?;
        }
        Ok(())
    }
}
