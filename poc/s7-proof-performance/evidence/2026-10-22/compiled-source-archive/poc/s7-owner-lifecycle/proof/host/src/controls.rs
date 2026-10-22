use crate::h::{Context, Result};
use kpi_two_v6_state as state;

#[derive(Debug)]
pub enum Expected {
    Journal(Vec<u8>),
    Reject(String),
}

pub const REJECTIONS: &[&str] = &[
    "trailing",
    "truncated",
    "wrong-domain",
    "changed-count-both",
    "state-version",
    "even-cm-count",
    "uninitialized",
    "reserve-zero",
    "reserve-equals-fee",
    "historical-path",
    "nf-index",
    "nf-predecessor-path",
    "nf-empty-path",
    "cm-empty-path",
    "history-empty-path",
];

pub fn mutate(input: &mut Vec<u8>, pin: &Context, case: &str) -> Result<Expected> {
    let rejection = match case {
        "valid" => return Ok(Expected::Journal(pin.journal.to_vec())),
        "outpoint-order" => {
            // Nonuniform bytes catch accidental reversal hidden by 33/55 txids.
            let mut point = [0; 36];
            for (i, byte) in point[..32].iter_mut().enumerate() {
                *byte = i as u8;
            }
            point[32..].copy_from_slice(&0x0102_0304u32.to_le_bytes());
            input[state::OUTPOINT_OFFSET..state::STATE_OFFSET].copy_from_slice(&point);
            let mut journal = pin.journal.to_vec();
            journal[74..110].copy_from_slice(&point);
            return Ok(Expected::Journal(journal));
        }
        "reserve-plus-one" => {
            let before = u64::from_le_bytes(pin.journal[320..328].try_into()?);
            let after = u64::from_le_bytes(pin.journal[328..336].try_into()?);
            input[state::RESERVE_OFFSET..state::ANCHOR_PATH_OFFSET].copy_from_slice(
                &before
                    .checked_add(1)
                    .ok_or("reserve overflow")?
                    .to_le_bytes(),
            );
            let mut journal = pin.journal.to_vec();
            journal[320..328].copy_from_slice(&(before + 1).to_le_bytes());
            journal[328..336].copy_from_slice(
                &after
                    .checked_add(1)
                    .ok_or("reserve overflow")?
                    .to_le_bytes(),
            );
            return Ok(Expected::Journal(journal));
        }
        "trailing" => {
            input.push(0);
            format!(
                "Length {{ expected: {}, actual: {} }}",
                state::INPUT_LEN,
                state::INPUT_LEN + 1
            )
        }
        "truncated" => {
            input.pop();
            format!(
                "Length {{ expected: {}, actual: {} }}",
                state::INPUT_LEN,
                state::INPUT_LEN - 1
            )
        }
        "wrong-domain" => {
            input[12] ^= 1;
            "Binding(Profile(\"public projection\"))".into()
        }
        "changed-count-both" => {
            input[kpi_two_v6_binding::PROJECTION_LEN + 40] ^= 1;
            input[kpi_two_v6_binding::PROJECTION_LEN + kpi_two_v6_binding::BUNDLE_LEN + 40] ^= 1;
            "Binding(InnerProof(\"invalid proof\"))".into()
        }
        "state-version" => {
            input[state::STATE_OFFSET] = 6;
            "StateVersion".into()
        }
        "even-cm-count" => {
            input[state::STATE_OFFSET + 1] ^= 1;
            "StateCounts".into()
        }
        "uninitialized" => {
            input[state::STATE_OFFSET + 5..state::STATE_OFFSET + 9].fill(0);
            "Uninitialized".into()
        }
        "reserve-zero" => {
            input[state::RESERVE_OFFSET..state::ANCHOR_PATH_OFFSET].fill(0);
            "Reserve".into()
        }
        "reserve-equals-fee" => {
            input[state::RESERVE_OFFSET..state::ANCHOR_PATH_OFFSET]
                .copy_from_slice(&80_000_000u64.to_le_bytes());
            "Reserve".into()
        }
        "historical-path" => {
            input[state::ANCHOR_PATH_OFFSET] ^= 1;
            "HistoricalRoot".into()
        }
        "nf-index" => {
            input[state::NF_OFFSET..state::NF_OFFSET + 4].fill(255);
            "NullifierIndex(0)".into()
        }
        "nf-predecessor-path" => {
            input[state::NF_OFFSET + 72] ^= 1;
            "NullifierRoot(0)".into()
        }
        "nf-empty-path" => {
            input[state::NF_OFFSET + 72 + 544] ^= 1;
            "NullifierOccupied(0)".into()
        }
        "cm-empty-path" => {
            input[state::CM_PATH_OFFSET] ^= 1;
            "CommitmentOccupied(0)".into()
        }
        "history-empty-path" => {
            input[state::HISTORY_PATH_OFFSET] ^= 1;
            "HistoryOccupied(0)".into()
        }
        _ => return Err("unknown state control".into()),
    };
    Ok(Expected::Reject(rejection))
}
