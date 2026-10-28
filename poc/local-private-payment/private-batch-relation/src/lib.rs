//! ADR-0074 new-profile relation. No legacy key, financial acceptance or privacy
//! qualification follows from synthesis or satisfied matrices.
#![forbid(unsafe_code)]

pub mod circuit;
pub mod compose;
pub mod joined_source;
pub mod row_transport;
mod exact_sha256;
mod gadgets;
pub mod wire;
pub mod state_trace;
pub mod joint_trace;
mod joint_ark;
pub mod trace;
pub mod trace_sha256;
pub mod owner_local;

use ark_bn254::Fr;
pub use auth::{CV, H, Note, cv};
pub use wire::{Context, EFFECT_BYTES, Effects, INTENT_BYTES, NullifierWitness, Profile};

pub const OWNERS: usize = 3;
pub const OUTPUTS: usize = 6;
pub const COMPONENT_INSTANCES: usize = 1 + 2 + OWNERS * 66;
pub const NOTE_FLOOR: u64 = auth::NOTE_FLOOR;
pub const MAX: u64 = auth::MAX;

/// Private record: deliberately neither Debug nor Serialize.
#[derive(Clone)]
pub struct OutputWitness {
    pub note: Note,
    pub blinding: H,
    pub tuple: [u8; 520],
}

/// Signing seed, signing scalar and signing nonce are not relation inputs.
#[derive(Clone)]
pub struct OwnerWitness {
    pub input_nf: H,
    pub input_cv: CV,
    pub note: Note,
    pub nullifier_secret: H,
    pub position: u32,
    pub path: [H; 16],
    pub blinding: H,
    /// Canonical owner-local CV blinding difference; never public egress.
    pub private_delta: H,
    pub authorization_key: [u8; 64],
    pub fee_sompi: u64,
    pub intent_nonce: H,
    pub outputs: [OutputWitness; 2],
}

/// Matrices contain field witnesses, so malformed fractional selectors can be
/// tested as actual unsatisfied constraints, rather than parser refusals only.
#[derive(Clone)]
pub struct BatchWitness {
    pub owners: [OwnerWitness; OWNERS],
    pub input_permutation: [[Fr; OWNERS]; OWNERS],
    pub output_permutation: [[Fr; OUTPUTS]; OUTPUTS],
    /// Quotient of the sum of three canonical private deltas by Q, bounded0..2.
    pub delta_quotient: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnRange { pub start: usize, pub end: usize }

/// Exact physical bit-column identities, not values or an owner-to-egress map.
/// Each byte field is flattened as LE bits per byte in canonical wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerColumns {
    pub input_nf_bits: Vec<usize>,
    pub input_cv_bits: Vec<usize>,
    pub output_tuple_bits: [Vec<usize>; 2],
    pub fee_bits: Vec<usize>,
    pub private_delta_bits: Vec<usize>,
    pub input_value_bits: Vec<usize>,
}

/// Public graph metadata only. This assigns no wallet/client to a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchLayout {
    pub effect_bit_columns: Vec<usize>,
    pub initial_joint_columns: ColumnRange,
    pub owner_local_columns: [ColumnRange; OWNERS],
    pub owner_fields: [OwnerColumns; OWNERS],
    pub final_joint_columns: ColumnRange,
}

#[derive(Clone)]
pub struct BatchCircuit {
    pub profile: Profile,
    pub effects: Effects,
    pub witness: BatchWitness,
}
