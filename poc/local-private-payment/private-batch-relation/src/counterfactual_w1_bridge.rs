//! Pinned typed bridge for the complete counterfactual-W1 verifier.
//!
//! The bridge has exactly one input: the opaque, source-owned authority minted
//! by the future atomic W0/C1/accepted-lineage owner.  It has exactly one
//! successful output: the opaque one-use closure returned after the complete
//! verifier succeeds.  There is no byte, path, manifest, digest, enum, Boolean,
//! FFI handle or arithmetic-only overload.
//!
//! This module deliberately does not provide the missing live source minter or
//! a C++ consumer.  Those remain separate fail-closed callsites; a fixture file
//! or successful subprocess exit cannot construct either authority.
//!
//! Raw bytes are not a source authority:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1_bridge::PinnedFullW1VerifierBridge;
//! let raw = vec![0u8; 32];
//! let _ = PinnedFullW1VerifierBridge::construct_and_verify(raw);
//! ```
//!
//! A caller Boolean is not a source authority:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1_bridge::PinnedFullW1VerifierBridge;
//! let _ = PinnedFullW1VerifierBridge::construct_and_verify(true);
//! ```
//!
//! A path or manifest location is not a source authority:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1_bridge::PinnedFullW1VerifierBridge;
//! let _ = PinnedFullW1VerifierBridge::construct_and_verify("HANDOFF.json");
//! ```
//!
//! External code cannot directly construct either typed endpoint:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1::FullW1SourceInstanceAuthority;
//! let _ = FullW1SourceInstanceAuthority {};
//! ```
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1::FullW1WitnessClosure;
//! let _ = FullW1WitnessClosure {};
//! ```
//!
//! The relation module does not expose a second verifier bridge:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1::FullW1WitnessBridge;
//! let _ = FullW1WitnessBridge;
//! ```
//!
//! The source is consumed, so replay does not type-check:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1::FullW1SourceInstanceAuthority;
//! use kpi_private_batch_relation::counterfactual_w1_bridge::PinnedFullW1VerifierBridge;
//! fn opaque_source() -> FullW1SourceInstanceAuthority { panic!() }
//! let source = opaque_source();
//! let _first = PinnedFullW1VerifierBridge::construct_and_verify(source);
//! let _replay = PinnedFullW1VerifierBridge::construct_and_verify(source);
//! ```
//!
//! The successful closure is also non-cloneable:
//!
//! ```compile_fail
//! use kpi_private_batch_relation::counterfactual_w1::FullW1WitnessClosure;
//! fn opaque_closure() -> FullW1WitnessClosure { panic!() }
//! let closure = opaque_closure();
//! let _copy = closure.clone();
//! ```

use crate::counterfactual_w1::{
    FullW1Refused, FullW1SourceInstanceAuthority, FullW1WitnessClosure, verify_pinned_source,
};

/// Sole public minting bridge for a verified FullW1 closure.
///
/// This zero-sized selector carries no configurable verifier, callback or
/// caller-supplied identity.  The selected source/build closure pins the code;
/// the verifier itself pins the exact matrices, verification keys and workload.
pub struct PinnedFullW1VerifierBridge {
    _private: (),
}

impl PinnedFullW1VerifierBridge {
    pub fn construct_and_verify(
        source: FullW1SourceInstanceAuthority,
    ) -> core::result::Result<FullW1WitnessClosure, FullW1Refused> {
        verify_pinned_source(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ExactVerifier = fn(
        FullW1SourceInstanceAuthority,
    ) -> core::result::Result<FullW1WitnessClosure, FullW1Refused>;

    #[test]
    fn public_bridge_has_only_the_owned_typed_signature() {
        let selected: ExactVerifier = PinnedFullW1VerifierBridge::construct_and_verify;
        let _ = selected;
    }
}
