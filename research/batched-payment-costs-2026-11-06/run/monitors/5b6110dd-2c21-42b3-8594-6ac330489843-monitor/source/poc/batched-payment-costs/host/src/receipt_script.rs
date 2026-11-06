//! Adapted without arithmetic changes from the existing covenant helper.
//! Source: poc/takeover/vendor/covenant/src/script.rs. See REUSE.json.
use kaspa_txscript::{
    opcodes::codes::*, script_builder::ScriptBuilder, zk_precompiles::tags::ZkTag,
};
pub mod groth16_consts {
    include!(concat!(env!("OUT_DIR"), "/groth16_consts.rs"));
}
pub fn verify_risc0_groth16(b: &mut ScriptBuilder, image_id: &[u8; 32]) {
    use groth16_consts::*;

    // Stack: [..., compressed_proof, journal_hash]
    b.add_data(image_id).unwrap();
    // Stack: [..., compressed_proof, journal_hash, image_id]

    // Move proof to alt stack.
    b.add_op(OpRot).unwrap();
    // Stack: [..., journal_hash, image_id, compressed_proof]
    b.add_op(OpToAltStack).unwrap();
    // Stack: [..., journal_hash, image_id]  alt: [..., compressed_proof]

    // Compute receipt_claim hash from (journal_hash, image_id) on-stack.
    compute_receipt_claim(b);
    // Stack: [..., receipt_claim_hash]  alt: [..., compressed_proof]

    // Public inputs are popped by the precompile as
    // `[a0, a1, claim_right_padded, claim_left_padded, id_bn254_fr]`; push in reverse so the
    // ordering is correct top→bottom.
    b.add_op(OpToAltStack).unwrap();
    // Stack: [...]  alt: [..., compressed_proof, receipt_claim_hash]

    b.add_data(&GROTH16_BN254_CONTROL_ID).unwrap();
    // Stack: [..., id]

    b.add_op(OpFromAltStack).unwrap();
    // Stack: [..., id, receipt_claim_hash]  alt: [..., compressed_proof]

    split_at_mid(b);
    // Stack: [..., id, claim_left, claim_right]

    // Right-pad claim_right (top) to 32 bytes.
    b.add_data(&[0u8; 16]).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., id, claim_left, claim_right_padded]

    // Pad claim_left in the same way.
    b.add_op(OpSwap).unwrap();
    b.add_data(&[0u8; 16]).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., id, claim_right_padded, claim_left_padded]

    // Control-root halves.
    b.add_data(&GROTH16_CONTROL_ROOT_A1).unwrap();
    b.add_data(&GROTH16_CONTROL_ROOT_A0).unwrap();
    // Stack: [..., id, c1, c0, a1, a0]

    // Public-input count.
    b.add_i64(GROTH16_PUBLIC_INPUT_COUNT as i64).unwrap();
    // Stack: [..., id, c1, c0, a1, a0, 5]

    // Recover proof from alt stack.
    b.add_op(OpFromAltStack).unwrap();
    // Stack: [..., id, c1, c0, a1, a0, 5, compressed_proof]

    // Verifying key.
    b.add_data(GROTH16_VK_COMPRESSED).unwrap();
    // Stack: [..., 5, compressed_proof, vk]

    // ZkTag byte + precompile + verify.
    b.add_data(&[ZkTag::Groth16 as u8]).unwrap();
    b.add_op(OpZkPrecompile).unwrap();
    b.add_op(OpVerify).unwrap();
}

/// Number of public inputs the risc0 Groth16 verifier consumes (id_bn254_fr,
/// claim_left_padded, claim_right_padded, control_root_a1, control_root_a0). See
/// `risc0-groth16` reference impl.
const GROTH16_PUBLIC_INPUT_COUNT: usize = 5;

/// Inlines the risc0 receipt-claim hash computation. Mirrors
/// `examples/zk-covenant-common/src/groth16.rs::compute_receipt_claim` field-for-field; the
/// preimage layout is risc0's canonical `ReceiptClaim` encoding.
///
/// Stack precondition: `[..., journal_hash, image_id]`
/// Stack postcondition: `[..., receipt_claim_hash]`
fn compute_receipt_claim(b: &mut ScriptBuilder) {
    use groth16_consts::*;

    // --- output_digest = SHA256(OUTPUT_TAG || journal_hash || zeros32 || 2u16_le) ---
    b.add_op(OpToAltStack).unwrap();
    // Stack: [..., journal_hash]  alt: [..., image_id]
    b.add_data(&OUTPUT_TAG_DIGEST).unwrap();
    b.add_op(OpSwap).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., OUTPUT_TAG || journal_hash]  (64B)
    b.add_data(&[0u8; 32]).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., OUTPUT_TAG || journal_hash || zeros32]  (96B)
    b.add_data(&2u16.to_le_bytes()).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., 98B-preimage]
    b.add_op(OpSHA256).unwrap();
    // Stack: [..., output_digest]  alt: [..., image_id]

    // --- receipt_claim = SHA256(RC_TAG || zeros32 || image_id || POST || output_digest ||
    // trailer10) ---
    b.add_data(&RECEIPT_CLAIM_TAG_DIGEST).unwrap();
    b.add_data(&[0u8; 32]).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., output_digest, RC_TAG || zeros32]  (64B partial)
    b.add_op(OpFromAltStack).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., output_digest, RC_TAG || zeros32 || image_id]  (96B)
    b.add_data(&POST_DIGEST).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., output_digest, RC_TAG || zeros32 || image_id || POST]  (128B)
    b.add_op(OpSwap).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., RC_TAG || ... || POST || output_digest]  (160B)
    b.add_data(&[0u8, 0, 0, 0, 0, 0, 0, 0, 4, 0]).unwrap();
    b.add_op(OpCat).unwrap();
    // Stack: [..., 170B receipt_claim preimage]
    b.add_op(OpSHA256).unwrap();
    // Stack: [..., receipt_claim_hash]
}

/// Splits the top-of-stack byte array at its midpoint. Mirrors
/// `examples/zk-covenant-common/src/script_ext.rs::split_at_mid`.
///
/// Stack precondition: `[..., byte_array]`
/// Stack postcondition: `[..., first_half, second_half]`
fn split_at_mid(b: &mut ScriptBuilder) {
    b.add_op(OpSize).unwrap();
    b.add_i64(2).unwrap();
    b.add_op(OpDiv).unwrap();
    b.add_op(Op2Dup).unwrap();
    b.add_i64(0).unwrap();
    b.add_op(OpSwap).unwrap();
    b.add_op(OpSubstr).unwrap();
    b.add_op(OpRot).unwrap();
    b.add_op(OpRot).unwrap();
    b.add_op(OpDup).unwrap();
    b.add_i64(2).unwrap();
    b.add_op(OpMul).unwrap();
    b.add_op(OpSubstr).unwrap();
}
