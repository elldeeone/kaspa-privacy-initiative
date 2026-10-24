//! Isolated exact-SHA256 cost probe. Adapted from ark-crypto-primitives0.6.0
//! commit ba00127bf673d93d73a3e8bf969cb9eeced20d12.
//! Original file attributes adaptation to nanpuyue/sha256 commit
//! bf6656b7dc72e76bb617445a8865f906670e585b. See LICENSE-MIT.
//! Only Ch/Maj Boolean formulas differ from the pinned compression body.
use ark_ff::PrimeField;
use ark_r1cs_std::{
    boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget},
    uint8::UInt8,
    uint32::UInt32,
};
use ark_relations::gr1cs::SynthesisError;
use std::iter;

fn ch<F: PrimeField>(
    e: &Boolean<F>,
    f: &Boolean<F>,
    g: &Boolean<F>,
) -> Result<Boolean<F>, SynthesisError> {
    e.select(f, g)
}
fn maj<F: PrimeField>(
    a: &Boolean<F>,
    b: &Boolean<F>,
    c: &Boolean<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // Preserve the upstream formula on constant operands: the two-gate identity
    // can cost more than upstream when a branch constant folds. Never regress.
    match (a, b, c) {
        (Boolean::Var(_), Boolean::Var(_), Boolean::Var(_)) => (a ^ b).select(c, a),
        _ => Ok((a & b) ^ (a & c) ^ (b & c)),
    }
}
fn ch_word<F: PrimeField>(
    e: &UInt32<F>,
    f: &UInt32<F>,
    g: &UInt32<F>,
) -> Result<UInt32<F>, SynthesisError> {
    let (e, f, g) = (e.to_bits_le()?, f.to_bits_le()?, g.to_bits_le()?);
    let bits = e
        .iter()
        .zip(&f)
        .zip(&g)
        .map(|((e, f), g)| ch(e, f, g))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UInt32::from_bits_le(&bits))
}
fn maj_word<F: PrimeField>(
    a: &UInt32<F>,
    b: &UInt32<F>,
    c: &UInt32<F>,
) -> Result<UInt32<F>, SynthesisError> {
    let (a, b, c) = (a.to_bits_le()?, b.to_bits_le()?, c.to_bits_le()?);
    let bits = a
        .iter()
        .zip(&b)
        .zip(&c)
        .map(|((a, b), c)| maj(a, b, c))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UInt32::from_bits_le(&bits))
}

const STATE_LEN: usize = 8;

type State = [u32; STATE_LEN];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H: State = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
pub struct Sha256Gadget<ConstraintF: PrimeField> {
    state: Vec<UInt32<ConstraintF>>,
    completed_data_blocks: u64,
    pending: Vec<UInt8<ConstraintF>>,
    num_pending: usize,
}

impl<ConstraintF: PrimeField> Default for Sha256Gadget<ConstraintF> {
    fn default() -> Self {
        Self {
            state: H.iter().cloned().map(UInt32::constant).collect(),
            completed_data_blocks: 0,
            pending: iter::repeat(0u8).take(64).map(UInt8::constant).collect(),
            num_pending: 0,
        }
    }
}

// Wikipedia's pseudocode is a good companion for understanding the below
// https://en.wikipedia.org/wiki/SHA-2#Pseudocode
impl<ConstraintF: PrimeField> Sha256Gadget<ConstraintF> {
    fn update_state(
        state: &mut [UInt32<ConstraintF>],
        data: &[UInt8<ConstraintF>],
    ) -> Result<(), SynthesisError> {
        assert_eq!(data.len(), 64);

        let mut w = vec![UInt32::constant(0); 64];
        for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
            *word = UInt32::from_bytes_be(chunk)?;
        }

        for i in 16..64 {
            let s0 = {
                let x1 = w[i - 15].rotate_right(7);
                let x2 = w[i - 15].rotate_right(18);
                let x3 = &w[i - 15] >> 3u8;
                x1 ^ &x2 ^ &x3
            };
            let s1 = {
                let x1 = w[i - 2].rotate_right(17);
                let x2 = w[i - 2].rotate_right(19);
                let x3 = &w[i - 2] >> 10u8;
                x1 ^ &x2 ^ &x3
            };
            w[i] = UInt32::wrapping_add_many(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?;
        }

        let mut h = state.to_vec();
        for i in 0..64 {
            let ch = ch_word(&h[4], &h[5], &h[6])?;
            let ma = maj_word(&h[0], &h[1], &h[2])?;
            let s0 = {
                let x1 = h[0].rotate_right(2);
                let x2 = h[0].rotate_right(13);
                let x3 = h[0].rotate_right(22);
                x1 ^ &x2 ^ &x3
            };
            let s1 = {
                let x1 = h[4].rotate_right(6);
                let x2 = h[4].rotate_right(11);
                let x3 = h[4].rotate_right(25);
                x1 ^ &x2 ^ &x3
            };
            let t0 = UInt32::wrapping_add_many(&[
                h[7].clone(),
                s1,
                ch,
                UInt32::constant(K[i]),
                w[i].clone(),
            ])?;
            let t1 = s0.wrapping_add(&ma);

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = h[3].wrapping_add(&t0);
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = t0.wrapping_add(&t1);
        }

        for (s, hi) in state.iter_mut().zip(h.iter()) {
            *s = s.wrapping_add(hi);
        }

        Ok(())
    }

    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<ConstraintF>]) -> Result<(), SynthesisError> {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 64 {
            offset = 64 - self.num_pending;
            // If the inputted data pushes the pending buffer over the chunk size, process it all
            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            Self::update_state(&mut self.state, &self.pending)?;

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(64) {
            let chunk_size = chunk.len();

            if chunk_size == 64 {
                // If it's a full chunk, process it
                Self::update_state(&mut self.state, chunk)?;
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }

        Ok(())
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        // Encode the number of processed bits as a u64, then serialize it to 8 big-endian bytes
        let data_bitlen = self.completed_data_blocks * 512 + self.num_pending as u64 * 8;
        let encoded_bitlen: Vec<UInt8<ConstraintF>> = {
            let bytes = data_bitlen.to_be_bytes();
            bytes.iter().map(|&b| UInt8::constant(b)).collect()
        };

        // Padding starts with a 1 followed by some number of zeros (0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 72];
        pending[0] = UInt8::constant(0x80);

        // We'll either append to the 56+8 = 64 byte boundary or the 120+8 = 128 byte boundary,
        // depending on whether we have at least 56 unprocessed bytes
        let offset = if self.num_pending < 56 {
            56 - self.num_pending
        } else {
            120 - self.num_pending
        };

        // Write the bitlen to the end of the padding. Then process all the padding
        pending[offset..offset + 8].clone_from_slice(&encoded_bitlen);
        self.update(&pending[..offset + 8])?;

        // Collect the state into big-endian bytes
        let bytes = Vec::from_iter(
            self.state
                .iter()
                .flat_map(|i| UInt32::to_bytes_be(i).unwrap()),
        );
        Ok(DigestVar(bytes))
    }

    /// Internal fixed-size HMAC inner compression. The caller constructs all
    /// SHA padding and length bytes from constants or the constrained selector.
    /// This initializes the standard IV and compresses exactly three full blocks;
    /// finalizing again would hash a different message and is intentionally absent.
    pub(crate) fn digest_padded_hmac_inner(
        data: &[UInt8<ConstraintF>],
    ) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        if data.len() != 3 * 64 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mut inner = Self::default();
        inner.update(data)?;
        let bytes = Vec::from_iter(
            inner
                .state
                .iter()
                .flat_map(|word| UInt32::to_bytes_be(word).unwrap()),
        );
        Ok(DigestVar(bytes))
    }

    /// Computes the digest of the given data. This is a shortcut for `default()` followed by
    /// `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<ConstraintF>]) -> Result<DigestVar<ConstraintF>, SynthesisError> {
        let mut sha256_var = Self::default();
        sha256_var.update(data)?;
        sha256_var.finalize()
    }
}

#[derive(Clone, Debug)]
pub struct DigestVar<F: PrimeField>(pub Vec<UInt8<F>>);

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::{GR1CSVar, alloc::AllocVar, eq::EqGadget};
    use ark_relations::gr1cs::ConstraintSystem;
    use sha2::{Digest, Sha256};

    #[test]
    fn boolean_truth_tables_and_no_constant_regression() {
        for mode in 0u8..8 {
            for value in 0u8..8 {
                let cs = ConstraintSystem::<Fr>::new_ref();
                let mut v = Vec::new();
                for i in 0..3 {
                    let bit = value & (1 << i) != 0;
                    v.push(if mode & (1 << i) == 0 {
                        Boolean::constant(bit)
                    } else {
                        Boolean::new_witness(cs.clone(), || Ok(bit)).unwrap()
                    });
                }
                let (a, b, c) = (&v[0], &v[1], &v[2]);
                let start = cs.num_constraints();
                let old_ch = (a & b) ^ ((!a) & c);
                let old_maj = (a & b) ^ (a & c) ^ (b & c);
                let old_cost = cs.num_constraints() - start;
                let start = cs.num_constraints();
                let new_ch = ch(a, b, c).unwrap();
                let new_maj = maj(a, b, c).unwrap();
                let new_cost = cs.num_constraints() - start;
                assert_eq!(old_ch.value().unwrap(), new_ch.value().unwrap());
                assert_eq!(old_maj.value().unwrap(), new_maj.value().unwrap());
                old_ch.enforce_equal(&new_ch).unwrap();
                old_maj.enforce_equal(&new_maj).unwrap();
                assert!(
                    new_cost <= old_cost,
                    "mode={mode} old={old_cost} new={new_cost}"
                );
                if mode == 7 {
                    assert_eq!((old_cost, new_cost), (8, 3));
                }
                assert!(cs.is_satisfied().unwrap());
            }
        }
    }

    #[test]
    fn exact_sha_boundary_and_contract_lengths() {
        for len in [
            0usize, 3, 55, 56, 63, 64, 72, 73, 76, 96, 104, 137, 140, 208, 484,
        ] {
            let message = (0..len)
                .map(|i| (i as u8).wrapping_mul(73).wrapping_add(19))
                .collect::<Vec<_>>();
            let expected = Sha256::digest(&message);
            let cs = ConstraintSystem::<Fr>::new_ref();
            let vars = UInt8::new_witness_vec(cs.clone(), &message).unwrap();
            let actual = Sha256Gadget::digest(&vars).unwrap().0;
            actual
                .enforce_equal(&UInt8::constant_vec(&expected))
                .unwrap();
            assert!(cs.is_satisfied().unwrap(), "message_len={len}");
            assert_eq!(actual.value().unwrap(), expected.to_vec());
        }
    }
}
