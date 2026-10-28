//! The retained SHA-256 compression, expressed through two operation adapters.
//!
//! The Ark adapter records recipes for the actual allocated witness IDs. The
//! scratch adapter is used by private state construction. Neither inspects
//! sample witness values to decide a recipe. Constants below are standard
//! SHA-256 constants; Boolean formulas follow `exact_sha256.rs` and its notices.
use crate::trace::{Error, Lc, Result, TraceBuilder};
use ark_bn254::Fr;
use ark_r1cs_std::{
    GR1CSVar, boolean::Boolean, convert::ToBitsGadget, uint8::UInt8, uint32::UInt32,
};
use ark_relations::gr1cs::{ConstraintSystemRef, LinearCombination, Variable};

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
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

trait Words {
    type Word: Clone;
    type Byte: Clone;
    fn constant_word(&self, value: u32) -> Self::Word;
    fn constant_byte(&self, value: u8) -> Self::Byte;
    fn from_be_bytes(&self, bytes: &[Self::Byte]) -> Result<Self::Word>;
    fn to_be_bytes(&self, word: &Self::Word) -> Result<Vec<Self::Byte>>;
    fn rotate(&self, word: &Self::Word, amount: usize) -> Self::Word;
    fn shift(&self, word: &Self::Word, amount: usize) -> Self::Word;
    fn xor(&mut self, a: &Self::Word, b: &Self::Word) -> Result<Self::Word>;
    fn choice(&mut self, e: &Self::Word, f: &Self::Word, g: &Self::Word) -> Result<Self::Word>;
    fn majority(&mut self, a: &Self::Word, b: &Self::Word, c: &Self::Word) -> Result<Self::Word>;
    fn add(&mut self, words: &[Self::Word]) -> Result<Self::Word>;
}

fn sha256<O: Words>(ops: &mut O, data: &[O::Byte]) -> Result<Vec<O::Byte>> {
    let bits = u64::try_from(data.len())
        .map_err(|_| Error::Shape("sha-message-length"))?
        .checked_mul(8)
        .ok_or(Error::Shape("sha-message-length"))?;
    let mut padded = data.to_vec();
    padded.push(ops.constant_byte(0x80));
    while padded.len() % 64 != 56 {
        padded.push(ops.constant_byte(0));
    }
    for byte in bits.to_be_bytes() {
        padded.push(ops.constant_byte(byte));
    }
    let mut state = H.iter().map(|x| ops.constant_word(*x)).collect::<Vec<_>>();
    for block in padded.chunks_exact(64) {
        let mut w = block
            .chunks_exact(4)
            .map(|chunk| ops.from_be_bytes(chunk))
            .collect::<Result<Vec<_>>>()?;
        for i in 16..64 {
            let a = ops.rotate(&w[i - 15], 7);
            let b = ops.rotate(&w[i - 15], 18);
            let c = ops.shift(&w[i - 15], 3);
            let ab = ops.xor(&a, &b)?;
            let s0 = ops.xor(&ab, &c)?;
            let a = ops.rotate(&w[i - 2], 17);
            let b = ops.rotate(&w[i - 2], 19);
            let c = ops.shift(&w[i - 2], 10);
            let ab = ops.xor(&a, &b)?;
            let s1 = ops.xor(&ab, &c)?;
            w.push(ops.add(&[w[i - 16].clone(), s0, w[i - 7].clone(), s1])?);
        }
        let mut h = state.clone();
        for i in 0..64 {
            let ch = ops.choice(&h[4], &h[5], &h[6])?;
            let ma = ops.majority(&h[0], &h[1], &h[2])?;
            let a = ops.rotate(&h[0], 2);
            let b = ops.rotate(&h[0], 13);
            let c = ops.rotate(&h[0], 22);
            let ab = ops.xor(&a, &b)?;
            let s0 = ops.xor(&ab, &c)?;
            let a = ops.rotate(&h[4], 6);
            let b = ops.rotate(&h[4], 11);
            let c = ops.rotate(&h[4], 25);
            let ab = ops.xor(&a, &b)?;
            let s1 = ops.xor(&ab, &c)?;
            let t0 = ops.add(&[h[7].clone(), s1, ch, ops.constant_word(K[i]), w[i].clone()])?;
            let t1 = ops.add(&[s0, ma])?;
            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = ops.add(&[h[3].clone(), t0.clone()])?;
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = ops.add(&[t0, t1])?;
        }
        for i in 0..8 {
            state[i] = ops.add(&[state[i].clone(), h[i].clone()])?;
        }
    }
    let mut result = Vec::with_capacity(32);
    for word in &state {
        result.extend(ops.to_be_bytes(word)?);
    }
    Ok(result)
}

struct Scratch<'a>(&'a mut TraceBuilder);
impl Words for Scratch<'_> {
    type Word = Vec<Lc>;
    type Byte = Vec<Lc>;
    fn constant_word(&self, v: u32) -> Self::Word {
        (0..32)
            .map(|i| Lc::constant(Fr::from((v >> i) & 1)))
            .collect()
    }
    fn constant_byte(&self, v: u8) -> Self::Byte {
        (0..8)
            .map(|i| Lc::constant(Fr::from((v >> i) & 1)))
            .collect()
    }
    fn from_be_bytes(&self, b: &[Self::Byte]) -> Result<Self::Word> {
        if b.len() != 4 || b.iter().any(|x| x.len() != 8) {
            return Err(Error::Shape("sha-word-width"));
        }
        Ok(b.iter().rev().flatten().cloned().collect())
    }
    fn to_be_bytes(&self, w: &Self::Word) -> Result<Vec<Self::Byte>> {
        if w.len() != 32 {
            return Err(Error::Shape("sha-word-width"));
        }
        Ok(w.chunks_exact(8).rev().map(|x| x.to_vec()).collect())
    }
    fn rotate(&self, w: &Self::Word, n: usize) -> Self::Word {
        (0..32).map(|i| w[(i + n) % 32].clone()).collect()
    }
    fn shift(&self, w: &Self::Word, n: usize) -> Self::Word {
        (0..32)
            .map(|i| w.get(i + n).cloned().unwrap_or_else(Lc::zero))
            .collect()
    }
    fn xor(&mut self, a: &Self::Word, b: &Self::Word) -> Result<Self::Word> {
        a.iter().zip(b).map(|(x, y)| self.0.bit_xor(x, y)).collect()
    }
    fn choice(&mut self, e: &Self::Word, f: &Self::Word, g: &Self::Word) -> Result<Self::Word> {
        e.iter()
            .zip(f)
            .zip(g)
            .map(|((e, f), g)| self.0.select(e, f, g))
            .collect()
    }
    fn majority(&mut self, a: &Self::Word, b: &Self::Word, c: &Self::Word) -> Result<Self::Word> {
        a.iter()
            .zip(b)
            .zip(c)
            .map(|((a, b), c)| {
                if a.as_constant().is_none()
                    && b.as_constant().is_none()
                    && c.as_constant().is_none()
                {
                    let ab = self.0.bit_xor(a, b)?;
                    self.0.select(&ab, c, a)
                } else {
                    let ab = self.0.bit_and(a, b)?;
                    let ac = self.0.bit_and(a, c)?;
                    let abc = self.0.bit_xor(&ab, &ac)?;
                    let bc = self.0.bit_and(b, c)?;
                    self.0.bit_xor(&abc, &bc)
                }
            })
            .collect()
    }
    fn add(&mut self, w: &[Self::Word]) -> Result<Self::Word> {
        let extra = usize::BITS as usize - (w.len() - 1).leading_zeros() as usize;
        let sum = self.0.add_bits(w, 32 + extra)?;
        Ok(sum[..32].to_vec())
    }
}

impl TraceBuilder {
    pub fn sha256_bytes(&mut self, bytes: &[Vec<Lc>]) -> Result<Vec<Vec<Lc>>> {
        if bytes.iter().any(|b| b.len() != 8) {
            return Err(Error::Shape("sha-byte-width"));
        }
        sha256(&mut Scratch(self), bytes)
    }
}

/// Expand symbolic Ark LCs to physical model columns, without reading values.
pub fn ark_lc(cs: &ConstraintSystemRef<Fr>, linear: LinearCombination<Fr>) -> Result<Lc> {
    fn expand(
        cs: &ConstraintSystemRef<Fr>,
        v: Variable,
        c: Fr,
        out: &mut Vec<(Fr, usize)>,
        depth: usize,
    ) -> Result<()> {
        if depth > 256 {
            return Err(Error::Shape("ark-lc-depth"));
        }
        if v.is_zero() {
        } else if v.is_lc() {
            for (coefficient, variable) in cs.get_lc(v).ok_or(Error::Shape("ark-lc-missing"))?.0 {
                expand(cs, variable, c * coefficient, out, depth + 1)?;
            }
        } else {
            out.push((
                c,
                v.get_variable_index(cs.num_instance_variables())
                    .ok_or(Error::Shape("ark-variable-kind"))?,
            ));
        }
        Ok(())
    }
    let mut result = Vec::new();
    for (c, v) in linear.0 {
        expand(cs, v, c, &mut result, 0)?;
    }
    Ok(Lc::canonical(result))
}
pub fn ark_bit(bit: &Boolean<Fr>) -> Result<Lc> {
    match bit {
        Boolean::Constant(v) => Ok(Lc::constant(Fr::from(*v))),
        _ => ark_lc(&bit.cs(), bit.lc()),
    }
}

struct Ark<'a>(&'a mut TraceBuilder);
impl Ark<'_> {
    fn bool_op(&mut self, a: &Boolean<Fr>, b: &Boolean<Fr>, kind: u8) -> Result<Boolean<Fr>> {
        let cs = a.cs().or(b.cs());
        let before = cs.num_witness_variables();
        let result = match kind {
            0 => a & b,
            1 => a ^ b,
            _ => return Err(Error::Shape("ark-boolean-operation")),
        };
        let after = cs.num_witness_variables();
        if after != before {
            if after != before + 1 || result.variable() != Variable::witness(before) {
                return Err(Error::Shape("ark-boolean-allocation-shape"));
            }
            let aa = ark_bit(a)?;
            let bb = ark_bit(b)?;
            let (left, add) = if kind == 0 {
                (aa, Lc::zero())
            } else {
                (aa.scaled(-Fr::from(2u64)), aa.plus(&bb))
            };
            self.0
                .assign_muladd(cs.num_instance_variables() + before, left, bb, add)?;
        }
        Ok(result)
    }
    fn choose(&mut self, c: &Boolean<Fr>, a: &Boolean<Fr>, b: &Boolean<Fr>) -> Result<Boolean<Fr>> {
        let cs = c.cs().or(a.cs()).or(b.cs());
        let before = cs.num_witness_variables();
        let result = c
            .select(a, b)
            .map_err(|_| Error::Shape("ark-sha-selection"))?;
        if cs.num_witness_variables() != before {
            if cs.num_witness_variables() != before + 1
                || result.variable() != Variable::witness(before)
            {
                return Err(Error::Shape("ark-selection-allocation-shape"));
            }
            let aa = ark_bit(a)?;
            let bb = ark_bit(b)?;
            self.0.assign_muladd(
                cs.num_instance_variables() + before,
                ark_bit(c)?,
                aa.minus(&bb),
                bb,
            )?;
        }
        Ok(result)
    }
}
impl Words for Ark<'_> {
    type Word = UInt32<Fr>;
    type Byte = UInt8<Fr>;
    fn constant_word(&self, v: u32) -> Self::Word {
        UInt32::constant(v)
    }
    fn constant_byte(&self, v: u8) -> Self::Byte {
        UInt8::constant(v)
    }
    fn from_be_bytes(&self, b: &[Self::Byte]) -> Result<Self::Word> {
        UInt32::from_bytes_be(b).map_err(|_| Error::Shape("ark-sha-from-bytes"))
    }
    fn to_be_bytes(&self, w: &Self::Word) -> Result<Vec<Self::Byte>> {
        w.to_bytes_be()
            .map_err(|_| Error::Shape("ark-sha-to-bytes"))
    }
    fn rotate(&self, w: &Self::Word, n: usize) -> Self::Word {
        w.rotate_right(n)
    }
    fn shift(&self, w: &Self::Word, n: usize) -> Self::Word {
        w >> (n as u8)
    }
    fn xor(&mut self, a: &Self::Word, b: &Self::Word) -> Result<Self::Word> {
        let aa = a.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let bb = b.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let bits = aa
            .iter()
            .zip(&bb)
            .map(|(a, b)| self.bool_op(a, b, 1))
            .collect::<Result<Vec<_>>>()?;
        Ok(UInt32::from_bits_le(&bits))
    }
    fn choice(&mut self, e: &Self::Word, f: &Self::Word, g: &Self::Word) -> Result<Self::Word> {
        let e = e.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let f = f.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let g = g.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let bits = e
            .iter()
            .zip(&f)
            .zip(&g)
            .map(|((e, f), g)| self.choose(e, f, g))
            .collect::<Result<Vec<_>>>()?;
        Ok(UInt32::from_bits_le(&bits))
    }
    fn majority(&mut self, a: &Self::Word, b: &Self::Word, c: &Self::Word) -> Result<Self::Word> {
        let a = a.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let b = b.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let c = c.to_bits_le().map_err(|_| Error::Shape("ark-sha-bits"))?;
        let bits = a
            .iter()
            .zip(&b)
            .zip(&c)
            .map(|((a, b), c)| {
                if matches!(
                    (a, b, c),
                    (Boolean::Var(_), Boolean::Var(_), Boolean::Var(_))
                ) {
                    let ab = self.bool_op(a, b, 1)?;
                    self.choose(&ab, c, a)
                } else {
                    let ab = self.bool_op(a, b, 0)?;
                    let ac = self.bool_op(a, c, 0)?;
                    let abc = self.bool_op(&ab, &ac, 1)?;
                    let bc = self.bool_op(b, c, 0)?;
                    self.bool_op(&abc, &bc, 1)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(UInt32::from_bits_le(&bits))
    }
    fn add(&mut self, w: &[Self::Word]) -> Result<Self::Word> {
        if w.is_empty() {
            return Err(Error::Shape("ark-sha-add-arity"));
        }
        let cs = w
            .iter()
            .fold(ConstraintSystemRef::None, |cs, w| cs.or(w.cs()));
        let before = cs.num_witness_variables();
        let mut words = w
            .iter()
            .map(|w| {
                w.to_bits_le()
                    .map_err(|_| Error::Shape("ark-sha-bits"))?
                    .iter()
                    .map(ark_bit)
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let result = UInt32::wrapping_add_many(w).map_err(|_| Error::Shape("ark-sha-add"))?;
        let after = cs.num_witness_variables();
        if after != before {
            let extra = usize::BITS as usize - (w.len() - 1).leading_zeros() as usize;
            let width = 32 + extra;
            if after - before != width {
                return Err(Error::Shape("ark-add-allocation-shape"));
            }
            for word in &mut words {
                word.resize(width, Lc::zero());
            }
            let targets = (before..after)
                .map(|i| cs.num_instance_variables() + i)
                .collect::<Vec<_>>();
            self.0.assign_add_bits(&targets, &words)?;
        }
        Ok(result)
    }
}

/// The selected model must be counted/built first. This second synthesis checks
/// actual Ark allocation IDs and refuses changed allocation semantics.
pub fn digest_with_ark_trace(
    bytes: &[UInt8<Fr>],
    trace: &mut TraceBuilder,
) -> Result<Vec<UInt8<Fr>>> {
    sha256(&mut Ark(trace), bytes)
}

/// Ordinary retained gadget for public model/count generation. This is not a
/// private witness input API; its values belong only to its local synthesizer.
pub fn retained_digest_for_model(
    bytes: &[UInt8<Fr>],
) -> std::result::Result<Vec<UInt8<Fr>>, ark_relations::gr1cs::SynthesisError> {
    Ok(crate::exact_sha256::Sha256Gadget::digest(bytes)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{exact_sha256::Sha256Gadget, trace::Bindings};
    use ark_ff::Field;
    use ark_relations::gr1cs::ConstraintSystem;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    fn run(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let original = ConstraintSystem::<Fr>::new_ref();
        let input = UInt8::new_witness_vec(original.clone(), message).unwrap();
        let output = Sha256Gadget::digest(&input).unwrap().0;
        let variables = original.num_variables();
        original.finalize();
        let matrices = original.to_matrices().unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let input = UInt8::new_witness_vec(cs.clone(), message).unwrap();
        let mut trace = TraceBuilder::new(variables, 1).unwrap();
        let mut inputs = BTreeMap::new();
        for byte in &input {
            for bit in byte.to_bits_le().unwrap() {
                let v = bit.variable();
                assert!(v.is_witness());
                let i = v.index().unwrap();
                trace.input(1 + i).unwrap();
                inputs.insert(1 + i, Fr::from(bit.value().unwrap()));
            }
        }
        let output2 = digest_with_ark_trace(&input, &mut trace).unwrap();
        assert_eq!(cs.num_variables(), variables);
        assert_eq!(output.value().unwrap(), output2.value().unwrap());
        cs.finalize();
        assert_eq!(matrices, cs.to_matrices().unwrap());
        assert!(cs.is_satisfied().unwrap());
        trace.require_complete_model().unwrap();
        let actual = trace.evaluate_public_fixture(&inputs).unwrap();
        let values = cs.borrow().unwrap();
        for (i, value) in values.witness_assignment().unwrap().iter().enumerate() {
            assert_eq!(actual[1 + i], *value, "actual-wire={}", 1 + i);
        }
        let mut text = Vec::new();
        trace
            .write_text(
                &mut text,
                &Bindings {
                    source_sha256: "1".repeat(64),
                    model_sha256: "2".repeat(64),
                    layout_sha256: "3".repeat(64),
                },
            )
            .unwrap();
        (output2.value().unwrap(), text)
    }
    #[test]
    fn actual_ark_sha_witness_recipes_preserve_every_row_and_carry() {
        for len in [3, 55, 64, 72] {
            let message = (0..len).map(|i| (i * 73 + 19) as u8).collect::<Vec<_>>();
            let (digest, _) = run(&message);
            assert_eq!(digest, Sha256::digest(&message).to_vec());
        }
    }
    #[test]
    fn trace_structure_is_independent_of_private_sample_values() {
        let (_, a) = run(&[0; 3]);
        let (_, b) = run(&[255; 3]);
        assert_eq!(a, b);
    }
    #[test]
    fn scratch_sha_folds_only_public_constants_and_matches_sha2() {
        let mut trace = TraceBuilder::new(1, 1).unwrap();
        let msg = b"abc";
        let bits = msg
            .iter()
            .map(|x| {
                (0..8)
                    .map(|i| Lc::constant(Fr::from((x >> i) & 1)))
                    .collect()
            })
            .collect::<Vec<_>>();
        let digest = trace.sha256_bytes(&bits).unwrap();
        assert_eq!(trace.variables(), 1);
        let bytes = digest
            .iter()
            .map(|b| {
                b.iter().enumerate().fold(0u8, |v, (i, b)| {
                    v | ((b.as_constant().unwrap() == Fr::ONE) as u8) << i
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(bytes, Sha256::digest(msg).to_vec());
    }
}
