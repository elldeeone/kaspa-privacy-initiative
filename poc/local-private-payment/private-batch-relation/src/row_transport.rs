//! Lossless PUBLIC finalized R1CS transport. No witness/PK/proof is accepted.
//! Exact16 magic, axisu64LE, canonicalFrmodulus32LE, instances/witnesses/rows
//! u64LE, then each row's termcountu64LE and (coefficient32LE,columnu64LE).
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use auth::join::R1cs;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
};
pub const MAGIC: &[u8; 16] = b"KPI_R1CS_AXIS_V1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AxisReceipt {
    pub axis: usize,
    pub raw_bytes: u64,
    pub raw_sha256: String,
    pub compressed_bytes: u64,
    pub compressed_sha256: String,
}
struct Hashed<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}
impl<W: Write> Write for Hashed<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.hash.update(&b[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("public byte count overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn u64le(n: usize) -> io::Result<[u8; 8]> {
    Ok(u64::try_from(n)
        .map_err(|_| io::Error::other("public usize overflow"))?
        .to_le_bytes())
}
fn payload(
    cs: &R1cs,
    axis: usize,
    out: &mut impl Write,
    mut fingerprint: Option<&mut Sha256>,
) -> io::Result<()> {
    cs.validate()
        .map_err(|_| io::Error::other("public matrix shape"))?;
    let matrix = cs
        .matrices
        .get(axis)
        .ok_or_else(|| io::Error::other("public axis"))?;
    out.write_all(MAGIC)?;
    out.write_all(&u64le(axis)?)?;
    out.write_all(&Fr::MODULUS.to_bytes_le())?;
    for n in [cs.instances, cs.witnesses, cs.constraints()] {
        out.write_all(&u64le(n)?)?;
    }
    for row in matrix {
        let length = u64le(row.len())?;
        out.write_all(&length)?;
        if let Some(h) = fingerprint.as_deref_mut() {
            h.update(length);
        }
        for (coefficient, column) in row {
            let field = coefficient.into_bigint().to_bytes_le();
            let index = u64le(*column)?;
            out.write_all(&field)?;
            out.write_all(&index)?;
            if let Some(h) = fingerprint.as_deref_mut() {
                h.update(&field);
                h.update(index);
            }
        }
    }
    Ok(())
}
/// Begin the retained KPINAS/R1CS/v1 identity. Stream axes0,1,2 exactly once
/// using `gzip_axis(...,Some(&mut hash))`; the axis container header is excluded.
pub fn fingerprint_start(cs: &R1cs) -> io::Result<Sha256> {
    let mut h = Sha256::new();
    h.update(b"KPINAS/R1CS/v1\0");
    for n in [cs.instances, cs.witnesses, cs.constraints()] {
        h.update(u64le(n)?);
    }
    Ok(h)
}
/// Standard one-member deterministic gzip. None counts/hashes output into a
/// sink before any artifact is written. Some creates a new public file. Input
/// rows are never normalized, truncated, combined, skipped or sampled here.
pub fn gzip_axis(
    cs: &R1cs,
    axis: usize,
    path: Option<&Path>,
    fingerprint: Option<&mut Sha256>,
) -> io::Result<AxisReceipt> {
    let output: Box<dyn Write + Send> = match path {
        Some(p) => Box::new(BufWriter::new(
            OpenOptions::new().write(true).create_new(true).open(p)?,
        )),
        None => Box::new(io::sink()),
    };
    let mut child = Command::new("/usr/bin/gzip")
        .args(["-1", "-n", "-c"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("gzip stdout"))?;
    let reader = thread::spawn(move || -> io::Result<(u64, String)> {
        let mut compressed = Hashed {
            inner: output,
            hash: Sha256::new(),
            bytes: 0,
        };
        let mut buffer = [0; 65536];
        loop {
            let n = stdout.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            compressed.write_all(&buffer[..n])?;
        }
        compressed.flush()?;
        Ok((compressed.bytes, hex::encode(compressed.hash.finalize())))
    });
    let raw_result = (|| -> io::Result<(u64, String)> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("gzip stdin"))?;
        let mut raw = Hashed {
            inner: BufWriter::new(stdin),
            hash: Sha256::new(),
            bytes: 0,
        };
        payload(cs, axis, &mut raw, fingerprint)?;
        raw.flush()?;
        Ok((raw.bytes, hex::encode(raw.hash.finalize())))
    })();
    let status = child.wait()?;
    let compressed = reader
        .join()
        .map_err(|_| io::Error::other("gzip reader panic"))??;
    let raw = raw_result?;
    if !status.success() {
        return Err(io::Error::other("gzip process failed"));
    }
    Ok(AxisReceipt {
        axis,
        raw_bytes: raw.0,
        raw_sha256: raw.1,
        compressed_bytes: compressed.0,
        compressed_sha256: compressed.1,
    })
}
pub fn gzip_binary_sha256() -> io::Result<String> {
    let mut file = File::open("/usr/bin/gzip")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, Field};
    #[test]
    fn exact_binary_axes_and_gzip_preserve_every_term() {
        let cs = R1cs {
            instances: 3,
            witnesses: 2,
            matrices: [
                vec![vec![(Fr::ONE, 4), (Fr::ZERO, 0), (-Fr::ONE, 4)]],
                vec![vec![]],
                vec![vec![(Fr::from(9u64), 2)]],
            ],
        };
        let mut hash = fingerprint_start(&cs).unwrap();
        for axis in 0..3 {
            let receipt = gzip_axis(&cs, axis, None, Some(&mut hash)).unwrap();
            let mut bytes = Vec::new();
            payload(&cs, axis, &mut bytes, None).unwrap();
            assert_eq!(receipt.raw_bytes, bytes.len() as u64);
            assert_eq!(receipt.raw_sha256, hex::encode(Sha256::digest(&bytes)));
            assert!(receipt.compressed_bytes > 0);
            assert_eq!(&bytes[..16], MAGIC);
            assert_eq!(
                u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                axis as u64
            );
        }
        assert_eq!(
            hex::encode(hash.finalize()),
            auth::join::fingerprint(&cs).unwrap()
        );
    }
}
