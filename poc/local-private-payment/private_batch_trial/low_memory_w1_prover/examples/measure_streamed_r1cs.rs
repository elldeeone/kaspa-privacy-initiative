//! Public synthetic scaling control for the streamed R1CS witness map.
//! It creates no setup, proving key, proof, private fixture, or network I/O.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use kpb_low_memory_w1_prover::algebraic_controls::{
    ExpectedIdentity, R1csGeometry, stream_r1cs_witness_map,
};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::Path,
    time::Instant,
};

struct HashedWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W: Write> HashedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(bytes)?;
        self.digest.update(bytes);
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("byte count overflow"))?;
        Ok(())
    }
}

fn u32le<W: Write>(writer: &mut HashedWriter<W>, value: usize) -> std::io::Result<()> {
    writer.write(
        &u32::try_from(value)
            .map_err(|_| std::io::Error::other("u32 overflow"))?
            .to_le_bytes(),
    )
}

fn u64le<W: Write>(writer: &mut HashedWriter<W>, value: u64) -> std::io::Result<()> {
    writer.write(&value.to_le_bytes())
}

fn section<W: Write>(writer: &mut HashedWriter<W>, kind: u32, bytes: u64) -> std::io::Result<()> {
    writer.write(&kind.to_le_bytes())?;
    u64le(writer, bytes)
}

fn write_term<W: Write>(
    writer: &mut HashedWriter<W>,
    wire: usize,
    one: &[u8; 32],
) -> std::io::Result<()> {
    u32le(writer, 1)?;
    u32le(writer, wire)?;
    writer.write(one)
}

fn write_new(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn proc_status_kib(label: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with(label))
        .ok_or("missing /proc/self/status field")?;
    let mut fields = line.split_ascii_whitespace();
    if fields.next() != Some(label) {
        return Err("wrong /proc/self/status label".into());
    }
    let value: u64 = fields.next().ok_or("missing status value")?.parse()?;
    if fields.next() != Some("kB") || fields.next().is_some() {
        return Err("wrong /proc/self/status units".into());
    }
    Ok(value)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: measure_streamed_r1cs ROWS FRESH.r1cs FRESH-RECEIPT.json".into());
    }
    let rows: usize = arguments[0].to_str().ok_or("rows UTF-8")?.parse()?;
    if !(1..=2_000_000).contains(&rows) {
        return Err("rows must be in 1..=2000000".into());
    }
    let r1cs_path = Path::new(&arguments[1]);
    let receipt_path = Path::new(&arguments[2]);
    if r1cs_path.exists() || receipt_path.exists() {
        return Err("fresh output paths required".into());
    }

    let started = Instant::now();
    let wires = rows.checked_add(3).ok_or("wire count overflow")?;
    let constraint_bytes = (rows as u64)
        .checked_mul(120)
        .ok_or("constraint byte overflow")?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(r1cs_path)?;
    let mut output = HashedWriter {
        inner: BufWriter::with_capacity(1 << 20, file),
        digest: Sha256::new(),
        bytes: 0,
    };
    let mut one = [0u8; 32];
    one[0] = 1;
    output.write(b"r1cs")?;
    output.write(&1u32.to_le_bytes())?;
    output.write(&3u32.to_le_bytes())?;
    section(&mut output, 1, 64)?;
    u32le(&mut output, 32)?;
    output.write(&Fr::MODULUS.to_bytes_le())?;
    u32le(&mut output, wires)?;
    u32le(&mut output, 0)?;
    u32le(&mut output, 2)?;
    u32le(&mut output, rows)?;
    u64le(&mut output, wires as u64)?;
    u32le(&mut output, rows)?;
    section(&mut output, 2, constraint_bytes)?;
    for row in 0..rows {
        let wire = row + 3;
        write_term(&mut output, wire, &one)?;
        write_term(&mut output, 0, &one)?;
        write_term(&mut output, wire, &one)?;
    }
    section(&mut output, 3, (wires as u64) * 8)?;
    for wire in 0..wires {
        u64le(&mut output, wire as u64)?;
    }
    let HashedWriter {
        mut inner,
        digest,
        bytes: r1cs_bytes,
    } = output;
    inner.flush()?;
    inner.get_ref().sync_all()?;
    drop(inner);
    let r1cs_sha256: [u8; 32] = digest.finalize().into();

    let mut assignment = Vec::with_capacity(wires);
    assignment.extend([Fr::from(1u64), Fr::from(7u64), Fr::from(11u64)]);
    assignment.extend((0..rows).map(|row| Fr::from((row as u64) + 1)));
    let streamed = stream_r1cs_witness_map(
        BufReader::with_capacity(1 << 20, File::open(r1cs_path)?),
        R1csGeometry {
            wires,
            public_outputs: 0,
            public_inputs: 2,
            private_inputs: rows,
            labels: wires as u64,
            constraints: rows,
            constraint_section_bytes: constraint_bytes,
            identity: ExpectedIdentity {
                bytes: r1cs_bytes,
                sha256: r1cs_sha256,
            },
        },
        &assignment,
    )?;
    let mut h_digest = Sha256::new();
    for value in &streamed.h {
        h_digest.update(value.into_bigint().to_bytes_le());
    }
    let peak_rss_kib = proc_status_kib("VmHWM:")?;
    let swap_kib = proc_status_kib("VmSwap:")?;
    let receipt = format!(
        "{{\n  \"schema\": \"kpb-low-memory-r1cs-scaling/v1\",\n  \"classification\": \"PUBLIC_SYNTHETIC_RESOURCE_CONTROL_NO_SETUP_PK_PROOF_OR_PRIVACY_CLAIM\",\n  \"rows\": {rows},\n  \"wires\": {wires},\n  \"domain_size\": {},\n  \"r1cs_bytes\": {r1cs_bytes},\n  \"r1cs_sha256\": \"{}\",\n  \"h_sha256\": \"{}\",\n  \"peak_rss_kib\": {peak_rss_kib},\n  \"swap_kib\": {swap_kib},\n  \"elapsed_seconds\": {},\n  \"setup_or_proof_executed\": false\n}}\n",
        streamed.domain_size,
        hex::encode(r1cs_sha256),
        hex::encode(h_digest.finalize()),
        started.elapsed().as_secs_f64(),
    );
    write_new(receipt_path, receipt.as_bytes())?;
    println!("{receipt}");
    Ok(())
}
