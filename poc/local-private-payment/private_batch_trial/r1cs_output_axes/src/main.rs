//! Exact current Output circuit -> immutable public A/B/C gzip axes.
//! No witness assignment, proving parameter, proof, setup, zkey or ceremony.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, R1CS_PREDICATE_LABEL, SynthesisMode,
};
use authority::join::R1cs;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Instant,
};

const MAGIC: &[u8; 16] = b"KPI_R1CS_AXIS_V1";
const FINGERPRINT_DOMAIN: &[u8] = b"KPINAS/R1CS/v1\0";
const OUTPUT_SOURCE: &str = "ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e";
const OUTPUT_MATRIX: &str = "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31";
const GZIP_BINARY: &str = "2ba6fd35db5f0b5561e56b97124a08b067464b795e8e08278367f23dc539d549";
const INSTANCES: usize = 3;
const WITNESSES: usize = 214_998;
const VARIABLES: usize = 215_001;
const CONSTRAINTS: usize = 217_807;
const NAMES: [&str; 3] = ["A.r1cs.bin.gz", "B.r1cs.bin.gz", "C.r1cs.bin.gz"];

const SELF_SOURCE: &[u8] = include_bytes!("main.rs");
const CARGO_TOML: &[u8] = include_bytes!("../Cargo.toml");
const CARGO_LOCK: &[u8] = include_bytes!("../Cargo.lock");
const RUST_TOOLCHAIN: &[u8] = include_bytes!("../rust-toolchain.toml");
const SOURCE_CLOSURE: &[u8] = include_bytes!("../source_closure.json");

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_reader(reader: &mut impl Read) -> io::Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("byte count overflow"))?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hex::encode(hash.finalize())))
}

fn file_hash(path: &Path) -> io::Result<(u64, String)> {
    hash_reader(&mut File::open(path)?)
}

fn binary_identity() -> io::Result<Value> {
    let mut file = File::open("/proc/self/exe")?;
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(io::Error::other("binary not regular"));
    }
    let (bytes, digest) = hash_reader(&mut file)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(io::Error::other("binary changed while hashing"));
    }
    Ok(json!({
        "bytes": bytes,
        "sha256": digest,
        "device": before.dev(),
        "inode": before.ino(),
        "mode": format!("{:04o}", before.mode() & 0o7777),
        "owner_uid": before.uid(),
        "mtime_seconds": before.mtime(),
        "mtime_nanoseconds": before.mtime_nsec(),
        "ctime_seconds": before.ctime(),
        "ctime_nanoseconds": before.ctime_nsec(),
    }))
}

fn dep_info_identity() -> AnyResult<Value> {
    let executable = fs::read_link("/proc/self/exe")?;
    let dep_info = executable.with_extension("d");
    let body = fs::read(&dep_info)?;
    let text = std::str::from_utf8(&body)?;
    let (_, dependencies) = text.split_once(": ").ok_or("build dep-info format")?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .ok_or("repository root")?;
    let mut local_sources = dependencies
        .split_whitespace()
        .filter_map(|value| {
            fs::canonicalize(value)
                .ok()?
                .strip_prefix(repository)
                .ok()
                .map(|relative| relative.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    local_sources.sort();
    local_sources.dedup();
    let local_identity = sha256(&serde_json::to_vec(&local_sources)?);
    let file = dep_info
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("dep-info name is not UTF-8")?;
    Ok(json!({
        "file": file,
        "bytes": body.len(),
        "sha256": sha256(&body),
        "local_source_count": local_sources.len(),
        "local_source_identity": local_identity,
        "local_sources": local_sources,
    }))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn circuit() -> AnyResult<output::OutputCircuit> {
    if hex::encode(output::proof::source_identity()) != OUTPUT_SOURCE {
        return Err("Output source identity changed".into());
    }
    let domain: [u8; 32] =
        hex::decode("a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0")?
            .try_into()
            .map_err(|_| "domain width")?;
    let profile_id: [u8; 32] =
        hex::decode("ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700")?
            .try_into()
            .map_err(|_| "profile width")?;
    let note = native::Note {
        owner: [1; 32],
        incoming: [2; 32],
        value: 200_000_000,
        rho: [3; 32],
        key_commitment: [4; 32],
        native_pk: [5; 32],
    };
    let blinding = [1_u8; 32];
    let statement = output::OutputStatement {
        domain,
        cm: note.commitment(&domain),
        cv: native::value_commitment(note.value, &blinding).map_err(|_| "value commitment")?,
        cf_hash: digest(b"KPB bounded setup public Output shape fixture"),
    };
    Ok(output::OutputCircuit {
        profile: output::Profile { domain, profile_id },
        statement,
        witness: output::OutputWitness { note, blinding },
    })
}

fn synthesize() -> AnyResult<R1cs> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit()?.generate_constraints(cs.clone())?;
    cs.finalize();
    let mut groups = cs.to_matrices()?;
    if groups.len() != 1 {
        return Err("unexpected predicate count".into());
    }
    let matrix = R1cs {
        instances: cs.num_instance_variables(),
        witnesses: cs.num_witness_variables(),
        matrices: groups
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or("missing R1CS predicate")?
            .try_into()
            .map_err(|_| "axis count")?,
    };
    drop(cs);
    matrix.validate().map_err(|_| "invalid matrix")?;
    if matrix.instances != INSTANCES
        || matrix.witnesses != WITNESSES
        || matrix.variables().map_err(|_| "variables")? != VARIABLES
        || matrix.constraints() != CONSTRAINTS
        || authority::join::fingerprint(&matrix).map_err(|_| "fingerprint")? != OUTPUT_MATRIX
    {
        return Err("Output matrix identity changed".into());
    }
    Ok(matrix)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AxisReceipt {
    axis: usize,
    rows: u64,
    terms: u64,
    maximum_row_terms: u64,
    raw_bytes: u64,
    raw_sha256: String,
    compressed_bytes: u64,
    compressed_sha256: String,
}

struct Hashed<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}

impl<W: Write> Write for Hashed<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hash.update(&bytes[..count]);
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("byte count overflow"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn u64le(value: usize) -> io::Result<[u8; 8]> {
    Ok(u64::try_from(value)
        .map_err(|_| io::Error::other("usize overflow"))?
        .to_le_bytes())
}

fn payload(
    matrix: &R1cs,
    axis: usize,
    output: &mut impl Write,
    mut fingerprint: Option<&mut Sha256>,
) -> io::Result<(u64, u64)> {
    output.write_all(MAGIC)?;
    output.write_all(&u64le(axis)?)?;
    let field = Fr::MODULUS.to_bytes_le();
    if field.len() != 32 {
        return Err(io::Error::other("field width"));
    }
    output.write_all(&field)?;
    for count in [matrix.instances, matrix.witnesses, matrix.constraints()] {
        output.write_all(&u64le(count)?)?;
    }
    let mut terms = 0_u64;
    let mut maximum = 0_u64;
    for (row_index, row) in matrix.matrices[axis].iter().enumerate() {
        let count = u64::try_from(row.len()).map_err(|_| io::Error::other("row count"))?;
        maximum = maximum.max(count);
        terms = terms
            .checked_add(count)
            .ok_or_else(|| io::Error::other("term overflow"))?;
        let count_bytes = count.to_le_bytes();
        output.write_all(&count_bytes)?;
        if let Some(hash) = fingerprint.as_deref_mut() {
            hash.update(count_bytes);
        }
        let mut previous = None;
        for (term_index, (coefficient, column)) in row.iter().enumerate() {
            if coefficient.is_zero() || previous.is_some_and(|value| *column <= value) {
                return Err(io::Error::other(format!(
                    "noncanonical term axis={axis} row={row_index} term={term_index}"
                )));
            }
            previous = Some(*column);
            let coefficient = coefficient.into_bigint().to_bytes_le();
            if coefficient.len() != 32 {
                return Err(io::Error::other("coefficient width"));
            }
            let column = u64le(*column)?;
            output.write_all(&coefficient)?;
            output.write_all(&column)?;
            if let Some(hash) = fingerprint.as_deref_mut() {
                hash.update(&coefficient);
                hash.update(column);
            }
        }
    }
    Ok((terms, maximum))
}

fn gzip_binary() -> io::Result<String> {
    Ok(file_hash(Path::new("/usr/bin/gzip"))?.1)
}

fn gzip_axis(
    matrix: &R1cs,
    axis: usize,
    path: Option<&Path>,
    fingerprint: Option<&mut Sha256>,
) -> io::Result<AxisReceipt> {
    if gzip_binary()? != GZIP_BINARY {
        return Err(io::Error::other("gzip binary identity"));
    }
    let output: Box<dyn Write + Send> = match path {
        Some(path) => Box::new(BufWriter::with_capacity(
            65_536,
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
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
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("gzip stdout"))?;
    let reader = thread::spawn(move || -> io::Result<(u64, String)> {
        let mut input = BufReader::with_capacity(65_536, stdout);
        let mut output = Hashed {
            inner: output,
            hash: Sha256::new(),
            bytes: 0,
        };
        io::copy(&mut input, &mut output)?;
        output.flush()?;
        Ok((output.bytes, hex::encode(output.hash.finalize())))
    });
    let raw = (|| -> io::Result<(u64, String, u64, u64)> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("gzip stdin"))?;
        let mut output = Hashed {
            inner: BufWriter::with_capacity(65_536, stdin),
            hash: Sha256::new(),
            bytes: 0,
        };
        let (terms, maximum) = payload(matrix, axis, &mut output, fingerprint)?;
        output.flush()?;
        Ok((
            output.bytes,
            hex::encode(output.hash.finalize()),
            terms,
            maximum,
        ))
    })();
    let status = child.wait()?;
    let compressed = reader
        .join()
        .map_err(|_| io::Error::other("gzip reader panic"))??;
    let raw = raw?;
    if !status.success() {
        return Err(io::Error::other("gzip failed"));
    }
    if let Some(path) = path {
        File::open(path)?.sync_all()?;
    }
    Ok(AxisReceipt {
        axis,
        rows: matrix.constraints() as u64,
        terms: raw.2,
        maximum_row_terms: raw.3,
        raw_bytes: raw.0,
        raw_sha256: raw.1,
        compressed_bytes: compressed.0,
        compressed_sha256: compressed.1,
    })
}

fn main() -> AnyResult<()> {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: kpb-output-r1cs-axes FRESH-OUTPUT-DIRECTORY".into());
    }
    let output = PathBuf::from(&args[1]);
    if output.exists() {
        return Err("fresh output directory required".into());
    }
    let started = Instant::now();
    let matrix = synthesize()?;
    let mut fingerprint = Sha256::new();
    fingerprint.update(FINGERPRINT_DOMAIN);
    for count in [matrix.instances, matrix.witnesses, matrix.constraints()] {
        fingerprint.update(u64le(count)?);
    }
    let mut expected = Vec::with_capacity(3);
    for axis in 0..3 {
        expected.push(gzip_axis(&matrix, axis, None, Some(&mut fingerprint))?);
    }
    let fingerprint = hex::encode(fingerprint.finalize());
    if fingerprint != OUTPUT_MATRIX {
        return Err("transport fingerprint differs from exact Output matrix".into());
    }
    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    let mut axes = Vec::with_capacity(3);
    for axis in 0..3 {
        let actual = gzip_axis(&matrix, axis, Some(&output.join(NAMES[axis])), None)?;
        if actual != expected[axis] {
            return Err("axis identity changed between passes".into());
        }
        axes.push(json!({
            "axis": actual.axis,
            "file_label": NAMES[axis],
            "rows": actual.rows,
            "terms": actual.terms,
            "maximum_row_terms": actual.maximum_row_terms,
            "raw_bytes": actual.raw_bytes,
            "raw_sha256": actual.raw_sha256,
            "compressed_bytes": actual.compressed_bytes,
            "compressed_sha256": actual.compressed_sha256,
        }));
    }
    let manifest = json!({
        "schema": "kpb-output-r1cs-axes/v1",
        "status": "PASS",
        "classification": "PUBLIC_UNASSIGNED_OUTPUT_ROWS_NO_SETUP_ZKEY_PROOF_OR_CEREMONY",
        "output_source_sha256": OUTPUT_SOURCE,
        "canonical_r1cs_fingerprint": OUTPUT_MATRIX,
        "field_decimal": Fr::MODULUS.to_string(),
        "instances_including_one": INSTANCES,
        "witnesses": WITNESSES,
        "variables": VARIABLES,
        "constraints": CONSTRAINTS,
        "generator_source_sha256": sha256(SELF_SOURCE),
        "cargo_toml_sha256": sha256(CARGO_TOML),
        "cargo_lock_sha256": sha256(CARGO_LOCK),
        "rust_toolchain_sha256": sha256(RUST_TOOLCHAIN),
        "source_closure_manifest_sha256": sha256(SOURCE_CLOSURE),
        "source_closure_identity": serde_json::from_slice::<Value>(SOURCE_CLOSURE)?["closure_identity"],
        "build_dep_info": dep_info_identity()?,
        "generator_binary": binary_identity()?,
        "gzip_binary_sha256": GZIP_BINARY,
        "gzip_arguments": ["-1", "-n", "-c"],
        "axes": axes,
        "private_assignment_included": false,
        "setup_executed": false,
        "zkey_generated": false,
        "phase1_executed": false,
        "phase2_executed": false,
        "ceremony_executed": false,
        "elapsed_seconds": started.elapsed().as_secs_f64(),
    });
    let manifest_path = output.join("AXES-MANIFEST.json");
    let mut manifest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    manifest_file.write_all(&bytes)?;
    manifest_file.sync_all()?;
    File::open(&output)?.sync_all()?;
    println!(
        "{}",
        json!({
            "schema": "kpb-output-r1cs-axes-status/v1",
            "status": "PASS",
            "manifest_sha256": sha256(&bytes),
            "setup_executed": false,
        })
    );
    Ok(())
}
