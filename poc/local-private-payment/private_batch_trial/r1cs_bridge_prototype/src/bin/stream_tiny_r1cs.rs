//! Synthetic-only bounded gzip-axis to standard R1CS v1 exporter.
//! The compiled plan cannot authorize the frozen 13M-row aggregate export.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::{File, Metadata, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const PLAN: &[u8] = include_bytes!("../../tiny_stream_plan.json");
const PLAN_SHA256: &str = "bce9352152cb1d92c0a4232da1973c569216bcb38d0a37fb8019adf6fe0fd424";
const FIXTURE_SOURCE_SHA256: &str =
    "9e6fb041bc7d4aa3a1a675e05b8ab45e6565667ac5f9cf59869f335e4911ec4b";
const MATRIX_FINGERPRINT: &str = "898baeab8bcddddc17845cf8b4956db569b253f0d551e7b9ddce0a53661812db";
const OUTPUT_SHA256: &str = "786364162a371e862488ed92dbb12e36670024c9fbb8c3acc1391f4c2bce33ab";
const MAGIC: &[u8; 16] = b"KPI_R1CS_AXIS_V1";
const FINGERPRINT_DOMAIN: &[u8] = b"KPINAS/R1CS/v1\0";
const INSTANCES: u64 = 3;
const WITNESSES: u64 = 3;
const VARIABLES: u64 = 6;
const CONSTRAINTS: u64 = 3;
const PUBLIC_OUTPUTS: u64 = 0;
const PUBLIC_INPUTS: u64 = 2;
const PRIVATE_INPUTS: u64 = 3;
const LABELS: u64 = 6;
const CONSTRAINT_SECTION_BYTES: u64 = 576;
const WIRE_MAP_BYTES: u64 = 48;
const OUTPUT_BYTES: u64 = 736;
const OUTPUT_NAME: &str = "tiny.r1cs";
const EXPORT_RECEIPT_NAME: &str = "EXPORT-RECEIPT.json";
const OUTPUT_PARTIAL_NAME: &str = ".tiny.r1cs.partial";
const RECEIPT_PARTIAL_NAME: &str = ".EXPORT-RECEIPT.json.partial";

#[derive(Clone, Copy)]
struct AxisPin {
    name: &'static str,
    compressed_bytes: u64,
    compressed_sha256: &'static str,
    raw_bytes: u64,
    raw_sha256: &'static str,
    terms: u64,
}

const AXES: [AxisPin; 3] = [
    AxisPin {
        name: "A.r1cs.bin.gz",
        compressed_bytes: 117,
        compressed_sha256: "9d26dbff4cb5775beeb53fbafcb1c74adc8d978a05ea268e9f0dc2ac4dba3c12",
        raw_bytes: 344,
        raw_sha256: "c41c813f980e515c0dcde491aeba85d846c2e8a36860771f5fd93533d4a5fc36",
        terms: 6,
    },
    AxisPin {
        name: "B.r1cs.bin.gz",
        compressed_bytes: 105,
        compressed_sha256: "7d8d8106d9a161fb15961dd996bb23af26a0d4fb22ab4326b326d7cb27db5d78",
        raw_bytes: 264,
        raw_sha256: "5c15bbb6eecaa9ed8fc5fc8ff917cdbe491471141e4139852c768c59aab0a3ba",
        terms: 4,
    },
    AxisPin {
        name: "C.r1cs.bin.gz",
        compressed_bytes: 114,
        compressed_sha256: "f84cda321e84e645498491dd20ec315866d6e42a47116e2ddc6fd21871b94360",
        raw_bytes: 304,
        raw_sha256: "02d51205dc70056d8d4bad364b75167b020e41339204cba92b482b9c55f4b344",
        terms: 5,
    },
];

#[derive(Debug)]
struct Problem {
    code: &'static str,
    axis: Option<usize>,
    row: Option<u64>,
    term: Option<u64>,
    detail: String,
}

type Result<T> = std::result::Result<T, Problem>;

fn problem(
    code: &'static str,
    axis: Option<usize>,
    row: Option<u64>,
    term: Option<u64>,
    detail: impl Into<String>,
) -> Problem {
    Problem {
        code,
        axis,
        row,
        term,
        detail: detail.into(),
    }
}

fn external(code: &'static str, error: impl std::fmt::Display) -> Problem {
    problem(code, None, None, None, error.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn file_identity(file: &File, axis: usize) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .map_err(|error| problem("input-metadata", Some(axis), None, None, error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(problem(
            "input-not-regular",
            Some(axis),
            None,
            None,
            "not a regular file",
        ));
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

fn hash_reader(reader: &mut impl Read) -> std::io::Result<(u64, String)> {
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
            .ok_or_else(|| std::io::Error::other("byte count overflow"))?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hex::encode(hash.finalize())))
}

fn hash_path(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    Ok(hash_reader(&mut file)?.1)
}

struct OpenedAxis {
    file: File,
    identity: FileIdentity,
}

fn open_and_pin(path: &Path, axis: usize) -> Result<OpenedAxis> {
    let pin = AXES[axis];
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| problem("input-open", Some(axis), None, None, error.to_string()))?;
    let before = file_identity(&file, axis)?;
    if before.size != pin.compressed_bytes {
        return Err(problem(
            "compressed-size-pin",
            Some(axis),
            None,
            None,
            format!("expected={} actual={}", pin.compressed_bytes, before.size),
        ));
    }
    let (bytes, digest) = hash_reader(&mut file)
        .map_err(|error| problem("compressed-read", Some(axis), None, None, error.to_string()))?;
    if bytes != pin.compressed_bytes || digest != pin.compressed_sha256 {
        return Err(problem(
            "compressed-identity-pin",
            Some(axis),
            None,
            None,
            format!(
                "expected_bytes={} actual_bytes={bytes} expected_sha256={} actual_sha256={digest}",
                pin.compressed_bytes, pin.compressed_sha256
            ),
        ));
    }
    let after = file_identity(&file, axis)?;
    if before != after {
        return Err(problem(
            "input-changed-during-pin",
            Some(axis),
            None,
            None,
            format!("before={before:?} after={after:?}"),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| problem("input-rewind", Some(axis), None, None, error.to_string()))?;
    Ok(OpenedAxis {
        file,
        identity: before,
    })
}

fn open_all_pinned(paths: [&Path; 3]) -> Result<Vec<OpenedAxis>> {
    let mut result = Vec::with_capacity(3);
    for (axis, path) in paths.iter().enumerate() {
        result.push(open_and_pin(path, axis)?);
    }
    Ok(result)
}

type Decoded = BufReader<GzDecoder<BufReader<File>>>;

struct AxisCursor {
    input: Decoded,
    raw_hash: Sha256,
    raw_bytes: u64,
    original: FileIdentity,
    axis: usize,
    next_row: u64,
    remaining_terms: u64,
    next_term: u64,
    previous_column: Option<u64>,
    total_terms: u64,
    maximum_row_terms: u64,
}

struct Term {
    coefficient: [u8; 32],
    column: u32,
    transport: [u8; 40],
}

impl AxisCursor {
    fn new(opened: OpenedAxis, axis: usize, prime: &[u8; 32]) -> Result<Self> {
        let compressed = BufReader::with_capacity(65_536, opened.file);
        let decoder = GzDecoder::new(compressed);
        let mut result = Self {
            input: BufReader::with_capacity(65_536, decoder),
            raw_hash: Sha256::new(),
            raw_bytes: 0,
            original: opened.identity,
            axis,
            next_row: 0,
            remaining_terms: 0,
            next_term: 0,
            previous_column: None,
            total_terms: 0,
            maximum_row_terms: 0,
        };
        let mut magic = [0_u8; 16];
        result.exact(&mut magic, None, None, "gzip-header-magic")?;
        if &magic != MAGIC {
            return Err(problem(
                "axis-magic",
                Some(axis),
                None,
                None,
                hex::encode(magic),
            ));
        }
        let (encoded_axis, _) = result.count(None, None, "gzip-header-axis")?;
        if encoded_axis != axis as u64 {
            return Err(problem(
                "axis-number",
                Some(axis),
                None,
                None,
                format!("actual={encoded_axis}"),
            ));
        }
        let mut encoded_prime = [0_u8; 32];
        result.exact(&mut encoded_prime, None, None, "gzip-header-field")?;
        if &encoded_prime != prime {
            return Err(problem(
                "field-modulus",
                Some(axis),
                None,
                None,
                hex::encode(encoded_prime),
            ));
        }
        for (label, expected) in [
            ("instances", INSTANCES),
            ("witnesses", WITNESSES),
            ("constraints", CONSTRAINTS),
        ] {
            let (actual, _) = result.count(None, None, "gzip-header-shape")?;
            if actual != expected {
                return Err(problem(
                    "axis-shape",
                    Some(axis),
                    None,
                    None,
                    format!("field={label} expected={expected} actual={actual}"),
                ));
            }
        }
        Ok(result)
    }

    fn exact(
        &mut self,
        output: &mut [u8],
        row: Option<u64>,
        term: Option<u64>,
        code: &'static str,
    ) -> Result<()> {
        self.input
            .read_exact(output)
            .map_err(|error| problem(code, Some(self.axis), row, term, error.to_string()))?;
        self.raw_bytes = self
            .raw_bytes
            .checked_add(output.len() as u64)
            .ok_or_else(|| {
                problem(
                    "raw-byte-overflow",
                    Some(self.axis),
                    row,
                    term,
                    "raw byte overflow",
                )
            })?;
        self.raw_hash.update(output);
        Ok(())
    }

    fn count(
        &mut self,
        row: Option<u64>,
        term: Option<u64>,
        code: &'static str,
    ) -> Result<(u64, [u8; 8])> {
        let mut bytes = [0_u8; 8];
        self.exact(&mut bytes, row, term, code)?;
        Ok((u64::from_le_bytes(bytes), bytes))
    }

    fn start_row(&mut self, row: u64) -> Result<(u32, [u8; 8])> {
        if row != self.next_row || self.remaining_terms != 0 || row >= CONSTRAINTS {
            return Err(problem(
                "row-state",
                Some(self.axis),
                Some(row),
                None,
                format!(
                    "next_row={} remaining_terms={}",
                    self.next_row, self.remaining_terms
                ),
            ));
        }
        let (terms, encoded) = self.count(Some(row), None, "row-term-count")?;
        let narrowed = u32::try_from(terms).map_err(|_| {
            problem(
                "row-term-count-u32",
                Some(self.axis),
                Some(row),
                None,
                format!("terms={terms}"),
            )
        })?;
        let pin = AXES[self.axis];
        if self.raw_bytes > pin.raw_bytes || terms > (pin.raw_bytes - self.raw_bytes) / 40 {
            return Err(problem(
                "row-exceeds-raw-frame",
                Some(self.axis),
                Some(row),
                None,
                format!("terms={terms} raw_bytes={}", self.raw_bytes),
            ));
        }
        self.total_terms = self.total_terms.checked_add(terms).ok_or_else(|| {
            problem(
                "term-total-overflow",
                Some(self.axis),
                Some(row),
                None,
                "term total overflow",
            )
        })?;
        self.maximum_row_terms = self.maximum_row_terms.max(terms);
        self.remaining_terms = terms;
        self.next_term = 0;
        self.previous_column = None;
        self.next_row += 1;
        Ok((narrowed, encoded))
    }

    fn next_term(&mut self, row: u64, prime: &[u8; 32]) -> Result<Term> {
        if self.remaining_terms == 0 {
            return Err(problem(
                "term-state",
                Some(self.axis),
                Some(row),
                Some(self.next_term),
                "no remaining term",
            ));
        }
        let term_index = self.next_term;
        let mut transport = [0_u8; 40];
        self.exact(
            &mut transport,
            Some(row),
            Some(term_index),
            "row-term-bytes",
        )?;
        let mut coefficient = [0_u8; 32];
        coefficient.copy_from_slice(&transport[..32]);
        let column_u64 = u64::from_le_bytes(transport[32..].try_into().map_err(|_| {
            problem(
                "term-column-width",
                Some(self.axis),
                Some(row),
                Some(term_index),
                "column width changed",
            )
        })?);
        let column = admit_term(
            self.axis,
            row,
            term_index,
            &coefficient,
            column_u64,
            self.previous_column,
            prime,
        )?;
        self.previous_column = Some(column_u64);
        self.remaining_terms -= 1;
        self.next_term += 1;
        Ok(Term {
            coefficient,
            column,
            transport,
        })
    }

    fn finish(mut self) -> Result<(u64, u64, String)> {
        let pin = AXES[self.axis];
        if self.next_row != CONSTRAINTS
            || self.remaining_terms != 0
            || self.total_terms != pin.terms
        {
            return Err(problem(
                "axis-row-or-term-total",
                Some(self.axis),
                None,
                None,
                format!(
                    "rows={} remaining={} expected_terms={} actual_terms={}",
                    self.next_row, self.remaining_terms, pin.terms, self.total_terms
                ),
            ));
        }
        let mut extra = [0_u8; 1];
        let extra_count = self.input.read(&mut extra).map_err(|error| {
            problem(
                "gzip-crc-or-stream",
                Some(self.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if extra_count != 0 {
            return Err(problem(
                "decoded-trailing-byte",
                Some(self.axis),
                None,
                None,
                format!("first_extra={:02x}", extra[0]),
            ));
        }
        let raw_bytes = self.raw_bytes;
        let raw_sha256 = hex::encode(self.raw_hash.finalize());
        if raw_bytes != pin.raw_bytes || raw_sha256 != pin.raw_sha256 {
            return Err(problem(
                "raw-identity-pin",
                Some(self.axis),
                None,
                None,
                format!(
                    "expected_bytes={} actual_bytes={raw_bytes} expected_sha256={} actual_sha256={raw_sha256}",
                    pin.raw_bytes, pin.raw_sha256
                ),
            ));
        }
        let decoder = self.input.into_inner();
        let mut compressed = decoder.into_inner();
        let trailing = compressed.fill_buf().map_err(|error| {
            problem(
                "compressed-eof-read",
                Some(self.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if !trailing.is_empty() {
            return Err(problem(
                "gzip-trailing-or-second-member",
                Some(self.axis),
                None,
                None,
                format!(
                    "prefix={}",
                    hex::encode(&trailing[..trailing.len().min(16)])
                ),
            ));
        }
        let file = compressed.into_inner();
        let final_identity = file_identity(&file, self.axis)?;
        if final_identity != self.original {
            return Err(problem(
                "input-changed-during-scan",
                Some(self.axis),
                None,
                None,
                format!("before={:?} after={final_identity:?}", self.original),
            ));
        }
        Ok((self.total_terms, self.maximum_row_terms, raw_sha256))
    }
}

fn less_than_le(left: &[u8], right: &[u8]) -> bool {
    for index in (0..left.len()).rev() {
        if left[index] != right[index] {
            return left[index] < right[index];
        }
    }
    false
}

fn admit_term(
    axis: usize,
    row: u64,
    term: u64,
    coefficient: &[u8; 32],
    column: u64,
    previous_column: Option<u64>,
    prime: &[u8; 32],
) -> Result<u32> {
    if coefficient.iter().all(|byte| *byte == 0) {
        return Err(problem(
            "zero-coefficient",
            Some(axis),
            Some(row),
            Some(term),
            format!("coefficient={} column={column}", hex::encode(coefficient)),
        ));
    }
    if !less_than_le(coefficient, prime) {
        return Err(problem(
            "noncanonical-coefficient",
            Some(axis),
            Some(row),
            Some(term),
            format!("coefficient={} column={column}", hex::encode(coefficient)),
        ));
    }
    if column >= VARIABLES {
        return Err(problem(
            "column-out-of-range",
            Some(axis),
            Some(row),
            Some(term),
            format!("coefficient={} column={column}", hex::encode(coefficient)),
        ));
    }
    if previous_column.is_some_and(|previous| column <= previous) {
        return Err(problem(
            "duplicate-or-reordered-column",
            Some(axis),
            Some(row),
            Some(term),
            format!(
                "coefficient={} previous_column={} column={column}",
                hex::encode(coefficient),
                previous_column.unwrap_or_default()
            ),
        ));
    }
    u32::try_from(column).map_err(|_| {
        problem(
            "column-u32",
            Some(axis),
            Some(row),
            Some(term),
            format!("column={column}"),
        )
    })
}

fn prime() -> Result<[u8; 32]> {
    Fr::MODULUS
        .to_bytes_le()
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            problem(
                "field-width",
                None,
                None,
                None,
                format!("actual={}", bytes.len()),
            )
        })
}

fn preflight(paths: [&Path; 3], prime: &[u8; 32]) -> Result<Vec<(u64, u64)>> {
    let opened = open_all_pinned(paths)?;
    let mut fingerprint = Sha256::new();
    fingerprint.update(FINGERPRINT_DOMAIN);
    for count in [INSTANCES, WITNESSES, CONSTRAINTS] {
        fingerprint.update(count.to_le_bytes());
    }
    let mut results = Vec::with_capacity(3);
    for (axis, opened_axis) in opened.into_iter().enumerate() {
        let mut cursor = AxisCursor::new(opened_axis, axis, prime)?;
        for row in 0..CONSTRAINTS {
            let (count, encoded_count) = cursor.start_row(row)?;
            fingerprint.update(encoded_count);
            for _ in 0..count {
                let term = cursor.next_term(row, prime)?;
                fingerprint.update(term.transport);
            }
        }
        let (terms, maximum, _) = cursor.finish()?;
        results.push((terms, maximum));
    }
    let actual = hex::encode(fingerprint.finalize());
    if actual != MATRIX_FINGERPRINT {
        return Err(problem(
            "matrix-fingerprint",
            None,
            None,
            None,
            format!("expected={MATRIX_FINGERPRINT} actual={actual}"),
        ));
    }
    Ok(results)
}

struct HashedOutput {
    output: BufWriter<File>,
    hash: Sha256,
    bytes: u64,
}

impl HashedOutput {
    fn create_new(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| external("output-create-new", error))?;
        Ok(Self {
            output: BufWriter::with_capacity(65_536, file),
            hash: Sha256::new(),
            bytes: 0,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.output
            .write_all(bytes)
            .map_err(|error| external("output-write", error))?;
        self.hash.update(bytes);
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| external("output-size", "output byte overflow"))?;
        Ok(())
    }

    fn u32(&mut self, value: u64) -> Result<()> {
        let value = u32::try_from(value).map_err(|_| external("output-u32", value))?;
        self.write(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<()> {
        self.write(&value.to_le_bytes())
    }

    fn finish(mut self) -> Result<(u64, String)> {
        self.output
            .flush()
            .map_err(|error| external("output-flush", error))?;
        self.output
            .get_ref()
            .sync_all()
            .map_err(|error| external("output-fsync", error))?;
        Ok((self.bytes, hex::encode(self.hash.finalize())))
    }
}

fn export_second_pass(
    paths: [&Path; 3],
    output_path: &Path,
    prime: &[u8; 32],
) -> Result<Vec<(u64, u64)>> {
    // Reopen and re-pin all inputs before creating any output.
    let opened = open_all_pinned(paths)?;
    let mut cursors = opened
        .into_iter()
        .enumerate()
        .map(|(axis, source)| AxisCursor::new(source, axis, prime))
        .collect::<Result<Vec<_>>>()?;
    let mut output = HashedOutput::create_new(output_path)?;
    output.write(b"r1cs")?;
    output.u32(1)?;
    output.u32(3)?;

    output.u32(1)?;
    output.u64(64)?;
    output.u32(32)?;
    output.write(prime)?;
    output.u32(VARIABLES)?;
    output.u32(PUBLIC_OUTPUTS)?;
    output.u32(PUBLIC_INPUTS)?;
    output.u32(PRIVATE_INPUTS)?;
    output.u64(LABELS)?;
    output.u32(CONSTRAINTS)?;

    output.u32(2)?;
    output.u64(CONSTRAINT_SECTION_BYTES)?;
    let constraint_start = output.bytes;
    for row in 0..CONSTRAINTS {
        for cursor in &mut cursors {
            let (terms, _) = cursor.start_row(row)?;
            output.u32(terms as u64)?;
            for _ in 0..terms {
                let term = cursor.next_term(row, prime)?;
                output.u32(term.column as u64)?;
                output.write(&term.coefficient)?;
            }
        }
    }
    if output.bytes - constraint_start != CONSTRAINT_SECTION_BYTES {
        return Err(external(
            "constraint-section-size",
            output.bytes - constraint_start,
        ));
    }

    output.u32(3)?;
    output.u64(WIRE_MAP_BYTES)?;
    let map_start = output.bytes;
    for wire in 0..VARIABLES {
        output.u64(wire)?;
    }
    if output.bytes - map_start != WIRE_MAP_BYTES {
        return Err(external("wire-map-size", output.bytes - map_start));
    }
    let (bytes, digest) = output.finish()?;
    if bytes != OUTPUT_BYTES || digest != OUTPUT_SHA256 {
        return Err(external(
            "output-identity",
            format!(
                "expected_bytes={OUTPUT_BYTES} actual_bytes={bytes} expected_sha256={OUTPUT_SHA256} actual_sha256={digest}"
            ),
        ));
    }
    let mut result = Vec::with_capacity(3);
    for cursor in cursors {
        let (terms, maximum, _) = cursor.finish()?;
        result.push((terms, maximum));
    }
    Ok(result)
}

fn validate_plan() -> Result<String> {
    let digest = hex::encode(Sha256::digest(PLAN));
    if digest != PLAN_SHA256 {
        return Err(external(
            "plan-identity",
            format!("expected={PLAN_SHA256} actual={digest}"),
        ));
    }
    let plan: Value = serde_json::from_slice(PLAN).map_err(|error| external("plan-json", error))?;
    let required = [
        ("fixture_source_sha256", FIXTURE_SOURCE_SHA256),
        ("canonical_r1cs_fingerprint", MATRIX_FINGERPRINT),
    ];
    for (field, expected) in required {
        if plan[field].as_str() != Some(expected) {
            return Err(external("plan-field", field));
        }
    }
    if plan["standard_r1cs_v1"]["sha256"].as_str() != Some(OUTPUT_SHA256)
        || plan["standard_r1cs_v1"]["complete_file_bytes"].as_u64() != Some(OUTPUT_BYTES)
        || plan["aggregate_full_export_authorized"].as_bool() != Some(false)
        || plan["setup_authorized"].as_bool() != Some(false)
        || plan["zkey_authorized"].as_bool() != Some(false)
        || plan["phase1_authorized"].as_bool() != Some(false)
        || plan["phase2_authorized"].as_bool() != Some(false)
        || plan["ceremony_authorized"].as_bool() != Some(false)
    {
        return Err(external(
            "plan-authority",
            "plan authority flags or output changed",
        ));
    }
    Ok(digest)
}

fn fresh_empty_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| external("output-directory", error))?;
    if !metadata.is_dir() {
        return Err(external("output-directory", "not a directory"));
    }
    let mut entries = fs::read_dir(path).map_err(|error| external("output-directory", error))?;
    if entries.next().is_some() {
        return Err(external("output-directory-not-empty", path.display()));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| external("directory-fsync", error))
}

fn publish_create_new(partial: &Path, final_path: &Path, directory: &Path) -> Result<()> {
    fs::hard_link(partial, final_path).map_err(|error| external("publish-create-new", error))?;
    fs::remove_file(partial).map_err(|error| external("publish-remove-partial", error))?;
    sync_directory(directory)
}

fn write_json_partial(path: &Path, value: &Value) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| external("receipt-json", error))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| external("receipt-create-new", error))?;
    file.write_all(&bytes)
        .map_err(|error| external("receipt-write", error))?;
    file.sync_all()
        .map_err(|error| external("receipt-fsync", error))
}

fn run(paths: [&Path; 3], output_directory: &Path, binary_sha256: &str) -> Result<Value> {
    fresh_empty_directory(output_directory)?;
    let plan_sha256 = validate_plan()?;
    let prime = prime()?;
    let preflight = preflight(paths, &prime)?;
    let partial_output = output_directory.join(OUTPUT_PARTIAL_NAME);
    let second_pass = export_second_pass(paths, &partial_output, &prime)?;
    if preflight != second_pass {
        return Err(external(
            "input-pass-substitution",
            format!("preflight={preflight:?} second={second_pass:?}"),
        ));
    }
    let final_output = output_directory.join(OUTPUT_NAME);
    publish_create_new(&partial_output, &final_output, output_directory)?;
    let axes = AXES
        .iter()
        .enumerate()
        .map(|(axis, pin)| {
            json!({
                "axis": axis,
                "file_label": pin.name,
                "compressed_bytes": pin.compressed_bytes,
                "compressed_sha256": pin.compressed_sha256,
                "raw_bytes": pin.raw_bytes,
                "raw_sha256": pin.raw_sha256,
                "terms": preflight[axis].0,
                "maximum_row_terms": preflight[axis].1,
            })
        })
        .collect::<Vec<_>>();
    let receipt = json!({
        "schema": "kpb-tiny-stream-r1cs-export-receipt/v1",
        "status": "PASS",
        "classification": "SYNTHETIC_FORMAT_BRIDGE_ONLY_NO_SETUP_OR_CEREMONY",
        "plan_sha256": plan_sha256,
        "fixture_source_sha256": FIXTURE_SOURCE_SHA256,
        "exporter_binary_sha256": binary_sha256,
        "canonical_r1cs_fingerprint": MATRIX_FINGERPRINT,
        "axes": axes,
        "passes": {
            "complete_admission_before_output": true,
            "second_pass_all_input_pins_and_eof_rechecked": true,
            "coefficients_canonical_nonzero": true,
            "columns_strictly_increasing_unique_and_in_range": true,
        },
        "output": {
            "file": OUTPUT_NAME,
            "bytes": OUTPUT_BYTES,
            "sha256": OUTPUT_SHA256,
            "section_order": [1, 2, 3],
            "constraint_section_bytes": CONSTRAINT_SECTION_BYTES,
            "identity_wire_map_bytes": WIRE_MAP_BYTES,
            "create_new_atomic_publish": true,
            "fsync_before_publish": true,
        },
        "independent_verifier_passed": false,
        "aggregate_full_export_authorized": false,
        "r1cs_full_aggregate_exported": false,
        "zkey_generated": false,
        "setup_executed": false,
        "phase1_executed": false,
        "phase2_executed": false,
        "ceremony_executed": false,
    });
    let partial_receipt = output_directory.join(RECEIPT_PARTIAL_NAME);
    write_json_partial(&partial_receipt, &receipt)?;
    let final_receipt = output_directory.join(EXPORT_RECEIPT_NAME);
    publish_create_new(&partial_receipt, &final_receipt, output_directory)?;
    Ok(receipt)
}

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() != 5 {
        eprintln!(
            "usage: {} A.r1cs.bin.gz B.r1cs.bin.gz C.r1cs.bin.gz FRESH-EMPTY-OUTPUT-DIRECTORY",
            PathBuf::from(args.first().cloned().unwrap_or_default()).display()
        );
        std::process::exit(2);
    }
    let binary_sha256 = match env::current_exe().and_then(|path| hash_path(&path)) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("exporter-binary-identity: {error}");
            std::process::exit(2);
        }
    };
    let paths = [
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    ];
    match run(paths, Path::new(&args[4]), &binary_sha256) {
        Ok(_) => println!(
            "{{\"schema\":\"kpb-tiny-stream-r1cs-export-status/v1\",\"status\":\"PASS\",\"output\":\"{OUTPUT_NAME}\",\"receipt\":\"{EXPORT_RECEIPT_NAME}\",\"setup_executed\":false}}"
        ),
        Err(error) => {
            eprintln!(
                "tiny-stream-export-rejected: code={} axis={:?} row={:?} term={:?} detail={}",
                error.code, error.axis, error.row, error.term, error.detail
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_and_size_freeze_are_exact() {
        assert_eq!(validate_plan().unwrap(), PLAN_SHA256);
        assert_eq!(
            112 + CONSTRAINT_SECTION_BYTES + WIRE_MAP_BYTES,
            OUTPUT_BYTES
        );
        assert!(
            !serde_json::from_slice::<Value>(PLAN).unwrap()["aggregate_full_export_authorized"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn hostile_term_controls_fail_closed() {
        let prime = prime().unwrap();
        let zero = [0_u8; 32];
        assert_eq!(
            admit_term(0, 0, 0, &zero, 0, None, &prime)
                .unwrap_err()
                .code,
            "zero-coefficient"
        );
        assert_eq!(
            admit_term(0, 0, 0, &prime, 0, None, &prime)
                .unwrap_err()
                .code,
            "noncanonical-coefficient"
        );
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(
            admit_term(0, 0, 1, &one, 2, Some(2), &prime)
                .unwrap_err()
                .code,
            "duplicate-or-reordered-column"
        );
        assert_eq!(
            admit_term(0, 0, 1, &one, VARIABLES, None, &prime)
                .unwrap_err()
                .code,
            "column-out-of-range"
        );
    }
}
