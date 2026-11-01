//! Read-only admission of the exact retained aggregate A/B/C gzip axes.
//! This emits one create-new receipt. It never exports R1CS or runs setup.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{File, Metadata, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 16] = b"KPI_R1CS_AXIS_V1";
const FINGERPRINT_DOMAIN: &[u8] = b"KPINAS/R1CS/v1\0";
const INSTANCES: u64 = 3;
const WITNESSES: u64 = 12_949_818;
const VARIABLES: u64 = 12_949_821;
const CONSTRAINTS: u64 = 13_093_029;
const EXPECTED_TOTAL_TERMS: u64 = 71_656_399;
const EXPECTED_CONSTRAINT_SECTION_BYTES: u64 = 2_736_746_712;
const EXPECTED_WIRE_MAP_BYTES: u64 = 103_598_568;
const EXPECTED_R1CS_BYTES: u64 = 2_840_345_392;
const EXPECTED_FINGERPRINT: &str =
    "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab";
const MANIFEST_SHA256: &str = "34cb8d48a1a2c9e6cbb8fb2481cfb73fc53d46d6f91c07655234485228e363e5";
const SOURCE_SHA256: &str = "04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7";
const TERM_BYTES: usize = 40;
const TERMS_PER_CHUNK: usize = 1024;

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
        compressed_bytes: 132_280_879,
        compressed_sha256: "4a78fccf7f49e9f25a77b2f212fb99b9beb0a6da63240567c13ae2d7754ff048",
        raw_bytes: 1_439_778_032,
        raw_sha256: "002b86f052e75f6e98eebfd27f977c5dcb7362a15d0a25d5af6642ac0cd2ecee",
        terms: 33_375_843,
    },
    AxisPin {
        name: "B.r1cs.bin.gz",
        compressed_bytes: 39_357_111,
        compressed_sha256: "8fe2d65194704b601f911099a5ed4123a2fd4f374aaefb1b1d620cc1603ca34c",
        raw_bytes: 703_804_592,
        raw_sha256: "a32c39c1e0a087172fb396a019ee3ad3ebff5b5833281ef1d72162e38cf5d565",
        terms: 14_976_507,
    },
    AxisPin {
        name: "C.r1cs.bin.gz",
        compressed_bytes: 71_201_926,
        compressed_sha256: "7e921a7eda84e389c91e2a9b6674b74c8c0dbc056ac78d9953976a95912f6d92",
        raw_bytes: 1_036_906_272,
        raw_sha256: "000b71a3433cb0b0e0ed3bb155a064314710fca5be5e26088ab5606aa588dbae",
        terms: 23_304_049,
    },
];

#[derive(Debug)]
struct Failure {
    reason: &'static str,
    axis: Option<usize>,
    row: Option<u64>,
    term: Option<u64>,
    detail: String,
}

type ScanResult<T> = Result<T, Failure>;

fn failure(
    reason: &'static str,
    axis: Option<usize>,
    row: Option<u64>,
    term: Option<u64>,
    detail: impl Into<String>,
) -> Failure {
    Failure {
        reason,
        axis,
        row,
        term,
        detail: detail.into(),
    }
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

fn metadata_identity(file: &File, axis: usize) -> ScanResult<FileIdentity> {
    let metadata = file
        .metadata()
        .map_err(|error| failure("input-metadata", Some(axis), None, None, error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(failure(
            "input-not-regular",
            Some(axis),
            None,
            None,
            "input descriptor is not a regular file",
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

fn open_and_pin(path: &Path, axis: usize, pin: AxisPin) -> ScanResult<(File, FileIdentity)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| failure("input-open", Some(axis), None, None, error.to_string()))?;
    let before = metadata_identity(&file, axis)?;
    if before.size != pin.compressed_bytes {
        return Err(failure(
            "compressed-size-pin",
            Some(axis),
            None,
            None,
            format!("expected={} actual={}", pin.compressed_bytes, before.size),
        ));
    }
    let (bytes, identity) = hash_reader(&mut file)
        .map_err(|error| failure("compressed-read", Some(axis), None, None, error.to_string()))?;
    if bytes != pin.compressed_bytes || identity != pin.compressed_sha256 {
        return Err(failure(
            "compressed-identity-pin",
            Some(axis),
            None,
            None,
            format!(
                "expected_bytes={} actual_bytes={} expected_sha256={} actual_sha256={identity}",
                pin.compressed_bytes, bytes, pin.compressed_sha256
            ),
        ));
    }
    let after = metadata_identity(&file, axis)?;
    if after != before {
        return Err(failure(
            "input-changed-during-pin",
            Some(axis),
            None,
            None,
            format!("before={before:?} after={after:?}"),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| failure("input-rewind", Some(axis), None, None, error.to_string()))?;
    Ok((file, before))
}

type DecodedFile = BufReader<GzDecoder<BufReader<File>>>;

struct RawReader {
    input: DecodedFile,
    hash: Sha256,
    bytes: u64,
    axis: usize,
}

impl RawReader {
    fn new(file: File, axis: usize) -> Self {
        let compressed = BufReader::with_capacity(65_536, file);
        let decoder = GzDecoder::new(compressed);
        Self {
            input: BufReader::with_capacity(65_536, decoder),
            hash: Sha256::new(),
            bytes: 0,
            axis,
        }
    }

    fn exact(
        &mut self,
        output: &mut [u8],
        row: Option<u64>,
        term: Option<u64>,
        label: &'static str,
    ) -> ScanResult<()> {
        self.input
            .read_exact(output)
            .map_err(|error| failure(label, Some(self.axis), row, term, error.to_string()))?;
        self.bytes = self.bytes.checked_add(output.len() as u64).ok_or_else(|| {
            failure(
                "raw-byte-overflow",
                Some(self.axis),
                row,
                term,
                "decoded byte count overflow",
            )
        })?;
        self.hash.update(output);
        Ok(())
    }

    fn count(
        &mut self,
        row: Option<u64>,
        term: Option<u64>,
        label: &'static str,
    ) -> ScanResult<(u64, [u8; 8])> {
        let mut bytes = [0_u8; 8];
        self.exact(&mut bytes, row, term, label)?;
        Ok((u64::from_le_bytes(bytes), bytes))
    }

    fn finish(mut self, pin: AxisPin, original: FileIdentity) -> ScanResult<(u64, String)> {
        let mut extra = [0_u8; 1];
        let count = self.input.read(&mut extra).map_err(|error| {
            failure(
                "gzip-crc-or-stream",
                Some(self.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if count != 0 {
            return Err(failure(
                "decoded-trailing-byte",
                Some(self.axis),
                None,
                None,
                format!("first_extra={:02x}", extra[0]),
            ));
        }
        let raw_bytes = self.bytes;
        let raw_sha256 = hex::encode(self.hash.finalize());
        if raw_bytes != pin.raw_bytes || raw_sha256 != pin.raw_sha256 {
            return Err(failure(
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
            failure(
                "compressed-eof-read",
                Some(self.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if !trailing.is_empty() {
            return Err(failure(
                "gzip-trailing-or-second-member",
                Some(self.axis),
                None,
                None,
                format!(
                    "trailing_prefix={} trailing_buffered_bytes={}",
                    hex::encode(&trailing[..trailing.len().min(16)]),
                    trailing.len()
                ),
            ));
        }
        let file = compressed.into_inner();
        let final_identity = metadata_identity(&file, self.axis)?;
        if final_identity != original {
            return Err(failure(
                "input-changed-during-scan",
                Some(self.axis),
                None,
                None,
                format!("before={original:?} after={final_identity:?}"),
            ));
        }
        Ok((raw_bytes, raw_sha256))
    }
}

fn less_than_le(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());
    for index in (0..left.len()).rev() {
        if left[index] != right[index] {
            return left[index] < right[index];
        }
    }
    false
}

fn expected_raw_bytes(terms: u64) -> ScanResult<u64> {
    80_u64
        .checked_add(
            CONSTRAINTS.checked_mul(8).ok_or_else(|| {
                failure("size-arithmetic", None, None, None, "row framing overflow")
            })?,
        )
        .and_then(|value| value.checked_add(terms.checked_mul(40)?))
        .ok_or_else(|| {
            failure(
                "size-arithmetic",
                None,
                None,
                None,
                "raw axis size overflow",
            )
        })
}

struct AxisScan {
    axis: usize,
    terms: u64,
    maximum_row_terms: u64,
    raw_bytes: u64,
    raw_sha256: String,
}

fn scan_axis(
    file: File,
    original: FileIdentity,
    axis: usize,
    pin: AxisPin,
    prime: &[u8; 32],
    fingerprint: &mut Sha256,
) -> ScanResult<AxisScan> {
    let mut raw = RawReader::new(file, axis);
    let mut magic = [0_u8; 16];
    raw.exact(&mut magic, None, None, "gzip-header-magic")?;
    if &magic != MAGIC {
        return Err(failure(
            "axis-magic",
            Some(axis),
            None,
            None,
            format!("actual={}", hex::encode(magic)),
        ));
    }
    let (encoded_axis, _) = raw.count(None, None, "gzip-header-axis")?;
    if encoded_axis != axis as u64 {
        return Err(failure(
            "axis-number",
            Some(axis),
            None,
            None,
            format!("actual={encoded_axis}"),
        ));
    }
    let mut encoded_prime = [0_u8; 32];
    raw.exact(&mut encoded_prime, None, None, "gzip-header-field")?;
    if &encoded_prime != prime {
        return Err(failure(
            "field-modulus",
            Some(axis),
            None,
            None,
            format!("actual={}", hex::encode(encoded_prime)),
        ));
    }
    for (label, expected) in [
        ("instances", INSTANCES),
        ("witnesses", WITNESSES),
        ("constraints", CONSTRAINTS),
    ] {
        let (actual, _) = raw.count(None, None, "gzip-header-shape")?;
        if actual != expected {
            return Err(failure(
                "axis-shape",
                Some(axis),
                None,
                None,
                format!("field={label} expected={expected} actual={actual}"),
            ));
        }
    }

    let mut total_terms = 0_u64;
    let mut maximum_row_terms = 0_u64;
    let mut chunk = [0_u8; TERM_BYTES * TERMS_PER_CHUNK];
    for row in 0..CONSTRAINTS {
        let (terms, encoded_terms) = raw.count(Some(row), None, "row-term-count")?;
        fingerprint.update(encoded_terms);
        if terms > u32::MAX as u64 {
            return Err(failure(
                "row-term-count-u32",
                Some(axis),
                Some(row),
                None,
                format!("terms={terms}"),
            ));
        }
        if raw.bytes > pin.raw_bytes || terms > (pin.raw_bytes - raw.bytes) / TERM_BYTES as u64 {
            return Err(failure(
                "row-exceeds-raw-frame",
                Some(axis),
                Some(row),
                None,
                format!("terms={terms} decoded_bytes={}", raw.bytes),
            ));
        }
        maximum_row_terms = maximum_row_terms.max(terms);
        total_terms = total_terms.checked_add(terms).ok_or_else(|| {
            failure(
                "term-total-overflow",
                Some(axis),
                Some(row),
                None,
                "term total overflow",
            )
        })?;
        let mut term_at = 0_u64;
        let mut previous_column = None;
        while term_at < terms {
            let in_chunk = (terms - term_at).min(TERMS_PER_CHUNK as u64) as usize;
            let byte_count = in_chunk * TERM_BYTES;
            raw.exact(
                &mut chunk[..byte_count],
                Some(row),
                Some(term_at),
                "row-term-bytes",
            )?;
            fingerprint.update(&chunk[..byte_count]);
            for (offset, encoded) in chunk[..byte_count].chunks_exact(TERM_BYTES).enumerate() {
                let term = term_at + offset as u64;
                let coefficient = &encoded[..32];
                let column = u64::from_le_bytes(encoded[32..].try_into().map_err(|_| {
                    failure(
                        "term-column-width",
                        Some(axis),
                        Some(row),
                        Some(term),
                        "column width changed",
                    )
                })?);
                if coefficient.iter().all(|byte| *byte == 0) {
                    return Err(failure(
                        "zero-coefficient",
                        Some(axis),
                        Some(row),
                        Some(term),
                        format!("coefficient={} column={column}", hex::encode(coefficient)),
                    ));
                }
                if !less_than_le(coefficient, prime) {
                    return Err(failure(
                        "noncanonical-coefficient",
                        Some(axis),
                        Some(row),
                        Some(term),
                        format!("coefficient={} column={column}", hex::encode(coefficient)),
                    ));
                }
                if column >= VARIABLES || column > u32::MAX as u64 {
                    return Err(failure(
                        "column-out-of-range",
                        Some(axis),
                        Some(row),
                        Some(term),
                        format!("coefficient={} column={column}", hex::encode(coefficient)),
                    ));
                }
                if previous_column.is_some_and(|previous| column <= previous) {
                    return Err(failure(
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
                previous_column = Some(column);
            }
            term_at += in_chunk as u64;
        }
    }
    if total_terms != pin.terms {
        return Err(failure(
            "axis-term-total",
            Some(axis),
            None,
            None,
            format!("expected={} actual={total_terms}", pin.terms),
        ));
    }
    if expected_raw_bytes(total_terms)? != pin.raw_bytes {
        return Err(failure(
            "axis-size-arithmetic",
            Some(axis),
            None,
            None,
            format!("terms={total_terms} raw_bytes={}", pin.raw_bytes),
        ));
    }
    let (raw_bytes, raw_sha256) = raw.finish(pin, original)?;
    Ok(AxisScan {
        axis,
        terms: total_terms,
        maximum_row_terms,
        raw_bytes,
        raw_sha256,
    })
}

fn checked_add(left: u64, right: u64, label: &'static str) -> ScanResult<u64> {
    left.checked_add(right)
        .ok_or_else(|| failure("size-arithmetic", None, None, None, label))
}

fn checked_mul(left: u64, right: u64, label: &'static str) -> ScanResult<u64> {
    left.checked_mul(right)
        .ok_or_else(|| failure("size-arithmetic", None, None, None, label))
}

fn sha256_path(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    Ok(hash_reader(&mut file)?.1)
}

fn run(paths: [&Path; 3], scanner_binary_sha256: &str) -> ScanResult<Value> {
    let modulus = Fr::MODULUS.to_bytes_le();
    if modulus.len() != 32 {
        return Err(failure(
            "field-width",
            None,
            None,
            None,
            format!("bytes={}", modulus.len()),
        ));
    }
    let prime: [u8; 32] = modulus.try_into().map_err(|_| {
        failure(
            "field-width",
            None,
            None,
            None,
            "BN254 scalar modulus is not 32 bytes",
        )
    })?;

    // All compressed pins are verified before the first decoder is created.
    let mut opened = Vec::with_capacity(3);
    for axis in 0..3 {
        let (file, identity) = open_and_pin(paths[axis], axis, AXES[axis])?;
        opened.push((file, identity));
    }

    let mut fingerprint = Sha256::new();
    fingerprint.update(FINGERPRINT_DOMAIN);
    for count in [INSTANCES, WITNESSES, CONSTRAINTS] {
        fingerprint.update(count.to_le_bytes());
    }
    let mut scans = Vec::with_capacity(3);
    for (axis, (file, identity)) in opened.into_iter().enumerate() {
        scans.push(scan_axis(
            file,
            identity,
            axis,
            AXES[axis],
            &prime,
            &mut fingerprint,
        )?);
    }
    let actual_fingerprint = hex::encode(fingerprint.finalize());
    if actual_fingerprint != EXPECTED_FINGERPRINT {
        return Err(failure(
            "matrix-fingerprint",
            None,
            None,
            None,
            format!("expected={EXPECTED_FINGERPRINT} actual={actual_fingerprint}"),
        ));
    }

    let total_terms = scans.iter().try_fold(0_u64, |total, scan| {
        checked_add(total, scan.terms, "term total")
    })?;
    if total_terms != EXPECTED_TOTAL_TERMS {
        return Err(failure(
            "complete-term-total",
            None,
            None,
            None,
            format!("expected={EXPECTED_TOTAL_TERMS} actual={total_terms}"),
        ));
    }
    let row_framing = checked_mul(CONSTRAINTS, 12, "constraint row framing")?;
    let term_framing = checked_mul(total_terms, 36, "constraint term framing")?;
    let constraint_section = checked_add(row_framing, term_framing, "constraint section")?;
    let wire_map = checked_mul(VARIABLES, 8, "wire map")?;
    let complete_file = checked_add(
        checked_add(112, constraint_section, "file plus constraints")?,
        wire_map,
        "file plus wire map",
    )?;
    if constraint_section != EXPECTED_CONSTRAINT_SECTION_BYTES
        || wire_map != EXPECTED_WIRE_MAP_BYTES
        || complete_file != EXPECTED_R1CS_BYTES
    {
        return Err(failure(
            "r1cs-size-freeze",
            None,
            None,
            None,
            format!(
                "constraint_section={constraint_section} wire_map={wire_map} complete_file={complete_file}"
            ),
        ));
    }

    let axes = scans
        .iter()
        .map(|scan| {
            let pin = AXES[scan.axis];
            json!({
                "axis": scan.axis,
                "file_label": pin.name,
                "compressed_bytes": pin.compressed_bytes,
                "compressed_sha256": pin.compressed_sha256,
                "compressed_pin_verified_before_decode": true,
                "raw_bytes": scan.raw_bytes,
                "raw_sha256": scan.raw_sha256,
                "single_gzip_member_crc_exact_eof": true,
                "rows": CONSTRAINTS,
                "terms": scan.terms,
                "maximum_row_terms": scan.maximum_row_terms,
                "metadata_unchanged": true,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "schema": "kpb-frozen-aggregate-r1cs-admission/v1",
        "status": "PASS",
        "classification": "READ_ONLY_FORMAT_ADMISSION_NO_R1CS_EXPORT_SETUP_ZKEY_OR_CEREMONY",
        "scanner_binary_sha256": scanner_binary_sha256,
        "frozen_manifest_sha256": MANIFEST_SHA256,
        "frozen_source_sha256": SOURCE_SHA256,
        "field_decimal": Fr::MODULUS.to_string(),
        "field_bytes": 32,
        "instances_including_one": INSTANCES,
        "witnesses": WITNESSES,
        "variables": VARIABLES,
        "constraints": CONSTRAINTS,
        "canonical_r1cs_fingerprint": actual_fingerprint,
        "axes": axes,
        "admission_predicates": {
            "regular_files_no_symlink_follow": true,
            "all_compressed_pins_verified_before_decode": true,
            "single_gzip_member_crc_and_exact_eof": true,
            "raw_size_and_sha256_exact": true,
            "axis_field_and_geometry_exact": true,
            "row_counts_fit_u32": true,
            "coefficients_canonical_and_nonzero": true,
            "columns_in_range_and_fit_u32": true,
            "columns_strictly_increasing_and_unique_per_lc": true,
            "all_rows_and_terms_consumed": true,
            "matrix_fingerprint_exact": true,
        },
        "standard_r1cs_v1_frozen_arithmetic": {
            "total_terms": total_terms,
            "row_axis_count_framing_bytes": row_framing,
            "term_framing_and_coefficient_bytes": term_framing,
            "constraint_section_bytes": constraint_section,
            "identity_wire_map_bytes": wire_map,
            "complete_file_bytes": complete_file,
        },
        "r1cs_exported": false,
        "zkey_generated": false,
        "setup_executed": false,
        "ceremony_executed": false,
        "privacy_or_financial_acceptance_claimed": false,
    }))
}

fn write_receipt(path: &Path, receipt: &Value) -> std::io::Result<()> {
    let mut encoded = serde_json::to_vec_pretty(receipt)?;
    encoded.push(b'\n');
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn failure_receipt(scanner_binary_sha256: &str, problem: &Failure) -> Value {
    json!({
        "schema": "kpb-frozen-aggregate-r1cs-admission/v1",
        "status": "REJECT",
        "classification": "FIRST_EXACT_COUNTEREXAMPLE_NO_R1CS_EXPORT_SETUP_ZKEY_OR_CEREMONY",
        "scanner_binary_sha256": scanner_binary_sha256,
        "frozen_manifest_sha256": MANIFEST_SHA256,
        "failure": {
            "reason": problem.reason,
            "axis": problem.axis,
            "row": problem.row,
            "term": problem.term,
            "detail": problem.detail,
        },
        "r1cs_exported": false,
        "zkey_generated": false,
        "setup_executed": false,
        "ceremony_executed": false,
    })
}

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() != 5 {
        eprintln!(
            "usage: {} A.r1cs.bin.gz B.r1cs.bin.gz C.r1cs.bin.gz NEW-RECEIPT.json",
            PathBuf::from(args.first().cloned().unwrap_or_default()).display()
        );
        std::process::exit(2);
    }
    let scanner_binary_sha256 = env::current_exe()
        .and_then(|path| sha256_path(&path))
        .unwrap_or_else(|error| format!("UNAVAILABLE:{error}"));
    let paths = [
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    ];
    let receipt_path = Path::new(&args[4]);
    match run(paths, &scanner_binary_sha256) {
        Ok(receipt) => {
            if let Err(error) = write_receipt(receipt_path, &receipt) {
                eprintln!("receipt-create-new-failed: {error}");
                std::process::exit(2);
            }
            println!(
                "{{\"schema\":\"kpb-frozen-aggregate-r1cs-admission-status/v1\",\"status\":\"PASS\",\"receipt\":\"{}\",\"r1cs_exported\":false,\"setup_executed\":false}}",
                receipt_path.display()
            );
        }
        Err(problem) => {
            let receipt = failure_receipt(&scanner_binary_sha256, &problem);
            if let Err(error) = write_receipt(receipt_path, &receipt) {
                eprintln!("receipt-create-new-failed: {error}");
            }
            eprintln!(
                "aggregate-admission-rejected: reason={} axis={:?} row={:?} term={:?} detail={}",
                problem.reason, problem.axis, problem.row, problem.term, problem.detail
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_size_arithmetic_is_exact() {
        let terms = AXES.iter().map(|axis| axis.terms).sum::<u64>();
        assert_eq!(terms, EXPECTED_TOTAL_TERMS);
        for axis in AXES {
            assert_eq!(expected_raw_bytes(axis.terms).unwrap(), axis.raw_bytes);
        }
        assert_eq!(
            CONSTRAINTS * 12 + terms * 36,
            EXPECTED_CONSTRAINT_SECTION_BYTES
        );
        assert_eq!(VARIABLES * 8, EXPECTED_WIRE_MAP_BYTES);
        assert_eq!(
            112 + EXPECTED_CONSTRAINT_SECTION_BYTES + EXPECTED_WIRE_MAP_BYTES,
            EXPECTED_R1CS_BYTES
        );
    }

    #[test]
    fn canonical_little_endian_comparison_rejects_zero_and_modulus() {
        let prime: [u8; 32] = Fr::MODULUS.to_bytes_le().try_into().unwrap();
        let zero = [0_u8; 32];
        let one = {
            let mut value = [0_u8; 32];
            value[0] = 1;
            value
        };
        assert!(less_than_le(&zero, &prime));
        assert!(less_than_le(&one, &prime));
        assert!(!less_than_le(&prime, &prime));
    }
}
