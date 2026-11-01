//! Production-sized, aggregate-only, descriptor-based R1CS v1 exporter.
//!
//! There is no runtime tiny/full selector. Unit tests inject small contracts
//! into private helpers; the executable embeds only `aggregate_export_plan.json`.

use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::fs::MetadataExt,
};

const PLAN_BYTES: &[u8] = include_bytes!("../aggregate_export_plan.json");
const SELF_SOURCE: &[u8] = include_bytes!("main.rs");
const CARGO_TOML: &[u8] = include_bytes!("../Cargo.toml");
const CARGO_LOCK: &[u8] = include_bytes!("../Cargo.lock");
const RUST_TOOLCHAIN: &[u8] = include_bytes!("../rust-toolchain.toml");
const VERIFIER_SOURCE: &[u8] = include_bytes!("../verify_frozen_aggregate_r1cs.py");

const AXIS_MAGIC: &[u8; 16] = b"KPI_R1CS_AXIS_V1";
const FINGERPRINT_DOMAIN: &[u8] = b"KPINAS/R1CS/v1\0";
const OUTPUT_NAME: &str = "aggregate.r1cs";
const OUTPUT_PARTIAL: &str = ".aggregate.r1cs.partial";
const RECEIPT_NAME: &str = "EXPORT-RECEIPT.json";
const RECEIPT_PARTIAL: &str = ".EXPORT-RECEIPT.json.partial";

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

fn external(code: &'static str, detail: impl std::fmt::Display) -> Problem {
    problem(code, None, None, None, detail.to_string())
}

fn checked_add(left: u64, right: u64, code: &'static str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| external(code, format!("{left}+{right}")))
}

fn checked_mul(left: u64, right: u64, code: &'static str) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| external(code, format!("{left}*{right}")))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_reader(reader: &mut impl Read) -> std::io::Result<(u64, String)> {
    let mut digest = Sha256::new();
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
        digest.update(&buffer[..count]);
    }
    Ok((bytes, hex::encode(digest.finalize())))
}

fn hash_current_executable() -> Result<(String, FileIdentity)> {
    let mut file = OpenOptions::new()
        .read(true)
        .open("/proc/self/exe")
        .map_err(|error| external("binary-open", error))?;
    let before = FileIdentity::of(&file, "binary-metadata")?;
    require_regular(before, "binary-not-regular")?;
    let (_, hash) = hash_reader(&mut file).map_err(|error| external("binary-read", error))?;
    let after = FileIdentity::of(&file, "binary-metadata")?;
    if after != before {
        return Err(external(
            "binary-changed-during-hash",
            format!("before={before:?} after={after:?}"),
        ));
    }
    Ok((hash, before))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AxisPin {
    axis: usize,
    label: String,
    compressed_bytes: u64,
    compressed_sha256: String,
    raw_bytes: u64,
    raw_sha256: String,
    terms: u64,
    maximum_row_terms: u64,
}

#[derive(Clone, Debug)]
struct Contract {
    plan_sha256: String,
    source_sha256: String,
    cargo_toml_sha256: String,
    cargo_lock_sha256: String,
    rust_toolchain_sha256: String,
    verifier_source_sha256: String,
    verifier_python_sha256: String,
    scanner_receipt_sha256: String,
    scanner_binary_sha256: String,
    frozen_manifest_sha256: String,
    frozen_source_sha256: String,
    field: [u8; 32],
    instances: u64,
    witnesses: u64,
    variables: u64,
    constraints: u64,
    public_outputs: u64,
    public_inputs: u64,
    private_inputs: u64,
    labels: u64,
    axes: [AxisPin; 3],
    matrix_fingerprint: String,
    constraint_section_bytes: u64,
    wire_map_bytes: u64,
    output_bytes: u64,
    aggregate_full_export_authorized: bool,
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| external("plan-field", field))
}

fn u64_field(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| external("plan-field", field))
}

fn false_field(value: &Value, field: &str) -> Result<()> {
    if value[field].as_bool() == Some(false) {
        Ok(())
    } else {
        Err(external("plan-authority", field))
    }
}

fn parse_contract() -> Result<Contract> {
    let plan: Value =
        serde_json::from_slice(PLAN_BYTES).map_err(|error| external("plan-json", error))?;
    if string_field(&plan, "schema")? != "kpb-frozen-aggregate-r1cs-export-plan/v1"
        || string_field(&plan, "classification")?
            != "PRODUCTION_SIZED_R1CS_CONVERSION_ONLY_NO_SETUP_OR_CEREMONY"
        || plan["materials_pending"].as_bool() != Some(false)
    {
        return Err(external(
            "plan-schema",
            "unexpected schema or pending materials",
        ));
    }
    for field in [
        "setup_authorized",
        "zkey_authorized",
        "phase1_authorized",
        "phase2_authorized",
        "ceremony_authorized",
    ] {
        false_field(&plan, field)?;
    }
    let materials = &plan["materials"];
    let geometry = &plan["geometry"];
    let layout = &plan["standard_r1cs_v1"];
    let mut field = [0_u8; 32];
    let decoded = hex::decode(string_field(&plan, "field_le_hex")?)
        .map_err(|error| external("plan-field-hex", error))?;
    if decoded.len() != field.len() {
        return Err(external("plan-field-width", decoded.len()));
    }
    field.copy_from_slice(&decoded);
    let axis_values = plan["axes"]
        .as_array()
        .ok_or_else(|| external("plan-axes", "not an array"))?;
    if axis_values.len() != 3 {
        return Err(external("plan-axes", axis_values.len()));
    }
    let mut pins = Vec::with_capacity(3);
    for (axis, value) in axis_values.iter().enumerate() {
        if u64_field(value, "axis")? != axis as u64 {
            return Err(external("plan-axis-number", axis));
        }
        pins.push(AxisPin {
            axis,
            label: string_field(value, "file_label")?.to_owned(),
            compressed_bytes: u64_field(value, "compressed_bytes")?,
            compressed_sha256: string_field(value, "compressed_sha256")?.to_owned(),
            raw_bytes: u64_field(value, "raw_bytes")?,
            raw_sha256: string_field(value, "raw_sha256")?.to_owned(),
            terms: u64_field(value, "terms")?,
            maximum_row_terms: u64_field(value, "maximum_row_terms")?,
        });
    }
    let axes: [AxisPin; 3] = pins
        .try_into()
        .map_err(|_| external("plan-axes", "wrong length"))?;
    let result = Contract {
        plan_sha256: sha256(PLAN_BYTES),
        source_sha256: string_field(materials, "exporter_source_sha256")?.to_owned(),
        cargo_toml_sha256: string_field(materials, "cargo_toml_sha256")?.to_owned(),
        cargo_lock_sha256: string_field(materials, "cargo_lock_sha256")?.to_owned(),
        rust_toolchain_sha256: string_field(materials, "rust_toolchain_sha256")?.to_owned(),
        verifier_source_sha256: string_field(materials, "verifier_source_sha256")?.to_owned(),
        verifier_python_sha256: string_field(materials, "verifier_python_sha256")?.to_owned(),
        scanner_receipt_sha256: string_field(&plan, "admission_receipt_sha256")?.to_owned(),
        scanner_binary_sha256: string_field(&plan, "scanner_binary_sha256")?.to_owned(),
        frozen_manifest_sha256: string_field(&plan, "frozen_manifest_sha256")?.to_owned(),
        frozen_source_sha256: string_field(&plan, "frozen_source_sha256")?.to_owned(),
        field,
        instances: u64_field(geometry, "instances_including_one")?,
        witnesses: u64_field(geometry, "witnesses")?,
        variables: u64_field(geometry, "variables")?,
        constraints: u64_field(geometry, "constraints")?,
        public_outputs: u64_field(geometry, "public_outputs")?,
        public_inputs: u64_field(geometry, "public_inputs")?,
        private_inputs: u64_field(geometry, "private_inputs")?,
        labels: u64_field(geometry, "labels")?,
        axes,
        matrix_fingerprint: string_field(&plan, "canonical_r1cs_fingerprint")?.to_owned(),
        constraint_section_bytes: u64_field(layout, "constraint_section_bytes")?,
        wire_map_bytes: u64_field(layout, "identity_wire_map_bytes")?,
        output_bytes: u64_field(layout, "complete_file_bytes")?,
        aggregate_full_export_authorized: plan["aggregate_full_export_authorized"]
            .as_bool()
            .ok_or_else(|| external("plan-authority", "aggregate_full_export_authorized"))?,
    };
    validate_contract(&result)?;
    Ok(result)
}

fn validate_materials(contract: &Contract) -> Result<()> {
    let actual = [
        (
            "exporter-source",
            sha256(SELF_SOURCE),
            &contract.source_sha256,
        ),
        (
            "cargo-toml",
            sha256(CARGO_TOML),
            &contract.cargo_toml_sha256,
        ),
        (
            "cargo-lock",
            sha256(CARGO_LOCK),
            &contract.cargo_lock_sha256,
        ),
        (
            "rust-toolchain",
            sha256(RUST_TOOLCHAIN),
            &contract.rust_toolchain_sha256,
        ),
        (
            "verifier-source",
            sha256(VERIFIER_SOURCE),
            &contract.verifier_source_sha256,
        ),
    ];
    for (label, actual_hash, expected) in actual {
        if actual_hash != *expected {
            return Err(external(
                "material-identity",
                format!("material={label} expected={expected} actual={actual_hash}"),
            ));
        }
    }
    Ok(())
}

fn validate_contract(contract: &Contract) -> Result<()> {
    if contract.instances != checked_add(contract.public_inputs, 1, "instance-overflow")?
        || contract.variables
            != checked_add(contract.witnesses, contract.instances, "variable-overflow")?
        || contract.private_inputs != contract.witnesses
        || contract.labels != contract.variables
    {
        return Err(external(
            "contract-geometry",
            "instance/witness split mismatch",
        ));
    }
    for value in [
        contract.variables,
        contract.constraints,
        contract.public_outputs,
        contract.public_inputs,
        contract.private_inputs,
    ] {
        u32::try_from(value).map_err(|_| external("contract-u32", value))?;
    }
    let total_terms = contract.axes.iter().try_fold(0_u64, |sum, pin| {
        checked_add(sum, pin.terms, "total-term-overflow")
    })?;
    let count_bytes = checked_mul(
        checked_mul(contract.constraints, 3, "row-axis-overflow")?,
        4,
        "row-count-byte-overflow",
    )?;
    let term_bytes = checked_mul(total_terms, 36, "term-byte-overflow")?;
    let constraint_bytes = checked_add(count_bytes, term_bytes, "constraint-byte-overflow")?;
    let map_bytes = checked_mul(contract.variables, 8, "map-byte-overflow")?;
    let output_bytes = checked_add(
        checked_add(112, constraint_bytes, "output-byte-overflow")?,
        map_bytes,
        "output-byte-overflow",
    )?;
    if constraint_bytes != contract.constraint_section_bytes
        || map_bytes != contract.wire_map_bytes
        || output_bytes != contract.output_bytes
    {
        return Err(external(
            "contract-layout",
            format!("constraints={constraint_bytes} map={map_bytes} output={output_bytes}"),
        ));
    }
    for pin in &contract.axes {
        let row_bytes = checked_mul(contract.constraints, 8, "raw-row-byte-overflow")?;
        let term_bytes = checked_mul(pin.terms, 40, "raw-term-byte-overflow")?;
        let raw_bytes = checked_add(
            checked_add(80, row_bytes, "raw-byte-overflow")?,
            term_bytes,
            "raw-byte-overflow",
        )?;
        if raw_bytes != pin.raw_bytes {
            return Err(problem(
                "contract-raw-layout",
                Some(pin.axis),
                None,
                None,
                format!("expected={} actual={raw_bytes}", pin.raw_bytes),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    owner: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn of(file: &File, code: &'static str) -> Result<Self> {
        let metadata = file.metadata().map_err(|error| external(code, error))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn json(self) -> Value {
        json!({
            "device": self.device,
            "inode": self.inode,
            "bytes": self.size,
            "mode": format!("{:04o}", self.mode & 0o7777),
            "owner_uid": self.owner,
            "mtime_seconds": self.modified_seconds,
            "mtime_nanoseconds": self.modified_nanoseconds,
            "ctime_seconds": self.changed_seconds,
            "ctime_nanoseconds": self.changed_nanoseconds,
        })
    }
}

fn duplicate_fd(raw: RawFd, code: &'static str) -> Result<File> {
    if raw <= 2 {
        return Err(external(code, "descriptor must be greater than 2"));
    }
    // SAFETY: fcntl duplicates a caller-owned descriptor; the returned descriptor is owned here.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(external(code, std::io::Error::last_os_error()));
    }
    // SAFETY: duplicate is a new valid owned descriptor on the success path above.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

fn require_regular(identity: FileIdentity, code: &'static str) -> Result<()> {
    if identity.mode & libc::S_IFMT != libc::S_IFREG {
        Err(external(code, format!("mode={:o}", identity.mode)))
    } else {
        Ok(())
    }
}

fn require_directory(file: &File) -> Result<FileIdentity> {
    let identity = FileIdentity::of(file, "output-directory-metadata")?;
    if identity.mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(external(
            "output-directory-type",
            format!("mode={:o}", identity.mode),
        ));
    }
    // Output confidentiality must not depend on the process umask.
    if identity.mode & 0o077 != 0 {
        return Err(external(
            "output-directory-not-private",
            format!("mode={:04o}", identity.mode & 0o7777),
        ));
    }
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if identity.owner != effective_uid {
        return Err(external(
            "output-directory-owner",
            format!("expected={effective_uid} actual={}", identity.owner),
        ));
    }
    require_empty_directory(file.as_raw_fd())?;
    Ok(identity)
}

fn require_empty_directory(directory_fd: RawFd) -> Result<()> {
    // SAFETY: fcntl duplicates the valid directory descriptor.
    let duplicate = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(external(
            "output-directory-dup",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fdopendir takes ownership of duplicate on success.
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        // SAFETY: duplicate is still owned here when fdopendir fails.
        unsafe { libc::close(duplicate) };
        return Err(external(
            "output-directory-open",
            std::io::Error::last_os_error(),
        ));
    }
    let mut found = None;
    loop {
        // SAFETY: directory is a live DIR pointer until closed below.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated for a valid dirent.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            found = Some(String::from_utf8_lossy(name).into_owned());
            break;
        }
    }
    // SAFETY: directory is a live DIR pointer and closed exactly once.
    let close_result = unsafe { libc::closedir(directory) };
    if close_result != 0 {
        return Err(external(
            "output-directory-close",
            std::io::Error::last_os_error(),
        ));
    }
    if let Some(name) = found {
        return Err(external("output-directory-not-empty", name));
    }
    Ok(())
}

fn parse_fd(value: &str, label: &'static str) -> Result<RawFd> {
    let parsed = value
        .parse::<i32>()
        .map_err(|error| external("descriptor-argument", format!("{label}: {error}")))?;
    if parsed <= 2 {
        return Err(external(
            "descriptor-argument",
            format!("{label}: {parsed}"),
        ));
    }
    Ok(parsed)
}

fn pin_compressed(file: &mut File, original: FileIdentity, pin: &AxisPin) -> Result<()> {
    require_regular(original, "axis-not-regular")?;
    if original.size != pin.compressed_bytes {
        return Err(problem(
            "compressed-size-pin",
            Some(pin.axis),
            None,
            None,
            format!("expected={} actual={}", pin.compressed_bytes, original.size),
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        problem(
            "compressed-rewind",
            Some(pin.axis),
            None,
            None,
            error.to_string(),
        )
    })?;
    let (bytes, hash) = hash_reader(file).map_err(|error| {
        problem(
            "compressed-read",
            Some(pin.axis),
            None,
            None,
            error.to_string(),
        )
    })?;
    let after = FileIdentity::of(file, "axis-metadata")?;
    if after != original {
        return Err(problem(
            "axis-changed-during-pin",
            Some(pin.axis),
            None,
            None,
            format!("before={original:?} after={after:?}"),
        ));
    }
    if bytes != pin.compressed_bytes || hash != pin.compressed_sha256 {
        return Err(problem(
            "compressed-identity-pin",
            Some(pin.axis),
            None,
            None,
            format!("bytes={bytes} sha256={hash}"),
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        problem(
            "compressed-rewind",
            Some(pin.axis),
            None,
            None,
            error.to_string(),
        )
    })?;
    Ok(())
}

type Decoder = BufReader<GzDecoder<BufReader<File>>>;

struct AxisCursor<'a> {
    input: Decoder,
    contract: &'a Contract,
    pin: &'a AxisPin,
    original: FileIdentity,
    raw_hash: Sha256,
    raw_bytes: u64,
    next_row: u64,
    remaining_terms: u64,
    next_term: u64,
    previous_column: Option<u64>,
    total_terms: u64,
    maximum_row_terms: u64,
}

#[derive(Clone)]
struct Term {
    coefficient: [u8; 32],
    column: u32,
    transport: [u8; 40],
}

impl<'a> AxisCursor<'a> {
    fn new(mut file: File, contract: &'a Contract, pin: &'a AxisPin) -> Result<Self> {
        let original = FileIdentity::of(&file, "axis-metadata")?;
        pin_compressed(&mut file, original, pin)?;
        let compressed = BufReader::with_capacity(65_536, file);
        let mut result = Self {
            input: BufReader::with_capacity(65_536, GzDecoder::new(compressed)),
            contract,
            pin,
            original,
            raw_hash: Sha256::new(),
            raw_bytes: 0,
            next_row: 0,
            remaining_terms: 0,
            next_term: 0,
            previous_column: None,
            total_terms: 0,
            maximum_row_terms: 0,
        };
        let mut magic = [0_u8; 16];
        result.exact(&mut magic, None, None, "axis-header")?;
        if &magic != AXIS_MAGIC {
            return Err(problem(
                "axis-magic",
                Some(pin.axis),
                None,
                None,
                hex::encode(magic),
            ));
        }
        if result.u64(None, None, "axis-number")? != pin.axis as u64 {
            return Err(problem(
                "axis-number",
                Some(pin.axis),
                None,
                None,
                "mismatch",
            ));
        }
        let mut field = [0_u8; 32];
        result.exact(&mut field, None, None, "axis-field")?;
        if field != contract.field {
            return Err(problem(
                "axis-field",
                Some(pin.axis),
                None,
                None,
                hex::encode(field),
            ));
        }
        let geometry = [contract.instances, contract.witnesses, contract.constraints];
        for expected in geometry {
            let actual = result.u64(None, None, "axis-geometry")?;
            if actual != expected {
                return Err(problem(
                    "axis-geometry",
                    Some(pin.axis),
                    None,
                    None,
                    format!("expected={expected} actual={actual}"),
                ));
            }
        }
        Ok(result)
    }

    fn exact(
        &mut self,
        bytes: &mut [u8],
        row: Option<u64>,
        term: Option<u64>,
        code: &'static str,
    ) -> Result<()> {
        self.input
            .read_exact(bytes)
            .map_err(|error| problem(code, Some(self.pin.axis), row, term, error.to_string()))?;
        self.raw_bytes = checked_add(self.raw_bytes, bytes.len() as u64, "raw-byte-overflow")?;
        self.raw_hash.update(bytes);
        Ok(())
    }

    fn u64(&mut self, row: Option<u64>, term: Option<u64>, code: &'static str) -> Result<u64> {
        let mut bytes = [0_u8; 8];
        self.exact(&mut bytes, row, term, code)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn start_row(&mut self, row: u64) -> Result<(u32, [u8; 8])> {
        if row != self.next_row || self.remaining_terms != 0 || row >= self.contract.constraints {
            return Err(problem(
                "row-state",
                Some(self.pin.axis),
                Some(row),
                None,
                "invalid state",
            ));
        }
        let mut encoded = [0_u8; 8];
        self.exact(&mut encoded, Some(row), None, "row-count")?;
        let count = u64::from_le_bytes(encoded);
        let narrowed = u32::try_from(count).map_err(|_| {
            problem(
                "row-count-u32",
                Some(self.pin.axis),
                Some(row),
                None,
                count.to_string(),
            )
        })?;
        if self.raw_bytes > self.pin.raw_bytes || count > (self.pin.raw_bytes - self.raw_bytes) / 40
        {
            return Err(problem(
                "row-exceeds-raw-frame",
                Some(self.pin.axis),
                Some(row),
                None,
                count.to_string(),
            ));
        }
        self.total_terms = checked_add(self.total_terms, count, "term-total-overflow")?;
        self.maximum_row_terms = self.maximum_row_terms.max(count);
        self.remaining_terms = count;
        self.next_term = 0;
        self.previous_column = None;
        self.next_row += 1;
        Ok((narrowed, encoded))
    }

    fn next_term(&mut self, row: u64) -> Result<Term> {
        if self.remaining_terms == 0 {
            return Err(problem(
                "term-state",
                Some(self.pin.axis),
                Some(row),
                Some(self.next_term),
                "no remaining term",
            ));
        }
        let term_index = self.next_term;
        let mut transport = [0_u8; 40];
        self.exact(&mut transport, Some(row), Some(term_index), "term-bytes")?;
        let mut coefficient = [0_u8; 32];
        coefficient.copy_from_slice(&transport[..32]);
        let column = u64::from_le_bytes(transport[32..].try_into().map_err(|_| {
            problem(
                "term-column",
                Some(self.pin.axis),
                Some(row),
                Some(term_index),
                "width",
            )
        })?);
        let narrowed = admit_term(
            self.pin.axis,
            row,
            term_index,
            &coefficient,
            column,
            self.previous_column,
            &self.contract.field,
            self.contract.variables,
        )?;
        self.previous_column = Some(column);
        self.remaining_terms -= 1;
        self.next_term += 1;
        Ok(Term {
            coefficient,
            column: narrowed,
            transport,
        })
    }

    fn finish(mut self) -> Result<(u64, u64)> {
        if self.next_row != self.contract.constraints
            || self.remaining_terms != 0
            || self.total_terms != self.pin.terms
            || self.maximum_row_terms != self.pin.maximum_row_terms
        {
            return Err(problem(
                "axis-totals",
                Some(self.pin.axis),
                None,
                None,
                format!(
                    "rows={} terms={} maximum={}",
                    self.next_row, self.total_terms, self.maximum_row_terms
                ),
            ));
        }
        let mut extra = [0_u8; 1];
        let decoded_extra = self.input.read(&mut extra).map_err(|error| {
            problem(
                "gzip-crc-or-stream",
                Some(self.pin.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if decoded_extra != 0 {
            return Err(problem(
                "decoded-trailing-byte",
                Some(self.pin.axis),
                None,
                None,
                format!("{:02x}", extra[0]),
            ));
        }
        let raw_hash = hex::encode(self.raw_hash.finalize());
        if self.raw_bytes != self.pin.raw_bytes || raw_hash != self.pin.raw_sha256 {
            return Err(problem(
                "raw-identity-pin",
                Some(self.pin.axis),
                None,
                None,
                format!("bytes={} sha256={raw_hash}", self.raw_bytes),
            ));
        }
        let decoder = self.input.into_inner();
        let mut compressed = decoder.into_inner();
        let trailing = compressed.fill_buf().map_err(|error| {
            problem(
                "compressed-eof",
                Some(self.pin.axis),
                None,
                None,
                error.to_string(),
            )
        })?;
        if !trailing.is_empty() {
            return Err(problem(
                "gzip-trailing-or-second-member",
                Some(self.pin.axis),
                None,
                None,
                hex::encode(&trailing[..trailing.len().min(16)]),
            ));
        }
        let file = compressed.into_inner();
        let final_identity = FileIdentity::of(&file, "axis-metadata")?;
        if final_identity != self.original {
            return Err(problem(
                "axis-changed-during-scan",
                Some(self.pin.axis),
                None,
                None,
                format!("before={:?} after={final_identity:?}", self.original),
            ));
        }
        Ok((self.total_terms, self.maximum_row_terms))
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

#[allow(clippy::too_many_arguments)]
fn admit_term(
    axis: usize,
    row: u64,
    term: u64,
    coefficient: &[u8; 32],
    column: u64,
    previous_column: Option<u64>,
    field: &[u8; 32],
    variables: u64,
) -> Result<u32> {
    if coefficient.iter().all(|byte| *byte == 0) {
        return Err(problem(
            "zero-coefficient",
            Some(axis),
            Some(row),
            Some(term),
            column.to_string(),
        ));
    }
    if !less_than_le(coefficient, field) {
        return Err(problem(
            "noncanonical-coefficient",
            Some(axis),
            Some(row),
            Some(term),
            column.to_string(),
        ));
    }
    if column >= variables {
        return Err(problem(
            "column-out-of-range",
            Some(axis),
            Some(row),
            Some(term),
            column.to_string(),
        ));
    }
    if previous_column.is_some_and(|previous| column <= previous) {
        return Err(problem(
            "duplicate-or-reordered-column",
            Some(axis),
            Some(row),
            Some(term),
            format!("previous={previous_column:?} column={column}"),
        ));
    }
    u32::try_from(column).map_err(|_| {
        problem(
            "column-u32",
            Some(axis),
            Some(row),
            Some(term),
            column.to_string(),
        )
    })
}

fn clone_axes(files: &[File; 3]) -> Result<[File; 3]> {
    let clones = files
        .iter()
        .map(|file| {
            file.try_clone()
                .map_err(|error| external("axis-dup", error))
        })
        .collect::<Result<Vec<_>>>()?;
    clones
        .try_into()
        .map_err(|_| external("axis-dup", "wrong count"))
}

fn scan_all(contract: &Contract, files: [File; 3]) -> Result<Vec<(u64, u64)>> {
    let mut fingerprint = Sha256::new();
    fingerprint.update(FINGERPRINT_DOMAIN);
    for count in [contract.instances, contract.witnesses, contract.constraints] {
        fingerprint.update(count.to_le_bytes());
    }
    let mut stats = Vec::with_capacity(3);
    for (axis, file) in files.into_iter().enumerate() {
        let mut cursor = AxisCursor::new(file, contract, &contract.axes[axis])?;
        for row in 0..contract.constraints {
            let (count, encoded) = cursor.start_row(row)?;
            fingerprint.update(encoded);
            for _ in 0..count {
                fingerprint.update(cursor.next_term(row)?.transport);
            }
        }
        stats.push(cursor.finish()?);
    }
    let actual = hex::encode(fingerprint.finalize());
    if actual != contract.matrix_fingerprint {
        return Err(external(
            "matrix-fingerprint",
            format!("expected={} actual={actual}", contract.matrix_fingerprint),
        ));
    }
    Ok(stats)
}

struct HashedWriter<W: Write> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

type R1csWriteResult = (File, u64, String, Vec<(u64, u64)>);

impl<W: Write> HashedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner
            .write_all(bytes)
            .map_err(|error| external("output-write", error))?;
        self.digest.update(bytes);
        self.bytes = checked_add(self.bytes, bytes.len() as u64, "output-byte-overflow")?;
        Ok(())
    }

    fn u32(&mut self, value: u64) -> Result<()> {
        let narrowed = u32::try_from(value).map_err(|_| external("output-u32", value))?;
        self.write(&narrowed.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<()> {
        self.write(&value.to_le_bytes())
    }

    fn finish(mut self) -> Result<(W, u64, String)> {
        self.inner
            .flush()
            .map_err(|error| external("output-flush", error))?;
        Ok((self.inner, self.bytes, hex::encode(self.digest.finalize())))
    }
}

fn write_r1cs(contract: &Contract, files: [File; 3], file: File) -> Result<R1csWriteResult> {
    let mut cursors = files
        .into_iter()
        .enumerate()
        .map(|(axis, source)| AxisCursor::new(source, contract, &contract.axes[axis]))
        .collect::<Result<Vec<_>>>()?;
    let mut output = HashedWriter::new(BufWriter::with_capacity(65_536, file));
    output.write(b"r1cs")?;
    output.u32(1)?;
    output.u32(3)?;
    output.u32(1)?;
    output.u64(64)?;
    output.u32(32)?;
    output.write(&contract.field)?;
    output.u32(contract.variables)?;
    output.u32(contract.public_outputs)?;
    output.u32(contract.public_inputs)?;
    output.u32(contract.private_inputs)?;
    output.u64(contract.labels)?;
    output.u32(contract.constraints)?;
    output.u32(2)?;
    output.u64(contract.constraint_section_bytes)?;
    let constraint_start = output.bytes;
    for row in 0..contract.constraints {
        for cursor in &mut cursors {
            let (count, _) = cursor.start_row(row)?;
            output.u32(count as u64)?;
            for _ in 0..count {
                let term = cursor.next_term(row)?;
                output.u32(term.column as u64)?;
                output.write(&term.coefficient)?;
            }
        }
    }
    if output.bytes - constraint_start != contract.constraint_section_bytes {
        return Err(external(
            "constraint-section-size",
            output.bytes - constraint_start,
        ));
    }
    output.u32(3)?;
    output.u64(contract.wire_map_bytes)?;
    let map_start = output.bytes;
    for wire in 0..contract.variables {
        output.u64(wire)?;
    }
    if output.bytes - map_start != contract.wire_map_bytes {
        return Err(external("wire-map-size", output.bytes - map_start));
    }
    let (buffered, bytes, hash) = output.finish()?;
    if bytes != contract.output_bytes {
        return Err(external(
            "output-size",
            format!("expected={} actual={bytes}", contract.output_bytes),
        ));
    }
    buffered
        .get_ref()
        .sync_all()
        .map_err(|error| external("output-fsync", error))?;
    let file = buffered
        .into_inner()
        .map_err(|error| external("output-finalize", error))?;
    let stats = cursors
        .into_iter()
        .map(AxisCursor::finish)
        .collect::<Result<Vec<_>>>()?;
    Ok((file, bytes, hash, stats))
}

fn c_name(value: &str) -> Result<CString> {
    CString::new(value).map_err(|error| external("output-name", error))
}

fn openat_create(directory_fd: RawFd, name: &str) -> Result<File> {
    let name = c_name(name)?;
    // SAFETY: directory_fd is valid and name is NUL-terminated; returned fd is owned below.
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(external(
            "output-create-new",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fd is a new valid owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn publish_create_new(directory_fd: RawFd, partial: &str, final_name: &str) -> Result<()> {
    let partial = c_name(partial)?;
    let final_name = c_name(final_name)?;
    // SAFETY: both names and directory descriptors are valid.
    let linked = unsafe {
        libc::linkat(
            directory_fd,
            partial.as_ptr(),
            directory_fd,
            final_name.as_ptr(),
            0,
        )
    };
    if linked != 0 {
        return Err(external(
            "publish-create-new",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: partial is a valid name relative to directory_fd.
    let unlinked = unsafe { libc::unlinkat(directory_fd, partial.as_ptr(), 0) };
    if unlinked != 0 {
        return Err(external(
            "publish-unlink-partial",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fsync accepts a live directory descriptor.
    if unsafe { libc::fsync(directory_fd) } != 0 {
        return Err(external(
            "output-directory-fsync",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn read_small_fd(
    mut file: File,
    maximum: u64,
    code: &'static str,
) -> Result<(Vec<u8>, FileIdentity)> {
    let before = FileIdentity::of(&file, code)?;
    require_regular(before, code)?;
    if before.size > maximum {
        return Err(external(code, format!("too large: {}", before.size)));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| external(code, error))?;
    let mut bytes = Vec::with_capacity(before.size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| external(code, error))?;
    let after = FileIdentity::of(&file, code)?;
    if after != before || bytes.len() as u64 != before.size {
        return Err(external(code, "identity changed while reading"));
    }
    Ok((bytes, before))
}

fn validate_admission_receipt(contract: &Contract, file: File) -> Result<(String, FileIdentity)> {
    let (bytes, identity) = read_small_fd(file, 64 * 1024, "admission-receipt")?;
    let hash = sha256(&bytes);
    if hash != contract.scanner_receipt_sha256 {
        return Err(external(
            "admission-receipt-identity",
            format!("expected={} actual={hash}", contract.scanner_receipt_sha256),
        ));
    }
    let receipt: Value = serde_json::from_slice(&bytes)
        .map_err(|error| external("admission-receipt-json", error))?;
    let exact = receipt["schema"].as_str() == Some("kpb-frozen-aggregate-r1cs-admission/v1")
        && receipt["status"].as_str() == Some("PASS")
        && receipt["canonical_r1cs_fingerprint"].as_str()
            == Some(contract.matrix_fingerprint.as_str())
        && receipt["scanner_binary_sha256"].as_str()
            == Some(contract.scanner_binary_sha256.as_str())
        && receipt["frozen_manifest_sha256"].as_str()
            == Some(contract.frozen_manifest_sha256.as_str())
        && receipt["frozen_source_sha256"].as_str() == Some(contract.frozen_source_sha256.as_str())
        && receipt["r1cs_exported"].as_bool() == Some(false)
        && receipt["zkey_generated"].as_bool() == Some(false)
        && receipt["setup_executed"].as_bool() == Some(false)
        && receipt["ceremony_executed"].as_bool() == Some(false);
    if !exact {
        return Err(external(
            "admission-receipt-fields",
            "required fields changed",
        ));
    }
    Ok((hash, identity))
}

fn initial_axis_identities(files: &[File; 3], contract: &Contract) -> Result<[FileIdentity; 3]> {
    let mut identities = Vec::with_capacity(3);
    for (axis, file) in files.iter().enumerate() {
        let identity = FileIdentity::of(file, "axis-metadata")?;
        require_regular(identity, "axis-not-regular")?;
        if identity.size != contract.axes[axis].compressed_bytes {
            return Err(problem(
                "compressed-size-pin",
                Some(axis),
                None,
                None,
                format!(
                    "expected={} actual={}",
                    contract.axes[axis].compressed_bytes, identity.size
                ),
            ));
        }
        identities.push(identity);
    }
    for left in 0..identities.len() {
        for right in left + 1..identities.len() {
            if identities[left].device == identities[right].device
                && identities[left].inode == identities[right].inode
            {
                return Err(external(
                    "axis-descriptor-reuse",
                    format!("{left} and {right}"),
                ));
            }
        }
    }
    identities
        .try_into()
        .map_err(|_| external("axis-identities", "wrong count"))
}

fn available_bytes(directory_fd: RawFd) -> Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: value points to writable memory and directory_fd is live.
    if unsafe { libc::fstatvfs(directory_fd, value.as_mut_ptr()) } != 0 {
        return Err(external("disk-preflight", std::io::Error::last_os_error()));
    }
    // SAFETY: fstatvfs initialized value on its success path.
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or_else(|| external("disk-preflight", "available-byte overflow"))
}

fn json_axis_pins(contract: &Contract, identities: [FileIdentity; 3]) -> Value {
    Value::Array(
        contract
            .axes
            .iter()
            .enumerate()
            .map(|(axis, pin)| {
                json!({
                    "axis": pin.axis,
                    "file_label": pin.label,
                    "descriptor_identity": identities[axis].json(),
                    "compressed_bytes": pin.compressed_bytes,
                    "compressed_sha256": pin.compressed_sha256,
                    "raw_bytes": pin.raw_bytes,
                    "raw_sha256": pin.raw_sha256,
                    "terms": pin.terms,
                    "maximum_row_terms": pin.maximum_row_terms,
                })
            })
            .collect(),
    )
}

fn preflight(
    contract: &Contract,
    scanner: File,
    axes: &[File; 3],
    output_directory: &File,
) -> Result<Value> {
    validate_materials(contract)?;
    let (admission_hash, admission_identity) = validate_admission_receipt(contract, scanner)?;
    let identities = initial_axis_identities(axes, contract)?;
    let directory_identity = require_directory(output_directory)?;
    let available = available_bytes(output_directory.as_raw_fd())?;
    let receipt_reserve = 1_048_576_u64;
    let required = checked_add(
        contract.output_bytes,
        receipt_reserve,
        "disk-required-overflow",
    )?;
    if available < required {
        return Err(external(
            "disk-preflight",
            format!("required={required} available={available}"),
        ));
    }
    Ok(json!({
        "schema": "kpb-frozen-aggregate-r1cs-export-preflight/v1",
        "status": "PASS",
        "classification": "NO_R1CS_EXPORT_NO_SETUP_OR_CEREMONY",
        "plan_sha256": contract.plan_sha256,
        "exporter_source_sha256": contract.source_sha256,
        "cargo_toml_sha256": contract.cargo_toml_sha256,
        "cargo_lock_sha256": contract.cargo_lock_sha256,
        "rust_toolchain_sha256": contract.rust_toolchain_sha256,
        "expected_verifier_source_sha256": contract.verifier_source_sha256,
        "expected_verifier_python_sha256": contract.verifier_python_sha256,
        "admission_receipt_sha256": admission_hash,
        "admission_receipt_descriptor_identity": admission_identity.json(),
        "axes": json_axis_pins(contract, identities),
        "output_directory_identity": directory_identity.json(),
        "exact_output_bytes": contract.output_bytes,
        "receipt_reserve_bytes": receipt_reserve,
        "required_available_bytes": required,
        "actual_available_bytes": available,
        "aggregate_full_export_authorized": contract.aggregate_full_export_authorized,
        "r1cs_exported": false,
        "zkey_generated": false,
        "setup_executed": false,
        "phase1_executed": false,
        "phase2_executed": false,
        "ceremony_executed": false,
    }))
}

fn write_receipt(directory_fd: RawFd, receipt: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|error| external("export-receipt-json", error))?;
    bytes.push(b'\n');
    let mut file = openat_create(directory_fd, RECEIPT_PARTIAL)?;
    file.write_all(&bytes)
        .map_err(|error| external("export-receipt-write", error))?;
    file.sync_all()
        .map_err(|error| external("export-receipt-fsync", error))?;
    drop(file);
    publish_create_new(directory_fd, RECEIPT_PARTIAL, RECEIPT_NAME)
}

fn export_with_hook<F: FnOnce()>(
    contract: &Contract,
    scanner: File,
    axes: [File; 3],
    output_directory: File,
    before_second_pass: F,
) -> Result<Value> {
    if !contract.aggregate_full_export_authorized {
        return Err(external(
            "aggregate-export-not-authorized",
            "embedded plan is preflight-only",
        ));
    }
    let preflight_receipt = preflight(contract, scanner, &axes, &output_directory)?;
    let identities = initial_axis_identities(&axes, contract)?;
    let pass_one = scan_all(contract, clone_axes(&axes)?)?;
    before_second_pass();
    // Every pin is rechecked before an output inode exists.
    let second_files = clone_axes(&axes)?;
    for (axis, mut file) in clone_axes(&axes)?.into_iter().enumerate() {
        pin_compressed(&mut file, identities[axis], &contract.axes[axis])?;
    }
    let output_partial = openat_create(output_directory.as_raw_fd(), OUTPUT_PARTIAL)?;
    let (_output_file, bytes, hash, pass_two) = write_r1cs(contract, second_files, output_partial)?;
    if pass_one != pass_two {
        return Err(external(
            "pass-substitution",
            format!("pass_one={pass_one:?} pass_two={pass_two:?}"),
        ));
    }
    publish_create_new(output_directory.as_raw_fd(), OUTPUT_PARTIAL, OUTPUT_NAME)?;
    let (binary_sha256, binary_identity) = hash_current_executable()?;
    let receipt = json!({
        "schema": "kpb-frozen-aggregate-r1cs-export-receipt/v1",
        "status": "PASS",
        "classification": "PRODUCTION_SIZED_R1CS_CONVERSION_ONLY_NO_SETUP_OR_CEREMONY",
        "plan_sha256": contract.plan_sha256,
        "exporter_source_sha256": contract.source_sha256,
        "exporter_binary_sha256": binary_sha256,
        "exporter_binary_descriptor_identity": binary_identity.json(),
        "cargo_toml_sha256": contract.cargo_toml_sha256,
        "cargo_lock_sha256": contract.cargo_lock_sha256,
        "rust_toolchain_sha256": contract.rust_toolchain_sha256,
        "expected_verifier_source_sha256": contract.verifier_source_sha256,
        "expected_verifier_python_sha256": contract.verifier_python_sha256,
        "admission_receipt_sha256": contract.scanner_receipt_sha256,
        "canonical_r1cs_fingerprint": contract.matrix_fingerprint,
        "axes": json_axis_pins(contract, identities),
        "preflight": preflight_receipt,
        "output": {
            "file": OUTPUT_NAME,
            "bytes": bytes,
            "sha256": hash,
            "section_order": [1, 2, 3],
            "constraint_section_bytes": contract.constraint_section_bytes,
            "identity_wire_map_bytes": contract.wire_map_bytes,
            "mode": "0600",
            "create_new_atomic_publish": true,
            "fsync_before_publish": true,
        },
        "independent_verifier_passed": false,
        "r1cs_full_aggregate_exported": true,
        "zkey_generated": false,
        "setup_executed": false,
        "phase1_executed": false,
        "phase2_executed": false,
        "ceremony_executed": false,
    });
    write_receipt(output_directory.as_raw_fd(), &receipt)?;
    Ok(receipt)
}

fn usage(program: &str) {
    eprintln!(
        "usage: {program} preflight|export ADMISSION_RECEIPT_FD A_FD B_FD C_FD PRIVATE_EMPTY_OUTPUT_DIRECTORY_FD"
    );
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 7 || (args[1] != "preflight" && args[1] != "export") {
        usage(
            args.first()
                .map(String::as_str)
                .unwrap_or("kpb-frozen-aggregate-r1cs-export"),
        );
        std::process::exit(2);
    }
    let result = (|| -> Result<Value> {
        let descriptors = [
            parse_fd(&args[2], "admission")?,
            parse_fd(&args[3], "A")?,
            parse_fd(&args[4], "B")?,
            parse_fd(&args[5], "C")?,
            parse_fd(&args[6], "output-directory")?,
        ];
        for left in 0..descriptors.len() {
            for right in left + 1..descriptors.len() {
                if descriptors[left] == descriptors[right] {
                    return Err(external("descriptor-reuse", format!("{left} and {right}")));
                }
            }
        }
        let scanner = duplicate_fd(descriptors[0], "admission-descriptor")?;
        let axes = [
            duplicate_fd(descriptors[1], "axis-descriptor")?,
            duplicate_fd(descriptors[2], "axis-descriptor")?,
            duplicate_fd(descriptors[3], "axis-descriptor")?,
        ];
        let output_directory = duplicate_fd(descriptors[4], "output-directory-descriptor")?;
        let contract = parse_contract()?;
        if args[1] == "preflight" {
            preflight(&contract, scanner, &axes, &output_directory)
        } else {
            export_with_hook(&contract, scanner, axes, output_directory, || {})
        }
    })();
    match result {
        Ok(value) => println!(
            "{}",
            serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned())
        ),
        Err(error) => {
            eprintln!(
                "frozen-aggregate-r1cs-rejected: code={} axis={:?} row={:?} term={:?} detail={}",
                error.code, error.axis, error.row, error.term, error.detail
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{
        fs, io,
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "kpb-aggregate-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temp directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("private temp directory");
        path
    }

    fn tiny_axis(field: [u8; 32], axis: usize) -> (Vec<u8>, AxisPin) {
        let mut raw = Vec::new();
        raw.extend_from_slice(AXIS_MAGIC);
        raw.extend_from_slice(&(axis as u64).to_le_bytes());
        raw.extend_from_slice(&field);
        for count in [1_u64, 1, 1] {
            raw.extend_from_slice(&count.to_le_bytes());
        }
        raw.extend_from_slice(&1_u64.to_le_bytes());
        let mut coefficient = [0_u8; 32];
        coefficient[0] = 1;
        raw.extend_from_slice(&coefficient);
        raw.extend_from_slice(&1_u64.to_le_bytes());
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&raw).expect("gzip input");
        let compressed = encoder.finish().expect("gzip finish");
        let pin = AxisPin {
            axis,
            label: format!("{axis}.gz"),
            compressed_bytes: compressed.len() as u64,
            compressed_sha256: sha256(&compressed),
            raw_bytes: raw.len() as u64,
            raw_sha256: sha256(&raw),
            terms: 1,
            maximum_row_terms: 1,
        };
        (compressed, pin)
    }

    fn tiny_contract() -> (Contract, [Vec<u8>; 3]) {
        let production = parse_contract().expect("production contract");
        let generated = [
            tiny_axis(production.field, 0),
            tiny_axis(production.field, 1),
            tiny_axis(production.field, 2),
        ];
        let mut fingerprint = Sha256::new();
        fingerprint.update(FINGERPRINT_DOMAIN);
        for count in [1_u64, 1, 1] {
            fingerprint.update(count.to_le_bytes());
        }
        let mut coefficient = [0_u8; 32];
        coefficient[0] = 1;
        for _ in 0..3 {
            fingerprint.update(1_u64.to_le_bytes());
            fingerprint.update(coefficient);
            fingerprint.update(1_u64.to_le_bytes());
        }
        let contract = Contract {
            instances: 1,
            witnesses: 1,
            variables: 2,
            constraints: 1,
            public_outputs: 0,
            public_inputs: 0,
            private_inputs: 1,
            labels: 2,
            axes: [
                generated[0].1.clone(),
                generated[1].1.clone(),
                generated[2].1.clone(),
            ],
            matrix_fingerprint: hex::encode(fingerprint.finalize()),
            constraint_section_bytes: 120,
            wire_map_bytes: 16,
            output_bytes: 248,
            aggregate_full_export_authorized: true,
            ..production
        };
        validate_contract(&contract).expect("tiny contract");
        (
            contract,
            [
                generated[0].0.clone(),
                generated[1].0.clone(),
                generated[2].0.clone(),
            ],
        )
    }

    fn consume_axis(file: File, contract: &Contract, pin: &AxisPin) -> Result<()> {
        let mut cursor = AxisCursor::new(file, contract, pin)?;
        let (count, _) = cursor.start_row(0)?;
        for _ in 0..count {
            cursor.next_term(0)?;
        }
        cursor.finish()?;
        Ok(())
    }

    #[test]
    fn production_layout_is_exact_and_overflow_fails() {
        let contract = parse_contract().expect("final plan must parse");
        assert_eq!(contract.constraint_section_bytes, 2_736_746_712);
        assert_eq!(contract.wire_map_bytes, 103_598_568);
        assert_eq!(contract.output_bytes, 2_840_345_392);
        assert!(contract.aggregate_full_export_authorized);
        let mut overflow = contract.clone();
        overflow.constraints = u64::MAX;
        assert_eq!(
            validate_contract(&overflow).unwrap_err().code,
            "contract-u32"
        );
    }

    #[test]
    fn hostile_terms_fail_closed() {
        let contract = parse_contract().expect("final plan must parse");
        let zero = [0_u8; 32];
        assert_eq!(
            admit_term(0, 0, 0, &zero, 0, None, &contract.field, contract.variables)
                .unwrap_err()
                .code,
            "zero-coefficient"
        );
        assert_eq!(
            admit_term(
                0,
                0,
                0,
                &contract.field,
                0,
                None,
                &contract.field,
                contract.variables,
            )
            .unwrap_err()
            .code,
            "noncanonical-coefficient"
        );
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(
            admit_term(
                0,
                0,
                1,
                &one,
                2,
                Some(2),
                &contract.field,
                contract.variables
            )
            .unwrap_err()
            .code,
            "duplicate-or-reordered-column"
        );
    }

    struct FailAfter {
        remaining: usize,
    }

    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "injected disk full",
                ));
            }
            let written = self.remaining.min(bytes.len());
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_disk_write_is_reported_before_hash_advances() {
        let mut writer = HashedWriter::new(FailAfter { remaining: 3 });
        let error = writer.write(b"four").unwrap_err();
        assert_eq!(error.code, "output-write");
        assert_eq!(writer.bytes, 0);
    }

    #[test]
    fn pass_mutation_crc_and_trailing_members_fail_closed() {
        let (contract, axes) = tiny_contract();
        let directory = temporary_directory("gzip-controls");

        let mutation_path = directory.join("mutation.gz");
        fs::write(&mutation_path, &axes[0]).expect("write mutation fixture");
        let mut mutation = File::open(&mutation_path).expect("open mutation fixture");
        let original = FileIdentity::of(&mutation, "test").expect("identity");
        pin_compressed(&mut mutation, original, &contract.axes[0]).expect("initial pin");
        let mut changed = axes[0].clone();
        changed[20] ^= 1;
        fs::write(&mutation_path, changed).expect("mutate between passes");
        let error = pin_compressed(&mut mutation, original, &contract.axes[0]).unwrap_err();
        assert!(matches!(
            error.code,
            "axis-changed-during-pin" | "compressed-identity-pin"
        ));

        let crc_path = directory.join("crc.gz");
        let mut corrupt_crc = axes[0].clone();
        let last = corrupt_crc.len() - 1;
        corrupt_crc[last] ^= 1;
        fs::write(&crc_path, &corrupt_crc).expect("write crc fixture");
        let mut crc_contract = contract.clone();
        crc_contract.axes[0].compressed_sha256 = sha256(&corrupt_crc);
        let error = consume_axis(
            File::open(&crc_path).expect("open crc fixture"),
            &crc_contract,
            &crc_contract.axes[0],
        )
        .unwrap_err();
        assert_eq!(error.code, "gzip-crc-or-stream");

        let trailing_path = directory.join("trailing.gz");
        let mut trailing = axes[0].clone();
        trailing.extend_from_slice(&axes[1]);
        fs::write(&trailing_path, &trailing).expect("write trailing fixture");
        let mut trailing_contract = contract.clone();
        trailing_contract.axes[0].compressed_bytes = trailing.len() as u64;
        trailing_contract.axes[0].compressed_sha256 = sha256(&trailing);
        let error = consume_axis(
            File::open(&trailing_path).expect("open trailing fixture"),
            &trailing_contract,
            &trailing_contract.axes[0],
        )
        .unwrap_err();
        assert_eq!(error.code, "gzip-trailing-or-second-member");

        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn material_substitution_and_receipt_reuse_fail_closed() {
        let mut contract = parse_contract().expect("production contract");
        contract.source_sha256 = "00".repeat(32);
        assert_eq!(
            validate_materials(&contract).unwrap_err().code,
            "material-identity"
        );

        let directory = temporary_directory("receipt-reuse");
        let directory_file = File::open(&directory).expect("open receipt directory");
        let receipt = json!({"schema": "test", "status": "PASS"});
        write_receipt(directory_file.as_raw_fd(), &receipt).expect("first receipt");
        let original = fs::read(directory.join(RECEIPT_NAME)).expect("read original receipt");
        assert_eq!(
            write_receipt(directory_file.as_raw_fd(), &receipt)
                .unwrap_err()
                .code,
            "publish-create-new"
        );
        assert_eq!(
            fs::read(directory.join(RECEIPT_NAME)).expect("reread original receipt"),
            original
        );
        drop(directory_file);
        fs::remove_dir_all(directory).expect("remove test directory");
    }
}
