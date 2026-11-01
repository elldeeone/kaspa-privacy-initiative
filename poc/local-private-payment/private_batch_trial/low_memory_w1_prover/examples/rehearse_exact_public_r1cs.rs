//! Exact public c023 R1CS parser/QAP resource rehearsal.
//!
//! This fixed control opens no proving key, assignment artifact, proof, or
//! network resource. It authenticates the complete public R1CS before the
//! library allocates its internal all-zero (except wire zero) assignment.

use kpb_low_memory_w1_prover::algebraic_controls::{
    ExpectedIdentity, R1csGeometry, rehearse_public_invalid_r1cs,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};

const R1CS_RELATIVE: &str = ".local/r1cs-aggregate-export-c023-20261029-02/aggregate.r1cs";
const RECEIPT_DIRECTORY_RELATIVE: &str = ".local/low-memory-w1-exact-r1cs-resource-20261029-01";
const EXPECTED_R1CS_BYTES: u64 = 2_840_345_392;
const EXPECTED_R1CS_SHA256: &str =
    "cc76d603d0cb184f4e43b99d3af9f215274c0a67bdbec28ed435046c2b9c42bc";
const WIRES: usize = 12_949_821;
const PUBLIC_INPUTS: usize = 2;
const PRIVATE_INPUTS: usize = 12_949_818;
const CONSTRAINTS: usize = 13_093_029;
const LABELS: u64 = 12_949_821;
const CONSTRAINT_SECTION_BYTES: u64 = 2_736_746_712;
const EXPECTED_DOMAIN_SIZE: usize = 16_777_216;

fn repository_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .ok_or_else(|| "crate is outside the reviewed repository layout".into())
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

fn address_space_limit_bytes() -> Result<u64, Box<dyn std::error::Error>> {
    let limits = fs::read_to_string("/proc/self/limits")?;
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .ok_or("missing address-space limit")?;
    let mut fields = line["Max address space".len()..].split_ascii_whitespace();
    let soft = fields.next().ok_or("missing soft address-space limit")?;
    if soft == "unlimited" {
        return Err("resource rehearsal requires a finite address-space cap".into());
    }
    let value = soft.parse()?;
    let hard = fields.next().ok_or("missing hard address-space limit")?;
    let units = fields.next().ok_or("missing address-space units")?;
    if hard != soft || units != "bytes" || fields.next().is_some() {
        return Err("unexpected address-space limit shape".into());
    }
    Ok(value)
}

fn write_new(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(body)?;
    output.sync_all()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("this fixed rehearsal accepts no caller arguments".into());
    }
    let root = repository_root()?;
    let r1cs_path = root.join(R1CS_RELATIVE);
    let receipt_directory = root.join(RECEIPT_DIRECTORY_RELATIVE);
    fs::create_dir(&receipt_directory)?;
    let started = Instant::now();
    let address_space_cap_bytes = address_space_limit_bytes()?;
    let file = File::open(&r1cs_path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.len() != EXPECTED_R1CS_BYTES
        || metadata.nlink() != 1
        || metadata.mode() & 0o222 != 0
    {
        return Err("public R1CS descriptor is not the sealed reviewed file".into());
    }
    let expected_sha256: [u8; 32] = hex::decode(EXPECTED_R1CS_SHA256)?
        .try_into()
        .map_err(|_| "wrong fixed R1CS digest length")?;
    let rehearsal = rehearse_public_invalid_r1cs(
        BufReader::with_capacity(1 << 20, file),
        R1csGeometry {
            wires: WIRES,
            public_outputs: 0,
            public_inputs: PUBLIC_INPUTS,
            private_inputs: PRIVATE_INPUTS,
            labels: LABELS,
            constraints: CONSTRAINTS,
            constraint_section_bytes: CONSTRAINT_SECTION_BYTES,
            identity: ExpectedIdentity {
                bytes: EXPECTED_R1CS_BYTES,
                sha256: expected_sha256,
            },
        },
    )?;
    if rehearsal.rows != CONSTRAINTS
        || rehearsal.wires != WIRES
        || rehearsal.domain_size != EXPECTED_DOMAIN_SIZE
        || rehearsal.unsatisfied_rows == 0
    {
        return Err("exact public resource rehearsal did not reach the fixed geometry".into());
    }
    let peak_rss_kib = proc_status_kib("VmHWM:")?;
    let swap_kib = proc_status_kib("VmSwap:")?;
    let receipt = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"kpb-low-memory-exact-public-r1cs-resource/v1\",\n",
            "  \"classification\": \"PUBLIC_INVALID_ASSIGNMENT_RESOURCE_CONTROL_NO_SATISFACTION_PK_PROOF_NETWORK_OR_PRIVACY_CLAIM\",\n",
            "  \"r1cs_relative\": \"{}\",\n",
            "  \"r1cs_bytes\": {},\n",
            "  \"r1cs_sha256\": \"{}\",\n",
            "  \"r1cs_device\": {},\n",
            "  \"r1cs_inode\": {},\n",
            "  \"r1cs_mode\": \"{:04o}\",\n",
            "  \"rows_scanned\": {},\n",
            "  \"wires\": {},\n",
            "  \"domain_size\": {},\n",
            "  \"synthetic_assignment\": \"wire0_one_all_other_wires_zero\",\n",
            "  \"unsatisfied_rows\": {},\n",
            "  \"h_sha256\": \"{}\",\n",
            "  \"address_space_cap_bytes\": {},\n",
            "  \"peak_rss_kib\": {},\n",
            "  \"swap_kib\": {},\n",
            "  \"elapsed_seconds\": {},\n",
            "  \"satisfaction_authority\": false,\n",
            "  \"assignment_artifact_opened\": false,\n",
            "  \"proving_key_opened\": false,\n",
            "  \"proof_executed\": false,\n",
            "  \"network_used\": false,\n",
            "  \"production_or_launch_authorized\": false\n",
            "}}\n"
        ),
        R1CS_RELATIVE,
        EXPECTED_R1CS_BYTES,
        EXPECTED_R1CS_SHA256,
        metadata.dev(),
        metadata.ino(),
        metadata.mode() & 0o7777,
        rehearsal.rows,
        rehearsal.wires,
        rehearsal.domain_size,
        rehearsal.unsatisfied_rows,
        hex::encode(rehearsal.h_sha256),
        address_space_cap_bytes,
        peak_rss_kib,
        swap_kib,
        started.elapsed().as_secs_f64(),
    );
    let receipt_path = receipt_directory.join("receipt.json");
    write_new(&receipt_path, receipt.as_bytes())?;
    File::open(&receipt_directory)?.sync_all()?;
    print!("{receipt}");
    Ok(())
}
