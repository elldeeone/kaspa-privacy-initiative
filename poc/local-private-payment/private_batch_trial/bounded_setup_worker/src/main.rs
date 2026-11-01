//! Source-closed FD-only Arkworks setup worker for the exact frozen Output and
//! aggregate circuits. It accepts no arguments, environment, paths, seed, or
//! caller entropy. Isolation and artifact admission belong to the supervisor.
#![deny(unsafe_op_in_unsafe_fn)]

use aggregate::joined_source::JoinedSourceCircuit;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, R1CS_PREDICATE_LABEL, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufWriter, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    os::fd::FromRawFd,
};
use zeroize::Zeroize;

const CIRCUIT_FD: i32 = 40;
const PLAN_FD: i32 = 42;
const AGGREGATE_CONTEXT_FD: i32 = 43;
const AGGREGATE_SIGNATURE_FD: i32 = 44;
const SWAP_FD: i32 = 45;
const PK_FD: i32 = 50;
const VK_FD: i32 = 51;
const STATUS_FD: i32 = 54;

const CLOSURE_BYTES: usize = 112;
const PLAN_BYTES: usize = 424;
const STATUS_BYTES: usize = 48;
const CLOSURE_MAGIC: &[u8; 8] = b"KPBCRSC1";
const PLAN_MAGIC: &[u8; 8] = b"KPBCRSP1";
const STATUS_MAGIC: &[u8; 8] = b"KPBCRSO1";
const PRECOMMIT_DOMAIN: &[u8] = b"KPB_BOUNDED_SETUP_PRECOMMIT_V1\n";
const PRECOMMIT_FINANCIAL_RUN: u8 = 1;
const PRECOMMIT_ROUND_ATTEMPT: u8 = 2;
const PRECOMMIT_ROUND_COHORT: u8 = 3;

const OUTPUT_SOURCE: &str = "ccd4e28a728cbf8ffd6db0dd0fa81a6200c0c6e4ecb20242435f00e5b6aae19e";
const OUTPUT_MATRIX: &str = "d8e94558a7b9e3a5cc6187a894cb7f141d85d3c6d862b6a628561a24c4bfdd31";
const AGGREGATE_SOURCE: &str = "04adfd77d3b97f60efe6c4547cda583856ea7f7be4c9538f4237330ac137a9d7";
const AGGREGATE_MATRIX: &str = "c02320f82593d16f347e22a7b14cbe5ae394027a260b6af8a4a247b1c6c756ab";
const CONTEXT_SHA256: &str = "ae20c64f7ea90bea3c00b060abe4d3e3c2766955a0b3ad8cfe12b9d8630b7411";
const SIGNATURE_SHA256: &str = "b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11";
const SIGNATURE_MAP_SHA256: &str =
    "dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712";

const POLICY_DUMPABLE_DISABLED: u64 = 1 << 0;
const POLICY_CORE_DISABLED: u64 = 1 << 1;
const POLICY_ENVIRONMENT_EMPTY: u64 = 1 << 2;
const POLICY_UNKNOWN_FDS_CLOSED: u64 = 1 << 3;
const POLICY_NETWORK_DENIED: u64 = 1 << 4;
const POLICY_SWAP_ZERO: u64 = 1 << 5;
const POLICY_CLOSURES_EXACT: u64 = 1 << 6;
const POLICY_PLAN_EXACT: u64 = 1 << 7;
const POLICY_SOURCE_OPENS_DENIED: u64 = 1 << 8;
const POLICY_DESCENDANTS_DENIED: u64 = 1 << 9;
const POLICY_ERASURE_ATTEMPTED: u64 = 1 << 10;

fn fail() -> Result<(), ()> {
    Err(())
}
fn need(value: bool) -> Result<(), ()> {
    if value { Ok(()) } else { fail() }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn precommit_child(trial: &[u8], kind: u8, round: u8) -> [u8; 32] {
    let mut value = Sha256::new();
    value.update(PRECOMMIT_DOMAIN);
    value.update(trial);
    value.update([kind, round]);
    value.finalize().into()
}
fn pinned(bytes: &[u8], expected: &str) -> Result<(), ()> {
    need(hex::encode(digest(bytes)) == expected)
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64, ()> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ))
}
fn put_u64(bytes: &mut [u8], at: usize, value: u64) -> Result<(), ()> {
    bytes
        .get_mut(at..at + 8)
        .ok_or(())?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn owned_fd(raw: i32) -> File {
    // SAFETY: the supervisor installs a unique open descriptor at every fixed
    // ABI number before exec. This worker takes ownership exactly once.
    unsafe { File::from_raw_fd(raw) }
}
fn read_exact_fd<const N: usize>(raw: i32) -> Result<[u8; N], ()> {
    let mut file = owned_fd(raw);
    let mut result = [0u8; N];
    file.read_exact(&mut result).map_err(|_| ())?;
    let mut trailing = [0u8; 1];
    need(file.read(&mut trailing).map_err(|_| ())? == 0)?;
    Ok(result)
}
fn read_bounded_fd(raw: i32, maximum: usize) -> Result<Vec<u8>, ()> {
    let file = owned_fd(raw);
    let mut result = Vec::new();
    file.take((maximum as u64) + 1)
        .read_to_end(&mut result)
        .map_err(|_| ())?;
    need(!result.is_empty() && result.len() <= maximum)?;
    Ok(result)
}

fn initial_policy() -> Result<u64, ()> {
    // SAFETY: constants and local pointers follow the libc call contracts.
    let dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let core = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0
        && limit.rlim_cur == 0
        && limit.rlim_max == 0;
    let environment = std::env::vars_os().next().is_none();
    let unknown = unsafe { libc::fcntl(200, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    let network = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9))
        .is_err_and(|error| error.raw_os_error() == Some(libc::EPERM));
    let source_open =
        File::open("/etc/passwd").is_err_and(|error| error.raw_os_error() == Some(libc::EPERM));
    let child = unsafe { libc::fork() };
    let descendants = child == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if child == 0 {
        unsafe { libc::_exit(91) }
    }
    if child > 0 {
        let mut status = 0;
        while unsafe { libc::waitpid(child, &mut status, 0) } == -1
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
    let swap = read_exact_fd::<2>(SWAP_FD)? == *b"0\n";
    need(
        dumpable && core && environment && unknown && network && source_open && descendants && swap,
    )?;
    Ok(POLICY_DUMPABLE_DISABLED
        | POLICY_CORE_DISABLED
        | POLICY_ENVIRONMENT_EMPTY
        | POLICY_UNKNOWN_FDS_CLOSED
        | POLICY_NETWORK_DENIED
        | POLICY_SWAP_ZERO
        | POLICY_SOURCE_OPENS_DENIED
        | POLICY_DESCENDANTS_DENIED)
}

struct CheckedOutput(output::OutputCircuit);
impl ConstraintSynthesizer<Fr> for CheckedOutput {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.0.generate_constraints(cs.clone())?;
        cs.finalize();
        let mut groups = cs.to_matrices()?;
        if groups.len() != 1 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let matrix = authority::join::R1cs {
            instances: cs.num_instance_variables(),
            witnesses: cs.num_witness_variables(),
            matrices: groups
                .remove(R1CS_PREDICATE_LABEL)
                .ok_or(SynthesisError::Unsatisfiable)?
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        };
        if matrix.instances != 3
            || matrix.constraints() != 217_807
            || matrix
                .variables()
                .map_err(|_| SynthesisError::Unsatisfiable)?
                != 215_001
            || authority::join::fingerprint(&matrix).map_err(|_| SynthesisError::Unsatisfiable)?
                != OUTPUT_MATRIX
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(())
    }
}

struct CheckedAggregate(JoinedSourceCircuit);
impl ConstraintSynthesizer<Fr> for CheckedAggregate {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let shape = self.0.generate_with_shape(cs.clone())?;
        cs.finalize();
        let mut groups = cs.to_matrices()?;
        if groups.len() != 1 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let matrix = authority::join::R1cs {
            instances: cs.num_instance_variables(),
            witnesses: cs.num_witness_variables(),
            matrices: groups
                .remove(R1CS_PREDICATE_LABEL)
                .ok_or(SynthesisError::Unsatisfiable)?
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        };
        if matrix.instances != 3
            || matrix.constraints() != 13_093_029
            || matrix
                .variables()
                .map_err(|_| SynthesisError::Unsatisfiable)?
                != 12_949_821
            || shape.final_variables != 12_949_821
            || shape.signature_variables != [10_049; 3]
            || authority::join::fingerprint(&matrix).map_err(|_| SynthesisError::Unsatisfiable)?
                != AGGREGATE_MATRIX
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(())
    }
}

fn output_circuit() -> Result<CheckedOutput, ()> {
    need(hex::encode(output::proof::source_identity()) == OUTPUT_SOURCE)?;
    let domain: [u8; 32] =
        hex::decode("a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0")
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())?;
    let profile_id: [u8; 32] =
        hex::decode("ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700")
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())?;
    let note = native::Note {
        owner: [1; 32],
        incoming: [2; 32],
        value: 200_000_000,
        rho: [3; 32],
        key_commitment: [4; 32],
        native_pk: [5; 32],
    };
    let blinding = [1u8; 32];
    let statement = output::OutputStatement {
        domain,
        cm: note.commitment(&domain),
        cv: native::value_commitment(note.value, &blinding).map_err(|_| ())?,
        cf_hash: digest(b"KPB bounded setup public Output shape fixture"),
    };
    Ok(CheckedOutput(output::OutputCircuit {
        profile: output::Profile { domain, profile_id },
        statement,
        witness: output::OutputWitness { note, blinding },
    }))
}

fn context(raw: [u8; 276]) -> aggregate::Context {
    aggregate::Context {
        profile: aggregate::Profile {
            chain_genesis: raw[..32].try_into().expect("fixed"),
            pool_lineage: raw[32..64].try_into().expect("fixed"),
            wallet_profile: raw[64..96].try_into().expect("fixed"),
            domain: raw[96..128].try_into().expect("fixed"),
            service_policy: raw[128..160].try_into().expect("fixed"),
        },
        reserve_outpoint: raw[160..196].try_into().expect("fixed"),
        old_cm_root: raw[196..228].try_into().expect("fixed"),
        old_nf_root: raw[228..260].try_into().expect("fixed"),
        old_cm_count: u32::from_le_bytes(raw[260..264].try_into().expect("fixed")),
        old_nf_count: u32::from_le_bytes(raw[264..268].try_into().expect("fixed")),
        old_reserve: u64::from_le_bytes(raw[268..].try_into().expect("fixed")),
    }
}

fn aggregate_circuit(context_raw: &[u8], signature_raw: &[u8]) -> Result<CheckedAggregate, ()> {
    pinned(context_raw, CONTEXT_SHA256)?;
    pinned(signature_raw, SIGNATURE_SHA256)?;
    let value: Value = serde_json::from_slice(context_raw).map_err(|_| ())?;
    need(value["schema"] == "kpb-public-context-history/v1")?;
    let text = value["context_hex"].as_str().ok_or(())?;
    need(
        text.len() == 552
            && text
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
    )?;
    let raw: [u8; 276] = hex::decode(text)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    let signature = authority::interchange::signature_matrix(
        signature_raw,
        SIGNATURE_SHA256,
        SIGNATURE_MAP_SHA256,
    )
    .map_err(|_| ())?;
    need(
        signature.instances == 67
            && signature.witnesses == 9_982
            && signature.constraints() == 10_065,
    )?;
    let circuit = JoinedSourceCircuit::from_public_context(
        context(raw),
        core::array::from_fn(|_| signature.clone()),
    )
    .map_err(|_| ())?;
    Ok(CheckedAggregate(circuit))
}

struct CountWriter<W> {
    inner: W,
    bytes: u64,
}
impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(value)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("size"))?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_parameters(pk: &ProvingKey<Bn254>, role: u8) -> Result<(), ()> {
    let pk_file = owned_fd(PK_FD);
    let mut pk_out = CountWriter {
        inner: BufWriter::new(pk_file),
        bytes: 0,
    };
    if role == 1 {
        pk.serialize_uncompressed(&mut pk_out)
    } else {
        pk.serialize_compressed(&mut pk_out)
    }
    .map_err(|_| ())?;
    pk_out.flush().map_err(|_| ())?;
    pk_out.inner.get_ref().sync_all().map_err(|_| ())?;
    let expected = if role == 1 { 85_578_096 } else { 2_608_842_576 };
    need(pk_out.bytes == expected)?;
    let mut vk = Vec::new();
    pk.vk.serialize_compressed(&mut vk).map_err(|_| ())?;
    need(vk.len() == 328)?;
    let vk_file = owned_fd(VK_FD);
    let mut vk_out = BufWriter::new(vk_file);
    vk_out.write_all(&vk).map_err(|_| ())?;
    vk_out.flush().map_err(|_| ())?;
    vk_out.get_ref().sync_all().map_err(|_| ())?;
    vk.zeroize();
    Ok(())
}

fn validate_wire(closure: &[u8; CLOSURE_BYTES], plan: &[u8; PLAN_BYTES]) -> Result<u8, ()> {
    need(&closure[..8] == CLOSURE_MAGIC && &plan[..8] == PLAN_MAGIC)?;
    let role = closure[8];
    need(role == 1 || role == 2)?;
    let (source, matrix, rows, variables, pk_bytes, plan_at) = if role == 1 {
        (
            OUTPUT_SOURCE,
            OUTPUT_MATRIX,
            217_807,
            215_001,
            85_578_096,
            232,
        )
    } else {
        (
            AGGREGATE_SOURCE,
            AGGREGATE_MATRIX,
            13_093_029,
            12_949_821,
            2_608_842_576,
            328,
        )
    };
    need(
        &closure[16..48] == hex::decode(source).map_err(|_| ())?
            && &closure[48..80] == hex::decode(matrix).map_err(|_| ())?
            && u64_at(closure, 80)? == rows
            && u64_at(closure, 88)? == variables
            && u64_at(closure, 96)? == pk_bytes
            && u64_at(closure, 104)? == 328
            && closure[16..80] == plan[plan_at..plan_at + 64]
            && closure[80..112] == plan[plan_at + 64..plan_at + 96],
    )?;
    for left in 0..7 {
        let left_at = 8 + left * 32;
        need(plan[left_at..left_at + 32].iter().any(|v| *v != 0))?;
        for right in left + 1..7 {
            let right_at = 8 + right * 32;
            need(plan[left_at..left_at + 32] != plan[right_at..right_at + 32])?;
        }
    }
    let trial = &plan[8..40];
    for round in 0..2 {
        let round_number = (round + 1) as u8;
        need(
            plan[40 + round * 32..72 + round * 32]
                == precommit_child(trial, PRECOMMIT_FINANCIAL_RUN, round_number)
                && plan[104 + round * 32..136 + round * 32]
                    == precommit_child(trial, PRECOMMIT_ROUND_ATTEMPT, round_number)
                && plan[168 + round * 32..200 + round * 32]
                    == precommit_child(trial, PRECOMMIT_ROUND_COHORT, round_number),
        )?;
    }
    Ok(role)
}

fn run() -> Result<(), ()> {
    let mut policy = initial_policy()?;
    let mut closure = read_exact_fd::<CLOSURE_BYTES>(CIRCUIT_FD)?;
    let mut plan = read_exact_fd::<PLAN_BYTES>(PLAN_FD)?;
    let plan_identity = digest(&plan);
    let role = validate_wire(&closure, &plan)?;
    policy |= POLICY_CLOSURES_EXACT | POLICY_PLAN_EXACT;
    let pk = if role == 1 {
        Groth16::<Bn254>::generate_random_parameters_with_reduction(output_circuit()?, &mut OsRng)
            .map_err(|_| ())?
    } else {
        let mut context_raw = read_bounded_fd(AGGREGATE_CONTEXT_FD, 4096)?;
        let mut signature_raw = read_bounded_fd(AGGREGATE_SIGNATURE_FD, 4 << 20)?;
        let circuit = aggregate_circuit(&context_raw, &signature_raw)?;
        context_raw.zeroize();
        signature_raw.zeroize();
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut OsRng)
            .map_err(|_| ())?
    };
    write_parameters(&pk, role)?;
    drop(pk);
    closure.zeroize();
    plan.zeroize();
    policy |= POLICY_ERASURE_ATTEMPTED;
    let mut status = [0u8; STATUS_BYTES];
    status[..8].copy_from_slice(STATUS_MAGIC);
    status[8..40].copy_from_slice(&plan_identity);
    put_u64(&mut status, 40, policy)?;
    let mut output = owned_fd(STATUS_FD);
    output.write_all(&status).map_err(|_| ())?;
    status.zeroize();
    Ok(())
}

fn main() {
    if run().is_err() {
        std::process::exit(70);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_setup_child_derivation_matches_controller_vectors() {
        let trial = [0x33; 32];
        let expected = [
            (
                PRECOMMIT_FINANCIAL_RUN,
                1,
                "570fec2056d38f569c66b902e40b847279b752990efc9112f287cbdd7a1186e2",
            ),
            (
                PRECOMMIT_FINANCIAL_RUN,
                2,
                "2ad33544b56955b606899418651055dd55c739bb91f49ad577322abc5f69ba9e",
            ),
            (
                PRECOMMIT_ROUND_ATTEMPT,
                1,
                "a724ae74c37c0ca13d9a7bffd679088fef02ed5c4e566d21d7ed8f1225598d5f",
            ),
            (
                PRECOMMIT_ROUND_ATTEMPT,
                2,
                "8d256d22727f353331ca268d359b7719588eb6d0b7c08f680718f0d6db8995a4",
            ),
            (
                PRECOMMIT_ROUND_COHORT,
                1,
                "09f5792c2e433c5c9e0a2c7e5edbd5dd53fd8bc0bfba8909e28c7fa1f9bc3227",
            ),
            (
                PRECOMMIT_ROUND_COHORT,
                2,
                "571d5ee6fc0d7c4289f93346bbe787166ec2c39afdfb232a1474f2044ddc7e7b",
            ),
        ];
        for (kind, round, identity) in expected {
            assert_eq!(hex::encode(precommit_child(&trial, kind, round)), identity);
        }
    }
}
