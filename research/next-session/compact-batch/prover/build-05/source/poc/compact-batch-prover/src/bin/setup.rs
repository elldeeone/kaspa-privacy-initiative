//! ADR0057: fresh role-specific development setup and resident proofs.
//! No prior PK, matrix, runtime selection override or witness export exists.
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use kpi_compact_batch_prover::{
    self as payment, Role, circuit::ActionCircuit, parameters, request,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs,
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    time::Instant,
};

type Result<T> = std::result::Result<T, &'static str>;

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_dir(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| "setup_directory_sync")
}

fn new_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "setup_output_create")?;
    sync_dir(path)?;
    sync_dir(parent(path))
}

fn save(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "setup_output_create")?;
    file.write_all(raw).map_err(|_| "setup_output_write")?;
    file.sync_all().map_err(|_| "setup_output_sync")?;
    sync_dir(parent(path))
}

fn save_json(path: &Path, value: &Value) -> Result<()> {
    let raw = serde_json::to_vec(value).map_err(|_| "setup_public_report_encoding")?;
    save(path, &raw)
}

fn emit(value: &Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).map_err(|_| "setup_event_write")?;
    stdout.write_all(b"\n").map_err(|_| "setup_event_write")?;
    stdout.flush().map_err(|_| "setup_event_write")
}

fn outside_git(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| "setup_pk_path")?;
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("setup_pk_symlink");
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("setup_pk_path"),
        }
    }
    let directory = parent(&absolute)
        .canonicalize()
        .map_err(|_| "setup_pk_parent")?;
    if !directory.is_dir() {
        return Err("setup_pk_parent");
    }
    for ancestor in directory.ancestors() {
        if fs::symlink_metadata(ancestor.join(".git")).is_ok() {
            return Err("setup_pk_inside_git");
        }
    }
    // Clear discovery/config overrides and suppress all path-bearing Git output.
    // Only Git's explicit not-a-repository outcome authorizes this location.
    let git = Command::new("git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "1")
        .arg("-C")
        .arg(&directory)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|_| "setup_git_check")?;
    if git.status.success() {
        return Err("setup_pk_inside_git");
    }
    if git.status.code() != Some(128)
        || !git.stdout.is_empty()
        || !git.stderr.starts_with(b"fatal: not a git repository")
    {
        return Err("setup_git_check");
    }
    let name = absolute.file_name().ok_or("setup_pk_path")?;
    Ok(directory.join(name))
}

type ObservedSystem = Rc<RefCell<Option<ConstraintSystemRef<Fr>>>>;

struct ObservedCircuit {
    inner: ActionCircuit,
    observed: ObservedSystem,
}

impl ConstraintSynthesizer<Fr> for ObservedCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> std::result::Result<(), SynthesisError> {
        let mut observed = self.observed.borrow_mut();
        if observed.is_some() {
            return Err(SynthesisError::Unsatisfiable);
        }
        *observed = Some(cs.clone());
        drop(observed);
        // Exactly the original relation, invoked once by the standard generator.
        self.inner.generate_constraints(cs)
    }
}

fn fresh_setup(
    shape: ActionCircuit,
) -> Result<(ProvingKey<Bn254>, parameters::Shape, parameters::Queries)> {
    let observed: ObservedSystem = Rc::new(RefCell::new(None));
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        ObservedCircuit {
            inner: shape,
            observed: observed.clone(),
        },
        &mut rand::rngs::OsRng,
    )
    .map_err(|_| "setup_generation")?;
    // The standard generator has now finalized this exact CS and completed its
    // QAP/setup. Retention costs additional RAM, recorded in later measurements.
    let cs = observed.borrow_mut().take().ok_or("setup_cs_missing")?;
    let shape = parameters::Shape {
        constraints: cs.num_constraints(),
        witness_variables: cs.num_witness_variables(),
        instances_including_one: cs.num_instance_variables(),
        matrix_sha256: payment::circuit::matrix_fingerprint(&cs)
            .map_err(|_| "setup_matrix_fingerprint")?,
        fft_domain_size: 0,
    };
    let mut shape = shape;
    shape.fft_domain_size = parameters::fft_domain_size(&shape).map_err(|e| e.0)?;
    let queries = parameters::queries(&pk);
    let total = shape
        .witness_variables
        .checked_add(shape.instances_including_one)
        .ok_or("setup_dimensions")?;
    if shape.constraints == 0
        || shape.instances_including_one != 3
        || queries.instances_including_one != 3
        || queries.a != total
        || queries.b_g1 != total
        || queries.b_g2 != total
        || queries.l != shape.witness_variables
        || queries.h
            != shape
                .fft_domain_size
                .checked_sub(1)
                .ok_or("setup_dimensions")?
    {
        return Err("setup_dimensions");
    }
    // Release the retained finalized CS before any official PK serialization.
    drop(cs);
    drop(observed);
    Ok((pk, shape, queries))
}

struct HashedWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("setup_pk_length"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn serialize_new(pk: &ProvingKey<Bn254>, path: &Path) -> Result<(u64, String)> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "setup_pk_create")?;
    let mut writer = HashedWriter {
        inner: BufWriter::new(file),
        hash: Sha256::new(),
        bytes: 0,
    };
    pk.serialize_uncompressed(&mut writer)
        .map_err(|_| "setup_pk_serialization")?;
    writer.flush().map_err(|_| "setup_pk_write")?;
    writer
        .inner
        .get_ref()
        .sync_all()
        .map_err(|_| "setup_pk_sync")?;
    let actual = writer
        .inner
        .get_ref()
        .metadata()
        .map_err(|_| "setup_pk_metadata")?
        .len();
    if actual != writer.bytes || actual == 0 {
        return Err("setup_pk_length");
    }
    let HashedWriter {
        mut inner,
        hash,
        bytes,
    } = writer;
    let streamed_hash = hex::encode(hash.finalize());
    // Independently confirm the actual fsynced artifact using the very same
    // newly created descriptor. Never reopen a path or read a previous PK.
    let file = inner.get_mut();
    file.seek(SeekFrom::Start(0)).map_err(|_| "setup_pk_seek")?;
    let mut actual_hash = Sha256::new();
    let mut actual_bytes = 0_u64;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| "setup_pk_readback")?;
        if count == 0 {
            break;
        }
        actual_hash.update(&buffer[..count]);
        actual_bytes = actual_bytes
            .checked_add(count as u64)
            .ok_or("setup_pk_length")?;
    }
    let hash = hex::encode(actual_hash.finalize());
    if actual_bytes != bytes
        || file.metadata().map_err(|_| "setup_pk_metadata")?.len() != bytes
        || hash != streamed_hash
    {
        return Err("setup_pk_readback_mismatch");
    }
    drop(inner);
    sync_dir(parent(path))?;
    Ok((bytes, hash))
}

fn read_request(role: Role, path: &Path) -> Result<ActionCircuit> {
    let mut file = fs::File::open(path).map_err(|_| "setup_request_io")?;
    request::read_for_role(&mut file, role).map_err(|error| error.code())
}

fn prove(
    role: Role,
    pk: &ProvingKey<Bn254>,
    vk: &[u8; 328],
    fixture: &Path,
    output: &Path,
) -> Result<()> {
    let began = Instant::now();
    let circuit = read_request(role, fixture)?;
    let auth = circuit.authorization.clone();
    new_dir(output)?;
    let proof = payment::prove(pk, circuit, &mut rand::rngs::OsRng)
        .map_err(|_| "setup_proof_generation")?;
    if !payment::Verifier::new(vk, role)
        .map_err(|_| "setup_vk_invalid")?
        .verify(&auth, &proof)
        .map_err(|_| "setup_proof_verification")?
    {
        return Err("setup_proof_verification");
    }
    let prove_seconds = began.elapsed().as_secs_f64();
    let proof_sha256 = parameters::digest(&proof);
    let auth_sha256 = parameters::digest(&auth.bytes());
    let vk_sha256 = parameters::digest(vk);
    let domain_hex32 = hex::encode(payment::DOMAIN);
    let build_identity_sha256 = parameters::build_identity_sha256();
    save(&output.join("proof128.bin"), &proof)?;
    save(&output.join("authorization528.bin"), &auth.bytes())?;
    save(&output.join("verification-key.bin"), vk)?;
    save_json(
        &output.join("report.json"),
        &json!({
            "schema": "kpx4-private-resident-proof-result/v1",
            "role":role.name(), "output_arity":role.output_count(), "actual_rayon_workers":rayon::current_num_threads(),
            "proof_sha256": proof_sha256,
            "authorization_sha256": auth_sha256,
            "vk_sha256": vk_sha256,
            "domain_hex32": domain_hex32,
            "compiled_build_identity_sha256": build_identity_sha256,
            "genuine_Groth16_verified": true,
            "request_parse_prove_and_checked_verification_seconds": prove_seconds,
        }),
    )?;
    emit(&json!({
        "event": "proof-complete", "role":role.name(),
        "proof_sha256": proof_sha256,
        "authorization_sha256": auth_sha256,
        "vk_sha256": vk_sha256,
        "domain_hex32": domain_hex32,
        "compiled_build_identity_sha256": build_identity_sha256,
        "genuine_Groth16_verified": true,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProveCommand {
    fixture: String,
    output: String,
}

fn commands(role: Role, pk: &ProvingKey<Bn254>, vk: &[u8; 328]) -> Result<()> {
    let mut stdin = BufReader::new(io::stdin());
    loop {
        let mut line = Vec::new();
        let count = (&mut stdin)
            .take((request::MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "setup_command_io")?;
        if count == 0 {
            return Ok(());
        }
        if line.len() > request::MAX_REQUEST_BYTES {
            return Err("setup_command_invalid");
        }
        if std::str::from_utf8(&line)
            .map_err(|_| "setup_command_invalid")?
            .trim()
            == "quit"
        {
            return Ok(());
        }
        if line.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
            return Err("setup_command_invalid");
        }
        let command: ProveCommand =
            serde_json::from_slice(&line).map_err(|_| "setup_command_invalid")?;
        prove(
            role,
            pk,
            vk,
            Path::new(&command.fixture),
            Path::new(&command.output),
        )?;
    }
}

fn session(role: Role, shape_path: &Path, output: &Path, pk_path: &Path) -> Result<()> {
    // The public AA/unselected template must stop before shape access or RNG.
    let trial = parameters::trial_identity().map_err(|error| error.0)?;
    let source_identity = parameters::source_identity_value();
    let build_identity = parameters::build_identity_value();
    let build_identity_sha256 = parameters::build_identity_sha256();
    let pk_path = outside_git(pk_path)?;
    let shape = read_request(role, shape_path)?;
    shape
        .authorization
        .validate_public_for_role(role)
        .map_err(|_| "setup_shape_public_invalid")?;
    new_dir(output)?;
    emit(&json!({
        "event": "setup-started", "role":role.name(),
        "trial_id": trial.trial_id,
        "domain_hex32": trial.domain_hex32,
        "compiled_build_identity_sha256": build_identity_sha256,
    }))?;
    let began = Instant::now();
    let (pk, constraint_shape, queries) = fresh_setup(shape)?;
    let setup_seconds = began.elapsed().as_secs_f64();
    let vk = payment::verification_key(&pk).map_err(|_| "setup_vk_invalid")?;
    let began_serialization = Instant::now();
    let (pk_bytes, pk_sha256) = serialize_new(&pk, &pk_path)?;
    let serialize_seconds = began_serialization.elapsed().as_secs_f64();
    let vk_sha256 = parameters::digest(&vk);
    save(&output.join("verification-key.bin"), &vk)?;
    save_json(
        &output.join("report.json"),
        &json!({
            "schema": "kpx4-compact-batch-setup-result/v1",
            "role":role.name(), "output_arity":role.output_count(), "actual_rayon_workers":rayon::current_num_threads(),
            "auth_magic_hex8":trial.auth_magic_hex8, "program_label":trial.program_label,
            "trial_id": trial.trial_id,
            "network_id": trial.network_id,
            "genesis_hash_hex": trial.genesis_hash_hex,
            "domain_hex32": trial.domain_hex32,
            "core_source_identity": source_identity,
            "build_identity": build_identity,
            "compiled_build_identity_sha256": build_identity_sha256,
            "constraint_shape": constraint_shape,
            "queries": queries,
            "vk_hex328": hex::encode(vk),
            "vk_sha256": vk_sha256,
            "format": "arkworks0.6-bn254-uncompressed",
            "pk_bytes": pk_bytes,
            "pk_sha256": pk_sha256,
            "setup_rng": "OsRng",
            "fresh_setup_and_finalized_shape_measurement_seconds": setup_seconds,
            "official_serialization_stream_hash_fsync_and_same_fd_readback_seconds": serialize_seconds,
        }),
    )?;
    emit(&json!({
        "event": "ready", "role":role.name(), "output_arity":role.output_count(), "actual_rayon_workers":rayon::current_num_threads(),
        "trial_id": trial.trial_id,
        "domain_hex32": trial.domain_hex32,
        "compiled_build_identity_sha256": build_identity_sha256,
        "vk_hex328": hex::encode(vk),
        "vk_sha256": vk_sha256,
        "pk_bytes": pk_bytes,
        "pk_sha256": pk_sha256,
        "constraint_shape": constraint_shape,
        "queries": queries,
    }))?;
    commands(role, &pk, &vk)
}

fn run() -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(14)
        .build_global()
        .map_err(|_| "setup_thread_pool_initialization")?;
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 || args[1] != "session" {
        return Err("setup_usage");
    }
    let role = Role::parse(args[2].to_str().ok_or("setup_role_invalid")?)
        .map_err(|_| "setup_role_invalid")?;
    session(
        role,
        Path::new(&args[3]),
        Path::new(&args[4]),
        Path::new(&args[5]),
    )
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("setup_panic")));
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
