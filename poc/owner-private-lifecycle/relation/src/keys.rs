//! Fresh research setup; complete externally pinned parameters precede stdin.
use crate::*;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        prelude::PermissionsExt,
    },
    path::Path,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub role: String,
    pub domain_hex32: String,
    pub pk_bytes: u64,
    pub pk_sha256: String,
    pub vk_hex328: String,
    pub vk_sha256: String,
    pub source_sha256: String,
    pub executable_sha256: String,
    pub curve_parameters_sha256: String,
    pub constraints: usize,
    pub instances: usize,
    pub witnesses: usize,
    pub matrix_sha256: String,
    pub setup_entropy: String,
}
pub fn source_identity() -> H {
    hash(&[
        include_bytes!("../Cargo.toml"),
        include_bytes!("../Cargo.lock"),
        include_bytes!("lib.rs"),
        include_bytes!("cv.rs"),
        include_bytes!("statements.rs"),
        include_bytes!("wire.rs"),
        include_bytes!("circuit.rs"),
        include_bytes!("exact_sha256.rs"),
        include_bytes!("request.rs"),
        include_bytes!("keys.rs"),
        include_bytes!("main.rs"),
    ])
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
pub fn read_pinned(path: &Path, pin: &str, expected_size: Option<u64>) -> Result<Vec<u8>> {
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Parameters);
    }
    for p in path.ancestors() {
        if fs::symlink_metadata(p)
            .map_err(|_| Error::Io)?
            .file_type()
            .is_symlink()
        {
            return Err(Error::Parameters);
        }
    }
    let before = fs::symlink_metadata(path).map_err(|_| Error::Io)?;
    if !before.is_file() || expected_size.is_some_and(|n| n != before.len()) {
        return Err(Error::Parameters);
    }
    let mut file = fs::File::open(path).map_err(|_| Error::Io)?;
    if !same(&before, &file.metadata().map_err(|_| Error::Io)?) {
        return Err(Error::Parameters);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| Error::Io)?;
    if !same(&before, &file.metadata().map_err(|_| Error::Io)?)
        || bytes.len() as u64 != before.len()
        || hex::encode(hash(&[&bytes])) != pin
    {
        return Err(Error::Parameters);
    }
    Ok(bytes)
}
pub fn load(
    role: Role,
    pk_path: &Path,
    pk_pin: &str,
    manifest_path: &Path,
    manifest_pin: &str,
) -> Result<(ProvingKey<Bn254>, Manifest)> {
    let raw = read_pinned(manifest_path, manifest_pin, None)?;
    let m: Manifest = serde_json::from_slice(&raw).map_err(|_| Error::Parameters)?;
    if m.schema != "kpx8-owner-private-parameters/v1"
        || m.role != role.name()
        || m.domain_hex32 != hex::encode(DOMAIN)
        || m.source_sha256 != hex::encode(source_identity())
        || m.curve_parameters_sha256 != hex::encode(parameter_powers_digest())
        || m.pk_sha256 != pk_pin
        || m.instances != 3
        || m.setup_entropy != "PRIVATE_OS_RNG_NOT_RETAINED"
    {
        return Err(Error::Parameters);
    }
    let vk = hex::decode(&m.vk_hex328).map_err(|_| Error::Parameters)?;
    checked_vk(&vk)?;
    if hex::encode(hash(&[&vk])) != m.vk_sha256 {
        return Err(Error::Parameters);
    }
    // Trusted-input decode only AFTER full bytes match the external selected manifest.
    // Neither an embedded VK nor a witness-provided hash grants this authority.
    let raw = read_pinned(pk_path, pk_pin, Some(m.pk_bytes))?;
    let mut rem = raw.as_slice();
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut rem)
        .map_err(|_| Error::Parameters)?;
    if !rem.is_empty()
        || vk_bytes(&pk.vk)?.as_slice() != vk
        || pk.a_query.len() != m.witnesses + 3
        || pk.b_g1_query.len() != m.witnesses + 3
        || pk.b_g2_query.len() != m.witnesses + 3
        || pk.l_query.len() != m.witnesses
    {
        return Err(Error::Parameters);
    }
    Ok((pk, m))
}
pub fn setup(role: Role, output: &Path) -> Result<Manifest> {
    if output.exists() {
        return Err(Error::Parameters);
    }
    fs::create_dir_all(output).map_err(|_| Error::Io)?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700)).map_err(|_| Error::Io)?;
    let (s, o) = circuit::fixture();
    let (shape, sat) = match role {
        Role::Spend => circuit::check(s.clone())?,
        Role::Output => circuit::check(o.clone())?,
        Role::Exit => circuit::check(circuit::exit_fixture())?,
    };
    if !sat || shape.instances != 3 {
        return Err(Error::Synthesis);
    }
    // Public Pedersen seed is NEVER used for Groth16 toxic-waste entropy.
    let pk = match role {
        Role::Spend => {
            Groth16::<Bn254>::generate_random_parameters_with_reduction(s, &mut rand::rngs::OsRng)
        }
        Role::Output => {
            Groth16::<Bn254>::generate_random_parameters_with_reduction(o, &mut rand::rngs::OsRng)
        }
        Role::Exit => Groth16::<Bn254>::generate_random_parameters_with_reduction(
            circuit::exit_fixture(),
            &mut rand::rngs::OsRng,
        ),
    }
    .map_err(|_| Error::Synthesis)?;
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)
        .map_err(|_| Error::Parameters)?;
    let vk = vk_bytes(&pk.vk)?;
    checked_vk(&vk)?;
    let exe = fs::read(std::env::current_exe().map_err(|_| Error::Io)?).map_err(|_| Error::Io)?;
    let m = Manifest {
        schema: "kpx8-owner-private-parameters/v1".into(),
        role: role.name().into(),
        domain_hex32: hex::encode(DOMAIN),
        pk_bytes: bytes.len() as u64,
        pk_sha256: hex::encode(hash(&[&bytes])),
        vk_hex328: hex::encode(vk),
        vk_sha256: hex::encode(hash(&[&vk])),
        source_sha256: hex::encode(source_identity()),
        executable_sha256: hex::encode(hash(&[&exe])),
        curve_parameters_sha256: hex::encode(parameter_powers_digest()),
        constraints: shape.constraints,
        instances: shape.instances,
        witnesses: shape.witnesses,
        matrix_sha256: shape.matrix_sha256,
        setup_entropy: "PRIVATE_OS_RNG_NOT_RETAINED".into(),
    };
    save(&output.join("parameters.pk"), &bytes, 0o400)?;
    save(&output.join("vk.bin"), &vk, 0o444)?;
    save(
        &output.join("manifest.json"),
        &serde_json::to_vec(&m).map_err(|_| Error::Parameters)?,
        0o444,
    )?;
    Ok(m)
}
pub fn save(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| Error::Io)?;
    f.write_all(bytes).map_err(|_| Error::Io)?;
    f.sync_all().map_err(|_| Error::Io)
}
pub fn prove_spend(pk: &ProvingKey<Bn254>, c: SpendCircuit) -> Result<[u8; 128]> {
    c.statement.validate()?;
    let s = c.statement.clone();
    let p = Groth16::<Bn254>::create_random_proof_with_reduction(c, pk, &mut rand::rngs::OsRng)
        .map_err(|_| Error::Synthesis)?;
    let p = proof_bytes(&p)?;
    if !Verifier::new(&vk_bytes(&pk.vk)?, Role::Spend)?.verify_spend(&s, &p)? {
        return Err(Error::Verification);
    }
    Ok(p)
}
pub fn prove_output(pk: &ProvingKey<Bn254>, c: OutputCircuit) -> Result<[u8; 128]> {
    c.statement.validate()?;
    let s = c.statement.clone();
    let p = Groth16::<Bn254>::create_random_proof_with_reduction(c, pk, &mut rand::rngs::OsRng)
        .map_err(|_| Error::Synthesis)?;
    let p = proof_bytes(&p)?;
    if !Verifier::new(&vk_bytes(&pk.vk)?, Role::Output)?.verify_output(&s, &p)? {
        return Err(Error::Verification);
    }
    Ok(p)
}
pub fn prove_exit(pk: &ProvingKey<Bn254>, c: ExitCircuit) -> Result<[u8; 128]> {
    c.statement.validate()?;
    let s = c.statement.clone();
    let p = Groth16::<Bn254>::create_random_proof_with_reduction(c, pk, &mut rand::rngs::OsRng)
        .map_err(|_| Error::Synthesis)?;
    let p = proof_bytes(&p)?;
    if !Verifier::new(&vk_bytes(&pk.vk)?, Role::Exit)?.verify_exit(&s, &p)? {
        return Err(Error::Verification);
    }
    Ok(p)
}
