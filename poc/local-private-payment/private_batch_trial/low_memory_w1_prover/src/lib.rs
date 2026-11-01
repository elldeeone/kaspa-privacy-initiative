//! Offline-only primitives for the frozen W1 aggregate. This crate neither
//! selects an attempt nor authorizes setup, proof launch, or publication.

#![forbid(unsafe_code)]

mod source_only_runner;

pub use source_only_runner::SourceOnlyRunnerContractStatus;

/// Non-authorizing status for the deliberately absent production boundary.
///
/// The fields are private so downstream code cannot construct a value that
/// pretends any missing authority has been selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionBoundaryStatus {
    os_rng_blinding: bool,
    source_owned_assignment: bool,
    historical_pk: bool,
    independent_vk: bool,
    sealed_gzip_same_inode_two_pass: bool,
    proof_launch: bool,
}

impl ProductionBoundaryStatus {
    pub const fn os_rng_blinding(self) -> bool {
        self.os_rng_blinding
    }

    pub const fn source_owned_assignment(self) -> bool {
        self.source_owned_assignment
    }

    pub const fn historical_pk(self) -> bool {
        self.historical_pk
    }

    pub const fn independent_vk(self) -> bool {
        self.independent_vk
    }

    pub const fn sealed_gzip_same_inode_two_pass(self) -> bool {
        self.sealed_gzip_same_inode_two_pass
    }

    pub const fn proof_launch(self) -> bool {
        self.proof_launch
    }
}

static PRODUCTION_BOUNDARY_STATUS: ProductionBoundaryStatus = ProductionBoundaryStatus {
    os_rng_blinding: false,
    source_owned_assignment: false,
    historical_pk: false,
    independent_vk: false,
    sealed_gzip_same_inode_two_pass: false,
    proof_launch: false,
};

#[cfg_attr(
    not(feature = "algebraic-controls"),
    doc = r#"
The raw algebraic proof entry points are absent from the default build.

```compile_fail
use kpb_low_memory_w1_prover::algebraic_controls::create_proof_from_compressed_pk;
```
"#
)]
pub const fn production_boundary_status() -> &'static ProductionBoundaryStatus {
    &PRODUCTION_BOUNDARY_STATUS
}

/// Report the non-authorizing fixed runner contract.
///
/// The implementation module is private, so downstream code cannot call its
/// OS-random sampler or manufacture a runner/assignment/artifact authority.
///
/// ```compile_fail
/// use kpb_low_memory_w1_prover::source_only_runner::SecretBlinding;
/// ```
///
/// The status is also not a caller-mintable authority:
///
/// ```compile_fail
/// use kpb_low_memory_w1_prover::SourceOnlyRunnerContractStatus;
/// let _forged = SourceOnlyRunnerContractStatus {
///     fixed_identity_contract: true,
///     internal_nonzero_osrng_control: true,
///     source_owned_assignment_bridge: true,
///     same_inode_artifact_authority: true,
///     in_process_verifier_authority: true,
///     independent_verifier_authority: true,
///     full_secret_zeroization: true,
///     accepted_invalid_fatal: true,
///     canonical_publication_authority: true,
///     runner_selected: true,
/// };
/// ```
pub const fn source_only_runner_contract_status() -> &'static SourceOnlyRunnerContractStatus {
    &source_only_runner::SOURCE_ONLY_RUNNER_CONTRACT_STATUS
}

/// Public synthetic algebra controls only. Enabling this feature does not mint
/// proof authority or make the crate eligible for a W1 launch.
#[cfg(feature = "algebraic-controls")]
pub mod algebraic_controls {
    use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_ff::{AdditiveGroup, BigInteger, FftField, Field, PrimeField, Zero};
    use ark_groth16::{Proof, VerifyingKey};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use sha2::{Digest, Sha256};
    use std::{
        fmt,
        io::{self, Read, Seek, SeekFrom, Write},
        ops::{Deref, DerefMut, Mul},
    };
    use zeroize::Zeroize;

    const FIELD_BYTES: u32 = 32;
    const CONTROL_MSM_BUFFER: usize = 65_536;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ExpectedIdentity {
        pub bytes: u64,
        pub sha256: [u8; 32],
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct R1csGeometry {
        pub wires: usize,
        pub public_outputs: usize,
        pub public_inputs: usize,
        pub private_inputs: usize,
        pub labels: u64,
        pub constraints: usize,
        pub constraint_section_bytes: u64,
        pub identity: ExpectedIdentity,
    }

    impl R1csGeometry {
        pub fn instance_variables(self) -> Result<usize, LowMemoryError> {
            1usize
                .checked_add(self.public_outputs)
                .and_then(|n| n.checked_add(self.public_inputs))
                .ok_or_else(|| err("geometry-overflow", "instance count overflow"))
        }

        pub fn witness_variables(self) -> Result<usize, LowMemoryError> {
            self.wires
                .checked_sub(self.instance_variables()?)
                .ok_or_else(|| err("geometry-underflow", "instances exceed wires"))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ProvingGeometry {
        pub instance_variables: usize,
        pub witness_variables: usize,
        pub domain_size: usize,
        pub identity: ExpectedIdentity,
        pub vk_identity: ExpectedIdentity,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct LowMemoryError {
        code: &'static str,
        detail: String,
    }

    impl LowMemoryError {
        pub fn code(&self) -> &'static str {
            self.code
        }
    }
    impl fmt::Display for LowMemoryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
    impl std::error::Error for LowMemoryError {}
    fn err(code: &'static str, detail: impl Into<String>) -> LowMemoryError {
        LowMemoryError {
            code,
            detail: detail.into(),
        }
    }

    /// Best-effort RAII erasure for secret-bearing algebraic intermediates.
    ///
    /// This protects ordinary returns, `?` failures, and unwinding panics. It
    /// cannot make guarantees for process abort/OOM, caller-owned input slices,
    /// copies made inside upstream Ark routines, or deliberately leaked values;
    /// the production full-zeroization status therefore remains false.
    struct Secret<T: Zeroize>(T);

    impl<T: Zeroize> Secret<T> {
        fn new(value: T) -> Self {
            Self(value)
        }

        fn replace(&mut self, replacement: T) -> T {
            core::mem::replace(&mut self.0, replacement)
        }

        fn zeroize_now(&mut self) {
            zeroize_secret(&mut self.0);
        }
    }

    impl<T: Zeroize> Deref for Secret<T> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0
        }
    }

    impl<T: Zeroize> DerefMut for Secret<T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0
        }
    }

    impl<T: Zeroize> Drop for Secret<T> {
        fn drop(&mut self) {
            zeroize_secret(&mut self.0);
        }
    }

    fn zeroize_secret<T: Zeroize>(value: &mut T) {
        value.zeroize();
        #[cfg(test)]
        ZEROIZE_EVENTS.with(|events| events.set(events.get() + 1));
    }

    #[cfg(test)]
    thread_local! {
        static ZEROIZE_EVENTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    #[cfg(test)]
    fn zeroize_events() -> usize {
        ZEROIZE_EVENTS.with(core::cell::Cell::get)
    }

    #[cfg(test)]
    fn reset_zeroize_events() {
        ZEROIZE_EVENTS.with(|events| events.set(0));
    }

    pub struct StreamedWitnessMap {
        pub h: Vec<Fr>,
        pub domain_size: usize,
    }

    impl Drop for StreamedWitnessMap {
        fn drop(&mut self) {
            zeroize_secret(&mut self.h);
        }
    }

    /// Public-only result of scanning the exact R1CS with an internally
    /// generated invalid assignment. This can measure parser/QAP resources;
    /// it cannot authorize satisfaction, a proof, or publication.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PublicInvalidResourceRehearsal {
        pub rows: usize,
        pub wires: usize,
        pub domain_size: usize,
        pub unsatisfied_rows: u64,
        pub h_sha256: [u8; 32],
    }
    pub struct StreamedProof {
        pub proof: Proof<Bn254>,
        pub vk: VerifyingKey<Bn254>,
    }

    struct FallibleChunkedMsm<G>
    where
        G: VariableBaseMSM + Zeroize,
        G::MulBase: Zeroize,
    {
        scalars: Secret<Vec<<G::ScalarField as PrimeField>::BigInt>>,
        bases: Secret<Vec<G::MulBase>>,
        result: Secret<G>,
    }

    impl<G> FallibleChunkedMsm<G>
    where
        G: VariableBaseMSM + Zeroize,
        G::MulBase: Zeroize,
    {
        fn new(label: &'static str) -> Result<Self, LowMemoryError> {
            let mut scalars = Vec::new();
            scalars
                .try_reserve_exact(CONTROL_MSM_BUFFER)
                .map_err(|e| err("allocation-refused", format!("{label} scalars: {e}")))?;
            let mut bases = Vec::new();
            bases
                .try_reserve_exact(CONTROL_MSM_BUFFER)
                .map_err(|e| err("allocation-refused", format!("{label} bases: {e}")))?;
            Ok(Self {
                scalars: Secret::new(scalars),
                bases: Secret::new(bases),
                result: Secret::new(G::zero()),
            })
        }

        fn add(&mut self, base: G::MulBase, scalar: <G::ScalarField as PrimeField>::BigInt) {
            let base = Secret::new(base);
            let scalar = Secret::new(scalar);
            self.scalars.push(*scalar);
            self.bases.push(*base);
            if self.scalars.len() == CONTROL_MSM_BUFFER {
                self.flush();
            }
        }

        fn flush(&mut self) {
            if !self.scalars.is_empty() {
                // Ark's bucket allocation inside msm_bigint remains fail-stop.
                // The selected production boundary remains false until an exact
                // host admission covers that upstream allocation.
                let chunk = Secret::new(G::msm_bigint(&self.bases, &self.scalars));
                *self.result += *chunk;
                self.scalars.zeroize_now();
                self.bases.zeroize_now();
            }
        }

        fn finalize(mut self) -> G {
            self.flush();
            self.result.replace(G::zero())
        }
    }

    struct DigestReader<R> {
        inner: R,
        digest: Sha256,
        bytes: u64,
    }
    impl<R> DigestReader<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                digest: Sha256::new(),
                bytes: 0,
            }
        }
    }

    fn require_identity(
        bytes: u64,
        actual: [u8; 32],
        expected: ExpectedIdentity,
    ) -> Result<(), LowMemoryError> {
        if bytes != expected.bytes {
            return Err(err(
                "artifact-size",
                format!("expected {}, read {bytes}", expected.bytes),
            ));
        }
        if actual != expected.sha256 {
            return Err(err(
                "artifact-sha256",
                format!(
                    "expected {}, read {}",
                    hex::encode(expected.sha256),
                    hex::encode(actual)
                ),
            ));
        }
        Ok(())
    }

    fn preauthenticate<R: Read + Seek>(
        reader: &mut R,
        expected: ExpectedIdentity,
    ) -> Result<(), LowMemoryError> {
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| err("artifact-seek", e.to_string()))?;
        let mut digest = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = Secret::new([0u8; 1 << 16]);
        loop {
            let count = reader
                .read(&mut buffer[..])
                .map_err(|e| err("artifact-read", e.to_string()))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            bytes = bytes
                .checked_add(count as u64)
                .ok_or_else(|| err("artifact-size-overflow", "byte count overflow"))?;
        }
        require_identity(bytes, digest.finalize().into(), expected)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| err("artifact-rewind", e.to_string()))?;
        Ok(())
    }

    fn zero_vec<T>(
        length: usize,
        zero: T,
        label: &'static str,
    ) -> Result<Secret<Vec<T>>, LowMemoryError>
    where
        T: Clone + Zeroize,
    {
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|e| err("allocation-refused", format!("{label}: {e}")))?;
        values.resize(length, zero);
        Ok(Secret::new(values))
    }

    impl<R: Read> Read for DigestReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.digest.update(&buf[..n]);
            self.bytes = self
                .bytes
                .checked_add(n as u64)
                .ok_or_else(|| io::Error::other("byte count overflow"))?;
            Ok(n)
        }
    }

    #[derive(Default)]
    struct DigestWriter {
        digest: Sha256,
        bytes: u64,
    }

    impl Write for DigestWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.digest.update(buffer);
            self.bytes = self
                .bytes
                .checked_add(buffer.len() as u64)
                .ok_or_else(|| io::Error::other("byte count overflow"))?;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn require_vk_identity(
        vk: &VerifyingKey<Bn254>,
        expected: ExpectedIdentity,
    ) -> Result<(), LowMemoryError> {
        let mut writer = DigestWriter::default();
        vk.serialize_compressed(&mut writer)
            .map_err(|e| err("vk-serialize", e.to_string()))?;
        if writer.bytes != expected.bytes {
            return Err(err(
                "vk-size",
                format!("expected {}, read {}", expected.bytes, writer.bytes),
            ));
        }
        let actual: [u8; 32] = writer.digest.finalize().into();
        if actual != expected.sha256 {
            return Err(err(
                "vk-sha256",
                format!(
                    "expected {}, read {}",
                    hex::encode(expected.sha256),
                    hex::encode(actual)
                ),
            ));
        }
        Ok(())
    }
    impl<R: Read> DigestReader<R> {
        fn finish(mut self, expected: ExpectedIdentity) -> Result<(), LowMemoryError> {
            let mut tail = Secret::new([0u8; 1]);
            match self.read(&mut tail[..]) {
                Ok(0) => {}
                Ok(_) => return Err(err("trailing-bytes", "artifact has trailing bytes")),
                Err(e) => return Err(err("artifact-eof", e.to_string())),
            }
            require_identity(self.bytes, self.digest.finalize().into(), expected)
        }
    }

    struct SectionReader<'a, R> {
        inner: &'a mut R,
        remaining: u64,
        label: &'static str,
    }
    impl<'a, R> SectionReader<'a, R> {
        fn new(inner: &'a mut R, remaining: u64, label: &'static str) -> Self {
            Self {
                inner,
                remaining,
                label,
            }
        }
        fn finish(self) -> Result<(), LowMemoryError> {
            if self.remaining != 0 {
                return Err(err(
                    "section-trailing",
                    format!("{} has {} unread bytes", self.label, self.remaining),
                ));
            }
            Ok(())
        }
    }
    impl<R: Read> Read for SectionReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let cap = usize::try_from(self.remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            let n = self.inner.read(&mut buf[..cap])?;
            self.remaining -= n as u64;
            Ok(n)
        }
    }

    fn exact<R: Read>(r: &mut R, out: &mut [u8], code: &'static str) -> Result<(), LowMemoryError> {
        r.read_exact(out).map_err(|e| err(code, e.to_string()))
    }
    fn u32le<R: Read>(r: &mut R, code: &'static str) -> Result<u32, LowMemoryError> {
        let mut b = [0; 4];
        exact(r, &mut b, code)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64le<R: Read>(r: &mut R, code: &'static str) -> Result<u64, LowMemoryError> {
        let mut b = [0; 8];
        exact(r, &mut b, code)?;
        Ok(u64::from_le_bytes(b))
    }
    fn usize32<R: Read>(r: &mut R, code: &'static str) -> Result<usize, LowMemoryError> {
        usize::try_from(u32le(r, code)?).map_err(|_| err(code, "u32 does not fit usize"))
    }
    fn eq32(got: u32, want: u32, code: &'static str) -> Result<(), LowMemoryError> {
        if got != want {
            return Err(err(code, format!("expected {want}, received {got}")));
        }
        Ok(())
    }
    fn eq64(got: u64, want: u64, code: &'static str) -> Result<(), LowMemoryError> {
        if got != want {
            return Err(err(code, format!("expected {want}, received {got}")));
        }
        Ok(())
    }
    fn field<R: Read>(r: &mut R) -> Result<Fr, LowMemoryError> {
        let mut b = Secret::new([0u8; FIELD_BYTES as usize]);
        exact(r, &mut b[..], "coefficient-truncated")?;
        Fr::deserialize_with_mode(&b[..], Compress::No, Validate::Yes)
            .map_err(|e| err("coefficient-noncanonical", e.to_string()))
    }
    fn axis<R: Read>(
        r: &mut R,
        assignment: &[Fr],
        row: usize,
        name: char,
    ) -> Result<Fr, LowMemoryError> {
        let count = usize32(r, "term-count-truncated")?;
        if count > assignment.len() {
            return Err(err(
                "term-count-impossible",
                format!("row {row} axis {name}: {count}"),
            ));
        }
        let mut prior = None;
        let mut sum = Secret::new(Fr::ZERO);
        for term in 0..count {
            let wire = usize32(r, "wire-truncated")?;
            if wire >= assignment.len() {
                return Err(err(
                    "wire-out-of-range",
                    format!("row {row} axis {name} term {term}: {wire}"),
                ));
            }
            if prior.is_some_and(|p| p >= wire) {
                return Err(err(
                    "wire-noncanonical-order",
                    format!("row {row} axis {name} term {term}: {wire}"),
                ));
            }
            let coeff = Secret::new(field(r)?);
            if coeff.is_zero() {
                return Err(err(
                    "coefficient-explicit-zero",
                    format!("row {row} axis {name} term {term}"),
                ));
            }
            let product = Secret::new(*coeff * assignment[wire]);
            *sum += *product;
            prior = Some(wire);
        }
        Ok(*sum)
    }

    /// Parse and authenticate one canonical standard R1CS file, require every row
    /// to be satisfied, then reproduce Ark 0.6.0's LibsnarkReduction witness map.
    pub fn stream_r1cs_witness_map<R: Read + Seek>(
        reader: R,
        geometry: R1csGeometry,
        assignment: &[Fr],
    ) -> Result<StreamedWitnessMap, LowMemoryError> {
        let (streamed, unsatisfied_rows) =
            stream_r1cs_witness_map_inner(reader, geometry, assignment, true, false)?;
        debug_assert_eq!(unsatisfied_rows, 0);
        Ok(streamed)
    }

    /// Authenticate the complete R1CS before allocating an internally fixed
    /// all-zero public assignment (except wire zero), scan every row without
    /// accepting satisfaction, and execute the full witness-map/QAP schedule.
    ///
    /// This is a resource control only. It returns only counts and an H digest;
    /// it never exposes H and is unavailable from the default build.
    pub fn rehearse_public_invalid_r1cs<R: Read + Seek>(
        mut reader: R,
        geometry: R1csGeometry,
    ) -> Result<PublicInvalidResourceRehearsal, LowMemoryError> {
        preauthenticate(&mut reader, geometry.identity)?;
        let mut assignment = zero_vec(geometry.wires, Fr::ZERO, "public-invalid-assignment")?;
        let first = assignment
            .first_mut()
            .ok_or_else(|| err("assignment-empty", "wire zero is absent"))?;
        *first = Fr::ONE;
        let (streamed, unsatisfied_rows) =
            stream_r1cs_witness_map_inner(reader, geometry, &assignment, false, true)?;
        if unsatisfied_rows == 0 {
            return Err(err(
                "synthetic-assignment-satisfied",
                "resource-control assignment unexpectedly satisfied every row",
            ));
        }
        let mut h_digest = Sha256::new();
        for value in &streamed.h {
            let encoded = Secret::new(value.into_bigint().to_bytes_le());
            h_digest.update(&encoded[..]);
        }
        Ok(PublicInvalidResourceRehearsal {
            rows: geometry.constraints,
            wires: geometry.wires,
            domain_size: streamed.domain_size,
            unsatisfied_rows,
            h_sha256: h_digest.finalize().into(),
        })
    }

    fn stream_r1cs_witness_map_inner<R: Read + Seek>(
        mut reader: R,
        geometry: R1csGeometry,
        assignment: &[Fr],
        reject_unsatisfied: bool,
        identity_prechecked: bool,
    ) -> Result<(StreamedWitnessMap, u64), LowMemoryError> {
        let instances = geometry.instance_variables()?;
        if geometry.public_outputs != 0 {
            return Err(err(
                "public-output-policy",
                "W1 requires zero public outputs",
            ));
        }
        if geometry.private_inputs != geometry.witness_variables()? {
            return Err(err(
                "private-input-geometry",
                "private-input and witness counts differ",
            ));
        }
        if assignment.len() != geometry.wires {
            return Err(err(
                "assignment-length",
                format!("expected {}, received {}", geometry.wires, assignment.len()),
            ));
        }
        if assignment.first() != Some(&Fr::ONE) {
            return Err(err("assignment-one", "wire zero is not one"));
        }
        if !identity_prechecked {
            preauthenticate(&mut reader, geometry.identity)?;
        }
        let minimum = geometry
            .constraints
            .checked_add(instances)
            .ok_or_else(|| err("domain-overflow", "domain overflow"))?;
        minimum
            .checked_next_power_of_two()
            .ok_or_else(|| err("domain-overflow", "domain power-of-two overflow"))?;
        let domain = GeneralEvaluationDomain::<Fr>::new(minimum)
            .ok_or_else(|| err("domain-unavailable", "no Ark domain"))?;
        let domain_size = domain.size();
        let mut a = zero_vec(domain_size, Fr::ZERO, "domain-a")?;
        let mut b = zero_vec(domain_size, Fr::ZERO, "domain-b")?;
        let mut c = zero_vec(domain_size, Fr::ZERO, "domain-c")?;

        let mut r = DigestReader::new(&mut reader);
        let mut magic = [0; 4];
        exact(&mut r, &mut magic, "magic-truncated")?;
        if &magic != b"r1cs" {
            return Err(err("magic", "expected r1cs"));
        }
        eq32(u32le(&mut r, "version-truncated")?, 1, "version")?;
        eq32(
            u32le(&mut r, "section-count-truncated")?,
            3,
            "section-count",
        )?;
        eq32(u32le(&mut r, "header-kind-truncated")?, 1, "section-order")?;
        let header_len = u64le(&mut r, "header-size-truncated")?;
        eq64(header_len, 64, "header-size")?;
        let mut unsatisfied_rows = 0u64;
        {
            let mut h = SectionReader::new(&mut r, header_len, "header");
            eq32(
                u32le(&mut h, "field-width-truncated")?,
                FIELD_BYTES,
                "field-width",
            )?;
            let mut modulus = [0u8; FIELD_BYTES as usize];
            exact(&mut h, &mut modulus, "modulus-truncated")?;
            if modulus.as_slice() != Fr::MODULUS.to_bytes_le().as_slice() {
                return Err(err("field-modulus", "wrong modulus"));
            }
            eq32(
                u32le(&mut h, "wires-truncated")?,
                u32::try_from(geometry.wires)
                    .map_err(|_| err("wires-overflow", "wires exceed u32"))?,
                "wire-count",
            )?;
            eq32(
                u32le(&mut h, "pubout-truncated")?,
                u32::try_from(geometry.public_outputs)
                    .map_err(|_| err("pubout-overflow", "count exceeds u32"))?,
                "public-output-count",
            )?;
            eq32(
                u32le(&mut h, "pubin-truncated")?,
                u32::try_from(geometry.public_inputs)
                    .map_err(|_| err("pubin-overflow", "count exceeds u32"))?,
                "public-input-count",
            )?;
            eq32(
                u32le(&mut h, "private-truncated")?,
                u32::try_from(geometry.private_inputs)
                    .map_err(|_| err("private-overflow", "count exceeds u32"))?,
                "private-input-count",
            )?;
            eq64(
                u64le(&mut h, "labels-truncated")?,
                geometry.labels,
                "label-count",
            )?;
            eq32(
                u32le(&mut h, "constraints-truncated")?,
                u32::try_from(geometry.constraints)
                    .map_err(|_| err("constraints-overflow", "count exceeds u32"))?,
                "constraint-count",
            )?;
            h.finish()?;
        }
        eq32(
            u32le(&mut r, "constraint-kind-truncated")?,
            2,
            "section-order",
        )?;
        let constraint_len = u64le(&mut r, "constraint-size-truncated")?;
        eq64(
            constraint_len,
            geometry.constraint_section_bytes,
            "constraint-section-size",
        )?;
        {
            let mut rows = SectionReader::new(&mut r, constraint_len, "constraints");
            for row in 0..geometry.constraints {
                let av = Secret::new(axis(&mut rows, assignment, row, 'A')?);
                let bv = Secret::new(axis(&mut rows, assignment, row, 'B')?);
                let cv = Secret::new(axis(&mut rows, assignment, row, 'C')?);
                let product = Secret::new(*av * *bv);
                if *product != *cv {
                    if reject_unsatisfied {
                        return Err(err("unsatisfied-row", format!("row {row}")));
                    }
                    unsatisfied_rows = unsatisfied_rows
                        .checked_add(1)
                        .ok_or_else(|| err("unsatisfied-overflow", "row count overflow"))?;
                }
                a[row] = *av;
                b[row] = *bv;
                c[row] = *cv;
            }
            rows.finish()?;
        }
        eq32(u32le(&mut r, "map-kind-truncated")?, 3, "section-order")?;
        let map_len = u64le(&mut r, "map-size-truncated")?;
        let expected_map_len = u64::try_from(geometry.wires)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or_else(|| err("map-overflow", "wire-map size overflow"))?;
        eq64(map_len, expected_map_len, "wire-map-size")?;
        {
            let mut map = SectionReader::new(&mut r, map_len, "wire-map");
            for wire in 0..geometry.wires {
                eq64(
                    u64le(&mut map, "map-truncated")?,
                    wire as u64,
                    "wire-map-substitution",
                )?;
            }
            map.finish()?;
        }
        r.finish(geometry.identity)?;

        let tail = geometry
            .constraints
            .checked_add(instances)
            .ok_or_else(|| err("instance-tail-overflow", "tail overflow"))?;
        a[geometry.constraints..tail].copy_from_slice(&assignment[..instances]);
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);
        let coset = domain
            .get_coset(Fr::GENERATOR)
            .ok_or_else(|| err("coset-unavailable", "no Ark coset"))?;
        coset.fft_in_place(&mut a);
        coset.fft_in_place(&mut b);
        for (av, bv) in a.iter_mut().zip(b.iter()) {
            *av *= bv;
        }
        drop(b);
        domain.ifft_in_place(&mut c);
        coset.fft_in_place(&mut c);
        let z_inv = domain
            .evaluate_vanishing_polynomial(Fr::GENERATOR)
            .inverse()
            .ok_or_else(|| err("vanishing-inverse", "zero vanishing value"))?;
        for (ab, cv) in a.iter_mut().zip(c.iter()) {
            *ab -= *cv;
            *ab *= z_inv;
        }
        coset.ifft_in_place(&mut a);
        Ok((
            StreamedWitnessMap {
                h: a.replace(Vec::new()),
                domain_size,
            },
            unsatisfied_rows,
        ))
    }

    fn g1<R: Read>(r: &mut R, code: &'static str) -> Result<G1Affine, LowMemoryError> {
        G1Affine::deserialize_with_mode(r, Compress::Yes, Validate::Yes)
            .map_err(|e| err(code, e.to_string()))
    }
    fn g2<R: Read>(r: &mut R, code: &'static str) -> Result<G2Affine, LowMemoryError> {
        G2Affine::deserialize_with_mode(r, Compress::Yes, Validate::Yes)
            .map_err(|e| err(code, e.to_string()))
    }
    fn g1_vec<R: Read>(
        r: &mut R,
        expected: usize,
        code: &'static str,
    ) -> Result<Vec<G1Affine>, LowMemoryError> {
        eq64(u64le(r, "query-length-truncated")?, expected as u64, code)?;
        let mut points = Vec::new();
        points
            .try_reserve_exact(expected)
            .map_err(|e| err("allocation-refused", format!("{code}: {e}")))?;
        for _ in 0..expected {
            points.push(g1(r, code)?);
        }
        Ok(points)
    }
    fn g1_query<R: Read, I: IntoIterator<Item = Fr>>(
        r: &mut R,
        expected: usize,
        scalars: I,
        code: &'static str,
    ) -> Result<G1Projective, LowMemoryError> {
        eq64(u64le(r, "query-length-truncated")?, expected as u64, code)?;
        let mut scalars = scalars.into_iter();
        let mut msm = FallibleChunkedMsm::<G1Projective>::new(code)?;
        for index in 0..expected {
            let base = Secret::new(g1(r, code)?);
            let scalar = Secret::new(
                scalars
                    .next()
                    .ok_or_else(|| err("query-scalar-short", format!("{code} index {index}")))?,
            );
            let encoded = Secret::new((*scalar).into_bigint());
            msm.add(*base, *encoded);
        }
        if scalars.next().is_some() {
            return Err(err("query-scalar-long", code));
        }
        Ok(msm.finalize())
    }
    fn g2_query<R: Read, I: IntoIterator<Item = Fr>>(
        r: &mut R,
        expected: usize,
        scalars: I,
        code: &'static str,
    ) -> Result<G2Projective, LowMemoryError> {
        eq64(u64le(r, "query-length-truncated")?, expected as u64, code)?;
        let mut scalars = scalars.into_iter();
        let mut msm = FallibleChunkedMsm::<G2Projective>::new(code)?;
        for index in 0..expected {
            let base = Secret::new(g2(r, code)?);
            let scalar = Secret::new(
                scalars
                    .next()
                    .ok_or_else(|| err("query-scalar-short", format!("{code} index {index}")))?,
            );
            let encoded = Secret::new((*scalar).into_bigint());
            msm.add(*base, *encoded);
        }
        if scalars.next().is_some() {
            return Err(err("query-scalar-long", code));
        }
        Ok(msm.finalize())
    }

    /// Consume Ark 0.6.0's canonical compressed proving-key serialization in
    /// field order. Query points are subgroup-validated and immediately folded
    /// into bounded accumulators; no query vector is retained.
    pub fn create_proof_from_compressed_pk<R: Read + Seek>(
        mut reader: R,
        geometry: ProvingGeometry,
        instances: &[Fr],
        witnesses: &[Fr],
        h: &[Fr],
        r_scalar: Fr,
        s_scalar: Fr,
    ) -> Result<StreamedProof, LowMemoryError> {
        // Only the owned wrapper storage below is best-effort erased. The
        // by-value ABI inputs, arithmetic/register temporaries, caller-owned
        // values, and copies inside upstream Ark remain outside this synthetic
        // control boundary.
        let r_scalar = Secret::new(r_scalar);
        let s_scalar = Secret::new(s_scalar);
        if instances.len() != geometry.instance_variables {
            return Err(err(
                "instance-assignment-length",
                format!(
                    "expected {}, received {}",
                    geometry.instance_variables,
                    instances.len()
                ),
            ));
        }
        if witnesses.len() != geometry.witness_variables {
            return Err(err(
                "witness-assignment-length",
                format!(
                    "expected {}, received {}",
                    geometry.witness_variables,
                    witnesses.len()
                ),
            ));
        }
        if instances.first() != Some(&Fr::ONE) {
            return Err(err("instance-one", "first instance is not one"));
        }
        if h.len() != geometry.domain_size {
            return Err(err(
                "h-length",
                format!("expected {}, received {}", geometry.domain_size, h.len()),
            ));
        }
        let variables = geometry
            .instance_variables
            .checked_add(geometry.witness_variables)
            .ok_or_else(|| err("variable-overflow", "variable count overflow"))?;
        let h_len = geometry
            .domain_size
            .checked_sub(1)
            .ok_or_else(|| err("domain-underflow", "empty domain"))?;
        preauthenticate(&mut reader, geometry.identity)?;

        let mut input = DigestReader::new(&mut reader);
        let alpha_g1 = g1(&mut input, "vk-alpha-g1")?;
        let beta_g2 = g2(&mut input, "vk-beta-g2")?;
        let gamma_g2 = g2(&mut input, "vk-gamma-g2")?;
        let delta_g2 = g2(&mut input, "vk-delta-g2")?;
        let gamma_abc_g1 = g1_vec(
            &mut input,
            geometry.instance_variables,
            "vk-gamma-abc-length",
        )?;
        let vk = VerifyingKey::<Bn254> {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        require_vk_identity(&vk, geometry.vk_identity)?;
        let beta_g1 = Secret::new(g1(&mut input, "pk-beta-g1")?);
        let delta_g1 = Secret::new(g1(&mut input, "pk-delta-g1")?);
        let assignment = || instances.iter().copied().chain(witnesses.iter().copied());
        let a_acc = Secret::new(g1_query(&mut input, variables, assignment(), "a-query")?);
        let b1_acc = Secret::new(g1_query(&mut input, variables, assignment(), "b-g1-query")?);
        let b2_acc = Secret::new(g2_query(&mut input, variables, assignment(), "b-g2-query")?);
        let h_acc = Secret::new(g1_query(
            &mut input,
            h_len,
            h.iter().copied().take(h_len),
            "h-query",
        )?);
        let l_acc = Secret::new(g1_query(
            &mut input,
            geometry.witness_variables,
            witnesses.iter().copied(),
            "l-query",
        )?);
        input.finish(geometry.identity)?;

        let mut proof_a = Secret::new(*a_acc);
        *proof_a += delta_g1.mul(*r_scalar);
        *proof_a += alpha_g1;
        let mut b1 = Secret::new(*b1_acc);
        *b1 += delta_g1.mul(*s_scalar);
        *b1 += *beta_g1;
        let mut proof_b = Secret::new(*b2_acc);
        *proof_b += delta_g2.mul(*s_scalar);
        *proof_b += beta_g2;
        let mut proof_c = Secret::new(*proof_a * *s_scalar);
        *proof_c += *b1 * *r_scalar;
        let rs = Secret::new(*r_scalar * *s_scalar);
        *proof_c -= delta_g1.mul(*rs);
        *proof_c += *l_acc;
        *proof_c += *h_acc;
        Ok(StreamedProof {
            proof: Proof {
                a: (*proof_a).into_affine(),
                b: (*proof_b).into_affine(),
                c: (*proof_c).into_affine(),
            },
            vk,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_ec::PrimeGroup;
        use std::{
            io::Cursor,
            panic::{AssertUnwindSafe, catch_unwind},
        };

        #[test]
        fn secret_raii_erases_on_explicit_error_and_unwind_drop() {
            reset_zeroize_events();
            let failure: Result<(), LowMemoryError> = {
                let _secret = Secret::new(vec![Fr::ONE, Fr::from(2u64)]);
                Err(err("forced-secret-error", "control"))
            };
            assert_eq!(failure.unwrap_err().code(), "forced-secret-error");
            assert_eq!(zeroize_events(), 1);

            let unwind = catch_unwind(AssertUnwindSafe(|| {
                let _secret = Secret::new(vec![Fr::from(3u64)]);
                panic!("forced-secret-unwind");
            }));
            assert!(unwind.is_err());
            assert_eq!(zeroize_events(), 2);

            let mut explicit = Secret::new(vec![Fr::ONE]);
            explicit.zeroize_now();
            assert!(explicit.is_empty());
            drop(explicit);
            assert_eq!(zeroize_events(), 4);
        }

        #[test]
        fn qap_buffers_erase_when_authenticated_parse_fails_after_allocation() {
            let geometry = R1csGeometry {
                wires: 1,
                public_outputs: 0,
                public_inputs: 0,
                private_inputs: 0,
                labels: 1,
                constraints: 0,
                constraint_section_bytes: 0,
                identity: ExpectedIdentity {
                    bytes: 4,
                    sha256: Sha256::digest(b"nope").into(),
                },
            };
            reset_zeroize_events();
            let error = stream_r1cs_witness_map_inner(
                Cursor::new(b"nope".as_slice()),
                geometry,
                &[Fr::ONE],
                true,
                true,
            )
            .err()
            .expect("bad magic was accepted");
            assert_eq!(error.code(), "magic");
            assert_eq!(zeroize_events(), 3, "a, b, and c must all erase");
        }

        #[test]
        fn owned_scalar_and_base_wrappers_drop_on_mid_query_decode_failure() {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&2u64.to_le_bytes());
            G1Projective::generator()
                .into_affine()
                .serialize_compressed(&mut encoded)
                .unwrap();
            encoded.push(0xff);
            reset_zeroize_events();
            let error = g1_query(
                &mut Cursor::new(encoded),
                2,
                [Fr::ONE, Fr::from(2u64)],
                "forced-query-failure",
            )
            .expect_err("truncated second query point was accepted");
            assert_eq!(error.code(), "forced-query-failure");
            assert!(
                zeroize_events() >= 8,
                "owned base/scalar wrappers and MSM buffers/results must erase"
            );
        }

        #[test]
        fn blinding_owned_wrappers_drop_on_first_proof_validation_error() {
            let geometry = ProvingGeometry {
                instance_variables: 2,
                witness_variables: 0,
                domain_size: 1,
                identity: ExpectedIdentity {
                    bytes: 0,
                    sha256: Sha256::digest([]).into(),
                },
                vk_identity: ExpectedIdentity {
                    bytes: 0,
                    sha256: Sha256::digest([]).into(),
                },
            };
            reset_zeroize_events();
            let error = create_proof_from_compressed_pk(
                Cursor::new(Vec::<u8>::new()),
                geometry,
                &[Fr::ONE],
                &[],
                &[Fr::ZERO],
                Fr::from(17u64),
                Fr::from(29u64),
            )
            .err()
            .expect("wrong instance length was accepted");
            assert_eq!(error.code(), "instance-assignment-length");
            assert_eq!(
                zeroize_events(),
                2,
                "r and s owned wrapper storage must erase"
            );
        }

        #[test]
        fn returned_h_and_temporary_encodings_erase_on_drop_or_error() {
            reset_zeroize_events();
            drop(StreamedWitnessMap {
                h: vec![Fr::ONE, Fr::from(2u64)],
                domain_size: 2,
            });
            assert_eq!(zeroize_events(), 1);

            let field_error = field(&mut Cursor::new([0xff; FIELD_BYTES as usize]))
                .expect_err("noncanonical field encoding was accepted");
            assert_eq!(field_error.code(), "coefficient-noncanonical");
            assert_eq!(zeroize_events(), 2);

            let identity_error = preauthenticate(
                &mut Cursor::new(b"x".as_slice()),
                ExpectedIdentity {
                    bytes: 2,
                    sha256: [0u8; 32],
                },
            )
            .expect_err("wrong artifact identity was accepted");
            assert_eq!(identity_error.code(), "artifact-size");
            assert_eq!(zeroize_events(), 3);
        }

        #[test]
        fn fallible_chunked_msm_matches_ark_across_a_flush_boundary() {
            let count = CONTROL_MSM_BUFFER + 1;
            let base = G1Projective::generator().into_affine();
            let mut bases = Vec::new();
            bases.try_reserve_exact(count).unwrap();
            let mut scalars = Vec::new();
            scalars.try_reserve_exact(count).unwrap();
            let mut streamed = FallibleChunkedMsm::<G1Projective>::new("control").unwrap();
            for index in 0..count {
                let scalar = Fr::from((index as u64) + 1).into_bigint();
                bases.push(base);
                scalars.push(scalar);
                streamed.add(base, scalar);
            }
            assert_eq!(
                streamed.finalize(),
                G1Projective::msm_bigint(&bases, &scalars)
            );
        }
    }
}
