//! Public, source-bound recipes for authenticated witness extension.
//!
//! A recipe contains wire identities and public coefficients, never witness
//! values. `evaluate_public_fixture` is a differential-test oracle only; actual
//! private execution belongs to the authenticated MASCOT interpreter.
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lc(pub Vec<(Fr, usize)>);

impl Lc {
    pub fn zero() -> Self {
        Self(Vec::new())
    }
    pub fn constant(value: Fr) -> Self {
        if value == Fr::ZERO {
            Self::zero()
        } else {
            Self(vec![(value, 0)])
        }
    }
    pub fn wire(index: usize) -> Self {
        Self(vec![(Fr::ONE, index)])
    }
    pub fn scaled(&self, coefficient: Fr) -> Self {
        Self::canonical(self.0.iter().map(|(c, i)| (*c * coefficient, *i)))
    }
    pub fn plus(&self, other: &Self) -> Self {
        Self::canonical(self.0.iter().chain(&other.0).copied())
    }
    pub fn minus(&self, other: &Self) -> Self {
        self.plus(&other.scaled(-Fr::ONE))
    }
    pub fn canonical(terms: impl IntoIterator<Item = (Fr, usize)>) -> Self {
        let mut values = BTreeMap::<usize, Fr>::new();
        for (coefficient, index) in terms {
            *values.entry(index).or_default() += coefficient;
        }
        Self(
            values
                .into_iter()
                .filter_map(|(i, c)| (c != Fr::ZERO).then_some((c, i)))
                .collect(),
        )
    }
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_constant(&self) -> Option<Fr> {
        match self.0.as_slice() {
            [] => Some(Fr::ZERO),
            [(value, 0)] => Some(*value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Linear {
        target: usize,
        value: Lc,
    },
    MulAdd {
        target: usize,
        left: Lc,
        right: Lc,
        add: Lc,
    },
    /// All vectors are little-endian bits, explicitly zero-extended to width.
    /// Every allocated carry/high bit is an output, so this is not truncation.
    AddBits {
        targets: Vec<usize>,
        words: Vec<Vec<Lc>>,
    },
    AssertZero {
        value: Lc,
    },
    /// Fresh jointly authenticated preprocessing bit. Never an owner input,
    /// never a model-prefix output, and never a clear value inferred locally.
    RandomBit {
        target: usize,
    },
}

#[derive(Debug)]
pub enum Error {
    Shape(&'static str),
    Io(io::Error),
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape(code) => f.write_str(code),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bindings {
    pub source_sha256: String,
    pub model_sha256: String,
    pub layout_sha256: String,
}

/// Immutable expected export shape, obtainable only from a complete Count pass.
/// Public identity pins still come from the independently selected job/source.
#[derive(Clone, Debug)]
pub struct CountDescriptor {
    bindings: Bindings,
    model_variables: usize,
    variables: usize,
    instances: usize,
    inputs: Vec<usize>,
    operations: usize,
    body_bytes: u64,
    body_sha256: [u8; 32],
    graph_sha256: [u8; 32],
    canonical_bytes: u64,
}
impl CountDescriptor {
    pub fn bindings(&self) -> &Bindings {
        &self.bindings
    }
    pub fn model_variables(&self) -> usize {
        self.model_variables
    }
    pub fn variables(&self) -> usize {
        self.variables
    }
    pub fn instances(&self) -> usize {
        self.instances
    }
    pub fn inputs(&self) -> &[usize] {
        &self.inputs
    }
    pub fn operations(&self) -> usize {
        self.operations
    }
    pub fn operation_text_bytes(&self) -> u64 {
        self.body_bytes
    }
    pub fn body_sha256(&self) -> [u8; 32] {
        self.body_sha256
    }
    pub fn graph_sha256(&self) -> [u8; 32] {
        self.graph_sha256
    }
    pub fn canonical_text_bytes(&self) -> u64 {
        self.canonical_bytes
    }
}

#[derive(Clone, Debug)]
pub struct StreamReceipt {
    pub uncompressed_sha256: [u8; 32],
    pub uncompressed_bytes: u64,
    pub operations: usize,
    pub graph_sha256: [u8; 32],
}

enum Store {
    Memory(Vec<Operation>),
    /// Graph sizing/hashing only. No body, values, input oracle or interpreter.
    Count {
        count: usize,
        operation_bytes: u64,
        operation_hash: Sha256,
    },
    Stream {
        path: PathBuf,
        writer: BufWriter<File>,
        count: usize,
    },
    /// Complete header first, then bounded-buffer direct writes to the sink.
    HeaderStream {
        expected: CountDescriptor,
        writer: RecordingSink,
        count: usize,
        operation_bytes: u64,
        operation_hash: Sha256,
        failed: bool,
    },
    /// Explicitly PUBLIC fixtures only; never an owner input route.
    PublicFixture {
        fixture: BTreeMap<usize, Fr>,
        values: Vec<Option<Fr>>,
        count: usize,
        operation_bytes: u64,
        operation_hash: Sha256,
        refused: Option<&'static str>,
        public_random_tape: Option<std::collections::VecDeque<bool>>,
    },
}

/// Fresh target assignments are checked as they are emitted. Large traces can
/// spool operation text to a selected public file instead of retaining it all.
pub struct TraceBuilder {
    model_variables: usize,
    instances: usize,
    assigned: Vec<u8>, // 0=unassigned,1=declared input,2=derived; ONE is implicit.
    inputs: Vec<usize>,
    // Public graph metadata only, populated solely by actual LINEAR targets.
    derived_prefix: Vec<Option<Lc>>,
    store: Store,
}

impl TraceBuilder {
    pub fn new(model_variables: usize, instances: usize) -> Result<Self> {
        if instances == 0 || model_variables < instances {
            return Err(Error::Shape("trace-model-shape"));
        }
        let mut assigned = vec![0; model_variables];
        assigned[0] = 2;
        Ok(Self {
            model_variables,
            instances,
            assigned,
            inputs: Vec::new(),
            derived_prefix: vec![None; instances],
            store: Store::Memory(Vec::new()),
        })
    }
    pub fn new_stream(
        model_variables: usize,
        instances: usize,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut result = Self::new(model_variables, instances)?;
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        result.store = Store::Stream {
            path,
            writer: BufWriter::new(file),
            count: 0,
        };
        Ok(result)
    }
    /// Count/hash the exact symbolic operation text without retaining its body.
    /// This mode has no values and cannot evaluate inputs or export a trace.
    pub fn new_counting(model_variables: usize, instances: usize) -> Result<Self> {
        let mut result = Self::new(model_variables, instances)?;
        result.store = Store::Count {
            count: 0,
            operation_bytes: 0,
            operation_hash: Sha256::new(),
        };
        Ok(result)
    }
    /// Freeze a complete Count graph and explicit external public identity pins.
    /// No body bytes or reference values are retained by this descriptor.
    pub fn export_descriptor(&self, bindings: Bindings) -> Result<CountDescriptor> {
        let Store::Count {
            count,
            operation_bytes,
            operation_hash,
        } = &self.store
        else {
            return Err(Error::Shape("trace-descriptor-count-only"));
        };
        if self.assigned.contains(&0) {
            return Err(Error::Shape("trace-graph-assignment-incomplete"));
        }
        let mut inputs = self.inputs.clone();
        inputs.sort_unstable();
        Ok(CountDescriptor {
            canonical_bytes: self.canonical_text_byte_count(&bindings)?,
            bindings,
            model_variables: self.model_variables,
            variables: self.variables(),
            instances: self.instances,
            inputs,
            operations: *count,
            body_bytes: *operation_bytes,
            body_sha256: operation_hash.clone().finalize().into(),
            graph_sha256: self.graph_sha256()?,
        })
    }
    /// Start the second, source-identical construction. Writes its COMPLETE
    /// expected header immediately; actual inputs must still be redeclared.
    /// The sink should be a temporary artifact/child stdin, admitted only after
    /// this builder's finish receipt AND the consumer/compressor succeed.
    pub fn new_header_stream(expected: CountDescriptor, sink: Box<dyn Write>) -> Result<Self> {
        let mut result = Self::new(expected.model_variables, expected.instances)?;
        let mut writer = RecordingSink {
            inner: BufWriter::with_capacity(256 * 1024, sink),
            hash: Sha256::new(),
            bytes: 0,
        };
        write_header_values(
            &mut writer,
            &expected.bindings,
            expected.model_variables,
            expected.variables,
            expected.instances,
            &expected.inputs,
            expected.operations,
        )?;
        result.store = Store::HeaderStream {
            expected,
            writer,
            count: 0,
            operation_bytes: 0,
            operation_hash: Sha256::new(),
            failed: false,
        };
        Ok(result)
    }
    /// Verify exact Count equivalence before appending END, flush, and consume
    /// the builder to close/drop its sink (for example gzip's stdin). A failed
    /// finish has no receipt; callers must discard the temporary output.
    pub fn finish_header_stream(mut self) -> Result<StreamReceipt> {
        if self.assigned.contains(&0) {
            return Err(Error::Shape("trace-graph-assignment-incomplete"));
        }
        let graph = self.graph_sha256()?;
        let variables = self.variables();
        let mut inputs = self.inputs.clone();
        inputs.sort_unstable();
        let Store::HeaderStream {
            expected,
            writer,
            count,
            operation_bytes,
            operation_hash,
            failed,
        } = &mut self.store
        else {
            return Err(Error::Shape("trace-not-header-stream"));
        };
        if *failed {
            return Err(Error::Shape("trace-header-stream-poisoned"));
        }
        let body: [u8; 32] = operation_hash.clone().finalize().into();
        if variables != expected.variables
            || inputs != expected.inputs
            || *count != expected.operations
            || *operation_bytes != expected.body_bytes
            || body != expected.body_sha256
            || graph != expected.graph_sha256
            || writer.bytes.checked_add(4) != Some(expected.canonical_bytes)
        {
            *failed = true;
            return Err(Error::Shape("trace-header-stream-count-mismatch"));
        }
        // Detect buffered body failures before adding the terminal marker.
        if let Err(error) = writer.flush() {
            *failed = true;
            return Err(error.into());
        }
        if let Err(error) = writer.write_all(b"END\n").and_then(|_| writer.flush()) {
            *failed = true;
            return Err(error.into());
        }
        if writer.bytes != expected.canonical_bytes {
            return Err(Error::Shape("trace-header-stream-text-size"));
        }
        Ok(StreamReceipt {
            uncompressed_sha256: writer.hash.clone().finalize().into(),
            uncompressed_bytes: writer.bytes,
            operations: *count,
            graph_sha256: graph,
        })
    }
    /// Bounded-memory PUBLIC-FIXTURE differential oracle. Every operation uses
    /// the same reference evaluator as Memory mode, then is discarded. Graph
    /// generation cannot inspect reference values. A private failure is deferred
    /// until final evaluation, so it never changes/truncates the generated IR.
    pub fn new_public_fixture(
        model_variables: usize,
        instances: usize,
        fixture: BTreeMap<usize, Fr>,
    ) -> Result<Self> {
        let mut result = Self::new(model_variables, instances)?;
        if fixture
            .keys()
            .any(|index| *index == 0 || *index >= model_variables)
        {
            return Err(Error::Shape("trace-public-fixture-index"));
        }
        let mut values = vec![None; model_variables];
        values[0] = Some(Fr::ONE);
        result.store = Store::PublicFixture {
            fixture,
            values,
            count: 0,
            operation_bytes: 0,
            operation_hash: Sha256::new(),
            refused: None,
            public_random_tape: None,
        };
        Ok(result)
    }
    /// Explicitly PUBLIC fixture tape for differential tests of RANDOM_BIT.
    /// The tape changes reference values only, never instructions, variable
    /// IDs or graph hashes. Production Stream/Memory use no clear random tape.
    pub fn new_public_fixture_with_random_tape(
        model_variables: usize,
        instances: usize,
        fixture: BTreeMap<usize, Fr>,
        tape: Vec<bool>,
    ) -> Result<Self> {
        let mut result = Self::new_public_fixture(model_variables, instances, fixture)?;
        let Store::PublicFixture {
            public_random_tape, ..
        } = &mut result.store
        else {
            unreachable!()
        };
        *public_random_tape = Some(tape.into());
        Ok(result)
    }
    pub fn variables(&self) -> usize {
        self.assigned.len()
    }
    pub fn model_variables(&self) -> usize {
        self.model_variables
    }
    pub fn operations(&self) -> Option<&[Operation]> {
        match &self.store {
            Store::Memory(ops) => Some(ops),
            _ => None,
        }
    }
    pub fn operation_count(&self) -> usize {
        match &self.store {
            Store::Memory(ops) => ops.len(),
            Store::Count { count, .. }
            | Store::Stream { count, .. }
            | Store::HeaderStream { count, .. }
            | Store::PublicFixture { count, .. } => *count,
        }
    }
    /// Hash of every canonical emitted operation plus structural header. Input
    /// values are excluded; matching hashes demonstrate matching symbolic IR.
    pub fn public_fixture_graph_sha256(&self) -> Result<[u8; 32]> {
        if !matches!(self.store, Store::PublicFixture { .. }) {
            return Err(Error::Shape("trace-not-public-fixture-mode"));
        }
        self.graph_sha256()
    }
    /// Same structural digest for Count and PUBLIC-fixture modes. This commits
    /// the canonical body hash, counts and sorted input IDs; it is not the SHA
    /// of a serialized trace file. Source/model/layout pins bind at export.
    pub fn graph_sha256(&self) -> Result<[u8; 32]> {
        let (count, operation_hash) = match &self.store {
            Store::Count {
                count,
                operation_hash,
                ..
            }
            | Store::PublicFixture {
                count,
                operation_hash,
                ..
            }
            | Store::HeaderStream {
                count,
                operation_hash,
                ..
            } => (count, operation_hash),
            _ => return Err(Error::Shape("trace-graph-hash-mode")),
        };
        let mut hash = Sha256::new();
        hash.update(b"KPB_PUBLIC_TRACE_GRAPH_V1");
        for value in [
            self.model_variables,
            self.instances,
            self.variables(),
            *count,
        ] {
            hash.update((value as u64).to_le_bytes());
        }
        let mut inputs = self.inputs.clone();
        inputs.sort_unstable();
        for index in inputs {
            hash.update((index as u64).to_le_bytes());
        }
        hash.update(operation_hash.clone().finalize());
        Ok(hash.finalize().into())
    }
    pub fn operation_text_bytes(&self) -> Result<u64> {
        match &self.store {
            Store::Count {
                operation_bytes, ..
            }
            | Store::PublicFixture {
                operation_bytes, ..
            }
            | Store::HeaderStream {
                operation_bytes, ..
            } => Ok(*operation_bytes),
            _ => Err(Error::Shape("trace-byte-count-mode")),
        }
    }
    /// Exact canonical text size, including the current public header and END.
    pub fn canonical_text_byte_count(&self, bindings: &Bindings) -> Result<u64> {
        let mut hash = Sha256::new();
        let mut bytes = 0;
        self.write_header(
            &mut HashCountWriter {
                hash: &mut hash,
                bytes: &mut bytes,
            },
            bindings,
        )?;
        Ok(bytes + self.operation_text_bytes()? + 4)
    }
    pub fn input(&mut self, index: usize) -> Result<Lc> {
        if index == 0 || index >= self.model_variables {
            return Err(Error::Shape("trace-input-index"));
        }
        if let Store::HeaderStream {
            expected, failed, ..
        } = &mut self.store
        {
            if *failed {
                return Err(Error::Shape("trace-header-stream-poisoned"));
            }
            if expected.inputs.binary_search(&index).is_err() {
                *failed = true;
                return Err(Error::Shape("trace-header-stream-unexpected-input"));
            }
        }
        match self.assigned[index] {
            0 => {
                self.assigned[index] = 1;
                self.inputs.push(index);
                if let Store::PublicFixture {
                    fixture,
                    values,
                    refused,
                    ..
                } = &mut self.store
                {
                    values[index] = Some(fixture.get(&index).copied().unwrap_or_else(|| {
                        refused.get_or_insert("trace-public-input-set");
                        Fr::ZERO
                    }));
                }
            }
            1 => {}
            _ => return Err(Error::Shape("trace-input-overwrites-derived")),
        }
        Ok(Lc::wire(index))
    }
    pub fn input_range(&mut self, start: usize, end: usize) -> Result<()> {
        if start == 0 || start > end || end > self.model_variables {
            return Err(Error::Shape("trace-input-range"));
        }
        for index in start..end {
            self.input(index)?;
        }
        Ok(())
    }
    pub fn constant(&self, value: Fr) -> Lc {
        Lc::constant(value)
    }
    pub fn bit_constant(&self, value: bool) -> Lc {
        Lc::constant(Fr::from(value))
    }
    fn temporary(&mut self) -> usize {
        let index = self.assigned.len();
        self.assigned.push(0);
        if let Store::PublicFixture { values, .. } = &mut self.store {
            values.push(None);
        }
        index
    }
    pub fn random_bit(&mut self) -> Result<Lc> {
        let target = self.temporary();
        self.fresh(&[target])?;
        self.store(Operation::RandomBit { target })?;
        self.assigned[target] = 2;
        Ok(Lc::wire(target))
    }
    fn known(&self, value: &Lc) -> Result<()> {
        if Lc::canonical(value.0.iter().copied()) != *value {
            return Err(Error::Shape("trace-noncanonical-lc"));
        }
        if value
            .0
            .iter()
            .any(|(_, i)| *i >= self.assigned.len() || self.assigned[*i] == 0)
        {
            return Err(Error::Shape("trace-read-before-assignment"));
        }
        Ok(())
    }
    fn fresh(&self, targets: &[usize]) -> Result<()> {
        let mut seen = targets.to_vec();
        seen.sort_unstable();
        if seen.windows(2).any(|w| w[0] == w[1])
            || targets
                .iter()
                .any(|i| *i == 0 || *i >= self.assigned.len() || self.assigned[*i] != 0)
        {
            return Err(Error::Shape("trace-target-not-fresh"));
        }
        Ok(())
    }
    fn store(&mut self, operation: Operation) -> Result<()> {
        match &mut self.store {
            Store::Memory(ops) => ops.push(operation),
            Store::Count {
                count,
                operation_bytes,
                operation_hash,
            } => {
                write_operation(
                    &mut HashCountWriter {
                        hash: operation_hash,
                        bytes: operation_bytes,
                    },
                    &operation,
                )?;
                *count += 1;
            }
            Store::Stream { writer, count, .. } => {
                write_operation(writer, &operation)?;
                *count += 1;
            }
            Store::HeaderStream {
                expected,
                writer,
                count,
                operation_bytes,
                operation_hash,
                failed,
            } => {
                if *failed {
                    return Err(Error::Shape("trace-header-stream-poisoned"));
                }
                if *count >= expected.operations {
                    *failed = true;
                    return Err(Error::Shape("trace-header-stream-extra-operation"));
                }
                let mut sink = ForwardHashWriter {
                    sink: writer,
                    hash: operation_hash,
                    bytes: operation_bytes,
                };
                if let Err(error) = write_operation(&mut sink, &operation) {
                    *failed = true;
                    return Err(error.into());
                }
                *count += 1;
                if *operation_bytes > expected.body_bytes {
                    *failed = true;
                    return Err(Error::Shape("trace-header-stream-extra-bytes"));
                }
            }
            Store::PublicFixture {
                values,
                count,
                operation_hash,
                operation_bytes,
                refused,
                public_random_tape,
                ..
            } => {
                write_operation(
                    &mut HashCountWriter {
                        hash: operation_hash,
                        bytes: operation_bytes,
                    },
                    &operation,
                )?;
                *count += 1;
                let public_random_bit = if matches!(operation, Operation::RandomBit { .. }) {
                    public_random_tape
                        .as_mut()
                        .and_then(|tape| tape.pop_front())
                } else {
                    None
                };
                if refused.is_none() {
                    if let Err(error) =
                        evaluate_public_operation(&operation, values, public_random_bit)
                    {
                        *refused = Some(match error {
                            Error::Shape(code) => code,
                            Error::Io(_) => "trace-public-reference-refused",
                        });
                    }
                }
            }
        }
        Ok(())
    }
    pub fn assign_linear(&mut self, target: usize, value: Lc) -> Result<()> {
        self.known(&value)?;
        self.fresh(&[target])?;
        let prefix = (target > 0 && target < self.instances).then(|| value.clone());
        self.store(Operation::Linear { target, value })?;
        self.assigned[target] = 2;
        if let Some(value) = prefix {
            self.derived_prefix[target] = Some(value);
        }
        Ok(())
    }
    /// Actual LINEAR recipes for every non-ONE public slot. These are public
    /// wire/coefficient metadata, not values. A promised prefix cannot be its
    /// own alias or depend on another public slot; runtime validates its DAG.
    pub fn derived_prefix_lcs(&self) -> Result<Vec<Lc>> {
        (1..self.instances)
            .map(|target| {
                let value = self.derived_prefix[target]
                    .as_ref()
                    .ok_or(Error::Shape("trace-prefix-not-linear-derived"))?;
                if value
                    .0
                    .iter()
                    .any(|(_, index)| *index > 0 && *index < self.instances)
                {
                    return Err(Error::Shape("trace-prefix-public-alias"));
                }
                Ok(value.clone())
            })
            .collect()
    }
    pub fn linear(&mut self, value: Lc) -> Result<Lc> {
        self.known(&value)?;
        if value.as_constant().is_some() {
            return Ok(value);
        }
        let target = self.temporary();
        self.assign_linear(target, value)?;
        Ok(Lc::wire(target))
    }
    pub fn assign_muladd(&mut self, target: usize, left: Lc, right: Lc, add: Lc) -> Result<()> {
        self.known(&left)?;
        self.known(&right)?;
        self.known(&add)?;
        self.fresh(&[target])?;
        self.store(Operation::MulAdd {
            target,
            left,
            right,
            add,
        })?;
        self.assigned[target] = 2;
        Ok(())
    }
    pub fn muladd(&mut self, left: Lc, right: Lc, add: Lc) -> Result<Lc> {
        self.known(&left)?;
        self.known(&right)?;
        self.known(&add)?;
        if let Some(a) = left.as_constant() {
            return Ok(right.scaled(a).plus(&add));
        }
        if let Some(b) = right.as_constant() {
            return Ok(left.scaled(b).plus(&add));
        }
        let target = self.temporary();
        self.assign_muladd(target, left, right, add)?;
        Ok(Lc::wire(target))
    }
    pub fn assign_add_bits(&mut self, targets: &[usize], words: &[Vec<Lc>]) -> Result<()> {
        if targets.is_empty()
            || targets.len() > 256
            || words.is_empty()
            || words.iter().any(|w| w.len() != targets.len())
        {
            return Err(Error::Shape("trace-add-bits-shape"));
        }
        self.fresh(targets)?;
        for word in words {
            for bit in word {
                self.known(bit)?;
            }
        }
        self.store(Operation::AddBits {
            targets: targets.to_vec(),
            words: words.to_vec(),
        })?;
        for index in targets {
            self.assigned[*index] = 2;
        }
        Ok(())
    }
    pub fn add_bits(&mut self, words: &[Vec<Lc>], width: usize) -> Result<Vec<Lc>> {
        if width == 0 || width > 256 || words.is_empty() || words.iter().any(|w| w.len() > width) {
            return Err(Error::Shape("trace-add-bits-shape"));
        }
        let words = words
            .iter()
            .map(|word| {
                let mut w = word.clone();
                w.resize(width, Lc::zero());
                w
            })
            .collect::<Vec<_>>();
        if words.iter().flatten().all(|x| x.as_constant().is_some()) {
            let mut sum = vec![false; width + words.len() + 1];
            for word in &words {
                let mut carry = false;
                for (i, bit) in word.iter().enumerate() {
                    let v = bit.as_constant().expect("public constant branch");
                    if v != Fr::ZERO && v != Fr::ONE {
                        return Err(Error::Shape("trace-constant-nonboolean"));
                    }
                    let b = v == Fr::ONE;
                    let a = sum[i];
                    sum[i] = a ^ b ^ carry;
                    carry = (a && b) || (carry && (a ^ b));
                }
                let mut i = width;
                while carry {
                    let a = sum[i];
                    sum[i] = !a;
                    carry = a;
                    i += 1;
                }
            }
            if sum[width..].iter().any(|x| *x) {
                return Err(Error::Shape("trace-add-bits-overflow"));
            }
            return Ok(sum[..width]
                .iter()
                .map(|x| Lc::constant(Fr::from(*x)))
                .collect());
        }
        let targets = (0..width).map(|_| self.temporary()).collect::<Vec<_>>();
        self.assign_add_bits(&targets, &words)?;
        Ok(targets.into_iter().map(Lc::wire).collect())
    }
    pub fn assert_zero(&mut self, value: Lc) -> Result<()> {
        self.known(&value)?;
        self.store(Operation::AssertZero { value })
    }
    pub fn bit_not(&self, value: &Lc) -> Lc {
        Lc::constant(Fr::ONE).minus(value)
    }
    pub fn bit_and(&mut self, a: &Lc, b: &Lc) -> Result<Lc> {
        self.muladd(a.clone(), b.clone(), Lc::zero())
    }
    pub fn bit_xor(&mut self, a: &Lc, b: &Lc) -> Result<Lc> {
        self.muladd(a.scaled(-Fr::from(2u64)), b.clone(), a.plus(b))
    }
    pub fn bit_or(&mut self, a: &Lc, b: &Lc) -> Result<Lc> {
        self.muladd(a.scaled(-Fr::ONE), b.clone(), a.plus(b))
    }
    pub fn select(&mut self, condition: &Lc, yes: &Lc, no: &Lc) -> Result<Lc> {
        if yes == no {
            return Ok(yes.clone());
        }
        self.muladd(condition.clone(), yes.minus(no), no.clone())
    }
    pub fn eq_bits(&mut self, a: &[Lc], b: &[Lc]) -> Result<Lc> {
        if a.len() != b.len() {
            return Err(Error::Shape("trace-compare-width"));
        }
        let mut equal = Lc::constant(Fr::ONE);
        for (x, y) in a.iter().zip(b) {
            let different = self.bit_xor(x, y)?;
            let same = self.bit_not(&different);
            equal = self.bit_and(&equal, &same)?;
        }
        Ok(equal)
    }
    pub fn lt_bits(&mut self, a: &[Lc], b: &[Lc]) -> Result<Lc> {
        if a.len() != b.len() {
            return Err(Error::Shape("trace-compare-width"));
        }
        let mut equal = Lc::constant(Fr::ONE);
        let mut less = Lc::zero();
        for (x, y) in a.iter().zip(b).rev() {
            let not_x = self.bit_not(x);
            let xy = self.bit_and(&not_x, y)?;
            let at = self.bit_and(&equal, &xy)?;
            less = self.bit_or(&less, &at)?;
            let different = self.bit_xor(x, y)?;
            let same = self.bit_not(&different);
            equal = self.bit_and(&equal, &same)?;
        }
        Ok(less)
    }
    /// Bindings are external expected identities, not self-authentication.
    fn write_header(&self, writer: &mut impl Write, bindings: &Bindings) -> Result<()> {
        let mut inputs = self.inputs.clone();
        inputs.sort_unstable();
        write_header_values(
            writer,
            bindings,
            self.model_variables,
            self.variables(),
            self.instances,
            &inputs,
            self.operation_count(),
        )
    }
    pub fn write_text(&mut self, writer: &mut impl Write, bindings: &Bindings) -> Result<()> {
        self.write_header(writer, bindings)?;
        match &mut self.store {
            Store::Memory(ops) => {
                for op in ops {
                    write_operation(writer, op)?;
                }
            }
            Store::Stream {
                path, writer: body, ..
            } => {
                body.flush()?;
                io::copy(&mut File::open(path)?, writer)?;
            }
            Store::Count { .. } => return Err(Error::Shape("trace-counting-has-no-retained-body")),
            Store::HeaderStream { .. } => {
                return Err(Error::Shape("trace-header-stream-already-writing"));
            }
            Store::PublicFixture { .. } => {
                return Err(Error::Shape("trace-public-fixture-has-no-retained-body"));
            }
        }
        writeln!(writer, "END")?;
        Ok(())
    }
    pub fn require_complete_model(&self) -> Result<()> {
        if self.assigned[..self.model_variables].contains(&0) {
            return Err(Error::Shape("trace-model-assignment-incomplete"));
        }
        Ok(())
    }
    /// Public graph coverage diagnostic only; contains column IDs, never values.
    pub fn unassigned_model_columns(&self) -> Vec<usize> {
        self.assigned[..self.model_variables]
            .iter()
            .enumerate()
            .filter_map(|(i, a)| (*a == 0).then_some(i))
            .collect()
    }
    /// Public fixtures only. Never route a real owner witness through this oracle.
    pub fn public_fixture_values(&self, inputs: &BTreeMap<usize, Fr>) -> Result<&[Option<Fr>]> {
        let Store::PublicFixture { fixture, .. } = &self.store else {
            return Err(Error::Shape("trace-not-public-fixture-mode"));
        };
        if inputs != fixture {
            return Err(Error::Shape("trace-public-fixture-inputs-changed"));
        }
        self.finish_public_fixture_values()
    }
    /// Finish an explicitly PUBLIC oracle using its immutable owned fixture.
    /// Avoids duplicating millions of public input-map entries solely to compare
    /// them again. This is never used to generate recipes or private inputs.
    pub fn finish_public_fixture_values(&self) -> Result<&[Option<Fr>]> {
        let Store::PublicFixture {
            fixture,
            values,
            refused,
            public_random_tape,
            ..
        } = &self.store
        else {
            return Err(Error::Shape("trace-not-public-fixture-mode"));
        };
        if fixture.len() != self.inputs.len()
            || self.inputs.iter().any(|i| !fixture.contains_key(i))
        {
            return Err(Error::Shape("trace-public-input-set"));
        }
        if let Some(code) = refused {
            return Err(Error::Shape(code));
        }
        if public_random_tape
            .as_ref()
            .is_some_and(|tape| !tape.is_empty())
        {
            return Err(Error::Shape("trace-public-random-tape-excess"));
        }
        Ok(values)
    }
    /// Public fixtures only. Never route a real owner witness through this oracle.
    pub fn evaluate_public_fixture(&self, inputs: &BTreeMap<usize, Fr>) -> Result<Vec<Fr>> {
        if inputs.len() != self.inputs.len() || self.inputs.iter().any(|i| !inputs.contains_key(i))
        {
            return Err(Error::Shape("trace-public-input-set"));
        }
        if let Store::PublicFixture { fixture, .. } = &self.store {
            if inputs != fixture {
                return Err(Error::Shape("trace-public-fixture-inputs-changed"));
            }
            let values = self.finish_public_fixture_values()?;
            return Ok(values.iter().map(|v| v.unwrap_or(Fr::ZERO)).collect());
        }
        let Store::Memory(ops) = &self.store else {
            return Err(Error::Shape("trace-public-oracle-memory-only"));
        };
        let mut values = vec![None; self.variables()];
        values[0] = Some(Fr::ONE);
        for (i, v) in inputs {
            values[*i] = Some(*v);
        }
        for op in ops {
            evaluate_public_operation(op, &mut values, None)?;
        }
        // Scratch can be left unused; every model variable is required by caller.
        Ok(values.into_iter().map(|v| v.unwrap_or(Fr::ZERO)).collect())
    }
}

/// One shared PUBLIC reference evaluator for memory and bounded-memory modes.
/// It never participates in authenticated execution or supplies private inputs.
fn evaluate_public_operation(
    operation: &Operation,
    values: &mut [Option<Fr>],
    public_random_bit: Option<bool>,
) -> Result<()> {
    let eval = |lc: &Lc, values: &[Option<Fr>]| -> Result<Fr> {
        lc.0.iter().try_fold(Fr::ZERO, |sum, (coefficient, index)| {
            values
                .get(*index)
                .and_then(|x| *x)
                .map(|v| sum + *coefficient * v)
                .ok_or(Error::Shape("trace-public-unassigned"))
        })
    };
    match operation {
        Operation::Linear { target, value } => values[*target] = Some(eval(value, values)?),
        Operation::MulAdd {
            target,
            left,
            right,
            add,
        } => {
            values[*target] = Some(eval(left, values)? * eval(right, values)? + eval(add, values)?)
        }
        Operation::AddBits { targets, words } => {
            let mut sum = vec![false; targets.len() + words.len() + 1];
            for word in words {
                let mut carry = false;
                for (i, bit) in word.iter().enumerate() {
                    let value = eval(bit, values)?;
                    if value != Fr::ZERO && value != Fr::ONE {
                        return Err(Error::Shape("trace-public-nonboolean"));
                    }
                    let b = value == Fr::ONE;
                    let a = sum[i];
                    sum[i] = a ^ b ^ carry;
                    carry = (a && b) || (carry && (a ^ b));
                }
                let mut i = word.len();
                while carry {
                    let old = sum[i];
                    sum[i] = !old;
                    carry = old;
                    i += 1;
                }
            }
            if sum[targets.len()..].iter().any(|x| *x) {
                return Err(Error::Shape("trace-add-bits-overflow"));
            }
            for (i, target) in targets.iter().enumerate() {
                values[*target] = Some(Fr::from(sum[i]));
            }
        }
        Operation::AssertZero { value } => {
            if eval(value, values)? != Fr::ZERO {
                return Err(Error::Shape("trace-public-assertion"));
            }
        }
        Operation::RandomBit { target } => {
            values[*target] = Some(Fr::from(
                public_random_bit.ok_or(Error::Shape("trace-public-random-tape-required"))?,
            ));
        }
    }
    Ok(())
}

fn write_header_values(
    writer: &mut impl Write,
    bindings: &Bindings,
    model_variables: usize,
    variables: usize,
    instances: usize,
    inputs: &[usize],
    operations: usize,
) -> Result<()> {
    for hash in [
        &bindings.source_sha256,
        &bindings.model_sha256,
        &bindings.layout_sha256,
    ] {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
        {
            return Err(Error::Shape("trace-binding-sha256"));
        }
    }
    writeln!(
        writer,
        "KPB_TRACE_V1\nFIELD {}\nSOURCE_SHA256 {}\nMODEL_SHA256 {}\nLAYOUT_SHA256 {}\nMODEL_VARIABLES {}\nVARIABLES {}\nINSTANCES {}",
        Fr::MODULUS,
        bindings.source_sha256,
        bindings.model_sha256,
        bindings.layout_sha256,
        model_variables,
        variables,
        instances
    )?;
    write!(writer, "INPUTS {}", inputs.len())?;
    for index in inputs {
        write!(writer, " {index}")?;
    }
    writeln!(writer, "\nOPS {operations}")?;
    Ok(())
}

struct RecordingSink {
    inner: BufWriter<Box<dyn Write>>,
    hash: Sha256,
    bytes: u64,
}
impl Write for RecordingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        if written > buffer.len() {
            return Err(io::Error::other("trace-invalid-sink-write-count"));
        }
        self.hash.update(&buffer[..written]);
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("trace-byte-count-overflow"))?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct ForwardHashWriter<'a> {
    sink: &'a mut RecordingSink,
    hash: &'a mut Sha256,
    bytes: &'a mut u64,
}
impl Write for ForwardHashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.sink.write(buffer)?;
        self.hash.update(&buffer[..written]);
        *self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("trace-byte-count-overflow"))?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

struct HashCountWriter<'a> {
    hash: &'a mut Sha256,
    bytes: &'a mut u64,
}
impl Write for HashCountWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.hash.update(data);
        *self.bytes += data.len() as u64;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_lc(writer: &mut impl Write, value: &Lc) -> io::Result<()> {
    write!(writer, " {}", value.0.len())?;
    for (coefficient, index) in &value.0 {
        write!(writer, " {coefficient} {index}")?;
    }
    Ok(())
}
fn write_operation(writer: &mut impl Write, operation: &Operation) -> io::Result<()> {
    match operation {
        Operation::Linear { target, value } => {
            write!(writer, "LINEAR {target}")?;
            write_lc(writer, value)?;
        }
        Operation::MulAdd {
            target,
            left,
            right,
            add,
        } => {
            write!(writer, "MULADD {target}")?;
            for lc in [left, right, add] {
                write_lc(writer, lc)?;
            }
        }
        Operation::AddBits { targets, words } => {
            write!(writer, "ADD_BITS {}", targets.len())?;
            for i in targets {
                write!(writer, " {i}")?;
            }
            write!(writer, " {}", words.len())?;
            for word in words {
                for lc in word {
                    write_lc(writer, lc)?;
                }
            }
        }
        Operation::AssertZero { value } => {
            write!(writer, "ASSERT_ZERO")?;
            write_lc(writer, value)?;
        }
        Operation::RandomBit { target } => write!(writer, "RANDOM_BIT {target}")?,
    }
    writeln!(writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    struct SharedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        closed: Arc<AtomicBool>,
        short_write: usize,
        fail_after: Option<usize>,
    }
    impl Write for SharedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().unwrap();
            if self.fail_after.is_some_and(|limit| bytes.len() >= limit) {
                return Err(io::Error::other("PUBLIC-test-sink-failure"));
            }
            let remaining = self
                .fail_after
                .map(|limit| limit - bytes.len())
                .unwrap_or(usize::MAX);
            let n = input.len().min(self.short_write).min(remaining);
            bytes.extend_from_slice(&input[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for SharedWriter {
        fn drop(&mut self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
    fn test_sink(
        short_write: usize,
        fail_after: Option<usize>,
    ) -> (Box<dyn Write>, Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>) {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        (
            Box::new(SharedWriter {
                bytes: bytes.clone(),
                closed: closed.clone(),
                short_write,
                fail_after,
            }),
            bytes,
            closed,
        )
    }
    fn test_bindings() -> Bindings {
        Bindings {
            source_sha256: "11".repeat(32),
            model_sha256: "22".repeat(32),
            layout_sha256: "33".repeat(32),
        }
    }
    fn public_fixture_shape(t: &mut TraceBuilder) {
        let a = t.input(1).unwrap();
        let b = t.input(2).unwrap();
        t.assign_muladd(3, a.clone(), b.clone(), Lc::zero())
            .unwrap();
        t.assign_add_bits(&[4, 5], &[vec![a, Lc::zero()], vec![b, Lc::zero()]])
            .unwrap();
        t.assert_zero(Lc::wire(5).minus(&Lc::wire(3))).unwrap();
        t.linear(Lc::wire(4).plus(&Lc::wire(5))).unwrap();
    }
    #[test]
    fn bounded_public_fixture_mode_uses_identical_reference_semantics() {
        let fixture = BTreeMap::from([(1, Fr::ONE), (2, Fr::ONE)]);
        let mut memory = TraceBuilder::new(6, 1).unwrap();
        public_fixture_shape(&mut memory);
        let mut bounded = TraceBuilder::new_public_fixture(6, 1, fixture.clone()).unwrap();
        public_fixture_shape(&mut bounded);
        assert_eq!(
            memory.evaluate_public_fixture(&fixture).unwrap(),
            bounded.evaluate_public_fixture(&fixture).unwrap()
        );
        assert_eq!(memory.operation_count(), bounded.operation_count());
        assert!(bounded.operations().is_none());
        assert!(
            bounded
                .write_text(
                    &mut Vec::new(),
                    &Bindings {
                        source_sha256: "11".repeat(32),
                        model_sha256: "22".repeat(32),
                        layout_sha256: "33".repeat(32)
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn counting_mode_matches_canonical_bytes_and_public_fixture_graph() {
        let fixture = BTreeMap::from([(1, Fr::ONE), (2, Fr::ONE)]);
        let bindings = Bindings {
            source_sha256: "11".repeat(32),
            model_sha256: "22".repeat(32),
            layout_sha256: "33".repeat(32),
        };
        let mut memory = TraceBuilder::new(6, 1).unwrap();
        public_fixture_shape(&mut memory);
        let mut counted = TraceBuilder::new_counting(6, 1).unwrap();
        public_fixture_shape(&mut counted);
        let mut public = TraceBuilder::new_public_fixture(6, 1, fixture.clone()).unwrap();
        public_fixture_shape(&mut public);
        let mut text = Vec::new();
        memory.write_text(&mut text, &bindings).unwrap();
        assert_eq!(
            counted.canonical_text_byte_count(&bindings).unwrap(),
            text.len() as u64
        );
        assert_eq!(
            counted.operation_text_bytes().unwrap(),
            public.operation_text_bytes().unwrap()
        );
        assert_eq!(
            counted.graph_sha256().unwrap(),
            public.public_fixture_graph_sha256().unwrap()
        );
        assert!(counted.evaluate_public_fixture(&fixture).is_err());
        assert!(counted.write_text(&mut Vec::new(), &bindings).is_err());
        assert!(counted.operations().is_none());
    }
    #[test]
    fn header_first_stream_exactly_matches_legacy_text_with_short_writes_and_closes_sink() {
        let bindings = test_bindings();
        let mut memory = TraceBuilder::new(6, 1).unwrap();
        public_fixture_shape(&mut memory);
        let mut expected = Vec::new();
        memory.write_text(&mut expected, &bindings).unwrap();
        let mut counted = TraceBuilder::new_counting(6, 1).unwrap();
        public_fixture_shape(&mut counted);
        let descriptor = counted.export_descriptor(bindings).unwrap();
        assert_eq!(descriptor.inputs(), [1, 2]);
        assert_eq!(descriptor.canonical_text_bytes(), expected.len() as u64);
        let (sink, bytes, closed) = test_sink(7, None);
        let mut direct = TraceBuilder::new_header_stream(descriptor.clone(), sink).unwrap();
        // Only ONE is assigned initially; advertised inputs aren't a dealer.
        assert_eq!(direct.unassigned_model_columns(), vec![1, 2, 3, 4, 5]);
        public_fixture_shape(&mut direct);
        let receipt = direct.finish_header_stream().unwrap();
        assert!(closed.load(Ordering::SeqCst));
        assert_eq!(*bytes.lock().unwrap(), expected);
        assert_eq!(
            receipt.uncompressed_sha256,
            <[u8; 32]>::from(Sha256::digest(&expected))
        );
        assert_eq!(receipt.uncompressed_bytes, expected.len() as u64);
        assert_eq!(receipt.graph_sha256, descriptor.graph_sha256());
        assert_eq!(receipt.operations, descriptor.operations());
    }
    #[test]
    fn header_first_refuses_changed_graph_missing_extra_and_unexpected_inputs_without_end() {
        let mut counted = TraceBuilder::new_counting(3, 1).unwrap();
        let input = counted.input(1).unwrap();
        counted.assign_linear(2, input).unwrap();
        let descriptor = counted.export_descriptor(test_bindings()).unwrap();
        let (sink, bytes, closed) = test_sink(usize::MAX, None);
        let mut changed = TraceBuilder::new_header_stream(descriptor.clone(), sink).unwrap();
        let input = changed.input(1).unwrap();
        changed
            .assign_linear(2, input.scaled(Fr::from(2u64)))
            .unwrap();
        assert!(changed.finish_header_stream().is_err());
        assert!(closed.load(Ordering::SeqCst));
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
        let (sink, bytes, _) = test_sink(usize::MAX, None);
        let mut missing = TraceBuilder::new_header_stream(descriptor.clone(), sink).unwrap();
        missing.input(1).unwrap();
        assert!(missing.finish_header_stream().is_err());
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
        let (sink, bytes, _) = test_sink(usize::MAX, None);
        let mut unexpected = TraceBuilder::new_header_stream(descriptor.clone(), sink).unwrap();
        assert!(unexpected.input(2).is_err());
        assert!(unexpected.finish_header_stream().is_err());
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
        let (sink, bytes, _) = test_sink(usize::MAX, None);
        let mut extra = TraceBuilder::new_header_stream(descriptor, sink).unwrap();
        let input = extra.input(1).unwrap();
        extra.assign_linear(2, input).unwrap();
        assert!(extra.random_bit().is_err());
        assert!(extra.finish_header_stream().is_err());
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
    }
    #[test]
    fn header_first_sink_failure_is_terminal_and_does_not_emit_end() {
        let mut counted = TraceBuilder::new_counting(2, 1).unwrap();
        let input = counted.input(1).unwrap();
        for _ in 0..20_000 {
            counted.linear(input.clone()).unwrap();
        }
        let descriptor = counted.export_descriptor(test_bindings()).unwrap();
        let (sink, bytes, _) = test_sink(17, Some(100));
        let mut stream = TraceBuilder::new_header_stream(descriptor, sink).unwrap();
        let input = stream.input(1).unwrap();
        let mut failed = false;
        for _ in 0..20_000 {
            if stream.linear(input.clone()).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "fixture must reach a real buffered sink write");
        assert!(stream.linear(input).is_err());
        assert!(stream.finish_header_stream().is_err());
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
    }
    #[test]
    fn header_first_count_descriptor_requires_complete_targets_and_explicit_pins() {
        let incomplete = TraceBuilder::new_counting(2, 1).unwrap();
        assert!(incomplete.export_descriptor(test_bindings()).is_err());
        let complete = TraceBuilder::new_counting(1, 1).unwrap();
        let mut wrong = test_bindings();
        wrong.source_sha256 = "bad".to_string();
        assert!(complete.export_descriptor(wrong).is_err());
        let descriptor = complete.export_descriptor(test_bindings()).unwrap();
        let (sink, bytes, _) = test_sink(usize::MAX, None);
        TraceBuilder::new_header_stream(descriptor, sink)
            .unwrap()
            .finish_header_stream()
            .unwrap();
        assert!(bytes.lock().unwrap().ends_with(b"INPUTS 0\nOPS 0\nEND\n"));
    }
    #[test]
    fn header_first_total_text_size_is_checked_before_end() {
        let complete = TraceBuilder::new_counting(1, 1).unwrap();
        let mut descriptor = complete.export_descriptor(test_bindings()).unwrap();
        // Internal negative fixture only: outside this module descriptors have
        // no public constructor or mutable field access.
        descriptor.canonical_bytes += 1;
        let (sink, bytes, _) = test_sink(usize::MAX, None);
        assert!(
            TraceBuilder::new_header_stream(descriptor, sink)
                .unwrap()
                .finish_header_stream()
                .is_err()
        );
        assert!(!bytes.lock().unwrap().ends_with(b"END\n"));
    }
    #[test]
    fn derived_prefix_metadata_requires_real_linear_assignments_without_public_aliases() {
        let mut derived = TraceBuilder::new_counting(5, 3).unwrap();
        let a = derived.input(3).unwrap();
        let b = derived.input(4).unwrap();
        derived.assign_linear(1, a.clone()).unwrap();
        derived.assign_linear(2, b.clone()).unwrap();
        assert_eq!(derived.derived_prefix_lcs().unwrap(), vec![a, b]);
        let mut inputs = TraceBuilder::new_counting(3, 3).unwrap();
        inputs.input(1).unwrap();
        inputs.input(2).unwrap();
        assert!(inputs.derived_prefix_lcs().is_err());
        let mut nonlinear = TraceBuilder::new_counting(4, 2).unwrap();
        let a = nonlinear.input(2).unwrap();
        let b = nonlinear.input(3).unwrap();
        nonlinear.assign_muladd(1, a, b, Lc::zero()).unwrap();
        assert!(nonlinear.derived_prefix_lcs().is_err());
        let mut alias = TraceBuilder::new_counting(4, 3).unwrap();
        let a = alias.input(3).unwrap();
        alias.assign_linear(1, a).unwrap();
        alias.assign_linear(2, Lc::wire(1)).unwrap();
        assert!(alias.derived_prefix_lcs().is_err());
        assert!(
            TraceBuilder::new_counting(3, 3)
                .unwrap()
                .derived_prefix_lcs()
                .is_err()
        );
    }
    #[test]
    fn explicit_public_random_tapes_change_only_reference_values() {
        fn shape(builder: &mut TraceBuilder) -> Result<Lc> {
            let a = builder.random_bit()?;
            let b = builder.random_bit()?;
            let sum = builder.linear(a.plus(&b))?;
            builder.assert_zero(sum.minus(&Lc::constant(Fr::ONE)))?;
            Ok(sum)
        }
        let mut counted = TraceBuilder::new_counting(1, 1).unwrap();
        shape(&mut counted).unwrap();
        let expected = counted.graph_sha256().unwrap();
        for (tape, valid) in [
            (vec![false, true], true),
            (vec![true, false], true),
            (vec![false, false], false),
            (vec![true], false),
            (vec![true, false, true], false),
        ] {
            let mut builder =
                TraceBuilder::new_public_fixture_with_random_tape(1, 1, BTreeMap::new(), tape)
                    .unwrap();
            let output = shape(&mut builder).unwrap();
            assert_eq!(builder.public_fixture_graph_sha256().unwrap(), expected);
            let values = builder.evaluate_public_fixture(&BTreeMap::new());
            assert_eq!(values.is_ok(), valid);
            if let Ok(values) = values {
                assert_eq!(values[output.0[0].1], Fr::ONE);
            }
        }
        let mut missing = TraceBuilder::new_public_fixture(1, 1, BTreeMap::new()).unwrap();
        shape(&mut missing).unwrap();
        assert!(missing.evaluate_public_fixture(&BTreeMap::new()).is_err());
        assert_eq!(missing.public_fixture_graph_sha256().unwrap(), expected);
    }
    #[test]
    fn public_fixture_values_and_refusals_do_not_change_symbolic_ir() {
        let fixtures = [
            BTreeMap::from([(1, Fr::ONE), (2, Fr::ONE)]),
            BTreeMap::from([(1, Fr::ZERO), (2, Fr::ONE)]),
            BTreeMap::from([(1, Fr::from(2u64)), (2, Fr::ONE)]),
        ];
        let mut hashes = Vec::new();
        for (index, fixture) in fixtures.into_iter().enumerate() {
            let mut bounded = TraceBuilder::new_public_fixture(6, 1, fixture.clone()).unwrap();
            public_fixture_shape(&mut bounded);
            hashes.push(bounded.public_fixture_graph_sha256().unwrap());
            assert_eq!(bounded.operation_count(), 4);
            assert_eq!(bounded.evaluate_public_fixture(&fixture).is_ok(), index < 2);
        }
        assert!(hashes.windows(2).all(|pair| pair[0] == pair[1]));
    }
    #[test]
    fn recipes_bind_exact_fresh_columns_and_carry_bits() {
        let mut t = TraceBuilder::new(6, 1).unwrap();
        let a = t.input(1).unwrap();
        let b = t.input(2).unwrap();
        t.assign_muladd(3, a.clone(), b.clone(), a.clone()).unwrap();
        t.assign_add_bits(
            &[4, 5],
            &[vec![a.clone(), Lc::zero()], vec![b.clone(), Lc::zero()]],
        )
        .unwrap();
        assert!(t.assign_linear(3, Lc::zero()).is_err());
        assert!(t.linear(Lc::wire(999)).is_err());
        let v = t
            .evaluate_public_fixture(&BTreeMap::from([(1, Fr::ONE), (2, Fr::ONE)]))
            .unwrap();
        assert_eq!(v[3], Fr::from(2u64));
        assert_eq!(v[4], Fr::ZERO);
        assert_eq!(v[5], Fr::ONE);
        assert!(
            t.evaluate_public_fixture(&BTreeMap::from([(1, Fr::from(2u64)), (2, Fr::ONE)]))
                .is_err()
        );
    }
    #[test]
    fn addbits_never_silently_truncates() {
        let mut t = TraceBuilder::new(4, 1).unwrap();
        let a = t.input(1).unwrap();
        let b = t.input(2).unwrap();
        t.assign_add_bits(&[3], &[vec![a], vec![b]]).unwrap();
        assert!(
            t.evaluate_public_fixture(&BTreeMap::from([(1, Fr::ONE), (2, Fr::ONE)]))
                .is_err()
        );
    }
    #[test]
    fn canonical_lc_and_header_have_no_fixture_values() {
        let mut t = TraceBuilder::new(4, 1).unwrap();
        let a = t.input(2).unwrap();
        let b = t.input(1).unwrap();
        let sum = Lc::canonical([(Fr::ONE, 2), (Fr::ONE, 1), (-Fr::ONE, 2)]);
        assert_eq!(sum, b);
        t.assign_linear(3, a.plus(&b)).unwrap();
        let mut bytes = Vec::new();
        t.write_text(
            &mut bytes,
            &Bindings {
                source_sha256: "1".repeat(64),
                model_sha256: "2".repeat(64),
                layout_sha256: "3".repeat(64),
            },
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("INPUTS 2 1 2\nOPS 1\nLINEAR 3 2 1 1 1 2\nEND\n"));
    }
}
