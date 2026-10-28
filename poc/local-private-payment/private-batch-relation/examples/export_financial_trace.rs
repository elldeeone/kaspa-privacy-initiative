//! Public source-only financial program export. No wallet body/WTNS is read.
//! Model/source pins must come from the independently selected actual model.
#[path = "qualify_joint_core.rs"]
mod qualifier;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::gr1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisMode,
};
use kpi_private_batch_relation::{
    Context,
    joined_source::JoinedSourceCircuit,
    joint_trace,
    state_trace::{PublicHistory, PublicNullifierLeaf},
    trace::{Bindings, Lc, TraceBuilder},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Instant,
};
type E = Box<dyn std::error::Error>;
struct HashWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.hash.update(&b[..n]);
        self.bytes = self
            .bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("public byte overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn gzip(
    path: &Path,
    producer: impl FnOnce(Box<dyn Write>) -> Result<(String, u64), E>,
) -> Result<Value, E> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut p = Command::new("/usr/bin/gzip")
        .args(["-1", "-n", "-c"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut out = p.stdout.take().ok_or("gzip stdout")?;
    let reader = thread::spawn(move || -> io::Result<(String, u64)> {
        let mut w = HashWriter {
            inner: BufWriter::new(file),
            hash: Sha256::new(),
            bytes: 0,
        };
        let mut b = [0; 65536];
        loop {
            let n = out.read(&mut b)?;
            if n == 0 {
                break;
            }
            w.write_all(&b[..n])?;
        }
        w.flush()?;
        w.inner.get_ref().sync_all()?;
        Ok((hex::encode(w.hash.finalize()), w.bytes))
    });
    let raw = producer(Box::new(BufWriter::new(
        p.stdin.take().ok_or("gzip stdin")?,
    )));
    let status = p.wait()?;
    let container = reader.join().map_err(|_| "gzip reader panic")??;
    let raw = raw?;
    if !status.success() {
        return Err("gzip process failed".into());
    }
    Ok(
        json!({"file":path.file_name().ok_or("artifact name")?.to_string_lossy(),"sha256":raw.0,"uncompressed_bytes":raw.1,"container_sha256":container.0,"container_bytes":container.1,"single_gzip_member":true}),
    )
}
fn cs(lcs: bool) -> ConstraintSystemRef<Fr> {
    let c = ConstraintSystem::new_ref();
    c.set_optimization_goal(OptimizationGoal::Constraints);
    c.set_mode(SynthesisMode::Prove {
        construct_matrices: false,
        generate_lc_assignments: lcs,
    });
    c
}
fn hash32(v: &Value) -> Result<[u8; 32], E> {
    Ok(hex::decode(v.as_str().ok_or("public hash")?)?
        .try_into()
        .map_err(|_| "public hash length")?)
}
fn history(v: &Value) -> Result<PublicHistory, E> {
    Ok(PublicHistory {
        commitments: v["commitments_hex32"]
            .as_array()
            .ok_or("public commitments")?
            .iter()
            .map(hash32)
            .collect::<Result<_, _>>()?,
        nullifiers: v["nullifiers"]
            .as_array()
            .ok_or("public nullifiers")?
            .iter()
            .map(|n| {
                Ok(PublicNullifierLeaf {
                    value: hash32(&n["value_hex32"])?,
                    successor: hash32(&n["successor_hex32"])?,
                    successor_index: u32::try_from(
                        n["successor_index"].as_u64().ok_or("public index")?,
                    )?,
                })
            })
            .collect::<Result<_, E>>()?,
    })
}
fn declare(t: &mut TraceBuilder, columns: &[Vec<usize>; 3]) -> Result<(), E> {
    for owner in columns {
        for i in owner {
            t.input(*i)?;
        }
    }
    Ok(())
}
fn construct(
    t: &mut TraceBuilder,
    context: &Context,
    history: &PublicHistory,
    template: &kpi_private_batch_relation::BatchCircuit,
    layout: &kpi_private_batch_relation::BatchLayout,
) -> Result<(), E> {
    let p = joint_trace::construct(t, context, history, &layout.owner_fields)?;
    let c = cs(true);
    let actual = template.clone().generate_with_trace(c.clone(), t, &p)?;
    if actual != *layout || c.num_variables() != layout.final_joint_columns.end {
        return Err("actual model layout changed".into());
    }
    Ok(())
}
fn main() -> Result<(), E> {
    let mut a = std::env::args().skip(1).collect::<Vec<_>>();
    let prepare = a.first().map(String::as_str) == Some("prepare");
    if prepare {
        a.remove(0);
    }
    if a.len() != if prepare { 6 } else { 7 } {
        return Err("usage: export_financial_trace PUBLIC-CONTEXT-HISTORY.json PUBLIC-SIGNATURE-MATRIX.json MATRIX-SHA MAP-SHA EXPECTED-QUERY-MODEL-SHA EXPECTED-SOURCE-SHA FRESH-OUT".into());
    }
    let source_pin = a[if prepare { 4 } else { 5 }].clone();
    let mut pins = vec![&a[2], &a[3], &source_pin];
    if !prepare {
        pins.push(&a[4]);
    }
    for s in pins {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("independent expected pin format".into());
        }
    }
    let root = PathBuf::from(&a[if prepare { 5 } else { 6 }]);
    fs::create_dir(&root)?;
    let started = Instant::now();
    let v: Value = serde_json::from_slice(&fs::read(&a[0])?)?;
    let context = qualifier::context(
        hex::decode(v["context_hex"].as_str().ok_or("public context")?)?
            .try_into()
            .map_err(|_| "context length")?,
    );
    let history = history(&v)?;
    history.validate(&context)?;
    let signature = auth::interchange::signature_matrix(&fs::read(&a[1])?, &a[2], &a[3])?;
    let sig_vars = signature.variables().map_err(|_| "signature variables")?;
    let source = JoinedSourceCircuit::from_public_context(
        context.clone(),
        core::array::from_fn(|_| signature.clone()),
    )?;
    let template = source.public_component_template();
    let c = cs(false);
    let layout = template.clone().generate_with_layout(c.clone())?;
    let core = c.num_variables();
    drop(c);
    let variables = core
        .checked_add(3 * (sig_vars - 1))
        .ok_or("model overflow")?;
    let columns: [Vec<usize>; 3] = core::array::from_fn(|owner| {
        let mut c = (3 + 66 * owner..3 + 66 * (owner + 1)).collect::<Vec<_>>();
        c.extend(layout.owner_local_columns[owner].start..layout.owner_local_columns[owner].end);
        let at = core + owner * (sig_vars - 1);
        c.extend(at..at + sig_vars - 1);
        c
    });
    for cols in &columns {
        if cols.windows(2).any(|p| p[0] >= p[1]) || cols.iter().any(|i| *i < 3 || *i >= variables) {
            return Err("owner layout shape".into());
        }
    }
    let layout_receipt = gzip(&root.join("layout.txt.gz"), |sink| {
        let mut w = HashWriter {
            inner: sink,
            hash: Sha256::new(),
            bytes: 0,
        };
        writeln!(
            w,
            "KPB_TRACE_LAYOUT_V1\nMODEL_VARIABLES {variables}\nINSTANCES 3\nOWNERS 3"
        )?;
        for (owner, cols) in columns.iter().enumerate() {
            write!(w, "OWNER owner{owner} {}", cols.len())?;
            for i in cols {
                write!(w, " {i}")?;
            }
            writeln!(w)?;
        }
        writeln!(w, "END")?;
        w.flush()?;
        Ok((hex::encode(w.hash.finalize()), w.bytes))
    })?;
    let mut counted = TraceBuilder::new_counting(variables, 3)?;
    declare(&mut counted, &columns)?;
    construct(&mut counted, &context, &history, &template, &layout)?;
    counted.require_complete_model()?;
    let prefix = counted.derived_prefix_lcs()?;
    let expected_graph = hex::encode(counted.graph_sha256()?);
    let expected_ops = counted.operation_count();
    let mut recipe = Vec::new();
    recipe.extend_from_slice(b"KPI_PREFIX_LC_V1");
    recipe.extend(Fr::MODULUS.to_bytes_le());
    for n in [variables, 3, prefix.len()] {
        recipe.extend((n as u64).to_le_bytes());
    }
    for Lc(terms) in &prefix {
        recipe.extend((terms.len() as u64).to_le_bytes());
        for (c, i) in terms {
            recipe.extend(c.into_bigint().to_bytes_le());
            recipe.extend((*i as u64).to_le_bytes());
        }
    }
    let recipe_sha = hex::encode(Sha256::digest(&recipe));
    fs::write(root.join("PREFIX-RECIPE.bin"), &recipe)?;
    if prepare {
        let manifest = json!({"schema":"kpb-financial-trace-independent-preparation/v1","classification":"PUBLIC_LAYOUT_RECIPE_AND_GRAPH_ONLY_NO_MODEL_PLACEHOLDER","source_sha256":source_pin,"model_variables":variables,"model_instances":3,"trace_variables":counted.variables(),"operations":expected_ops,"operation_text_bytes":counted.operation_text_bytes()?,"graph_sha256":expected_graph,"layout":layout_receipt,"prefix_recipe":{"file":"PREFIX-RECIPE.bin","sha256":recipe_sha,"bytes":recipe.len(),"outputs":prefix.len()},"original_signature_matrix_sha256":a[2],"original_signature_mapping_sha256":a[3],"owner_input_counts":columns.iter().map(Vec::len).collect::<Vec<_>>(),"public_context_sha256":hex::encode(Sha256::digest(context.bytes())),"elapsed_seconds":started.elapsed().as_secs_f64(),"model_identity_claim":false,"private_owner_material_read":false});
        fs::write(
            root.join("PUBLIC-TRACE-PREPARATION.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        println!(
            "{}",
            json!({"stage":"independent_actual_layout_recipe_preparation_complete","output":root,"layout_sha256":manifest["layout"]["sha256"],"prefix_recipe_sha256":recipe_sha,"graph_sha256":expected_graph})
        );
        return Ok(());
    }
    let bindings = Bindings {
        source_sha256: source_pin,
        model_sha256: a[4].clone(),
        layout_sha256: layout_receipt["sha256"]
            .as_str()
            .ok_or("layout pin")?
            .to_owned(),
    };
    let descriptor = counted.export_descriptor(bindings)?;
    let expected_bytes = descriptor.canonical_text_bytes();
    drop(counted);
    println!(
        "{}",
        json!({"stage":"actual_financial_trace_counted","model_variables":variables,"operations":expected_ops,"uncompressed_bytes":expected_bytes,"graph_sha256":expected_graph,"prefix_recipe_sha256":recipe_sha})
    );
    io::stdout().flush()?;
    let trace_receipt = gzip(&root.join("trace.txt.gz"), |sink| {
        let mut t = TraceBuilder::new_header_stream(descriptor, sink)?;
        declare(&mut t, &columns)?;
        construct(&mut t, &context, &history, &template, &layout)?;
        let done = t.finish_header_stream()?;
        if hex::encode(done.graph_sha256) != expected_graph || done.operations != expected_ops {
            return Err("header-first complete graph changed".into());
        }
        Ok((
            hex::encode(done.uncompressed_sha256),
            done.uncompressed_bytes,
        ))
    })?;
    let manifest = json!({"schema":"kpb-financial-authenticated-trace-gzip/v1","classification":"PUBLIC_PROGRAM_NO_OWNER_BODY_WTNS_OR_PROOF","source_sha256":a[5],"model_sha256":a[4],"model_variables":variables,"model_instances":3,"operations":expected_ops,"expected_graph_sha256":expected_graph,"trace":trace_receipt,"layout":layout_receipt,"prefix_recipe":{"file":"PREFIX-RECIPE.bin","sha256":recipe_sha,"bytes":recipe.len(),"outputs":prefix.len()},"original_signature_matrix_sha256":a[2],"original_signature_mapping_sha256":a[3],"owner_input_counts":columns.iter().map(Vec::len).collect::<Vec<_>>(),"public_context_sha256":hex::encode(Sha256::digest(context.bytes())),"elapsed_seconds":started.elapsed().as_secs_f64(),"private_owner_body_read":false,"aggregate_proof_or_financial_acceptance":false});
    fs::write(
        root.join("PUBLIC-TRACE-MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::File::open(&root)?.sync_all()?;
    println!(
        "{}",
        json!({"stage":"actual_financial_compressed_trace_export_complete","elapsed_seconds":started.elapsed().as_secs_f64(),"output":root})
    );
    Ok(())
}
