//! Public synthetic buffer-size control for Ark's variable-base MSM.
//! It uses no circuit, assignment, proving key, proof, or private input.

use ark_bn254::{G1Projective, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use std::{env, fs, hint::black_box, time::Instant};

struct BenchMsm<G: VariableBaseMSM> {
    scalars: Vec<<G::ScalarField as PrimeField>::BigInt>,
    bases: Vec<G::MulBase>,
    result: G,
    buffer: usize,
}

impl<G: VariableBaseMSM> BenchMsm<G> {
    fn new(buffer: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut scalars = Vec::new();
        scalars.try_reserve_exact(buffer)?;
        let mut bases = Vec::new();
        bases.try_reserve_exact(buffer)?;
        Ok(Self {
            scalars,
            bases,
            result: G::zero(),
            buffer,
        })
    }

    fn add(&mut self, base: G::MulBase, scalar: <G::ScalarField as PrimeField>::BigInt) {
        self.bases.push(base);
        self.scalars.push(scalar);
        if self.scalars.len() == self.buffer {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.scalars.is_empty() {
            self.result += G::msm_bigint(&self.bases, &self.scalars);
            self.scalars.clear();
            self.bases.clear();
        }
    }

    fn finalize(mut self) -> G {
        self.flush();
        self.result
    }
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

fn run<G>(count: usize, buffer: usize, base: G::MulBase) -> Result<(), Box<dyn std::error::Error>>
where
    G: VariableBaseMSM,
    G::MulBase: Copy,
    G::ScalarField: From<u64>,
{
    let started = Instant::now();
    let mut msm = BenchMsm::<G>::new(buffer)?;
    for index in 0..count {
        let scalar = G::ScalarField::from((index as u64).wrapping_add(1)).into_bigint();
        msm.add(base, scalar);
    }
    black_box(msm.finalize());
    println!(
        "{{\"count\":{count},\"buffer\":{buffer},\"elapsed_seconds\":{},\"peak_rss_kib\":{},\"swap_kib\":{}}}",
        started.elapsed().as_secs_f64(),
        proc_status_kib("VmHWM:")?,
        proc_status_kib("VmSwap:")?,
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: measure_msm_buffers g1|g2 COUNT 1024|65536|262144".into());
    }
    let count: usize = args[1].parse()?;
    if count == 0 {
        return Err("count must be nonzero".into());
    }
    let buffer: usize = args[2].parse()?;
    if !matches!(buffer, 1024 | 65536 | 262144) {
        return Err("buffer is not in the reviewed benchmark set".into());
    }
    match args[0].as_str() {
        "g1" => run::<G1Projective>(count, buffer, G1Projective::generator().into_affine()),
        "g2" => run::<G2Projective>(count, buffer, G2Projective::generator().into_affine()),
        _ => Err("group must be g1 or g2".into()),
    }
}
