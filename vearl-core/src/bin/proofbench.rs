//! proofbench: where the time of a program job at n=1024 goes (computation, Merkle commitments, verification).
use vearl_core::model::*;
use vearl_core::prog::*;
use vearl_core::work::*;
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "models/mnist-mlp.json".into());
    let m = load(std::path::Path::new(&path)).expect("model");
    let n = m.n;
    let (x0, ws, ops) = m.program(0).unwrap();
    let t = Instant::now();
    let (tens, zs) = run_program(&x0, &ws, &ops, n);
    println!("run_program (CPU, plain_gemm): {:.2} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let z = zs[0].as_ref().unwrap();
    let zt = c_tree(z, n);
    println!("c_tree (Z: {} leaves): {:.3} s", n, t.elapsed().as_secs_f64());
    let t = Instant::now();
    let ct = cols_tree(&tens[1], n);
    println!("cols_tree (tensor {n} columns): {:.3} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let rt = rows_tree(&ws[0], n);
    println!("rows_tree (weights): {:.3} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let cm = CommittedMatrices::new(ws[0].clone(), tens[0].clone(), &WorkParams { n, tile: 16, rank: 63, fold_k: 64 });
    println!("CommittedMatrices::new: {:.3} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let ok = freivalds(&ws[0], &tens[0], z, n, 24, &[7u8; 32]);
    println!("freivalds 24 rounds (n={n}): {:.3} s -> {ok}", t.elapsed().as_secs_f64());
    let _ = (zt, ct, rt, cm);
}
