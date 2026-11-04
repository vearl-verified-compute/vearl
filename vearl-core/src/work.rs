//! NoisyGEMM-T work (VEARL variant, inspired by the PoUW-matmul literature, NOT audited).
//!
//! For a seed sigma: C' = (A+E)(B+F) with E = EL*ER, F = FL*FR of rank r << n.
//! Each output tile (ti,tj) produces an "attempt": hash of the transcript of its
//! partial sums (one per block of k of size r). The attempt wins if hash < target.
//!
//! Verifying a block = recomputing ONE tile: O(T^2 * n) instead of O(n^3),
//! with Merkle openings of the T rows of A and T columns of B against the job's commitments.
//! The honest miner obtains C = A*B by decoding: O(n^2 r) overhead.
use crate::crypto::*;
use serde::{Deserialize, Serialize};

pub const VAL_MAX: i32 = 64;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkParams {
    pub n: usize,
    /// Side of an output tile (16: native shape of the int8 tensor cores).
    pub tile: usize,
    /// Rank of the noise. Noise in {-1,0,1} => |E| <= rank, so A+E fits in int8 if rank <= 63.
    pub rank: usize,
    /// Interval (in k) between two folds of the transcript. Multiple of 16; larger = less hash overhead.
    pub fold_k: usize,
}

/// Words of the folded digest hashed per tile (64 words = 256 bytes).
pub const FOLD_WORDS: usize = 64;

impl WorkParams {
    /// STRUCTURAL constraints (consensus and GPU kernel correctness) + SECURITY constraint coming from
    /// the attack analysis (docs/03): the gain of an attacker who chooses low-rank inputs is
    /// ~ fold_k / rank; we require fold_k <= 1.05 * rank so that no structured input makes an attempt
    /// noticeably cheaper than an honest computation.
    pub fn security_check(&self) -> Result<(), String> {
        if self.tile != 16 {
            return Err("tile must be 16 (int8 tensor-core shape)".into());
        }
        if self.n % 128 != 0 {
            return Err("n must be a multiple of 128".into());
        }
        if self.rank == 0 || self.rank > 63 {
            return Err("rank must be in 1..=63 so that A+E stays within int8 (|A|<=64, |E|<=rank)".into());
        }
        if self.fold_k % 32 != 0 || self.fold_k == 0 || self.n % self.fold_k != 0 {
            return Err("fold_k must be a multiple of 32 (mma m16n8k32 step) dividing n".into());
        }
        if (self.fold_k as f64) > 1.05 * self.rank as f64 {
            return Err(format!(
                "fold_k={} exceeds 1.05*rank={}: structured (low-rank) inputs would make attempts ~{:.1}x cheaper than honest work",
                self.fold_k,
                self.rank,
                self.fold_k as f64 / self.rank as f64
            ));
        }
        Ok(())
    }

    pub const TESTNET: WorkParams = WorkParams { n: 128, tile: 16, rank: 63, fold_k: 64 };
    pub fn tiles(&self) -> usize {
        self.n / self.tile
    }
    pub fn depth(&self) -> usize {
        depth_for(self.n)
    }
    /// Depth of the tree of a whole matrix (C, Z, products, sums): one leaf per ROW (v2 commitment).
    pub fn c_depth(&self) -> usize {
        depth_for(self.n)
    }
}

pub struct Noise {
    pub el: Vec<i32>, // n x r
    pub er: Vec<i32>, // r x n
    pub fl: Vec<i32>, // n x r
    pub fr: Vec<i32>, // r x n
}

pub fn derive_noise(sigma: &Hash, p: &WorkParams) -> Noise {
    let mut hs = blake3::Hasher::new_derive_key("vearl/noise/v1");
    hs.update(sigma);
    let mut xof = hs.finalize_xof();
    let mut gen = |len: usize| -> Vec<i32> {
        let mut buf = vec![0u8; len];
        xof.fill(&mut buf);
        buf.into_iter().map(|b| (b % 3) as i32 - 1).collect() // {-1,0,1}: keeps A+E within int8
    };
    let (n, r) = (p.n, p.rank);
    let el = gen(n * r);
    let er = gen(r * n);
    let fl = gen(n * r);
    let fr = gen(r * n);
    Noise { el, er, fl, fr }
}

/// Row i of A' = A + EL*ER. Loops ordered for contiguous accesses (vectorisable); exact i32 arithmetic.
pub fn noised_a_row(a_row: &[i8], i: usize, noise: &Noise, p: &WorkParams) -> Vec<i32> {
    let (n, r) = (p.n, p.rank);
    let mut v: Vec<i32> = a_row.iter().map(|&x| x as i32).collect();
    for t in 0..r {
        let c = noise.el[i * r + t];
        if c == 0 {
            continue; // would add 0
        }
        let er = &noise.er[t * n..(t + 1) * n];
        for k in 0..n {
            v[k] = v[k].wrapping_add(c.wrapping_mul(er[k]));
        }
    }
    v
}

/// Column j of B' = B + FL*FR.
pub fn noised_b_col(b_col: &[i8], j: usize, noise: &Noise, p: &WorkParams) -> Vec<i32> {
    let (n, r) = (p.n, p.rank);
    let frcol: Vec<i32> = (0..r).map(|t| noise.fr[t * n + j]).collect();
    (0..n)
        .map(|k| {
            let fl = &noise.fl[k * r..(k + 1) * r];
            let mut v = b_col[k] as i32;
            for t in 0..r {
                v = v.wrapping_add(fl[t].wrapping_mul(frcol[t]));
            }
            v
        })
        .collect()
}

/// Transcript of a tile: folds the accumulator every `fold_k` steps of k, then hashes the digest.
pub fn tile_transcript(
    sigma: &Hash,
    ti: usize,
    tj: usize,
    arows: &[Vec<i32>],
    bcols: &[Vec<i32>],
    p: &WorkParams,
) -> (Hash, Vec<i32>) {
    let t = p.tile;
    let mut acc = vec![0i32; t * t];
    let mut fold = [0u32; FOLD_WORDS];
    for s in 0..p.n / p.fold_k {
        let k0 = s * p.fold_k;
        for x in 0..t {
            for y in 0..t {
                let mut sum = 0i32;
                for k in k0..k0 + p.fold_k {
                    sum = sum.wrapping_add(arows[x][k].wrapping_mul(bcols[y][k]));
                }
                acc[x * t + y] = acc[x * t + y].wrapping_add(sum);
            }
        }
        // Fold (XOR + rotation depending on the step) of the CURRENT accumulator:
        // the final digest depends on all the partial sums. [RESEARCH NEEDED: formal analysis]
        fold_step(&mut fold, &acc, s);
    }
    (jackpot_from_fold(sigma, ti, tj, &fold), acc)
}

/// One fold step: XOR of the current accumulator (rotated by `step % 31 + 1` bits) into the 64-word digest.
pub fn fold_step(fold: &mut [u32; FOLD_WORDS], acc: &[i32], step: usize) {
    let rot = (step % 31) as u32 + 1;
    for (i, v) in acc.iter().enumerate() {
        fold[i % FOLD_WORDS] ^= (*v as u32).rotate_left(rot);
    }
}

/// Final hash of the tile. A single blake3 chunk (16 + 32 + 8 + 256 = 312 bytes): easy to reproduce on GPU.
pub fn jackpot_from_fold(sigma: &Hash, ti: usize, tj: usize, fold: &[u32; FOLD_WORDS]) -> Hash {
    let mut hs = blake3::Hasher::new();
    hs.update(JACKPOT_DOMAIN);
    hs.update(sigma);
    hs.update(&(ti as u32).to_le_bytes());
    hs.update(&(tj as u32).to_le_bytes());
    for w in fold {
        hs.update(&w.to_le_bytes());
    }
    *hs.finalize().as_bytes()
}

pub const JACKPOT_DOMAIN: &[u8; 16] = b"vearl/jackpot/v2";

pub struct GemmOut {
    pub jackpots: Vec<Hash>,   // one hash per tile, order (ti, tj)
    pub c_noised: Vec<i32>,    // complete C' (n x n)
}

/// The real GPU/CPU computation: complete noised GEMM + hash of each tile.
pub fn run_noisy_gemm(a: &[i8], b: &[i8], sigma: &Hash, p: &WorkParams) -> (GemmOut, Noise) {
    let noise = derive_noise(sigma, p);
    let n = p.n;
    let arows: Vec<Vec<i32>> = (0..n).map(|i| noised_a_row(&a[i * n..(i + 1) * n], i, &noise, p)).collect();
    let bcols: Vec<Vec<i32>> = (0..n)
        .map(|j| {
            let col: Vec<i8> = (0..n).map(|k| b[k * n + j]).collect();
            noised_b_col(&col, j, &noise, p)
        })
        .collect();
    let (tl, t) = (p.tiles(), p.tile);
    let mut jackpots = Vec::with_capacity(tl * tl);
    let mut c = vec![0i32; n * n];
    for ti in 0..tl {
        for tj in 0..tl {
            let (jp, acc) = tile_transcript(sigma, ti, tj, &arows[ti * t..(ti + 1) * t], &bcols[tj * t..(tj + 1) * t], p);
            jackpots.push(jp);
            for x in 0..t {
                for y in 0..t {
                    c[(ti * t + x) * n + tj * t + y] = acc[x * t + y];
                }
            }
        }
    }
    (GemmOut { jackpots, c_noised: c }, noise)
}

fn matmul(x: &[i32], xr: usize, xc: usize, y: &[i32], yc: usize) -> Vec<i32> {
    let mut o = vec![0i32; xr * yc];
    for i in 0..xr {
        for k in 0..xc {
            let v = x[i * xc + k];
            if v == 0 {
                continue;
            }
            for j in 0..yc {
                o[i * yc + j] = o[i * yc + j].wrapping_add(v.wrapping_mul(y[k * yc + j]));
            }
        }
    }
    o
}

/// C = C' - A*F - E*B - E*F, in O(n^2 r).
pub fn decode(c_noised: &[i32], a: &[i8], b: &[i8], noise: &Noise, p: &WorkParams) -> Vec<i32> {
    let (n, r) = (p.n, p.rank);
    let a32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b32: Vec<i32> = b.iter().map(|&x| x as i32).collect();
    let af = matmul(&matmul(&a32, n, n, &noise.fl, r), n, r, &noise.fr, n);
    let eb = matmul(&noise.el, n, r, &matmul(&noise.er, r, n, &b32, n), n);
    let erfl = matmul(&noise.er, r, n, &noise.fl, r);
    let ef = matmul(&matmul(&noise.el, n, r, &erfl, r), n, r, &noise.fr, n);
    (0..n * n)
        .map(|i| c_noised[i].wrapping_sub(af[i]).wrapping_sub(eb[i]).wrapping_sub(ef[i]))
        .collect()
}

/// Enables the exact GEMM on GPU for `plain_gemm` (worker --gpu). The result is an exact integer: identical to the CPU computation.
static GPU_EXACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_gpu_exact(on: bool) {
    GPU_EXACT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// True when the worker runs with `--gpu` (useful computations such as Render2 tiles then also use the GPU).
pub fn gpu_exact_on() -> bool {
    GPU_EXACT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn plain_gemm(a: &[i8], b: &[i8], n: usize) -> Vec<i32> {
    #[cfg(feature = "gpu")]
    if n >= 256 && GPU_EXACT.load(std::sync::atomic::Ordering::Relaxed) {
        if let Some(c) = crate::gpu::exact_gemm(a, b, n) {
            return c;
        }
    }
    let a32: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b32: Vec<i32> = b.iter().map(|&x| x as i32).collect();
    matmul(&a32, n, n, &b32, n)
}

// ---------------- Probabilistic verification of the result (Freivalds) ----------------

/// Freivalds test on A*B == C: error <= 2^-rounds if C is wrong. O(rounds * n^2).
pub fn freivalds(a: &[i8], b: &[i8], c: &[i32], n: usize, rounds: usize, seed: &Hash) -> bool {
    freivalds_bad_rows(a, b, c, n, rounds, seed).is_empty()
}

/// Rows of C detected as wrong (union over the rounds).
pub fn freivalds_bad_rows(a: &[i8], b: &[i8], c: &[i32], n: usize, rounds: usize, seed: &Hash) -> Vec<usize> {
    let mut hs = blake3::Hasher::new_derive_key("vearl/freivalds/v1");
    hs.update(seed);
    let mut xof = hs.finalize_xof();
    let mut bad = std::collections::BTreeSet::new();
    for _ in 0..rounds {
        let mut bits = vec![0u8; n];
        xof.fill(&mut bits);
        let x: Vec<i64> = bits.iter().map(|b| (b & 1) as i64).collect();
        let bx: Vec<i64> = (0..n).map(|k| (0..n).map(|j| b[k * n + j] as i64 * x[j]).sum()).collect();
        for i in 0..n {
            let l: i64 = (0..n).map(|k| a[i * n + k] as i64 * bx[k]).sum();
            let r: i64 = (0..n).map(|j| c[i * n + j] as i64 * x[j]).sum();
            if l != r {
                bad.insert(i);
            }
        }
    }
    bad.into_iter().collect()
}

/// Locates a wrong entry (i, j): Freivalds for the row, then O(n^2) for the column.
pub fn find_bad_entry(a: &[i8], b: &[i8], c: &[i32], n: usize, seed: &Hash) -> Option<(usize, usize)> {
    let i = *freivalds_bad_rows(a, b, c, n, 32, seed).first()?;
    (0..n).find(|&j| (0..n).map(|k| a[i * n + k] as i32 * b[k * n + j] as i32).sum::<i32>() != c[i * n + j]).map(|j| (i, j))
}

// ---------------- Matrices natives (Native Work) ----------------

pub fn native_matrices(epoch: u64, p: &WorkParams) -> (Vec<i8>, Vec<i8>) {
    let mut hs = blake3::Hasher::new_derive_key("vearl/native/v1");
    hs.update(&epoch.to_le_bytes());
    let mut xof = hs.finalize_xof();
    let mut g = || -> Vec<i8> {
        let mut buf = vec![0u8; p.n * p.n];
        xof.fill(&mut buf);
        buf.into_iter().map(|b| ((b as i32 % 129) - 64) as i8).collect()
    };
    let a = g();
    let b = g();
    (a, b)
}

// ---------------- Commitments and tile proofs ----------------

#[derive(Clone, Debug)]
pub struct CommittedMatrices {
    pub a: Vec<i8>, // row-major
    pub b: Vec<i8>, // row-major
    pub a_tree: MerkleTree, // leaves = rows of A
    pub b_tree: MerkleTree, // leaves = columns of B
}

impl CommittedMatrices {
    pub fn new(a: Vec<i8>, b: Vec<i8>, p: &WorkParams) -> Self {
        let n = p.n;
        let a_tree = MerkleTree::new((0..n).map(|i| leaf_hash(i as u64, &i8_bytes(&a[i * n..(i + 1) * n]))).collect());
        let b_tree = MerkleTree::new(
            (0..n)
                .map(|j| {
                    let col: Vec<i8> = (0..n).map(|k| b[k * n + j]).collect();
                    leaf_hash(j as u64, &i8_bytes(&col))
                })
                .collect(),
        );
        Self { a, b, a_tree, b_tree }
    }
    pub fn a_root(&self) -> Hash {
        self.a_tree.root()
    }
    pub fn b_root(&self) -> Hash {
        self.b_tree.root()
    }
    pub fn col(&self, j: usize, n: usize) -> Vec<i8> {
        (0..n).map(|k| self.b[k * n + j]).collect()
    }
}

/// Bytes of a sequence of i32 values (little-endian).
pub fn i32_bytes(v: &[i32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

/// Leaf `i` of the commitment of an INTEGER matrix (result C, Z of a Gemm, block products and sums): the whole ROW `i`,
/// `leaf_hash(i, row_i as i32 LE)` (v2 commitment, docs/07 section 3). One leaf per row instead of one per element: n hash calls
/// instead of 2 n^2 (measured at n = 1024, one thread: 4 ms against 396 ms), at the price of larger openings (4n bytes).
pub fn row_leaf(i: usize, row: &[i32]) -> Hash {
    leaf_hash(i as u64, &i32_bytes(row))
}

/// Verifies that `row` (n values) is row `i` of the matrix committed by `root`.
pub fn verify_row(root: &Hash, i: usize, row: &[i32], path: &[Hash], p: &WorkParams) -> bool {
    row.len() == p.n && i < p.n && verify_proof(root, row_leaf(i, row), i, path, p.c_depth())
}

/// Row `i` of an n x n matrix stored row-major.
pub fn row_of(c: &[i32], n: usize, i: usize) -> Vec<i32> {
    c[i * n..(i + 1) * n].to_vec()
}

/// Merkle root of `c_tree(c, n)` without keeping the tree.
pub fn c_root(c: &[i32], n: usize) -> Hash {
    MerkleTree::root_of((0..n).map(|i| row_leaf(i, &c[i * n..(i + 1) * n])).collect())
}

/// Same value as `c_root` (kept for calls from threads that are already parallel).
pub fn c_root_st(c: &[i32], n: usize) -> Hash {
    MerkleTree::root_of_st((0..n).map(|i| row_leaf(i, &c[i * n..(i + 1) * n])).collect())
}

pub fn c_tree(c: &[i32], n: usize) -> MerkleTree {
    MerkleTree::new((0..n).map(|i| row_leaf(i, &c[i * n..(i + 1) * n])).collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TileProof {
    pub ti: u32,
    pub tj: u32,
    pub a_rows: Vec<Vec<i8>>,
    pub a_paths: Vec<Vec<Hash>>,
    pub b_cols: Vec<Vec<i8>>,
    pub b_paths: Vec<Vec<Hash>>,
}

impl TileProof {
    /// What a node keeps in memory of the proof of a buried block: only the tile. A real proof always has `tile` rows, so this is never mistaken for one,
    /// and `verify_tile_proof` refuses it.
    pub fn evicted(ti: u32, tj: u32) -> Self {
        TileProof { ti, tj, a_rows: vec![], a_paths: vec![], b_cols: vec![], b_paths: vec![] }
    }

    pub fn is_evicted(&self) -> bool {
        self.a_rows.is_empty()
    }
}

pub fn build_proof(cm: &CommittedMatrices, ti: usize, tj: usize, p: &WorkParams) -> TileProof {
    let (n, t) = (p.n, p.tile);
    let (mut a_rows, mut a_paths, mut b_cols, mut b_paths) = (vec![], vec![], vec![], vec![]);
    for x in 0..t {
        let i = ti * t + x;
        a_rows.push(cm.a[i * n..(i + 1) * n].to_vec());
        a_paths.push(cm.a_tree.proof(i));
        let j = tj * t + x;
        b_cols.push(cm.col(j, n));
        b_paths.push(cm.b_tree.proof(j));
    }
    TileProof { ti: ti as u32, tj: tj as u32, a_rows, a_paths, b_cols, b_paths }
}

/// Verifies a tile proof and returns the recomputed jackpot. Cost: O(T^2 n + n r T).
pub fn verify_tile_proof(proof: &TileProof, sigma: &Hash, a_root: &Hash, b_root: &Hash, p: &WorkParams) -> Option<Hash> {
    let (tl, t, n) = (p.tiles(), p.tile, p.n);
    let (ti, tj) = (proof.ti as usize, proof.tj as usize);
    if ti >= tl || tj >= tl {
        return None;
    }
    if [proof.a_rows.len(), proof.a_paths.len(), proof.b_cols.len(), proof.b_paths.len()].iter().any(|&l| l != t) {
        return None;
    }
    let noise = derive_noise(sigma, p);
    let (mut arows, mut bcols) = (Vec::with_capacity(t), Vec::with_capacity(t));
    for x in 0..t {
        let (row, col) = (&proof.a_rows[x], &proof.b_cols[x]);
        if row.len() != n || col.len() != n {
            return None;
        }
        if row.iter().chain(col.iter()).any(|v| (*v as i32).abs() > VAL_MAX) {
            return None;
        }
        let (i, j) = (ti * t + x, tj * t + x);
        if !verify_proof(a_root, leaf_hash(i as u64, &i8_bytes(row)), i, &proof.a_paths[x], p.depth()) {
            return None;
        }
        if !verify_proof(b_root, leaf_hash(j as u64, &i8_bytes(col)), j, &proof.b_paths[x], p.depth()) {
            return None;
        }
        arows.push(noised_a_row(row, i, &noise, p));
        bcols.push(noised_b_col(col, j, &noise, p));
    }
    Some(tile_transcript(sigma, ti, tj, &arows, &bcols, p).0)
}

/// Jackpot of ONE tile (ti, tj) for seed `sigma`, computed from the complete matrices: this is what a pool server
/// recomputes to verify a share (docs/16). Cost O(T n r), without the full product. Same value as `tile_transcript` /
/// `verify_tile_proof` (test: `pool::tile_jackpot_matches_the_full_run`).
pub fn tile_jackpot(cm: &CommittedMatrices, sigma: &Hash, ti: usize, tj: usize, p: &WorkParams) -> Option<Hash> {
    let (tl, t, n) = (p.tiles(), p.tile, p.n);
    if ti >= tl || tj >= tl {
        return None;
    }
    let noise = derive_noise(sigma, p);
    let (mut arows, mut bcols) = (Vec::with_capacity(t), Vec::with_capacity(t));
    for x in 0..t {
        let (i, j) = (ti * t + x, tj * t + x);
        arows.push(noised_a_row(&cm.a[i * n..(i + 1) * n], i, &noise, p));
        bcols.push(noised_b_col(&cm.col(j, n), j, &noise, p));
    }
    Some(tile_transcript(sigma, ti, tj, &arows, &bcols, p).0)
}

pub fn meets_target(jackpot: &Hash, target: u64) -> bool {
    u64::from_be_bytes(jackpot[..8].try_into().unwrap()) < target
}

/// Merkle tree over the ROWS of an n x n matrix (commitment of the operand A / of the weights W_l).
pub fn rows_tree(m: &[i8], n: usize) -> MerkleTree {
    MerkleTree::new((0..n).map(|i| leaf_hash(i as u64, &i8_bytes(&m[i * n..(i + 1) * n]))).collect())
}

/// Merkle tree over the COLUMNS of an n x n matrix (commitment of the operand B / of the activations X_l).
pub fn cols_tree(m: &[i8], n: usize) -> MerkleTree {
    MerkleTree::new(
        (0..n)
            .map(|j| {
                let col: Vec<i8> = (0..n).map(|k| m[k * n + j]).collect();
                leaf_hash(j as u64, &i8_bytes(&col))
            })
            .collect(),
    )
}
