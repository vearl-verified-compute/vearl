//! Chain: block validation, difficulty, cumulative work, miner (CPU or GPU) for the testnet.
use crate::crypto::*;
use crate::state::*;
use crate::types::*;
use crate::work::*;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// A block cannot be timestamped more than MAX_FUTURE seconds after the validator's local clock.
pub const MAX_FUTURE: u64 = 60;

/// CONSENSUS rule: maximum number of transactions per block (before, only the size of P2P messages bounded a block).
pub const MAX_BLOCK_TXS: usize = 256;

/// CONSENSUS rule: maximum size of the transactions of a block (sum of `bincode(SignedTx)`), 4 MiB. A block thus always fits
/// in a P2P message (16 MiB) together with its tile proof; bounds the worst case of post-quantum transactions (7.9 KiB each) and of
/// row-wise fraud proofs.
pub const MAX_BLOCK_TX_BYTES: u64 = 4 << 20;
/// Level-2 fraud proofs per block. Judging one means recomputing a whole chunk of the job's kernel (up to `MAX_CHUNK_COST3` evaluation
/// units for Render3, about a second on one core for a typical scene and several seconds in the worst case), so a block may carry only
/// a few of them: a flood of bogus proofs cannot stall the nodes that validate the block. The rest waits for the next block.
pub const MAX_L2_FRAUD_PER_BLOCK: usize = 8;

/// Number of level-2 fraud proofs in a list of transactions.
pub fn l2_fraud_count(txs: &[SignedTx]) -> usize {
    txs.iter().filter(|t| matches!(&t.tx.kind, TxKind::L2(crate::l2::L2Tx::Fraud { .. }))).count()
}

/// Serialised size of the transactions of a block (saturating).
pub fn txs_bytes(txs: &[SignedTx]) -> u64 {
    txs.iter().map(|t| bincode::serialized_size(t).unwrap_or(u64::MAX)).fold(0u64, |a, b| a.saturating_add(b))
}

/// State snapshots: one every SNAP_EVERY blocks, the last SNAP_KEEP are kept (plus the genesis one).
/// They are used to reorganise without replaying the whole chain from genesis.
/// 480 s of blocks (16 blocks of 30 s before the block time became 10 s): 64 snapshots reach back 8.5 hours, the horizon of MESS.
pub const SNAP_EVERY: u64 = 480 / BLOCK_TIME;
/// The horizon of the snapshots, in snapshot intervals: SNAP_KEEP * SNAP_EVERY blocks.
pub const SNAP_KEEP: usize = 64;
/// The newest snapshots are kept at every interval, the older ones one in SNAP_THIN (see `validate_inner`).
pub const SNAP_NEAR: usize = 8;
pub const SNAP_THIN: u64 = 8;

/// The tile proof of a block of the native work class is about 42 KB, 95 % of the block, and nothing reads it again once the block is buried: only a
/// peer that syncs asks for old blocks. A node keeps the proofs of the last PROOF_KEEP blocks (more than the snapshots reach back, so a reorganisation
/// never needs a dropped one) and rebuilds the others from the epoch matrices when it has to serve them (`Chain::full_block`), byte for byte what the
/// miner built. At 100,000 blocks this is 4 GB less in memory; the file on disk and the network messages do not change.
pub const PROOF_KEEP: usize = 4096;
/// Epochs whose matrices (about 2 MB each) a node keeps in memory: the current one and a few around it.
pub const NATIVE_KEEP: usize = 24;

/// Slowing down of deep reorganisations (MESS, inspired by ECIP-1100 of Ethereum Classic): a competing chain must have
/// accumulated `f(t)` times the work of ours since the common ancestor, where `t` = time elapsed on OUR chain since that ancestor,
/// `f` grows from 1 to MESS_MAX_FACTOR (cubic smoothing) as t goes from 0 to MESS_T_MAX. SUBJECTIVE rule (local, not consensus) [HYP].
/// Time scale and cap of ECIP-1100 (xcap = 25,132 s, maximum factor 31). OPTIONAL (`node --mess`), disabled by default:
/// measured (tools/fork_test.py), two halves of equal power separated by 90 s no longer merged again with the old setting (2.1 h);
/// on a young network, liveness (a partition heals by itself) takes priority (docs/13 section 3).
pub const MESS_T_MAX: u64 = 25_132;
pub const MESS_MAX_FACTOR: u128 = 31;

/// `f(t)` in thousandths: 1000 + (MAX-1) * 1000 * s^2 (3 - 2 s), s = min(t, MESS_T_MAX) / MESS_T_MAX. Integers only.
pub fn mess_factor_milli(t: u64) -> u128 {
    let s = (t.min(MESS_T_MAX) as u128) * 1_000_000 / MESS_T_MAX as u128; // 0..1e6
    let smooth = s * s / 1_000_000 * (3_000_000 - 2 * s) / 1_000_000; // 0..1e6
    1000 + (MESS_MAX_FACTOR - 1) * smooth / 1000
}

/// True if a competing chain of work `cand_work` (since the common ancestor) replaces ours (`local_work`, which is `elapsed`
/// seconds ahead of the ancestor). Without slowdown (`mess` false): simple comparison of work.
pub fn reorg_accepted(local_work: u128, cand_work: u128, elapsed: u64, mess: bool) -> bool {
    let f = if mess { mess_factor_milli(elapsed) } else { 1000 };
    cand_work.saturating_mul(1000) > local_work.saturating_mul(f)
}

/// GPU job (A,B resident in VRAM) reused from one block to the next as long as the commitments do not change.
#[cfg(feature = "gpu")]
pub type GpuCache = Option<(Hash, Hash, crate::gpu::GpuPool)>;
#[cfg(not(feature = "gpu"))]
pub type GpuCache = ();

/// Difficulty adjustment rule (genesis parameter).
/// - `Asert`: ASERT (aserti3-2d of Bitcoin Cash, 2020) [LIT], half-life `ASERT_HALFLIFE`; target ABSOLUTELY scheduled relative to the
///   first block: an intermittent miner no longer slows the chain down (simulation, docs/13 section 5). Default rule of new geneses.
/// - `Lwma`: LWMA-1 (Zawy) over 30 blocks [LIT]; unbiased in steady state, but a periodic miner slows it down (up to +28 %).
/// - `Ema`: old rule (EMA 1/16, dt bounded to [T/2, 2T]); kept for comparison.
/// - `Fixed`: no retargeting; TESTS and devnets where fast blocks are wanted.
/// (The order of the variants fixes their encoding in the genesis hash: any new variant goes AT THE END.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Retarget {
    Ema,
    Lwma,
    Fixed,
    #[default]
    Asert,
}

/// ASERT half-life: 900 s = 90 blocks of 10 s (chosen by simulation, docs/13 section 5: neutralises the periodic miner, reaction to jumps in
/// power comparable to LWMA-1; a timestamp advance of MAX_FUTURE = 60 s makes the next block only 2^(60/900) = 4.7 % easier).
pub const ASERT_HALFLIFE: u64 = 900;

/// ASERT core, EXACTLY the integer formula of the aserti3-2d specification: `anchor * 2^((dt - ideal*(dh+1)) / half_life)`, exponent
/// in 16.16 fixed point truncated toward zero, 2^frac by the specification's cubic polynomial; then VEARL bounds [2^16, 2^64 - 1].
/// Checked against an independent Python implementation (tools/asert_ref.py), itself checked against the official vectors.
pub fn asert_core(anchor_target: u64, time_delta: i128, height_delta: u64, ideal: u64, halflife: u64) -> u64 {
    let exponent = (time_delta - ideal as i128 * (height_delta as i128 + 1)) * 65536 / halflife as i128; // `/` truncates toward zero
    let shifts = exponent >> 16; // arithmetic shift: floor
    let frac = exponent - shifts * 65536; // [0, 65536)
    let factor = ((195_766_423_245_049i128 * frac + 971_821_376i128 * frac * frac + 5127i128 * frac * frac * frac + (1i128 << 47)) >> 48) + 65536;
    let t = anchor_target as u128 * factor as u128; // < 2^81
    let t = if shifts < 0 {
        if -shifts >= 128 { 0 } else { t >> (-shifts) as u32 }
    } else if shifts == 0 {
        t
    } else if shifts >= 128 || t.leading_zeros() <= shifts as u32 {
        u128::MAX // overflow: beyond any representable target
    } else {
        t << shifts as u32
    };
    (t >> 16).clamp(1 << 16, u64::MAX as u128) as u64
}

/// Target of the block that follows `blocks` with ASERT. Anchor = the FIRST block (its target, and a parent assumed on schedule: `ts_0 - T`); thus
/// the schedule starts from the first mined block, not from the genesis timestamp (often very old).
pub fn asert_next_target(blocks: &[Block], halflife: u64) -> Option<u64> {
    let (first, tip) = (blocks.first()?, blocks.last()?);
    let time_delta = tip.header.timestamp as i128 - (first.header.timestamp as i128 - BLOCK_TIME as i128);
    Some(asert_core(first.header.target, time_delta, (blocks.len() - 1) as u64, BLOCK_TIME, halflife))
}

pub const LWMA_N: usize = 90; // 900 s of blocks, as the half-life of ASERT

/// LWMA-1: mean target of the window x (weighted sum of solve times) / (T x N(N+1)/2).
/// Solve times bounded to [1, 6T]; variation per block bounded to [x0.5; x2]. Integers only.
pub fn lwma_next_target(blocks: &[Block], fallback: u64) -> u64 {
    let len = blocks.len();
    if len < LWMA_N + 1 {
        return fallback;
    }
    let w: Vec<(u64, u64)> = blocks[len - LWMA_N - 1..].iter().map(|b| (b.header.timestamp, b.header.target)).collect();
    lwma_core(&w)
}

/// LWMA-1 over the last LWMA_N + 1 pairs (timestamp, target).
pub fn lwma_core(w: &[(u64, u64)]) -> u64 {
    let (mut num, mut sum_t) = (0u128, 0u128);
    for i in 1..=LWMA_N {
        let st = (w[i].0 as i128 - w[i - 1].0 as i128).clamp(1, 6 * BLOCK_TIME as i128) as u128;
        num += i as u128 * st;
        sum_t += w[i].1 as u128;
    }
    let den = BLOCK_TIME as u128 * (LWMA_N * (LWMA_N + 1) / 2) as u128;
    let next = (sum_t / LWMA_N as u128) * num / den;
    let prev = w[LWMA_N].1 as u128;
    next.clamp(prev / 2, prev.saturating_mul(2)).clamp(1 << 16, u64::MAX as u128) as u64
}

/// HEADER-BASED LIGHT CLIENT (equivalent of an SPV client): follows the chain WITHOUT the state or the transactions. For each
/// header it verifies: chaining (height, parent), increasing timestamp, target = the genesis difficulty rule recomputed on the headers,
/// jackpot under the target, and the TILE PROOF against the work roots carried by the v2 header (`a_root`, `b_root`); for the
/// Native class it recomputes these roots itself (matrices of the epoch). It can then verify a balance through a Merkle path
/// against `accounts_root`.
/// What it does NOT verify (SPV assumption: the majority of the work is honest): the validity of the transactions, that the miner of a
/// useful block really is the worker of the job, the value of `accounts_root` itself. No MESS slowdown and no reorganisation (a single source).
pub struct LightClient {
    cfg: GenesisConfig,
    /// (timestamp, target) of each accepted header.
    hist: Vec<(u64, u64)>,
    tip: Hash,
    last: Option<Header>,
    pub target: u64,
    pub work: u128,
    native: HashMap<u64, (Hash, Hash)>,
}

impl LightClient {
    pub fn new(cfg: &GenesisConfig) -> Self {
        LightClient { cfg: cfg.clone(), hist: vec![], tip: [0u8; 32], last: None, target: cfg.target, work: 0, native: HashMap::new() }
    }

    pub fn height(&self) -> u64 {
        self.hist.len() as u64
    }

    pub fn tip_header(&self) -> Option<&Header> {
        self.last.as_ref()
    }

    fn native_roots(&mut self, epoch: u64) -> (Hash, Hash) {
        let p = self.cfg.params;
        *self.native.entry(epoch).or_insert_with(|| {
            let (a, b) = native_matrices(epoch, &p);
            (rows_tree(&a, p.n).root(), cols_tree(&b, p.n).root())
        })
    }

    /// Validates and appends a header (with the tile proof of its block).
    pub fn apply(&mut self, hd: &Header, proof: &TileProof, now: Option<u64>) -> Result<(), String> {
        let p = self.cfg.params;
        if hd.version != 2 {
            return Err("bad version".into());
        }
        if hd.height != self.height() || hd.prev != self.tip {
            return Err("header does not extend the light chain".into());
        }
        let prev_ts = self.hist.last().map_or(self.cfg.ts, |x| x.0);
        if hd.timestamp <= prev_ts {
            return Err("timestamp not increasing".into());
        }
        if now.map_or(false, |now| hd.timestamp > now + MAX_FUTURE) {
            return Err("timestamp too far in the future".into());
        }
        if hd.target != self.target || !meets_target(&hd.jackpot, hd.target) {
            return Err("wrong target or jackpot above target".into());
        }
        if matches!(hd.class, WorkClass::Native) && (hd.a_root, hd.b_root) != self.native_roots(hd.height / EPOCH_LEN) {
            return Err("native work roots mismatch".into());
        }
        if (proof.ti, proof.tj) != (hd.ti, hd.tj) {
            return Err("tile mismatch".into());
        }
        let sg = sigma(&hd.prev, &hd.miner, &hd.class, hd.extra_nonce, &hd.tx_root, hd.timestamp);
        if verify_tile_proof(proof, &sg, &hd.a_root, &hd.b_root, &p) != Some(hd.jackpot) {
            return Err("invalid tile proof".into());
        }
        // next target: same rule as the full chain, recomputed on the headers alone
        self.hist.push((hd.timestamp, hd.target));
        let ema = next_target(self.target, hd.timestamp - prev_ts);
        self.target = match self.cfg.retarget {
            Retarget::Fixed => self.target,
            Retarget::Ema => ema,
            Retarget::Lwma => {
                if self.hist.len() < LWMA_N + 1 {
                    ema
                } else {
                    lwma_core(&self.hist[self.hist.len() - LWMA_N - 1..])
                }
            }
            Retarget::Asert => {
                let (first, tip) = (self.hist[0], *self.hist.last().unwrap());
                asert_core(first.1, tip.0 as i128 - (first.0 as i128 - BLOCK_TIME as i128), (self.hist.len() - 1) as u64, BLOCK_TIME, ASERT_HALFLIFE)
            }
        };
        self.work += block_work(hd.target);
        self.tip = hd.hash();
        self.last = Some(hd.clone());
        Ok(())
    }

    /// Verifies an account (balance, nonce) against the account root of the LAST accepted header.
    pub fn verify_account(&self, pk: &PubKey, balance: u64, nonce: u64, index: u64, count: u64, path: &[Hash]) -> bool {
        self.last.as_ref().map_or(false, |h| crate::state::verify_account_proof(&h.accounts_root, pk, balance, nonce, index as usize, count as usize, path))
    }
}

#[derive(Clone, Debug)]
pub struct GenesisConfig {
    pub params: WorkParams,
    pub alloc: Vec<(PubKey, u64)>,
    pub ts: u64,
    pub target: u64,
    pub timing: Timing,
    pub retarget: Retarget,
}

/// Devnet genesis. The "faucet" keys are derived from PUBLIC seeds: testnet only.
pub fn devnet_genesis() -> GenesisConfig {
    let alloc = (100u8..103)
        .map(|s| (pubkey(&SigningKey::from_bytes(&[s; 32])), 1_000_000 * COIN))
        .collect();
    GenesisConfig { params: WorkParams::TESTNET, alloc, ts: 1_700_000_000, target: u64::MAX / 2048, timing: Timing::default(), retarget: Retarget::default() }
}

pub struct Chain {
    pub params: WorkParams,
    pub blocks: Vec<Block>,
    pub state: State,
    pub target: u64,
    pub genesis_supply: u64,
    pub retarget: Retarget,
    genesis_ts: u64,
    /// height -> (state after `height` blocks, target); key 0 (genesis) is never evicted.
    snaps: std::collections::BTreeMap<u64, (State, u64)>,
    native: HashMap<u64, Arc<CommittedMatrices>>,
    gpu_cache: GpuCache,
    /// how many recent blocks keep their tile proof in memory (PROOF_KEEP; tests lower it)
    proof_keep: usize,
}

pub fn next_target(target: u64, dt: u64) -> u64 {
    let e = BLOCK_TIME as u128;
    let adj = (dt as u128).clamp(e / 2, e * 2);
    let t = (target as u128) * (15 * e + adj) / (16 * e);
    t.min(u64::MAX as u128).max(1 << 16) as u64
}

/// Work expected for a block of this target (~ 2^64 / target): used for the chain choice (cumulative work).
pub fn block_work(target: u64) -> u128 {
    (1u128 << 64) / (target as u128 + 1)
}

pub struct MineOutput {
    pub block: Block,
    /// Decoded useful result C = A*B of the winning attempt (empty for Native Work).
    pub c: Vec<i32>,
    pub attempts_sigma: u64,
}

/// Everything needed to mine WITHOUT holding a lock on the chain.
#[derive(Clone)]
pub struct MiningTemplate {
    pub params: WorkParams,
    pub height: u64,
    pub prev: Hash,
    pub target: u64,
    pub class: WorkClass,
    pub cm: Arc<CommittedMatrices>,
    /// State at the time of the template: used to compute the account root after applying the block's transactions.
    pub state: Arc<State>,
}

impl Chain {
    pub fn genesis(params: WorkParams, alloc: &[(PubKey, u64)], genesis_ts: u64, initial_target: u64) -> Self {
        // work parameters: structural constraints + security against structured inputs (docs/03)
        params.security_check().expect("work parameters rejected by security_check");
        let mut state = State::default();
        let mut supply = 0;
        for (pk, amt) in alloc {
            state.accounts.entry(*pk).or_default().balance += amt;
            supply += amt;
        }
        let mut snaps = std::collections::BTreeMap::new();
        snaps.insert(0, (state.clone(), initial_target));
        Self { params, blocks: vec![], state, target: initial_target, genesis_supply: supply, retarget: Retarget::default(), genesis_ts, snaps, native: HashMap::new(), gpu_cache: Default::default(), proof_keep: PROOF_KEEP }
    }

    /// Tests: keep the proofs of fewer blocks (must stay above what a reorganisation can touch in the scenario).
    pub fn set_proof_keep(&mut self, keep: usize) {
        self.proof_keep = keep;
    }

    pub fn from_config(c: &GenesisConfig) -> Self {
        let mut chain = Self::genesis(c.params, &c.alloc, c.ts, c.target);
        chain.state.timing = c.timing;
        chain.retarget = c.retarget;
        chain.snaps.insert(0, (chain.state.clone(), chain.target));
        chain
    }

    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }
    pub fn tip_hash(&self) -> Hash {
        self.blocks.last().map(|b| b.header.hash()).unwrap_or([0u8; 32])
    }
    pub fn tip_ts(&self) -> u64 {
        self.blocks.last().map(|b| b.header.timestamp).unwrap_or(self.genesis_ts)
    }
    pub fn total_work(&self) -> u128 {
        self.blocks.iter().map(|b| block_work(b.header.target)).sum()
    }

    pub fn native_committed(&mut self, epoch: u64) -> &CommittedMatrices {
        let p = self.params;
        if !self.native.contains_key(&epoch) && self.native.len() >= NATIVE_KEEP {
            // forget the epoch farthest from this one (every epoch ever validated used to stay: 2 MB each, forever)
            if let Some(far) = self.native.keys().copied().max_by_key(|e| e.abs_diff(epoch)) {
                self.native.remove(&far);
            }
        }
        self.native.entry(epoch).or_insert_with(|| {
            let (a, b) = native_matrices(epoch, &p);
            Arc::new(CommittedMatrices::new(a, b, &p))
        })
    }

    /// Number of epochs whose matrices are held in memory (bounded by NATIVE_KEEP).
    pub fn native_cached(&self) -> usize {
        self.native.len()
    }

    /// Number of state snapshots held (see SNAP_NEAR / SNAP_THIN).
    pub fn snapshot_count(&self) -> usize {
        self.snaps.len()
    }

    fn native_arc(&mut self, epoch: u64) -> Arc<CommittedMatrices> {
        self.native_committed(epoch);
        self.native[&epoch].clone()
    }

    /// The block with its tile proof, also when the proof was dropped from memory (see PROOF_KEEP): rebuilt from the epoch matrices, which is exactly what the
    /// miner did. `cache` holds the matrices built on the way, so a batch of blocks of one epoch builds them once.
    pub fn full_block<'a>(&self, b: &'a Block, cache: &mut HashMap<u64, Arc<CommittedMatrices>>) -> std::borrow::Cow<'a, Block> {
        if !b.proof.is_evicted() {
            return std::borrow::Cow::Borrowed(b);
        }
        let (p, epoch) = (self.params, b.header.height / EPOCH_LEN);
        let cm = match self.native.get(&epoch) {
            Some(c) => c.clone(),
            None => cache
                .entry(epoch)
                .or_insert_with(|| {
                    let (a, bm) = native_matrices(epoch, &p);
                    Arc::new(CommittedMatrices::new(a, bm, &p))
                })
                .clone(),
        };
        std::borrow::Cow::Owned(Block { header: b.header.clone(), proof: build_proof(&cm, b.header.ti as usize, b.header.tj as usize, &p), txs: b.txs.clone() })
    }

    /// Drops the tile proof of the native block that just got PROOF_KEEP blocks deep (other work classes are rare and their data is not rebuildable).
    fn evict_buried_proof(&mut self) {
        let len = self.blocks.len();
        if len > self.proof_keep {
            let b = &mut self.blocks[len - 1 - self.proof_keep];
            if matches!(b.header.class, WorkClass::Native) && !b.proof.is_evicted() {
                b.proof = TileProof::evicted(b.proof.ti, b.proof.tj);
            }
        }
    }

    /// Verifies the supply: balances + escrows + bonds + burn == genesis + emission.
    pub fn check_supply_invariant(&self) -> bool {
        self.state.total_value() + self.state.burned == self.genesis_supply + self.state.minted
    }

    /// Validation without clock check (tests, chain replay).
    pub fn validate_and_apply(&mut self, block: Block) -> Result<(), String> {
        self.validate_inner(block, None)
    }

    /// Validation with local clock `now` (seconds): refuses timestamps too far in the future.
    pub fn validate_and_apply_at(&mut self, block: Block, now: u64) -> Result<(), String> {
        self.validate_inner(block, Some(now))
    }

    fn validate_inner(&mut self, block: Block, now: Option<u64>) -> Result<(), String> {
        let hd = &block.header;
        let p = self.params;
        if hd.version != 2 {
            return Err("bad version".into());
        }
        if hd.height != self.height() {
            return Err("bad height".into());
        }
        if hd.prev != self.tip_hash() {
            return Err("bad prev".into());
        }
        if hd.timestamp <= self.tip_ts() {
            return Err("timestamp not increasing".into());
        }
        if let Some(now) = now {
            if hd.timestamp > now + MAX_FUTURE {
                return Err("timestamp too far in the future".into());
            }
        }
        if hd.target != self.target {
            return Err("wrong target".into());
        }
        // Anti-DoS filter: the ANNOUNCED jackpot must already be under the target. A randomly forged header only passes
        // this test with probability `target`, so the costly verification (Merkle + tile) is avoided.
        if !meets_target(&hd.jackpot, hd.target) {
            return Err("jackpot above target".into());
        }
        if block.txs.len() > MAX_BLOCK_TXS {
            return Err("too many transactions in block".into());
        }
        if txs_bytes(&block.txs) > MAX_BLOCK_TX_BYTES {
            return Err("block transactions too large".into());
        }
        if l2_fraud_count(&block.txs) > MAX_L2_FRAUD_PER_BLOCK {
            return Err("too many level-2 fraud proofs in block".into());
        }
        if hd.tx_root != tx_root(&block.txs) {
            return Err("bad tx_root".into());
        }
        // Work class: where do A and B come from?
        let (a_root, b_root) = match &hd.class {
            WorkClass::Op { job, op } => {
                let j = self.state.progs.get(job).ok_or("unknown program job")?;
                match &j.status {
                    crate::prog::ProgStatus::Working { worker, .. } | crate::prog::ProgStatus::Complete { worker, .. } if *worker == hd.miner => {}
                    _ => return Err("miner is not the active worker of this program".into()),
                }
                j.gemm_roots(*op as usize).ok_or("operation is not an unlocked Gemm")?
            }
            WorkClass::Product { job, i, j: jj, k } => {
                let j = self.state.tiled.get(job).ok_or("unknown tiled job")?;
                match &j.status {
                    crate::tiled::TiledStatus::Claimed { worker, .. } | crate::tiled::TiledStatus::Posted { worker, .. } if *worker == hd.miner => {}
                    _ => return Err("miner is not the active worker of this tiled job".into()),
                }
                j.block_roots(*i as usize, *jj as usize, *k as usize).ok_or("block index out of range")?
            }
            WorkClass::Layer { job, layer } => {
                let j = self.state.mlps.get(job).ok_or("unknown inference job")?;
                match &j.status {
                    crate::mlp::MlpStatus::Working { worker, .. } if *worker == hd.miner => {}
                    _ => return Err("miner is not the active worker of this inference job".into()),
                }
                j.layer_roots(*layer as usize).ok_or("layer not unlocked yet")?
            }
            WorkClass::Native => {
                let cm = self.native_committed(hd.height / EPOCH_LEN);
                (cm.a_root(), cm.b_root())
            }
            WorkClass::Job(id) => {
                let j = self.state.jobs.get(id).ok_or("unknown job")?;
                match &j.status {
                    JobStatus::Claimed { worker, .. } | JobStatus::Posted { worker, .. } if *worker == hd.miner => {}
                    _ => return Err("miner is not the active worker of this job".into()),
                }
                (j.a_root, j.b_root)
            }
        };
        if (hd.a_root, hd.b_root) != (a_root, b_root) {
            return Err("header work roots mismatch".into());
        }
        let sg = sigma(&hd.prev, &hd.miner, &hd.class, hd.extra_nonce, &hd.tx_root, hd.timestamp);
        if block.proof.is_evicted() {
            return Err("missing tile proof".into());
        }
        if (hd.ti as usize, hd.tj as usize) != (block.proof.ti as usize, block.proof.tj as usize) {
            return Err("tile mismatch".into());
        }
        let jp = verify_tile_proof(&block.proof, &sg, &a_root, &b_root, &p).ok_or("invalid tile proof")?;
        if jp != hd.jackpot {
            return Err("jackpot mismatch".into());
        }
        if !meets_target(&jp, hd.target) {
            return Err("jackpot above target".into());
        }
        // Application of the state on a copy (atomic).
        let mut st = self.state.clone();
        for t in &block.txs {
            st.apply_tx(t, hd.height, hd.timestamp, &hd.miner, &p).map_err(|e| format!("tx invalid: {e}"))?;
        }
        st.pay_block_reward(hd.height, &hd.miner, &hd.class);
        if st.accounts_root() != hd.accounts_root {
            return Err("bad accounts_root".into());
        }
        let dt = hd.timestamp - self.tip_ts();
        self.state = st;
        let ema = next_target(self.target, dt);
        self.blocks.push(block);
        self.evict_buried_proof();
        self.target = match self.retarget {
            Retarget::Fixed => self.target,
            Retarget::Ema => ema,
            Retarget::Lwma => lwma_next_target(&self.blocks, ema),
            Retarget::Asert => asert_next_target(&self.blocks, ASERT_HALFLIFE).unwrap_or(self.target),
        };
        let h = self.height();
        if h % SNAP_EVERY == 0 {
            self.snaps.insert(h, (self.state.clone(), self.target));
            // Each snapshot is a complete copy of the state, which keeps growing with the jobs: 65 of them held several GB at 100,000 blocks. The newest
            // SNAP_NEAR stay one every SNAP_EVERY blocks; the older ones are thinned to one every SNAP_EVERY * SNAP_THIN blocks, and nothing is kept
            // further back than the horizon (SNAP_KEEP * SNAP_EVERY blocks) but the genesis. A rewind then replays at most SNAP_EVERY * SNAP_THIN blocks.
            let near_from = h.saturating_sub(SNAP_NEAR as u64 * SNAP_EVERY);
            let horizon = h.saturating_sub(SNAP_KEEP as u64 * SNAP_EVERY);
            self.snaps.retain(|&k, _| k == 0 || (k > horizon && (k > near_from || k % (SNAP_EVERY * SNAP_THIN) == 0)));
        }
        Ok(())
    }

    /// Brings the chain back to height `h` (state, target, blocks) WITHOUT replaying from genesis: start from the last snapshot <= h
    /// then replay the remaining blocks. Returns the removed blocks (h..), in order.
    pub fn rewind_to(&mut self, h: u64) -> Result<Vec<Block>, String> {
        if h > self.height() {
            return Err("cannot rewind above tip".into());
        }
        let snap_h = *self.snaps.range(..=h).next_back().map(|(k, _)| k).ok_or("no snapshot")?;
        let mut tail = self.blocks.split_off(snap_h as usize);
        let (st, tg) = self.snaps[&snap_h].clone();
        self.state = st;
        self.target = tg;
        self.snaps.retain(|k, _| *k <= snap_h);
        let removed = tail.split_off((h - snap_h) as usize);
        // a rewind that starts from the genesis snapshot replays blocks whose proof was dropped from memory: rebuild them first (the removed blocks too, they
        // may have to be replayed if the candidate chain is refused)
        let mut cache = HashMap::new();
        let tail: Vec<Block> = tail.into_iter().map(|b| if b.proof.is_evicted() { self.full_block(&b, &mut cache).into_owned() } else { b }).collect();
        let removed: Vec<Block> = removed.into_iter().map(|b| if b.proof.is_evicted() { self.full_block(&b, &mut cache).into_owned() } else { b }).collect();
        for b in tail {
            self.validate_inner(b, None).map_err(|e| format!("rewind replay: {e}"))?;
        }
        Ok(removed)
    }

    /// Cumulative work of the blocks of a list.
    pub fn work_of(blocks: &[Block]) -> u128 {
        blocks.iter().map(|b| block_work(b.header.target)).sum()
    }

    /// Reorganisation: replaces the blocks `fork_h..` by `cand` (which must connect to it) if the `reorg_accepted` rule allows it.
    /// Atomic: on failure (invalid block, insufficient work, MESS slowdown) the chain is restored. Returns the abandoned blocks.
    pub fn try_reorg(&mut self, fork_h: u64, cand: Vec<Block>, now: u64, mess: bool) -> Result<Vec<Block>, String> {
        if fork_h > self.height() {
            return Err("fork above tip".into());
        }
        let local_work = Self::work_of(&self.blocks[fork_h as usize..]);
        let cand_claimed = Self::work_of(&cand);
        // from genesis, the reference timestamp is that of the first block (the genesis date is arbitrary, often very old)
        let elapsed = match (fork_h, self.blocks.first()) {
            (_, None) => 0,
            (0, Some(b0)) => self.tip_ts().saturating_sub(b0.header.timestamp),
            (h, Some(_)) => self.tip_ts().saturating_sub(self.blocks[h as usize - 1].header.timestamp),
        };
        if !reorg_accepted(local_work, cand_claimed, elapsed, mess) {
            return Err("candidate does not out-work the local chain enough".into());
        }
        let old = self.rewind_to(fork_h)?;
        let mut applied = 0usize;
        let mut failure = None;
        for b in cand {
            if let Err(e) = self.validate_inner(b, Some(now)) {
                failure = Some(e);
                break;
            }
            applied += 1;
        }
        let new_work = Self::work_of(&self.blocks[fork_h as usize..]);
        let ok = failure.is_none() && reorg_accepted(local_work, new_work, elapsed, mess);
        if !ok {
            // restoration: go back to fork_h then replay the old blocks (already valid)
            self.rewind_to(fork_h)?;
            for b in old {
                self.validate_inner(b, None).map_err(|e| format!("restore failed: {e}"))?;
            }
            return Err(failure.map(|e| format!("invalid candidate block {applied}: {e}")).unwrap_or_else(|| "candidate does not out-work the local chain enough".into()));
        }
        Ok(old)
    }

    /// Prepares a mining template (briefly takes &mut self for the native matrices cache).
    pub fn template(&mut self, class: WorkClass, job_data: Option<&CommittedMatrices>) -> Result<MiningTemplate, String> {
        let height = self.height();
        let cm = match &class {
            WorkClass::Native => self.native_arc(height / EPOCH_LEN),
            WorkClass::Op { job, op } => {
                let d = job_data.ok_or("operation data required")?;
                let j = self.state.progs.get(job).ok_or("unknown program job")?;
                let (ra, rb) = j.gemm_roots(*op as usize).ok_or("operation is not an unlocked Gemm")?;
                if d.a_root() != ra || d.b_root() != rb {
                    return Err("operation data does not match commitments".into());
                }
                Arc::new(d.clone())
            }
            WorkClass::Product { job, i, j: jj, k } => {
                let d = job_data.ok_or("block data required")?;
                let j = self.state.tiled.get(job).ok_or("unknown tiled job")?;
                let (ra, rb) = j.block_roots(*i as usize, *jj as usize, *k as usize).ok_or("block index out of range")?;
                if d.a_root() != ra || d.b_root() != rb {
                    return Err("block data does not match commitments".into());
                }
                Arc::new(d.clone())
            }
            WorkClass::Layer { job, layer } => {
                let d = job_data.ok_or("layer data required")?;
                let j = self.state.mlps.get(job).ok_or("unknown inference job")?;
                let (ra, rb) = j.layer_roots(*layer as usize).ok_or("layer not unlocked yet")?;
                if d.a_root() != ra || d.b_root() != rb {
                    return Err("layer data does not match commitments".into());
                }
                Arc::new(d.clone())
            }
            WorkClass::Job(id) => {
                let d = job_data.ok_or("job data required")?;
                let j = self.state.jobs.get(id).ok_or("unknown job")?;
                if d.a_root() != j.a_root || d.b_root() != j.b_root {
                    return Err("job data does not match commitments".into());
                }
                Arc::new(d.clone())
            }
        };
        Ok(MiningTemplate { params: self.params, height, prev: self.tip_hash(), target: self.target, class, cm, state: Arc::new(self.state.clone()) })
    }

    /// Reference miner (CPU). For Job(id), `job_data` = matrices A,B known to the worker.
    pub fn mine(
        &mut self,
        sk: &SigningKey,
        class: WorkClass,
        job_data: Option<&CommittedMatrices>,
        txs: Vec<SignedTx>,
        timestamp: u64,
    ) -> Result<MineOutput, String> {
        let t = self.template(class, job_data)?;
        let mut cache = std::mem::take(&mut self.gpu_cache);
        let r = mine_template(&t, sk, txs, timestamp, None, false, &mut cache);
        self.gpu_cache = cache;
        r
    }

    /// Same protocol, GEMM + tile hashing on GPU (tensor cores). Requires n to be a multiple of 128 and tile 16.
    #[cfg(feature = "gpu")]
    pub fn mine_gpu(
        &mut self,
        sk: &SigningKey,
        class: WorkClass,
        job_data: Option<&CommittedMatrices>,
        txs: Vec<SignedTx>,
        timestamp: u64,
    ) -> Result<MineOutput, String> {
        let t = self.template(class, job_data)?;
        let mut cache = std::mem::take(&mut self.gpu_cache);
        let r = mine_template(&t, sk, txs, timestamp, None, true, &mut cache);
        self.gpu_cache = cache;
        r
    }
}

/// Total number of sigma evaluated by the mining loop of this process (CPU or GPU): used for the hash rate shown by the mining node.
pub static SIGMA_DONE: AtomicU64 = AtomicU64::new(0);

/// Mining loop on a template. `cancel` allows giving up when a new block arrives from the network.
pub fn mine_template(
    t: &MiningTemplate,
    sk: &SigningKey,
    txs: Vec<SignedTx>,
    timestamp: u64,
    cancel: Option<&AtomicBool>,
    use_gpu: bool,
    cache: &mut GpuCache,
) -> Result<MineOutput, String> {
    let (p, cm, class, prev, target, height) = (t.params, &t.cm, &t.class, t.prev, t.target, t.height);
    let miner = pubkey(sk);
    let root = tx_root(&txs);

    // Winner of the search shared by several GPUs: (extra_nonce, jackpots of that sigma); None with one GPU or on the CPU.
    #[cfg(feature = "gpu")]
    let mut found: Option<(u64, (usize, Hash))> = None;
    #[cfg(feature = "gpu")]
    let gpu: Option<&crate::gpu::GpuJob> = if use_gpu {
        let key = (cm.a_root(), cm.b_root());
        if !matches!(cache, Some((ra, rb, _)) if (*ra, *rb) == key) {
            *cache = Some((key.0, key.1, crate::gpu::GpuPool::new(&cm.a, &cm.b, &p).ok_or("gpu init failed")?));
        }
        let pool = &mut cache.as_mut().unwrap().2;
        if pool.jobs.len() > 1 {
            found = Some(search_gpus(&mut pool.jobs, &prev, &miner, class, &root, timestamp, target, cancel)?);
        }
        cache.as_ref().map(|(_, _, g)| &g.jobs[0])
    } else {
        None
    };
    #[cfg(not(feature = "gpu"))]
    {
        let _ = cache;
        if use_gpu {
            return Err("built without the `gpu` feature".into());
        }
    }

    #[cfg(feature = "gpu")]
    let mut queue: std::collections::VecDeque<Option<(usize, Hash)>> = Default::default(); // per extra_nonce of the batch in progress: its first winning tile (index, jackpot), if any
    #[cfg(feature = "gpu")]
    let first_nonce = found.as_ref().map_or(0, |f| f.0);
    #[cfg(not(feature = "gpu"))]
    let first_nonce = 0u64;
    for extra_nonce in first_nonce..u64::MAX {
        if cancel.map_or(false, |c| c.load(Ordering::Relaxed)) {
            return Err("cancelled".into());
        }
        let sg = sigma(&prev, &miner, class, extra_nonce, &root, timestamp);
        #[cfg(not(feature = "gpu"))]
        SIGMA_DONE.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "gpu")]
        if gpu.is_none() {
            SIGMA_DONE.fetch_add(1, Ordering::Relaxed);
        }
        // (first winning tile of this sigma: (index, jackpot), C' if already available)
        let (first_hit, mut c_noised): (Option<(usize, Hash)>, Option<Vec<i32>>) = {
            #[cfg(feature = "gpu")]
            {
                if let Some(g) = gpu {
                    if let Some((_, hit)) = found.take() {
                        // several GPUs: the winning sigma was found by `search_gpus`, its winning tile is already here
                        (Some(hit), None)
                    } else {
                        if queue.is_empty() {
                            let sigs: Vec<Hash> = (0..g.batch_size() as u64).map(|d| sigma(&prev, &miner, class, extra_nonce.wrapping_add(d), &root, timestamp)).collect();
                            // the GPU filters the jackpots against the target: only the winners come back (sorted by sigma, then tile)
                            let hits = g.run_batch_hits(&sigs, target).map_err(|e| format!("gpu error {e}"))?;
                            queue = (0..sigs.len()).map(|d| hits.iter().find(|h| h.0 == d).map(|h| (h.1, h.2))).collect();
                            SIGMA_DONE.fetch_add(sigs.len() as u64, Ordering::Relaxed);
                        }
                        (queue.pop_front().unwrap(), None)
                    }
                } else {
                    let (o, _) = run_noisy_gemm(&cm.a, &cm.b, &sg, &p);
                    (o.jackpots.iter().position(|jp| meets_target(jp, target)).map(|i| (i, o.jackpots[i])), Some(o.c_noised))
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                let (o, _) = run_noisy_gemm(&cm.a, &cm.b, &sg, &p);
                (o.jackpots.iter().position(|jp| meets_target(jp, target)).map(|i| (i, o.jackpots[i])), Some(o.c_noised))
            }
        };
        if let Some((idx, winning_jackpot)) = first_hit {
            let (ti, tj) = (idx / p.tiles(), idx % p.tiles());
            // account root AFTER the block: we apply the transactions then the reward on a copy of the template's state.
            // If a transaction is invalid (the node never includes it, cf. select_txs; the tests build such blocks on purpose),
            // the root is null: the block will be refused by validation, for the reason of the transaction.
            let mut post = (*t.state).clone();
            let mut all_ok = true;
            for tx in &txs {
                if post.apply_tx(tx, height, timestamp, &miner, &p).is_err() {
                    all_ok = false;
                    break;
                }
            }
            post.pay_block_reward(height, &miner, class);
            let header = Header {
                version: 2,
                height,
                prev,
                timestamp,
                miner,
                class: class.clone(),
                extra_nonce,
                ti: ti as u32,
                tj: tj as u32,
                jackpot: winning_jackpot,
                tx_root: root,
                target,
                a_root: cm.a_root(),
                b_root: cm.b_root(),
                accounts_root: if all_ok { post.accounts_root() } else { [0u8; 32] },
            };
            let proof = build_proof(cm, ti, tj, &p);
            // The useful result C = A*B only exists for a job: Native Work decodes nothing.
            let c = if matches!(class, WorkClass::Job(_) | WorkClass::Layer { .. } | WorkClass::Product { .. } | WorkClass::Op { .. }) {
                #[cfg(feature = "gpu")]
                if c_noised.is_none() {
                    // the GPU kernel only returns C' on request: only for the winning block
                    c_noised = gpu.unwrap().run(&sg, true).map_err(|e| format!("gpu error {e}"))?.c_noised;
                }
                let noise = derive_noise(&sg, &p);
                decode(c_noised.as_ref().unwrap(), &cm.a, &cm.b, &noise, &p)
            } else {
                let _ = &mut c_noised;
                Vec::new()
            };
            return Ok(MineOutput { block: Block { header, proof, txs }, c, attempts_sigma: extra_nonce + 1 });
        }
    }
    Err("no solution found".into())
}

/// Search for a winning sigma on SEVERAL GPUs at once (one thread per GPU). The extra_nonce space is cut into batches of
/// `batch_size()` consecutive values; each GPU takes the next free batch when it is done with its own, so a faster GPU simply does
/// more of them. Any extra_nonce whose jackpot meets the target is a valid block (the header carries it), so the first winner found
/// is returned (the lowest extra_nonce if two GPUs finish together). Errors of one GPU stop that GPU only; the search fails when
/// none is left.
#[cfg(feature = "gpu")]
fn search_gpus(
    jobs: &mut [crate::gpu::GpuJob],
    prev: &Hash,
    miner: &PubKey,
    class: &WorkClass,
    root: &Hash,
    timestamp: u64,
    target: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(u64, (usize, Hash)), String> {
    use std::sync::Mutex;
    let bs = jobs[0].batch_size() as u64;
    let next = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let best: Mutex<Option<(u64, (usize, Hash))>> = Mutex::new(None);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for (gi, job) in jobs.iter_mut().enumerate() {
            let (next, stop, best, errors) = (&next, &stop, &best, &errors);
            sc.spawn(move || {
                while !stop.load(Ordering::Relaxed) && !cancel.map_or(false, |c| c.load(Ordering::Relaxed)) {
                    let first = next.fetch_add(1, Ordering::Relaxed).saturating_mul(bs);
                    let sigs: Vec<Hash> = (0..bs).map(|d| sigma(prev, miner, class, first.wrapping_add(d), root, timestamp)).collect();
                    match job.run_batch_hits(&sigs, target) {
                        Ok(hits) => {
                            SIGMA_DONE.fetch_add(sigs.len() as u64, Ordering::Relaxed);
                            // sorted by (sigma, tile): the first one is the lowest winning sigma and its first winning tile
                            if let Some(&(d, idx, jp)) = hits.first() {
                                let mut b = best.lock().unwrap();
                                if b.as_ref().map_or(true, |(n, _)| first + (d as u64) < *n) {
                                    *b = Some((first + d as u64, (idx, jp)));
                                }
                                stop.store(true, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            errors.lock().unwrap().push(format!("GPU #{gi}: error {e}"));
                            return;
                        }
                    }
                }
            });
        }
    });
    if let Some(w) = best.into_inner().unwrap() {
        return Ok(w);
    }
    if cancel.map_or(false, |c| c.load(Ordering::Relaxed)) {
        return Err("cancelled".into());
    }
    Err(format!("gpu error: {}", errors.into_inner().unwrap().join("; ")))
}

/// Helper: builds a signed transaction with the account's current nonce.
pub fn make_tx(chain: &Chain, sk: &SigningKey, fee: u64, kind: TxKind) -> SignedTx {
    let from = pubkey(sk);
    SignedTx::new(Tx { from, nonce: chain.state.nonce(&from), fee, kind }, sk)
}
