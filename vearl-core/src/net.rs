//! Testnet P2P network: TCP + length-prefixed bincode messages, block/transaction gossip,
//! synchronisation, chain choice by CUMULATIVE WORK (reorg by replay), mempool, basic anti-abuse.
//!
//! Encrypted/authenticated Noise XX channel (see secure.rs), pinnable peer keys, admission limits per IP and
//! per /16, misbehaviour scoring. Not provided: real Sybil defence, robust discovery, NAT traversal.
use crate::chain::*;
use crate::crypto::*;
use crate::types::*;
use crate::mlp::*;
use crate::secure::*;
use crate::prog::*;
use crate::tiled::*;
use crate::work::*;
use bincode::Options;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_MSG: usize = MAX_APP_MSG;
pub const BATCH: usize = 64;
pub const MAX_OUT: usize = 6;
pub const MAX_IN: usize = 24;
const MAX_PER_IP: usize = 2;
const MAX_PER_SUBNET: usize = 4;
const MAX_HANDSHAKES: usize = 64;
/// Simultaneous inbound connections of every kind (peers AND short requests of wallets and tools), and per IP address.
const MAX_CONNS: usize = 256;
const MAX_CONN_PER_IP: usize = 16;

// Limits of this process (`set_inbound_limits`: the node's --max-inbound, --max-per-ip, --max-per-subnet, --max-conns). The defaults are the
// constants above. They bound the PEERS (nodes that exchange blocks): a public seed raises them. Wallets and command-line tools are not peers:
// they are bounded by the two connection limits only, so that a wallet on an address that already hosts two nodes is no longer refused.
static LIM_IN: AtomicUsize = AtomicUsize::new(MAX_IN);
static LIM_IP: AtomicUsize = AtomicUsize::new(MAX_PER_IP);
static LIM_NET: AtomicUsize = AtomicUsize::new(MAX_PER_SUBNET);
static LIM_CONNS: AtomicUsize = AtomicUsize::new(MAX_CONNS);
static LIM_CONN_IP: AtomicUsize = AtomicUsize::new(MAX_CONN_PER_IP);

/// Sets the admission limits of this process: peers (total, per IP, per /16) and simultaneous connections (total; the per-IP limit follows,
/// at least 16). A zero keeps the default of that limit.
pub fn set_inbound_limits(max_in: usize, per_ip: usize, per_subnet: usize, max_conns: usize) {
    let put = |a: &AtomicUsize, v: usize, d: usize| a.store(if v == 0 { d } else { v }, Ordering::SeqCst);
    put(&LIM_IN, max_in, MAX_IN);
    put(&LIM_IP, per_ip, MAX_PER_IP);
    put(&LIM_NET, per_subnet, MAX_PER_SUBNET);
    put(&LIM_CONNS, max_conns, MAX_CONNS);
    LIM_CONN_IP.store(LIM_IP.load(Ordering::SeqCst).max(MAX_CONN_PER_IP), Ordering::SeqCst);
}

/// Refusals are logged at most once every 10 s, with the number of refusals since the last line (a flood must not flood the log).
fn note_refusal(why: &str, ip: &IpAddr) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, Ordering::SeqCst);
    let mut last = LAST.lock().unwrap();
    if last.map_or(true, |t| t.elapsed() >= Duration::from_secs(10)) {
        *last = Some(Instant::now());
        eprintln!("[net] refused {} inbound connection(s) in the last seconds (latest: {ip}, {why})", COUNT.swap(0, Ordering::SeqCst));
    }
}

/// One inbound connection counted in `Shared` (total and per IP) until it ends.
struct ConnGuard {
    sh: Arc<Shared>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.sh.conns.fetch_sub(1, Ordering::SeqCst);
        let mut m = self.sh.conn_ips.lock().unwrap();
        if let Some(c) = m.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}
const BAN_SCORE: u32 = 100;
pub const MEMPOOL_MAX: usize = 5_000;
pub const MEMPOOL_PER_SENDER: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Msg {
    Hello { node_id: u64, genesis: Hash, height: u64, work: u128, listen: Option<String> },
    GetBlocks { from: u64 },
    Blocks(Vec<Block>),
    NewBlock(Block),
    NewTx(SignedTx),
    GetPeers,
    Peers(Vec<String>),
    GetStatus,
    /// `params` = (n, tile, rank, fold_k) of the chain: clients (CLI) adapt to it instead of assuming n=128.
    Status { height: u64, tip: Hash, work: u128, mempool: usize, peers: usize, burned: u64, minted: u64, params: (u64, u64, u64, u64) },
    GetAccount(PubKey),
    Account { balance: u64, nonce: u64, next_nonce: u64 },
    Ack { ok: bool, info: String },
    /// The client deposits A and B with a worker (off-chain); the worker recognises them through the job's Merkle roots.
    PutJob { a: Vec<i8>, b: Vec<i8> },
    GetJob(JobId),
    JobInfo { status: String, escrow_net: u64, worker: Option<PubKey>, best_bid: Option<(PubKey, u64)>, auction_end_ts: u64, fetches: Vec<(u32, u32)> },
    /// Entries already served on-chain for this job (i, j, value, Merkle path).
    GetServed(JobId),
    /// (i, j, served row i, path): the requested entry is `row[j]`.
    Served { entries: Vec<(u32, u32, Vec<i32>, Vec<Hash>)> },
    GetRep(PubKey),
    Rep { done: u32, slashed: u32, expired: u32 },
    GetResult(JobId),
    JobResult { c: Vec<i32> },
    /// The client deposits X_0 and the weights W_l of an inference job with a worker (off-chain).
    PutMlp { x0: Vec<i8>, ws: Vec<Vec<i8>> },
    GetMlp(JobId),
    MlpInfo { status: String, layers_posted: u8, layers_total: u8, escrow_net: u64, posted: Vec<(Hash, Hash)> },
    GetLayer { job: JobId, layer: u8 },
    LayerData { z: Vec<i32>, x: Vec<i8> },
    /// Deposit of the matrices A (M x K) and B (K x N) of a block-product job with a worker (off-chain).
    PutTiled { a: Vec<i8>, b: Vec<i8>, dims: (u8, u8, u8) },
    GetTiled(JobId),
    TiledInfo { status: String, dims: (u8, u8, u8), products: u32, posted: bool, escrow_net: u64, product_roots: Vec<Hash>, c_roots: Vec<Hash> },
    /// Group (i, j): the Kb products P_ijk and the sum C_ij (int32, n x n each).
    GetTiledGroup { job: JobId, i: u8, j: u8 },
    TiledGroup { products: Vec<Vec<i32>>, c: Vec<i32> },
    /// Deposit of the input X_0 and the weights of a tensor program with a worker (off-chain).
    PutProg { x0: Vec<i8>, ws: Vec<Vec<i8>> },
    GetProg(JobId),
    ProgInfo { status: String, posted: u8, total: u8, escrow_net: u64, roots: Vec<(Hash, Hash)> },
    GetOp { job: JobId, op: u8 },
    OpData { z: Option<Vec<i32>>, x: Vec<i8> },
    /// Level 2 (Monte Carlo, rendering): state of a job (with its kernel, so that the client can recompute a chunk) and output of a chunk.
    GetL2(JobId),
    L2Info { status: String, chunks: u32, escrow_net: u64, root: Option<Hash>, kernel: crate::l2::Kernel },
    GetL2Chunk { job: JobId, chunk: u32 },
    L2ChunkData { out: Vec<u8>, path: Vec<Hash> },
    /// Rest of the weights of a program whose first deposit (`PutProg`) has already been made: avoids messages larger than 16 MiB when
    /// a large network has many weight matrices (n = 1024: 1 MiB each). The weights are appended in order.
    PutProgMore { x0_root: Hash, ws: Vec<Vec<i8>> },
    /// MODEL REGISTRY (off-chain, per worker): weight blocks are deposited ONCE, then found by their Merkle root
    /// (the one committed on-chain in `w_roots`). A job then only sends its input (`PutProgRef`).
    PutModel { ws: Vec<Vec<i8>> },
    /// Which weight-block roots does this worker already know?
    HasModel { roots: Vec<Hash> },
    ModelHave { have: Vec<bool> },
    /// Input X_0 of a program whose weights are already in the registry (referenced by root).
    PutProgRef { x0: Vec<i8>, w_roots: Vec<Hash> },
    /// Deposit by ROWS of a large block product (a message is bounded to 16 MiB): `which` 0 = A (M x K), 1 = B (K x N);
    /// `row_start` = first row of `data` (whole rows); `key` = session identifier chosen by the client.
    PutTiledStage { key: Hash, which: u8, dims: (u8, u8, u8), row_start: u32, data: Vec<i8> },
    /// End of the deposit: all the rows of A and B have arrived -> the data set is registered.
    PutTiledDone { key: Hash },
    /// A product P_ijk (int32, n x n) of a finished job: the client verifies it (Freivalds) and sums it itself.
    GetTiledProduct { job: JobId, i: u8, j: u8, k: u8 },
    TiledProduct { p: Vec<i32> },
    /// The sum C_ij (int32, n x n) of a finished job: this is all the client downloads on the fast path.
    GetTiledSum { job: JobId, i: u8, j: u8 },
    TiledSum { c: Vec<i32> },
    /// LIGHT CLIENT: headers and tile proofs from height `from` (at most BATCH), without the transactions.
    GetHeaders { from: u64 },
    Headers(Vec<(Header, crate::work::TileProof)>),
    /// Merkle proof of an account against `accounts_root` of the header at height `height` (the tip). `Ack { ok: false }` if the account
    /// does not exist (no proof of absence in this version).
    GetAccountProof(PubKey),
    AccountProof { height: u64, tip: Hash, balance: u64, nonce: u64, index: u64, count: u64, path: Vec<Hash> },
    /// Like `GetOp`, for SEVERAL operations in one round trip and as a BOUNDING BOX: only the top-left corner (rows x columns)
    /// outside of which everything is zero is sent, for the output and for Z. The worker answers a PREFIX of the list (at least one operation,
    /// at most OPS_BOX_BUDGET bytes); the client asks again for the rest. Pure transport encoding: the client rebuilds the matrices and
    /// verifies their roots exactly as with `OpData`.
    GetOpsBox { job: JobId, ops: Vec<u8> },
    OpsBox(Vec<BoxedOp>),
    /// Signed beacon of the combined miner for the fee audit (feeguard.rs): accepted only by seeds started with --collect-fee-beacons.
    FeeBeacon(crate::feeguard::FeeBeacon),
    /// RELAY (docs/21): a worker behind a home router keeps one outgoing connection to a relay node (a seed started with `--relay`)
    /// and announces which account it works for. `sig` = signature of `relay_msg(genesis, our Noise key)` by the account key: it ties the
    /// account to THIS connection, so nobody can claim another worker's account or replay the announcement.
    RelayAnnounce { account: PubKey, sig: Vec<u8> },
    /// Client -> relay node: forward `req` (an encoded read-only request) to the worker `to` and bring back its reply.
    RelayRequest { to: RelayTo, req: Vec<u8> },
    /// Relay node -> worker, over the worker's own outgoing connection.
    RelayForward { id: u64, req: Vec<u8> },
    /// Worker -> relay node: encoded reply to the forwarded request `id`.
    RelayReply { id: u64, resp: Vec<u8> },
    /// Relay node -> client: encoded reply of the worker.
    RelayResponse { resp: Vec<u8> },
    /// Like `GetOpsBox`, for a client that understands the compressed reply (rc25). A worker or a relay of an older release does not know it.
    GetOpsBoxZ { job: JobId, ops: Vec<u8> },
    /// The `BoxedOp`s of the requested operations, bincode then deflate (`pack_ops_z` / `unpack_ops_z`). The boxes are mostly repetitions: 40x or more.
    OpsBoxZ(Vec<u8>),
    /// Link test (rc25): the worker answers `Probe` with `bytes` bytes that do not compress (a stream derived from `nonce`), at most PROBE_MAX. A client
    /// times it to know whether a miner can send the operations of a big job in reasonable time, directly or through a relay.
    GetProbe { bytes: u32, nonce: u64 },
    Probe(Vec<u8>),
}

/// Who a relayed request is for: a worker account, or the worker that holds a level 2 job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayTo {
    Account(PubKey),
    L2Job(JobId),
}

/// Relay limits (a relay node must not become an amplifier): size of a forwarded request, routes, requests in flight overall and per worker.
pub const RELAY_MAX_REQ: usize = 64 << 10;
const RELAY_MAX_ROUTES: usize = 1024;
const RELAY_MAX_PENDING: usize = 128;
const RELAY_PER_ROUTE: usize = 64;
/// Largest reply a relay node hands over (memory held for a client that does not read is bounded by pending requests x this).
const RELAY_MAX_RESP: usize = 2 << 20;
/// BULK relayed requests (jobs of an AI model that the miner holds in advance, docs/21 section 4 bis): the input of a job goes to the worker (`PutProgRef`:
/// one n x n matrix of 1 MiB + the roots of the weights) and bounding boxes of operations come back (`GetOpsBox`, `GetOp`: at most OPS_BOX_BUDGET, or a
/// full operation of 5 MiB). Both stay below MAX_MSG. Few of them at a time, because the seed carries every byte.
pub const RELAY_MAX_REQ_BULK: usize = (1 << 20) + (64 << 10);
pub const RELAY_MAX_RESP_BULK: usize = OPS_BOX_BUDGET + (1 << 20);
/// A model block that is not in the miner's pack (the mean vector of a text depends on its length): at most this many blocks per relayed `PutModel`.
pub const RELAY_MAX_PUT_BLOCKS: usize = 2;
pub const RELAY_MAX_REQ_PUT: usize = 2 * (1 << 20) + (128 << 10);
const RELAY_MAX_BULK: usize = 16;
const RELAY_BULK_PER_ROUTE: usize = 4;
const RELAY_TTL: Duration = Duration::from_secs(60);
/// Requests a worker answers at the same time on behalf of relay nodes.
const RELAY_SERVE_MAX: usize = 64;

/// What travels through a relay: the small READ requests of the audit of a level 2 job (replies of a few kilobytes), and, for the jobs of an AI model
/// that the miner holds in advance, the four requests of the client (`HasModel`, `PutProgRef`, `GetOpsBox`, `GetOp`: see `relay_is_bulk`). Nothing
/// else that writes (`PutModel` would upload the weights, `NewTx`), nothing that relays again, no other matrix.
pub fn relay_allowed(m: &Msg) -> bool {
    matches!(m, Msg::GetL2(_) | Msg::GetL2Chunk { .. } | Msg::GetJob(_) | Msg::GetMlp(_) | Msg::GetProg(_) | Msg::GetTiled(_) | Msg::GetServed(_) | Msg::GetRep(_) | Msg::GetStatus | Msg::HasModel { .. })
        || relay_is_bulk(m)
}

/// The relayed requests that carry a matrix (the input of a job, the outputs of operations): bigger limits, but counted separately and few at a time.
pub fn relay_is_bulk(m: &Msg) -> bool {
    match m {
        Msg::PutModel { ws } => ws.len() <= RELAY_MAX_PUT_BLOCKS, // only the few blocks that a pack does not hold; the weights of a model never travel here
        _ => matches!(m, Msg::PutProgRef { .. } | Msg::GetOpsBox { .. } | Msg::GetOpsBoxZ { .. } | Msg::GetOp { .. } | Msg::GetProbe { .. }),
    }
}

/// What a worker signs to announce itself to a relay node.
pub fn relay_msg(genesis: &Hash, noise_key: &[u8; 32]) -> Hash {
    h("vearl/relay/v1", &[genesis, noise_key])
}

/// Output and Z of an operation as a bounding box (see `Msg::GetOpsBox`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoxedOp {
    pub x_dims: (u32, u32),
    pub x: Vec<i8>,
    pub z_dims: Option<(u32, u32)>,
    pub z: Vec<i32>,
}

/// Maximum size of an `OpsBox` reply (below MAX_MSG, even with a full 5 MiB operation on top).
pub const OPS_BOX_BUDGET: usize = 8 << 20;
/// Largest link test a worker answers.
pub const PROBE_MAX: u32 = 8 << 20;

/// The bytes of a link test: a stream of `blake3` output, so that nothing compresses it.
pub fn probe_bytes(bytes: u32, nonce: u64) -> Vec<u8> {
    let mut buf = vec![0u8; bytes.min(PROBE_MAX) as usize];
    let mut h = blake3::Hasher::new();
    h.update(b"vearl/probe/v1");
    h.update(&nonce.to_le_bytes());
    h.finalize_xof().fill(&mut buf);
    buf
}

/// `OpsBoxZ`: the boxes are limited BEFORE compression (a worker builds them in memory) and the reply AFTER it (it must go through a relay).
pub const OPS_BOX_BUDGET_Z: usize = 48 << 20;
/// A client refuses to inflate more than this (a bomb): a little more than the budget above.
pub const OPS_BOX_Z_MAX_RAW: usize = 64 << 20;

/// Boxes of the requested operations: the same prefix rule as `OpsBox`, with the byte budget of the caller.
fn ops_box_items(tensors: &[Vec<i8>], zs: &[Option<Vec<i32>>], ops: &[u8], pn: usize, budget: usize) -> Option<Vec<BoxedOp>> {
    if ops.is_empty() || ops.iter().any(|op| *op as usize >= zs.len()) {
        return None;
    }
    let (mut items, mut bytes) = (vec![], 0usize);
    for op in ops {
        let (x_dims, x) = box_pack(&tensors[*op as usize + 1], pn);
        let (z_dims, z) = match &zs[*op as usize] {
            Some(z) => {
                let (d, v) = box_pack(z, pn);
                (Some(d), v)
            }
            None => (None, vec![]),
        };
        let sz = x.len() + 4 * z.len();
        if !items.is_empty() && bytes + sz > budget {
            break;
        }
        bytes += sz;
        items.push(BoxedOp { x_dims, x, z_dims, z });
    }
    Some(items)
}

/// bincode + deflate of the boxes (see `Msg::OpsBoxZ`).
pub fn pack_ops_z(items: &[BoxedOp]) -> Option<Vec<u8>> {
    let raw = bincode::serialize(items).ok()?;
    Some(miniz_oxide::deflate::compress_to_vec(&raw, 6))
}

/// Inverse of `pack_ops_z`; refuses more than `OPS_BOX_Z_MAX_RAW` bytes once inflated.
pub fn unpack_ops_z(z: &[u8]) -> Option<Vec<BoxedOp>> {
    let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(z, OPS_BOX_Z_MAX_RAW).ok()?;
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(OPS_BOX_Z_MAX_RAW as u64).deserialize(&raw).ok()
}

/// `OpsBoxZ` reply: as many of the requested operations as fit, after compression, in what a relay hands over.
fn ops_box_reply_z(tensors: &[Vec<i8>], zs: &[Option<Vec<i32>>], ops: &[u8], pn: usize) -> Msg {
    let mut budget = OPS_BOX_BUDGET_Z;
    loop {
        let Some(items) = ops_box_items(tensors, zs, ops, pn, budget) else { return Msg::Ack { ok: false, info: "no such operation".into() } };
        match pack_ops_z(&items) {
            Some(z) if z.len() <= RELAY_MAX_RESP_BULK - (1 << 20) => return Msg::OpsBoxZ(z),
            _ if items.len() > 1 && budget > (1 << 20) => budget /= 2, // does not compress well: fewer operations per reply
            _ => return Msg::Ack { ok: false, info: "reply too large".into() },
        }
    }
}

/// Bounding box (rows, columns) of the non-zero content of an n x n matrix stored row by row.
pub fn nz_box<T: Copy + Default + PartialEq>(m: &[T], n: usize) -> (usize, usize) {
    let zero = T::default();
    let (mut rows, mut cols) = (0, 0);
    for (i, row) in m.chunks(n).enumerate() {
        if let Some(j) = row.iter().rposition(|v| *v != zero) {
            rows = i + 1;
            cols = cols.max(j + 1);
        }
    }
    (rows, cols)
}

/// Top-left corner (rows x columns) containing everything non-zero.
pub fn box_pack<T: Copy + Default + PartialEq>(m: &[T], n: usize) -> ((u32, u32), Vec<T>) {
    let (r, c) = nz_box(m, n);
    ((r as u32, c as u32), (0..r).flat_map(|i| m[i * n..i * n + c].iter().copied()).collect())
}

/// n x n matrix from its corner (dimensions checked: a peer cannot make it overflow).
pub fn box_unpack<T: Copy + Default>(dims: (u32, u32), data: &[T], n: usize) -> Option<Vec<T>> {
    let (r, c) = (dims.0 as usize, dims.1 as usize);
    if r > n || c > n || data.len() != r * c {
        return None;
    }
    let mut m = vec![T::default(); n * n];
    for i in 0..r {
        m[i * n..i * n + c].copy_from_slice(&data[i * c..(i + 1) * c]);
    }
    Some(m)
}

/// Workers (or relays) that did not understand `GetOpsBoxZ`: asked the old way from then on.
static NO_ZBOX: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> = std::sync::LazyLock::new(|| Mutex::new(Default::default()));

/// `request`, and again (a few times, with a short pause) while a relay node or a worker answers that it is busy: the relay only lets a few bulk
/// requests through at a time, and a client that verifies a job in parallel has to wait its turn instead of failing.
pub fn request_retry_busy(addr: &str, m: &Msg) -> io::Result<Msg> {
    let mut tries = 0;
    loop {
        match request(addr, m) {
            Ok(Msg::Ack { ok: false, info }) if tries < 60 && (info.contains("relay busy") || info.contains("worker busy")) => {
                tries += 1;
                thread::sleep(Duration::from_millis(150 + 25 * (tries.min(20) as u64)));
            }
            r => return r,
        }
    }
}

/// Outputs and Z of the operations `ops` of a program at the worker, in as few round trips as possible (bounding boxes);
/// an old worker that does not know `GetOpsBox` is queried operation by operation (`GetOp`).
pub fn fetch_ops(worker: &str, job: JobId, ops: &[u8], n: usize) -> Option<Vec<(Option<Vec<i32>>, Vec<i8>)>> {
    let mut out = Vec::with_capacity(ops.len());
    while out.len() < ops.len() {
        // compressed reply first (40x or more smaller); a worker or a relay that does not know it is remembered and asked the old way
        let zip_ok = !NO_ZBOX.lock().unwrap().contains(worker);
        let reply = if zip_ok {
            match request_retry_busy(worker, &Msg::GetOpsBoxZ { job, ops: ops[out.len()..].to_vec() }) {
                Ok(Msg::OpsBoxZ(z)) => unpack_ops_z(&z).map(Msg::OpsBox).ok_or_else(|| ioerr("bad compressed reply")),
                Ok(Msg::Ack { ok: false, info }) if info.contains("no such operation") => Ok(Msg::Ack { ok: false, info }),
                Ok(_) | Err(_) => {
                    NO_ZBOX.lock().unwrap().insert(worker.to_string());
                    request_retry_busy(worker, &Msg::GetOpsBox { job, ops: ops[out.len()..].to_vec() })
                }
            }
        } else {
            request_retry_busy(worker, &Msg::GetOpsBox { job, ops: ops[out.len()..].to_vec() })
        };
        match reply {
            Ok(Msg::OpsBox(items)) if !items.is_empty() && items.len() <= ops.len() - out.len() => {
                for b in items {
                    let x = box_unpack(b.x_dims, &b.x, n)?;
                    let z = match b.z_dims {
                        Some(d) => Some(box_unpack(d, &b.z, n)?),
                        None if b.z.is_empty() => None,
                        None => return None,
                    };
                    out.push((z, x));
                }
            }
            _ => {
                let op = ops[out.len()];
                match request_retry_busy(worker, &Msg::GetOp { job, op }).ok()? {
                    Msg::OpData { z, x } => out.push((z, x)),
                    _ => return None,
                }
            }
        }
    }
    Some(out)
}

/// A single operation (see `fetch_ops`).
pub fn fetch_op(worker: &str, job: JobId, op: u8, n: usize) -> Option<(Option<Vec<i32>>, Vec<i8>)> {
    fetch_ops(worker, job, &[op], n)?.pop()
}

fn codec() -> impl Options {
    bincode::options().with_fixint_encoding().with_limit(MAX_MSG as u64)
}
fn ioerr<E: ToString>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}
pub fn encode(m: &Msg) -> io::Result<Vec<u8>> {
    codec().serialize(m).map_err(ioerr)
}
pub fn decode_msg(b: &[u8]) -> io::Result<Msg> {
    codec().deserialize(b).map_err(ioerr)
}

/// Encrypted connection on the client side (CLI, tests): anonymous ephemeral identity.
pub struct Conn {
    r: SecureReader,
    w: SecureWriter,
    pub remote: [u8; 32],
    /// `relay://` address: every request goes through a relay node to a worker that cannot be reached directly.
    relay: Option<RelayTo>,
}

/// `relay://HOST:PORT/acct:<64 hex>` or `relay://HOST:PORT/l2:<64 hex>`: the relay node, and the worker behind it
/// (an account, or the worker of a level 2 job). Any other string is an ordinary `HOST:PORT`.
pub fn parse_relay_addr(addr: &str) -> Option<(String, RelayTo)> {
    let rest = addr.strip_prefix("relay://")?;
    let (host, target) = rest.split_once('/')?;
    let (kind, hex) = target.split_once(':')?;
    let id = parse_hex32(hex)?;
    match kind {
        "acct" => Some((host.to_string(), RelayTo::Account(id))),
        "l2" => Some((host.to_string(), RelayTo::L2Job(id))),
        _ => None,
    }
}

impl Conn {
    pub fn connect(addr: &str) -> io::Result<Conn> {
        let (direct, relay) = match addr.strip_prefix("relay://") {
            Some(_) => {
                let (host, to) = parse_relay_addr(addr).ok_or_else(|| ioerr("bad relay address"))?;
                (host, Some(to))
            }
            None => (addr.to_string(), None),
        };
        let sa = std::net::ToSocketAddrs::to_socket_addrs(&direct)?.next().ok_or_else(|| ioerr("bad addr"))?;
        let s = TcpStream::connect_timeout(&sa, Duration::from_secs(3))?;
        let (r, w, remote) = handshake(s, &Keys::generate(), true, Duration::from_secs(10))?;
        Ok(Conn { r, w, remote, relay })
    }
    pub fn send(&mut self, m: &Msg) -> io::Result<()> {
        match self.relay {
            Some(to) => self.w.write_msg_bytes(&encode(&Msg::RelayRequest { to, req: encode(m)? })?),
            None => self.w.write_msg_bytes(&encode(m)?),
        }
    }
    pub fn recv(&mut self) -> io::Result<Msg> {
        let m = decode_msg(&self.r.read_msg_bytes()?)?;
        match (self.relay, m) {
            // the relay node answers with the worker's own reply, still encoded: the caller sees exactly what a direct connection gives
            (Some(_), Msg::RelayResponse { resp }) => decode_msg(&resp),
            (_, m) => Ok(m),
        }
    }
    /// Sends arbitrary application bytes over the encrypted channel (fuzz: malformed messages).
    pub fn send_raw(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_msg_bytes(b)
    }
    pub fn set_timeout(&self, d: Duration) {
        let _ = self.r.set_read_timeout(Some(d));
    }
}

fn subnet16(ip: &IpAddr) -> Option<[u8; 2]> {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            Some([o[0], o[1]])
        }
        _ => None,
    }
}

/// Admission of INCOMING connections (basic anti-eclipse): global cap, per IP, per /16. Pure function.
pub fn inbound_allowed(existing_inbound: &[IpAddr], new: &IpAddr) -> bool {
    if existing_inbound.len() >= LIM_IN.load(Ordering::SeqCst) {
        return false;
    }
    if new.is_loopback() {
        return true;
    }
    let same_ip = existing_inbound.iter().filter(|i| *i == new).count();
    let same_net = existing_inbound.iter().filter(|i| subnet16(i).is_some() && subnet16(i) == subnet16(new)).count();
    same_ip < LIM_IP.load(Ordering::SeqCst) && same_net < LIM_NET.load(Ordering::SeqCst)
}

/// Choice of OUTGOING targets: never two outgoing peers in the same /16 (except loopback).
pub fn outbound_candidate_ok(current_out: &[IpAddr], cand: &IpAddr) -> bool {
    cand.is_loopback() || !current_out.iter().any(|i| subnet16(i).is_some() && subnet16(i) == subnet16(cand))
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

enum SyncMode {
    Idle,
    Extend,
    /// Fork: we look for the common ancestor by stepping back (`from` = requested height, `step` doubles at each failure).
    Locate { from: u64, step: u64 },
    /// Ancestor found: we download the peer's chain from height `base` (aligned with our chain).
    Fork { base: u64, buf: Vec<Block> },
}

/// Initial step back (in blocks) when looking for the common ancestor during a fork.
const LOCATE_STEP: u64 = 8;

struct Peer {
    tx: SyncSender<Msg>,
    addr: String,
    listen: Option<String>,
    key: [u8; 32], // authenticated static Noise key: this is the peer's identity
    outbound: bool,
    ip: Option<IpAddr>,
    score: u32, // accumulated misbehaviour; >= BAN_SCORE => disconnection + ban
    work: u128,
    height: u64,
    sync: SyncMode,
    /// Handle to close the socket when the node is stopped.
    kill: Option<TcpStream>,
}

pub struct Node {
    pub chain: Chain,
    genesis: GenesisConfig,
    pub mempool: Vec<SignedTx>,
    mempool_ids: HashSet<Hash>,
    /// Time each mempool transaction entered (used to evict stuck transactions).
    mempool_since: HashMap<Hash, Instant>,
    peers: HashMap<u64, Peer>,
    known: HashSet<String>,
    next_peer: u64,
    banned: HashMap<std::net::IpAddr, Instant>,
    /// Job data known to this node (worker): (root A, root B) -> matrices.
    job_data: HashMap<(Hash, Hash), Arc<CommittedMatrices>>,
    /// Computed results (C and its Merkle root), served to the client.
    results: HashMap<JobId, (Arc<Vec<i32>>, Hash)>,
    worker: Option<WorkerCfg>,
    me: Option<PubKey>,
    store: Option<Store>,
    /// Pinned peer keys (address -> expected static key).
    pins: HashMap<String, [u8; 32]>,
    seen: HashSet<Hash>,
    data_dir: Option<PathBuf>,
    /// Inference job data known to this node (worker).
    mlp_data: Vec<MlpData>,
    /// Inference computations in progress / finished (computed layers, published or not).
    mlp_runs: HashMap<JobId, MlpRun>,
    tiled_data: Vec<TiledData>,
    tiled_runs: HashMap<JobId, TiledRun>,
    /// Row-by-row deposits in progress (block products of large size).
    tiled_stage: HashMap<Hash, TiledStage>,
    /// Block-product computations started as a background task (outside the node lock) and their results.
    tiled_computing: HashSet<JobId>,
    /// Programs executed as a background task (outside the node lock): results to merge back, jobs in progress.
    prog_inbox: Arc<Mutex<Vec<(JobId, ProgRun)>>>,
    prog_computing: HashSet<JobId>,
    tiled_inbox: Arc<Mutex<Vec<(JobId, TiledRun)>>>,
    prog_data: Vec<ProgData>,
    /// Model registry: weight blocks by Merkle root.
    models: HashMap<Hash, Vec<i8>>,
    /// How many blocks of `models` come from the packs installed on this machine (`--models-dir`): they do not count in the upload cap.
    models_pre: usize,
    prog_runs: HashMap<JobId, ProgRun>,
    l2_runs: HashMap<JobId, L2Run>,
    /// Level 2 jobs computed as a background task (outside the node lock): results to merge back, jobs in progress.
    l2_inbox: Arc<Mutex<Vec<(JobId, L2Run)>>>,
    l2_computing: HashSet<JobId>,
    /// Slowing down of deep reorganisations (MESS, see chain.rs): OPTIONAL (`node --mess` or VEARL_MESS=1), disabled by default.
    pub mess: bool,
    /// Maximum size (serialised bytes) of a `Blocks` / `Headers` sync reply: a batch must never exceed the
    /// size of one message (16 MiB) even with heavy blocks. Adjustable for tests.
    pub sync_budget: u64,
    /// RELAY node (seed started with `--relay`, docs/21): accepts `RelayAnnounce` from workers and forwards read requests to them.
    pub relay: bool,
    /// Worker key of this node, used to announce it to the (pinned) relay nodes it dials.
    relay_sk: Option<SigningKey>,
    /// Worker account -> peer id of its connection (relay node side).
    relay_routes: HashMap<PubKey, u64>,
    /// What the relay node knows about each announced worker: where it can be dialed and whether a connection from here worked (see `relay_workers`).
    relay_direct: HashMap<PubKey, RelayDirect>,
    /// Forwarded requests waiting for the worker's reply (relay node side).
    relay_pending: HashMap<u64, RelayPending>,
    relay_next: u64,
}

struct RelayDirect {
    dial: Option<String>,
    /// `Some(true)`: a TCP connection from this node to `dial` worked (the miner has a reachable address); `None`: not tested yet.
    direct: Option<bool>,
    since: u64,
}

struct RelayPending {
    client: SyncSender<Msg>,
    peer: u64,
    at: Instant,
    /// a bulk request (see `relay_is_bulk`): its reply may be larger
    bulk: bool,
}

/// A worker announced to this relay node: its account, where it can be dialed, and whether that worked from here (`/api/workers`).
pub struct RelayWorker {
    pub account: PubKey,
    pub dial: Option<String>,
    pub direct: Option<bool>,
    pub seconds: u64,
}

pub fn relay_workers(sh: &Arc<Shared>) -> Vec<RelayWorker> {
    let n = sh.node.lock().unwrap();
    let now = now_secs();
    let mut v: Vec<RelayWorker> = n
        .relay_routes
        .keys()
        .map(|a| {
            let d = n.relay_direct.get(a);
            RelayWorker { account: *a, dial: d.and_then(|d| d.dial.clone()), direct: d.and_then(|d| d.direct), seconds: now.saturating_sub(d.map_or(now, |d| d.since)) }
        })
        .collect();
    v.sort_by_key(|w| w.account);
    v
}

/// Maximum number of weight blocks in a worker's registry (n = 1024: 1 MiB each).
const MAX_MODEL_BLOCKS: usize = 1024; // (Qwen3-Embedding-0.6B alone holds 528 blocks of 1 MiB)

/// Model pack: the weight blocks of a model, installed on the machine in advance so that a client never has to send them
/// (`node --models-dir DIR` loads every `*.vblocks` of the folder into the registry, which `HasModel` then reports as present).
/// Layout: 8 bytes `VBLOCK01`, n (u32 LE), number of blocks (u32 LE), then the blocks (n*n i8 each, row-major).
pub const MODEL_PACK_MAGIC: &[u8; 8] = b"VBLOCK01";

/// Reads a pack and gives each block to `f`; the pack must be built for matrices of size `n` (the chain's).
pub fn read_model_pack(path: &std::path::Path, n: usize, mut f: impl FnMut(Vec<i8>)) -> Result<usize, String> {
    let mut r = io::BufReader::with_capacity(1 << 20, File::open(path).map_err(|e| e.to_string())?);
    let mut head = [0u8; 16];
    r.read_exact(&mut head).map_err(|_| "file too short".to_string())?;
    if &head[..8] != MODEL_PACK_MAGIC {
        return Err("not a model pack".into());
    }
    let (pn, count) = (u32::from_le_bytes(head[8..12].try_into().unwrap()) as usize, u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize);
    if pn != n {
        return Err(format!("built for n={pn}, this chain uses n={n}"));
    }
    for i in 0..count {
        let mut raw = vec![0u8; n * n];
        r.read_exact(&mut raw).map_err(|_| format!("truncated at block {i}/{count}"))?;
        if raw.iter().any(|b| (*b as i8 as i32).abs() > VAL_MAX) {
            return Err(format!("block {i} holds a value outside the allowed range"));
        }
        f(raw.into_iter().map(|b| b as i8).collect());
    }
    Ok(count)
}

/// Maximum number of program data sets (input + weights) kept by a worker.
const MAX_PROG_DATA: usize = 32;

/// Number of tensor-program jobs a worker takes at a time unless `--max-jobs` says otherwise (a value above 1 replaces it). A program takes
/// seconds to run, so a worker keeps several going, but not the whole queue: the other workers that hold the same data take the rest.
const PROG_ACTIVE: usize = 16;

/// Frees room in the program data store: drops the oldest sets for which NO job is alive
/// (Open / Working / Complete) - settled, penalised, expired jobs, or deposits never submitted - together with the matching computations.
fn prog_store_make_room(n: &mut Node) -> bool {
    while n.prog_data.len() >= MAX_PROG_DATA {
        let live = |d: &ProgData, n: &Node| n.chain.state.progs.values().any(|j| j.x0_root == d.x0_root && j.w_roots == d.w_roots && matches!(j.status, ProgStatus::Open | ProgStatus::Working { .. } | ProgStatus::Complete { .. }));
        let Some(i) = (0..n.prog_data.len()).find(|&i| !live(&n.prog_data[i], n)) else { return false };
        let d = n.prog_data.remove(i);
        let dead: Vec<JobId> = n.prog_runs.keys().filter(|id| n.chain.state.progs.get(*id).map_or(false, |j| j.x0_root == d.x0_root && j.w_roots == d.w_roots)).cloned().collect();
        for id in dead {
            n.prog_runs.remove(&id);
        }
    }
    true
}

/// Drops the oldest block-product data sets for which no job is alive (same rules as for programs).
fn tiled_store_make_room(n: &mut Node) -> bool {
    while n.tiled_data.len() >= MAX_TILED_DATA {
        let live = |d: &TiledData, n: &Node| n.chain.state.tiled.values().any(|j| j.dims == d.dims && j.a_roots == d.a_roots && j.b_roots == d.b_roots && matches!(j.status, TiledStatus::Open | TiledStatus::Claimed { .. } | TiledStatus::Posted { .. }));
        let Some(i) = (0..n.tiled_data.len()).find(|&i| !live(&n.tiled_data[i], n)) else { return false };
        let d = n.tiled_data.remove(i);
        let dead: Vec<JobId> = n.tiled_runs.keys().filter(|id| n.chain.state.tiled.get(*id).map_or(false, |j| j.dims == d.dims && j.a_roots == d.a_roots && j.b_roots == d.b_roots)).cloned().collect();
        for id in dead {
            n.tiled_runs.remove(&id);
        }
    }
    true
}

struct ProgData {
    x0: Vec<i8>,
    ws: Vec<Vec<i8>>,
    x0_root: Hash,
    w_roots: Vec<Hash>,
}

struct ProgRun {
    /// Shared (Arc): a client request borrows them under the lock then boxes them OUTSIDE the lock.
    tensors: Arc<Vec<Vec<i8>>>,
    zs: Arc<Vec<Option<Vec<i32>>>>,
    /// (root of Z, root of the output) of each operation, computed ONCE (outside the lock) together with the program.
    roots: Vec<(Hash, Hash)>,
    cms: HashMap<u8, Arc<CommittedMatrices>>,
    next: usize,
}

struct TiledData {
    a: Vec<i8>,
    b: Vec<i8>,
    dims: (usize, usize, usize),
    a_roots: Vec<Hash>,
    b_roots: Vec<Hash>,
}

struct TiledStage {
    dims: (usize, usize, usize),
    a: Vec<i8>,
    b: Vec<i8>,
    a_rows: Vec<bool>,
    b_rows: Vec<bool>,
}

/// Maximum number of block-product data sets kept by a worker.
const MAX_TILED_DATA: usize = 8;

#[derive(Default)]
struct TiledRun {
    product_roots: Vec<Hash>,
    c_roots: Vec<Hash>,
    products: Vec<Vec<i32>>,
    sums: Vec<Vec<i32>>,
    cms: HashMap<(u8, u8, u8), Arc<CommittedMatrices>>,
    next: usize,
}

struct MlpData {
    x0: Vec<i8>,
    ws: Vec<Vec<i8>>,
    x0_root: Hash,
    w_roots: Vec<Hash>,
}

/// Computed outputs of a level 2 job (all the chunks) and their Merkle tree.
struct L2Run {
    outs: Vec<Vec<u8>>,
    tree: MerkleTree,
}

#[derive(Default)]
struct MlpRun {
    /// (Z_l, X_l, root of Z_l, root of X_l) for each computed layer.
    layers: Vec<(Arc<Vec<i32>>, Arc<Vec<i8>>, Hash, Hash)>,
    /// Committed matrices (W_l, X_{l-1}) of each layer, built only once.
    cms: HashMap<u8, Arc<CommittedMatrices>>,
}

/// Disk persistence: append-only file of blocks (u32 LE length + bincode), replayed at startup.
struct Store {
    path: PathBuf,
    persisted: usize,
    persisted_tip: Hash,
}

#[derive(Clone, Copy, Default)]
pub struct WorkerCfg {
    /// TEST ONLY: the worker cheats (wrong result on one entry; for inference: wrong GEMM at layer 1)
    /// to exercise the fraud proofs.
    pub cheat: bool,
    /// TEST ONLY: for inference, wrong activation at layer 0 (the GEMM stays correct).
    pub cheat_act: bool,
    /// Asking price (base units) for auction jobs: the worker bids this price if it beats the best bid.
    /// None = the worker does not take part in auctions (it only claims fixed-price jobs).
    pub ask: Option<u64>,
    /// TEST ONLY: the worker never answers on-chain data requests (to exercise SlashUnserved).
    pub no_serve: bool,
    /// TEST ONLY: the worker publishes the root of an INVENTED result (all entries wrong), which it serves consistently.
    pub cheat_garbage: bool,
    /// TEST ONLY: for a block-product job, a wrong SUM (the products stay correct).
    pub cheat_sum: bool,
    /// TEST ONLY: for a tensor program, a wrong output at operation 0 (im2col).
    pub cheat_elem: bool,
    /// TEST ONLY: for a tensor program, a wrong column at the first softmax/normalisation operation.
    pub cheat_col: bool,
    /// TEST ONLY: for a level 2 job, a wrong chunk (the middle one), committed in the published root.
    pub cheat_l2: bool,
    /// Maximum number of level 2 jobs claimed at the same time (claimed, not yet published): 0 = 1. A busy worker does not claim
    /// from the queue: waiting jobs stay for the other miners.
    pub max_jobs: usize,
    /// Worker only (`node --worker --no-native`): the node never mines Native blocks, it only works on the jobs it claims. This is the
    /// miner's pool mode with paid jobs: the pool miner does the Native mining, this node takes the compute market.
    pub no_native: bool,
}

impl Node {
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

/// Submits a signed transaction (HTTP API): same admission and same relay as one received from a peer or from the CLI.
pub fn submit_tx(sh: &Shared, t: SignedTx) -> Result<(), String> {
    let mut n = sh.node.lock().unwrap();
    admit_tx(&mut n, t.clone())?;
    broadcast(&n, None, &Msg::NewTx(t));
    Ok(())
}

/// Submits an already complete block (pool: the work comes from the pool's miners, docs/16): same validation, persistence, mempool
/// cleanup and relay as for a block mined by the node itself. Refuses a block whose parent is no longer the tip.
pub fn submit_block(sh: &Shared, b: Block) -> Result<(), String> {
    let mut n = sh.node.lock().unwrap();
    if n.chain.tip_hash() != b.header.prev {
        return Err("stale: the chain moved".into());
    }
    n.chain.validate_and_apply_at(b.clone(), now_secs())?;
    persist(&mut n);
    prune_mempool(&mut n);
    broadcast(&n, None, &Msg::NewBlock(b));
    sh.cancel.store(true, Ordering::SeqCst);
    Ok(())
}

pub struct Shared {
    pub node: Mutex<Node>,
    pub cancel: AtomicBool,
    /// Set by the dual-mining scheduler (`dual.rs`): the mining loop sleeps while it is true.
    pub paused: AtomicBool,
    /// True when the last look at the job queue found nothing for this node to compute (native work only).
    pub native_work: AtomicBool,
    /// Explorer data derived from the blocks (`index.rs`), and a small response cache of the API keyed by the chain tip. Lock order: `node`, then `index`, then `cache`.
    pub index: Mutex<crate::index::Index>,
    pub cache: Mutex<HashMap<String, (Hash, u16, &'static str, Vec<u8>)>>,
    pub node_id: u64,
    pub listen: Mutex<Option<String>>,
    pub genesis_hash: Hash,
    pub stop: AtomicBool,
    pub keys: Keys,
    handshakes: AtomicUsize,
    /// Inbound connections right now, of every kind (peers and short requests), in total and per IP address.
    conns: AtomicUsize,
    conn_ips: Mutex<HashMap<IpAddr, usize>>,
    /// Requests this worker is answering on behalf of relay nodes right now.
    relay_busy: AtomicUsize,
}

pub struct NodeConfig {
    pub genesis: GenesisConfig,
    pub listen: String, // "127.0.0.1:0" for a free port
    pub peers: Vec<String>,
    pub mine_key: Option<SigningKey>,
    pub use_gpu: bool,
    pub log: bool,
    /// If set, the node claims and mines the jobs whose data it knows (requires mine_key).
    pub worker: Option<WorkerCfg>,
    /// If set, the chain is persisted and reloaded from this folder.
    pub data_dir: Option<PathBuf>,
}

pub struct NodeHandle {
    pub shared: Arc<Shared>,
    pub addr: String,
}

impl NodeHandle {
    pub fn height(&self) -> u64 {
        self.shared.node.lock().unwrap().chain.height()
    }
    pub fn tip(&self) -> Hash {
        self.shared.node.lock().unwrap().chain.tip_hash()
    }
    pub fn work(&self) -> u128 {
        self.shared.node.lock().unwrap().chain.total_work()
    }
    pub fn peer_count(&self) -> usize {
        self.shared.node.lock().unwrap().peers.len()
    }
    /// Noise public key of the node (hex): to be shared so that others can pin it (`addr@hex`).
    pub fn id_hex(&self) -> String {
        self.shared.keys.public_hex()
    }
    /// Turns this node into a relay node (`node --relay`): workers behind a router that dial it can be reached through it.
    pub fn set_relay(&self, on: bool) {
        self.shared.node.lock().unwrap().relay = on;
    }
    /// Number of workers currently announced to this relay node.
    pub fn relay_routes(&self) -> usize {
        self.shared.node.lock().unwrap().relay_routes.len()
    }
    /// Loads the model packs (`*.vblocks`) of a folder into the registry of this node, in the background: from then on a client that asks
    /// `HasModel` is told the blocks are here and sends nothing. With `watch`, the folder is looked at again every 30 s (the miner downloads the
    /// packs while it already runs) until the node stops. Returns the thread (its result: blocks registered, packs refused).
    pub fn preload_models(&self, dir: PathBuf, watch: bool) -> thread::JoinHandle<(usize, usize)> {
        let sh = self.shared.clone();
        thread::spawn(move || {
            let n = sh.node.lock().unwrap().chain.params.n;
            let (mut loaded, mut refused) = (0usize, 0usize);
            let mut done: HashSet<(String, u64)> = HashSet::new();
            loop {
                let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
                    .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().map_or(false, |x| x == "vblocks")).collect())
                    .unwrap_or_default();
                files.sort();
                for p in files {
                    let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                    if !done.insert((name.clone(), std::fs::metadata(&p).map_or(0, |m| m.len()))) {
                        continue;
                    }
                    let mut added = 0usize;
                    let res = read_model_pack(&p, n, |w| {
                        let root = rows_tree(&w, n).root();
                        let mut g = sh.node.lock().unwrap();
                        if g.models.insert(root, w).is_none() {
                            g.models_pre += 1;
                            added += 1;
                        }
                    });
                    match res {
                        Ok(c) => {
                            loaded += added;
                            eprintln!("[models] {name}: {c} weight blocks ({added} new) ready: clients no longer have to send this model");
                        }
                        Err(e) => {
                            refused += 1;
                            eprintln!("[models] {name} ignored: {e}");
                        }
                    }
                }
                if !watch {
                    break;
                }
                for _ in 0..30 {
                    if sh.stop.load(Ordering::SeqCst) {
                        return (loaded, refused);
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
            (loaded, refused)
        })
    }
    pub fn connect(&self, addr: &str) {
        let sh = self.shared.clone();
        let a = addr.to_string();
        thread::spawn(move || {
            let _ = dial(&sh, &a);
        });
    }
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cancel.store(true, Ordering::SeqCst);
        // a stopped node closes its connections: its peers (and the relay nodes that route to it) notice at once
        for p in self.shared.node.lock().unwrap().peers.values() {
            if let Some(k) = &p.kill {
                let _ = k.shutdown(Shutdown::Both);
            }
        }
        // unblocks accept()
        if let Some(a) = self.shared.listen.lock().unwrap().clone() {
            let _ = TcpStream::connect(a);
        }
    }
}

/// Genesis hash: covers the work parameters, the allocations, the timestamp, the target, the durations and the difficulty adjustment.
pub fn genesis_hash(g: &GenesisConfig) -> Hash {
    h("vearl/genesis/v1", &[&bincode::serialize(&(g.params, &g.alloc, g.ts, g.target, g.timing, g.retarget)).unwrap()])
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// "host:port" or "host:port@key_hex" (pinned Noise public key).
fn split_spec(spec: &str) -> (String, Option<[u8; 32]>) {
    match spec.split_once('@') {
        Some((a, k)) => (a.to_string(), parse_hex32(k)),
        None => (spec.to_string(), None),
    }
}

fn save_known(n: &Node) {
    if let Some(d) = &n.data_dir {
        let list: Vec<&String> = n.known.iter().collect();
        let _ = std::fs::write(d.join("peers.txt"), list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"));
    }
}

/// `TcpListener::bind` asks the kernel for a queue of 128 connections waiting to be accepted. The seed of the public testnet overflowed it about
/// five times a second (`TcpExtListenOverflows`): the kernel then drops the SYN and the client only retries a second later, a wallet or a miner
/// that dials the seed sometimes waits for seconds. Asking again with a larger number is allowed on a listening socket (the kernel caps it at
/// `net.core.somaxconn`).
#[cfg(target_os = "linux")]
fn raise_backlog(l: &TcpListener) {
    use std::os::unix::io::AsRawFd;
    extern "C" {
        fn listen(fd: i32, backlog: i32) -> i32;
    }
    // SAFETY: `listen` on a valid listening socket owned by `l`; the result only matters as an optimisation
    unsafe {
        listen(l.as_raw_fd(), 4096);
    }
}
#[cfg(not(target_os = "linux"))]
fn raise_backlog(_: &TcpListener) {}

pub fn spawn_node(cfg: NodeConfig) -> io::Result<NodeHandle> {
    let listener = TcpListener::bind(&cfg.listen)?;
    raise_backlog(&listener);
    let addr = listener.local_addr()?.to_string();
    let mut chain = Chain::from_config(&cfg.genesis);
    let store = cfg.data_dir.as_ref().map(|d| {
        let _ = std::fs::create_dir_all(d);
        let path = d.join("chain.bin");
        let n = load_chain(&mut chain, &path);
        Store { path, persisted: n, persisted_tip: chain.blocks.last().map(|b| b.header.hash()).unwrap_or([0u8; 32]) }
    });
    let keys = match &cfg.data_dir {
        Some(d) => Keys::load_or_create(&d.join("node.key")),
        None => Keys::generate(),
    };
    let (mut known, mut pins) = (HashSet::new(), HashMap::new());
    for spec in &cfg.peers {
        let (a, pin) = split_spec(spec);
        if let Some(k) = pin {
            pins.insert(a.clone(), k);
        }
        known.insert(a);
    }
    // already known peers (anchors): retried at startup, which limits eclipse by restart
    if let Some(d) = &cfg.data_dir {
        if let Ok(txt) = std::fs::read_to_string(d.join("peers.txt")) {
            known.extend(txt.lines().filter(|l| l.len() < 64 && !l.is_empty()).map(|l| l.to_string()));
        }
    }
    let shared = Arc::new(Shared {
        node: Mutex::new(Node {
            chain,
            genesis: cfg.genesis.clone(),
            mempool: vec![],
            mempool_ids: HashSet::new(),
            mempool_since: HashMap::new(),
            peers: HashMap::new(),
            known,
            next_peer: 1,
            banned: HashMap::new(),
            job_data: HashMap::new(),
            results: HashMap::new(),
            worker: cfg.worker,
            me: cfg.mine_key.as_ref().map(pubkey),
            store,
            pins,
            seen: HashSet::new(),
            data_dir: cfg.data_dir.clone(),
            mlp_data: Vec::new(),
            mlp_runs: HashMap::new(),
            tiled_data: Vec::new(),
            tiled_runs: HashMap::new(),
            tiled_stage: HashMap::new(),
            tiled_computing: HashSet::new(),
            prog_inbox: Arc::new(Mutex::new(Vec::new())),
            prog_computing: HashSet::new(),
            tiled_inbox: Arc::new(Mutex::new(Vec::new())),
            prog_data: Vec::new(),
            models: HashMap::new(),
            models_pre: 0,
            prog_runs: HashMap::new(),
            l2_runs: HashMap::new(),
            l2_inbox: Arc::new(Mutex::new(Vec::new())),
            l2_computing: HashSet::new(),
            mess: std::env::var("VEARL_MESS").is_ok(),
            sync_budget: 8 << 20,
            relay: false,
            relay_sk: if cfg.worker.is_some() { cfg.mine_key.clone() } else { None },
            relay_routes: HashMap::new(),
            relay_direct: HashMap::new(),
            relay_pending: HashMap::new(),
            relay_next: 1,
        }),
        cancel: AtomicBool::new(false),
        paused: AtomicBool::new(false),
        native_work: AtomicBool::new(true),
        index: Mutex::new(crate::index::Index::default()),
        cache: Mutex::new(HashMap::new()),
        node_id: rand::random(),
        listen: Mutex::new(Some(addr.clone())),
        genesis_hash: genesis_hash(&cfg.genesis),
        stop: AtomicBool::new(false),
        keys,
        handshakes: AtomicUsize::new(0),
        conns: AtomicUsize::new(0),
        conn_ips: Mutex::new(HashMap::new()),
        relay_busy: AtomicUsize::new(0),
    });

    load_puts(&shared);

    // acceptance (with admission per IP / per /16 / cap on simultaneous handshakes)
    {
        let sh = shared.clone();
        thread::spawn(move || {
            for s in listener.incoming() {
                if sh.stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(s) = s else { continue };
                let Ok(pa) = s.peer_addr() else { continue };
                let ip = pa.ip();
                {
                    let n = sh.node.lock().unwrap();
                    if !ip.is_loopback() && n.banned.get(&ip).map_or(false, |t| t.elapsed() < Duration::from_secs(600)) {
                        continue;
                    }
                }
                if sh.handshakes.load(Ordering::SeqCst) >= MAX_HANDSHAKES {
                    continue; // protection against mass-opened handshakes (slow-loris)
                }
                // simultaneous connections of every kind: total and per IP. The limits on PEERS (total, per IP, per /16) are applied when the
                // connection says Hello, not here: a wallet or a tool is not a peer and must not be refused because nodes already use the address.
                if !ip.is_loopback() {
                    let total = sh.conns.load(Ordering::SeqCst);
                    let same = sh.conn_ips.lock().unwrap().get(&ip).copied().unwrap_or(0);
                    if total >= LIM_CONNS.load(Ordering::SeqCst) {
                        note_refusal("too many connections in total", &ip);
                        continue;
                    }
                    if same >= LIM_CONN_IP.load(Ordering::SeqCst) {
                        note_refusal("too many connections from this address", &ip);
                        continue;
                    }
                }
                sh.conns.fetch_add(1, Ordering::SeqCst);
                *sh.conn_ips.lock().unwrap().entry(ip).or_insert(0) += 1;
                let guard = ConnGuard { sh: sh.clone(), ip };
                let sh2 = sh.clone();
                thread::spawn(move || {
                    let _guard = guard;
                    peer_loop(sh2, s, None)
                });
            }
        });
    }
    // outgoing connections: cap MAX_OUT, never two outgoing peers in the same /16
    {
        let sh = shared.clone();
        let mines = cfg.mine_key.is_some();
        thread::spawn(move || {
            let mut no_out_since: Option<Instant> = None;
            let mut warned = false;
            let mut last_evict = Instant::now();
            while !sh.stop.load(Ordering::SeqCst) {
                // The eviction of stuck transactions ran only in the mining loop. A node that does not mine (the seed, the node of a pool, a
                // relay) kept for good the transactions that can no longer go through (a lost claim, an expired job), passed them on again and
                // again, and refused every later transaction of their senders (`admit_tx` wants the nonce to follow the pending sequence):
                // a worker whose claim had lost a race could not send anything any more (seen on the public testnet, 2026-10-25).
                if !mines && last_evict.elapsed() >= Duration::from_secs(5) {
                    last_evict = Instant::now();
                    let mut n = sh.node.lock().unwrap();
                    let ts = now_secs().max(n.chain.tip_ts() + 1);
                    evict_stuck(&mut n, ts, &[0u8; 32]);
                }
                let (todo, mut out_ips, out_count, has_known) = {
                    let n = sh.node.lock().unwrap();
                    let mine = sh.listen.lock().unwrap().clone();
                    let out_ips: Vec<IpAddr> = n.peers.values().filter(|p| p.outbound).filter_map(|p| p.ip).collect();
                    let out_count = n.peers.values().filter(|p| p.outbound).count();
                    let todo: Vec<String> = n
                        .known
                        .iter()
                        .filter(|a| Some(*a) != mine.as_ref() && !n.peers.values().any(|p| p.listen.as_ref() == Some(*a) || &p.addr == *a))
                        .cloned()
                        .collect();
                    (todo, out_ips, out_count, !n.known.is_empty())
                };
                if out_count == 0 && has_known {
                    let t = *no_out_since.get_or_insert_with(Instant::now);
                    if !warned && t.elapsed() > Duration::from_secs(30) {
                        eprintln!("[net] WARNING: no outgoing peer for 30 s (risk of eclipse or unreachable network)");
                        warned = true;
                    }
                } else {
                    no_out_since = None;
                    warned = false;
                }
                let mut count = out_count;
                for a in todo {
                    if count >= MAX_OUT {
                        break;
                    }
                    let Some(sa) = std::net::ToSocketAddrs::to_socket_addrs(&a).ok().and_then(|mut i| i.next()) else { continue };
                    if !outbound_candidate_ok(&out_ips, &sa.ip()) {
                        continue;
                    }
                    if dial(&sh, &a).is_ok() {
                        out_ips.push(sa.ip());
                        count += 1;
                    }
                }
                thread::sleep(Duration::from_millis(500));
            }
        });
    }
    // mining
    if let Some(sk) = cfg.mine_key.clone() {
        let sh = shared.clone();
        let (gpu, log) = (cfg.use_gpu, cfg.log);
        thread::spawn(move || mining_loop(sh, sk, gpu, log));
    }
    Ok(NodeHandle { shared, addr })
}

fn dial(sh: &Arc<Shared>, spec: &str) -> io::Result<()> {
    let (addr, pin) = split_spec(spec);
    if let Some(k) = pin {
        sh.node.lock().unwrap().pins.insert(addr.clone(), k);
    }
    let sa: std::net::SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&addr)?.next().ok_or_else(|| ioerr("bad addr"))?;
    let s = TcpStream::connect_timeout(&sa, Duration::from_secs(3))?;
    let sh2 = sh.clone();
    thread::spawn(move || peer_loop(sh2, s, Some(addr)));
    Ok(())
}

fn hello(sh: &Shared) -> Msg {
    let n = sh.node.lock().unwrap();
    Msg::Hello { node_id: sh.node_id, genesis: sh.genesis_hash, height: n.chain.height(), work: n.chain.total_work(), listen: sh.listen.lock().unwrap().clone() }
}

fn penalize(n: &mut Node, id: u64, pts: u32) -> u32 {
    n.peers.get_mut(&id).map_or(0, |p| {
        p.score += pts;
        p.score
    })
}

fn peer_loop(sh: Arc<Shared>, stream: TcpStream, dialed: Option<String>) {
    let addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let ip = stream.peer_addr().map(|a| a.ip()).ok();
    let _ = stream.set_nodelay(true);
    let kill = stream.try_clone().ok();
    let outbound = dialed.is_some();

    // encrypted channel + mutual authentication (Noise XX) before ANY application exchange
    sh.handshakes.fetch_add(1, Ordering::SeqCst);
    let hs = handshake(stream, &sh.keys, outbound, Duration::from_secs(10));
    sh.handshakes.fetch_sub(1, Ordering::SeqCst);
    let Ok((mut reader, mut writer, remote)) = hs else { return };
    if remote == sh.keys.public {
        return; // connection to ourselves
    }
    if let Some(a) = &dialed {
        if let Some(pin) = sh.node.lock().unwrap().pins.get(a) {
            if *pin != remote {
                eprintln!("[net] key of peer {a} differs from the pinned key: connection refused");
                return;
            }
        }
    }

    let (tx, rx): (SyncSender<Msg>, Receiver<Msg>) = sync_channel(512);
    thread::spawn(move || {
        while let Ok(m) = rx.recv() {
            match encode(&m) {
                Ok(b) => {
                    if writer.write_msg_bytes(&b).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        writer.shutdown();
    });
    let _ = tx.send(hello(&sh));

    let _ = reader.set_read_timeout(Some(Duration::from_secs(10))); // quick Hello after the handshake
    let mut peer_id: Option<u64> = None;
    let (mut tokens, mut last) = (200f64, Instant::now());
    let (mut relay_tokens, mut relay_last) = (2000f64, Instant::now());
    loop {
        let m = match reader.read_msg_bytes().and_then(|b| decode_msg(&b)) {
            Ok(m) => m,
            Err(_) => break,
        };
        // per-peer rate limiting (token bucket: 100 msg/s, burst 200). Relayed requests and replies (docs/21) have a bucket of their
        // own, ten times larger: an audit fetches thousands of chunks, one message each way, and must not cut the worker's connection
        if matches!(m, Msg::RelayForward { .. } | Msg::RelayReply { .. }) {
            relay_tokens = (relay_tokens + relay_last.elapsed().as_secs_f64() * 1000.0).min(2000.0);
            relay_last = Instant::now();
            relay_tokens -= 1.0;
            if relay_tokens < 0.0 {
                break;
            }
        } else {
            tokens = (tokens + last.elapsed().as_secs_f64() * 100.0).min(200.0);
            last = Instant::now();
            tokens -= 1.0;
            if tokens < 0.0 {
                break;
            }
        }
        match &m {
            Msg::Hello { genesis, height, work, listen, .. } => {
                if *genesis != sh.genesis_hash {
                    break;
                }
                let mut n = sh.node.lock().unwrap();
                if n.peers.values().any(|p| p.key == remote) {
                    break; // already connected to this identity
                }
                if !outbound {
                    let inbound_ips: Vec<IpAddr> = n.peers.values().filter(|p| !p.outbound).filter_map(|p| p.ip).collect();
                    let n_in = n.peers.values().filter(|p| !p.outbound).count();
                    let admitted = match ip {
                        Some(ip) => inbound_allowed(&inbound_ips, &ip) && n_in < LIM_IN.load(Ordering::SeqCst),
                        None => n_in < LIM_IN.load(Ordering::SeqCst),
                    };
                    if !admitted {
                        // no room for one more peer: tell it where else to connect (so that a full seed does not leave a new node without
                        // any address), then close
                        if let Some(ip) = ip {
                            note_refusal("no room for another peer (limit per node, per address or per network)", &ip);
                        }
                        let list: Vec<String> = n.known.iter().take(32).cloned().collect();
                        let _ = tx.try_send(Msg::Peers(list));
                        drop(n);
                        thread::sleep(Duration::from_millis(250)); // lets the writer thread send the list before the connection is closed
                        break;
                    }
                }
                let id = n.next_peer;
                n.next_peer += 1;
                let dial_addr = listen.clone().or(dialed.clone());
                if let Some(a) = &dial_addr {
                    if a.len() < 64 && n.known.insert(a.clone()) {
                        save_known(&n);
                    }
                }
                n.peers.insert(id, Peer { tx: tx.clone(), addr: addr.clone(), listen: dial_addr, key: remote, outbound, ip, score: 0, work: *work, height: *height, sync: SyncMode::Idle, kill: kill.as_ref().and_then(|k| k.try_clone().ok()) });
                peer_id = Some(id);
                let _ = reader.set_read_timeout(None);
                let _ = tx.try_send(Msg::GetPeers);
                // a worker tells the relay nodes it dialed (PINNED seeds only: an older node would not understand the message) which
                // account it works for, so that clients that cannot reach it can still audit it through them
                if let (Some(a), Some(sk)) = (&dialed, &n.relay_sk) {
                    if n.pins.contains_key(a) {
                        let sig = sign(sk, &relay_msg(&sh.genesis_hash, &sh.keys.public));
                        let _ = tx.try_send(Msg::RelayAnnounce { account: pubkey(sk), sig });
                    }
                }
                maybe_sync(&mut n, id);
            }
            other => {
                let Some(id) = peer_id else {
                    // clients (CLI): simple requests without Hello
                    if let Msg::RelayRequest { to, req } = other {
                        relay_request(&sh, to, req, &tx); // the reply comes later, from the worker's connection
                        continue;
                    }
                    if let Some(reply) = client_reply(&sh, other) {
                        if matches!(reply, Msg::Ack { ok: true, .. }) && matches!(other, Msg::PutJob { .. } | Msg::PutMlp { .. } | Msg::PutTiled { .. } | Msg::PutProg { .. } | Msg::PutProgMore { .. } | Msg::PutModel { .. } | Msg::PutProgRef { .. } | Msg::PutTiledStage { .. } | Msg::PutTiledDone { .. }) {
                            persist_put(&sh, other);
                        }
                        let _ = tx.try_send(reply);
                        continue;
                    }
                    break;
                };
                if let Msg::RelayForward { id: rid, req } = other {
                    // a relay node forwards a client's read request: answered like a direct client request, in its own thread
                    // (never under the node lock, never in the reading loop), a bounded number at a time
                    let (sh2, tx2, rid, req) = (sh.clone(), tx.clone(), *rid, req.clone());
                    if sh.relay_busy.fetch_add(1, Ordering::SeqCst) >= RELAY_SERVE_MAX {
                        sh.relay_busy.fetch_sub(1, Ordering::SeqCst);
                        let _ = tx.try_send(Msg::RelayReply { id: rid, resp: encode(&Msg::Ack { ok: false, info: "worker busy".into() }).unwrap_or_default() });
                    } else {
                        thread::spawn(move || {
                            let resp = relay_serve(&sh2, &req);
                            sh2.relay_busy.fetch_sub(1, Ordering::SeqCst);
                            let _ = tx2.send(Msg::RelayReply { id: rid, resp });
                        });
                    }
                    continue;
                }
                let r = {
                    let mut n = sh.node.lock().unwrap();
                    on_msg(&sh, &mut n, id, other.clone())
                };
                if let Err(e) = r {
                    if let Some(ip) = ip {
                        sh.node.lock().unwrap().banned.insert(ip, Instant::now());
                    }
                    let _ = tx.try_send(Msg::Ack { ok: false, info: e });
                    break;
                }
            }
        }
    }
    if let Some(id) = peer_id {
        let mut n = sh.node.lock().unwrap();
        n.peers.remove(&id);
        // relay node: the routes of this connection disappear, and the clients waiting on it are told at once
        n.relay_routes.retain(|_, p| *p != id);
        let live: Vec<PubKey> = n.relay_routes.keys().copied().collect();
        n.relay_direct.retain(|a, _| live.contains(a));
        let dead: Vec<u64> = n.relay_pending.iter().filter(|(_, p)| p.peer == id).map(|(k, _)| *k).collect();
        for k in dead {
            if let Some(p) = n.relay_pending.remove(&k) {
                let _ = p.client.try_send(Msg::Ack { ok: false, info: "worker disconnected".into() });
            }
        }
    }
    reader.shutdown();
    if let Some(k) = kill {
        let _ = k.shutdown(Shutdown::Both);
    }
}

/// File of the data deposited by clients with this worker (matrices, weights, inputs): without it, a worker that restarts
/// loses the data of the jobs it has claimed and can no longer execute them (its bond would be lost at the deadline).
const PUT_FILE: &str = "putdata.bin";
const PUT_FILE_MAX: u64 = 2 << 30;

fn persist_put(sh: &Arc<Shared>, m: &Msg) {
    let Some(dir) = sh.node.lock().unwrap().data_dir.clone() else { return };
    let path = dir.join(PUT_FILE);
    if std::fs::metadata(&path).map_or(0, |m| m.len()) >= PUT_FILE_MAX {
        return;
    }
    let Ok(bytes) = encode(m) else { return };
    let res = OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| {
        f.write_all(&(bytes.len() as u32).to_le_bytes())?;
        f.write_all(&bytes)?;
        f.sync_data()
    });
    if let Err(e) = res {
        eprintln!("[store] data deposit not persisted: {e}");
    }
}

/// Reloads the deposited data (at startup, before accepting connections) by replaying the `Put*` requests.
fn load_puts(sh: &Arc<Shared>) {
    let Some(dir) = sh.node.lock().unwrap().data_dir.clone() else { return };
    let Ok(mut f) = File::open(dir.join(PUT_FILE)) else { return };
    let mut count = 0;
    loop {
        let mut l = [0u8; 4];
        if f.read_exact(&mut l).is_err() {
            break;
        }
        let len = u32::from_le_bytes(l) as usize;
        if len > MAX_MSG {
            break;
        }
        let mut buf = vec![0u8; len];
        if f.read_exact(&mut buf).is_err() {
            break; // interrupted write: we keep what was read
        }
        let Ok(m) = decode_msg(&buf) else { break };
        if client_reply(sh, &m).is_some() {
            count += 1;
        }
    }
    if count > 0 {
        eprintln!("[node] {count} job data deposit(s) reloaded from disk");
    }
}

/// `OpsBox` reply: prefix of the requested operations, as bounding boxes, at most OPS_BOX_BUDGET bytes (at least one).
fn ops_box_reply(tensors: &[Vec<i8>], zs: &[Option<Vec<i32>>], ops: &[u8], pn: usize) -> Msg {
    if ops.is_empty() || ops.iter().any(|op| *op as usize >= zs.len()) {
        return Msg::Ack { ok: false, info: "no such operation".into() };
    }
    let (mut items, mut bytes) = (vec![], 0usize);
    for op in ops {
        let (x_dims, x) = box_pack(&tensors[*op as usize + 1], pn);
        let (z_dims, z) = match &zs[*op as usize] {
            Some(z) => {
                let (d, v) = box_pack(z, pn);
                (Some(d), v)
            }
            None => (None, vec![]),
        };
        let sz = x.len() + 4 * z.len();
        if !items.is_empty() && bytes + sz > OPS_BOX_BUDGET {
            break;
        }
        bytes += sz;
        items.push(BoxedOp { x_dims, x, z_dims, z });
    }
    Msg::OpsBox(items)
}

/// RELAY NODE: a client asks for a worker that it cannot reach. The request is checked (read-only, small), the worker is found
/// (announced account, or the worker of the level 2 job), and the request goes down the worker's own connection; the reply
/// comes back through `on_msg` (`RelayReply`) and is handed to the client's channel. Nothing is stored but the pending entry.
fn relay_request(sh: &Arc<Shared>, to: &RelayTo, req: &[u8], client: &SyncSender<Msg>) {
    let nack = |info: &str| {
        let _ = client.try_send(Msg::Ack { ok: false, info: info.to_string() });
    };
    let mut n = sh.node.lock().unwrap();
    if !n.relay {
        return nack("this node is not a relay");
    }
    let bulk = match decode_msg(req) {
        Ok(m) if relay_allowed(&m) && req.len() <= match m { Msg::PutProgRef { .. } => RELAY_MAX_REQ_BULK, Msg::PutModel { .. } => RELAY_MAX_REQ_PUT, _ => RELAY_MAX_REQ } => relay_is_bulk(&m),
        _ => return nack("request not relayable"),
    };
    let account = match to {
        RelayTo::Account(a) => *a,
        RelayTo::L2Job(id) => match n.chain.state.l2.get(id).map(|j| &j.status) {
            Some(crate::l2::L2Status::Claimed { worker, .. }) | Some(crate::l2::L2Status::Posted { worker, .. }) => *worker,
            _ => return nack("no worker for this job"),
        },
    };
    let Some(&pid) = n.relay_routes.get(&account) else { return nack("no relay route to this worker") };
    n.relay_pending.retain(|_, p| p.at.elapsed() < RELAY_TTL);
    if n.relay_pending.len() >= RELAY_MAX_PENDING || n.relay_pending.values().filter(|p| p.peer == pid).count() >= RELAY_PER_ROUTE {
        return nack("relay busy");
    }
    if bulk && (n.relay_pending.values().filter(|p| p.bulk).count() >= RELAY_MAX_BULK || n.relay_pending.values().filter(|p| p.bulk && p.peer == pid).count() >= RELAY_BULK_PER_ROUTE) {
        return nack("relay busy");
    }
    let Some(ptx) = n.peers.get(&pid).map(|p| p.tx.clone()) else {
        n.relay_routes.remove(&account);
        return nack("no relay route to this worker");
    };
    let id = n.relay_next;
    n.relay_next += 1;
    if ptx.try_send(Msg::RelayForward { id, req: req.to_vec() }).is_err() {
        return nack("worker busy");
    }
    n.relay_pending.insert(id, RelayPending { client: client.clone(), peer: pid, at: Instant::now(), bulk });
}

/// WORKER: answers a forwarded request exactly as it would answer the same client directly.
fn relay_serve(sh: &Arc<Shared>, req: &[u8]) -> Vec<u8> {
    let reply = match decode_msg(req) {
        Ok(m) if relay_allowed(&m) => {
            let reply = client_reply(sh, &m).unwrap_or(Msg::Ack { ok: false, info: "unsupported".into() });
            if matches!(reply, Msg::Ack { ok: true, .. }) && matches!(m, Msg::PutProgRef { .. } | Msg::PutModel { .. }) {
                persist_put(sh, &m); // the input of a job is kept as when the client puts it directly
            }
            reply
        }
        _ => Msg::Ack { ok: false, info: "request not relayable".into() },
    };
    encode(&reply).or_else(|_| encode(&Msg::Ack { ok: false, info: "reply too large".into() })).unwrap_or_default()
}

/// Replies to requests from clients that did not send a Hello (CLI).
fn client_reply(sh: &Arc<Shared>, m: &Msg) -> Option<Msg> {
    if let Msg::GetProbe { bytes, nonce } = m {
        return Some(Msg::Probe(probe_bytes(*bytes, *nonce)));
    }
    if let Msg::GetOpsBox { job, ops } | Msg::GetOpsBoxZ { job, ops } = m {
        // the operations of a program are borrowed under the lock (two Arcs) then boxed OUTSIDE the lock: the parallel
        // requests of a client no longer block the node (nor each other)
        let (run, pn) = {
            let n = sh.node.lock().unwrap();
            let run = if n.worker.map_or(false, |w| w.no_serve) { None } else { n.prog_runs.get(job).map(|r| (r.tensors.clone(), r.zs.clone())) };
            (run, n.chain.params.n)
        };
        let zip = matches!(m, Msg::GetOpsBoxZ { .. });
        return Some(match run {
            Some((tensors, zs)) if zip => ops_box_reply_z(&tensors, &zs, ops, pn),
            Some((tensors, zs)) => ops_box_reply(&tensors, &zs, ops, pn),
            None => Msg::Ack { ok: false, info: "no such operation".into() },
        });
    }
    let mut n = sh.node.lock().unwrap();
    let _held = LockTimer::new("client request");
    match m {
        Msg::GetServed(_) | Msg::GetRep(_) | Msg::GetStatus | Msg::FeeBeacon(_) | Msg::GetAccount(_) | Msg::NewTx(_) | Msg::PutJob { .. } | Msg::GetJob(_) | Msg::GetResult(_) | Msg::PutMlp { .. } | Msg::GetMlp(_) | Msg::GetLayer { .. } | Msg::PutTiled { .. } | Msg::GetTiled(_) | Msg::GetTiledGroup { .. } | Msg::PutProg { .. } | Msg::GetProg(_) | Msg::GetOp { .. } | Msg::GetL2(_) | Msg::GetL2Chunk { .. } | Msg::PutProgMore { .. } | Msg::PutModel { .. } | Msg::HasModel { .. } | Msg::PutProgRef { .. } | Msg::PutTiledStage { .. } | Msg::PutTiledDone { .. } | Msg::GetTiledProduct { .. } | Msg::GetTiledSum { .. } | Msg::GetHeaders { .. } | Msg::GetAccountProof(_) | Msg::GetOpsBox { .. } => on_msg_reply(sh, &mut n, m),
        _ => None,
    }
}

fn on_msg_reply(sh: &Arc<Shared>, n: &mut Node, m: &Msg) -> Option<Msg> {
    match m {
        Msg::FeeBeacon(b) => Some(match crate::feeguard::record_beacon(b, now_secs()) {
            Ok(()) => Msg::Ack { ok: true, info: String::new() },
            Err(e) => Msg::Ack { ok: false, info: e },
        }),
        Msg::GetStatus => Some(Msg::Status {
            height: n.chain.height(),
            tip: n.chain.tip_hash(),
            work: n.chain.total_work(),
            mempool: n.mempool.len(),
            peers: n.peers.len(),
            burned: n.chain.state.burned,
            minted: n.chain.state.minted,
            params: (n.chain.params.n as u64, n.chain.params.tile as u64, n.chain.params.rank as u64, n.chain.params.fold_k as u64),
        }),
        Msg::GetAccount(pk) => {
            let pending = n.mempool.iter().filter(|t| &t.tx.from == pk).count() as u64;
            let nonce = n.chain.state.nonce(pk);
            Some(Msg::Account { balance: n.chain.state.balance(pk), nonce, next_nonce: nonce + pending })
        }
        Msg::NewTx(t) => {
            let r = admit_tx(n, t.clone());
            if r.is_ok() {
                broadcast(n, None, &Msg::NewTx(t.clone()));
            }
            let _ = sh;
            Some(Msg::Ack { ok: r.is_ok(), info: r.err().unwrap_or_default() })
        }
        Msg::PutJob { a, b } => {
            let p = n.chain.params;
            if a.len() != p.n * p.n || b.len() != p.n * p.n || a.iter().chain(b.iter()).any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "bad matrices".into() });
            }
            if n.job_data.len() >= 16 {
                return Some(Msg::Ack { ok: false, info: "job data store full".into() });
            }
            let cm = CommittedMatrices::new(a.clone(), b.clone(), &p);
            n.job_data.insert((cm.a_root(), cm.b_root()), Arc::new(cm));
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::GetJob(id) => Some(match n.chain.state.jobs.get(id) {
            Some(j) => {
                let (status, worker) = match &j.status {
                    crate::state::JobStatus::Claimed { worker, .. } => ("Claimed".to_string(), Some(*worker)),
                    crate::state::JobStatus::Posted { worker, at, .. } => (format!("Posted(at={at})"), Some(*worker)),
                    other => (format!("{other:?}"), None),
                };
                Msg::JobInfo { status, escrow_net: j.escrow_net, worker, best_bid: j.best_bid, auction_end_ts: j.auction_end_ts, fetches: j.fetches.iter().map(|f| (f.i, f.j)).collect() }
            }
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::PutProg { x0, ws } => {
            let p = n.chain.params;
            if ws.is_empty() || ws.len() > MAX_WEIGHTS || x0.len() != p.n * p.n || ws.iter().any(|w| w.len() != p.n * p.n) {
                return Some(Msg::Ack { ok: false, info: "bad matrices".into() });
            }
            if x0.iter().chain(ws.iter().flatten()).any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "values out of range".into() });
            }
            if !prog_store_make_room(n) {
                return Some(Msg::Ack { ok: false, info: "program data store full".into() });
            }
            let w_roots: Vec<Hash> = ws.iter().map(|w| rows_tree(w, p.n).root()).collect();
            n.prog_data.push(ProgData { x0_root: cols_tree(x0, p.n).root(), x0: x0.clone(), ws: ws.clone(), w_roots });
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::PutModel { ws } => {
            let p = n.chain.params;
            if ws.is_empty() || ws.iter().any(|w| w.len() != p.n * p.n) || ws.iter().flatten().any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "bad matrices".into() });
            }
            if n.models.len() - n.models_pre + ws.len() > MAX_MODEL_BLOCKS {
                return Some(Msg::Ack { ok: false, info: "model registry full".into() });
            }
            for w in ws {
                n.models.insert(rows_tree(w, p.n).root(), w.clone());
            }
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::HasModel { roots } => Some(Msg::ModelHave { have: roots.iter().map(|r| n.models.contains_key(r)).collect() }),
        Msg::PutProgRef { x0, w_roots } => {
            let p = n.chain.params;
            if w_roots.is_empty() || w_roots.len() > MAX_WEIGHTS || x0.len() != p.n * p.n || x0.iter().any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "bad input".into() });
            }
            if !prog_store_make_room(n) {
                return Some(Msg::Ack { ok: false, info: "program data store full".into() });
            }
            let mut ws = Vec::with_capacity(w_roots.len());
            for r in w_roots {
                match n.models.get(r) {
                    Some(w) => ws.push(w.clone()),
                    None => return Some(Msg::Ack { ok: false, info: "unknown model block (send PutModel first)".into() }),
                }
            }
            n.prog_data.push(ProgData { x0_root: cols_tree(x0, p.n).root(), x0: x0.clone(), ws, w_roots: w_roots.clone() });
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::PutProgMore { x0_root, ws } => {
            let p = n.chain.params;
            let Some(d) = n.prog_data.iter_mut().find(|d| d.x0_root == *x0_root) else {
                return Some(Msg::Ack { ok: false, info: "unknown program data (send PutProg first)".into() });
            };
            if ws.is_empty() || d.ws.len() + ws.len() > MAX_WEIGHTS || ws.iter().any(|w| w.len() != p.n * p.n) {
                return Some(Msg::Ack { ok: false, info: "bad matrices".into() });
            }
            if ws.iter().flatten().any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "values out of range".into() });
            }
            for w in ws {
                d.w_roots.push(rows_tree(w, p.n).root());
                d.ws.push(w.clone());
            }
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::GetProg(id) => Some(match n.chain.state.progs.get(id) {
            Some(j) => Msg::ProgInfo {
                status: format!("{:?}", j.status).split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string(),
                posted: j.posted.len() as u8,
                total: j.ops.len() as u8,
                escrow_net: j.escrow_net,
                roots: j.posted.iter().map(|p| (p.z_root, p.x_root)).collect(),
            },
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::GetL2(id) => Some(match n.chain.state.l2.get(id) {
            Some(j) => Msg::L2Info {
                status: format!("{:?}", j.status).split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string(),
                chunks: j.chunks,
                escrow_net: j.escrow_net,
                root: match &j.status {
                    crate::l2::L2Status::Posted { root, .. } => Some(*root),
                    _ => None,
                },
                kernel: j.kernel.clone(),
            },
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::GetL2Chunk { job, chunk } => Some(match n.l2_runs.get(job) {
            Some(r) if (*chunk as usize) < r.outs.len() => Msg::L2ChunkData { out: r.outs[*chunk as usize].clone(), path: r.tree.proof(*chunk as usize) },
            _ => Msg::Ack { ok: false, info: "no such chunk".into() },
        }),
        Msg::GetOp { job, op } => Some(match n.prog_runs.get(job) {
            _ if n.worker.map_or(false, |w| w.no_serve) => Msg::Ack { ok: false, info: "no such operation".into() }, // TEST worker that withholds the data
            Some(r) if (*op as usize) < r.zs.len() => Msg::OpData { z: r.zs[*op as usize].clone(), x: r.tensors[*op as usize + 1].clone() },
            _ => Msg::Ack { ok: false, info: "no such operation".into() },
        }),
        Msg::GetOpsBox { job, ops } => Some(match n.prog_runs.get(job) {
            _ if n.worker.map_or(false, |w| w.no_serve) => Msg::Ack { ok: false, info: "no such operation".into() },
            Some(r) => ops_box_reply(&r.tensors, &r.zs, ops, n.chain.params.n),
            _ => Msg::Ack { ok: false, info: "no such operation".into() },
        }),
        Msg::GetOpsBoxZ { job, ops } => Some(match n.prog_runs.get(job) {
            _ if n.worker.map_or(false, |w| w.no_serve) => Msg::Ack { ok: false, info: "no such operation".into() },
            Some(r) => ops_box_reply_z(&r.tensors, &r.zs, ops, n.chain.params.n),
            _ => Msg::Ack { ok: false, info: "no such operation".into() },
        }),
        Msg::PutTiled { a, b, dims } => {
            let p = n.chain.params;
            let (bi, bk, bj) = (dims.0 as usize, dims.1 as usize, dims.2 as usize);
            if [bi, bk, bj].iter().any(|d| *d == 0 || *d > MAX_BLOCKS) || a.len() != bi * p.n * bk * p.n || b.len() != bk * p.n * bj * p.n {
                return Some(Msg::Ack { ok: false, info: "bad dimensions".into() });
            }
            if a.iter().chain(b.iter()).any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "values out of range".into() });
            }
            if !tiled_store_make_room(n) {
                return Some(Msg::Ack { ok: false, info: "tiled data store full".into() });
            }
            let (a_roots, b_roots) = (a_block_roots(a, bk * p.n, bi, bk, p.n), b_block_roots(b, bj * p.n, bk, bj, p.n));
            n.tiled_data.push(TiledData { a: a.clone(), b: b.clone(), dims: (bi, bk, bj), a_roots, b_roots });
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::PutTiledStage { key, which, dims, row_start, data } => {
            let p = n.chain.params;
            let (bi, bk, bj) = (dims.0 as usize, dims.1 as usize, dims.2 as usize);
            if [bi, bk, bj].iter().any(|d| *d == 0 || *d > MAX_BLOCKS) || *which > 1 {
                return Some(Msg::Ack { ok: false, info: "bad dimensions".into() });
            }
            if data.iter().any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "values out of range".into() });
            }
            if !n.tiled_stage.contains_key(key) {
                if n.tiled_stage.len() >= 2 {
                    return Some(Msg::Ack { ok: false, info: "too many uploads in progress".into() });
                }
                n.tiled_stage.insert(*key, TiledStage { dims: (bi, bk, bj), a: vec![0; bi * p.n * bk * p.n], b: vec![0; bk * p.n * bj * p.n], a_rows: vec![false; bi * p.n], b_rows: vec![false; bk * p.n] });
            }
            let st = n.tiled_stage.get_mut(key).unwrap();
            if st.dims != (bi, bk, bj) {
                return Some(Msg::Ack { ok: false, info: "dimensions differ from the first chunk".into() });
            }
            let (row_len, buf, got) = if *which == 0 { (bk * p.n, &mut st.a, &mut st.a_rows) } else { (bj * p.n, &mut st.b, &mut st.b_rows) };
            let r0 = *row_start as usize;
            if data.is_empty() || data.len() % row_len != 0 || r0 + data.len() / row_len > got.len() {
                return Some(Msg::Ack { ok: false, info: "bad row range".into() });
            }
            buf[r0 * row_len..r0 * row_len + data.len()].copy_from_slice(data);
            for r in r0..r0 + data.len() / row_len {
                got[r] = true;
            }
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::PutTiledDone { key } => {
            let p = n.chain.params;
            let Some(st) = n.tiled_stage.get(key) else { return Some(Msg::Ack { ok: false, info: "unknown upload".into() }) };
            if !st.a_rows.iter().all(|x| *x) || !st.b_rows.iter().all(|x| *x) {
                return Some(Msg::Ack { ok: false, info: "upload incomplete".into() });
            }
            if !tiled_store_make_room(n) {
                return Some(Msg::Ack { ok: false, info: "tiled data store full".into() });
            }
            let st = n.tiled_stage.remove(key).unwrap();
            let (bi, bk, bj) = st.dims;
            let (a_roots, b_roots) = (a_block_roots(&st.a, bk * p.n, bi, bk, p.n), b_block_roots(&st.b, bj * p.n, bk, bj, p.n));
            n.tiled_data.push(TiledData { a: st.a, b: st.b, dims: st.dims, a_roots, b_roots });
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::GetTiledProduct { .. } | Msg::GetTiledSum { .. } if n.worker.map_or(false, |w| w.no_serve) => Some(Msg::Ack { ok: false, info: "no such data".into() }), // TEST worker that withholds the data
        Msg::GetTiledProduct { job, i, j, k } => Some(match (n.tiled_runs.get(job), n.chain.state.tiled.get(job)) {
            (Some(run), Some(tj)) if (*i as usize) < tj.dims.0 && (*j as usize) < tj.dims.2 && (*k as usize) < tj.dims.1 && run.products.len() == tj.products() => {
                Msg::TiledProduct { p: run.products[tj.pidx(*i as usize, *j as usize, *k as usize)].clone() }
            }
            _ => Msg::Ack { ok: false, info: "no such product".into() },
        }),
        Msg::GetTiledSum { job, i, j } => Some(match (n.tiled_runs.get(job), n.chain.state.tiled.get(job)) {
            (Some(run), Some(tj)) if (*i as usize) < tj.dims.0 && (*j as usize) < tj.dims.2 && run.sums.len() == tj.dims.0 * tj.dims.2 => Msg::TiledSum { c: run.sums[*i as usize * tj.dims.2 + *j as usize].clone() },
            _ => Msg::Ack { ok: false, info: "no such sum".into() },
        }),
        Msg::GetHeaders { from } => Some(Msg::Headers(sync_batch(n, *from as usize, |b| (b.header.clone(), b.proof.clone())))),
        Msg::GetAccountProof(pk) => Some(match n.chain.state.accounts_proof(pk) {
            Some((index, count, path)) => Msg::AccountProof {
                height: n.chain.height(),
                tip: n.chain.tip_hash(),
                balance: n.chain.state.balance(pk),
                nonce: n.chain.state.nonce(pk),
                index: index as u64,
                count: count as u64,
                path,
            },
            None => Msg::Ack { ok: false, info: "unknown account".into() },
        }),
        Msg::GetTiled(id) => Some(match n.chain.state.tiled.get(id) {
            Some(j) => Msg::TiledInfo {
                status: format!("{:?}", j.status).split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string(),
                dims: (j.dims.0 as u8, j.dims.1 as u8, j.dims.2 as u8),
                products: j.products() as u32,
                posted: !j.product_roots.is_empty(),
                escrow_net: j.escrow_net,
                product_roots: j.product_roots.clone(),
                c_roots: j.c_roots.clone(),
            },
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::GetTiledGroup { job, i, j } => Some(match (n.tiled_runs.get(job), n.chain.state.tiled.get(job)) {
            (Some(run), Some(tj)) if (*i as usize) < tj.dims.0 && (*j as usize) < tj.dims.2 && run.products.len() == tj.products() => Msg::TiledGroup {
                products: (0..tj.dims.1).map(|k| run.products[tj.pidx(*i as usize, *j as usize, k)].clone()).collect(),
                c: run.sums[*i as usize * tj.dims.2 + *j as usize].clone(),
            },
            _ => Msg::Ack { ok: false, info: "no such group".into() },
        }),
        Msg::GetServed(id) => Some(match n.chain.state.jobs.get(id) {
            Some(j) => Msg::Served { entries: j.served.clone() },
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::GetRep(pk) => {
            let r = n.chain.state.reputation(pk);
            Some(Msg::Rep { done: r.done, slashed: r.slashed, expired: r.expired })
        }
        Msg::PutMlp { x0, ws } => {
            let p = n.chain.params;
            let ok_len = !ws.is_empty() && ws.len() <= MAX_LAYERS && x0.len() == p.n * p.n && ws.iter().all(|w| w.len() == p.n * p.n);
            if !ok_len || x0.iter().chain(ws.iter().flatten()).any(|v| (*v as i32).abs() > VAL_MAX) {
                return Some(Msg::Ack { ok: false, info: "bad matrices".into() });
            }
            if n.mlp_data.len() >= 8 {
                return Some(Msg::Ack { ok: false, info: "inference data store full".into() });
            }
            let w_roots: Vec<Hash> = ws.iter().map(|w| rows_root_of(w, p.n)).collect();
            n.mlp_data.push(MlpData { x0_root: cols_root_of(x0, p.n), x0: x0.clone(), ws: ws.clone(), w_roots });
            Some(Msg::Ack { ok: true, info: String::new() })
        }
        Msg::GetMlp(id) => Some(match n.chain.state.mlps.get(id) {
            Some(j) => Msg::MlpInfo {
                status: format!("{:?}", j.status).split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_string(),
                layers_posted: j.layers.len() as u8,
                layers_total: j.w_roots.len() as u8,
                escrow_net: j.escrow_net,
                posted: j.layers.iter().map(|l| (l.z_root, l.x_root)).collect(),
            },
            None => Msg::Ack { ok: false, info: "unknown job".into() },
        }),
        Msg::GetLayer { job, layer } => Some(match n.mlp_runs.get(job).and_then(|r| r.layers.get(*layer as usize)) {
            Some((z, x, _, _)) => Msg::LayerData { z: (**z).clone(), x: (**x).clone() },
            None => Msg::Ack { ok: false, info: "no such layer".into() },
        }),
        Msg::GetResult(id) => Some(match n.results.get(id) {
            Some((c, _)) => Msg::JobResult { c: (**c).clone() },
            None => Msg::Ack { ok: false, info: "no result".into() },
        }),
        _ => None,
    }
}

fn broadcast(n: &Node, except: Option<u64>, m: &Msg) {
    for (id, p) in &n.peers {
        if Some(*id) != except {
            let _ = p.tx.try_send(m.clone());
        }
    }
}

fn admit_tx(n: &mut Node, t: SignedTx) -> Result<(), String> {
    let id = t.id();
    if n.mempool_ids.contains(&id) {
        return Err("duplicate".into());
    }
    if n.mempool.len() >= MEMPOOL_MAX {
        return Err("mempool full".into());
    }
    let from = t.tx.from;
    let pending = n.mempool.iter().filter(|x| x.tx.from == from).count();
    if pending >= MEMPOOL_PER_SENDER {
        return Err("too many pending txs for this sender".into());
    }
    let msg = bincode::serialize(&t.tx).map_err(|e| e.to_string())?;
    if !verify_sig(&from, &msg, &t.sig) {
        return Err("bad signature".into());
    }
    if t.tx.nonce != n.chain.state.nonce(&from) + pending as u64 {
        return Err("bad nonce (must follow the sender's pending sequence)".into());
    }
    if n.chain.state.balance(&from) < t.tx.fee {
        return Err("cannot pay fee".into());
    }
    // anti-spam: an EMPTY account cannot pay anything (neither fee, nor amount, nor escrow); without this rule, thousands of throwaway keys
    // would fill the mempool with transactions that will never be included.
    if n.chain.state.balance(&from) == 0 {
        return Err("cannot pay: empty account".into());
    }
    n.mempool_ids.insert(id);
    n.mempool_since.insert(id, Instant::now());
    n.mempool.push(t);
    Ok(())
}

fn prune_mempool(n: &mut Node) {
    let st = &n.chain.state;
    n.mempool.retain(|t| t.tx.nonce >= st.nonce(&t.tx.from));
    n.mempool_ids = n.mempool.iter().map(|t| t.id()).collect();
    let ids = &n.mempool_ids;
    n.mempool_since.retain(|k, _| ids.contains(k));
}

/// Time after which the head transaction of a sender, still not applicable, is considered STUCK.
const STUCK_SECS: u64 = 30;
/// A nonce GAP (the expected transaction is missing: lost in a reorganisation or at restart) is handled faster:
/// if it has not arrived through gossip within a few seconds, it will not arrive.
const GAP_SECS: u64 = 10;

/// Evicts STUCK transactions. A sender's nonces form a sequence: if its first pending transaction can never go through again
/// (e.g. a bid arriving after the end of the auction, a nonce lost after a reorganisation), all the following ones are
/// stuck behind it, and `has_pending` prevents the worker from sending them again -> it stops working.
/// Found by the endurance test (tools/soak.py). After eviction, the worker rebuilds its transactions from the current state.
fn evict_stuck(n: &mut Node, ts: u64, miner: &PubKey) {
    if n.mempool.is_empty() {
        return;
    }
    let now = Instant::now();
    let (st, h, params) = (n.chain.state.clone(), n.chain.height(), n.chain.params);
    let senders: HashSet<PubKey> = n.mempool.iter().map(|t| t.tx.from).collect();
    let mut drop_from: HashSet<PubKey> = HashSet::new();
    for from in senders {
        let expect = st.nonce(&from);
        let Some(head) = n.mempool.iter().filter(|t| t.tx.from == from).min_by_key(|t| t.tx.nonce) else { continue };
        let age = n.mempool_since.get(&head.id()).map_or(u64::MAX, |s| now.duration_since(*s).as_secs());
        if age < if head.tx.nonce != expect { GAP_SECS } else { STUCK_SECS } {
            continue;
        }
        let blocked = head.tx.nonce != expect || st.clone().apply_tx(head, h, ts, miner, &params).is_err();
        if blocked {
            drop_from.insert(from);
        }
    }
    if !drop_from.is_empty() {
        let before = n.mempool.len();
        n.mempool.retain(|t| !drop_from.contains(&t.tx.from));
        prune_mempool(n);
        if std::env::var("VEARL_DEBUG_MEMPOOL").is_ok() {
            eprintln!("[mempool] {} stuck transactions evicted ({} sender(s))", before - n.mempool.len(), drop_from.len());
        }
    }
}

fn maybe_sync(n: &mut Node, id: u64) {
    let my_work = n.chain.total_work();
    let my_h = n.chain.height();
    if let Some(p) = n.peers.get_mut(&id) {
        if p.work > my_work && matches!(p.sync, SyncMode::Idle) {
            p.sync = SyncMode::Extend;
            let _ = p.tx.try_send(Msg::GetBlocks { from: my_h });
        }
    }
}

fn write_frame(f: &mut File, b: &Block) -> io::Result<()> {
    let bytes = bincode::serialize(b).map_err(ioerr)?;
    f.write_all(&(bytes.len() as u32).to_le_bytes())?;
    f.write_all(&bytes)
}

/// Replays the block file; stops (and truncates) at the first invalid or incomplete block.
fn load_chain(chain: &mut Chain, path: &PathBuf) -> usize {
    let Ok(mut f) = File::open(path) else { return 0 };
    let mut ok_bytes = 0u64;
    let mut count = 0;
    loop {
        let mut l = [0u8; 4];
        if f.read_exact(&mut l).is_err() {
            break;
        }
        let len = u32::from_le_bytes(l) as usize;
        if len > MAX_MSG {
            break;
        }
        let mut buf = vec![0u8; len];
        if f.read_exact(&mut buf).is_err() {
            break;
        }
        let Ok(b) = bincode::deserialize::<Block>(&buf) else { break };
        if chain.validate_and_apply(b).is_err() {
            break;
        }
        ok_bytes += 4 + len as u64;
        count += 1;
    }
    drop(f);
    if let Ok(f) = OpenOptions::new().write(true).open(path) {
        let _ = f.set_len(ok_bytes); // discard an interrupted write
    }
    count
}

fn persist(n: &mut Node) {
    let Some(st) = n.store.as_mut() else { return };
    let blocks = &n.chain.blocks;
    let prefix_ok = st.persisted == 0 || blocks.get(st.persisted - 1).map(|b| b.header.hash()) == Some(st.persisted_tip);
    let res = if prefix_ok {
        OpenOptions::new().create(true).append(true).open(&st.path).and_then(|mut f| {
            for b in &blocks[st.persisted.min(blocks.len())..] {
                write_frame(&mut f, b)?;
            }
            f.sync_data()
        })
    } else {
        // reorganisation: the complete chain is rewritten (temporary file + atomic rename)
        let tmp = st.path.with_extension("tmp");
        File::create(&tmp)
            .and_then(|mut f| {
                for b in blocks {
                    write_frame(&mut f, b)?;
                }
                f.sync_data()
            })
            .and_then(|_| std::fs::rename(&tmp, &st.path))
    };
    if res.is_ok() {
        st.persisted = blocks.len();
        st.persisted_tip = blocks.last().map(|b| b.header.hash()).unwrap_or([0u8; 32]);
    } else {
        eprintln!("[store] write failed: {:?}", res.err());
    }
}

fn adopt_tip_changed(sh: &Shared, n: &mut Node) {
    persist(n);
    prune_mempool(n);
    sh.cancel.store(true, Ordering::SeqCst);
}

/// Handles a message from an identified peer. Err(..) => faulty peer (disconnected + banned).
fn on_msg(sh: &Arc<Shared>, n: &mut Node, id: u64, m: Msg) -> Result<(), String> {
    match m {
        Msg::Hello { .. } => {}
        Msg::GetPeers => {
            let list: Vec<String> = n.known.iter().take(32).cloned().collect();
            if let Some(p) = n.peers.get(&id) {
                let _ = p.tx.try_send(Msg::Peers(list));
            }
        }
        Msg::Peers(list) => {
            let before = n.known.len();
            for a in list.into_iter().take(32) {
                if a.len() < 64 && !a.contains('@') && n.known.len() < 256 {
                    n.known.insert(a);
                }
            }
            if n.known.len() != before {
                save_known(n);
            }
        }
        Msg::GetBlocks { from } => {
            let blocks = sync_batch(n, from as usize, |b| b.clone());
            if let Some(p) = n.peers.get(&id) {
                let _ = p.tx.try_send(Msg::Blocks(blocks));
            }
        }
        Msg::NewTx(t) => match admit_tx(n, t.clone()) {
            Ok(()) => broadcast(n, Some(id), &Msg::NewTx(t)),
            Err(e) => {
                // duplicates / full mempool are not faults; an invalid signature, nonce or fee is
                if (e.starts_with("bad ") || e.starts_with("cannot pay")) && penalize(n, id, 10) >= BAN_SCORE {
                    return Err("too many invalid transactions".into());
                }
            }
        },
        Msg::NewBlock(b) => {
            if !n.seen.insert(b.header.hash()) {
                return Ok(()); // already seen: not revalidated (avoids duplicated work on gossip)
            }
            if n.seen.len() > 4096 {
                n.seen.clear();
            }
            let (h, tip, my_h) = (b.header.height, n.chain.tip_hash(), n.chain.height());
            if h == my_h && b.header.prev == tip {
                n.chain.validate_and_apply_at(b.clone(), now_secs()).map_err(|e| format!("invalid block: {e}"))?;
                if let Some(p) = n.peers.get_mut(&id) {
                    p.height = h + 1;
                    p.work = n.chain.total_work();
                }
                adopt_tip_changed(sh, n);
                broadcast(n, Some(id), &Msg::NewBlock(b));
            } else if h >= my_h {
                // late or fork: note that this peer probably has more work and synchronise
                if let Some(p) = n.peers.get_mut(&id) {
                    p.work = p.work.max(n.chain.total_work() + 1);
                    p.height = p.height.max(h + 1);
                }
                maybe_sync(n, id);
            }
        }
        Msg::Blocks(v) => on_blocks(sh, n, id, v)?,
        Msg::GetStatus | Msg::GetAccount(_) | Msg::FeeBeacon(_) => {
            if let Some(r) = on_msg_reply(sh, n, &Msg::GetStatus) {
                if let Some(p) = n.peers.get(&id) {
                    let _ = p.tx.try_send(r);
                }
            }
        }
        Msg::GetHeaders { .. } | Msg::GetAccountProof(_) => {
            // light client connected as a peer (after Hello): we answer on the same connection
            if let Some(r) = on_msg_reply(sh, n, &m) {
                if let Some(p) = n.peers.get(&id) {
                    let _ = p.tx.try_send(r);
                }
            }
        }
        Msg::RelayAnnounce { account, sig } => {
            if n.relay {
                let Some(key) = n.peers.get(&id).map(|p| p.key) else { return Ok(()) };
                if !verify_sig(&account, &relay_msg(&sh.genesis_hash, &key), &sig) {
                    if penalize(n, id, 20) >= BAN_SCORE {
                        return Err("bad relay announcement".into());
                    }
                } else if n.relay_routes.len() < RELAY_MAX_ROUTES || n.relay_routes.contains_key(&account) {
                    n.relay_routes.retain(|_, p| *p != id); // one account per connection
                    n.relay_routes.insert(account, id);
                    // can a connection from here reach the worker itself? (its address as seen by this node + the port it listens on)
                    let dial = n.peers.get(&id).and_then(|p| {
                        let port = p.listen.as_ref()?.rsplit(':').next()?.parse::<u16>().ok()?;
                        Some(format!("{}:{port}", p.ip?))
                    });
                    n.relay_direct.insert(account, RelayDirect { dial: dial.clone(), direct: None, since: now_secs() });
                    if let Some(d) = dial {
                        let sh2 = sh.clone();
                        thread::spawn(move || {
                            let ok = d.parse::<std::net::SocketAddr>().ok().map_or(false, |a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).is_ok());
                            if let Some(e) = sh2.node.lock().unwrap().relay_direct.get_mut(&account) {
                                e.direct = Some(ok);
                            }
                        });
                    }
                    eprintln!("[relay] worker {} reachable through peer {id} ({} route(s))", crate::feeguard::hex(&account[..4]), n.relay_routes.len());
                }
            }
        }
        Msg::RelayReply { id: rid, resp } => {
            // only the connection the request was sent down may answer it
            if n.relay_pending.get(&rid).map_or(false, |p| p.peer == id) {
                if let Some(p) = n.relay_pending.remove(&rid) {
                    let msg = if resp.len() > if p.bulk { RELAY_MAX_RESP_BULK } else { RELAY_MAX_RESP } { Msg::Ack { ok: false, info: "reply too large for a relay".into() } } else { Msg::RelayResponse { resp } };
                    let _ = p.client.try_send(msg);
                }
            }
        }
        Msg::RelayRequest { .. } | Msg::RelayForward { .. } | Msg::RelayResponse { .. } => {}
        Msg::Headers(_) | Msg::AccountProof { .. } | Msg::GetOpsBox { .. } | Msg::OpsBox(_) | Msg::GetOpsBoxZ { .. } | Msg::OpsBoxZ(_) | Msg::GetProbe { .. } | Msg::Probe(_) => {}
        Msg::Status { .. } | Msg::Account { .. } | Msg::Ack { .. } | Msg::JobInfo { .. } | Msg::JobResult { .. } => {}
        Msg::PutJob { .. } | Msg::GetJob(_) | Msg::GetResult(_) | Msg::PutMlp { .. } | Msg::GetMlp(_) | Msg::GetLayer { .. } => {}
        Msg::MlpInfo { .. } | Msg::LayerData { .. } | Msg::Rep { .. } | Msg::GetRep(_) | Msg::GetServed(_) | Msg::Served { .. } => {}
        Msg::PutTiled { .. } | Msg::GetTiled(_) | Msg::GetTiledGroup { .. } | Msg::TiledInfo { .. } | Msg::TiledGroup { .. } => {}
        Msg::PutProg { .. } | Msg::GetProg(_) | Msg::GetOp { .. } | Msg::ProgInfo { .. } | Msg::OpData { .. } => {}
        Msg::GetL2(_) | Msg::GetL2Chunk { .. } | Msg::L2Info { .. } | Msg::L2ChunkData { .. } | Msg::PutProgMore { .. } => {}
        Msg::PutModel { .. } | Msg::HasModel { .. } | Msg::ModelHave { .. } | Msg::PutProgRef { .. } => {}
        Msg::PutTiledStage { .. } | Msg::PutTiledDone { .. } | Msg::GetTiledProduct { .. } | Msg::TiledProduct { .. } | Msg::GetTiledSum { .. } | Msg::TiledSum { .. } => {}
    }
    Ok(())
}

/// Sync batch starting at `from`: at most BATCH items and at most `sync_budget` bytes (at least one item). The
/// requester keeps going as long as the batch is not EMPTY (it no longer assumes that an incomplete batch is the end of the chain).
fn sync_batch<T: Serialize>(n: &Node, from: usize, f: impl Fn(&Block) -> T) -> Vec<T> {
    let (mut out, mut bytes) = (Vec::new(), 0u64);
    for b in n.chain.blocks.iter().skip(from).take(BATCH) {
        let item = f(b);
        let sz = bincode::serialized_size(&item).unwrap_or(u64::MAX);
        if !out.is_empty() && bytes.saturating_add(sz) > n.sync_budget {
            break;
        }
        bytes = bytes.saturating_add(sz);
        out.push(item);
    }
    out
}

fn on_blocks(sh: &Arc<Shared>, n: &mut Node, id: u64, v: Vec<Block>) -> Result<(), String> {
    let Some(p) = n.peers.get_mut(&id) else { return Ok(()) };
    let sync = std::mem::replace(&mut p.sync, SyncMode::Idle);
    match sync {
        SyncMode::Idle => Ok(()), // unsolicited
        SyncMode::Extend => {
            if v.is_empty() {
                return Ok(());
            }
            let connects = v[0].header.height == n.chain.height() && v[0].header.prev == n.chain.tip_hash();
            if !connects {
                // fork: walk back to the common ancestor (instead of downloading and replaying the peer's whole chain again)
                let from = n.chain.height().saturating_sub(LOCATE_STEP);
                let p = n.peers.get_mut(&id).unwrap();
                p.sync = SyncMode::Locate { from, step: LOCATE_STEP };
                let _ = p.tx.try_send(Msg::GetBlocks { from });
                return Ok(());
            }
            for b in v {
                n.chain.validate_and_apply_at(b, now_secs()).map_err(|e| format!("invalid synced block: {e}"))?;
            }
            adopt_tip_changed(sh, n);
            let (my_h, my_tip) = (n.chain.height(), n.chain.tip_hash());
            let _ = my_tip;
            if let Some(p) = n.peers.get_mut(&id) {
                p.height = p.height.max(my_h);
                // non-empty batch: ask for the next one (the end is signalled by an empty batch)
                p.sync = SyncMode::Extend;
                let _ = p.tx.try_send(Msg::GetBlocks { from: my_h });
            }
            let tip = n.chain.tip_hash();
            broadcast(n, Some(id), &Msg::NewBlock(n.chain.blocks.last().unwrap().clone()));
            let _ = tip;
            Ok(())
        }
        SyncMode::Locate { from, step } => {
            // the batch must connect to OUR chain at height `from`; otherwise we step back further
            let joins = |b: &Block| b.header.height == from && (from == 0 || n.chain.blocks.get(from as usize - 1).map(|m| m.header.hash()) == Some(b.header.prev));
            match v.first() {
                None => Err("peer has no blocks at the requested height".into()),
                Some(b0) if joins(b0) => {
                    let next = from + v.len() as u64;
                    let p = n.peers.get_mut(&id).unwrap();
                    p.sync = SyncMode::Fork { base: from, buf: v };
                    let _ = p.tx.try_send(Msg::GetBlocks { from: next });
                    Ok(())
                }
                Some(_) => {
                    if from == 0 {
                        return Err("peer chain does not share our genesis".into());
                    }
                    let (nf, ns) = (from.saturating_sub(step * 2), step * 2);
                    let p = n.peers.get_mut(&id).unwrap();
                    p.sync = SyncMode::Locate { from: nf, step: ns };
                    let _ = p.tx.try_send(Msg::GetBlocks { from: nf });
                    Ok(())
                }
            }
        }
        SyncMode::Fork { base, mut buf } => {
            let more = !v.is_empty();
            buf.extend(v);
            if buf.len() > 200_000 {
                return Err("peer chain too long".into());
            }
            if more {
                let next = base + buf.len() as u64;
                let p = n.peers.get_mut(&id).unwrap();
                p.sync = SyncMode::Fork { base, buf };
                let _ = p.tx.try_send(Msg::GetBlocks { from: next });
                return Ok(());
            }
            finish_fork(sh, n, id, base, buf)
        }
    }
}

/// Peer chain received from `base`: skip the common prefix, then try the reorganisation (atomic, MESS included).
fn finish_fork(sh: &Arc<Shared>, n: &mut Node, id: u64, base: u64, buf: Vec<Block>) -> Result<(), String> {
    let common = buf.iter().enumerate().take_while(|(i, b)| n.chain.blocks.get(base as usize + i).map(|m| m.header.hash()) == Some(b.header.hash())).count();
    let fork_h = base + common as u64;
    let cand: Vec<Block> = buf.into_iter().skip(common).collect();
    if cand.is_empty() {
        return Ok(()); // the peer has nothing more than us
    }
    let (mess, now) = (n.mess, now_secs());
    match n.chain.try_reorg(fork_h, cand, now, mess) {
        Ok(old) => {
            // transactions of the abandoned branch that the new chain did not include: to be put back into the mempool
            let new_ids: HashSet<Hash> = n.chain.blocks[fork_h as usize..].iter().flat_map(|b| b.txs.iter().map(|t| t.id())).collect();
            let orphaned: Vec<SignedTx> = old.iter().flat_map(|b| b.txs.iter().cloned()).filter(|t| !new_ids.contains(&t.id())).collect();
            let depth = old.len();
            adopt_tip_changed(sh, n);
            let readded = orphaned.into_iter().filter(|t| admit_tx(n, t.clone()).is_ok()).count();
            if depth > 0 || readded > 0 {
                eprintln!("[node] reorganisation: {depth} block(s) abandoned, {readded} transaction(s) put back into the mempool");
            }
            if let Some(b) = n.chain.blocks.last().cloned() {
                broadcast(n, Some(id), &Msg::NewBlock(b));
            }
            Ok(())
        }
        Err(e) if e.starts_with("invalid candidate block") => Err(e), // invalid block: faulty peer
        Err(e) => {
            if std::env::var("VEARL_DEBUG_SYNC").is_ok() {
                eprintln!("[node] fork refused: {e}");
            }
            Ok(()) // insufficient work or MESS slowdown: not a fault of the peer
        }
    }
}

pub fn select_txs(n: &Node, miner: &PubKey, ts: u64) -> Vec<SignedTx> {
    let mut st = n.chain.state.clone();
    let height = n.chain.height();
    let mut out = Vec::new();
    let mut bytes = 0u64;
    let debug = std::env::var("VEARL_DEBUG_MEMPOOL").is_ok();
    let mut skipped: Vec<String> = Vec::new();
    for t in &n.mempool {
        if out.len() >= 200 {
            break;
        }
        let sz = bincode::serialized_size(t).unwrap_or(u64::MAX);
        if bytes.saturating_add(sz) > MAX_BLOCK_TX_BYTES {
            continue; // no longer fits in this block (consensus rule): it will wait for the next one
        }
        if matches!(&t.tx.kind, TxKind::L2(crate::l2::L2Tx::Fraud { .. })) && out.iter().filter(|o: &&SignedTx| matches!(&o.tx.kind, TxKind::L2(crate::l2::L2Tx::Fraud { .. }))).count() >= MAX_L2_FRAUD_PER_BLOCK {
            continue; // consensus cap on level 2 fraud proofs per block: this one will wait for the next
        }
        let mut probe = st.clone();
        match probe.apply_tx(t, height, ts, miner, &n.chain.params) {
            Ok(()) => {
                st = probe;
                bytes += sz;
                out.push(t.clone());
            }
            Err(e) => {
                if debug {
                    skipped.push(format!("{} (nonce {}): {e}", format!("{:?}", t.tx.kind).chars().take(24).collect::<String>(), t.tx.nonce));
                }
            }
        }
    }
    if debug && !skipped.is_empty() {
        // VEARL_DEBUG_MEMPOOL=1: at most one line every 10 s, to diagnose transactions that do not go through
        static LAST: AtomicU64 = AtomicU64::new(0);
        let now = now_secs();
        if now >= LAST.load(Ordering::Relaxed) + 10 {
            LAST.store(now, Ordering::Relaxed);
            eprintln!("[mempool] {} tx not includable at height {}: {:?}", skipped.len(), height, &skipped[..skipped.len().min(6)]);
        }
    }
    out
}

/// Pushes a transaction of the node itself into its mempool (nonce = sequence of the pending transactions).
fn push_own_tx(n: &mut Node, sk: &SigningKey, kind: TxKind) {
    let from = pubkey(sk);
    let pending = n.mempool.iter().filter(|t| t.tx.from == from).count() as u64;
    let tx = SignedTx::new(Tx { from, nonce: n.chain.state.nonce(&from) + pending, fee: 0, kind }, sk);
    // The transaction must also be RELAYED: otherwise it would only be included if this node finds a block itself, which almost never happens to a small miner
    // (or to a node whose mining is paused during another miner's window).
    if admit_tx(n, tx.clone()).is_ok() {
        broadcast(n, None, &Msg::NewTx(tx));
    }
}

fn has_pending(n: &Node, me: &PubKey, pred: impl Fn(&TxKind) -> bool) -> bool {
    n.mempool.iter().any(|t| &t.tx.from == me && pred(&t.tx.kind))
}

enum Target {
    Job(JobId, Arc<CommittedMatrices>),
    Layer(JobId, u8, Arc<CommittedMatrices>),
    Product(JobId, (u8, u8, u8), Arc<CommittedMatrices>),
    Op(JobId, u8, Arc<CommittedMatrices>),
}

/// Every mining node reports data requests left unanswered (it receives half of the bond).
fn slash_step(n: &mut Node, sk: &SigningKey) {
    let me = pubkey(sk);
    // CHAIN time (the deadline is in block timestamp, which may run ahead of the wall clock by 60 s)
    let now = n.chain.tip_ts() + 1;
    let todo: Vec<JobId> = n
        .chain
        .state
        .jobs
        .iter()
        .filter(|(_, j)| {
            matches!(&j.status, crate::state::JobStatus::Posted { worker, .. } if *worker != me) && j.fetches.iter().any(|f| now > f.deadline_ts)
        })
        .map(|(id, _)| *id)
        .collect();
    for id in todo {
        if !has_pending(n, &me, |k| matches!(k, TxKind::SlashUnserved { job_id } if *job_id == id)) {
            push_own_tx(n, sk, TxKind::SlashUnserved { job_id: id });
        }
    }
    // tensor programs: same monitoring of data requests left unanswered
    let ptodo: Vec<JobId> = n
        .chain
        .state
        .progs
        .iter()
        .filter(|(_, j)| matches!(&j.status, ProgStatus::Complete { worker, .. } if *worker != me) && j.fetches.iter().any(|f| now > f.deadline_ts))
        .map(|(id, _)| *id)
        .collect();
    for id in ptodo {
        if !has_pending(n, &me, |k| matches!(k, TxKind::Prog(ProgTx::SlashUnserved { job_id }) if *job_id == id)) {
            push_own_tx(n, sk, TxKind::Prog(ProgTx::SlashUnserved { job_id: id }));
        }
    }
    // block products
    let ttodo: Vec<JobId> = n
        .chain
        .state
        .tiled
        .iter()
        .filter(|(_, j)| matches!(&j.status, TiledStatus::Posted { worker, .. } if *worker != me) && j.fetches.iter().any(|f| now > f.deadline_ts))
        .map(|(id, _)| *id)
        .collect();
    for id in ttodo {
        if !has_pending(n, &me, |k| matches!(k, TxKind::Tiled(TiledTx::SlashUnserved { job_id }) if *job_id == id)) {
            push_own_tx(n, sk, TxKind::Tiled(TiledTx::SlashUnserved { job_id: id }));
        }
    }
}

/// Worker logic: claim the jobs whose data we have, compute/publish, settle after the window.
/// Returns the mining target (Job or Layer class) if one is active for this node.
/// A worker computes a paid job IN THE BACKGROUND (block products, programs, level 2): the GPU is not free for another miner.
fn background_compute_busy(n: &Node) -> bool {
    n.worker.is_some() && (!n.tiled_computing.is_empty() || !n.prog_computing.is_empty() || !n.l2_computing.is_empty())
}

fn worker_step(n: &mut Node, sk: &SigningKey) -> Option<Target> {
    use crate::state::JobStatus;
    let me = pubkey(sk);
    let height = n.chain.height();
    let now = now_secs().max(n.chain.tip_ts() + 1);
    let mut active = None;

    let jobs: Vec<(JobId, crate::state::Job)> = n.chain.state.jobs.iter().map(|(k, v)| (*k, v.clone())).collect();
    for (id, j) in jobs {
        let Some(data) = n.job_data.get(&(j.a_root, j.b_root)).cloned() else { continue };
        match j.status {
            JobStatus::Open if height <= j.deadline => {
                let tip_ts = n.chain.tip_ts() + 1;
                if j.auction_end_ts > 0 {
                    let ask = n.worker.and_then(|w| w.ask);
                    if tip_ts < j.auction_end_ts {
                        // auction open: we bid our price if it beats the best bid
                        if let Some(ask) = ask {
                            let beats = j.best_bid.map_or(true, |(_, b)| ask < b) && ask <= j.escrow_net && ask > 0;
                            if beats && !has_pending(n, &me, |k| matches!(k, TxKind::Bid { job_id, .. } if *job_id == id)) {
                                push_own_tx(n, sk, TxKind::Bid { job_id: id, price: ask });
                            }
                        }
                    } else {
                        // auction finished: the winner claims; with no bid or after the grace period, claim at the full price
                        let mine = j.best_bid.map_or(false, |(w, _)| w == me);
                        let open_to_all = j.best_bid.is_none() || tip_ts >= j.auction_end_ts + crate::state::AUCTION_GRACE_SECS;
                        let wants_full_price = ask.is_none() && open_to_all;
                        if (mine || wants_full_price) && !has_pending(n, &me, |k| matches!(k, TxKind::ClaimJob { job_id } if *job_id == id)) {
                            push_own_tx(n, sk, TxKind::ClaimJob { job_id: id });
                        }
                    }
                } else if !has_pending(n, &me, |k| matches!(k, TxKind::ClaimJob { job_id } if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::ClaimJob { job_id: id });
                }
            }
            JobStatus::Claimed { worker, .. } if worker == me => {
                if let Some((_, c_root)) = n.results.get(&id).cloned() {
                    if !has_pending(n, &me, |k| matches!(k, TxKind::PostResult { job_id, .. } if *job_id == id)) {
                        push_own_tx(n, sk, TxKind::PostResult { job_id: id, c_root });
                    }
                }
                if active.is_none() {
                    active = Some(Target::Job(id, data));
                }
            }
            JobStatus::Posted { worker, at, at_ts, .. } if worker == me => {
                // after a restart the result (C) is no longer in memory: we recompute it by mining a block on the job
                // (the data was reloaded from disk), otherwise we could no longer SERVE the requested data
                if !n.results.contains_key(&id) && active.is_none() {
                    active = Some(Target::Job(id, data.clone()));
                }
                if !n.worker.map_or(false, |w| w.no_serve) {
                    if let Some((c, _)) = n.results.get(&id).cloned() {
                        let tree = c_tree(&c, n.chain.params.n);
                        for f in &j.fetches {
                            let (fi, fj) = (f.i, f.j);
                            if !has_pending(n, &me, |k| matches!(k, TxKind::Serve { job_id, i, j, .. } if *job_id == id && *i == fi && *j == fj)) {
                                let row = row_of(&c, n.chain.params.n, fi as usize);
                                push_own_tx(n, sk, TxKind::Serve { job_id: id, i: fi, j: fj, row, path: tree.proof(fi as usize) });
                            }
                        }
                    }
                }
                if j.fetches.is_empty() && !n.chain.state.timing.challenge_open(height, now, at, at_ts) && !has_pending(n, &me, |k| matches!(k, TxKind::Settle { job_id } if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Settle { job_id: id });
                }
            }
            _ => {}
        }
    }

    // block-product matrix jobs
    let done: Vec<(JobId, TiledRun)> = std::mem::take(&mut *n.tiled_inbox.lock().unwrap());
    for (id, run) in done {
        n.tiled_computing.remove(&id);
        n.tiled_runs.insert(id, run);
    }
    let tjobs: Vec<(JobId, TiledJob)> = n.chain.state.tiled.iter().map(|(k, v)| (*k, v.clone())).collect();
    for (id, j) in tjobs {
        let Some(di) = n.tiled_data.iter().position(|d| d.dims == j.dims && d.a_roots == j.a_roots && d.b_roots == j.b_roots) else { continue };
        match &j.status {
            TiledStatus::Open if height <= j.deadline => {
                if !has_pending(n, &me, |k| matches!(k, TxKind::Tiled(TiledTx::Claim { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Tiled(TiledTx::Claim { job_id: id }));
                }
            }
            TiledStatus::Claimed { worker, .. } if *worker == me => {
                let p = n.chain.params;
                if !n.tiled_runs.contains_key(&id) {
                    // full computation of the result + Merkle roots, IN THE BACKGROUND (outside the node lock: for large sizes it
                    // takes seconds); the result is merged back on the next turn
                    if n.tiled_computing.insert(id) {
                        let d = &n.tiled_data[di];
                        let (a, b, dims) = (d.a.clone(), d.b.clone(), d.dims);
                        let w = n.worker.unwrap_or_default();
                        let inbox = n.tiled_inbox.clone();
                        let (nn, bk) = (p.n, j.dims.1);
                        thread::spawn(move || {
                            let t_start = Instant::now();
                            let (mut products, mut sums) = compute_all(&a, &b, dims, nn);
                            let t_gemm = t_start.elapsed().as_secs_f64();
                            if w.cheat && products.len() > 1 {
                                let idx = 1;
                                let l = products[idx].len();
                                products[idx][l / 3] += 1; // TEST: a wrong product
                                // the sums are recomputed from the published products: only the block's GEMM is wrong
                                for ij in 0..sums.len() {
                                    let mut s = vec![0i32; nn * nn];
                                    for k in 0..bk {
                                        for (x, v) in s.iter_mut().zip(&products[ij * bk + k]) {
                                            *x += *v;
                                        }
                                    }
                                    sums[ij] = s;
                                }
                            }
                            if w.cheat_sum {
                                let l = sums[0].len();
                                sums[0][l / 2] -= 1; // TEST: correct products, wrong sum
                            }
                            let roots = |v: &Vec<Vec<i32>>| -> Vec<Hash> {
                                let threads = thread::available_parallelism().map_or(1, |x| x.get()).min(v.len()).max(1);
                                let per = (v.len() + threads - 1) / threads;
                                thread::scope(|sc| {
                                    let hs: Vec<_> = v.chunks(per).map(|ch| sc.spawn(move || ch.iter().map(|x| c_root(x, nn)).collect::<Vec<Hash>>())).collect();
                                    hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
                                })
                            };
                            let (product_roots, c_roots) = (roots(&products), roots(&sums));
                            eprintln!("[worker] block product {}x{}x{}: {} exact GEMMs {:.2} s, {} Merkle roots {:.2} s", dims.0, dims.1, dims.2, products.len(), t_gemm, products.len() + sums.len(), t_start.elapsed().as_secs_f64() - t_gemm);
                            inbox.lock().unwrap().push((id, TiledRun { product_roots, c_roots, products, sums, ..Default::default() }));
                        });
                    }
                    continue;
                }
                let run = n.tiled_runs.get(&id).unwrap();
                if !has_pending(n, &me, |k| matches!(k, TxKind::Tiled(TiledTx::Post { job_id, .. }) if *job_id == id)) {
                    let (pr, cr) = (run.product_roots.clone(), run.c_roots.clone());
                    push_own_tx(n, sk, TxKind::Tiled(TiledTx::Post { job_id: id, product_roots: pr, c_roots: cr }));
                }
                // meanwhile: we mine products (any of them) so that the useful computation feeds the lottery
                if active.is_none() {
                    let run = n.tiled_runs.get_mut(&id).unwrap();
                    let total = j.products();
                    let flat = run.next % total;
                    run.next += 1;
                    let (bk, bj) = (j.dims.1, j.dims.2);
                    let (i, jj, k) = (flat / (bj * bk), (flat % (bj * bk)) / bk, flat % bk);
                    let key = (i as u8, jj as u8, k as u8);
                    let cm = match run.cms.get(&key) {
                        Some(cm) => cm.clone(),
                        None => {
                            let d = &n.tiled_data[di];
                            let cm = Arc::new(CommittedMatrices::new(get_block(&d.a, d.dims.1 * p.n, i, k, p.n), get_block(&d.b, d.dims.2 * p.n, k, jj, p.n), &p));
                            n.tiled_runs.get_mut(&id).unwrap().cms.insert(key, cm.clone());
                            cm
                        }
                    };
                    active = Some(Target::Product(id, key, cm));
                }
            }
            TiledStatus::Posted { worker, at, at_ts, .. } if *worker == me => {
                // client data requests: we serve them (except for a --no-serve test worker)
                if !n.worker.map_or(false, |w| w.no_serve) && n.tiled_runs.contains_key(&id) {
                    for f in &j.fetches {
                        let fk = (f.which, f.i, f.j, f.k, f.idx);
                        if !has_pending(n, &me, |t| matches!(t, TxKind::Tiled(TiledTx::Serve { job_id, which, i, j: jj, k, idx, .. }) if *job_id == id && (*which, *i, *jj, *k, *idx) == fk)) {
                            let run = &n.tiled_runs[&id];
                            let pn = n.chain.params.n;
                            let data = if f.which == 0 { &run.products[j.pidx(f.i as usize, f.j as usize, f.k as usize)] } else { &run.sums[f.i as usize * j.dims.2 + f.j as usize] };
                            let r = f.idx as usize / pn;
                            let (row, path) = (row_of(data, pn, r), c_tree(data, pn).proof(r));
                            push_own_tx(n, sk, TxKind::Tiled(TiledTx::Serve { job_id: id, which: f.which, i: f.i, j: f.j, k: f.k, idx: f.idx, row, path }));
                        }
                    }
                }
                if j.fetches.is_empty() && !n.chain.state.timing.challenge_open(height, now, *at, *at_ts) && !has_pending(n, &me, |k| matches!(k, TxKind::Tiled(TiledTx::Settle { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Tiled(TiledTx::Settle { job_id: id }));
                }
            }
            _ => {}
        }
    }

    // verifiable tensor programs
    let done: Vec<(JobId, ProgRun)> = std::mem::take(&mut *n.prog_inbox.lock().unwrap());
    for (id, run) in done {
        n.prog_computing.remove(&id);
        n.prog_runs.insert(id, run);
    }
    // a run of a job that this worker no longer holds is dropped: its claim lived on a chain branch that was reorganised away (the job is open again
    // or another worker holds it), and serving the data would make two workers answer for the same job
    {
        let stale: Vec<JobId> = n
            .prog_runs
            .keys()
            .filter(|id| match n.chain.state.progs.get(*id).map(|j| &j.status) {
                Some(ProgStatus::Open) => true,
                Some(ProgStatus::Working { worker, .. }) | Some(ProgStatus::Complete { worker, .. }) => *worker != me,
                _ => false,
            })
            .copied()
            .collect();
        for id in stale {
            n.prog_runs.remove(&id);
        }
    }
    // claims that lost the race (another worker took the job first) will never go through and would block every later transaction of this
    // worker (nonces) until the eviction of stuck transactions: when everything from the first lost claim on is a claim, drop it all at once,
    // the jobs still open are claimed again with fresh nonces at the next turn.
    // Level 2 claims count too: with many workers racing for the same public jobs, a lost level 2 claim sat in front of the claims of the AI
    // jobs (one nonce sequence per account) and nothing went through (seen on the public testnet, 2026-10-25).
    {
        let mut mine: Vec<(u64, bool, bool)> = n
            .mempool
            .iter()
            .filter(|t| t.tx.from == me)
            .map(|t| match &t.tx.kind {
                TxKind::Prog(ProgTx::Claim { job_id }) => (t.tx.nonce, true, !matches!(n.chain.state.progs.get(job_id).map(|j| &j.status), Some(ProgStatus::Open))),
                TxKind::L2(crate::l2::L2Tx::Claim { job_id }) => (
                    t.tx.nonce,
                    true,
                    !n.chain.state.l2.get(job_id).map_or(false, |j| j.claimable_at(&n.chain.state.timing, height, now)),
                ),
                _ => (t.tx.nonce, false, false),
            })
            .collect();
        mine.sort();
        if let Some(first_lost) = mine.iter().position(|m| m.2) {
            if mine[first_lost..].iter().all(|m| m.1) {
                let from_nonce = mine[first_lost].0;
                n.mempool.retain(|t| !(t.tx.from == me && t.tx.nonce >= from_nonce));
                prune_mempool(n);
            }
        }
    }
    let mut pjobs: Vec<(JobId, ProgJob)> = n.chain.state.progs.iter().map(|(k, v)| (*k, v.clone())).collect();
    // several workers may hold the data of the same jobs (the client deposited it with each of them): each looks at the queue in its own
    // order and takes at most PROG_ACTIVE jobs at a time, so that the jobs spread over the workers instead of all going to the first claim
    pjobs.sort_by_key(|(id, _)| id.iter().zip(me.iter()).fold(0u64, |a, (x, y)| a.wrapping_mul(1_000_003).wrapping_add((x ^ y) as u64 + 1)));
    let prog_cap = match n.worker.map_or(0, |w| w.max_jobs) {
        0 | 1 => PROG_ACTIVE, // default
        k => k,         // set explicitly with --max-jobs
    };
    let mut prog_busy = pjobs
        .iter()
        .filter(|(id, j)| match &j.status {
            ProgStatus::Working { worker, .. } => *worker == me,
            ProgStatus::Open => has_pending(n, &me, |k| matches!(k, TxKind::Prog(ProgTx::Claim { job_id }) if job_id == id)),
            _ => false,
        })
        .count();
    for (id, j) in pjobs {
        let Some(di) = n.prog_data.iter().position(|d| d.x0_root == j.x0_root && d.w_roots == j.w_roots) else { continue };
        match &j.status {
            ProgStatus::Open if height <= j.deadline => {
                if prog_busy < prog_cap && !has_pending(n, &me, |k| matches!(k, TxKind::Prog(ProgTx::Claim { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Prog(ProgTx::Claim { job_id: id }));
                    prog_busy += 1;
                }
            }
            ProgStatus::Working { worker, .. } if *worker == me => {
                let p = n.chain.params;
                if !n.prog_runs.contains_key(&id) {
                    // full execution + Merkle roots IN THE BACKGROUND (outside the node lock): a 195-operation program at
                    // n = 1024 takes seconds, during which all requests (clients, peers) were waiting; merged back on the next turn
                    if n.prog_computing.insert(id) {
                        let d = &n.prog_data[di];
                        let (x0, ws, ops) = (d.x0.clone(), d.ws.clone(), j.ops.clone());
                        let w = n.worker.unwrap_or_default();
                        let inbox = n.prog_inbox.clone();
                        let nn = p.n;
                        thread::spawn(move || {
                            let (mut tensors, mut zs) = (vec![x0], Vec::<Option<Vec<i32>>>::new());
                            let mut gemm_seen = 0;
                            let mut col_cheated = false;
                            for (k, op) in ops.iter().enumerate() {
                                let (mut z, mut out) = eval_op(op, &tensors, &ws, nn);
                                if let Op::Gemm { shift, relu, .. } | Op::GemmAT { shift, relu, .. } = op {
                                    gemm_seen += 1;
                                    if w.cheat && gemm_seen == 2 {
                                        let zz = z.as_mut().unwrap();
                                        zz[3 * nn + 5] += 1 << *shift; // TEST: wrong GEMM (output consistent with the falsified Z)
                                        out = zz.iter().map(|&v| act_fn(v, *shift, *relu)).collect();
                                    }
                                    if w.cheat_act && gemm_seen == 1 {
                                        out[0] = out[0].wrapping_add(1); // TEST: wrong activation, correct Z
                                    }
                                } else if w.cheat_elem && k == 0 && !op.is_col_op() {
                                    out[0] = out[0].wrapping_add(1); // TEST: wrong output of the non-Gemm operation
                                } else if w.cheat_col && op.is_col_op() && !col_cheated {
                                    col_cheated = true;
                                    out[0] = out[0].wrapping_add(1); // TEST: wrong column 0 (softmax / normalisation)
                                }
                                zs.push(z);
                                tensors.push(out);
                            }
                            let roots = crate::crypto::par_map_heavy(zs.len(), |k| (zs[k].as_ref().map_or([0u8; 32], |z| c_root(z, nn)), cols_tree(&tensors[k + 1], nn).root()));
                            inbox.lock().unwrap().push((id, ProgRun { tensors: Arc::new(tensors), zs: Arc::new(zs), roots, cms: HashMap::new(), next: 0 }));
                        });
                    }
                    continue;
                }
                // publish all the remaining operations, in order (sequential nonces in the same block); roots already computed
                let run = n.prog_runs.get(&id).unwrap();
                let to_post: Vec<(u8, Hash, Hash)> = (j.posted.len()..j.ops.len()).map(|k| (k as u8, run.roots[k].0, run.roots[k].1)).collect();
                if let Some(&(first, _, _)) = to_post.first() {
                    // ONE transaction for all the remaining operations (PostBatch): the chain no longer carries #ops transactions per job
                    let posts: Vec<(Hash, Hash)> = to_post.iter().map(|(_, z, x)| (*z, *x)).collect();
                    if !has_pending(n, &me, |t| matches!(t, TxKind::Prog(ProgTx::PostBatch { job_id, op, .. }) if *job_id == id && *op == first)) {
                        push_own_tx(n, sk, TxKind::Prog(ProgTx::PostBatch { job_id: id, op: first, posts }));
                    }
                }
            }
            ProgStatus::Complete { worker, at, at_ts, .. } if *worker == me => {
                // client data requests: we serve them (except for a --no-serve test worker)
                if !n.worker.map_or(false, |w| w.no_serve) && n.prog_runs.contains_key(&id) {
                    for f in &j.fetches {
                        let (tensor, col) = (f.tensor, f.col);
                        if !has_pending(n, &me, |k| matches!(k, TxKind::Prog(ProgTx::Serve { job_id, tensor: t, col: c, .. }) if *job_id == id && *t == tensor && *c == col)) {
                            let pn = n.chain.params.n;
                            let tens = &n.prog_runs[&id].tensors[tensor as usize];
                            let vals: Vec<i8> = (0..pn).map(|i| tens[i * pn + col as usize]).collect();
                            let path = cols_tree(tens, pn).proof(col as usize);
                            push_own_tx(n, sk, TxKind::Prog(ProgTx::Serve { job_id: id, tensor, col, vals, path }));
                        }
                    }
                }
                if j.fetches.is_empty() && !n.chain.state.timing.challenge_open(height, now, *at, *at_ts) && !has_pending(n, &me, |k| matches!(k, TxKind::Prog(ProgTx::Settle { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Prog(ProgTx::Settle { job_id: id }));
                }
            }
            _ => {}
        }
        // opportunistic mining: while the job is running OR in its dispute window, the worker can mine its GEMMs
        let mine_ok = matches!(&j.status, ProgStatus::Working { worker, .. } | ProgStatus::Complete { worker, .. } if *worker == me);
        if mine_ok && n.prog_runs.contains_key(&id) {
            let p = n.chain.params;
        // miner: any Gemm whose input is already published (rotation)
        if active.is_none() {
            let eligible: Vec<usize> = (0..j.ops.len()).filter(|&k| j.gemm_roots(k).is_some()).collect();
            if !eligible.is_empty() {
                let run = n.prog_runs.get_mut(&id).unwrap();
                let k = eligible[run.next % eligible.len()];
                run.next += 1;
                let cm = match run.cms.get(&(k as u8)) {
                    Some(cm) => cm.clone(),
                    None => {
                        let d = &n.prog_data[di];
                        let ts = &n.prog_runs[&id].tensors;
                        let (a_mat, b_mat): (Vec<i8>, Vec<i8>) = match &j.ops[k] {
                            Op::Gemm { w, x, .. } => (d.ws[*w as usize].clone(), ts[*x as usize].clone()),
                            Op::GemmAT { a, x, .. } => {
                                let ta = &ts[*a as usize];
                                ((0..p.n * p.n).map(|idx| ta[(idx % p.n) * p.n + idx / p.n]).collect(), ts[*x as usize].clone())
                            }
                            _ => unreachable!(),
                        };
                        let cm = Arc::new(CommittedMatrices::new(a_mat, b_mat, &p));
                        n.prog_runs.get_mut(&id).unwrap().cms.insert(k as u8, cm.clone());
                        cm
                    }
                };
                active = Some(Target::Op(id, k as u8, cm));
            }
        }

        }
    }

    // multi-layer inference jobs
    let mjobs: Vec<(JobId, MlpJob)> = n.chain.state.mlps.iter().map(|(k, v)| (*k, v.clone())).collect();
    for (id, j) in mjobs {
        let Some(di) = n.mlp_data.iter().position(|d| d.x0_root == j.x0_root && d.w_roots == j.w_roots) else { continue };
        match &j.status {
            MlpStatus::Open if height <= j.deadline => {
                if !has_pending(n, &me, |k| matches!(k, TxKind::Mlp(MlpTx::Claim { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Mlp(MlpTx::Claim { job_id: id }));
                }
            }
            MlpStatus::Working { worker, .. } if *worker == me => {
                let l = j.layers.len();
                {
                    // resume after a restart: the layers already published on-chain are recomputed (the data comes from disk)
                    let p = n.chain.params;
                    while n.mlp_runs.entry(id).or_default().layers.len() < l {
                        let i = n.mlp_runs[&id].layers.len();
                        let xprev: Vec<i8> = if i == 0 { n.mlp_data[di].x0.clone() } else { (*n.mlp_runs[&id].layers[i - 1].1).clone() };
                        let z = plain_gemm(&n.mlp_data[di].ws[i], &xprev, p.n);
                        let x = requantize(&z, j.shifts[i], j.is_hidden(i));
                        let (zr, xr) = (c_tree(&z, p.n).root(), cols_root_of(&x, p.n));
                        n.mlp_runs.get_mut(&id).unwrap().layers.push((Arc::new(z), Arc::new(x), zr, xr));
                    }
                }
                let run = n.mlp_runs.entry(id).or_default();
                // layer computed but not yet published: we publish it
                let post = if run.layers.len() > l { Some((run.layers[l].2, run.layers[l].3)) } else { None };
                if l < j.w_roots.len() && run.layers.len() >= l {
                    let cm = match run.cms.get(&(l as u8)) {
                        Some(cm) => cm.clone(),
                        None => {
                            let p = n.chain.params;
                            let xprev: Vec<i8> = if l == 0 { n.mlp_data[di].x0.clone() } else { (*run.layers[l - 1].1).clone() };
                            let cm = Arc::new(CommittedMatrices::new(n.mlp_data[di].ws[l].clone(), xprev, &p));
                            n.mlp_runs.get_mut(&id).unwrap().cms.insert(l as u8, cm.clone());
                            cm
                        }
                    };
                    if active.is_none() {
                        active = Some(Target::Layer(id, l as u8, cm));
                    }
                }
                if let Some((z_root, x_root)) = post {
                    if !has_pending(n, &me, |k| matches!(k, TxKind::Mlp(MlpTx::PostLayer { job_id, layer, .. }) if *job_id == id && *layer as usize == l)) {
                        push_own_tx(n, sk, TxKind::Mlp(MlpTx::PostLayer { job_id: id, layer: l as u8, z_root, x_root }));
                    }
                }
            }
            MlpStatus::Complete { worker, at, at_ts, .. } if *worker == me => {
                if !n.chain.state.timing.challenge_open(height, now, *at, *at_ts) && !has_pending(n, &me, |k| matches!(k, TxKind::Mlp(MlpTx::Settle { job_id }) if *job_id == id)) {
                    push_own_tx(n, sk, TxKind::Mlp(MlpTx::Settle { job_id: id }));
                }
            }
            _ => {}
        }
    }

    // level 2 (Monte Carlo, rendering): the parameters are ON-CHAIN, no data to receive; we compute the chunks, commit
    // to the root of their outputs, serve the requested chunks, settle after the window
    {
        use crate::l2::*;
        // results of finished background computations
        let done: Vec<(JobId, L2Run)> = std::mem::take(&mut *n.l2_inbox.lock().unwrap());
        for (id, run) in done {
            n.l2_computing.remove(&id);
            n.l2_runs.insert(id, run);
        }
        // my only pending transaction is a lost claim (another miner took the job): it will never go through, so we
        // remove it right away instead of waiting for the eviction of stuck transactions (30 s during which this worker would be silent)
        let lost_claim = {
            let mut mine = n.mempool.iter().filter(|t| t.tx.from == me);
            match (mine.next(), mine.next()) {
                (Some(t), None) => matches!(&t.tx.kind, TxKind::L2(L2Tx::Claim { job_id }) if !n.chain.state.l2.get(job_id).map_or(false, |j| j.claimable_at(&n.chain.state.timing, height, now))),
                _ => false,
            }
        };
        if lost_claim {
            n.mempool.retain(|t| t.tx.from != me);
            prune_mempool(n);
        }
        let mut l2jobs: Vec<(JobId, L2Job)> = n.chain.state.l2.iter().map(|(k, v)| (*k, v.clone())).collect();
        // order specific to each worker (fingerprint of the job and of the worker key): two miners facing the same queue do not fight
        // over the same job, each starts with a different one
        let scatter = |id: &JobId| id.iter().zip(me.iter()).fold(0u64, |a, (x, y)| a.wrapping_mul(1_000_003).wrapping_add((x ^ y) as u64 + 1));
        l2jobs.sort_by_key(|(id, _)| scatter(id));
        let w = n.worker.unwrap_or_default();
        let max_jobs = if w.max_jobs == 0 { 1 } else { w.max_jobs };
        // jobs this worker already holds: claimed (not yet published) or claim pending in the mempool
        let mut busy = l2jobs
            .iter()
            .filter(|(id, j)| match &j.status {
                L2Status::Claimed { worker, .. } => *worker == me || has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Claim { job_id }) if job_id == id)),
                L2Status::Open => has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Claim { job_id }) if job_id == id)),
                _ => false,
            })
            .count();
        for (id, j) in l2jobs {
            match &j.status {
                // an open job, or a job whose worker did not publish within its lease (taken back, the first worker loses its bond)
                L2Status::Open | L2Status::Claimed { .. }
                    if j.claimable_at(&n.chain.state.timing, height, now) && !matches!(&j.status, L2Status::Claimed { worker, .. } if *worker == me) =>
                {
                    let price_ok = w.ask.map_or(true, |a| a <= j.escrow_net);
                    if busy < max_jobs && price_ok && !has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Claim { job_id }) if *job_id == id)) {
                        push_own_tx(n, sk, TxKind::L2(L2Tx::Claim { job_id: id }));
                        busy += 1;
                    }
                }
                L2Status::Claimed { worker, .. } | L2Status::Posted { worker, .. } if *worker == me => {
                    if !n.l2_runs.contains_key(&id) {
                        // computation of all the chunks + Merkle tree IN THE BACKGROUND (outside the node lock): a render of several
                        // minutes no longer freezes the node (blocks, transactions, served chunks); merged back on the next turn
                        if n.l2_computing.insert(id) {
                            let (kernel, chunks, cheat) = (j.kernel.clone(), j.chunks, w.cheat_l2);
                            let inbox = n.l2_inbox.clone();
                            thread::spawn(move || {
                                let mut outs = compute_all(&kernel, chunks);
                                if cheat {
                                    let mid = outs.len() / 2;
                                    outs[mid][0] ^= 1; // TEST: a wrong chunk, committed in the root
                                }
                                let tree = chunk_tree(&outs);
                                inbox.lock().unwrap().push((id, L2Run { outs, tree }));
                            });
                        }
                        continue;
                    }
                    if let L2Status::Claimed { .. } = &j.status {
                        let root = n.l2_runs[&id].tree.root();
                        if !has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Post { job_id, .. }) if *job_id == id)) {
                            push_own_tx(n, sk, TxKind::L2(L2Tx::Post { job_id: id, root }));
                        }
                    }
                    if let L2Status::Posted { at, at_ts, .. } = &j.status {
                        if !w.no_serve {
                            for (chunk, _) in &j.fetches {
                                let chunk = *chunk;
                                if !has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Serve { job_id, chunk: c, .. }) if *job_id == id && *c == chunk)) {
                                    let run = &n.l2_runs[&id];
                                    let (out, path) = (run.outs[chunk as usize].clone(), run.tree.proof(chunk as usize));
                                    push_own_tx(n, sk, TxKind::L2(L2Tx::Serve { job_id: id, chunk, out, path }));
                                }
                            }
                        }
                        if j.fetches.is_empty() && !n.chain.state.timing.challenge_open(height, now, *at, *at_ts) && !has_pending(n, &me, |k| matches!(k, TxKind::L2(L2Tx::Settle { job_id }) if *job_id == id)) {
                            push_own_tx(n, sk, TxKind::L2(L2Tx::Settle { job_id: id }));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    active
}

/// Diagnostic (VEARL_TIMING=1): reports on stderr any section held for more than 50 ms under the node lock.
struct LockTimer(&'static str, Instant);

impl LockTimer {
    fn new(what: &'static str) -> Option<Self> {
        std::env::var("VEARL_TIMING").is_ok().then(|| LockTimer(what, Instant::now()))
    }
}

impl Drop for LockTimer {
    fn drop(&mut self) {
        let ms = self.1.elapsed().as_millis();
        if ms >= 50 {
            eprintln!("[lock] {}: {ms} ms", self.0);
        }
    }
}

fn mining_loop(sh: Arc<Shared>, sk: SigningKey, use_gpu: bool, log: bool) {
    let miner = pubkey(&sk);
    let mut cache = GpuCache::default();
    let mut last_probe = Instant::now();
    while !sh.stop.load(Ordering::SeqCst) {
        if sh.paused.load(Ordering::SeqCst) {
            // Window of another miner (dual.rs): we do not mine, but we keep watching the paid-job queue every ~400 ms,
            // so that a job that arrives takes the GPU back at once (the scheduler reads `native_work`).
            if last_probe.elapsed() >= Duration::from_millis(400) {
                last_probe = Instant::now();
                let mut n = sh.node.lock().unwrap();
                if n.worker.is_some() {
                    let busy = worker_step(&mut n, &sk).is_some() || background_compute_busy(&n);
                    sh.native_work.store(!busy, Ordering::SeqCst);
                }
            }
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let (tpl, txs, ts) = {
            let mut n = sh.node.lock().unwrap();
            let _held = LockTimer::new("mining loop (template, worker_step)");
            sh.cancel.store(false, Ordering::SeqCst);
            if sh.paused.load(Ordering::SeqCst) {
                continue; // paused between the check above and the reset of `cancel`
            }
            let ts = now_secs().max(n.chain.tip_ts() + 1);
            if ts > now_secs() + MAX_FUTURE - 5 {
                drop(_held);
                drop(n);
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            slash_step(&mut n, &sk);
            evict_stuck(&mut n, ts, &miner);
            let t_ws = LockTimer::new("  of which worker_step");
            let target = if n.worker.is_some() { worker_step(&mut n, &sk) } else { None };
            drop(t_ws);
            sh.native_work.store(target.is_none() && !background_compute_busy(&n), Ordering::SeqCst);
            if target.is_none() && n.worker.map_or(false, |w| w.no_native) {
                // no job to work on and no Native mining wanted here: wait for the next one (the queue is read again at every turn)
                drop(_held);
                drop(n);
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            let _t_tpl = LockTimer::new("  of which template + transaction selection");
            let tpl = match &target {
                Some(Target::Job(id, data)) => n.chain.template(WorkClass::Job(*id), Some(data)),
                Some(Target::Layer(id, l, cm)) => n.chain.template(WorkClass::Layer { job: *id, layer: *l }, Some(cm)),
                Some(Target::Op(id, op, cm)) => n.chain.template(WorkClass::Op { job: *id, op: *op }, Some(cm)),
                Some(Target::Product(id, (i, j, k), cm)) => n.chain.template(WorkClass::Product { job: *id, i: *i, j: *j, k: *k }, Some(cm)),
                None => n.chain.template(WorkClass::Native, None),
            };
            let Ok(tpl) = tpl else { continue };
            let txs = select_txs(&n, &miner, ts);
            (tpl, txs, ts)
        };
        match mine_template(&tpl, &sk, txs, ts, Some(&sh.cancel), use_gpu, &mut cache) {
            Ok(out) => {
                let mut n = sh.node.lock().unwrap();
                let _held = LockTimer::new("mined block: validation and application");
                if n.chain.tip_hash() != tpl.prev {
                    continue; // a block from the network arrived in the meantime
                }
                let b = out.block;
                match n.chain.validate_and_apply_at(b.clone(), now_secs()) {
                    Ok(()) => {
                        match &b.header.class {
                            WorkClass::Job(id) => {
                                // the real client product A*B: we keep it to serve it and to publish its root
                                if !n.results.contains_key(id) {
                                    let mut c = out.c.clone();
                                    if n.worker.map_or(false, |w| w.cheat) {
                                        let l = c.len();
                                        c[l / 3] += 1; // TEST: a single wrong entry
                                    }
                                    if n.worker.map_or(false, |w| w.cheat_garbage) {
                                        for (k, v) in c.iter_mut().enumerate() {
                                            *v = (k as i32).wrapping_mul(2654435761u32 as i32) ^ 12345; // TEST: invented result
                                        }
                                    }
                                    let root = c_root(&c, tpl.params.n);
                                    n.results.insert(*id, (Arc::new(c), root));
                                }
                            }
                            WorkClass::Layer { job, layer } => {
                                let (lay, cheat) = (*layer as usize, n.worker.unwrap_or_default());
                                let total = n.chain.state.mlps.get(job).map_or(0, |j| j.w_roots.len());
                                let shift = n.chain.state.mlps.get(job).map_or(0, |j| j.shifts.get(lay).copied().unwrap_or(0));
                                let have = n.mlp_runs.get(job).map_or(0, |r| r.layers.len());
                                if have == lay && !out.c.is_empty() {
                                    let hidden = lay + 1 < total;
                                    let mut z = out.c.clone();
                                    if cheat.cheat && lay == 1.min(total - 1) {
                                        let l = z.len();
                                        z[l / 3] += 1; // TEST: wrong GEMM (X stays consistent with the falsified Z)
                                    }
                                    let mut x = requantize(&z, shift, hidden);
                                    if cheat.cheat_act && lay == 0 {
                                        if let Some(i) = x.iter().position(|v| *v != 63 && *v != 64) {
                                            x[i] = x[i].wrapping_add(1); // TEST: wrong activation, correct Z
                                        }
                                    }
                                    let n_dim = tpl.params.n;
                                    let (zr, xr) = (c_tree(&z, n_dim).root(), cols_root_of(&x, n_dim));
                                    n.mlp_runs.entry(*job).or_default().layers.push((Arc::new(z), Arc::new(x), zr, xr));
                                }
                            }
                            WorkClass::Native | WorkClass::Product { .. } | WorkClass::Op { .. } => {}
                        }
                        if log {
                            eprintln!(
                                "[mine] block #{} ({}) {} sigma, {} txs, work={}",
                                b.header.height,
                                match &b.header.class {
                                    WorkClass::Native => "native".to_string(),
                                    WorkClass::Job(_) => "JOB".to_string(),
                                    WorkClass::Layer { layer, .. } => format!("LAYER {layer}"),
                                    WorkClass::Product { i, j, k, .. } => format!("PRODUCT {i},{j},{k}"),
                                    WorkClass::Op { op, .. } => format!("OP {op}"),
                                },
                                out.attempts_sigma,
                                b.txs.len(),
                                n.chain.total_work()
                            );
                        }
                        persist(&mut n);
                        prune_mempool(&mut n);
                        broadcast(&n, None, &Msg::NewBlock(b));
                    }
                    Err(e) => eprintln!("[mine] block rejected by ourselves: {e}"),
                }
            }
            Err(e) if e == "cancelled" => {}
            Err(e) => {
                eprintln!("[mine] error: {e}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Minimal client (CLI): opens an encrypted channel, sends a request and reads the reply.
pub fn request(addr: &str, m: &Msg) -> io::Result<Msg> {
    let mut c = Conn::connect(addr)?;
    c.set_timeout(Duration::from_secs(10));
    c.send(m)?;
    loop {
        match c.recv()? {
            Msg::Hello { .. } => continue, // the node announces its Hello first
            r => return Ok(r),
        }
    }
}
