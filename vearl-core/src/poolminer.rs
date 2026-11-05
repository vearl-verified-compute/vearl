//! VEARL pool client (`vpool/2`, docs/16-pool-protocol.md): connects, receives the jobs, looks for shares with the CPU or the GPU
//! and submits them. The client only knows the pool's PUBLIC key and its own payout address: no private key here.
//! Automatic reconnection (1 s wait doubled up to 30 s).
use crate::crypto::*;
use crate::pool::{hex, parse_u64hex, read_line_limited, u64hex, unhex32, E_BANNED, PROTO2};
use crate::poolpoints::verify_receipt_sig;
use crate::types::*;
use crate::work::*;
use serde_json::{json, Value};
use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct MinerConfig {
    /// HOST:PORT of the pool
    pub pool: String,
    /// vrl1... payout address
    pub address: String,
    pub worker: String,
    /// CPU compute threads (ignored with `gpu`)
    pub threads: usize,
    pub gpu: bool,
    /// estimated rate in sigma/s, to choose the initial share target (None: the pool assumes a small CPU)
    pub rate_hint: Option<f64>,
    pub log: bool,
    /// file that receives every receipt the pool sends (JSON lines): the evidence the miner keeps, checked by `vearl-pool-audit`
    pub receipts: Option<std::path::PathBuf>,
}

#[derive(Default)]
pub struct MinerStats {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub blocks: AtomicU64,
    pub sigmas: AtomicU64,
    pub connected: AtomicBool,
    pub last_error: Mutex<String>,
    /// receipts received (valid signature, our address) and the latest one
    pub receipts: AtomicU64,
    pub last_receipt: Mutex<Option<Value>>,
    /// testnet points earned through this pool so far (provisional figure of the pool), refreshed every two minutes
    pub points: Mutex<Option<f64>>,
}

/// Job described by the pool (message `job`).
#[derive(Clone, Debug)]
pub struct JobSpec {
    pub id: String,
    pub clean: bool,
    pub height: u64,
    pub prev: Hash,
    pub miner: PubKey,
    pub timestamp: u64,
    pub tx_root: Hash,
    pub epoch: u64,
    pub target: u64,
    pub share_target: u64,
    pub nonce_start: u64,
    pub nonce_end: u64,
    pub params: WorkParams,
}

pub fn parse_job(p: &Value) -> Result<JobSpec, String> {
    let s = |k: &str| p.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("job: field {k} missing"));
    let u = |k: &str| p.get(k).and_then(|x| x.as_u64()).ok_or_else(|| format!("job: field {k} missing"));
    let h = |k: &str| s(k).and_then(|v| unhex32(v).ok_or_else(|| format!("job: {k} invalid")));
    let t = |k: &str| s(k).and_then(|v| parse_u64hex(v).ok_or_else(|| format!("job: {k} invalid")));
    if s("class")? != "native" {
        return Err("job: only the native class is supported".into());
    }
    let pr = p.get("params").ok_or("job: params missing")?;
    let g = |k: &str| pr.get(k).and_then(|x| x.as_u64()).map(|v| v as usize).ok_or_else(|| format!("job: params.{k} missing"));
    let params = WorkParams { n: g("n")?, tile: g("tile")?, rank: g("rank")?, fold_k: g("fold_k")? };
    // a hostile pool must not be able to make us allocate anything
    params.security_check()?;
    if params.n > 4096 {
        return Err("job: n too large".into());
    }
    let spec = JobSpec {
        id: s("job_id")?.to_string(),
        clean: p.get("clean").and_then(|x| x.as_bool()).unwrap_or(true),
        height: u("height")?,
        prev: h("prev")?,
        miner: h("miner")?,
        timestamp: u("timestamp")?,
        tx_root: h("tx_root")?,
        epoch: u("epoch")?,
        target: t("target")?,
        share_target: t("share_target")?,
        nonce_start: t("nonce_start")?,
        nonce_end: t("nonce_end")?,
        params,
    };
    if spec.nonce_end <= spec.nonce_start {
        return Err("job: empty nonce range".into());
    }
    Ok(spec)
}

struct Live {
    job: Mutex<Option<Arc<JobSpec>>>,
    gen: AtomicU64,
    share_target: AtomicU64,
    alive: AtomicBool,
    next_id: AtomicU64,
}

impl Live {
    fn current(&self) -> Option<(u64, Arc<JobSpec>)> {
        let j = self.job.lock().unwrap();
        j.clone().map(|j| (self.gen.load(Ordering::SeqCst), j))
    }
}

/// Request id of the periodic `stats` call (the shares use small counters).
const STATS_ID: u64 = 1 << 40;

fn submit_line(live: &Live, job: &JobSpec, en: u64, ti: usize, tj: usize) -> String {
    let id = live.next_id.fetch_add(1, Ordering::SeqCst);
    json!({"id": id, "method": "submit", "params": {"job_id": job.id, "extra_nonce": u64hex(en), "ti": ti, "tj": tj}}).to_string()
}

// Bound startup bursts without blocking compute workers or delaying control messages.
const SHARE_QUEUE_CAPACITY: usize = 80;
struct PendingShare {
    line: String,
    generation: u64,
    jackpot: Hash,
    block_target: u64,
}

enum OutboundMessage {
    Control(String),
    Share(PendingShare),
}

fn next_message(control: &Receiver<String>, shares: &Receiver<PendingShare>) -> Option<OutboundMessage> {
    if let Ok(line) = control.try_recv() {
        Some(OutboundMessage::Control(line))
    } else {
        shares.recv_timeout(Duration::from_millis(100)).ok().map(OutboundMessage::Share)
    }
}

impl PendingShare {
    fn eligible(&self, live: &Live) -> bool {
        self.generation == live.gen.load(Ordering::SeqCst)
            && meets_target(&self.jackpot, live.share_target.load(Ordering::SeqCst).max(self.block_target))
    }
}

fn queue_share(tx: &SyncSender<PendingShare>, live: &Live, job: &JobSpec, generation: u64, jackpot: Hash, en: u64, ti: usize, tj: usize) {
    let share = PendingShare { line: submit_line(live, job, en, ti, tj), generation, jackpot, block_target: job.target };
    // A full/disconnected queue must not block the GPU or grow memory indefinitely.
    let _ = tx.try_send(share);
}

fn cpu_worker(live: Arc<Live>, tid: usize, nthreads: usize, stats: Arc<MinerStats>, stop: Arc<AtomicBool>, tx: SyncSender<PendingShare>) {
    let mut cache: Option<(u64, WorkParams, Vec<i8>, Vec<i8>)> = None;
    while live.alive.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
        let Some((gen, job)) = live.current() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        if !matches!(&cache, Some((e, p, _, _)) if *e == job.epoch && *p == job.params) {
            let (a, b) = native_matrices(job.epoch, &job.params);
            cache = Some((job.epoch, job.params, a, b));
        }
        let (_, _, a, b) = cache.as_ref().unwrap();
        let tiles = job.params.tiles();
        let mut counter = job.nonce_start.saturating_add(tid as u64);
        while live.gen.load(Ordering::SeqCst) == gen && live.alive.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
            if counter >= job.nonce_end {
                thread::sleep(Duration::from_millis(100)); // range exhausted (2^40 sigma): wait for the next job
                continue;
            }
            let sg = sigma(&job.prev, &job.miner, &WorkClass::Native, counter, &job.tx_root, job.timestamp);
            let (out, _) = run_noisy_gemm(a, b, &sg, &job.params);
            let st = live.share_target.load(Ordering::SeqCst);
            for (idx, jp) in out.jackpots.iter().enumerate() {
                if meets_target(jp, st) {
                    queue_share(&tx, &live, &job, gen, *jp, counter, idx / tiles, idx % tiles);
                }
            }
            stats.sigmas.fetch_add(1, Ordering::Relaxed);
            counter = counter.saturating_add(nthreads as u64);
        }
    }
}

#[cfg(feature = "gpu")]
fn gpu_worker(live: Arc<Live>, stats: Arc<MinerStats>, stop: Arc<AtomicBool>, tx: SyncSender<PendingShare>, dev: usize, idx: u64, count: u64) {
    let mut cache: Option<(u64, WorkParams, crate::gpu::GpuJob)> = None;
    while live.alive.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
        let Some((gen, job)) = live.current() else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        if !matches!(&cache, Some((e, p, _)) if *e == job.epoch && *p == job.params) {
            let (a, b) = native_matrices(job.epoch, &job.params);
            match crate::gpu::GpuJob::new_on(dev, &a, &b, &job.params) {
                Some(g) => cache = Some((job.epoch, job.params, g)),
                None => {
                    *stats.last_error.lock().unwrap() = "gpu init failed".into();
                    eprintln!("[poolminer] GPU #{dev}: initialisation failed");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }
        }
        let g = &cache.as_ref().unwrap().2;
        let tiles = job.params.tiles();
        // several GPUs share the nonce range in interleaved batches: GPU number `idx` of `count` takes batches idx, idx + count, ...
        let bs = g.batch_size() as u64;
        let mut counter = job.nonce_start.saturating_add(idx * bs);
        while live.gen.load(Ordering::SeqCst) == gen && live.alive.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
            if counter.saturating_add(bs) > job.nonce_end {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            let sigs: Vec<Hash> = (0..bs).map(|d| sigma(&job.prev, &job.miner, &WorkClass::Native, counter + d, &job.tx_root, job.timestamp)).collect();
            // the GPU filters the jackpots against the share target and returns only the shares
            let hits = match g.run_batch_hits(&sigs, live.share_target.load(Ordering::SeqCst)) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[poolminer] GPU #{dev}: error {e}");
                    thread::sleep(Duration::from_secs(1));
                    break;
                }
            };
            // the pool may have made the target harder while the batch was running: keep what still qualifies
            let st = live.share_target.load(Ordering::SeqCst);
            for (d, idx, jp) in hits {
                if meets_target(&jp, st) {
                    queue_share(&tx, &live, &job, gen, jp, counter + d as u64, idx / tiles, idx % tiles);
                }
            }
            stats.sigmas.fetch_add(bs, Ordering::Relaxed);
            counter += bs * count;
        }
    }
}

fn session(cfg: &MinerConfig, stats: &Arc<MinerStats>, stop: &Arc<AtomicBool>) -> Result<(), String> {
    let addr = cfg.pool.to_socket_addrs().map_err(|e| format!("{}: {e}", cfg.pool))?.next().ok_or("pool address not found")?;
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("cannot connect to {}: {e}", cfg.pool))?;
    let _ = sock.set_nodelay(true);
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
    let mut writer = sock.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(sock);
    let live = Arc::new(Live { job: Mutex::new(None), gen: AtomicU64::new(0), share_target: AtomicU64::new(0), alive: AtomicBool::new(true), next_id: AtomicU64::new(2) });
    let mut login = json!({"proto": PROTO2, "address": cfg.address, "worker": cfg.worker, "agent": concat!("vearl-poolminer/", env!("CARGO_PKG_VERSION"))});
    if let Some(r) = cfg.rate_hint {
        login["sigma_rate"] = json!(r);
    }
    writeln!(writer, "{}", json!({"id": 1, "method": "login", "params": login})).map_err(|e| e.to_string())?;
    // write thread: shares + periodic ping
    let (tx, control_rx) = channel::<String>();
    let (share_tx, rx) = sync_channel::<PendingShare>(SHARE_QUEUE_CAPACITY);
    {
        let (live, stop) = (live.clone(), stop.clone());
        thread::spawn(move || {
            let mut last = Instant::now();
            // the shares are emitted at most ~40/s (burst 80): beyond that the pool would refuse anyway (starting target too easy before the `hint`)
            let (mut tokens, mut t_tok) = (80.0f64, Instant::now());
            while live.alive.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
                // Hints/stats cannot sit behind a burst of shares mined at an easy target.
                let line = match next_message(&control_rx, &rx) {
                    Some(OutboundMessage::Control(control)) => Some(control),
                    Some(OutboundMessage::Share(share)) => {
                        tokens = (tokens + t_tok.elapsed().as_secs_f64() * 40.0).min(80.0);
                        t_tok = Instant::now();
                        if !share.eligible(&live) || tokens < 1.0 {
                            continue;
                        }
                        tokens -= 1.0;
                        Some(share.line)
                    }
                    None => None,
                };
                if let Some(line) = line {
                    if writeln!(writer, "{line}").is_err() {
                        live.alive.store(false, Ordering::SeqCst);
                    }
                    last = Instant::now();
                } else if last.elapsed() > Duration::from_secs(30) {
                    let id = live.next_id.fetch_add(1, Ordering::SeqCst);
                    if writeln!(writer, "{}", json!({"id": id, "method": "ping"})).is_err() {
                        live.alive.store(false, Ordering::SeqCst);
                    }
                    last = Instant::now();
                }
            }
            let _ = writer.shutdown(std::net::Shutdown::Both);
        });
    }
    // one worker per GPU (all the GPUs of capability >= 8.0, or those of VEARL_GPUS), or the CPU threads
    #[cfg(feature = "gpu")]
    let gpu_devs: Vec<usize> = if cfg.gpu { crate::gpu::mining_devices() } else { Vec::new() };
    #[cfg(not(feature = "gpu"))]
    let gpu_devs: Vec<usize> = Vec::new();
    #[cfg(feature = "gpu")]
    let threads = if cfg.gpu { gpu_devs.len().max(1) * crate::gpu::workers_per_gpu() } else { cfg.threads.max(1) };
    #[cfg(not(feature = "gpu"))]
    let threads = if cfg.gpu { gpu_devs.len().max(1) } else { cfg.threads.max(1) };
    for t in 0..threads {
        let (l, s, st, txc) = (live.clone(), stats.clone(), stop.clone(), share_tx.clone());
        if cfg.gpu {
            #[cfg(feature = "gpu")]
            {
                let dev = gpu_devs.get(t % gpu_devs.len().max(1)).copied().unwrap_or(0);
                let count = threads as u64;
                thread::spawn(move || gpu_worker(l, s, st, txc, dev, t as u64, count));
            }
            #[cfg(not(feature = "gpu"))]
            {
                let _ = (l, s, st, txc);
                live.alive.store(false, Ordering::SeqCst);
                return Err("compiled without the gpu feature (cargo build --release --features gpu)".into());
            }
        } else {
            thread::spawn(move || cpu_worker(l, t, threads, s, st, txc));
        }
    }
    let mut line: Vec<u8> = Vec::with_capacity(1024);
    let mut last_rx = Instant::now();
    // rate measured over the first seconds: the pool immediately deduces an adapted share target from it
    let mut hint_at: Option<(Instant, u64)> = None;
    let mut hint_sent = cfg.rate_hint.is_some();
    let mut stats_at: Option<Instant> = None;
    let result = loop {
        if stop.load(Ordering::SeqCst) || !live.alive.load(Ordering::SeqCst) {
            break Ok(());
        }
        if let (false, Some((t0, s0))) = (hint_sent, hint_at) {
            if t0.elapsed() >= Duration::from_secs(4) {
                let rate = (stats.sigmas.load(Ordering::Relaxed).saturating_sub(s0)) as f64 / t0.elapsed().as_secs_f64();
                if rate > 0.0 {
                    let id = live.next_id.fetch_add(1, Ordering::SeqCst);
                    let _ = tx.send(json!({"id": id, "method": "hint", "params": {"sigma_rate": rate}}).to_string());
                    hint_sent = true;
                }
            }
        }
        if stats.connected.load(Ordering::SeqCst) && stats_at.map_or(true, |t| t.elapsed() > Duration::from_secs(120)) {
            let _ = tx.send(json!({"id": STATS_ID, "method": "stats"}).to_string());
            stats_at = Some(Instant::now());
        }
        match read_line_limited(&mut reader, &mut line) {
            Ok(true) => {}
            Ok(false) => break Err("the pool closed the connection".to_string()),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                if last_rx.elapsed() > Duration::from_secs(180) {
                    break Err("the pool no longer answers".into());
                }
                continue;
            }
            Err(e) => break Err(e.to_string()),
        }
        last_rx = Instant::now();
        let v: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(_) => {
                line.clear();
                continue;
            }
        };
        line.clear();
        match v.get("method").and_then(|m| m.as_str()) {
            Some("job") => match parse_job(&v["params"]) {
                Ok(j) => {
                    live.share_target.store(j.share_target, Ordering::SeqCst);
                    if cfg.log {
                        eprintln!("[poolminer] job {} (block {}{}) share target {}", j.id, j.height, if j.clean { ", new" } else { "" }, u64hex(j.share_target));
                    }
                    *live.job.lock().unwrap() = Some(Arc::new(j));
                    live.gen.fetch_add(1, Ordering::SeqCst);
                    hint_at.get_or_insert((Instant::now(), stats.sigmas.load(Ordering::Relaxed)));
                }
                Err(e) => break Err(format!("job refused: {e}")),
            },
            Some("receipt") => {
                // the pool's signed promise of our cumulative weight in the epoch: checked against the pool key that is in every job, kept
                let r = &v["params"];
                let pool_key = live.job.lock().unwrap().as_ref().map(|j| j.miner);
                let ok = pool_key.map_or(false, |k| verify_receipt_sig(r, &k).is_ok()) && r["address"].as_str() == Some(cfg.address.as_str());
                if ok {
                    stats.receipts.fetch_add(1, Ordering::Relaxed);
                    *stats.last_receipt.lock().unwrap() = Some(r.clone());
                    if let Some(path) = &cfg.receipts {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                            let _ = writeln!(f, "{r}");
                        }
                    }
                } else if cfg.log {
                    eprintln!("[poolminer] a receipt was ignored (bad signature or not for our address)");
                }
            }
            Some("set_target") => {
                if let Some(t) = v["params"]["share_target"].as_str().and_then(parse_u64hex) {
                    live.share_target.store(t, Ordering::SeqCst);
                    if cfg.log {
                        eprintln!("[poolminer] new share target {}", u64hex(t));
                    }
                }
            }
            Some(_) => {}
            None => {
                let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                if let Some(e) = v.get("error") {
                    let (code, msg) = (e["code"].as_i64().unwrap_or(0) as i32, e["message"].as_str().unwrap_or("").to_string());
                    if id == 1 || code == E_BANNED {
                        break Err(format!("refused by the pool: {msg}"));
                    }
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    if cfg.log && code != crate::pool::E_STALE {
                        eprintln!("[poolminer] share refused ({code}): {msg}");
                    }
                } else if let Some(r) = v.get("result") {
                    if id == STATS_ID {
                        if let Some(p) = r["points"].as_f64() {
                            *stats.points.lock().unwrap() = Some(p);
                        }
                    } else if id == 1 {
                        stats.connected.store(true, Ordering::SeqCst);
                        if let Some(t) = r["share_target"].as_str().and_then(parse_u64hex) {
                            live.share_target.store(t, Ordering::SeqCst);
                        }
                        if cfg.log {
                            eprintln!("[poolminer] connected to {} (slot {}, fee {} %), payouts to {}", cfg.pool, r["slot"], r["fee_bps"].as_f64().unwrap_or(0.0) / 100.0, cfg.address);
                        }
                    } else if r.get("accepted").and_then(|x| x.as_bool()) == Some(true) {
                        stats.accepted.fetch_add(1, Ordering::Relaxed);
                        if r.get("block").and_then(|x| x.as_bool()) == Some(true) {
                            stats.blocks.fetch_add(1, Ordering::Relaxed);
                            if cfg.log {
                                eprintln!("[poolminer] BLOCK found!");
                            }
                        }
                    }
                }
            }
        }
    };
    live.alive.store(false, Ordering::SeqCst);
    stats.connected.store(false, Ordering::SeqCst);
    result
}

/// Main loop: (re)connects as long as `stop` is not raised.
pub fn run(cfg: MinerConfig, stats: Arc<MinerStats>, stop: Arc<AtomicBool>) {
    let mut backoff = 1u64;
    while !stop.load(Ordering::SeqCst) {
        let t0 = Instant::now();
        match session(&cfg, &stats, &stop) {
            Ok(()) => {}
            Err(e) => {
                *stats.last_error.lock().unwrap() = e.clone();
                if cfg.log {
                    eprintln!("[poolminer] {e} ; new attempt in {backoff} s");
                }
            }
        }
        if t0.elapsed() > Duration::from_secs(60) {
            backoff = 1; // the session held: start again from zero
        }
        for _ in 0..backoff * 10 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        backoff = (backoff * 2).min(30);
    }
}

/// Helper for tests and tools: public key of the pool from a job.
pub fn pool_key_of(j: &JobSpec) -> String {
    hex(&j.miner)
}

#[cfg(test)]
mod outbound_tests {
    use super::*;

    fn live(target: u64) -> Live {
        Live { job: Mutex::new(None), gen: AtomicU64::new(1), share_target: AtomicU64::new(target), alive: AtomicBool::new(true), next_id: AtomicU64::new(2) }
    }

    fn share(jackpot: u64) -> PendingShare {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&jackpot.to_be_bytes());
        PendingShare { line: "share".into(), generation: 1, jackpot: hash, block_target: 5 }
    }

    #[test]
    fn queued_shares_are_rechecked_after_target_tightens() {
        let live = live(100);
        let (tx, rx) = sync_channel(3);
        for jackpot in [10, 40, 80] { tx.try_send(share(jackpot)).unwrap_or_else(|_| panic!("queue unexpectedly full")); }
        // All were valid when produced, but only one still qualifies at send time.
        live.share_target.store(20, Ordering::SeqCst);
        let sent: Vec<_> = rx.try_iter().filter(|s| s.eligible(&live)).collect();
        assert_eq!(sent.len(), 1);
        assert!(meets_target(&sent[0].jackpot, 20));
    }

    #[test]
    fn queued_shares_from_replaced_job_are_dropped() {
        let live = live(100);
        let queued = share(1);
        assert!(queued.eligible(&live));
        live.gen.store(2, Ordering::SeqCst);
        assert!(!queued.eligible(&live));
    }

    #[test]
    fn network_block_survives_harder_session_target() {
        let live = live(1);
        assert!(share(3).eligible(&live));
        assert!(!share(6).eligible(&live));
    }

    #[test]
    fn easy_target_burst_is_bounded_and_does_not_block_control() {
        let (tx, rx) = sync_channel(SHARE_QUEUE_CAPACITY);
        for _ in 0..SHARE_QUEUE_CAPACITY { assert!(tx.try_send(share(1)).is_ok()); }
        assert!(matches!(tx.try_send(share(1)), Err(std::sync::mpsc::TrySendError::Full(_))));
        let (control, control_rx) = channel();
        control.send("rate hint".to_string()).unwrap();
        // The writer checks this independent queue before consuming another share.
        assert!(matches!(next_message(&control_rx, &rx), Some(OutboundMessage::Control(line)) if line == "rate hint"));
        assert_eq!(rx.try_iter().count(), SHARE_QUEUE_CAPACITY);
    }
}
