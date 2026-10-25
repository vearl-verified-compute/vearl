//! Pool points ledger (protocol `vpool/2`, docs/16 section 13): what makes the points of a pool's miners verifiable.
//!
//! A pool is the `miner` of its blocks, so the chain alone cannot say which pool miner deserves the points of a block. The pool therefore
//! publishes, for every hour (an EPOCH), a signed document: the blocks it found, the work (share weight) of every miner, the jobs its shares
//! belong to and the Merkle root of the complete list of shares. Each epoch document commits to the previous one (`prev`), so history cannot be
//! rewritten quietly. Fraud is made hard to hide in four independent ways:
//!   1. every share can be re-checked by anybody (it is a tile jackpot under the share target: `verify_share`), and the Merkle root makes the
//!      pool commit to the whole list BEFORE anyone chooses which shares to sample;
//!   2. the blocks listed must be exactly the pool's blocks on the chain;
//!   3. each miner holds RECEIPTS signed by the pool (cumulative weight in the epoch): a document that credits less than a receipt contradicts
//!      the pool's own signature (`make_receipt`, `audit_pool`);
//!   4. the work claimed must be consistent with the blocks found (a Poisson test): claimed work far above or below what the blocks imply is
//!      reported for a human look.
//! Nothing here changes the consensus. See `tools/pool_points.py` for the rewards side and `vearl-pool-audit` for the checker.
use crate::crypto::*;
use crate::pool::{hex, parse_u64hex, share_weight, u64hex, unhex32};
use crate::state::EPOCH_LEN;
use crate::types::*;
use crate::wallet::{address_of, parse_address};
use crate::work::*;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const POINTS_PROTO: &str = "vpool-points/1";
pub const DOC_DOMAIN: &[u8] = b"vearl/pool-points/v1\0";
pub const RECEIPT_DOMAIN: &[u8] = b"vearl/pool-receipt/v1\0";
/// Length of an epoch, in seconds: one hour (divides a day, so epochs line up with the scoring days of the rewards program).
pub const EPOCH_SECS: u64 = 3600;
pub const ZERO_HASH: Hash = [0u8; 32];
/// Tolerance, in seconds, between the header timestamp of a block and the epoch it was found in: the timestamp is that of the job (which can be a few
/// minutes old) and the chain accepts timestamps slightly ahead of the clock.
pub const MAX_JOB_AGE: u64 = 600;

/// The job a share was found for (what is needed to recompute its jackpot).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRec {
    pub prev: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub tx_root: Hash,
    /// network target of the job
    pub target: u64,
    pub native_epoch: u64,
}

/// One accepted share: enough to recompute it (with its job) and to know whom it was credited to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRec {
    pub addr: PubKey,
    /// index in the epoch document's `jobs`
    pub job: u32,
    pub extra_nonce: u64,
    pub ti: u16,
    pub tj: u16,
    /// the share target it was credited at: its weight is `share_weight(target)`
    pub target: u64,
    /// the miner spoke vpool/2 (receipts, eligible for points)
    pub v2: bool,
}

impl ShareRec {
    pub fn bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("share record")
    }
    pub fn from_bytes(b: &[u8]) -> Option<ShareRec> {
        bincode::deserialize(b).ok()
    }
    pub fn weight(&self) -> u128 {
        share_weight(self.target)
    }
}

pub fn share_leaf(index: u64, rec: &ShareRec) -> Hash {
    leaf_hash(index, &rec.bytes())
}

pub fn shares_tree(recs: &[ShareRec]) -> MerkleTree {
    MerkleTree::new(recs.iter().enumerate().map(|(i, r)| share_leaf(i as u64, r)).collect())
}

/// Canonical text of a JSON value (keys sorted, no spaces, integers only): what is signed and hashed.
pub fn canonical(v: &Value) -> String {
    v.to_string()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn without_sig(doc: &Value) -> Value {
    let mut d = doc.clone();
    if let Some(o) = d.as_object_mut() {
        o.remove("sig");
    }
    d
}

/// Hash of an epoch document (without its signature): the `prev` of the next one.
pub fn doc_hash(doc: &Value) -> String {
    sha256_hex(canonical(&without_sig(doc)).as_bytes())
}

fn signed_bytes(domain: &[u8], v: &Value) -> Vec<u8> {
    [domain, canonical(&without_sig(v)).as_bytes()].concat()
}

fn check_sig(v: &Value, pool_key: &PubKey, domain: &[u8]) -> Result<(), String> {
    let sig_hex = v.get("sig").and_then(|s| s.as_str()).ok_or("no signature")?;
    if sig_hex.len() != 128 || !sig_hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("malformed signature".into());
    }
    let sig: Vec<u8> = (0..64).map(|i| u8::from_str_radix(&sig_hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    if verify_sig(pool_key, &signed_bytes(domain, v), &sig) {
        Ok(())
    } else {
        Err("bad signature".into())
    }
}

/// Everything the document of an epoch is built from.
pub struct EpochData<'a> {
    pub epoch: u64,
    pub epoch_secs: u64,
    pub fee_bps: u64,
    /// (height, hash, header timestamp) of the blocks the pool found in this epoch
    pub blocks: &'a [(u64, Hash, u64)],
    pub jobs: &'a [JobRec],
    pub records: &'a [ShareRec],
}

/// Per-address totals of a list of shares: (weight of all shares, shares, weight of vpool/2 shares, vpool/2 shares).
pub fn totals(recs: &[ShareRec]) -> BTreeMap<PubKey, (u128, u64, u128, u64)> {
    let mut m: BTreeMap<PubKey, (u128, u64, u128, u64)> = BTreeMap::new();
    for r in recs {
        let e = m.entry(r.addr).or_default();
        e.0 += r.weight();
        e.1 += 1;
        if r.v2 {
            e.2 += r.weight();
            e.3 += 1;
        }
    }
    m
}

/// The signed document of an epoch. `prev` = hash of the previous document (ZERO_HASH for the first one).
pub fn build_doc(sk: &SigningKey, genesis: &Hash, prev: &Hash, d: &EpochData) -> Value {
    let pool_key = pubkey(sk);
    let tot = totals(d.records);
    let mut miners: Vec<(String, Value)> = tot
        .iter()
        .map(|(a, (w, n, w2, n2))| {
            let addr = address_of(a);
            (addr.clone(), json!({"address": addr, "shares": n, "v2_shares": n2, "v2_weight": w2.to_string(), "weight": w.to_string()}))
        })
        .collect();
    miners.sort_by(|a, b| a.0.cmp(&b.0));
    let total_weight: u128 = tot.values().map(|t| t.0).sum();
    let root = shares_tree(d.records).root();
    let blocks: Vec<Value> = d.blocks.iter().map(|(h, hash, ts)| json!({"height": h, "hash": hex(hash), "timestamp": ts})).collect();
    let jobs: Vec<Value> = d
        .jobs
        .iter()
        .map(|j| json!({"prev": hex(&j.prev), "height": j.height, "timestamp": j.timestamp, "tx_root": hex(&j.tx_root), "target": u64hex(j.target), "native_epoch": j.native_epoch}))
        .collect();
    let mut doc = json!({
        "proto": POINTS_PROTO, "pool": address_of(&pool_key), "pool_key": hex(&pool_key), "genesis": hex(genesis),
        "epoch": d.epoch, "epoch_secs": d.epoch_secs, "start": d.epoch * d.epoch_secs, "end": (d.epoch + 1) * d.epoch_secs,
        "prev": hex(prev), "fee_bps": d.fee_bps, "blocks": blocks, "jobs": jobs,
        "miners": miners.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        "total_weight": total_weight.to_string(), "total_shares": d.records.len(), "shares_count": d.records.len(), "shares_root": hex(&root),
    });
    let sig = sign(sk, &signed_bytes(DOC_DOMAIN, &doc));
    doc["sig"] = json!(hex(&sig));
    doc
}

pub fn verify_doc(doc: &Value, pool_key: &PubKey, genesis: &Hash) -> Result<(), String> {
    if doc.get("proto").and_then(|x| x.as_str()) != Some(POINTS_PROTO) {
        return Err("unknown document type".into());
    }
    if doc.get("pool_key").and_then(|x| x.as_str()) != Some(&hex(pool_key)) || doc.get("pool").and_then(|x| x.as_str()) != Some(&address_of(pool_key)) {
        return Err("document of another pool".into());
    }
    if doc.get("genesis").and_then(|x| x.as_str()) != Some(&hex(genesis)) {
        return Err("document of another network".into());
    }
    check_sig(doc, pool_key, DOC_DOMAIN)
}

/// Receipt: the pool's signed promise that, in `epoch`, the address has at least `weight` of vpool/2 share weight (`shares` shares).
pub fn make_receipt(sk: &SigningKey, genesis: &Hash, address: &str, epoch: u64, weight: u128, shares: u64, ts: u64) -> Value {
    let mut v = json!({"address": address, "epoch": epoch, "genesis": hex(genesis), "pool": address_of(&pubkey(sk)), "shares": shares, "ts": ts, "weight": weight.to_string()});
    let sig = sign(sk, &signed_bytes(RECEIPT_DOMAIN, &v));
    v["sig"] = json!(hex(&sig));
    v
}

/// Signature and pool of a receipt (a miner does not know the genesis hash, the pool key it learned from its jobs is enough).
pub fn verify_receipt_sig(v: &Value, pool_key: &PubKey) -> Result<(), String> {
    if v.get("pool").and_then(|x| x.as_str()) != Some(&address_of(pool_key)) {
        return Err("receipt of another pool".into());
    }
    check_sig(v, pool_key, RECEIPT_DOMAIN)
}

pub fn verify_receipt(v: &Value, pool_key: &PubKey, genesis: &Hash) -> Result<(), String> {
    if v.get("genesis").and_then(|x| x.as_str()) != Some(&hex(genesis)) {
        return Err("receipt of another network".into());
    }
    verify_receipt_sig(v, pool_key)
}

/// The native matrices needed to recompute shares, kept for a few epochs only. A hostile pool can refer to as many different matrices as it
/// likes (one per job height): the cache is small and the number of times a matrix may be built in one audit is bounded.
pub struct ShareCache {
    map: HashMap<u64, CommittedMatrices>,
    pub builds: usize,
    pub max_builds: usize,
}

impl ShareCache {
    pub fn new(max_builds: usize) -> Self {
        ShareCache { map: HashMap::new(), builds: 0, max_builds }
    }
}

/// A listed block this many heights above the top of the chain the auditor holds is a phantom (a copy of the chain can lag by minutes, not by this much).
pub const MAX_CHAIN_LAG: u64 = 1000;

/// Error of `verify_share` when the audit has used up its budget of matrix builds (the audit reports it as a suspicion, not as fraud).
pub const BUDGET_EXCEEDED: &str = "audit budget exceeded";

/// Recomputes the jackpot of a share and checks it against the target it was credited at.
pub fn verify_share(rec: &ShareRec, job: &JobRec, pool_key: &PubKey, p: &WorkParams, cache: &mut ShareCache) -> Result<(), String> {
    if job.native_epoch != job.height / EPOCH_LEN {
        return Err("job: native epoch does not match its height".into());
    }
    // A share credited at a target HARDER than its job's network target is not a finding: the network target of a job can get easier while the
    // pool still holds the session target of the previous job (it keeps it for 30 s), and the recomputation below proves that the jackpot
    // really reaches the target the share was credited at, which is all that its weight needs. (Older audits called it fraud: an honest pool
    // was excluded after a difficulty drop.)
    let sg = sigma(&job.prev, pool_key, &WorkClass::Native, rec.extra_nonce, &job.tx_root, job.timestamp);
    if !cache.map.contains_key(&job.native_epoch) {
        if cache.builds >= cache.max_builds {
            return Err(BUDGET_EXCEEDED.into());
        }
        cache.builds += 1;
        if cache.map.len() >= 6 {
            cache.map.clear();
        }
        let (a, b) = native_matrices(job.native_epoch, p);
        cache.map.insert(job.native_epoch, CommittedMatrices::new(a, b, p));
    }
    let cm = &cache.map[&job.native_epoch];
    let jp = tile_jackpot(cm, &sg, rec.ti as usize, rec.tj as usize, p).ok_or("tile out of range")?;
    if meets_target(&jp, rec.target) {
        Ok(())
    } else {
        Err("jackpot not below the credited target".into())
    }
}

// ---------------------------------------------------------------- statistics

/// P(X <= k) for X ~ Poisson(mu), in log space (stable for large values).
pub fn poisson_cdf(k: u64, mu: f64) -> f64 {
    if mu <= 0.0 {
        return 1.0;
    }
    let (ln_mu, mut lg) = (mu.ln(), 0.0f64);
    let mut terms: Vec<f64> = Vec::with_capacity(k as usize + 1);
    for i in 0..=k {
        if i > 0 {
            lg += (i as f64).ln();
        }
        terms.push(-mu + i as f64 * ln_mu - lg);
    }
    let m = terms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (m + terms.iter().map(|t| (t - m).exp()).sum::<f64>().ln()).exp().min(1.0)
}

/// P(X >= k) for X ~ Poisson(mu).
pub fn poisson_sf(k: u64, mu: f64) -> f64 {
    if k == 0 {
        1.0
    } else {
        (1.0 - poisson_cdf(k - 1, mu)).max(0.0)
    }
}

/// Expected number of blocks for a total share weight, given the network target: weight / 2^32 tile attempts, each a block with
/// probability target / 2^64.
pub fn expected_blocks(total_weight: u128, net_target: u64) -> f64 {
    (total_weight as f64 / 4294967296.0) * (net_target as f64 / 18446744073709551616.0)
}

// ---------------------------------------------------------------- audit

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Suspect,
    Fraud,
}

impl Severity {
    pub fn name(&self) -> &'static str {
        match self {
            Severity::Info => "ok",
            Severity::Suspect => "suspect",
            Severity::Fraud => "fraud",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub epoch: Option<u64>,
    pub severity: Severity,
    pub code: &'static str,
    pub detail: String,
}

pub struct ChainBlock {
    pub height: u64,
    pub timestamp: u64,
    pub miner: String,
    pub hash: Option<String>,
}

pub struct ShareProof {
    pub index: u64,
    pub rec: ShareRec,
    pub path: Vec<Hash>,
}

pub enum Samples {
    /// the complete list of shares of the epoch
    Full(Vec<ShareRec>),
    /// shares drawn by the auditor AFTER the document was published, with their Merkle paths
    Proofs(Vec<ShareProof>),
}

#[derive(Default)]
pub struct AuditInput {
    pub docs: BTreeMap<u64, Value>,
    pub samples: BTreeMap<u64, Samples>,
    pub chain: Option<Vec<ChainBlock>>,
    pub receipts: Vec<Value>,
    /// epoch -> Unix time at which we first held its document (a document that shows up long after its epoch is held)
    pub seen: BTreeMap<u64, u64>,
}

pub struct AuditCfg {
    pub pool_key: PubKey,
    pub genesis: Hash,
    pub params: WorkParams,
    /// current time (a document is only due `publish_deadline` seconds after its epoch ended)
    pub now: u64,
    pub publish_deadline: u64,
    /// at most this many shares of a full list are recomputed (evenly spread, offset from the document hash)
    pub verify_max: usize,
    /// significance levels of the work-versus-blocks test
    pub p_suspect: f64,
    /// epoch lengths a pool may use (3600 on the public testnet): a pool that picks its own windows could move work between scoring days
    pub allowed_epoch_secs: Vec<u64>,
    /// a document first seen later than this after its epoch ended is held
    pub max_publish_lag: u64,
    /// how many times the audit may build the native matrices (each costs about a second at n = 1024)
    pub max_matrix_builds: usize,
}

impl AuditCfg {
    pub fn new(pool_key: PubKey, genesis: Hash, params: WorkParams, now: u64) -> Self {
        AuditCfg { pool_key, genesis, params, now, publish_deadline: 24 * 3600, verify_max: 64, p_suspect: 1e-9, allowed_epoch_secs: vec![EPOCH_SECS], max_publish_lag: 3 * 3600, max_matrix_builds: 400 }
    }
}

pub struct AuditReport {
    pub pool: String,
    pub verdict: Severity,
    pub epochs: BTreeMap<u64, Severity>,
    pub findings: Vec<Finding>,
    pub stats: Value,
}

impl AuditReport {
    pub fn to_json(&self) -> Value {
        json!({
            "proto": "vpool-audit/1", "pool": self.pool, "verdict": self.verdict.name(),
            "epochs": self.epochs.iter().map(|(e, s)| (e.to_string(), json!(s.name()))).collect::<serde_json::Map<String, Value>>(),
            "findings": self.findings.iter().map(|f| json!({"epoch": f.epoch, "severity": f.severity.name(), "code": f.code, "detail": f.detail})).collect::<Vec<_>>(),
            "stats": self.stats,
        })
    }
    pub fn has(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }
}

fn s_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}
fn u_field(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(|x| x.as_u64())
}
fn dec128(v: &Value, k: &str) -> Option<u128> {
    s_field(v, k)?.parse().ok()
}

fn parse_jobs(doc: &Value) -> Option<Vec<JobRec>> {
    doc.get("jobs")?
        .as_array()?
        .iter()
        .map(|j| {
            Some(JobRec {
                prev: unhex32(s_field(j, "prev")?)?,
                height: u_field(j, "height")?,
                timestamp: u_field(j, "timestamp")?,
                tx_root: unhex32(s_field(j, "tx_root")?)?,
                target: parse_u64hex(s_field(j, "target")?)?,
                native_epoch: u_field(j, "native_epoch")?,
            })
        })
        .collect()
}

/// (address -> (weight, shares, v2 weight, v2 shares)) announced by a document.
fn doc_miners(doc: &Value) -> Option<BTreeMap<String, (u128, u64, u128, u64)>> {
    let mut m = BTreeMap::new();
    for x in doc.get("miners")?.as_array()? {
        let a = s_field(x, "address")?.to_string();
        if m.insert(a, (dec128(x, "weight")?, u_field(x, "shares")?, dec128(x, "v2_weight")?, u_field(x, "v2_shares")?)).is_some() {
            return None;
        }
    }
    Some(m)
}

fn doc_blocks(doc: &Value) -> Option<Vec<(u64, String, u64)>> {
    doc.get("blocks")?.as_array()?.iter().map(|b| Some((u_field(b, "height")?, s_field(b, "hash")?.to_string(), u_field(b, "timestamp")?))).collect()
}

/// Audits what a pool published. Pure function: every input is data (documents, samples, chain blocks, receipts).
pub fn audit_pool(cfg: &AuditCfg, inp: &AuditInput) -> AuditReport {
    let pool_addr = address_of(&cfg.pool_key);
    let mut findings: Vec<Finding> = vec![];
    let mut add = |epoch: Option<u64>, severity: Severity, code: &'static str, detail: String| findings.push(Finding { epoch, severity, code, detail });
    let mut stats = serde_json::Map::new();

    // ---- 1. the documents: signature, identity, arithmetic, chaining
    let mut good: BTreeMap<u64, &Value> = BTreeMap::new();
    for (e, d) in &inp.docs {
        if let Err(m) = verify_doc(d, &cfg.pool_key, &cfg.genesis) {
            add(Some(*e), Severity::Suspect, "document_unusable", format!("epoch {e}: {m}"));
            continue;
        }
        let secs = u_field(d, "epoch_secs").unwrap_or(0);
        if !cfg.allowed_epoch_secs.contains(&secs) {
            add(Some(*e), Severity::Suspect, "document_unusable", format!("epoch {e}: epoch length {secs} s is not one the program counts"));
            continue;
        }
        if u_field(d, "epoch") != Some(*e) || secs == 0 || u_field(d, "start") != Some(e * secs) || u_field(d, "end") != Some((e + 1) * secs) {
            add(Some(*e), Severity::Fraud, "document_inconsistent", format!("epoch {e}: epoch number or window does not match"));
            continue;
        }
        match doc_miners(d) {
            Some(m) => {
                let tw: u128 = m.values().map(|t| t.0).sum();
                let ts: u64 = m.values().map(|t| t.1).sum();
                if dec128(d, "total_weight") != Some(tw) || u_field(d, "total_shares") != Some(ts) || u_field(d, "shares_count") != Some(ts) || m.values().any(|t| t.2 > t.0 || t.3 > t.1) {
                    add(Some(*e), Severity::Fraud, "document_inconsistent", format!("epoch {e}: the totals do not add up"));
                    continue;
                }
            }
            None => {
                add(Some(*e), Severity::Fraud, "document_inconsistent", format!("epoch {e}: miners list unreadable or duplicated"));
                continue;
            }
        }
        let (Some(jobs), Some(_)) = (parse_jobs(d), doc_blocks(d)) else {
            add(Some(*e), Severity::Fraud, "document_inconsistent", format!("epoch {e}: jobs or blocks unreadable"));
            continue;
        };
        // the shares of an epoch were found on jobs of that epoch: a job far outside the window means work done at another time, claimed here
        let (start, end) = (*e * secs, (*e + 1) * secs);
        if let Some(j) = jobs.iter().find(|j| j.timestamp >= end + MAX_JOB_AGE || j.timestamp + MAX_JOB_AGE < start || j.native_epoch != j.height / EPOCH_LEN) {
            add(Some(*e), Severity::Fraud, "job_outside_epoch", format!("epoch {e}: a job (height {}, timestamp {}) cannot belong to the window {start}..{end}", j.height, j.timestamp));
            continue;
        }
        good.insert(*e, d);
    }
    // chaining: each document commits to the previous one that we hold
    let mut prev_hash = hex(&ZERO_HASH);
    let mut first = true; // the first document we hold may follow earlier ones we were not given: not an anomaly by itself
    for (e, d) in &good {
        if !first && s_field(d, "prev").unwrap_or("") != prev_hash {
            add(Some(*e), Severity::Suspect, "chain_break", format!("epoch {e}: its `prev` is not the hash of the previous document we hold (missing or rewritten document)"));
        }
        first = false;
        prev_hash = doc_hash(d);
    }

    for (e, d) in &good {
        if let Some(t) = inp.seen.get(e) {
            if *t > u_field(d, "end").unwrap() + cfg.max_publish_lag {
                add(Some(*e), Severity::Suspect, "late_document", format!("epoch {e}: the document only appeared {} s after its epoch ended", t - u_field(d, "end").unwrap()));
            }
        }
    }
    let hash_at: HashMap<u64, &String> = inp.chain.iter().flatten().filter_map(|b| b.hash.as_ref().map(|h| (b.height, h))).collect();
    if let Some(chain) = &inp.chain {
        let top = chain.iter().map(|b| b.height).max().unwrap_or(0);
        let (mut jobs_total, mut jobs_off) = (0usize, 0usize);
        for (e, d) in &good {
            for j in parse_jobs(d).unwrap() {
                jobs_total += 1;
                if j.height > top + 2 {
                    add(Some(*e), Severity::Fraud, "job_from_the_future", format!("epoch {e}: a job is at height {} but the chain is at {top}", j.height));
                    break;
                }
                if j.height > 0 && hash_at.get(&(j.height - 1)).map_or(false, |h| **h != hex(&j.prev)) {
                    jobs_off += 1;
                }
            }
        }
        if jobs_total >= 8 && jobs_off * 4 > jobs_total {
            add(None, Severity::Suspect, "unknown_parent_jobs", format!("{jobs_off} of {jobs_total} jobs build on a parent block that is not on the chain"));
        }
    }

    // ---- 2. the pool's blocks on the chain are exactly the blocks of its documents
    let mut chain_pool_blocks = 0usize;
    if let Some(chain) = &inp.chain {
        let mine: Vec<&ChainBlock> = chain.iter().filter(|b| b.miner == pool_addr).collect();
        chain_pool_blocks = mine.len();
        // A block is documented in the epoch in which the pool FOUND it; its header timestamp is the age of the job it was found with, so it
        // may precede the epoch by up to MAX_JOB_AGE seconds (old job) or follow it by as much (the chain accepts timestamps slightly ahead of time).
        let mut seen: HashSet<u64> = HashSet::new();
        let tip = chain.iter().map(|b| b.height).max().unwrap_or(0);
        let (mut listed, mut orphans) = (0usize, 0usize);
        for (e, d) in &good {
            let (start, end) = (u_field(d, "start").unwrap(), u_field(d, "end").unwrap());
            for (h, hash, ts) in &doc_blocks(d).unwrap() {
                if !seen.insert(*h) {
                    add(Some(*e), Severity::Fraud, "block_listed_twice", format!("block {h} appears in two documents"));
                }
                if *ts >= end + MAX_JOB_AGE || *ts + MAX_JOB_AGE < start {
                    add(Some(*e), Severity::Fraud, "block_outside_epoch", format!("block {h} has timestamp {ts}, which cannot belong to the epoch window {start}..{end}"));
                }
                listed += 1;
                // The pool lists every block it FOUND. A block that lost the race to another block of the same height (an orphan: normal on a chain with
                // blocks every 10 s) is not on the chain, and earns nothing: the points are computed from the blocks of the CHAIN. It is not a finding
                // (only a high share of orphans is, below). A block far above the top of the chain we hold cannot be explained by a lagging copy of it.
                match chain.iter().find(|b| b.height == *h) {
                    Some(b) if b.miner == pool_addr && b.timestamp == *ts && b.hash.as_ref().map_or(true, |x| x == hash) => {}
                    Some(b) => {
                        orphans += 1;
                        let who = if b.miner == pool_addr { "another block of this pool" } else { "a block of another miner" };
                        add(Some(*e), Severity::Info, "orphaned_block", format!("block {h} is listed but the chain holds {who} at that height: it lost the race and earns nothing"));
                    }
                    None if *h > tip + MAX_CHAIN_LAG => add(Some(*e), Severity::Fraud, "phantom_block", format!("block {h} is listed but the chain we hold stops at {tip}: it cannot be that far ahead")),
                    None => add(Some(*e), Severity::Info, "block_not_on_chain_yet", format!("block {h} is listed but is above the chain we hold ({tip}): it may be a block of the last minutes")),
                }
            }
        }
        // a pool whose blocks are mostly not on the chain either mines on a fork or lists blocks it never found: a person looks at it
        if listed >= 8 && orphans * 3 > listed {
            add(None, Severity::Suspect, "many_orphans", format!("{orphans} of the {listed} blocks the pool lists are not on the chain (more than a third)"));
        }
        // every PPLNS block of the pool on the chain must be listed in some document; the pool has until the deadline to publish the epoch it
        // was found in. A block mined through a SOLO port under the same pool address (a legitimate, common setup: ours included) is on chain
        // under this address too but is never in the PPLNS ledger by design, so this cannot be told apart from real hiding with chain data
        // alone: Suspect (a human checks with the pool), not Fraud.
        for b in mine {
            if seen.contains(&b.height) {
                continue;
            }
            let epoch = b.timestamp / EPOCH_SECS;
            if cfg.now < b.timestamp + cfg.publish_deadline {
                add(Some(epoch), Severity::Info, "block_pending", format!("block {}: not in a published ledger yet (still within the deadline)", b.height));
            } else if good.values().any(|d| u_field(d, "end").unwrap() > b.timestamp) {
                add(Some(epoch), Severity::Suspect, "hidden_block", format!("block {} of this pool is on the chain but in none of its signed ledgers, although later ledgers were published (or it was mined through a solo port under the same address, which is never in the PPLNS ledger)", b.height));
            } else {
                add(Some(epoch), Severity::Suspect, "undocumented_block", format!("block {} has no signed ledger and its publication deadline has passed (or it was mined through a solo port under the same address, which is never in the PPLNS ledger)", b.height));
            }
        }
    }

    // ---- 3. the shares: Merkle commitment, arithmetic, recomputation
    let mut cache = ShareCache::new(cfg.max_matrix_builds);
    let (mut verified, mut unknown_parent, mut over_budget) = (0usize, 0usize, false);
    let chain_hash_at = |h: u64| -> Option<&String> { hash_at.get(&h).copied() };
    for (e, d) in &good {
        let Some(samples) = inp.samples.get(e) else {
            add(Some(*e), Severity::Info, "not_sampled", format!("epoch {e}: no shares were provided to check"));
            continue;
        };
        let jobs = parse_jobs(d).unwrap();
        let root = unhex32(s_field(d, "shares_root").unwrap_or("")).unwrap_or(ZERO_HASH);
        let count = u_field(d, "shares_count").unwrap_or(0) as usize;
        let mut to_check: Vec<&ShareRec> = vec![];
        let mut proofs_ok = true;
        match samples {
            Samples::Full(recs) => {
                if recs.len() != count || shares_tree(recs).root() != root {
                    add(Some(*e), Severity::Fraud, "shares_root_mismatch", format!("epoch {e}: the complete list of shares does not match the signed Merkle root"));
                    proofs_ok = false;
                } else {
                    let want = doc_miners(d).unwrap();
                    let got = totals(recs);
                    let got_s: BTreeMap<String, (u128, u64, u128, u64)> = got.iter().map(|(a, t)| (address_of(a), *t)).collect();
                    if got_s != want {
                        add(Some(*e), Severity::Fraud, "weights_mismatch", format!("epoch {e}: the miners' weights are not the sum of the listed shares"));
                        proofs_ok = false;
                    }
                    let mut dup: HashSet<(u32, u64, u16, u16)> = HashSet::new();
                    if recs.iter().any(|r| !dup.insert((r.job, r.extra_nonce, r.ti, r.tj))) {
                        add(Some(*e), Severity::Fraud, "duplicate_share", format!("epoch {e}: the same share is counted twice"));
                        proofs_ok = false;
                    }
                    if proofs_ok {
                        let n = recs.len();
                        let stride = (n / cfg.verify_max.max(1)).max(1);
                        let off = d_offset(d, stride);
                        to_check = recs.iter().skip(off).step_by(stride).take(cfg.verify_max).collect();
                    }
                }
            }
            Samples::Proofs(ps) => {
                let depth = depth_for(count.max(1));
                for p in ps {
                    if (p.index as usize) >= count || !verify_proof(&root, share_leaf(p.index, &p.rec), p.index as usize, &p.path, depth) {
                        add(Some(*e), Severity::Fraud, "shares_root_mismatch", format!("epoch {e}: share {} is not in the committed list", p.index));
                        proofs_ok = false;
                    } else {
                        to_check.push(&p.rec);
                    }
                }
            }
        }
        if !proofs_ok {
            continue;
        }
        let miners: HashSet<String> = doc_miners(d).unwrap().keys().cloned().collect();
        for r in to_check {
            let Some(job) = jobs.get(r.job as usize) else {
                add(Some(*e), Severity::Fraud, "share_invalid", format!("epoch {e}: a share refers to a job that does not exist"));
                continue;
            };
            if !miners.contains(&address_of(&r.addr)) {
                add(Some(*e), Severity::Fraud, "share_invalid", format!("epoch {e}: a share is credited to an address that is not in the document"));
                continue;
            }
            match verify_share(r, job, &cfg.pool_key, &cfg.params, &mut cache) {
                Ok(()) => verified += 1,
                Err(m) if m == BUDGET_EXCEEDED => {
                    if !over_budget {
                        over_budget = true;
                        add(None, Severity::Suspect, "audit_budget", "too many different matrices to rebuild: the audit stopped recomputing shares; run it again on fewer epochs".to_string());
                    }
                }
                Err(m) => add(Some(*e), Severity::Fraud, "share_invalid", format!("epoch {e}: {m}")),
            }
            if job.height > 0 {
                if let Some(h) = chain_hash_at(job.height - 1) {
                    if *h != hex(&job.prev) {
                        unknown_parent += 1;
                    }
                }
            }
        }
    }
    if verified >= 10 && unknown_parent * 4 > verified {
        add(None, Severity::Suspect, "unknown_parent", format!("{unknown_parent} of {verified} checked shares were found on a parent block that is not on the chain"));
    }

    // ---- 4. receipts: the pool must not contradict its own signatures
    let mut best: BTreeMap<(u64, String), (u128, u64)> = BTreeMap::new();
    for r in &inp.receipts {
        if verify_receipt(r, &cfg.pool_key, &cfg.genesis).is_err() {
            continue; // not signed by this pool: not evidence of anything
        }
        let (Some(e), Some(a), Some(w), Some(n)) = (u_field(r, "epoch"), s_field(r, "address"), dec128(r, "weight"), u_field(r, "shares")) else { continue };
        let slot = best.entry((e, a.to_string())).or_default();
        slot.0 = slot.0.max(w);
        slot.1 = slot.1.max(n);
    }
    for ((e, a), (w, n)) in &best {
        match good.get(e) {
            Some(d) => {
                let m = doc_miners(d).unwrap();
                let (cw, cn) = m.get(a).map_or((0, 0), |t| (t.2, t.3));
                if cw < *w || cn < *n {
                    add(Some(*e), Severity::Fraud, "receipt_contradiction", format!("epoch {e}: the pool signed a receipt of {w} (shares {n}) for {a}, its signed ledger credits {cw} (shares {cn})"));
                }
            }
            None => {
                if cfg.now >= (e + 1) * EPOCH_SECS + cfg.publish_deadline {
                    add(Some(*e), Severity::Fraud, "receipt_unpublished", format!("epoch {e}: the pool signed a receipt for {a} but never published the ledger of that epoch"));
                }
            }
        }
    }

    // ---- 5. work versus blocks, per day (a Poisson test; block withholding by a miner also lowers the blocks: a human decides)
    let mut days: BTreeMap<u64, (f64, u64)> = BTreeMap::new();
    for (_, d) in &good {
        let jobs = parse_jobs(d).unwrap();
        if jobs.is_empty() {
            continue;
        }
        let mean_target = jobs.iter().map(|j| j.target as f64).sum::<f64>() / jobs.len() as f64;
        let tw = dec128(d, "total_weight").unwrap_or(0);
        let day = u_field(d, "start").unwrap() / 86400;
        let slot = days.entry(day).or_default();
        slot.0 += (tw as f64 / 4294967296.0) * (mean_target / 18446744073709551616.0);
        slot.1 += doc_blocks(d).unwrap().len() as u64;
    }
    let mut worst_p = 1.0f64;
    for (day, (mu, k)) in &days {
        if *mu < 8.0 {
            continue;
        }
        let (lo, hi) = (poisson_cdf(*k, *mu), poisson_sf(*k, *mu));
        worst_p = worst_p.min(lo.min(hi));
        if lo < cfg.p_suspect {
            add(None, Severity::Suspect, "work_vs_blocks", format!("day {day}: the ledger claims work worth {mu:.1} blocks but the pool found {k} (p = {lo:.2e}): claimed work too high"));
        } else if hi < cfg.p_suspect {
            add(None, Severity::Suspect, "work_vs_blocks", format!("day {day}: the pool found {k} blocks for work worth {mu:.1} (p = {hi:.2e}): the ledger hides work"));
        }
    }

    stats.insert("documents".into(), json!(inp.docs.len()));
    stats.insert("documents_usable".into(), json!(good.len()));
    stats.insert("pool_blocks_on_chain".into(), json!(chain_pool_blocks));
    stats.insert("shares_recomputed".into(), json!(verified));
    stats.insert("receipts_checked".into(), json!(best.len()));
    stats.insert("work_vs_blocks_worst_p".into(), json!(worst_p));

    let mut epochs: BTreeMap<u64, Severity> = good.keys().map(|e| (*e, Severity::Info)).collect();
    let mut verdict = Severity::Info;
    for f in &findings {
        verdict = verdict.max(f.severity);
        if let Some(e) = f.epoch {
            let s = epochs.entry(e).or_insert(Severity::Info);
            *s = (*s).max(f.severity);
        }
    }
    // a finding that concerns the whole pool (no epoch) holds every epoch at that level at least
    for f in findings.iter().filter(|f| f.epoch.is_none()) {
        for s in epochs.values_mut() {
            *s = (*s).max(f.severity);
        }
    }
    AuditReport { pool: pool_addr, verdict, epochs, findings, stats: Value::Object(stats) }
}

fn d_offset(doc: &Value, stride: usize) -> usize {
    let h = doc_hash(doc);
    (usize::from_str_radix(&h[..4], 16).unwrap_or(0)) % stride.max(1)
}

/// Address check shared with the tools: the pool address of a document as a key.
pub fn pool_key_of_address(addr: &str) -> Result<PubKey, String> {
    parse_address(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tx;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn poisson_tails_are_right() {
        assert!((poisson_cdf(0, 1.0) - (-1.0f64).exp()).abs() < 1e-12);
        assert!((poisson_cdf(2, 2.0) - 5.0 * (-2.0f64).exp()).abs() < 1e-12);
        assert!(poisson_cdf(10, 1000.0) < 1e-100);
        assert!((poisson_cdf(1000, 1000.0) - 0.5).abs() < 0.03);
        assert!((poisson_sf(0, 3.0) - 1.0).abs() < 1e-12);
        assert!(poisson_cdf(5, 0.0) == 1.0);
    }

    #[test]
    fn a_document_is_signed_chained_and_tamper_evident() {
        let (sk, g) = (key(9), [1u8; 32]);
        let job = JobRec { prev: [2; 32], height: 5, timestamp: 100, tx_root: [3; 32], target: 1 << 40, native_epoch: 0 };
        let recs = vec![
            ShareRec { addr: pubkey(&key(1)), job: 0, extra_nonce: 7, ti: 1, tj: 2, target: 1 << 50, v2: true },
            ShareRec { addr: pubkey(&key(2)), job: 0, extra_nonce: 8, ti: 1, tj: 3, target: 1 << 50, v2: false },
        ];
        let blocks = [(5u64, [4u8; 32], 100u64)];
        let d = EpochData { epoch: 3, epoch_secs: EPOCH_SECS, fee_bps: 100, blocks: &blocks, jobs: &[job], records: &recs };
        let doc = build_doc(&sk, &g, &ZERO_HASH, &d);
        assert!(verify_doc(&doc, &pubkey(&sk), &g).is_ok());
        assert!(verify_doc(&doc, &pubkey(&key(8)), &g).is_err(), "another pool key");
        assert!(verify_doc(&doc, &pubkey(&sk), &[2u8; 32]).is_err(), "another network");
        let mut forged = doc.clone();
        forged["miners"][0]["v2_weight"] = json!("999999999999999999999999");
        assert!(verify_doc(&forged, &pubkey(&sk), &g).is_err(), "changing a weight breaks the signature");
        assert_eq!(doc_hash(&doc), doc_hash(&doc));
        let second = build_doc(&sk, &g, &ZERO_HASH, &EpochData { epoch: 4, ..d });
        assert_ne!(doc_hash(&doc), doc_hash(&second));
        assert_eq!(doc["total_shares"], 2);
        assert_eq!(doc["miners"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn receipts_verify_only_for_their_pool_and_network() {
        let (sk, g) = (key(9), [1u8; 32]);
        let r = make_receipt(&sk, &g, "vrl1abc", 12, 5000, 3, 99);
        assert!(verify_receipt(&r, &pubkey(&sk), &g).is_ok());
        assert!(verify_receipt(&r, &pubkey(&key(7)), &g).is_err());
        assert!(verify_receipt(&r, &pubkey(&sk), &[0; 32]).is_err());
        let mut t = r.clone();
        t["weight"] = json!("4999");
        assert!(verify_receipt(&t, &pubkey(&sk), &g).is_err());
    }

    #[test]
    fn the_shares_tree_proves_membership() {
        let recs: Vec<ShareRec> = (0..13u64).map(|i| ShareRec { addr: pubkey(&key(1)), job: 0, extra_nonce: i, ti: 0, tj: 0, target: 1 << 40, v2: true }).collect();
        let t = shares_tree(&recs);
        let depth = depth_for(recs.len());
        for i in [0usize, 5, 12] {
            assert!(verify_proof(&t.root(), share_leaf(i as u64, &recs[i]), i, &t.proof(i), depth));
        }
        assert!(!verify_proof(&t.root(), share_leaf(3, &recs[4]), 3, &t.proof(3), depth), "a different share is not at that index");
        assert_eq!(ShareRec::from_bytes(&recs[2].bytes()), Some(recs[2].clone()));
    }

    #[test]
    fn what_the_pool_key_signs_can_never_be_read_as_a_transaction() {
        // Transactions are signed WITHOUT a domain prefix (bincode of the transaction): to be safe, nothing else the pool key signs may parse as one of
        // its own. Documents and receipts start with a fixed 21-byte domain, so the 32 bytes read as `from` are never the pool key.
        let sk = key(9);
        let g = [1u8; 32];
        let doc = build_doc(&sk, &g, &ZERO_HASH, &EpochData { epoch: 1, epoch_secs: EPOCH_SECS, fee_bps: 0, blocks: &[], jobs: &[], records: &[] });
        let receipt = make_receipt(&sk, &g, "vrl1x", 1, 1, 1, 1);
        for m in [signed_bytes(DOC_DOMAIN, &doc), signed_bytes(RECEIPT_DOMAIN, &receipt)] {
            assert!(m.len() > 32);
            assert_ne!(&m[..32], &pubkey(&sk)[..], "the first 32 bytes of a tx are the sender: it can never be the signer");
            if let Ok(tx) = bincode::deserialize::<Tx>(&m) {
                assert_ne!(tx.from, pubkey(&sk));
            }
        }
        // and the relay announcement is a bare 32-byte hash, too short to be a transaction
        assert_eq!(crate::net::relay_msg(&g, &[2; 32]).len(), 32);
    }

    #[test]
    fn expected_blocks_scales_with_work() {
        let w = share_weight(1 << 40);
        let a = expected_blocks(w, 1 << 30);
        assert!((expected_blocks(2 * w, 1 << 30) / a - 2.0).abs() < 1e-9);
        assert!((expected_blocks(w, 1 << 31) / a - 2.0).abs() < 1e-9);
    }
}
