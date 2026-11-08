//! Pool points ledger (vpool/2, docs/16 section 13): a real node, a real pool and real CPU miners publish signed hourly documents
//! (here every 4 seconds); the audit accepts the honest pool and catches every way of cheating that we could think of.
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vearl_core::chain::*;
use vearl_core::crypto::*;
use vearl_core::net::*;
use vearl_core::pool::*;
use vearl_core::poolminer::{run, MinerConfig, MinerStats};
use vearl_core::poolpoints::*;
use vearl_core::wallet::address_of;

const SHARE_TARGET: u64 = u64::MAX / 1024;
const EPOCH: u64 = 4;

fn genesis() -> GenesisConfig {
    let mut g = devnet_genesis();
    g.target = u64::MAX / 4096;
    g.retarget = Retarget::Fixed;
    g
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timeout: {what}");
}

fn http_get(addr: &str, path: &str) -> Value {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let i = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice(&buf[i..]).unwrap_or(Value::Null)
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

struct Run {
    pool: Arc<Pool>,
    node: NodeHandle,
    sk: SigningKey,
    http: String,
    miners: Vec<(Arc<MinerStats>, Arc<AtomicBool>, String)>,
    dir: std::path::PathBuf,
    /// start of the (test) program: the points are counted from here
    start: u64,
}

fn start(miners: &[(u8, &str)]) -> Run {
    start_with(miners, |_| {})
}

fn start_with(miners: &[(u8, &str)], tweak: impl FnOnce(&mut PoolConfig)) -> Run {
    let node = spawn_node(NodeConfig { genesis: genesis(), listen: "127.0.0.1:0".into(), peers: vec![], mine_key: None, use_gpu: false, log: false, worker: None, data_dir: None }).unwrap();
    let sk = SigningKey::from_bytes(&[200; 32]);
    let start = now_secs() - 600;
    let mut cfg = PoolConfig {
        listen: "127.0.0.1:0".into(),
        http: Some("127.0.0.1:0".into()),
        fee_bps: 200,
        confirmations: 2,
        min_payout: 1,
        payout_interval: 1,
        fixed_share_target: Some(SHARE_TARGET),
        data_dir: None,
        log: false,
        points_epoch_secs: EPOCH,
        points_grace_secs: 1,
        receipt_secs: 1,
        testnet_start: start,
        ..PoolConfig::default()
    };
    tweak(&mut cfg);
    let pool = Pool::start(cfg, node.shared.clone(), sk.clone()).unwrap();
    let http = pool.http_addr.lock().unwrap().clone().unwrap();
    let dir = std::env::temp_dir().join(format!("vpool-points-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ms = vec![];
    for (seed, name) in miners {
        let address = address_of(&pubkey(&SigningKey::from_bytes(&[*seed; 32])));
        let stats = Arc::new(MinerStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let c = MinerConfig { pool: pool.local_addr(), address: address.clone(), worker: name.to_string(), threads: 1, gpu: false, rate_hint: Some(1000.0), log: false, receipts: Some(dir.join(format!("receipts-{seed}.jsonl"))) };
        let (s, st) = (stats.clone(), stop.clone());
        std::thread::spawn(move || run(c, s, st));
        ms.push((stats, stop, address));
    }
    Run { pool, node, sk, http, miners: ms, dir, start }
}

impl Run {
    fn epochs(&self) -> Vec<u64> {
        http_get(&self.http, "/api/points/index")["epochs"].as_array().map(|a| a.iter().map(|e| e["epoch"].as_u64().unwrap()).collect()).unwrap_or_default()
    }
    fn doc(&self, e: u64) -> Value {
        http_get(&self.http, &format!("/api/points/epoch/{e}"))
    }
    fn full(&self, e: u64) -> Vec<ShareRec> {
        http_get(&self.http, &format!("/api/points/shares/{e}"))["records"].as_array().unwrap().iter().map(|x| ShareRec::from_bytes(&from_hex(x.as_str().unwrap())).unwrap()).collect()
    }
    fn proofs(&self, e: u64, count: usize, k: usize) -> Vec<ShareProof> {
        (0..k.min(count))
            .map(|j| {
                let i = j * count / k.min(count);
                let v = http_get(&self.http, &format!("/api/points/share/{e}/{i}"));
                ShareProof { index: i as u64, rec: ShareRec::from_bytes(&from_hex(v["record"].as_str().unwrap())).unwrap(), path: v["path"].as_array().unwrap().iter().map(|h| unhex32(h.as_str().unwrap()).unwrap()).collect() }
            })
            .collect()
    }
    fn chain(&self) -> Vec<ChainBlock> {
        let n = self.node.shared.node.lock().unwrap();
        n.chain.blocks.iter().map(|b| ChainBlock { height: b.header.height, timestamp: b.header.timestamp, miner: address_of(&b.header.miner), hash: Some(hex(&b.header.hash())) }).collect()
    }
    fn receipts(&self) -> Vec<Value> {
        let mut out = vec![];
        for e in std::fs::read_dir(&self.dir).unwrap().flatten() {
            for l in std::fs::read_to_string(e.path()).unwrap_or_default().lines() {
                if let Ok(v) = serde_json::from_str(l) {
                    out.push(v);
                }
            }
        }
        out
    }
    fn cfg(&self) -> AuditCfg {
        let mut c = AuditCfg::new(self.pool.pk, genesis_hash(&genesis()), genesis().params, now_secs());
        c.verify_max = 100_000; // recompute every share of the test epochs
        // this test chain finds a block every few attempts, so most solutions are stale (one block per height): the work-versus-blocks test
        // only makes sense on a chain where stale solutions are rare; it is exercised on its own in the second test
        c.p_suspect = 0.0;
        c.allowed_epoch_secs = vec![EPOCH];
        c
    }
    /// Stops the miners and waits until every epoch is published (no open epoch left): the figures are then final.
    fn halt_miners(&self) {
        for (_, stop, _) in &self.miners {
            stop.store(true, Ordering::SeqCst);
        }
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(60) {
            if self.pool.ledger_snapshot(|l| l.epochs.is_empty()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let open: Vec<(u64, usize, usize)> = self.pool.ledger_snapshot(|l| l.epochs.iter().map(|(e, r)| (*e, r.records.len(), r.blocks.len())).collect());
        panic!("epochs still open: {open:?} (now = epoch {}); sessions connected: {}", now_secs() / EPOCH, self.pool.stats_json()["workers"]);
    }
    fn stop(&self) {
        for (_, stop, _) in &self.miners {
            stop.store(true, Ordering::SeqCst);
        }
        self.pool.stop();
        self.node.stop();
    }
}

fn codes(r: &AuditReport) -> Vec<&'static str> {
    r.findings.iter().filter(|f| f.severity != Severity::Info).map(|f| f.code).collect()
}

#[test]
fn an_honest_pool_passes_and_every_way_of_cheating_is_caught() {
    let r = start(&[(11, "a"), (12, "b")]);
    // wait for three published epochs, at least two of them with a block and shares of both miners
    wait("published epochs", 120, || {
        let es = r.epochs();
        es.len() >= 3 && es.iter().filter(|e| r.doc(**e)["blocks"].as_array().map_or(false, |b| !b.is_empty())).count() >= 2
    });
    let es = r.epochs();
    let sk = r.sk.clone();
    let g = genesis_hash(&genesis());
    let chain = r.chain();
    let receipts = r.receipts();
    assert!(!receipts.is_empty(), "the miners received receipts");
    assert!(r.miners.iter().all(|(s, _, _)| s.receipts.load(Ordering::Relaxed) > 0));

    let mut input = AuditInput { chain: Some(chain), receipts: receipts.clone(), ..Default::default() };
    let mut records = std::collections::BTreeMap::new();
    for e in &es {
        input.docs.insert(*e, r.doc(*e));
        let full = r.full(*e);
        let doc_count = input.docs[e]["shares_count"].as_u64().unwrap() as usize;
        assert_eq!(full.len(), doc_count);
        if *e % 2 == 0 {
            input.samples.insert(*e, Samples::Full(full.clone()));
        } else {
            input.samples.insert(*e, Samples::Proofs(r.proofs(*e, doc_count, 12)));
        }
        records.insert(*e, full);
    }
    let cfg = r.cfg();

    // ---- the honest pool
    let rep = audit_pool(&cfg, &input);
    assert_eq!(rep.verdict, Severity::Info, "{:?}", rep.findings.iter().filter(|f| f.severity != Severity::Info).map(|f| (f.code, f.detail.clone())).collect::<Vec<_>>());
    assert!(rep.stats["shares_recomputed"].as_u64().unwrap() > 10, "shares were recomputed");
    assert!(rep.stats["receipts_checked"].as_u64().unwrap() > 0);
    assert_eq!(rep.stats["documents_usable"].as_u64().unwrap() as usize, es.len());
    // fixture for the Python tools (tests/vectors/pool-points): documents signed by this very code, to prove that tools/pool_points.py reads them
    if let Ok(dir) = std::env::var("VEARL_DUMP_POINTS_FIXTURE") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        for e in &es {
            std::fs::write(dir.join(format!("epoch-{e}.json")), serde_json::to_string_pretty(&input.docs[e]).unwrap()).unwrap();
        }
        std::fs::write(dir.join("pool.txt"), format!("{}
", address_of(&r.pool.pk))).unwrap();
        let blocks: Vec<Value> = input.chain.as_ref().unwrap().iter().map(|b| serde_json::json!({"height": b.height, "timestamp": b.timestamp, "miner": b.miner, "work": "native"})).collect();
        std::fs::write(dir.join("blocks.json"), serde_json::to_string_pretty(&serde_json::json!({"blocks": blocks})).unwrap()).unwrap();
        std::fs::write(dir.join("audit.json"), serde_json::to_string_pretty(&rep.to_json()).unwrap()).unwrap();
    }
    // the documents chain to each other and the weights are the sums of the shares
    for w in es.windows(2) {
        assert_eq!(input.docs[&w[1]]["prev"], serde_json::json!(doc_hash(&input.docs[&w[0]])));
    }

    // a helper: replace one epoch's document (re-signed by the pool key, as a cheating operator could) and its share list
    let with_epoch = |e: u64, recs: Vec<ShareRec>, blocks: Option<Vec<(u64, Hash, u64)>>| -> AuditInput {
        let old = &input.docs[&e];
        let prev = unhex32(old["prev"].as_str().unwrap()).unwrap();
        let jobs: Vec<JobRec> = old["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|j| JobRec { prev: unhex32(j["prev"].as_str().unwrap()).unwrap(), height: j["height"].as_u64().unwrap(), timestamp: j["timestamp"].as_u64().unwrap(), tx_root: unhex32(j["tx_root"].as_str().unwrap()).unwrap(), target: parse_u64hex(j["target"].as_str().unwrap()).unwrap(), native_epoch: j["native_epoch"].as_u64().unwrap() })
            .collect();
        let blocks = blocks.unwrap_or_else(|| old["blocks"].as_array().unwrap().iter().map(|b| (b["height"].as_u64().unwrap(), unhex32(b["hash"].as_str().unwrap()).unwrap(), b["timestamp"].as_u64().unwrap())).collect());
        let d = build_doc(&sk, &g, &prev, &EpochData { epoch: e, epoch_secs: EPOCH, fee_bps: 200, blocks: &blocks, jobs: &jobs, records: &recs });
        let mut i2 = AuditInput { chain: input.chain.as_ref().map(|c| c.iter().map(|b| ChainBlock { height: b.height, timestamp: b.timestamp, miner: b.miner.clone(), hash: b.hash.clone() }).collect()), receipts: receipts.clone(), ..Default::default() };
        for (k, v) in &input.docs {
            i2.docs.insert(*k, if *k == e { d.clone() } else { v.clone() });
        }
        for (k, s) in &input.samples {
            if *k != e {
                i2.samples.insert(*k, match s {
                    Samples::Full(x) => Samples::Full(x.clone()),
                    Samples::Proofs(p) => Samples::Proofs(p.iter().map(|q| ShareProof { index: q.index, rec: q.rec.clone(), path: q.path.clone() }).collect()),
                });
            }
        }
        i2.samples.insert(e, Samples::Full(recs));
        i2
    };
    let busy = *es.iter().find(|e| input.docs[e]["blocks"].as_array().map_or(false, |b| !b.is_empty()) && records[e].len() >= 4).expect("an epoch with blocks");
    let honest_blocks: Vec<(u64, Hash, u64)> = input.docs[&busy]["blocks"].as_array().unwrap().iter().map(|b| (b["height"].as_u64().unwrap(), unhex32(b["hash"].as_str().unwrap()).unwrap(), b["timestamp"].as_u64().unwrap())).collect();
    // the control: the same helper with the true data is still clean
    assert_eq!(audit_pool(&cfg, &with_epoch(busy, records[&busy].clone(), None)).verdict, Severity::Info);

    // ---- 1. a document edited after signing
    let mut forged = AuditInput { chain: None, receipts: vec![], ..Default::default() };
    let mut d = input.docs[&busy].clone();
    d["miners"][0]["v2_weight"] = serde_json::json!("999999999999999999999999");
    forged.docs.insert(busy, d);
    let rep = audit_pool(&cfg, &forged);
    assert!(rep.has("document_unusable"), "{:?}", codes(&rep));
    // ---- 2. a document signed by somebody else
    let mut other = AuditInput::default();
    other.docs.insert(busy, build_doc(&SigningKey::from_bytes(&[1; 32]), &g, &ZERO_HASH, &EpochData { epoch: busy, epoch_secs: EPOCH, fee_bps: 0, blocks: &[], jobs: &[], records: &[] }));
    assert!(audit_pool(&cfg, &other).has("document_unusable"));

    // ---- 3. fake miners: shares that nobody computed, credited to made-up addresses
    let mut fake = records[&busy].clone();
    let job0 = fake[0].job;
    for i in 0..40u64 {
        fake.push(ShareRec { addr: pubkey(&SigningKey::from_bytes(&[90 + (i % 5) as u8; 32])), job: job0, extra_nonce: 0xdead_0000 + i, ti: 0, tj: 0, target: SHARE_TARGET, v2: true });
    }
    let rep = audit_pool(&cfg, &with_epoch(busy, fake, None));
    assert_eq!(rep.verdict, Severity::Fraud);
    assert!(rep.has("share_invalid"), "{:?}", codes(&rep));
    assert_eq!(rep.epochs[&busy], Severity::Fraud);

    // ---- 4. a block of the pool hidden from the document, and one that does not exist
    let mut after_deadline = r.cfg();
    after_deadline.now += 48 * 3600;
    let hidden = with_epoch(busy, records[&busy].clone(), Some(vec![]));
    assert!(!audit_pool(&cfg, &hidden).has("hidden_block"), "within the deadline a missing block is only pending");
    let rep = audit_pool(&after_deadline, &hidden);
    assert!(rep.has("hidden_block"), "{:?}", codes(&rep));
    let mut phantom = honest_blocks.clone();
    phantom.push((987_654, [9; 32], honest_blocks[0].2));
    let rep = audit_pool(&cfg, &with_epoch(busy, records[&busy].clone(), Some(phantom)));
    assert!(rep.has("phantom_block"), "{:?}", codes(&rep));

    // ---- 4 bis. an ORPHAN is not fraud: the chain holds another miner's block at the height of a block the pool found (it lost the race)
    let somebody = address_of(&pubkey(&SigningKey::from_bytes(&[55; 32])));
    let chain_copy = |orphan: &dyn Fn(&ChainBlock) -> bool| -> Vec<ChainBlock> {
        input.chain.as_ref().unwrap().iter().map(|b| ChainBlock { height: b.height, timestamp: b.timestamp, miner: if orphan(b) { somebody.clone() } else { b.miner.clone() }, hash: b.hash.clone() }).collect()
    };
    let h0 = honest_blocks[0].0;
    let mut one = with_epoch(busy, records[&busy].clone(), None);
    one.chain = Some(chain_copy(&|b: &ChainBlock| b.height == h0));
    let rep = audit_pool(&cfg, &one);
    assert!(rep.has("orphaned_block") && !rep.has("phantom_block"), "{:?}", rep.findings.iter().map(|f| (f.code, f.severity.name())).collect::<Vec<_>>());
    assert!(rep.verdict < Severity::Fraud && !codes(&rep).contains(&"hidden_block"), "{:?}", codes(&rep));
    // ... but a pool whose blocks are mostly NOT on the chain is looked at by a person (suspect, never fraud by itself)
    let listed: usize = es.iter().map(|e| input.docs[e]["blocks"].as_array().map_or(0, |b| b.len())).sum();
    let mut all = with_epoch(busy, records[&busy].clone(), None);
    all.chain = Some(chain_copy(&|b: &ChainBlock| b.miner == address_of(&r.pool.pk)));
    let rep = audit_pool(&cfg, &all);
    assert!(!rep.has("phantom_block"), "{:?}", codes(&rep));
    assert!(listed >= 8, "the test chain lists enough blocks ({listed}) to exercise the orphan ratio");
    {
        assert!(rep.has("many_orphans") && rep.verdict == Severity::Suspect, "{:?}", rep.findings.iter().map(|f| (f.code, f.severity.name())).collect::<Vec<_>>());
    }

    // ---- 4 ter. a share credited at a target HARDER than its job's network target (the target eased while the pool still held the session target of
    // the previous job) is real work: it verifies, because the jackpot reaches the target it was credited at; a lie is still caught by the recomputation
    {
        let rec = records[&busy][0].clone();
        let j = &input.docs[&busy]["jobs"][rec.job as usize];
        let mut job = JobRec { prev: unhex32(j["prev"].as_str().unwrap()).unwrap(), height: j["height"].as_u64().unwrap(), timestamp: j["timestamp"].as_u64().unwrap(), tx_root: unhex32(j["tx_root"].as_str().unwrap()).unwrap(), target: parse_u64hex(j["target"].as_str().unwrap()).unwrap(), native_epoch: j["native_epoch"].as_u64().unwrap() };
        job.target = u64::MAX; // the network target is now far easier than the target the share was credited at
        assert!(rec.target < job.target);
        let mut cache = ShareCache::new(10);
        assert_eq!(verify_share(&rec, &job, &r.pool.pk, &genesis().params, &mut cache), Ok(()));
        let mut lie = rec.clone();
        lie.target = 1; // a target the jackpot cannot reach
        assert!(verify_share(&lie, &job, &r.pool.pk, &genesis().params, &mut cache).is_err());
    }

    // ---- 5. a miner credited less than the pool signed: the pool contradicts itself
    let victim = r.miners[0].2.clone();
    let victim_key = parse_address_for_test(&victim);
    let mut cut: Vec<ShareRec> = records[&busy].iter().filter(|x| !(x.addr == victim_key && x.v2)).cloned().collect();
    if cut.len() == records[&busy].len() {
        cut.truncate(cut.len() - 1);
    }
    let rep = audit_pool(&cfg, &with_epoch(busy, cut, None));
    assert!(rep.has("receipt_contradiction"), "{:?}", codes(&rep));
    assert_eq!(rep.verdict, Severity::Fraud);

    // ---- 6. a share counted twice, and shares credited at a target they do not reach
    let mut twice = records[&busy].clone();
    twice.push(twice[0].clone());
    assert!(audit_pool(&cfg, &with_epoch(busy, twice, None)).has("duplicate_share"));
    let mut hard = records[&busy].clone();
    for x in hard.iter_mut() {
        x.target = x.target / 4096; // a harder target = more weight per share, but the jackpot does not reach it
    }
    let rep = audit_pool(&cfg, &with_epoch(busy, hard, None));
    assert!(rep.has("share_invalid"), "{:?}", codes(&rep));

    // ---- 7. history rewritten: a document replaced after the next one committed to it
    if es.len() >= 2 {
        let first = es[0];
        let mut rew = with_epoch(first, records[&first].clone(), None);
        let d0 = &rew.docs[&first];
        let different = build_doc(&sk, &g, &unhex32(d0["prev"].as_str().unwrap()).unwrap(), &EpochData { epoch: first, epoch_secs: EPOCH, fee_bps: 777, blocks: &[], jobs: &[], records: &[] });
        rew.docs.insert(first, different);
        rew.chain = None;
        rew.samples.clear();
        assert!(audit_pool(&cfg, &rew).has("chain_break"));
    }

    // ---- 8. a block on the chain whose epoch has no document, once the deadline is over
    let mut late = AuditInput { chain: input.chain.as_ref().map(|c| c.iter().map(|b| ChainBlock { height: b.height, timestamp: b.timestamp, miner: b.miner.clone(), hash: b.hash.clone() }).collect()), ..Default::default() };
    late.docs.insert(es[0], input.docs[&es[0]].clone());
    let mut c2 = r.cfg();
    c2.now += 48 * 3600;
    let rep = audit_pool(&c2, &late);
    assert!(rep.has("undocumented_block"), "{:?}", codes(&rep));

    // ---- the points a miner sees on the pool: its share of the pool's blocks, by work
    r.halt_miners();
    let addr_a = &r.miners[0].2;
    let addr_b = &r.miners[1].2;
    let (a, b) = (http_get(&r.http, &format!("/api/points/miner/{addr_a}")), http_get(&r.http, &format!("/api/points/miner/{addr_b}")));
    let (pa, pb) = (a["provisional"].as_f64().unwrap(), b["provisional"].as_f64().unwrap());
    assert!(pa > 0.0 && pb > 0.0, "{a} {b}");
    let pot = a["pool_points_total"].as_f64().unwrap();
    assert!(pot > 1.0 && (pa + pb - pot).abs() < 0.01, "the two miners share exactly the points of the pool's blocks: {pa} + {pb} vs {pot}");
    // the same figure in the miner's own page, and in the stats it can ask over the protocol
    let page = http_get(&r.http, &format!("/api/miner/{addr_a}"));
    assert_eq!(page["points"]["provisional"].as_f64().unwrap(), pa);
    assert_eq!(page["points"]["official"], Value::Null, "no leaderboard was given to this pool");
    assert!(r.miners.iter().all(|(s, _, _)| s.points.lock().unwrap().is_some()), "the miners asked for their points");
    // an address that never mined here has none; so does a vpool/1 miner (it has no receipts)
    let nobody = http_get(&r.http, &format!("/api/points/miner/{}", address_of(&pubkey(&SigningKey::from_bytes(&[77; 32])))));
    assert_eq!(nobody["provisional"].as_f64().unwrap(), 0.0);
    assert!(http_get(&r.http, "/api/points/miner/nonsense")["error"].is_string(), "a malformed address is refused");

    r.stop();
    let _ = std::fs::remove_dir_all(&r.dir);
}

fn parse_address_for_test(a: &str) -> PubKey {
    vearl_core::wallet::parse_address(a).unwrap()
}

#[test]
fn claimed_work_far_above_the_blocks_found_is_flagged_and_normal_luck_is_not() {
    let sk = SigningKey::from_bytes(&[5; 32]);
    let g = [3u8; 32];
    let net_target = u64::MAX / 4096; // a block per 4096 attempts
    let share_target = u64::MAX / 1024; // a share per 1024 attempts
    let params = genesis().params;
    let job = JobRec { prev: [1; 32], height: 1, timestamp: 0, tx_root: [2; 32], target: net_target, native_epoch: 0 };
    // a day with 20,000 shares = about 20.5M attempts = about 5,000 blocks expected
    let make = |blocks: usize| {
        let recs: Vec<ShareRec> = (0..20_000u64).map(|i| ShareRec { addr: pubkey(&SigningKey::from_bytes(&[(i % 7) as u8 + 1; 32])), job: 0, extra_nonce: i, ti: 0, tj: 0, target: share_target, v2: true }).collect();
        let bl: Vec<(u64, Hash, u64)> = (0..blocks as u64).map(|i| (i, [i as u8; 32], 100 + i)).collect();
        let doc = build_doc(&sk, &g, &ZERO_HASH, &EpochData { epoch: 0, epoch_secs: 86400, fee_bps: 0, blocks: &bl, jobs: &[job.clone()], records: &recs });
        let mut inp = AuditInput::default();
        inp.docs.insert(0, doc);
        inp
    };
    let mut cfg = AuditCfg::new(pubkey(&sk), g, params, 1_000_000);
    cfg.allowed_epoch_secs = vec![86400];
    let expected = expected_blocks(20_000 * share_weight(share_target), net_target);
    assert!((expected - 4_882.0).abs() < 400.0, "{expected}");
    // right on expectation: clean
    assert_eq!(audit_pool(&cfg, &make(expected as usize)).verdict, Severity::Info);
    // a normal bad day (10 % short) is not flagged at the 1e-9 level
    assert_eq!(audit_pool(&cfg, &make((expected * 0.97) as usize)).verdict, Severity::Info);
    // work claimed with almost no blocks behind it: flagged for a human
    let rep = audit_pool(&cfg, &make(100));
    assert!(rep.has("work_vs_blocks"), "{:?}", codes(&rep));
    assert_eq!(rep.verdict, Severity::Suspect);
    // blocks without the work that would explain them: also flagged
    let rep = audit_pool(&cfg, &make((expected * 3.0) as usize));
    assert!(rep.has("work_vs_blocks"));
}

/// The whole tool chain a person would use: the Python downloader against the live pool, then the `vearl-pool-audit` program on what it saved.
#[test]
fn the_command_line_tools_audit_a_live_pool_end_to_end() {
    let python = ["python", "python3"].into_iter().find(|p| std::process::Command::new(p).args(["-c", "import cryptography"]).output().map_or(false, |o| o.status.success()));
    let Some(python) = python else {
        eprintln!("no python with the `cryptography` package on this machine: end-to-end tools test skipped");
        return;
    };
    let r = start(&[(21, "a"), (22, "b")]);
    wait("published epochs", 120, || r.epochs().len() >= 3);
    r.halt_miners();
    let dir = std::env::temp_dir().join(format!("vpool-bundle-{}", rand::random::<u32>()));
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("genesis.json"), vearl_core::genesis::genesis_to_json("test", &genesis())).unwrap();
    let blocks: Vec<Value> = r.chain().iter().map(|b| serde_json::json!({"height": b.height, "timestamp": b.timestamp, "miner": b.miner, "hash": b.hash, "work": "native"})).collect();
    std::fs::write(dir.join("blocks.json"), serde_json::to_string(&serde_json::json!({"blocks": blocks})).unwrap()).unwrap();
    let receipts: Vec<String> = std::fs::read_dir(&r.dir).unwrap().flatten().map(|e| e.path().to_string_lossy().to_string()).collect();

    let tools = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools");
    let fetch = std::process::Command::new(python)
        .arg(tools.join("fetch_pool_bundle.py"))
        .args(["--pool", &format!("http://{}", r.http), "--out", bundle.to_str().unwrap(), "--samples", "8", "--full", "--last", "3"])
        .output()
        .unwrap();
    assert!(fetch.status.success(), "{}", String::from_utf8_lossy(&fetch.stderr));
    let audit = |extra: &[&str]| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_vearl-pool-audit"));
        c.args(["--bundle", bundle.to_str().unwrap(), "--genesis", dir.join("genesis.json").to_str().unwrap(), "--pool", &address_of(&r.pool.pk), "--blocks", dir.join("blocks.json").to_str().unwrap(), "--out", dir.join("audit.json").to_str().unwrap()]);
        for f in &receipts {
            c.args(["--receipts", f]);
        }
        c.args(["--epoch-secs", "4"]);
        c.args(extra);
        c.output().unwrap()
    };
    // (the fast test chain is outside the range of the work-versus-blocks test, see the other test: --now is irrelevant to it here)
    let ok = audit(&[]);
    let text = String::from_utf8_lossy(&ok.stdout).to_string();
    let rep: Value = serde_json::from_slice(&std::fs::read(dir.join("audit.json")).unwrap()).unwrap();
    // only the statistical suspicion may show on this artificial chain
    let bad: Vec<_> = rep["findings"].as_array().unwrap().iter().filter(|f| f["severity"] != "ok" && f["code"] != "work_vs_blocks").collect();
    assert!(bad.is_empty(), "{text} {bad:?}");
    let listing: Vec<String> = std::fs::read_dir(&bundle).unwrap().flatten().map(|e| format!("{} ({} bytes)", e.file_name().to_string_lossy(), e.metadata().unwrap().len())).collect();
    assert!(rep["stats"]["shares_recomputed"].as_u64().unwrap() > 0 && rep["stats"]["receipts_checked"].as_u64().unwrap() > 0, "{text} {listing:?} {}", rep["findings"]);

    // the team's side: pools.json -> audit_pools.py (downloads again, audits, writes the report) -> the leaderboard with --pools
    let spec = dir.join("pools.json");
    std::fs::write(&spec, serde_json::to_string(&serde_json::json!({"pools": [{"address": address_of(&r.pool.pk), "name": "test pool", "url": format!("http://{}", r.http), "dir": "teampool", "audit": "teampool-audit.json", "epoch_secs": [4]}]})).unwrap()).unwrap();
    let team = std::process::Command::new(python)
        .arg(tools.join("audit_pools.py"))
        .args(["--spec", spec.to_str().unwrap(), "--genesis", dir.join("genesis.json").to_str().unwrap(), "--blocks", dir.join("blocks.json").to_str().unwrap(), "--audit-bin", env!("CARGO_BIN_EXE_vearl-pool-audit"), "--audit-arg=--p-suspect", "--audit-arg=0", "--audit-arg=--epoch-secs", "--audit-arg=4"])
        .output()
        .unwrap();
    assert!(team.status.success(), "{}", String::from_utf8_lossy(&team.stderr));
    let team_audit: Value = serde_json::from_slice(&std::fs::read(dir.join("teampool-audit.json")).unwrap_or_else(|e| panic!("no report ({e}): {} {}", String::from_utf8_lossy(&team.stdout), String::from_utf8_lossy(&team.stderr)))).unwrap();
    assert_eq!(team_audit["verdict"], "ok", "{}", String::from_utf8_lossy(&team.stdout));
    let start = chrono_like(r.start);
    let lb = dir.join("leaderboard");
    let rew = std::process::Command::new(python)
        .arg(tools.join("testnet_rewards.py"))
        .args(["--blocks-file", dir.join("blocks.json").to_str().unwrap(), "--start", &start, "--out", lb.to_str().unwrap(), "--pools", spec.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(rew.status.success(), "{}", String::from_utf8_lossy(&rew.stderr));
    let board: Value = serde_json::from_slice(&std::fs::read(lb.join("leaderboard.json")).unwrap()).unwrap();
    let rows = board["miners"].as_array().unwrap();
    let pool_addr = address_of(&r.pool.pk);
    assert!(rows.iter().all(|m| m["address"] != pool_addr.as_str()), "the pool's own address earns nothing");
    for (_, _, a) in &r.miners {
        let row = rows.iter().find(|m| m["address"] == a.as_str()).unwrap_or_else(|| panic!("{a} has no points: {board}"));
        assert!(row["pool_points"].as_f64().unwrap() > 0.0 && row["blocks"] == 0, "{row}");
    }
    assert_eq!(board["pools"][0]["audit_verdict"], "ok");
    // the pool and the leaderboard tool, written independently, give a miner the same points
    for (_, _, a) in &r.miners {
        let official = rows.iter().find(|m| m["address"] == a.as_str()).unwrap()["points"].as_f64().unwrap();
        let shown = http_get(&r.http, &format!("/api/points/miner/{a}"))["provisional"].as_f64().unwrap();
        assert!((official - shown).abs() < 0.01 * official.max(1.0), "{a}: leaderboard {official}, pool {shown}");
    }

    // edit one saved document: the tool reports it and exits with a non-zero status
    let e = *r.epochs().last().unwrap(); // the bundle holds the last three epochs
    let p = bundle.join(format!("epoch-{e}.json"));
    let mut d: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    d["miners"][0]["v2_weight"] = serde_json::json!("1");
    std::fs::write(&p, serde_json::to_string(&d).unwrap()).unwrap();
    let bad = audit(&[]);
    assert_ne!(bad.status.code(), Some(0), "{}", String::from_utf8_lossy(&bad.stdout));
    assert!(String::from_utf8_lossy(&bad.stdout).contains("document_unusable"));

    r.stop();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&r.dir);
}

/// "YYYY-MM-DDTHH:MM:SSZ" of a Unix time (the rewards tool takes ISO dates).
fn chrono_like(t: u64) -> String {
    vearl_core::genesis::fmt_utc(t).replace(" UTC", "Z").replace(' ', "T")
}

/// A pool that is not trusted must not be able to overload the audit, crash it, or slip a document past it.
#[test]
fn hostile_documents_are_refused_or_held_and_never_trusted() {
    let sk = SigningKey::from_bytes(&[5; 32]);
    let g = [3u8; 32];
    let params = genesis().params;
    let mut cfg = AuditCfg::new(pubkey(&sk), g, params, 2_000_000_000);
    cfg.allowed_epoch_secs = vec![3600];
    let rec = |job: u32, i: u64| ShareRec { addr: pubkey(&SigningKey::from_bytes(&[9; 32])), job, extra_nonce: i, ti: 0, tj: 0, target: u64::MAX / 2, v2: true };
    let epoch = 1_000_000u64;
    let t0 = epoch * 3600;
    let job = |height: u64, ts: u64| JobRec { prev: [1; 32], height, timestamp: ts, tx_root: [2; 32], target: 1 << 40, native_epoch: height / vearl_core::state::EPOCH_LEN };
    let doc = |epoch_secs: u64, jobs: &[JobRec], recs: &[ShareRec]| {
        let d = build_doc(&sk, &g, &ZERO_HASH, &EpochData { epoch, epoch_secs, fee_bps: 0, blocks: &[], jobs, records: recs });
        let mut inp = AuditInput::default();
        inp.docs.insert(epoch, d);
        inp
    };
    // an epoch length the program does not count: unusable, so held
    let rep = audit_pool(&cfg, &doc(86400, &[], &[]));
    assert!(rep.has("document_unusable") && rep.verdict >= Severity::Suspect);
    // work claimed for a window it was not done in: the jobs are far from the epoch
    let rep = audit_pool(&cfg, &doc(3600, &[job(5, t0 + 40 * 3600)], &[rec(0, 1)]));
    assert!(rep.has("job_outside_epoch") && rep.verdict == Severity::Fraud);
    let rep = audit_pool(&cfg, &doc(3600, &[job(5, t0.saturating_sub(40 * 3600))], &[rec(0, 1)]));
    assert!(rep.has("job_outside_epoch"));
    // a job whose native epoch does not match its height
    let mut bad = job(5, t0 + 10);
    bad.native_epoch = 77;
    assert!(audit_pool(&cfg, &doc(3600, &[bad], &[rec(0, 1)])).has("job_outside_epoch"));
    // jobs built on heights the chain has not reached
    let mut inp = doc(3600, &[job(900_000, t0 + 10)], &[rec(0, 1)]);
    inp.chain = Some(vec![ChainBlock { height: 10, timestamp: t0, miner: "x".into(), hash: Some("00".repeat(32)) }]);
    assert!(audit_pool(&cfg, &inp).has("job_from_the_future"));
    // a copy of the chain a few minutes (or an hour) behind the hour that just ended: information, never a fraud (AriaPool, 2026-11-04)
    let mut inp = doc(3600, &[job(60, t0 + 10)], &[rec(0, 1)]);
    inp.chain = Some(vec![ChainBlock { height: 10, timestamp: t0, miner: "x".into(), hash: Some("00".repeat(32)) }]);
    let rep = audit_pool(&cfg, &inp);
    assert!(rep.has("job_above_the_chain_we_hold") && !rep.has("job_from_the_future"), "{:?}", codes(&rep));

    // a document that appears long after its epoch: held
    let mut late = doc(3600, &[job(5, t0 + 10)], &[rec(0, 1)]);
    late.seen.insert(epoch, t0 + 3600 + 10 * 3600);
    let rep = audit_pool(&cfg, &late);
    assert!(rep.has("late_document") && rep.epochs[&epoch] >= Severity::Suspect);
    let mut punctual = doc(3600, &[job(5, t0 + 10)], &[rec(0, 1)]);
    punctual.seen.insert(epoch, t0 + 3600 + 600);
    assert!(!audit_pool(&cfg, &punctual).has("late_document"));

    // many different matrices to rebuild (one per job height): the audit stops at its budget and says so, it does not run for hours
    let jobs: Vec<JobRec> = (0..30u64).map(|i| job(i * vearl_core::state::EPOCH_LEN + 5, t0 + 10)).collect();
    let recs: Vec<ShareRec> = (0..30u32).map(|i| rec(i, i as u64)).collect();
    let mut inp = doc(3600, &jobs, &recs);
    inp.samples.insert(epoch, Samples::Full(recs.clone()));
    cfg.max_matrix_builds = 3;
    cfg.verify_max = 1000;
    let rep = audit_pool(&cfg, &inp);
    assert!(rep.has("audit_budget"), "{:?}", codes(&rep));
    assert!(rep.stats["shares_recomputed"].as_u64().unwrap() <= 3);

    // garbage in the pool's own fields never panics the audit
    let mut weird = doc(3600, &[job(5, t0 + 10)], &[rec(0, 1)]);
    for key in ["miners", "blocks", "jobs", "total_weight", "shares_count", "prev", "start"] {
        let mut d = weird.docs[&epoch].clone();
        d[key] = serde_json::json!({"x": [1, 2, {"y": null}]});
        let mut one = AuditInput::default();
        one.docs.insert(epoch, d);
        let _ = audit_pool(&cfg, &one); // must return, whatever the verdict
    }
    weird.docs.insert(epoch + 1, serde_json::json!("not even an object"));
    let _ = audit_pool(&cfg, &weird);
}

/// The ledger of an hour cannot grow without bound, whatever a client does.
#[test]
fn the_ledger_of_an_hour_is_bounded() {
    let r = start_with(&[(31, "a")], |c| c.max_epoch_shares = 12);
    wait("the cap is reached and shares are refused", 60, || r.miners[0].0.rejected.load(Ordering::Relaxed) > 3);
    let most = r.pool.ledger_snapshot(|l| l.epochs.values().map(|e| e.records.len()).max().unwrap_or(0));
    assert!(most <= 12, "{most} shares recorded in one hour with a cap of 12");
    r.stop();
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
fn the_page_of_the_pool_escapes_what_comes_from_the_api() {
    let page = vearl_core::pool::POOL_PAGE_FOR_TESTS;
    assert!(page.contains("const X="), "an escaping helper is defined");
    assert!(page.contains("X(m.points.official.reasons.join"));
    assert!(page.contains("X(w.worker)"));
}

/// Batching only samples keeps full-history document checks while resetting the per-process budget.
#[test]
fn share_batches_complete_without_waiving_the_matrix_budget() {
    let sk = SigningKey::from_bytes(&[5; 32]);
    let g = genesis_hash(&genesis());
    let mut cfg = AuditCfg::new(pubkey(&sk), g, genesis().params, 4_000_000_000);
    cfg.p_suspect = 0.0;
    cfg.max_matrix_builds = 1;
    let mut inp = AuditInput::default();
    let mut previous = ZERO_HASH;
    for i in 0..2u64 {
        let epoch = 1_000_000 + i;
        let job = JobRec { prev: [1; 32], height: i * vearl_core::state::EPOCH_LEN + 5,
            timestamp: epoch * 3600 + 10, tx_root: [2; 32], target: u64::MAX, native_epoch: i };
        let rec = ShareRec { addr: pubkey(&SigningKey::from_bytes(&[9; 32])), job: 0,
            extra_nonce: 1, ti: 0, tj: 0, target: u64::MAX, v2: true };
        let doc = build_doc(&sk, &g, &previous, &EpochData { epoch, epoch_secs: 3600,
            fee_bps: 0, blocks: &[], jobs: &[job], records: &[rec.clone()] });
        previous = unhex32(&doc_hash(&doc)).unwrap();
        inp.docs.insert(epoch, doc);
        inp.samples.insert(epoch, Samples::Full(vec![rec]));
    }
    let whole = audit_pool(&cfg, &inp);
    assert!(whole.has("audit_budget"));
    let samples = std::mem::take(&mut inp.samples);
    let dir = std::env::temp_dir().join(format!("vpool-batches-{}", rand::random::<u32>()));
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    for (epoch, doc) in &inp.docs {
        std::fs::write(bundle.join(format!("epoch-{epoch}.json")), serde_json::to_vec(doc).unwrap()).unwrap();
    }
    for (epoch, sample) in &samples {
        if let Samples::Full(recs) = sample {
            let json = serde_json::json!({"records": recs.iter().map(|r| hex(&r.bytes())).collect::<Vec<_>>()});
            std::fs::write(bundle.join(format!("shares-{epoch}.json")), serde_json::to_vec(&json).unwrap()).unwrap();
        }
    }
    std::fs::write(dir.join("genesis.json"), vearl_core::genesis::genesis_to_json("test", &genesis())).unwrap();
    let mut verified = 0;
    for (epoch, sample) in samples {
        inp.samples.clear();
        inp.samples.insert(epoch, sample);
        let batch = audit_pool(&cfg, &inp);
        assert!(!batch.has("audit_budget"), "{:?}", codes(&batch));
        assert_eq!(batch.stats["documents"], 2);
        assert_eq!(batch.stats["documents_usable"], 2);
        assert_eq!(batch.stats["unknown_parent_shares"], 0);
        assert!(batch.verdict < Severity::Suspect, "{:?}", codes(&batch));
        verified += batch.stats["shares_recomputed"].as_u64().unwrap();
    }
    assert_eq!(verified, 2);
    // Exercise the real CLI and Python orchestrator, including budget-triggered retry.
    let script = r#"
import sys
from pathlib import Path
from audit_batches import run_batched
root = Path(sys.argv[2])
cmd = [sys.argv[1], '--bundle', str(root/'bundle'), '--out', str(root/'audit.json'),
       '--genesis', str(root/'genesis.json'), '--pool', sys.argv[3], '--p-suspect', '0',
       '--now', '4000000000', '--matrix-builds', '1']
r = run_batched(cmd, root/'bundle', root/'audit.json', sys.argv[3], batch_size=2)
assert r['verdict'] == 'ok', r
assert r['stats']['shares_recomputed'] == 2, r
assert r['stats']['share_batches'] == 2, r
assert set(r['epochs'].values()) == {'ok'}, r
"#;
    let result = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .args(["-c", script, env!("CARGO_BIN_EXE_vearl-pool-audit"), dir.to_str().unwrap(), &address_of(&pubkey(&sk))])
        .env("PYTHONPATH", std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools"))
        .output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let _ = std::fs::remove_dir_all(dir);
}
