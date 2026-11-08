//! vearl-pool-audit: checks what a mining pool published, against the chain and against the receipts its miners hold (docs/16 section 13).
//!
//! vearl-pool-audit --bundle DIR --genesis genesis.json --pool vrl1... [--blocks blocks.json] [--receipts FILE]... [--out audit.json]
//!                  [--now UNIX] [--deadline-hours 24] [--verify-max 64] [--p-suspect 1e-9] [--epoch-secs 3600]... [--matrix-builds 400]
//!
//! DIR is made by `tools/fetch_pool_bundle.py` (the epoch documents, and the shares drawn after the documents were published):
//!   epoch-<E>.json   signed document of an epoch
//!   shares-<E>.json  {"records": [hex, ...]}                         the complete list of the shares of the epoch, or
//!   proofs-<E>.json  {"proofs": [{"index", "record", "path"}, ...]}  shares drawn at random, with their Merkle paths
//! Exit status: 0 = nothing wrong found, 1 = suspect (a human must look), 2 = fraud proven by the pool's own signatures, the chain or the work.
use std::collections::BTreeMap;
use vearl_core::crypto::Hash;
use vearl_core::genesis::parse_genesis;
use vearl_core::net::genesis_hash;
use vearl_core::pool::unhex32;
use vearl_core::poolpoints::*;
use vearl_core::wallet::parse_address;

fn die(m: &str) -> ! {
    eprintln!("error: {m}");
    std::process::exit(3)
}

const HELP: &str = r#"vearl-pool-audit: checks what a Vearl mining pool published (protocol vpool/2).

  vearl-pool-audit --bundle DIR --genesis genesis.json --pool vrl1... [--blocks blocks.json] [--receipts FILE]... [--out audit.json]

Checks the signatures and the chaining of the pool's hourly documents, that the blocks they list are exactly the pool's blocks on the chain,
the shares drawn from the pool (Merkle path and recomputed work), your receipts (the pool must not credit you less than it signed) and that the
work claimed is consistent with the blocks found. Exit status 0 = nothing wrong, 1 = suspect, 2 = fraud. Details: docs/16 section 13."#;

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
}

/// Largest file the audit reads: the data comes from a pool that is not trusted (a complete share list is about 60 bytes a share).
const MAX_FILE: u64 = 512 << 20;

fn read_json(path: &std::path::Path) -> Option<serde_json::Value> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn main() {
    vearl_core::launcher::help_or_continue(HELP);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let all = |name: &str| -> Vec<String> { args.iter().enumerate().filter(|(_, a)| *a == name).filter_map(|(i, _)| args.get(i + 1).cloned()).collect() };
    for a in &args {
        if a.starts_with("--") && !["--bundle", "--genesis", "--pool", "--blocks", "--receipts", "--out", "--now", "--deadline-hours", "--verify-max", "--p-suspect", "--epoch-secs", "--max-lag-hours", "--matrix-builds"].contains(&a.as_str()) {
            die(&format!("unknown option: {a}"));
        }
    }
    let bundle = std::path::PathBuf::from(arg("--bundle").unwrap_or_else(|| die("--bundle DIR required")));
    let gpath = arg("--genesis").unwrap_or_else(|| die("--genesis FILE required"));
    let pool_addr = arg("--pool").unwrap_or_else(|| die("--pool vrl1... required"));
    let pool_key = parse_address(&pool_addr).unwrap_or_else(|e| die(&format!("--pool: {e}")));
    let (_, g) = parse_genesis(&std::fs::read_to_string(&gpath).unwrap_or_else(|e| die(&format!("{gpath}: {e}")))).unwrap_or_else(|e| die(&e));
    let genesis: Hash = genesis_hash(&g);

    let now = arg("--now").map_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), |v| v.parse().unwrap_or_else(|_| die("--now: integer")));
    let mut cfg = AuditCfg::new(pool_key, genesis, g.params, now);
    if let Some(h) = arg("--deadline-hours") {
        cfg.publish_deadline = (h.parse::<f64>().unwrap_or_else(|_| die("--deadline-hours: number")) * 3600.0) as u64;
    }
    if let Some(v) = arg("--verify-max") {
        cfg.verify_max = v.parse().unwrap_or_else(|_| die("--verify-max: integer"));
    }
    if let Some(value) = arg("--matrix-builds") {
        let limit: usize = value.parse().unwrap_or_else(|_| die("--matrix-builds: integer"));
        if limit == 0 || limit > cfg.max_matrix_builds {
            die("--matrix-builds: between 1 and the default budget (400)");
        }
        cfg.max_matrix_builds = limit;
    }
    let lens = all("--epoch-secs");
    if !lens.is_empty() {
        cfg.allowed_epoch_secs = lens.iter().map(|v| v.parse().unwrap_or_else(|_| die("--epoch-secs: integer"))).collect();
    }
    if let Some(h) = arg("--max-lag-hours") {
        cfg.max_publish_lag = (h.parse::<f64>().unwrap_or_else(|_| die("--max-lag-hours: number")) * 3600.0) as u64;
    }
    if let Some(v) = arg("--p-suspect") {
        cfg.p_suspect = v.parse().unwrap_or_else(|_| die("--p-suspect: number (0 turns the work-versus-blocks test off)"));
    }

    let mut inp = AuditInput::default();
    let rd = std::fs::read_dir(&bundle).unwrap_or_else(|e| die(&format!("{}: {e}", bundle.display())));
    for f in rd.flatten() {
        let name = f.file_name().to_string_lossy().to_string();
        let epoch = |prefix: &str| name.strip_prefix(prefix).and_then(|x| x.strip_suffix(".json")).and_then(|x| x.parse::<u64>().ok());
        if let Some(e) = epoch("epoch-") {
            match read_json(&f.path()) {
                Some(v) => {
                    inp.docs.insert(e, v);
                }
                None => eprintln!("warning: {name} is not valid JSON, ignored"),
            }
        } else if let Some(e) = epoch("shares-") {
            let v = read_json(&f.path()).unwrap_or_else(|| die(&format!("{name}: not valid JSON")));
            let recs: Option<Vec<ShareRec>> = v["records"].as_array().map(|a| a.iter().map(|x| x.as_str().and_then(from_hex).and_then(|b| ShareRec::from_bytes(&b))).collect()).and_then(|x: Vec<Option<ShareRec>>| x.into_iter().collect());
            match recs {
                Some(r) => {
                    inp.samples.insert(e, Samples::Full(r));
                }
                None => die(&format!("{name}: unreadable share records")),
            }
        } else if let Some(e) = epoch("proofs-") {
            let v = read_json(&f.path()).unwrap_or_else(|| die(&format!("{name}: not valid JSON")));
            let mut ps = vec![];
            for p in v["proofs"].as_array().unwrap_or(&vec![]) {
                let rec = p["record"].as_str().and_then(from_hex).and_then(|b| ShareRec::from_bytes(&b));
                let path: Option<Vec<Hash>> = p["path"].as_array().map(|a| a.iter().map(|x| x.as_str().and_then(unhex32)).collect()).and_then(|x: Vec<Option<Hash>>| x.into_iter().collect());
                match (p["index"].as_u64(), rec, path) {
                    (Some(index), Some(rec), Some(path)) => ps.push(ShareProof { index, rec, path }),
                    _ => die(&format!("{name}: unreadable proof")),
                }
            }
            inp.samples.insert(e, Samples::Proofs(ps));
        }
    }
    if let Some(bp) = arg("--blocks") {
        let v = read_json(std::path::Path::new(&bp)).unwrap_or_else(|| die(&format!("{bp}: unreadable")));
        let list = v.get("blocks").cloned().unwrap_or(v);
        let mut chain = vec![];
        for b in list.as_array().unwrap_or_else(|| die("--blocks: a list of blocks expected")) {
            if let (Some(height), Some(timestamp), Some(miner)) = (b["height"].as_u64(), b["timestamp"].as_u64(), b["miner"].as_str()) {
                chain.push(ChainBlock { height, timestamp, miner: miner.to_string(), hash: b["hash"].as_str().map(|s| s.to_string()) });
            }
        }
        inp.chain = Some(chain);
    }
    // when each document was first held (written by fetch_pool_bundle.py)
    if let Some(v) = read_json(&bundle.join("seen.json")) {
        if let Some(o) = v.as_object() {
            for (k, t) in o {
                if let (Ok(e), Some(t)) = (k.parse::<u64>(), t.as_u64()) {
                    inp.seen.insert(e, t);
                }
            }
        }
    }
    for rf in all("--receipts") {
        let txt = std::fs::read_to_string(&rf).unwrap_or_else(|e| die(&format!("{rf}: {e}")));
        for line in txt.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(v) = serde_json::from_str(line) {
                inp.receipts.push(v);
            }
        }
    }

    // The data comes from a pool that is not trusted. A document built to crash the audit must not be a way to escape it: a crash is reported as
    // a suspicion (exit status 1), never as "nothing found".
    let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| audit_pool(&cfg, &inp))).unwrap_or_else(|_| AuditReport {
        pool: pool_addr.clone(),
        verdict: Severity::Suspect,
        epochs: inp.docs.keys().map(|e| (*e, Severity::Suspect)).collect(),
        findings: vec![Finding { epoch: None, severity: Severity::Suspect, code: "audit_crashed", detail: "the audit failed on this data; a person must look at the pool's documents".into() }],
        stats: serde_json::json!({}),
    });
    let json = report.to_json();
    if let Some(out) = arg("--out") {
        std::fs::write(&out, serde_json::to_string_pretty(&json).unwrap()).unwrap_or_else(|e| die(&format!("{out}: {e}")));
    }
    println!("pool {}: {}", report.pool, report.verdict.name().to_uppercase());
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &report.findings {
        *by.entry(f.code).or_default() += 1;
    }
    println!("{} document(s), {} usable, {} share(s) recomputed, {} receipt(s) checked", report.stats["documents"], report.stats["documents_usable"], report.stats["shares_recomputed"], report.stats["receipts_checked"]);
    for f in report.findings.iter().filter(|f| f.severity != Severity::Info) {
        println!("  [{}] {}: {}", f.severity.name(), f.code, f.detail);
    }
    std::process::exit(match report.verdict {
        Severity::Info => 0,
        Severity::Suspect => 1,
        Severity::Fraud => 2,
    });
}
