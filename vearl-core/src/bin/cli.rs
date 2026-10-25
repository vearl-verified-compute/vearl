//! Keys are written `wallet:FILE` (encrypted wallet; password: VEARL_WALLET_PASSWORD[_FILE] or masked prompt)
//! or `seed:N` (PUBLIC seed, devnet only); accounts can also be written `vrl1...`.
//! vearl-cli address (seed:N | HEX64 | vrl1... | wallet:FILE)   (the vrl1... address of a key, without contacting a node)
//! vearl-cli status NODE
//! vearl-cli balance NODE (seed:N | HEX64)
//! vearl-cli transfer NODE seed:FROM (seed:TO | HEX64) AMOUNT_NXS [FEE_NXS]
//! vearl-cli job-submit NODE WORKER seed:CLIENT ESCROW_NXS DATA_SEED   (matrices A,B derived from DATA_SEED)
//! (job-submit accepts a 7th argument AUCTION_SECS: reverse auction, the workers propose their price)
//! vearl-cli job-audit NODE seed:CLIENT JOBID_HEX DATA_SEED K   (demands K entries ON-CHAIN, verifies them, proves fraud if needed)
//! vearl-cli reputation NODE (seed:N | HEX64)
//! vearl-cli job-status NODE JOBID_HEX
//! vearl-cli job-finish NODE WORKER seed:CLIENT JOBID_HEX DATA_SEED    (verifies the result: Accept or Fraud)
//! vearl-cli tiled-submit NODE WORKER KEY ESCROW_PER_PRODUCT BI BK BJ DATA_SEED   (block product A*B, rectangular shapes)
//! vearl-cli tiled-run NODE WORKER KEY ESCROW_PER_PRODUCT A.i8 B.i8 BI BK BJ C.i32   (LARGE matrices end to end: row-wise deposit, verification of each product, Accept, C written)
//! vearl-cli tiled-status NODE JOBID_HEX
//! vearl-cli tiled-finish NODE WORKER KEY JOBID_HEX BI BK BJ DATA_SEED   (verifies each product and each sum: Accept or Fraud)
//! vearl-cli prog-submit NODE WORKER KEY ESCROW_PER_GEMM DATA_SEED [cnn|transformer]   (CNN with a residual block, or transformer encoder block)
//! vearl-cli prog-status NODE JOBID_HEX
//! vearl-cli prog-finish NODE WORKER KEY JOBID_HEX DATA_SEED [cnn|transformer]   (verifies each operation: Accept or fraud proof)
//! vearl-cli infer NODE WORKER[,WORKER...] KEY ESCROW_PER_GEMM MODEL.json FIRST LAST OUTPUT.i8 [IN_FLIGHT=4]   (BATCH inference / embeddings: one job per sample of the model,
//!     weights sent ONCE to the worker registry, each job verified operation by operation before payment; int8 output [samples, classes])
//! vearl-cli l2-submit NODE KEY ESCROW_NXS mc SAMPLES CHUNKS SEED        (level 2: Monte Carlo, estimation of pi)
//! vearl-cli l2-submit NODE KEY ESCROW_NXS render WIDTH HEIGHT SPP SEED   (level 2: 3D rendering in 16x16 tiles)
//! vearl-cli l2-submit NODE KEY ESCROW_NXS render3 SCENE WIDTH HEIGHT SPP PASSES SEED   (level 2: path tracer; SCENE = watch | mini | cocktail | orb | gallery)
//! vearl-cli l2-status NODE JOBID_HEX
//! vearl-cli l2-who NODE JOBID_HEX WORKER [WORKER...]   (which of these nodes serves the job's chunks, opened against the root: `worker = ADDR` or `worker = none`)
//! vearl-cli l2-finish NODE WORKER KEY JOBID_HEX M [IMAGE.ppm]   (audits M randomly drawn chunks: local recomputation + Merkle opening; Accept or Fraud)
//! vearl-cli mlp-submit NODE WORKER seed:CLIENT ESCROW_PER_LAYER LAYERS DATA_SEED   (quantised multi-layer inference)
//! vearl-cli mlp-status NODE JOBID_HEX
//! vearl-cli mlp-finish NODE WORKER seed:CLIENT JOBID_HEX LAYERS DATA_SEED   (verifies each layer: Accept or Fraud)
use ed25519_dalek::SigningKey;
use vearl_core::crypto::*;
use vearl_core::l2::*;
use vearl_core::mlp::*;
use vearl_core::net::*;
use vearl_core::state::{BLOCK_TIME, COIN};

/// A job submitted by this tool expires after 12,000 s (3 h 20) if nobody takes it, whatever the block time.
const DEADLINE_BLOCKS: u64 = 12_000 / BLOCK_TIME;
use vearl_core::types::*;
use vearl_core::wallet::{load_signing_key, parse_address, read_password};
use vearl_core::prog::*;
use vearl_core::tiled::*;
use vearl_core::work::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn parse_pk(s: &str) -> PubKey {
    if s.starts_with("vrl1") {
        return parse_address(s).unwrap_or_else(|e| panic!("{e}"));
    }
    if let Some(f) = s.strip_prefix("wallet:") {
        return pubkey(&key(&format!("wallet:{f}")));
    }
    if let Some(n) = s.strip_prefix("seed:") {
        return pubkey(&SigningKey::from_bytes(&[n.parse::<u8>().expect("seed u8"); 32]));
    }
    assert_eq!(s.len(), 64, "key / identifier = 64 hex");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Signing key: `wallet:PATH` (encrypted wallet, password through VEARL_WALLET_PASSWORD[_FILE] or masked
/// prompt) or `seed:N` (PUBLIC devnet seed).
fn key(s: &str) -> SigningKey {
    if let Some(path) = s.strip_prefix("wallet:") {
        let pw = read_password(&format!("Password for {path}: "), None).unwrap_or_else(|e| panic!("{e}"));
        return load_signing_key(std::path::Path::new(path), &pw, 0).unwrap_or_else(|e| panic!("{e}"));
    }
    SigningKey::from_bytes(&[s.strip_prefix("seed:").expect("seed:N or wallet:FILE").parse::<u8>().unwrap(); 32])
}

/// Freivalds test on a SUM of block products: C_ij == sum_k A_ik * B_kj, `rounds` rounds (error <= 2^-rounds).
fn freivalds_sum(am: &[i8], bm: &[i8], ij: (usize, usize), kj: (usize, usize), c: &[i32], n: usize, rounds: usize) -> bool {
    let (i, j) = ij;
    let (bk, bj) = kj;
    let a_blocks: Vec<Vec<i8>> = (0..bk).map(|k| get_block(am, bk * n, i, k, n)).collect();
    let b_blocks: Vec<Vec<i8>> = (0..bk).map(|k| get_block(bm, bj * n, k, j, n)).collect();
    let mut rng = rand::thread_rng();
    for _ in 0..rounds {
        let x: Vec<i64> = (0..n).map(|_| rng.gen_range(0..2)).collect();
        let cx: Vec<i64> = (0..n).map(|r| (0..n).map(|cc| c[r * n + cc] as i64 * x[cc]).sum()).collect();
        let mut lhs = vec![0i64; n];
        for k in 0..bk {
            let bx: Vec<i64> = (0..n).map(|r| (0..n).map(|cc| b_blocks[k][r * n + cc] as i64 * x[cc]).sum()).collect();
            for r in 0..n {
                lhs[r] += (0..n).map(|t| a_blocks[k][r * n + t] as i64 * bx[t]).sum::<i64>();
            }
        }
        if lhs != cx {
            return false;
        }
    }
    true
}

fn matrices(data_seed: u64, p: &WorkParams) -> CommittedMatrices {
    let mut rng = StdRng::seed_from_u64(data_seed);
    let mut m = || (0..p.n * p.n).map(|_| rng.gen_range(-64..=64) as i8).collect::<Vec<i8>>();
    let (a, b) = (m(), m());
    CommittedMatrices::new(a, b, p)
}

fn now_seed() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn next_nonce(node: &str, pk: PubKey) -> u64 {
    match request(node, &Msg::GetAccount(pk)).expect("node") {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("unexpected reply: {m:?}"),
    }
}

fn send(node: &str, sk: &SigningKey, kind: TxKind) -> Msg {
    let tx = SignedTx::new(Tx { from: pubkey(sk), nonce: next_nonce(node, pubkey(sk)), fee: 0, kind }, sk);
    request(node, &Msg::NewTx(tx)).expect("node")
}

fn run_cmd() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cmd = a.first().map(String::as_str).unwrap_or("");
    if cmd == "address" && a.len() == 2 {
        // vearl-cli address (seed:N | HEX64 | vrl1... | wallet:FILE) : the vrl1... address of a key, without talking to a node
        println!("{}", vearl_core::wallet::address_of(&parse_pk(&a[1])));
        return;
    }
    if a.len() < 2 {
        eprintln!("usage: see the header of the file (status | balance | transfer | job-submit | job-status | job-finish)");
        return;
    }
    let node = &a[1];
    // chain width announced by the node (n = 128 by default, up to 1024)
    let p = match request(node, &Msg::GetStatus) {
        Ok(Msg::Status { params, .. }) => WorkParams { n: params.0 as usize, tile: params.1 as usize, rank: params.2 as usize, fold_k: params.3 as usize },
        _ => WorkParams::TESTNET,
    };
    match cmd {
        "status" => println!("{:?}", request(node, &Msg::GetStatus).expect("node")),
        "probe" => {
            // vearl-cli probe NODE WORKER [MB]: time a download of MB megabytes (default 4, at most 8) that does not compress, from a worker (a direct
            // address or relay://SEED:PORT/acct:HEX); prints `PROBE bytes=... secs=... mbit=...`, what the routing of AI jobs uses
            let mb: u32 = a.get(3).map_or(4, |v| v.parse().expect("MB"));
            let bytes = mb.clamp(1, 8) << 20;
            let t = std::time::Instant::now();
            match request_retry_busy(&a[2], &Msg::GetProbe { bytes, nonce: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64) }) {
                Ok(Msg::Probe(v)) if v.len() == bytes as usize => {
                    let secs = t.elapsed().as_secs_f64().max(1e-6);
                    println!("PROBE bytes={} secs={secs:.3} mbit={:.1}", v.len(), v.len() as f64 * 8.0 / 1e6 / secs);
                }
                other => println!("PROBE failed: {other:?}"),
            }
        }
        "has-model" => {
            // vearl-cli has-model NODE WORKER MODEL.json: how many weight blocks of the model the worker already holds (the packs installed in advance)
            // the weight blocks are the base64 strings found under a "weights" key (a model written by a tool of tools/, or the template of MiniLM / BGE,
            // whose operations depend on the length of the text), read the way tools/make_model_pack.py reads them
            fn collect(v: &serde_json::Value, under: bool, out: &mut Vec<String>) {
                match v {
                    serde_json::Value::Object(o) => o.iter().for_each(|(k, x)| collect(x, under || k == "weights", out)),
                    serde_json::Value::Array(l) => l.iter().for_each(|x| collect(x, under, out)),
                    serde_json::Value::String(t) if under => out.push(t.clone()),
                    _ => {}
                }
            }
            let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&a[3]).expect("model file")).expect("model json");
            let mut strings = vec![];
            collect(&doc, false, &mut strings);
            let base: Vec<Vec<i8>> = strings.iter().filter_map(|t| vearl_core::model::b64_decode(t, p.n * p.n).ok()).collect();
            let mut roots: Vec<Hash> = par_map_heavy(base.len(), |k| rows_tree(&base[k], p.n).root());
            roots.sort();
            roots.dedup();
            match request_retry_busy(&a[2], &Msg::HasModel { roots: roots.clone() }) {
                Ok(Msg::ModelHave { have }) if have.len() == roots.len() => println!("HASMODEL present={} total={}", have.iter().filter(|h| **h).count(), roots.len()),
                other => println!("HASMODEL failed: {other:?}"),
            }
        }
        "balance" => {
            if let Msg::Account { balance, nonce, .. } = request(node, &Msg::GetAccount(parse_pk(&a[2]))).expect("node") {
                println!("{} VRL (nonce {nonce})", balance as f64 / COIN as f64);
            }
        }
        "transfer" => {
            let sk = key(&a[2]);
            let amount = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let fee = a.get(5).map_or(0, |f| (f.parse::<f64>().unwrap() * COIN as f64) as u64);
            let tx = SignedTx::new(Tx { from: pubkey(&sk), nonce: next_nonce(node, pubkey(&sk)), fee, kind: TxKind::Transfer { to: parse_pk(&a[3]), amount } }, &sk);
            println!("tx {} -> {:?}", hex(&tx.id()[..8]), request(node, &Msg::NewTx(tx)).expect("node"));
        }
        "job-submit" => {
            let (worker, sk) = (&a[2], key(&a[3]));
            let escrow = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let cm = matrices(a[5].parse().unwrap(), &p);
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let nonce = next_nonce(node, pubkey(&sk));
            let id = job_id(&pubkey(&sk), nonce, &cm.a_root(), &cm.b_root());
            println!("data deposited with the worker: {:?}", request(worker, &Msg::PutJob { a: cm.a.clone(), b: cm.b.clone() }).expect("worker"));
            let kind = match a.get(6).map(|s| s.parse::<u64>().unwrap()) {
                Some(secs) => TxKind::SubmitJobAuction { a_root: cm.a_root(), b_root: cm.b_root(), escrow, deadline: height + DEADLINE_BLOCKS, auction_secs: secs },
                None => TxKind::SubmitJob { a_root: cm.a_root(), b_root: cm.b_root(), escrow, deadline: height + DEADLINE_BLOCKS },
            };
            println!("SubmitJob: {:?}", send(node, &sk, kind));
            println!("job_id = {}", hex(&id));
        }
        "job-audit" => {
            let (sk, id) = (key(&a[2]), parse_pk(&a[3]));
            let cm = matrices(a[4].parse().unwrap(), &p);
            let k: usize = a[5].parse().unwrap();
            let mut rng = StdRng::seed_from_u64(now_seed());
            let picks: Vec<(u32, u32)> = (0..k).map(|_| (rng.gen_range(0..p.n) as u32, rng.gen_range(0..p.n) as u32)).collect();
            for (i, j) in &picks {
                println!("Fetch({i},{j}): {:?}", send(node, &sk, TxKind::Fetch { job_id: id, i: *i, j: *j }));
            }
            // waits for the worker's replies (or the expiry: in that case a mining node will trigger SlashUnserved)
            let mut served = vec![];
            for _ in 0..60 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if let Msg::Served { entries } = request(node, &Msg::GetServed(id)).expect("node") {
                    served = entries;
                }
                if picks.iter().all(|(i, j)| served.iter().any(|s| s.0 == *i && s.1 == *j)) {
                    break;
                }
            }
            for (i, j, row, path) in &served {
                let (iu, ju) = (*i as usize, *j as usize);
                let expected: i32 = (0..p.n).map(|t| cm.a[iu * p.n + t] as i32 * cm.b[t * p.n + ju] as i32).sum();
                let val = row.get(ju).copied().unwrap_or(i32::MIN);
                if expected == val {
                    println!("entry ({i},{j}) served and CORRECT");
                } else {
                    println!("entry ({i},{j}) served but WRONG ({val} instead of {expected}) -> fraud proof");
                    let proof = FraudProof {
                        job_id: id,
                        i: *i,
                        j: *j,
                        a_row: cm.a[iu * p.n..(iu + 1) * p.n].to_vec(),
                        a_path: cm.a_tree.proof(iu),
                        b_col: cm.col(ju, p.n),
                        b_path: cm.b_tree.proof(ju),
                        c_row: row.clone(),
                        c_path: path.clone(),
                    };
                    println!("Fraud: {:?}", send(node, &sk, TxKind::Fraud(proof)));
                    return;
                }
            }
            if served.len() < picks.len() {
                println!("{} request(s) unanswered: the worker will be slashed after SERVE_SECS by a mining node", picks.len() - served.len());
            }
        }
        "reputation" => println!("{:?}", request(node, &Msg::GetRep(parse_pk(&a[2]))).expect("node")),
        "job-status" => println!("{:?}", request(node, &Msg::GetJob(parse_pk(&a[2]))).expect("node")),
        "job-finish" => {
            let (worker, sk, id) = (&a[2], key(&a[3]), parse_pk(&a[4]));
            let cm = matrices(a[5].parse().unwrap(), &p);
            let Msg::JobResult { c } = request(worker, &Msg::GetResult(id)).expect("worker") else {
                println!("no result at the worker yet");
                return;
            };
            if freivalds(&cm.a, &cm.b, &c, p.n, 24, &[7u8; 32]) {
                println!("correct result (Freivalds, 24 rounds, error <= 2^-24) -> Accept: {:?}", send(node, &sk, TxKind::Accept { job_id: id }));
            } else {
                let (i, j) = find_bad_entry(&cm.a, &cm.b, &c, p.n, &[7u8; 32]).expect("wrong entry located");
                println!("WRONG RESULT: C[{i}][{j}] -> fraud proof");
                let ct = c_tree(&c, p.n);
                let proof = FraudProof {
                    job_id: id,
                    i: i as u32,
                    j: j as u32,
                    a_row: cm.a[i * p.n..(i + 1) * p.n].to_vec(),
                    a_path: cm.a_tree.proof(i),
                    b_col: cm.col(j, p.n),
                    b_path: cm.b_tree.proof(j),
                    c_row: row_of(&c, p.n, i),
                    c_path: ct.proof(i),
                };
                println!("Fraud: {:?}", send(node, &sk, TxKind::Fraud(proof)));
            }
        }
        "tiled-submit" => {
            let (worker, sk) = (&a[2], key(&a[3]));
            let per = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let dims = (a[5].parse::<usize>().unwrap(), a[6].parse::<usize>().unwrap(), a[7].parse::<usize>().unwrap());
            let (am, bm) = demo_matrices(p.n, dims, a[8].parse().unwrap());
            let (ar, br) = (a_block_roots(&am, dims.1 * p.n, dims.0, dims.1, p.n), b_block_roots(&bm, dims.2 * p.n, dims.1, dims.2, p.n));
            let d8 = (dims.0 as u8, dims.1 as u8, dims.2 as u8);
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let id = tiled_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), d8, &ar, &br);
            println!("matrices deposited with the worker: {:?}", request(worker, &Msg::PutTiled { a: am, b: bm, dims: d8 }).expect("worker"));
            let kind = TxKind::Tiled(TiledTx::Submit { dims: d8, a_roots: ar, b_roots: br, escrow: per * (dims.0 * dims.1 * dims.2) as u64, deadline: height + DEADLINE_BLOCKS });
            println!("Submit: {:?}", send(node, &sk, kind));
            println!("job_id = {}", hex(&id));
        }
        "tiled-run" => {
            // Product C = A*B of LARGE matrices, end to end: row-wise deposit, submission, wait, download and verification of
            // each block product (Merkle root + Freivalds), exact local sum, Accept (or fraud proof), writing of C (int32 LE).
            let (worker, sk) = (&a[2], key(&a[3]));
            let per = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let (am, bm) = (std::fs::read(&a[5]).expect("A"), std::fs::read(&a[6]).expect("B"));
            let dims = (a[7].parse::<usize>().unwrap(), a[8].parse::<usize>().unwrap(), a[9].parse::<usize>().unwrap());
            let (bi, bk, bj) = dims;
            let (am, bm): (Vec<i8>, Vec<i8>) = (am.iter().map(|v| *v as i8).collect(), bm.iter().map(|v| *v as i8).collect());
            assert_eq!(am.len(), bi * p.n * bk * p.n, "A must be {} x {} bytes", bi * p.n, bk * p.n);
            assert_eq!(bm.len(), bk * p.n * bj * p.n, "B must be {} x {} bytes", bk * p.n, bj * p.n);
            let t0 = std::time::Instant::now();
            // 1) row-wise deposit (messages <= 8 MiB)
            let mut key_bytes = [0u8; 32];
            rand::thread_rng().fill(&mut key_bytes);
            let dd = (bi as u8, bk as u8, bj as u8);
            for (which, mat, rows, row_len) in [(0u8, &am, bi * p.n, bk * p.n), (1u8, &bm, bk * p.n, bj * p.n)] {
                let per_msg = ((8 << 20) / row_len).max(1);
                let mut r = 0;
                while r < rows {
                    let cnt = per_msg.min(rows - r);
                    let ack = request(worker, &Msg::PutTiledStage { key: key_bytes, which, dims: dd, row_start: r as u32, data: mat[r * row_len..(r + cnt) * row_len].to_vec() }).expect("worker");
                    assert!(matches!(ack, Msg::Ack { ok: true, .. }), "deposit refused: {ack:?}");
                    r += cnt;
                }
            }
            let ack = request(worker, &Msg::PutTiledDone { key: key_bytes }).expect("worker");
            assert!(matches!(ack, Msg::Ack { ok: true, .. }), "end of deposit refused: {ack:?}");
            let t_upload = t0.elapsed().as_secs_f64();
            // 2) on-chain submission
            let (a_roots, b_roots) = (a_block_roots(&am, bk * p.n, bi, bk, p.n), b_block_roots(&bm, bj * p.n, bk, bj, p.n));
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let products = (bi * bk * bj) as u64;
            let id = tiled_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), dd, &a_roots, &b_roots);
            let r = send(node, &sk, TxKind::Tiled(TiledTx::Submit { dims: dd, a_roots, b_roots, escrow: per * products, deadline: height + 2 * DEADLINE_BLOCKS }));
            assert!(matches!(r, Msg::Ack { ok: true, .. }), "Submit refused: {r:?}");
            println!("job_id = {} ({} block products {}x{}, escrow {:.2} VRL); deposit {:.1} s", hex(&id), products, p.n, p.n, (per * products) as f64 / COIN as f64, t_upload);
            // 3) wait for the worker to publish the roots
            let t1 = std::time::Instant::now();
            let product_roots = loop {
                if let Ok(Msg::TiledInfo { posted: true, product_roots, .. }) = request(node, &Msg::GetTiled(id)) {
                    break product_roots;
                }
                assert!(t1.elapsed().as_secs() < 1800, "the worker did not publish");
                std::thread::sleep(std::time::Duration::from_millis(300));
            };
            let t_compute = t1.elapsed().as_secs_f64();
            // 4) VERIFICATION. Fast path: per group (i, j) only the SUM C_ij is downloaded (I*J transfers instead of I*J*K) and it is
            // verified by Freivalds on the sum of the K block products (A_ik * (B_kj * x)): cost O(K n^2) instead of the product itself.
            // Detailed path (check failure, or VEARL_TILED_FULL=1): the K products of the group are downloaded one by one, their root
            // checked, each verified by Freivalds; the wrong product (or sum) is located and the fraud proof is published.
            let t2 = std::time::Instant::now();
            let n_total = bj * p.n;
            let mut c_full = vec![0i32; bi * p.n * n_total];
            let c_roots = match request(node, &Msg::GetTiled(id)) {
                Ok(Msg::TiledInfo { c_roots, .. }) => c_roots,
                m => panic!("{m:?}"),
            };
            let full_mode = std::env::var("VEARL_TILED_FULL").is_ok();
            let groups: Vec<(usize, usize)> = (0..bi).flat_map(|i| (0..bj).map(move |j| (i, j))).collect();
            let par = std::thread::available_parallelism().map_or(8, |x| x.get()).clamp(4, 32);
            let mut suspects: Vec<(usize, usize)> = vec![];
            let mut bytes_down = 0usize;
            let prof = std::sync::Mutex::new([0f64; 3]);
            for chunk in groups.chunks(par) {
                let got: Vec<Result<(usize, usize, Vec<i32>, bool), String>> = std::thread::scope(|sc| {
                    let hs: Vec<_> = chunk
                        .iter()
                        .map(|&(i, j)| {
                            let (am, bm, c_roots, pp, prof) = (&am, &bm, &c_roots, &p, &prof);
                            sc.spawn(move || {
                                let t = std::time::Instant::now();
                                let Ok(Msg::TiledSum { c }) = request(worker, &Msg::GetTiledSum { job: id, i: i as u8, j: j as u8 }) else { return Err(format!("sum ({i},{j}) unavailable")) };
                                let t_req = t.elapsed().as_secs_f64();
                                let t = std::time::Instant::now();
                                if c.len() != pp.n * pp.n || c_root_st(&c, pp.n) != c_roots[i * bj + j] {
                                    return Err(format!("sum ({i},{j}): served data differs from the published root"));
                                }
                                let t_root = t.elapsed().as_secs_f64();
                                let t = std::time::Instant::now();
                                let ok = !full_mode && freivalds_sum(am, bm, (i, j), (bk, bj), &c, pp.n, 24);
                                prof.lock().unwrap().iter_mut().zip([t_req, t_root, t.elapsed().as_secs_f64()]).for_each(|(a, b)| *a += b);
                                Ok((i, j, c, ok))
                            })
                        })
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap()).collect()
                });
                for r in got {
                    match r {
                        Err(e) => {
                            println!("{e}");
                            if e.contains("unavailable") {
                                // the worker withholds the data: we demand an ON-CHAIN entry (Fetch); with no answer after SERVE_SECS it is penalised
                                let r = send(node, &sk, TxKind::Tiled(TiledTx::Fetch { job_id: id, which: 1, i: 0, j: 0, k: 0, idx: 0 }));
                                println!("data withheld -> on-chain Fetch: {r:?}");
                                let serve_secs: u64 = std::env::var("VEARL_SERVE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(130);
                                std::thread::sleep(std::time::Duration::from_secs(serve_secs + 10));
                                let status = |id: JobId| match request(node, &Msg::GetTiled(id)) {
                                    Ok(Msg::TiledInfo { status, .. }) => status,
                                    _ => "unknown".into(),
                                };
                                if status(id).starts_with("Posted") {
                                    println!("request not served -> SlashUnserved: {:?}", send(node, &sk, TxKind::Tiled(TiledTx::SlashUnserved { job_id: id })));
                                }
                                let t = std::time::Instant::now();
                                while t.elapsed().as_secs() < 120 && !status(id).starts_with("Slashed") && !status(id).starts_with("Settled") {
                                    std::thread::sleep(std::time::Duration::from_millis(500));
                                }
                                println!("final job status: {}", status(id));
                            }
                            return;
                        }
                        Ok((i, j, c, ok)) => {
                            bytes_down += c.len() * 4;
                            if !ok {
                                suspects.push((i, j));
                                continue;
                            }
                            for r in 0..p.n {
                                let dst = (i * p.n + r) * n_total + j * p.n;
                                c_full[dst..dst + p.n].copy_from_slice(&c[r * p.n..(r + 1) * p.n]);
                            }
                        }
                    }
                }
            }
            if let Some(&(i, j)) = suspects.first() {
                println!("{} suspect group(s) at the quick check (first: ({i},{j})) -> detailed download of the {bk} products", suspects.len());
                let mut prods: Vec<Vec<i32>> = vec![];
                for k in 0..bk {
                    let Ok(Msg::TiledProduct { p: prod }) = request(worker, &Msg::GetTiledProduct { job: id, i: i as u8, j: j as u8, k: k as u8 }) else {
                        println!("product ({i},{j},{k}) unavailable");
                        return;
                    };
                    bytes_down += prod.len() * 4;
                    if prod.len() != p.n * p.n || c_root_st(&prod, p.n) != product_roots[(i * bj + j) * bk + k] {
                        println!("product ({i},{j},{k}): served data differs from the published root");
                        return;
                    }
                    let (ab, bb) = (get_block(&am, bk * p.n, i, k, p.n), get_block(&bm, bj * p.n, k, j, p.n));
                    if !freivalds(&ab, &bb, &prod, p.n, 24, &[7u8; 32]) {
                        let (r, cc) = find_bad_entry(&ab, &bb, &prod, p.n, &[7u8; 32]).expect("wrong entry located");
                        println!("product ({i},{j},{k}) WRONG at [{r}][{cc}] -> fraud proof");
                        let kind = TiledFraudKind::Product {
                            i: i as u8, j: j as u8, k: k as u8, r: r as u32, c: cc as u32,
                            a_row: ab[r * p.n..(r + 1) * p.n].to_vec(), a_path: rows_tree(&ab, p.n).proof(r),
                            b_col: (0..p.n).map(|t| bb[t * p.n + cc]).collect(), b_path: cols_tree(&bb, p.n).proof(cc),
                            z_row: row_of(&prod, p.n, r), z_path: c_tree(&prod, p.n).proof(r),
                        };
                        println!("Fraud: {:?}", send(node, &sk, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })));
                        return;
                    }
                    prods.push(prod);
                }
                // all the products are right: the published SUM is wrong
                let Ok(Msg::TiledSum { c }) = request(worker, &Msg::GetTiledSum { job: id, i: i as u8, j: j as u8 }) else {
                    println!("sum ({i},{j}) unavailable");
                    return;
                };
                let Some(idx) = (0..p.n * p.n).find(|&e| prods.iter().map(|x| x[e] as i64).sum::<i64>() != c[e] as i64) else {
                    println!("quick check failed but no exact inconsistency found (test error?): giving up without accepting");
                    return;
                };
                println!("sum ({i},{j}) WRONG at [{}][{}] -> fraud proof", idx / p.n, idx % p.n);
                let ptrees: Vec<_> = prods.iter().map(|x| c_tree(x, p.n)).collect();
                let kind = TiledFraudKind::Sum {
                    i: i as u8, j: j as u8, r: (idx / p.n) as u32, c: (idx % p.n) as u32,
                    z_rows: prods.iter().map(|x| row_of(x, p.n, (idx) / p.n)).collect(), z_paths: ptrees.iter().map(|t| t.proof((idx) / p.n)).collect(),
                    c_row: row_of(&c, p.n, idx / p.n), c_path: c_tree(&c, p.n).proof(idx / p.n),
                };
                println!("Fraud: {:?}", send(node, &sk, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })));
                return;
            }
            let t_verify = t2.elapsed().as_secs_f64();
            let pf = *prof.lock().unwrap();
            println!("client profile (time accumulated over the threads): requests {:.1} s, Merkle roots {:.1} s, Freivalds {:.1} s", pf[0], pf[1], pf[2]);
            println!("{} sums C_ij verified (Merkle root + Freivalds 24 rounds on the sum of the {} block products) -> Accept: {:?}", bi * bj, bk, send(node, &sk, TxKind::Tiled(TiledTx::Accept { job_id: id })));
            let bytes: Vec<u8> = c_full.iter().flat_map(|v| v.to_le_bytes()).collect();
            std::fs::write(&a[10], &bytes).expect("writing C");
            let ops = 2.0 * (bi * p.n) as f64 * (bk * p.n) as f64 * (bj * p.n) as f64;
            println!(
                "TILED: C ({} x {}) written to {}; deposit {:.1} s | worker computation (submission -> roots published) {:.1} s | download+verification {:.1} s ({:.0} MiB) | total {:.1} s | {:.1} GOP in total",
                bi * p.n, bj * p.n, a[10], t_upload, t_compute, t_verify, bytes_down as f64 / 1048576.0, t0.elapsed().as_secs_f64(), ops / 1e9
            );
        }
        "tiled-status" => println!("{:?}", request(node, &Msg::GetTiled(parse_pk(&a[2]))).expect("node")),
        "tiled-finish" => {
            let (worker, sk, id) = (&a[2], key(&a[3]), parse_pk(&a[4]));
            let dims = (a[5].parse::<usize>().unwrap(), a[6].parse::<usize>().unwrap(), a[7].parse::<usize>().unwrap());
            let (am, bm) = demo_matrices(p.n, dims, a[8].parse().unwrap());
            let Msg::TiledInfo { posted, product_roots, c_roots, .. } = request(node, &Msg::GetTiled(id)).expect("node") else { panic!("unknown job") };
            if !posted {
                println!("the worker has not published its result yet");
                return;
            }
            let (bi, bk, bj) = dims;
            let mut all = vec![];
            for i in 0..bi {
                for j in 0..bj {
                    let Msg::TiledGroup { products, c } = request(worker, &Msg::GetTiledGroup { job: id, i: i as u8, j: j as u8 }).expect("worker") else {
                        println!("group ({i},{j}) unavailable at the worker");
                        return;
                    };
                    let ptrees: Vec<_> = products.iter().map(|x| c_tree(x, p.n)).collect();
                    let ctree = c_tree(&c, p.n);
                    for k in 0..bk {
                        if ptrees[k].root() != product_roots[(i * bj + j) * bk + k] {
                            println!("product ({i},{j},{k}): served data differs from the published root");
                            return;
                        }
                    }
                    if ctree.root() != c_roots[i * bj + j] {
                        println!("sum ({i},{j}): served data differs from the published root");
                        return;
                    }
                    for k in 0..bk {
                        let (ab, bb) = (get_block(&am, bk * p.n, i, k, p.n), get_block(&bm, bj * p.n, k, j, p.n));
                        if !freivalds(&ab, &bb, &products[k], p.n, 24, &[7u8; 32]) {
                            let (r, cc) = find_bad_entry(&ab, &bb, &products[k], p.n, &[7u8; 32]).expect("wrong entry located");
                            println!("product ({i},{j},{k}) WRONG at [{r}][{cc}] -> fraud proof");
                            let kind = TiledFraudKind::Product {
                                i: i as u8, j: j as u8, k: k as u8, r: r as u32, c: cc as u32,
                                a_row: ab[r * p.n..(r + 1) * p.n].to_vec(), a_path: rows_tree(&ab, p.n).proof(r),
                                b_col: (0..p.n).map(|t| bb[t * p.n + cc]).collect(), b_path: cols_tree(&bb, p.n).proof(cc),
                                z_row: row_of(&products[k], p.n, r), z_path: ptrees[k].proof(r),
                            };
                            println!("Fraud: {:?}", send(node, &sk, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })));
                            return;
                        }
                    }
                    if let Some(idx) = (0..p.n * p.n).find(|&e| products.iter().map(|x| x[e] as i64).sum::<i64>() != c[e] as i64) {
                        println!("sum ({i},{j}) WRONG at [{}][{}] -> fraud proof", idx / p.n, idx % p.n);
                        let kind = TiledFraudKind::Sum {
                            i: i as u8, j: j as u8, r: (idx / p.n) as u32, c: (idx % p.n) as u32,
                            z_rows: products.iter().map(|x| row_of(x, p.n, (idx) / p.n)).collect(), z_paths: ptrees.iter().map(|t| t.proof((idx) / p.n)).collect(),
                            c_row: row_of(&c, p.n, (idx) / p.n), c_path: ctree.proof((idx) / p.n),
                        };
                        println!("Fraud: {:?}", send(node, &sk, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })));
                        return;
                    }
                    all.push(c);
                }
            }
            let full = assemble(&all, bi, bj, p.n);
            println!("result C ({} x {}) verified: {} products (Freivalds) and {} sums exact -> Accept: {:?}", bi * p.n, bj * p.n, bi * bk * bj, bi * bj, send(node, &sk, TxKind::Tiled(TiledTx::Accept { job_id: id })));
            println!("C[0][0] = {}", full[0]);
        }
        "prog-submit" => {
            let (worker, sk) = (&a[2], key(&a[3]));
            let per = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let (x0, ws, ops) = demo_program(a.get(6).map_or("cnn", |s| s.as_str()), p.n, a[5].parse().unwrap()).expect("unknown program (cnn | transformer)");
            let x0_root = cols_tree(&x0, p.n).root();
            let w_roots: Vec<Hash> = ws.iter().map(|w| rows_tree(w, p.n).root()).collect();
            let gemms = ops.iter().filter(|o| o.is_gemm()).count() as u64;
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let id = prog_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), &x0_root, &w_roots, &ops);
            // worker model registry: only the weight blocks it does not know are sent (once and for all), then the input
            let per_msg = ((12 << 20) / (p.n * p.n)).max(1);
            let uniq: Vec<Hash> = { let mut u: Vec<Hash> = vec![]; for r in &w_roots { if !u.contains(r) { u.push(*r); } } u };
            let Msg::ModelHave { have } = request(worker, &Msg::HasModel { roots: uniq.clone() }).expect("worker") else { panic!("registry unavailable") };
            let missing: Vec<Vec<i8>> = uniq.iter().zip(&have).filter(|(_, h)| !**h).map(|(r, _)| ws[w_roots.iter().position(|x| x == r).unwrap()].clone()).collect();
            println!("worker model registry: {}/{} weight blocks already present, {} to send", have.iter().filter(|h| **h).count(), uniq.len(), missing.len());
            for part in missing.chunks(per_msg) {
                let r = request(worker, &Msg::PutModel { ws: part.to_vec() }).expect("worker");
                assert!(matches!(r, Msg::Ack { ok: true, .. }), "weight deposit refused: {r:?}");
            }
            println!("input deposited with the worker: {:?}", request(worker, &Msg::PutProgRef { x0, w_roots: w_roots.clone() }).expect("worker"));
            println!("Submit: {:?}", send(node, &sk, TxKind::Prog(ProgTx::Submit { x0_root, w_roots, ops: ops.clone(), escrow: per * gemms, deadline: height + DEADLINE_BLOCKS })));
            println!("job_id = {}", hex(&id));
        }
        "prog-status" => println!("{:?}", request(node, &Msg::GetProg(parse_pk(&a[2]))).expect("node")),
        "prog-finish" => {
            let (worker, sk, id) = (&a[2], key(&a[3]), parse_pk(&a[4]));
            let (x0, ws, ops) = demo_program(a.get(6).map_or("cnn", |s| s.as_str()), p.n, a[5].parse().unwrap()).expect("unknown program (cnn | transformer)");
            let Msg::ProgInfo { posted, total, roots, .. } = request(node, &Msg::GetProg(id)).expect("node") else { panic!("unknown job") };
            if posted < total {
                println!("the worker only published {posted}/{total} operations");
                return;
            }
            let mut tens = vec![x0];
            let mut zs = vec![];
            // download and check of the operation roots IN PARALLEL (8 at a time): the Merkle trees of 10^6 leaves
            // and the transfers of several MiB dominate the verification time of a large program
            let fetch = |k: usize| -> Result<(Option<Vec<i32>>, Vec<i8>), String> {
                let Some((z, x)) = fetch_op(worker, id, k as u8, p.n) else { return Err(format!("operation {k} unavailable at the worker")) };
                if (z.as_ref().map_or([0u8; 32], |zz| c_tree(zz, p.n).root()), cols_tree(&x, p.n).root()) != roots[k] {
                    return Err(format!("operation {k}: served data differs from the roots published on-chain"));
                }
                Ok((z, x))
            };
            let all: Vec<usize> = (0..ops.len()).collect();
            for group in all.chunks(8) {
                let got: Vec<Result<(Option<Vec<i32>>, Vec<i8>), String>> = std::thread::scope(|sc| {
                    let hs: Vec<_> = group.iter().map(|&k| { let f = &fetch; sc.spawn(move || f(k)) }).collect();
                    hs.into_iter().map(|h| h.join().unwrap()).collect()
                });
                for r in got {
                    match r {
                        Ok((z, x)) => {
                            zs.push(z);
                            tens.push(x);
                        }
                        Err(e) => {
                            println!("{e}");
                            return;
                        }
                    }
                }
            }
            match find_fraud_proof(&ops, &ws, &tens, &zs, p.n) {
                Some((op, kind)) => {
                    println!("operation {op} WRONG ({}) -> fraud proof", match &kind { ProgFraud::Gemm { .. } => "GEMM", ProgFraud::Act { .. } => "activation", ProgFraud::Elem { .. } => "element-wise operation", ProgFraud::Col { .. } => "softmax / normalisation", ProgFraud::Bias { .. } => "bias", ProgFraud::Lut { .. } => "activation table", ProgFraud::MulW { .. } => "product with a table" });
                    println!("Fraud: {:?}", send(node, &sk, TxKind::Prog(ProgTx::Fraud { job_id: id, op, kind })));
                }
                None => {
                    println!("{} operations verified (Freivalds for the GEMMs, exact recomputation for the rest) -> Accept: {:?}", ops.len(), send(node, &sk, TxKind::Prog(ProgTx::Accept { job_id: id })));
                    let scores = tens.last().unwrap();
                    if let Some(path) = a.get(6).and_then(|s| s.strip_prefix("model:")) {
                        // imported model: predicted class (arg max, first tie) of each image of the batch, compared with the labels
                        let m = vearl_core::model::load(std::path::Path::new(path)).expect("model");
                        let idx: usize = a[5].parse().unwrap();
                        let (classes, batch) = (m.classes.max(1), m.batch.max(1));
                        let pred: Vec<usize> = (0..batch).map(|b| (0..classes).fold(0, |best, r| if scores[r * p.n + b] > scores[best * p.n + b] { r } else { best })).collect();
                        let labels = &m.samples[idx].labels;
                        let ok = pred.iter().zip(labels).filter(|(p, l)| **p == **l as usize).count();
                        if pred.len() <= 32 {
                            println!("classes predicted by the network (verified operation by operation): {pred:?}; true labels: {labels:?}; {ok} correct out of {}", labels.len());
                        } else {
                            println!("{} images classified by the network (every operation verified before payment): {ok} correct = {:.2} %; first 16 predictions {:?}", labels.len(), 100.0 * ok as f64 / labels.len() as f64, &pred[..16]);
                        }
                    } else {
                        println!("scores (class 0..3, first column): {:?}", (0..4).map(|r| scores[r * p.n]).collect::<Vec<_>>());
                    }
                }
            }
        }
        "infer" => {
            // WORKER: one address, or several separated by commas: the data is deposited with each of them and the first that claims a job computes it
            let workers: Vec<String> = a[2].split(',').map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).collect();
            assert!(!workers.is_empty(), "WORKER: one address, or several separated by commas");
            let (worker, sk) = (&workers[0], key(&a[3]));
            let per = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let m = vearl_core::model::load(std::path::Path::new(&a[5])).expect("model");
            assert_eq!(m.n, p.n, "the model is written for n = {} but the chain has n = {}", m.n, p.n);
            let (first, last): (usize, usize) = (a[6].parse().unwrap(), a[7].parse().unwrap());
            let out_path = &a[8];
            let inflight: usize = a.get(9).map_or(4, |v| v.parse().unwrap());
            let (classes, batch) = (m.classes.max(1), m.batch.max(1));
            // common blocks decoded and hashed ONCE; a sample may have its own program and a few blocks of its own
            // (e.g. the length of a text): all the samples go out in the same series, without resending anything that is shared
            let base = m.base_weights().expect("weights");
            let base_roots: Vec<Hash> = par_map_heavy(base.len(), |k| rows_tree(&base[k], p.n).root());
            let sample_roots = |idx: usize| -> Vec<Hash> {
                let mut r = base_roots.clone();
                for (i, w) in &m.samples[idx].weights {
                    r[*i] = rows_tree(&vearl_core::model::b64_decode(w, p.n * p.n).expect("weights"), p.n).root();
                }
                r
            };
            let t_start = std::time::Instant::now();
            // 1) worker model registry: the unknown weight blocks are sent only once for the whole series
            // (through a relay only a couple of blocks go in one message, see `relay_is_bulk`: the weights of a model are meant to be installed in advance)
            let per_msg = if workers.iter().any(|w| w.starts_with("relay://")) { RELAY_MAX_PUT_BLOCKS } else { ((12 << 20) / (p.n * p.n)).max(1) };
            let mut uniq: Vec<Hash> = vec![];
            let mut block_of: std::collections::HashMap<Hash, (usize, Option<usize>)> = Default::default();
            for (k, r) in base_roots.iter().enumerate() {
                if !block_of.contains_key(r) {
                    block_of.insert(*r, (k, None));
                    uniq.push(*r);
                }
            }
            let mut roots_of: std::collections::HashMap<usize, Vec<Hash>> = Default::default();
            for idx in first..=last {
                let sr = sample_roots(idx);
                for i in m.samples[idx].weights.keys() {
                    if !block_of.contains_key(&sr[*i]) {
                        block_of.insert(sr[*i], (*i, Some(idx)));
                        uniq.push(sr[*i]);
                    }
                }
                roots_of.insert(idx, sr);
            }
            let block = |r: &Hash| -> Vec<i8> {
                match block_of[r] {
                    (k, None) => base[k].clone(),
                    (k, Some(idx)) => vearl_core::model::b64_decode(&m.samples[idx].weights[&k], p.n * p.n).expect("weights"),
                }
            };
            for worker in &workers {
                let Msg::ModelHave { have } = request(worker, &Msg::HasModel { roots: uniq.clone() }).expect("worker") else { panic!("registry unavailable") };
                let missing: Vec<Vec<i8>> = uniq.iter().zip(&have).filter(|(_, h)| !**h).map(|(r, _)| block(r)).collect();
                println!("worker {worker} registry: {}/{} weight blocks already present, {} sent once for the {} batches", have.iter().filter(|h| **h).count(), uniq.len(), missing.len(), last + 1 - first);
                for part in missing.chunks(per_msg) {
                    let r = request_retry_busy(worker, &Msg::PutModel { ws: part.to_vec() }).expect("worker");
                    assert!(matches!(r, Msg::Ack { ok: true, .. }), "weight deposit refused: {r:?}");
                }
            }
            // 2) pipeline: up to `inflight` jobs in flight; each one is verified (Freivalds + recomputation) as soon as the worker has published its operations
            let mut queue: Vec<usize> = (first..=last).collect();
            queue.reverse();
            let mut flying: Vec<(usize, JobId, Vec<i8>, Vec<Op>, std::time::Instant)> = vec![];
            let mut results: Vec<(usize, Vec<i8>)> = vec![];
            let (mut accepted, mut fraud, mut sent_x) = (0usize, 0usize, 0usize);
            let mut escrow_total = 0u64;
            let mut verify_secs = 0f64;
            while !queue.is_empty() || !flying.is_empty() {
                while flying.len() < inflight && !queue.is_empty() {
                    let idx = queue.pop().unwrap();
                    let s = &m.samples[idx];
                    let x0 = vearl_core::model::b64_decode(&s.x0, p.n * p.n).expect("sample");
                    let ops = s.ops.clone().unwrap_or_else(|| m.ops.clone());
                    let w_roots = roots_of[&idx].clone();
                    let gemms = ops.iter().filter(|o| o.is_gemm()).count() as u64;
                    let x0_root = cols_tree(&x0, p.n).root();
                    let height = match request(node, &Msg::GetStatus).expect("node") {
                        Msg::Status { height, .. } => height,
                        m => panic!("{m:?}"),
                    };
                    let id = prog_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), &x0_root, &w_roots, &ops);
                    // submission first: the mempool limits the number of pending transactions per sender; if it is full we wait for a block
                    // (nothing has been deposited with the worker); the data arrives afterwards, before the claim (the worker only claims what it has)
                    let r = send(node, &sk, TxKind::Prog(ProgTx::Submit { x0_root, w_roots: w_roots.clone(), ops: ops.clone(), escrow: per * gemms, deadline: height + DEADLINE_BLOCKS }));
                    if let Msg::Ack { ok: false, info } = &r {
                        if info.contains("too many pending") || info.contains("mempool full") {
                            queue.push(idx);
                            break;
                        }
                    }
                    assert!(matches!(r, Msg::Ack { ok: true, .. }), "Submit refused: {r:?}");
                    for worker in &workers {
                        let r = request_retry_busy(worker, &Msg::PutProgRef { x0: x0.clone(), w_roots: w_roots.clone() }).expect("worker");
                        assert!(matches!(r, Msg::Ack { ok: true, .. }), "input refused by {worker}: {r:?}");
                    }
                    escrow_total += per * gemms;
                    sent_x += 1;
                    flying.push((idx, id, x0, ops, std::time::Instant::now()));
                }
                // ready batches (all operations published): verified IN PARALLEL, at most VERIFY_PAR at a time with FETCH_PAR requests
                // each (VERIFY_PAR x FETCH_PAR connections: under the worker's incoming connection cap, MAX_IN); the transactions
                // (Accept / Fraud) then go out in order, from this thread (sequential nonces)
                // through a relay (a miner at home) every byte goes through the seed: fewer requests at the same time
                let relayed = workers.iter().any(|w| w.starts_with("relay://"));
                let (verify_par, fetch_par) = if relayed { (2usize, 2usize) } else { (4usize, 4usize) };
                let mut ready = vec![];
                let mut k = 0;
                while k < flying.len() && ready.len() < verify_par {
                    match request(node, &Msg::GetProg(flying[k].1)) {
                        Ok(Msg::ProgInfo { posted, total, .. }) if posted == total => {
                            let (idx, id, x0, ops, _) = flying.remove(k);
                            ready.push((idx, id, x0, ops));
                        }
                        Ok(Msg::ProgInfo { .. }) => k += 1,
                        // job never appeared on-chain (Submit evicted from the mempool, e.g. behind a stuck transaction): we resubmit it
                        _ if flying[k].4.elapsed().as_secs() > 90 => {
                            let (idx, id, ..) = flying.remove(k);
                            println!("batch {idx}: job {} absent from the chain after 90 s -> resubmitted", hex(&id[..4]));
                            queue.push(idx);
                            sent_x -= 1;
                            escrow_total -= per * m.samples[idx].ops.as_ref().unwrap_or(&m.ops).iter().filter(|o| o.is_gemm()).count() as u64;
                        }
                        _ => k += 1,
                    }
                }
                let progressed = !ready.is_empty();
                let check = |(idx, id, x0, ops): (usize, JobId, Vec<i8>, Vec<Op>)| {
                    let tv = std::time::Instant::now();
                    let ws = m.sample_program(idx, &base).expect("sample").1;
                    let Msg::ProgInfo { roots, .. } = request(node, &Msg::GetProg(id)).expect("node") else { unreachable!() };
                    let net_us = std::sync::atomic::AtomicU64::new(0);
                    // the worker that claimed this job (several may hold the data): the first that serves its first operation
                    let serving: &String = workers.iter().find(|w| fetch_ops(w, id, &[0u8], p.n).is_some()).unwrap_or(&workers[0]);
                    // operations in groups of OPS_PER_REQ in one round trip (bounding boxes), groups in parallel; roots in parallel
                    const OPS_PER_REQ: usize = 16;
                    let groups = ops.len().div_ceil(OPS_PER_REQ);
                    let fetched: Vec<Result<Vec<(Option<Vec<i32>>, Vec<i8>)>, String>> = par_map_limit(groups, fetch_par, |g| {
                        let (lo, hi) = (g * OPS_PER_REQ, ((g + 1) * OPS_PER_REQ).min(ops.len()));
                        let t_net = std::time::Instant::now();
                        let want: Vec<u8> = (lo..hi).map(|o| o as u8).collect();
                        let got = fetch_ops(serving, id, &want, p.n).ok_or_else(|| format!("operations {lo}..{hi} unavailable"));
                        net_us.fetch_add(t_net.elapsed().as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
                        got
                    });
                    let mut data = vec![];
                    let mut failed = None;
                    for r in fetched {
                        match r {
                            Ok(v) => data.extend(v),
                            Err(e) => failed = failed.or(Some(e)),
                        }
                    }
                    let t_root = std::time::Instant::now();
                    if failed.is_none() {
                        let bad: Vec<usize> = par_map_heavy(data.len(), |op| {
                            let (z, x) = &data[op];
                            ((z.as_ref().map_or([0u8; 32], |zz| c_root(zz, p.n)), cols_tree(x, p.n).root()) != roots[op]).then_some(op)
                        })
                        .into_iter()
                        .flatten()
                        .collect();
                        if let Some(op) = bad.first() {
                            failed = Some(format!("operation {op}: served data differs from the published roots"));
                        }
                    }
                    let root_s = t_root.elapsed().as_secs_f64();
                    let (mut tens, mut zs) = (vec![x0], vec![]);
                    for (z, x) in data {
                        zs.push(z);
                        tens.push(x);
                    }
                    let t_fetch = tv.elapsed().as_secs_f64();
                    let verdict = match failed {
                        Some(e) => Err(e),
                        None => Ok(find_fraud_proof(&ops, &ws, &tens, &zs, p.n)),
                    };
                    if std::env::var("VEARL_TIMING").is_ok() {
                        println!("batch {idx}: fetch+roots {t_fetch:.2} s (network {:.2} s accumulated over the threads, roots {root_s:.2} s); find_fraud_proof {:.2} s ({} operations)", net_us.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e6, tv.elapsed().as_secs_f64() - t_fetch, ops.len());
                    }
                    (idx, id, tens.pop().unwrap_or_default(), verdict, tv.elapsed().as_secs_f64())
                };
                let check = &check;
                let checked: Vec<_> = std::thread::scope(|sc| {
                    let hs: Vec<_> = ready.into_iter().map(|r| sc.spawn(move || check(r))).collect();
                    hs.into_iter().map(|h| h.join().unwrap()).collect()
                });
                for (idx, id, out, verdict, secs) in checked {
                    verify_secs += secs;
                    match verdict {
                        Err(e) => {
                            println!("batch {idx}: {e}");
                            if e.contains("unavailable") {
                                // the worker withholds the data: we demand it ON-CHAIN (Fetch); with no answer after SERVE_SECS it is penalised (SlashUnserved)
                                let r = send(node, &sk, TxKind::Prog(ProgTx::Fetch { job_id: id, tensor: 1, col: 0 }));
                                println!("batch {idx}: data withheld -> on-chain Fetch: {r:?}");
                                let serve_secs: u64 = std::env::var("VEARL_SERVE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(130);
                                std::thread::sleep(std::time::Duration::from_secs(serve_secs + 10));
                                let status = |id: JobId| match request(node, &Msg::GetProg(id)) {
                                    Ok(Msg::ProgInfo { status, .. }) => status,
                                    _ => "unknown".into(),
                                };
                                if status(id).starts_with("Complete") {
                                    println!("batch {idx}: request not served -> SlashUnserved: {:?}", send(node, &sk, TxKind::Prog(ProgTx::SlashUnserved { job_id: id })));
                                }
                                let t = std::time::Instant::now();
                                while t.elapsed().as_secs() < 120 && !status(id).starts_with("Slashed") && !status(id).starts_with("Settled") {
                                    std::thread::sleep(std::time::Duration::from_millis(500));
                                }
                                println!("batch {idx}: final job status {}: {}", hex(&id[..4]), status(id));
                            } else {
                                println!("batch {idx}: (job abandoned)");
                            }
                            fraud += 1;
                            continue;
                        }
                        Ok(Some((op, kind))) => {
                            println!("batch {idx}: operation {op} WRONG -> fraud proof: {:?}", send(node, &sk, TxKind::Prog(ProgTx::Fraud { job_id: id, op, kind })));
                            fraud += 1;
                        }
                        Ok(None) => {
                            // Accept only if the job is still waiting for the client: if the dispute window has passed, the worker has
                            // already settled the job (paid) and an Accept that cannot be included would block all our following transactions (nonces)
                            match request(node, &Msg::GetProg(id)) {
                                Ok(Msg::ProgInfo { status, .. }) if status.starts_with("Complete") => {
                                    let r = send(node, &sk, TxKind::Prog(ProgTx::Accept { job_id: id }));
                                    assert!(matches!(r, Msg::Ack { ok: true, .. }), "Accept refused: {r:?}");
                                }
                                Ok(Msg::ProgInfo { status, .. }) => println!("batch {idx}: verified, but already settled ({status}): no Accept"),
                                r => println!("batch {idx}: verified, unreadable status ({r:?}): no Accept"),
                            }
                            accepted += 1;
                            let mut v = Vec::with_capacity(batch * classes);
                            for b in 0..batch {
                                for c in 0..classes {
                                    v.push(out[c * p.n + b]);
                                }
                            }
                            results.push((idx, v));
                        }
                    }
                    println!("batch {idx} verified ({}/{}): {:.1} s since the start", accepted + fraud, last + 1 - first, t_start.elapsed().as_secs_f64());
                }
                if !progressed {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
                assert!(t_start.elapsed().as_secs() < 6 * 3600, "timeout exceeded");
            }
            results.sort_by_key(|r| r.0);
            let bytes: Vec<u8> = results.iter().flat_map(|r| r.1.iter().map(|v| *v as u8)).collect();
            std::fs::write(out_path, &bytes).expect("write");
            let secs = t_start.elapsed().as_secs_f64();
            let items = accepted * batch;
            println!("INFER: {accepted} batch(es) accepted, {fraud} refused; {items} samples in {secs:.1} s = {:.0} /s; cumulative client verification {verify_secs:.1} s; output {out_path} ({} bytes, int8 [{items}, {classes}]); escrow committed {:.2} VRL ({sent_x} jobs)", items as f64 / secs, bytes.len(), escrow_total as f64 / COIN as f64);
        }
        "l2-submit" => {
            let sk = key(&a[2]);
            let escrow = (a[3].parse::<f64>().unwrap() * COIN as f64) as u64;
            let seed32 = |v: &str| -> [u8; 32] {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&v.parse::<u64>().unwrap().to_le_bytes());
                s
            };
            let (kernel, chunks) = match a[4].as_str() {
                "mc" => (Kernel::MonteCarlo(McParams { seed: seed32(&a[7]), dim: 2, samples: a[5].parse().unwrap(), out: 6, program: mc_pi_program() }), a[6].parse::<u32>().unwrap()),
                "render" => {
                    let k = Kernel::Render(demo_scene(a[5].parse().unwrap(), a[6].parse().unwrap(), a[7].parse().unwrap(), seed32(&a[8])));
                    let c = k.forced_chunks().expect("chunks");
                    (k, c)
                }
                "render2" => {
                    let k = Kernel::Render2(vearl_core::render2::scene_orb(a[5].parse().unwrap(), a[6].parse().unwrap(), a[7].parse().unwrap(), 2, 28.0, 1.2, seed32(&a[8])));
                    let c = k.forced_chunks().expect("chunks");
                    (k, c)
                }
                "render3" => {
                    // render3 SCENE WIDTH HEIGHT SPP_PER_PASS PASSES SEED
                    let (w, h, spp, passes): (u16, u16, u8, u16) = (a[6].parse().unwrap(), a[7].parse().unwrap(), a[8].parse().unwrap(), a[9].parse().unwrap());
                    let seed = seed32(&a[10]);
                    let p = match a[5].as_str() {
                        "watch" => vearl_core::render3::scene3_watch(w, h, spp, passes, seed),
                        "mini" => vearl_core::render3::scene3_mini(w, h, spp, passes, 6, seed),
                        "cocktail" => vearl_core::render3::scene3_cocktail(w, h, spp, passes, seed),
                        "orb" => vearl_core::render3::scene3_orb(w, h, spp, passes, seed),
                        "gallery" => vearl_core::render3::scene3_gallery(w, h, spp, passes, seed),
                        s => panic!("unknown scene '{s}' (watch | mini | cocktail | orb | gallery)"),
                    };
                    let k = Kernel::Render3(p);
                    let c = k.forced_chunks().expect("chunks");
                    (k, c)
                }
                other => panic!("unknown kernel '{other}' (mc | render | render2 | render3)"),
            };
            kernel.validate(chunks).unwrap_or_else(|e| panic!("kernel refused: {e}"));
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let id = l2_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), &kernel, chunks);
            println!("Submit: {:?}", send(node, &sk, TxKind::L2(L2Tx::Submit { kernel: kernel.clone(), chunks, escrow, deadline: height + DEADLINE_BLOCKS })));
            println!("{chunks} chunks (cost {} units per chunk)", kernel.cost());
            println!("job_id = {}", hex(&id));
        }
        "l2-status" => match request(node, &Msg::GetL2(parse_pk(&a[2]))).expect("node") {
            Msg::L2Info { status, chunks, escrow_net, root, .. } => println!("L2 {status}: {chunks} chunks, net escrow {}, root {:?}", escrow_net as f64 / COIN as f64, root.map(|r| hex(&r[..4]))),
            m => println!("{m:?}"),
        },
        "l2-who" => {
            // Which of these nodes holds the outputs of a Posted job? Each candidate is asked for chunk 0 and must open it against the
            // published root (a node that merely answers is not enough). The first one that does is printed as `worker = ADDR`, else
            // `worker = none`. Nothing is sent to the chain: unlike l2-finish, a wrong candidate costs nothing.
            let id = parse_pk(&a[2]);
            let Msg::L2Info { status, chunks, root, .. } = request(node, &Msg::GetL2(id)).expect("node") else { panic!("unknown job") };
            let (true, Some(root)) = (status.starts_with("Posted"), root) else {
                println!("worker = none (status {status})");
                return;
            };
            let depth = depth_for(chunks as usize);
            for w in &a[3..] {
                if let Ok(Msg::L2ChunkData { out, path }) = request(w, &Msg::GetL2Chunk { job: id, chunk: 0 }) {
                    if verify_proof(&root, chunk_leaf(0, &out), 0, &path, depth) {
                        println!("worker = {w}");
                        return;
                    }
                }
            }
            println!("worker = none (asked {} node(s))", a.len() - 3);
        }
        "l2-finish" => {
            let (worker, sk, id) = (&a[2], key(&a[3]), parse_pk(&a[4]));
            let m: usize = a[5].parse().unwrap();
            let Msg::L2Info { status, chunks, root, kernel, .. } = request(node, &Msg::GetL2(id)).expect("node") else { panic!("unknown job") };
            let (true, Some(root)) = (status.starts_with("Posted"), root) else {
                println!("the worker has not published a result yet (status {status})");
                return;
            };
            let depth = depth_for(chunks as usize);
            // 1. audit by sampling: m randomly drawn chunks, recomputed locally
            let mut rng = StdRng::seed_from_u64(now_seed());
            let picked: Vec<usize> = if m >= chunks as usize { (0..chunks as usize).collect() } else { rand::seq::index::sample(&mut rng, chunks as usize, m).into_vec() };
            for &i in &picked {
                let (out, path) = match request(worker, &Msg::GetL2Chunk { job: id, chunk: i as u32 }) {
                    Ok(Msg::L2ChunkData { out, path }) => (out, path),
                    _ => {
                        println!("the worker does not serve chunk {i} off-chain: ON-CHAIN demand (Fetch): {:?}", send(node, &sk, TxKind::L2(L2Tx::Fetch { job_id: id, chunk: i as u32 })));
                        return;
                    }
                };
                if !verify_proof(&root, chunk_leaf(i as u32, &out), i, &path, depth) {
                    println!("chunk {i}: the served output is NOT the one committed in the published root (worker inconsistency, no on-chain proof possible; do not accept)");
                    return;
                }
                if kernel.chunk(i as u32) != out {
                    println!("chunk {i} WRONG (the kernel gives another output) -> fraud proof; Fraud: {:?}", send(node, &sk, TxKind::L2(L2Tx::Fraud { job_id: id, chunk: i as u32, out, path })));
                    return;
                }
            }
            let frac = |phi: f64| 1.0 - (1.0 - phi).powi(picked.len() as i32);
            println!("{} chunk(s) out of {chunks} recomputed locally and opened against the root: all correct", picked.len());
            println!("PROBABILISTIC guarantee: a worker that falsified {} isolated chunk would be detected with probability {:.1} %; if it falsified 5 %, with {:.2} %", 1, 100.0 * picked.len() as f64 / chunks as f64, 100.0 * frac(0.05));
            println!("Accept: {:?}", send(node, &sk, TxKind::L2(L2Tx::Accept { job_id: id })));
            // 2. complete result: all the chunks (opened against the root), assembled
            // fetched on 32 connections at once, each kept open: a long image (tens of thousands of chunks) over a network with some
            // latency would otherwise take many minutes
            let n = chunks as usize;
            let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
            let per = (n + 31) / 32;
            std::thread::scope(|sc| {
                for (t, part) in slots.chunks_mut(per.max(1)).enumerate() {
                    sc.spawn(move || {
                        // one connection per thread, kept open for all its chunks (the node answers a client's requests one after the other)
                        let mut conn: Option<vearl_core::net::Conn> = None;
                        for (k, slot) in part.iter_mut().enumerate() {
                            let i = t * per + k;
                            for _try in 0..4 {
                                if conn.is_none() {
                                    conn = vearl_core::net::Conn::connect(worker).ok().map(|c| {
                                        c.set_timeout(std::time::Duration::from_secs(20));
                                        c
                                    });
                                }
                                let Some(c) = conn.as_mut() else {
                                    std::thread::sleep(std::time::Duration::from_millis(300));
                                    continue;
                                };
                                let reply = c.send(&Msg::GetL2Chunk { job: id, chunk: i as u32 }).and_then(|_| loop {
                                    match c.recv()? {
                                        Msg::Hello { .. } => continue,
                                        r => break Ok(r),
                                    }
                                });
                                match reply {
                                    Ok(Msg::L2ChunkData { out, path }) if verify_proof(&root, chunk_leaf(i as u32, &out), i, &path, depth) => {
                                        *slot = Some(out);
                                        break;
                                    }
                                    _ => {
                                        conn = None;
                                        std::thread::sleep(std::time::Duration::from_millis(200));
                                    }
                                }
                            }
                        }
                    });
                }
            });
            let mut outs: Vec<Vec<u8>> = vec![];
            for (i, s) in slots.into_iter().enumerate() {
                match s {
                    Some(out) => outs.push(out),
                    None => {
                        println!("chunk {i} unavailable or inconsistent: complete result not assembled");
                        return;
                    }
                }
            }
            match &kernel {
                Kernel::MonteCarlo(p) => {
                    let (mut s1, mut s2) = (0i128, 0i128);
                    for o in &outs {
                        s1 += i128::from_le_bytes(o[..16].try_into().unwrap());
                        s2 += i128::from_le_bytes(o[16..32].try_into().unwrap());
                    }
                    let n = chunks as f64 * p.samples as f64;
                    let (mean, m2) = (s1 as f64 / (1u128 << 32) as f64 / n, s2 as f64 / (1u128 << 32) as f64 / n);
                    let stderr = ((m2 - mean * mean).max(0.0) / n).sqrt();
                    println!("Monte Carlo estimate: E = {mean:.6} +- {stderr:.6} ({} samples); if the integrand is the indicator of the quarter disc: pi ~ {:.5}", n as u64, 4.0 * mean);
                }
                Kernel::Render3(p) => {
                    let img = vearl_core::render3::assemble(p, &outs, 1.05);
                    let path = a.get(6).cloned().unwrap_or_else(|| "level2-render.ppm".into());
                    let mut ppm = format!("P6
{} {}
255
", p.width, p.height).into_bytes();
                    ppm.extend_from_slice(&img);
                    std::fs::write(&path, ppm).expect("writing the image");
                    println!("image {}x{} assembled ({} passes of {} tiles) -> {path}", p.width, p.height, p.passes, vearl_core::render3::render3_tiles(p));
                }
                Kernel::Render(_) | Kernel::Render2(_) => {
                    let (w, h) = match &kernel {
                        Kernel::Render(p) => (p.width as usize, p.height as usize),
                        Kernel::Render2(p) => (p.width as usize, p.height as usize),
                        _ => unreachable!(),
                    };
                    let mut img = vec![0u8; w * h * 3];
                    for (c, t) in outs.iter().enumerate() {
                        let (tx, ty) = (c % (w / TILE), c / (w / TILE));
                        for y in 0..TILE {
                            for x in 0..TILE {
                                let dst = ((ty * TILE + y) * w + tx * TILE + x) * 3;
                                img[dst..dst + 3].copy_from_slice(&t[(y * TILE + x) * 3..(y * TILE + x) * 3 + 3]);
                            }
                        }
                    }
                    let path = a.get(6).cloned().unwrap_or_else(|| "level2-render.ppm".into());
                    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
                    ppm.extend_from_slice(&img);
                    std::fs::write(&path, ppm).expect("writing the image");
                    println!("image {w}x{h} assembled ({chunks} tiles, all opened against the root) -> {path}");
                }
            }
        }
        "mlp-submit" => {
            let (worker, sk) = (&a[2], key(&a[3]));
            let per_layer = (a[4].parse::<f64>().unwrap() * COIN as f64) as u64;
            let layers: usize = a[5].parse().unwrap();
            let (x0, ws) = demo_net(p.n, layers, a[6].parse().unwrap());
            let x0_root = cols_root_of(&x0, p.n);
            let w_roots: Vec<Hash> = ws.iter().map(|w| rows_root_of(w, p.n)).collect();
            let height = match request(node, &Msg::GetStatus).expect("node") {
                Msg::Status { height, .. } => height,
                m => panic!("{m:?}"),
            };
            let id = mlp_id(&pubkey(&sk), next_nonce(node, pubkey(&sk)), &x0_root, &w_roots);
            println!("data deposited with the worker: {:?}", request(worker, &Msg::PutMlp { x0, ws }).expect("worker"));
            let kind = TxKind::Mlp(MlpTx::Submit { x0_root, w_roots, shifts: vec![DEMO_SHIFT; layers], escrow: per_layer * layers as u64, deadline: height + DEADLINE_BLOCKS });
            println!("Submit: {:?}", send(node, &sk, kind));
            println!("job_id = {}", hex(&id));
        }
        "mlp-status" => println!("{:?}", request(node, &Msg::GetMlp(parse_pk(&a[2]))).expect("node")),
        "mlp-finish" => {
            let (worker, sk, id) = (&a[2], key(&a[3]), parse_pk(&a[4]));
            let layers: usize = a[5].parse().unwrap();
            let (x0, ws) = demo_net(p.n, layers, a[6].parse().unwrap());
            let Msg::MlpInfo { posted, layers_total, .. } = request(node, &Msg::GetMlp(id)).expect("node") else { panic!("unknown job") };
            if posted.len() < layers_total as usize {
                println!("the worker only published {}/{} layers", posted.len(), layers_total);
                return;
            }
            let mut xprev = x0.clone();
            for l in 0..layers {
                let Msg::LayerData { z, x } = request(worker, &Msg::GetLayer { job: id, layer: l as u8 }).expect("worker") else {
                    println!("layer {l} unavailable at the worker");
                    return;
                };
                let (zt, xt) = (c_tree(&z, p.n), cols_tree(&x, p.n));
                if (zt.root(), xt.root()) != posted[l] {
                    println!("layer {l}: the served data does not match the roots published on-chain");
                    return;
                }
                if !freivalds(&ws[l], &xprev, &z, p.n, 24, &[7u8; 32]) {
                    let (i, j) = find_bad_entry(&ws[l], &xprev, &z, p.n, &[7u8; 32]).expect("wrong entry located");
                    println!("layer {l}: WRONG GEMM at Z[{i}][{j}] -> fraud proof");
                    let kind = MlpFraudKind::Gemm {
                        i: i as u32,
                        j: j as u32,
                        a_row: ws[l][i * p.n..(i + 1) * p.n].to_vec(),
                        a_path: rows_tree(&ws[l], p.n).proof(i),
                        b_col: (0..p.n).map(|k| xprev[k * p.n + j]).collect(),
                        b_path: cols_tree(&xprev, p.n).proof(j),
                        z_row: row_of(&z, p.n, i),
                        z_path: zt.proof(i),
                    };
                    println!("Fraud: {:?}", send(node, &sk, TxKind::Mlp(MlpTx::Fraud { job_id: id, layer: l as u8, kind })));
                    return;
                }
                let want = requantize(&z, DEMO_SHIFT, l + 1 < layers);
                if let Some(idx) = (0..want.len()).find(|&k| want[k] != x[k]) {
                    let (i, j) = (idx / p.n, idx % p.n);
                    println!("layer {l}: WRONG ACTIVATION at X[{i}][{j}] -> fraud proof");
                    let kind = MlpFraudKind::Act {
                        i: i as u32,
                        j: j as u32,
                        z_row: row_of(&z, p.n, (idx) / p.n),
                        z_path: zt.proof((idx) / p.n),
                        x_col: (0..p.n).map(|k| x[k * p.n + j]).collect(),
                        x_path: xt.proof(j),
                    };
                    println!("Fraud: {:?}", send(node, &sk, TxKind::Mlp(MlpTx::Fraud { job_id: id, layer: l as u8, kind })));
                    return;
                }
                println!("layer {l}: GEMM (Freivalds, 24 rounds) and activation OK");
                xprev = x;
            }
            println!("correct inference -> Accept: {:?}", send(node, &sk, TxKind::Mlp(MlpTx::Accept { job_id: id })));
        }
        _ => eprintln!("unknown command"),
    }
}

/// An `Ack ok` only means "accepted into the node's mempool": a fraud proof only has an effect if it is
/// INCLUDED in a block before the end of the dispute window. The `*-finish` commands therefore wait for the final state.
const HELP: &str = r#"vearl-cli: command-line client of a Vearl node (tokens have no value, not audited).

A key is written wallet:FILE (a wallet made by vearl-wallet; the password is asked) or seed:N (PUBLIC development key, devnet only).
NODE is HOST:PORT of a node API.

  vearl-cli address (wallet:FILE | seed:N | HEX64 | vrl1...)       the vrl1... address of a key (no node needed)
  vearl-cli status NODE                                            state of the chain (height, peers, supply...)
  vearl-cli balance NODE (vrl1... | seed:N | HEX64)                balance of an account
  vearl-cli transfer NODE KEY (TO_ADDRESS) AMOUNT [FEE]            send tokens
  vearl-cli job-submit | job-status | job-finish | job-audit ...   matrix product jobs
  vearl-cli tiled-submit | tiled-run | tiled-status | tiled-finish ...   large products
  vearl-cli prog-submit | prog-status | prog-finish ...            tensor programs (CNN, transformer)
  vearl-cli infer NODE WORKER[,WORKER...] KEY ESCROW MODEL.json FIRST LAST OUT.i8   batch inference with a verified model (several workers share the jobs)
  vearl-cli l2-submit | l2-status | l2-finish ...                  Monte Carlo and 3D rendering jobs
  vearl-cli mlp-submit | mlp-status | mlp-finish ...               multi-layer inference

The exact arguments of every command are in the documentation: docs/06 (running a network) and docs/07 (specification).
Example:  vearl-cli status 127.0.0.1:8545"#;

fn main() {
    vearl_core::launcher::help_or_continue(HELP);
    run_cmd();
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cmd = a.first().map(String::as_str).unwrap_or("");
    if !cmd.ends_with("-finish") || a.len() < 5 {
        return;
    }
    let id = parse_pk(&a[4]);
    let q = match cmd {
        "job-finish" => Msg::GetJob(id),
        "tiled-finish" => Msg::GetTiled(id),
        "prog-finish" => Msg::GetProg(id),
        "mlp-finish" => Msg::GetMlp(id),
        "l2-finish" => Msg::GetL2(id),
        _ => return,
    };
    let t0 = std::time::Instant::now();
    let mut last = String::new();
    // with slow blocks, the inclusion of the Accept can take more than one block: VEARL_WAIT_SECS (default 90)
    let wait: u64 = std::env::var("VEARL_WAIT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(90);
    while t0.elapsed().as_secs() < wait {
        last = match request(&a[1], &q) {
            Ok(Msg::JobInfo { status, .. }) | Ok(Msg::TiledInfo { status, .. }) | Ok(Msg::ProgInfo { status, .. }) | Ok(Msg::MlpInfo { status, .. }) | Ok(Msg::L2Info { status, .. }) => status,
            _ => "unknown".into(),
        };
        if last.starts_with("Settled") || last.starts_with("Slashed") || last.starts_with("Expired") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!("final job status: {last}");
}
