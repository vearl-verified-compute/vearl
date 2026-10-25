//! Read-only JSON HTTP API (+ submission of SIGNED transactions) and block explorer.
//!
//! No endpoint handles a private key: transactions are signed by the wallet, the node only relays them.
//! By default the API listens on the loopback interface only; for public exposure, put a TLS reverse proxy in front
//! (the built-in HTTP server has neither TLS nor per-client rate limiting).
use crate::crypto::*;
use crate::httpmini::{query_get, serve, Request, Response};
use crate::mlp::MlpStatus;
use crate::net::*;
use crate::state::*;
use crate::types::*;
use crate::wallet::{address_of, parse_address};
use serde_json::{json, Value};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static WAITERS: AtomicUsize = AtomicUsize::new(0);
const MAX_WAITERS: usize = 16;

const EXPLORER_HTML: &str = include_str!("explorer.html");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > 4 * 1024 * 1024 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()).collect()
}

fn hash_arg(s: &str) -> Option<Hash> {
    <Hash>::try_from(unhex(s)?.as_slice()).ok()
}

fn amount(v: u64) -> String {
    format!("{}.{:08}", v / COIN, v % COIN)
}

fn kind_json(k: &TxKind) -> Value {
    use crate::mlp::MlpTx;
    match k {
        TxKind::Transfer { to, amount: a } => json!({ "type": "transfer", "to": address_of(to), "amount": amount(*a) }),
        TxKind::SubmitJob { escrow, deadline, .. } => json!({ "type": "submit_job", "escrow": amount(*escrow), "deadline": deadline }),
        TxKind::SubmitJobAuction { escrow, deadline, auction_secs, .. } => json!({ "type": "submit_job_auction", "escrow": amount(*escrow), "deadline": deadline, "auction_secs": auction_secs }),
        TxKind::Bid { job_id, price } => json!({ "type": "bid", "job": hex(job_id), "price": amount(*price) }),
        TxKind::ClaimJob { job_id } => json!({ "type": "claim_job", "job": hex(job_id) }),
        TxKind::PostResult { job_id, c_root } => json!({ "type": "post_result", "job": hex(job_id), "c_root": hex(c_root) }),
        TxKind::Accept { job_id } => json!({ "type": "accept", "job": hex(job_id) }),
        TxKind::Fraud(f) => json!({ "type": "fraud_proof", "job": hex(&f.job_id), "entry": [f.i, f.j] }),
        TxKind::Settle { job_id } => json!({ "type": "settle", "job": hex(job_id) }),
        TxKind::Fetch { job_id, i, j } => json!({ "type": "fetch", "job": hex(job_id), "entry": [i, j] }),
        TxKind::Serve { job_id, i, j, .. } => json!({ "type": "serve", "job": hex(job_id), "entry": [i, j] }),
        TxKind::SlashUnserved { job_id } => json!({ "type": "slash_unserved", "job": hex(job_id) }),
        TxKind::Prog(m) => {
            use crate::prog::ProgTx;
            match m {
                ProgTx::Submit { ops, escrow, .. } => json!({ "type": "program_submit", "ops": ops.len(), "escrow": amount(*escrow) }),
                ProgTx::Claim { job_id } => json!({ "type": "program_claim", "job": hex(job_id) }),
                ProgTx::PostOp { job_id, op, .. } => json!({ "type": "program_post_op", "job": hex(job_id), "op": op }),
                ProgTx::PostBatch { job_id, op, posts } => json!({ "type": "program_post_batch", "job": hex(job_id), "op": op, "count": posts.len() }),
                ProgTx::Accept { job_id } => json!({ "type": "program_accept", "job": hex(job_id) }),
                ProgTx::Fraud { job_id, op, .. } => json!({ "type": "program_fraud_proof", "job": hex(job_id), "op": op }),
                ProgTx::Settle { job_id } => json!({ "type": "program_settle", "job": hex(job_id) }),
                ProgTx::Fetch { job_id, tensor, col } => json!({ "type": "program_fetch", "job": hex(job_id), "tensor": tensor, "col": col }),
                ProgTx::Serve { job_id, tensor, col, .. } => json!({ "type": "program_serve", "job": hex(job_id), "tensor": tensor, "col": col }),
                ProgTx::SlashUnserved { job_id } => json!({ "type": "program_slash_unserved", "job": hex(job_id) }),
            }
        }
        TxKind::L2(m) => {
            use crate::l2::L2Tx;
            match m {
                L2Tx::Submit { kernel, chunks, escrow, .. } => json!({ "type": "level2_submit", "kernel": match kernel { crate::l2::Kernel::MonteCarlo(_) => "monte_carlo", crate::l2::Kernel::Render(_) => "render", crate::l2::Kernel::Render2(_) => "render2", crate::l2::Kernel::Render3(_) => "render3" }, "chunks": chunks, "escrow": amount(*escrow) }),
                L2Tx::Claim { job_id } => json!({ "type": "level2_claim", "job": hex(job_id) }),
                L2Tx::Post { job_id, root } => json!({ "type": "level2_post", "job": hex(job_id), "root": hex(root) }),
                L2Tx::Accept { job_id } => json!({ "type": "level2_accept", "job": hex(job_id) }),
                L2Tx::Fetch { job_id, chunk } => json!({ "type": "level2_fetch", "job": hex(job_id), "chunk": chunk }),
                L2Tx::Serve { job_id, chunk, .. } => json!({ "type": "level2_serve", "job": hex(job_id), "chunk": chunk }),
                L2Tx::SlashUnserved { job_id } => json!({ "type": "level2_slash_unserved", "job": hex(job_id) }),
                L2Tx::Fraud { job_id, chunk, .. } => json!({ "type": "level2_fraud_proof", "job": hex(job_id), "chunk": chunk }),
                L2Tx::Settle { job_id } => json!({ "type": "level2_settle", "job": hex(job_id) }),
            }
        }
        TxKind::Tiled(m) => {
            use crate::tiled::TiledTx;
            match m {
                TiledTx::Submit { dims, escrow, .. } => json!({ "type": "tiled_submit", "blocks": [dims.0, dims.1, dims.2], "escrow": amount(*escrow) }),
                TiledTx::Claim { job_id } => json!({ "type": "tiled_claim", "job": hex(job_id) }),
                TiledTx::Post { job_id, .. } => json!({ "type": "tiled_post_result", "job": hex(job_id) }),
                TiledTx::Accept { job_id } => json!({ "type": "tiled_accept", "job": hex(job_id) }),
                TiledTx::Fraud { job_id, .. } => json!({ "type": "tiled_fraud_proof", "job": hex(job_id) }),
                TiledTx::Settle { job_id } => json!({ "type": "tiled_settle", "job": hex(job_id) }),
                TiledTx::Fetch { job_id, which, .. } => json!({ "type": "tiled_fetch", "job": hex(job_id), "which": which }),
                TiledTx::Serve { job_id, which, .. } => json!({ "type": "tiled_serve", "job": hex(job_id), "which": which }),
                TiledTx::SlashUnserved { job_id } => json!({ "type": "tiled_slash_unserved", "job": hex(job_id) }),
            }
        }
        TxKind::Mlp(m) => match m {
            MlpTx::Submit { w_roots, escrow, .. } => json!({ "type": "inference_submit", "layers": w_roots.len(), "escrow": amount(*escrow) }),
            MlpTx::Claim { job_id } => json!({ "type": "inference_claim", "job": hex(job_id) }),
            MlpTx::PostLayer { job_id, layer, .. } => json!({ "type": "inference_post_layer", "job": hex(job_id), "layer": layer }),
            MlpTx::Accept { job_id } => json!({ "type": "inference_accept", "job": hex(job_id) }),
            MlpTx::Fraud { job_id, layer, .. } => json!({ "type": "inference_fraud_proof", "job": hex(job_id), "layer": layer }),
            MlpTx::Settle { job_id } => json!({ "type": "inference_settle", "job": hex(job_id) }),
        },
    }
}

fn tx_json(t: &SignedTx) -> Value {
    json!({ "id": hex(&t.id()), "from": address_of(&t.tx.from), "nonce": t.tx.nonce, "fee": amount(t.tx.fee), "kind": kind_json(&t.tx.kind) })
}

fn class_json(c: &WorkClass) -> Value {
    match c {
        WorkClass::Native => json!({ "type": "native" }),
        WorkClass::Job(id) => json!({ "type": "job", "job": hex(id) }),
        WorkClass::Layer { job, layer } => json!({ "type": "layer", "job": hex(job), "layer": layer }),
        WorkClass::Op { job, op } => json!({ "type": "program_op", "job": hex(job), "op": op }),
        WorkClass::Product { job, i, j, k } => json!({ "type": "product", "job": hex(job), "block": [i, j, k] }),
    }
}

fn block_json(b: &Block, full: bool) -> Value {
    let h = &b.header;
    let mut v = json!({
        "height": h.height, "hash": hex(&h.hash()), "prev": hex(&h.prev), "timestamp": h.timestamp,
        "miner": address_of(&h.miner), "work": class_json(&h.class), "tile": [h.ti, h.tj],
        "jackpot": hex(&h.jackpot), "target": h.target.to_string(), "tx_count": b.txs.len(),
        "reward": amount(base_reward(h.height)),
    });
    if full {
        v["txs"] = Value::Array(b.txs.iter().map(tx_json).collect());
    }
    v
}

fn status(sh: &Arc<Shared>) -> Response {
    let n = sh.node.lock().unwrap();
    let c = &n.chain;
    Response::json(
        200,
        &json!({
            "height": c.height(), "tip": hex(&c.tip_hash()), "tip_timestamp": c.tip_ts(),
            "total_work": c.total_work().to_string(), "target": c.target.to_string(),
            "mempool": n.mempool.len(), "peers": n.peer_count(),
            "supply": { "minted": amount(c.state.minted), "burned": amount(c.state.burned), "genesis": amount(c.genesis_supply) },
            "params": { "n": c.params.n, "tile": c.params.tile, "rank": c.params.rank, "fold_k": c.params.fold_k },
            "retarget": format!("{:?}", c.retarget),
            "jobs": c.state.jobs.len(), "inference_jobs": c.state.mlps.len(), "supply_invariant": c.check_supply_invariant(),
            "tensor_programs": c.state.progs.len(), "tiled_jobs": c.state.tiled.len(), "level2_jobs": c.state.l2.len(),
            "accounts": c.state.accounts.values().filter(|a| a.balance != 0 || a.nonce != 0).count(),
            "genesis_hash": hex(&sh.genesis_hash), "version": env!("CARGO_PKG_VERSION"), "reward": amount(base_reward(c.height())),
            "node_time": crate::net::now_secs(),
        }),
    )
}

/// The workers announced to this relay node (docs/21). Their addresses are not public: only a request from the machine itself gets the accounts and
/// where each one can be dialed (the job service on the seed reads it); anybody else gets the count.
fn workers(sh: &Arc<Shared>, req: &Request) -> Response {
    let list = crate::net::relay_workers(sh);
    let local = req.peer.parse::<std::net::IpAddr>().map_or(false, |ip| ip.is_loopback());
    if !local {
        return Response::json(200, &json!({ "count": list.len() }));
    }
    let items: Vec<Value> = list.iter().map(|w| json!({ "account": hex(&w.account), "dial": w.dial, "direct": w.direct, "seconds": w.seconds })).collect();
    Response::json(200, &json!({ "count": list.len(), "workers": items }))
}

fn blocks(sh: &Arc<Shared>, q: &str) -> Response {
    let n = sh.node.lock().unwrap();
    let tip = n.chain.height();
    let limit = query_get(q, "limit").and_then(|v| v.parse::<u64>().ok()).unwrap_or(20).clamp(1, 100);
    let start = query_get(q, "from").and_then(|v| v.parse::<u64>().ok()).unwrap_or(tip.saturating_sub(1)).min(tip.saturating_sub(1));
    if tip == 0 {
        return Response::json(200, &json!({ "blocks": [] }));
    }
    let list: Vec<Value> = (0..limit).filter_map(|k| start.checked_sub(k)).filter_map(|h| n.chain.blocks.get(h as usize)).map(|b| block_json(b, false)).collect();
    Response::json(200, &json!({ "tip": tip, "blocks": list }))
}

fn block(sh: &Arc<Shared>, arg: &str) -> Response {
    let n = sh.node.lock().unwrap();
    let found = if let Ok(h) = arg.parse::<usize>() {
        n.chain.blocks.get(h)
    } else if let Some(hh) = hash_arg(arg) {
        n.chain.blocks.iter().rev().find(|b| b.header.hash() == hh)
    } else {
        return Response::error(400, "height or hash expected");
    };
    match found {
        Some(b) => Response::json(200, &block_json(b, true)),
        None => Response::error(404, "unknown block"),
    }
}

fn tx(sh: &Arc<Shared>, arg: &str) -> Response {
    let Some(id) = hash_arg(arg) else { return Response::error(400, "64-character hexadecimal transaction id expected") };
    let n = sh.node.lock().unwrap();
    for b in n.chain.blocks.iter().rev() {
        if let Some(t) = b.txs.iter().find(|t| t.id() == id) {
            let mut v = tx_json(t);
            v["status"] = json!("confirmed");
            v["height"] = json!(b.header.height);
            v["confirmations"] = json!(n.chain.height() - b.header.height);
            return Response::json(200, &v);
        }
    }
    if let Some(t) = n.mempool.iter().find(|t| t.id() == id) {
        let mut v = tx_json(t);
        v["status"] = json!("pending");
        return Response::json(200, &v);
    }
    Response::error(404, "unknown transaction")
}

fn account(sh: &Arc<Shared>, arg: &str) -> Response {
    let pk = match parse_address(arg) {
        Ok(p) => p,
        Err(e) => return Response::error(400, &e),
    };
    let n = sh.node.lock().unwrap();
    let pending = n.mempool.iter().filter(|t| t.tx.from == pk).count() as u64;
    let nonce = n.chain.state.nonce(&pk);
    let r = n.chain.state.reputation(&pk);
    Response::json(
        200,
        &json!({
            "address": address_of(&pk), "balance": amount(n.chain.state.balance(&pk)), "balance_base_units": n.chain.state.balance(&pk).to_string(),
            "nonce": nonce, "next_nonce": nonce + pending,
            "reputation": { "done": r.done, "slashed": r.slashed, "expired": r.expired },
        }),
    )
}

fn job_core(sh: &Arc<Shared>, arg: &str) -> Response {
    let Some(id) = hash_arg(arg) else { return Response::error(400, "64-character hexadecimal job id expected") };
    let n = sh.node.lock().unwrap();
    if let Some(j) = n.chain.state.jobs.get(&id) {
        let (status, worker) = match &j.status {
            JobStatus::Claimed { worker, .. } => ("claimed".to_string(), Some(*worker)),
            JobStatus::Posted { worker, .. } => ("posted".to_string(), Some(*worker)),
            other => (format!("{other:?}").to_lowercase(), None),
        };
        return Response::json(
            200,
            &json!({
                "kind": "matrix_product", "id": hex(&id), "status": status, "client": address_of(&j.client),
                "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(j.escrow_net), "deadline_height": j.deadline,
                "auction_end_ts": j.auction_end_ts, "best_bid": j.best_bid.map(|(w, p)| json!({ "worker": address_of(&w), "price": amount(p) })),
                "pending_data_requests": j.fetches.len(), "served_entries": j.served.len(),
            }),
        );
    }
    if let Some(j) = n.chain.state.mlps.get(&id) {
        let (status, worker) = match &j.status {
            MlpStatus::Working { worker, .. } => ("working".to_string(), Some(*worker)),
            MlpStatus::Complete { worker, .. } => ("complete".to_string(), Some(*worker)),
            other => (format!("{other:?}").split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_lowercase(), None),
        };
        return Response::json(
            200,
            &json!({
                "kind": "inference", "id": hex(&id), "status": status, "client": address_of(&j.client),
                "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(j.escrow_net), "deadline_height": j.deadline,
                "layers_total": j.w_roots.len(), "layers_posted": j.layers.len(),
            }),
        );
    }
    if let Some(j) = n.chain.state.progs.get(&id) {
        use crate::prog::ProgStatus;
        let (status, worker) = match &j.status {
            ProgStatus::Working { worker, .. } => ("working".to_string(), Some(*worker)),
            ProgStatus::Complete { worker, .. } => ("complete".to_string(), Some(*worker)),
            other => (format!("{other:?}").split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_lowercase(), None),
        };
        return Response::json(
            200,
            &json!({
                "kind": "tensor_program", "id": hex(&id), "status": status, "client": address_of(&j.client),
                "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(j.escrow_net), "deadline_height": j.deadline,
                "operations": j.ops.len(), "operations_posted": j.posted.len(), "gemms": j.gemm_count(),
            }),
        );
    }
    if let Some(j) = n.chain.state.tiled.get(&id) {
        use crate::tiled::TiledStatus;
        let (status, worker) = match &j.status {
            TiledStatus::Claimed { worker, .. } => ("claimed".to_string(), Some(*worker)),
            TiledStatus::Posted { worker, .. } => ("posted".to_string(), Some(*worker)),
            other => (format!("{other:?}").split(|c: char| c == ' ' || c == '{').next().unwrap_or("").to_lowercase(), None),
        };
        return Response::json(
            200,
            &json!({
                "kind": "tiled_matrix_product", "id": hex(&id), "status": status, "client": address_of(&j.client),
                "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(j.escrow_net), "deadline_height": j.deadline,
                "blocks": [j.dims.0, j.dims.1, j.dims.2], "products": j.products(),
            }),
        );
    }
    if let Some(j) = n.chain.state.l2.get(&id) {
        use crate::l2::L2Status;
        let (status, worker) = match &j.status {
            L2Status::Claimed { worker, .. } => ("claimed".to_string(), Some(*worker)),
            L2Status::Posted { worker, .. } => ("posted".to_string(), Some(*worker)),
            other => (word(other), None),
        };
        return Response::json(
            200,
            &json!({
                "kind": "level2", "id": hex(&id), "status": status, "client": address_of(&j.client),
                "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(j.escrow_net), "deadline_height": j.deadline,
                "kernel": kernel_name(&j.kernel), "chunks": j.chunks, "pending_data_requests": j.fetches.len(),
            }),
        );
    }
    Response::error(404, "unknown job")
}

fn ev_json(e: &crate::index::Event) -> Value {
    json!({ "height": e.height, "time": e.ts, "what": e.what, "by": address_of(&e.by), "tx": e.tx.map(|t| hex(&t)) })
}

/// Per-day totals (UTC days), newest first. `days` <= 366.
fn stats_daily(sh: &Arc<Shared>, q: &str) -> Response {
    let days = query_get(q, "days").and_then(|v| v.parse::<usize>().ok()).unwrap_or(30).clamp(1, 366);
    let n = sh.node.lock().unwrap();
    let mut ix = sh.index.lock().unwrap();
    ix.sync(&n.chain);
    let rows: Vec<Value> = ix
        .days
        .iter()
        .rev()
        .take(days)
        .map(|(d, s)| {
            json!({
                "day": crate::genesis::fmt_utc(d * 86_400).split(' ').next().unwrap_or(""), "day_start": d * 86_400,
                "blocks": s.blocks, "paid_blocks": s.paid_blocks, "txs": s.txs, "miners": s.miners.len(),
                "jobs_submitted": s.jobs_submitted, "jobs_closed": s.jobs_closed, "fraud_proofs": s.fraud_proofs,
                "transfer_volume": amount(s.volume.min(u64::MAX as u128) as u64), "fees": amount(s.fees.min(u64::MAX as u128) as u64),
                "base_rewards": amount(s.rewards.min(u64::MAX as u128) as u64),
            })
        })
        .collect();
    Response::json(200, &json!({ "days": rows, "blocks_indexed": ix.len() }))
}

/// Job events, newest first. Filters: `what` (comma separated, e.g. `fraud_proof,slash_unserved`), `limit` (<= 200).
fn events(sh: &Arc<Shared>, q: &str) -> Response {
    let limit = query_get(q, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50).clamp(1, 200);
    let what: Vec<&str> = query_get(q, "what").unwrap_or("").split(',').filter(|s| !s.is_empty()).collect();
    let n = sh.node.lock().unwrap();
    let mut ix = sh.index.lock().unwrap();
    ix.sync(&n.chain);
    let rows: Vec<Value> = ix
        .recent
        .iter()
        .rev()
        .filter(|(_, _, e)| what.is_empty() || what.contains(&e.what))
        .take(limit)
        .map(|(job, kind, e)| {
            let mut v = ev_json(e);
            v["job"] = json!(hex(job));
            v["kind"] = json!(kind);
            v
        })
        .collect();
    Response::json(200, &json!({ "events": rows }))
}

/// `/api/job/{id}` with its history (when the job was submitted, claimed, posted, settled, who mined for it).
fn job(sh: &Arc<Shared>, arg: &str) -> Response {
    let r = job_core(sh, arg);
    if r.status != 200 {
        return r;
    }
    let Ok(mut v) = serde_json::from_slice::<Value>(&r.body) else { return r };
    if let Some(id) = hash_arg(arg) {
        let n = sh.node.lock().unwrap();
        let mut ix = sh.index.lock().unwrap();
        ix.sync(&n.chain);
        if let Some(evs) = ix.jobs.get(&id) {
            if let Some(first) = evs.iter().find(|e| e.what == "submitted") {
                v["created_height"] = json!(first.height);
                v["created_time"] = json!(first.ts);
            }
            v["history"] = Value::Array(evs.iter().map(ev_json).collect());
        }
    }
    Response::json(200, &v)
}

fn kernel_name(k: &crate::l2::Kernel) -> &'static str {
    match k {
        crate::l2::Kernel::MonteCarlo(_) => "monte_carlo",
        crate::l2::Kernel::Render(_) => "render",
        crate::l2::Kernel::Render2(_) => "render2",
        crate::l2::Kernel::Render3(_) => "render3",
    }
}

/// First word of the Debug form of a status, in lower case ("Claimed { .. }" -> "claimed").
fn word<T: std::fmt::Debug>(s: &T) -> String {
    format!("{s:?}").split(|c: char| c == ' ' || c == '{' || c == '(').next().unwrap_or("").to_lowercase()
}

/// All jobs of every kind, newest deadline first. Filters: `kind` (matrix_product, inference, tensor_program, tiled_matrix_product,
/// level2), `status`; paging: `limit` (<= 200), `offset`.
fn jobs(sh: &Arc<Shared>, q: &str) -> Response {
    use crate::l2::L2Status;
    use crate::prog::ProgStatus;
    use crate::tiled::TiledStatus;
    let kind_f = query_get(q, "kind").filter(|k| !k.is_empty());
    let status_f = query_get(q, "status").filter(|k| !k.is_empty());
    let limit = query_get(q, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50).clamp(1, 200);
    let offset = query_get(q, "offset").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let n = sh.node.lock().unwrap();
    let mut ix = sh.index.lock().unwrap();
    ix.sync(&n.chain);
    let st = &n.chain.state;
    let mut rows: Vec<(u64, Value)> = Vec::new();
    let mut push = |kind: &str, id: &Hash, status: String, client: &PubKey, worker: Option<PubKey>, escrow: u64, deadline: u64, extra: Value| {
        let created = ix.jobs.get(id).and_then(|e| e.iter().find(|x| x.what == "submitted"));
        let mut v = json!({ "kind": kind, "id": hex(id), "status": status, "client": address_of(client), "worker": worker.map(|w| address_of(&w)), "escrow_net": amount(escrow), "deadline_height": deadline, "created_height": created.map(|c| c.height), "created_time": created.map(|c| c.ts) });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, x) in e {
                o.insert(k.clone(), x.clone());
            }
        }
        rows.push((created.map_or(0, |c| c.height), v));
    };
    for (id, j) in st.jobs.iter() {
        let w = match &j.status {
            JobStatus::Claimed { worker, .. } | JobStatus::Posted { worker, .. } => Some(*worker),
            _ => None,
        };
        push("matrix_product", id, word(&j.status), &j.client, w, j.escrow_net, j.deadline, json!({}));
    }
    for (id, j) in st.mlps.iter() {
        let w = match &j.status {
            MlpStatus::Working { worker, .. } | MlpStatus::Complete { worker, .. } => Some(*worker),
            _ => None,
        };
        push("inference", id, word(&j.status), &j.client, w, j.escrow_net, j.deadline, json!({ "layers": j.w_roots.len() }));
    }
    for (id, j) in st.progs.iter() {
        let w = match &j.status {
            ProgStatus::Working { worker, .. } | ProgStatus::Complete { worker, .. } => Some(*worker),
            _ => None,
        };
        push("tensor_program", id, word(&j.status), &j.client, w, j.escrow_net, j.deadline, json!({ "operations": j.ops.len() }));
    }
    for (id, j) in st.tiled.iter() {
        let w = match &j.status {
            TiledStatus::Claimed { worker, .. } | TiledStatus::Posted { worker, .. } => Some(*worker),
            _ => None,
        };
        push("tiled_matrix_product", id, word(&j.status), &j.client, w, j.escrow_net, j.deadline, json!({ "products": j.products() }));
    }
    for (id, j) in st.l2.iter() {
        let w = match &j.status {
            L2Status::Claimed { worker, .. } | L2Status::Posted { worker, .. } => Some(*worker),
            _ => None,
        };
        push("level2", id, word(&j.status), &j.client, w, j.escrow_net, j.deadline, json!({ "kernel": kernel_name(&j.kernel), "chunks": j.chunks }));
    }
    let mut counts = serde_json::Map::new();
    let mut by_status = serde_json::Map::new();
    for (_, v) in &rows {
        let k = v["kind"].as_str().unwrap_or("").to_string();
        let s = v["status"].as_str().unwrap_or("").to_string();
        let c = counts.entry(k).or_insert(json!(0));
        *c = json!(c.as_u64().unwrap_or(0) + 1);
        let c = by_status.entry(s).or_insert(json!(0));
        *c = json!(c.as_u64().unwrap_or(0) + 1);
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1["id"].as_str().cmp(&b.1["id"].as_str())));
    let list: Vec<Value> = rows
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| kind_f.map_or(true, |k| v["kind"] == k) && status_f.map_or(true, |s| v["status"] == s))
        .collect();
    let total = list.len();
    let page: Vec<Value> = list.into_iter().skip(offset).take(limit).collect();
    Response::json(200, &json!({ "total": total, "counts": counts, "by_status": by_status, "jobs": page }))
}

/// Who mined the last `window` blocks (<= 20,000): blocks, share, blocks that carried paid work, reward at the base rate.
fn miners(sh: &Arc<Shared>, q: &str) -> Response {
    let window = query_get(q, "window").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1000).clamp(1, 20_000);
    let n = sh.node.lock().unwrap();
    let mut by: std::collections::HashMap<PubKey, (u64, u64, u64, u64)> = std::collections::HashMap::new(); // blocks, useful, last height, reward
    let mut total = 0u64;
    for b in n.chain.blocks.iter().rev().take(window) {
        let e = by.entry(b.header.miner).or_insert((0, 0, 0, 0));
        e.0 += 1;
        if !matches!(b.header.class, WorkClass::Native) {
            e.1 += 1;
        }
        e.2 = e.2.max(b.header.height);
        e.3 += base_reward(b.header.height);
        total += 1;
    }
    let mut rows: Vec<(PubKey, (u64, u64, u64, u64))> = by.into_iter().collect();
    rows.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
    let list: Vec<Value> = rows
        .iter()
        .take(100)
        .map(|(pk, (blocks, useful, last, reward))| {
            json!({ "address": address_of(pk), "blocks": blocks, "share": if total > 0 { *blocks as f64 / total as f64 } else { 0.0 }, "useful_blocks": useful, "last_height": last, "reward": amount(*reward), "reputation": { "done": n.chain.state.reputation(pk).done, "slashed": n.chain.state.reputation(pk).slashed } })
        })
        .collect();
    Response::json(200, &json!({ "window": window, "blocks": total, "distinct_miners": rows.len(), "miners": list }))
}

/// Largest balances.
fn accounts(sh: &Arc<Shared>, q: &str) -> Response {
    let limit = query_get(q, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50).clamp(1, 200);
    let n = sh.node.lock().unwrap();
    let st = &n.chain.state;
    let mut rows: Vec<(&PubKey, u64, u64)> = st.accounts.iter().filter(|(_, a)| a.balance > 0).map(|(k, a)| (k, a.balance, a.nonce)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let held: u64 = rows.iter().map(|r| r.1).sum();
    let list: Vec<Value> = rows.iter().take(limit).map(|(k, bal, nonce)| json!({ "address": address_of(k), "balance": amount(*bal), "share": if held > 0 { *bal as f64 / held as f64 } else { 0.0 }, "nonce": nonce })).collect();
    Response::json(200, &json!({ "holders": rows.len(), "held": amount(held), "accounts": list }))
}

/// Compact per-block series for the charts (last `blocks` blocks, <= 1000, oldest first).
fn chart(sh: &Arc<Shared>, q: &str) -> Response {
    let count = query_get(q, "blocks").and_then(|v| v.parse::<usize>().ok()).unwrap_or(120).clamp(1, 1000);
    let n = sh.node.lock().unwrap();
    let len = n.chain.blocks.len();
    let from = len.saturating_sub(count);
    let (mut heights, mut times, mut txs, mut classes, mut targets, mut miners) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    let mut seen: Vec<String> = Vec::new();
    for b in &n.chain.blocks[from..] {
        let h = &b.header;
        heights.push(h.height);
        times.push(h.timestamp);
        txs.push(b.txs.len());
        classes.push(match h.class {
            WorkClass::Native => 0,
            WorkClass::Job(_) => 1,
            WorkClass::Layer { .. } => 2,
            WorkClass::Op { .. } => 3,
            WorkClass::Product { .. } => 4,
        });
        targets.push(h.target.to_string());
        let a = address_of(&h.miner);
        let idx = match seen.iter().position(|x| *x == a) {
            Some(i) => i,
            None => {
                seen.push(a);
                seen.len() - 1
            }
        };
        miners.push(idx);
    }
    Response::json(200, &json!({ "heights": heights, "timestamps": times, "txs": txs, "classes": classes, "targets": targets, "miners": miners, "miner_addresses": seen }))
}

/// Resolves what a search box typed: a height, a 64-hex block hash / transaction id / job id, or an address.
fn search(sh: &Arc<Shared>, q: &str) -> Response {
    let raw = query_get(q, "q").unwrap_or("").trim().to_string();
    let n = sh.node.lock().unwrap();
    if raw.is_empty() {
        return Response::error(400, "empty query");
    }
    if raw.len() <= 12 {
        if let Ok(h) = raw.parse::<usize>() {
            return if h < n.chain.blocks.len() { Response::json(200, &json!({ "type": "block", "id": h.to_string() })) } else { Response::error(404, "no such block height") };
        }
    }
    if let Some(id) = hash_arg(&raw) {
        if n.chain.blocks.iter().rev().any(|b| b.header.hash() == id) {
            return Response::json(200, &json!({ "type": "block", "id": hex(&id) }));
        }
        if n.chain.blocks.iter().rev().any(|b| b.txs.iter().any(|t| t.id() == id)) || n.mempool.iter().any(|t| t.id() == id) {
            return Response::json(200, &json!({ "type": "tx", "id": hex(&id) }));
        }
        let st = &n.chain.state;
        if st.jobs.contains_key(&id) || st.mlps.contains_key(&id) || st.progs.contains_key(&id) || st.tiled.contains_key(&id) || st.l2.contains_key(&id) {
            return Response::json(200, &json!({ "type": "job", "id": hex(&id) }));
        }
        return Response::error(404, "nothing found for this identifier");
    }
    match parse_address(&raw) {
        Ok(pk) => Response::json(200, &json!({ "type": "address", "id": address_of(&pk) })),
        Err(_) => Response::error(404, "not a height, a 64-character hexadecimal identifier or a Vearl address"),
    }
}


/// History of an address: transactions sent or received (transfers), most recent first; pending ones come first.
/// Backward walk over the blocks, bounded (no index: enough for a testnet).
fn address_txs(sh: &Arc<Shared>, arg: &str, q: &str) -> Response {
    let pk = match parse_address(arg) {
        Ok(p) => p,
        Err(e) => return Response::error(400, &e),
    };
    let limit = query_get(q, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(25).clamp(1, 100);
    let involves = |t: &SignedTx| t.tx.from == pk || matches!(&t.tx.kind, TxKind::Transfer { to, .. } if *to == pk);
    let n = sh.node.lock().unwrap();
    let tip = n.chain.height();
    let mut out: Vec<Value> = n
        .mempool
        .iter()
        .filter(|t| involves(t))
        .map(|t| {
            let mut v = tx_json(t);
            v["status"] = json!("pending");
            v["direction"] = json!(if t.tx.from == pk { "out" } else { "in" });
            v
        })
        .collect();
    'scan: for b in n.chain.blocks.iter().rev().take(200_000) {
        for t in b.txs.iter().rev().filter(|t| involves(t)) {
            if out.len() >= limit {
                break 'scan;
            }
            let mut v = tx_json(t);
            v["status"] = json!("confirmed");
            v["height"] = json!(b.header.height);
            v["confirmations"] = json!(tip - b.header.height);
            v["direction"] = json!(if t.tx.from == pk { "out" } else { "in" });
            out.push(v);
        }
    }
    Response::json(200, &json!({ "address": address_of(&pk), "txs": out }))
}

/// Long poll: answers as soon as the height exceeds `height`, or after `timeout` seconds (<= 25). Avoids polling.
fn wait_for_block(sh: &Arc<Shared>, q: &str) -> Response {
    let Some(h) = query_get(q, "height").and_then(|v| v.parse::<u64>().ok()) else { return Response::error(400, "parameter 'height' required") };
    let timeout = query_get(q, "timeout").and_then(|v| v.parse::<u64>().ok()).unwrap_or(25).min(25);
    if WAITERS.fetch_add(1, Ordering::SeqCst) >= MAX_WAITERS {
        WAITERS.fetch_sub(1, Ordering::SeqCst);
        return Response::error(429, "too many simultaneous waits");
    }
    let start = Instant::now();
    let resp = loop {
        {
            let n = sh.node.lock().unwrap();
            if n.chain.height() > h || start.elapsed() >= Duration::from_secs(timeout) {
                break Response::json(200, &json!({ "height": n.chain.height(), "tip": hex(&n.chain.tip_hash()), "timed_out": n.chain.height() <= h }));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    WAITERS.fetch_sub(1, Ordering::SeqCst);
    resp
}

fn mempool(sh: &Arc<Shared>) -> Response {
    let n = sh.node.lock().unwrap();
    Response::json(200, &json!({ "count": n.mempool.len(), "txs": n.mempool.iter().take(100).map(tx_json).collect::<Vec<_>>() }))
}

fn post_tx(sh: &Arc<Shared>, body: &[u8]) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return Response::error(400, "JSON body expected: {\"hex\": \"...\"}") };
    let Some(bytes) = v.get("hex").and_then(|h| h.as_str()).and_then(unhex) else { return Response::error(400, "invalid field 'hex'") };
    let Ok(stx) = bincode::deserialize::<SignedTx>(&bytes) else { return Response::error(400, "unreadable transaction") };
    match submit_tx(sh, stx.clone()) {
        Ok(()) => Response::json(200, &json!({ "accepted": true, "id": hex(&stx.id()) })),
        Err(e) => Response::json(400, &json!({ "accepted": false, "error": e })),
    }
}

/// Answers from the cache when the chain tip has not moved since the same URL was computed: the heavy read routes depend on the chain
/// only, so a crowd of visitors costs one computation per block. The cache holds at most 128 URLs.
fn cached(sh: &Arc<Shared>, req: &Request, f: fn(&Arc<Shared>, &str) -> Response) -> Response {
    let key = format!("{}?{}", req.path, req.query);
    let tip = sh.node.lock().unwrap().chain.tip_hash();
    if let Some((t, status, ct, body)) = sh.cache.lock().unwrap().get(&key) {
        if *t == tip {
            return Response { status: *status, content_type: ct, body: body.clone() };
        }
    }
    let r = f(sh, &req.query);
    if r.status == 200 {
        let mut c = sh.cache.lock().unwrap();
        if c.len() >= 128 {
            c.clear();
        }
        c.insert(key, (tip, r.status, r.content_type, r.body.clone()));
    }
    r
}

pub fn route(sh: &Arc<Shared>, req: Request) -> Response {
    match req.method.as_str() {
        "GET" => match req.path.as_str() {
            "/" | "/index.html" => Response::html(EXPLORER_HTML),
            "/api/status" => status(sh),
            "/api/blocks" => blocks(sh, &req.query),
            "/api/mempool" => mempool(sh),
            "/api/workers" => workers(sh, &req),
            "/api/jobs" => cached(sh, &req, jobs),
            "/api/miners" => cached(sh, &req, miners),
            "/api/accounts" => cached(sh, &req, accounts),
            "/api/chart" => cached(sh, &req, chart),
            "/api/stats/daily" => cached(sh, &req, stats_daily),
            "/api/events" => cached(sh, &req, events),
            "/api/search" => search(sh, &req.query),
            "/api/wait" => wait_for_block(sh, &req.query),
            "/api/fee/beacons" => {
                // reserved to the local auditor: the seed only reads on the loopback interface, and the public proxy (which sets X-Real-IP) gives no access to it
                let local = req.peer.parse::<std::net::IpAddr>().map_or(false, |ip| ip.is_loopback());
                if crate::feeguard::collecting() && local {
                    Response::json(200, &crate::feeguard::beacons_json(crate::net::now_secs()))
                } else {
                    Response::error(404, "not found")
                }
            }
            p if p.starts_with("/api/block/") => block(sh, &p["/api/block/".len()..]),
            p if p.starts_with("/api/tx/") => tx(sh, &p["/api/tx/".len()..]),
            p if p.starts_with("/api/address/") && p.ends_with("/txs") => address_txs(sh, &p["/api/address/".len()..p.len() - "/txs".len()], &req.query),
            p if p.starts_with("/api/account/") => account(sh, &p["/api/account/".len()..]),
            p if p.starts_with("/api/job/") => job(sh, &p["/api/job/".len()..]),
            _ => Response::error(404, "unknown route"),
        },
        "POST" if req.path == "/api/tx" => post_tx(sh, &req.body),
        "POST" => Response::error(404, "unknown route"),
        _ => Response::error(405, "method not allowed"),
    }
}

/// Starts the API. Returns the address actually bound.
pub fn spawn_api(sh: Arc<Shared>, addr: &str) -> io::Result<String> {
    serve(addr, move |req| route(&sh, req))
}
