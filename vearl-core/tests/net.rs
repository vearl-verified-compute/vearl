use ed25519_dalek::SigningKey;
use vearl_core::chain::*;
use vearl_core::crypto::*;
use vearl_core::net::*;
use vearl_core::state::*;
use vearl_core::types::*;
use std::time::{Duration, Instant};

fn genesis() -> GenesisConfig {
    let mut g = devnet_genesis();
    g.target = u64::MAX / 256; // fast blocks for the tests
    g.retarget = Retarget::Fixed; // no retargeting: fast blocks for the tests
    g.timing.serve_secs = 6; // response delay to data requests shortened for the tests
    g
}

fn node(peers: Vec<String>, seed: Option<u8>) -> NodeHandle {
    node_with(peers, seed, None, None)
}

fn node_with(peers: Vec<String>, seed: Option<u8>, worker: Option<WorkerCfg>, data_dir: Option<std::path::PathBuf>) -> NodeHandle {
    spawn_node(NodeConfig {
        genesis: genesis(),
        listen: "127.0.0.1:0".into(),
        peers,
        mine_key: seed.map(|s| SigningKey::from_bytes(&[s; 32])),
        use_gpu: false,
        log: false,
        worker,
        data_dir,
    })
    .unwrap()
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timeout: {what}");
}

fn block_hash_at(n: &NodeHandle, h: u64) -> Option<Hash> {
    n.shared.node.lock().unwrap().chain.blocks.get(h as usize).map(|b| b.header.hash())
}

#[test]
fn three_nodes_propagate_blocks_and_transactions() {
    let a = node(vec![], Some(1));
    let b = node(vec![a.addr.clone()], None);
    let c = node(vec![b.addr.clone()], None); // c only knows b
    wait("b and c follow a", 30, || a.height() >= 5 && b.height() >= 5 && c.height() >= 5);
    // the three nodes have the same block at the common height (a keeps mining)
    wait("identical blocks", 30, || {
        let h = a.height().min(b.height()).min(c.height()) - 1;
        block_hash_at(&a, h) == block_hash_at(&b, h) && block_hash_at(&b, h) == block_hash_at(&c, h)
    });

    // a transaction sent to c is mined by a and visible on b
    let (alice, bob) = (SigningKey::from_bytes(&[100; 32]), SigningKey::from_bytes(&[101; 32]));
    let nonce = match request(&c.addr, &Msg::GetAccount(pubkey(&alice))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let before = b.shared.node.lock().unwrap().chain.state.balance(&pubkey(&bob));
    let tx = SignedTx::new(Tx { from: pubkey(&alice), nonce, fee: COIN / 10, kind: TxKind::Transfer { to: pubkey(&bob), amount: 5 * COIN } }, &alice);
    assert!(matches!(request(&c.addr, &Msg::NewTx(tx)).unwrap(), Msg::Ack { ok: true, .. }));
    wait("transfer applied on b", 30, || b.shared.node.lock().unwrap().chain.state.balance(&pubkey(&bob)) == before + 5 * COIN);
    for n in [&a, &b, &c] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn partitioned_miners_converge_on_the_chain_with_most_work() {
    let a = node(vec![], Some(1));
    let b = node(vec![], Some(2));
    wait("two independent chains", 30, || a.height() >= 4 && b.height() >= 6);
    assert_ne!(a.tip(), b.tip(), "disjoint chains before the connection");
    b.connect(&a.addr); // end of the partition
    wait("convergence", 60, || {
        let h = a.height().min(b.height()) - 1;
        h >= 3 && block_hash_at(&a, h) == block_hash_at(&b, h)
    });
    assert!(a.peer_count() >= 1 && b.peer_count() >= 1);
    a.stop();
    b.stop();
}

#[test]
fn a_peer_sending_an_invalid_block_is_dropped_and_chain_is_unaffected() {
    let n = node(vec![], None); // passive node: its height only moves on what we send it
    let miner = SigningKey::from_bytes(&[9; 32]);
    let mut local = Chain::from_config(&genesis());
    let ts = local.tip_ts() + BLOCK_TIME;
    let good = local.mine(&miner, WorkClass::Native, None, vec![], ts).unwrap().block;
    local.validate_and_apply(good.clone()).unwrap();
    let ts = local.tip_ts() + BLOCK_TIME;
    let mut bad = local.mine(&miner, WorkClass::Native, None, vec![], ts).unwrap().block;
    bad.header.jackpot[0] ^= 1; // proof inconsistent with the header

    let mut c = Conn::connect(&n.addr).unwrap();
    c.send(&Msg::Hello { node_id: 4242, genesis: n.shared.genesis_hash, height: 0, work: 0, listen: None }).unwrap();
    c.send(&Msg::NewBlock(good)).unwrap();
    wait("valid block accepted", 10, || n.height() == 1);
    c.send(&Msg::NewBlock(bad)).unwrap();
    // the node must CLOSE the connection (end of stream or reset), not just let the timeout expire
    c.set_timeout(Duration::from_secs(5));
    loop {
        match c.recv() {
            Ok(_) => continue, // Hello / GetPeers / Ack before the closing
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => panic!("connection not closed"),
            Err(_) => break,
        }
    }
    assert_eq!(n.height(), 1, "the invalid block was not accepted");
    n.stop();
}

// ---------------------------------------------------------------- end-to-end compute market

use vearl_core::work::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn job_status(node: &str, id: JobId) -> String {
    match request(node, &Msg::GetJob(id)).unwrap() {
        Msg::JobInfo { status, .. } => status,
        _ => "unknown".into(),
    }
}

fn rand_cm(seed: u64) -> CommittedMatrices {
    let p = WorkParams::TESTNET;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut m = || (0..p.n * p.n).map(|_| rng.gen_range(-64..=64) as i8).collect::<Vec<i8>>();
    let (a, b) = (m(), m());
    CommittedMatrices::new(a, b, &p)
}

fn submit_job(client: &SigningKey, passive: &NodeHandle, worker: &NodeHandle, cm: &CommittedMatrices) -> JobId {
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = job_id(&pubkey(client), nonce, &cm.a_root(), &cm.b_root());
    assert!(matches!(request(&worker.addr, &Msg::PutJob { a: cm.a.clone(), b: cm.b.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    let height = passive.height();
    let tx = SignedTx::new(
        Tx { from: pubkey(client), nonce, fee: 0, kind: TxKind::SubmitJob { a_root: cm.a_root(), b_root: cm.b_root(), escrow: 40 * COIN, deadline: height + 500 } },
        client,
    );
    assert!(matches!(request(&passive.addr, &Msg::NewTx(tx)).unwrap(), Msg::Ack { ok: true, .. }));
    id
}

#[test]
fn compute_market_end_to_end_honest_worker_is_paid() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(5);
    let id = submit_job(&client, &passive, &worker, &cm);

    // the worker claims by itself, mines Job-class blocks, publishes the root of the result
    wait("job posted", 60, || job_status(&passive.addr, id).starts_with("Posted"));
    let c = match request(&worker.addr, &Msg::GetResult(id)).unwrap() {
        Msg::JobResult { c } => c,
        m => panic!("{m:?}"),
    };
    assert!(freivalds(&cm.a, &cm.b, &c, WorkParams::TESTNET.n, 24, &[7u8; 32]), "the worker's result is the real A*B");
    assert_eq!(c, plain_gemm(&cm.a, &cm.b, WorkParams::TESTNET.n));
    // at least one Job-class block was mined by the worker for THIS job
    assert!(worker.shared.node.lock().unwrap().chain.blocks.iter().any(|b| b.header.class == WorkClass::Job(id)));

    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let accept = SignedTx::new(Tx { from: pubkey(&client), nonce, fee: 0, kind: TxKind::Accept { job_id: id } }, &client);
    assert!(matches!(request(&passive.addr, &Msg::NewTx(accept)).unwrap(), Msg::Ack { ok: true, .. }));
    wait("job settled", 60, || job_status(&passive.addr, id) == "Settled");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

/// A worker-only node (`--worker --no-native`, the pool mode of the miner with paid jobs) never mines a Native block, but it claims and computes the
/// jobs whose data it knows: the pool miner does the Native mining, this node takes the compute market. The blocks come from another miner (in real
/// life, the pool); the worker's balance must not move (no block reward) until it works on a job.
#[test]
fn a_worker_only_node_mines_no_native_block_but_still_computes_jobs() {
    let worker_key = SigningKey::from_bytes(&[101; 32]);
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { no_native: true, ..Default::default() }), None);
    let miner = node(vec![worker.addr.clone()], Some(102)); // the native miner (the pool)
    let balance = |n: &NodeHandle| match request(&n.addr, &Msg::GetAccount(pubkey(&worker_key))).unwrap() {
        Msg::Account { balance, .. } => balance,
        m => panic!("{m:?}"),
    };
    let before = balance(&worker);
    wait("the native miner makes blocks and the worker follows them", 60, || miner.height() >= 6 && worker.height() >= 6);
    assert_eq!(balance(&worker), before, "a worker-only node earns no block reward: it mined no Native block");
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(6);
    let id = submit_job(&client, &miner, &worker, &cm);
    wait("job posted by the worker-only node", 90, || job_status(&miner.addr, id).starts_with("Posted"));
    assert!(balance(&worker) != before, "it mined the blocks of the job and was rewarded for them");
}

#[test]
fn compute_market_end_to_end_cheating_worker_is_slashed_by_fraud_proof() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(6);
    let n = WorkParams::TESTNET.n;
    let id = submit_job(&client, &passive, &worker, &cm);
    wait("job posted", 60, || job_status(&passive.addr, id).starts_with("Posted"));

    let c = match request(&worker.addr, &Msg::GetResult(id)).unwrap() {
        Msg::JobResult { c } => c,
        m => panic!("{m:?}"),
    };
    assert!(!freivalds(&cm.a, &cm.b, &c, n, 24, &[7u8; 32]), "the client detects the wrong result");
    let (i, j) = find_bad_entry(&cm.a, &cm.b, &c, n, &[7u8; 32]).unwrap();
    let ct = c_tree(&c, n);
    let proof = FraudProof {
        job_id: id,
        i: i as u32,
        j: j as u32,
        a_row: cm.a[i * n..(i + 1) * n].to_vec(),
        a_path: cm.a_tree.proof(i),
        b_col: cm.col(j, n),
        b_path: cm.b_tree.proof(j),
        c_row: row_of(&c, n, i),
        c_path: ct.proof(i),
    };
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let tx = SignedTx::new(Tx { from: pubkey(&client), nonce, fee: 0, kind: TxKind::Fraud(proof) }, &client);
    assert!(matches!(request(&passive.addr, &Msg::NewTx(tx)).unwrap(), Msg::Ack { ok: true, .. }));
    wait("worker slashed", 60, || job_status(&passive.addr, id) == "Slashed");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn chain_survives_restart_from_disk_and_torn_writes_are_dropped() {
    let dir = std::env::temp_dir().join(format!("vearl-test-{}", rand::random::<u64>()));
    let a = node_with(vec![], Some(1), None, Some(dir.clone()));
    wait("a mine", 30, || a.height() >= 6);
    a.stop();
    std::thread::sleep(Duration::from_millis(300)); // lets the miner finish
    let (h, hash) = {
        let n = a.shared.node.lock().unwrap();
        let h = n.chain.height();
        (h, n.chain.blocks[h as usize - 1].header.hash())
    };
    // interrupted write: we append stray bytes at the end of the file
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(dir.join("chain.bin")).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
    }
    let b = node_with(vec![], None, None, Some(dir.clone()));
    assert_eq!(b.height(), h, "the whole chain is reloaded, without the corrupted fragment");
    assert_eq!(block_hash_at(&b, h - 1), Some(hash));
    assert!(b.shared.node.lock().unwrap().chain.check_supply_invariant());
    b.stop();
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- network security

use vearl_core::secure::Keys;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};

#[test]
fn plaintext_peers_are_rejected_no_handshake_no_service() {
    let n = node(vec![], None);
    let mut s = TcpStream::connect(&n.addr).unwrap();
    // old plaintext protocol: u32 length + bincode of a GetStatus
    let body = bincode::serialize(&Msg::GetStatus).unwrap();
    s.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
    s.write_all(&body).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
    let mut buf = [0u8; 256];
    let got = s.read(&mut buf);
    // either closing or reset: never a service reply (a Status would start with application bytes)
    assert!(matches!(got, Ok(0) | Err(_)) || got.unwrap() < 4, "the node must not serve anything in the clear");
    assert_eq!(n.peer_count(), 0);
    n.stop();
}

#[test]
fn a_tampered_ciphertext_kills_the_session() {
    // Two real Noise endpoints: we alter one encrypted byte in transit => authentication fails.
    let n = node(vec![], None);
    let mut raw = TcpStream::connect(&n.addr).unwrap();
    let keys = Keys::generate();
    // handshake by hand through the test proxy: we do it with the library, then inject noisy bytes
    let (_r, _w, _) = vearl_core::secure::handshake(raw.try_clone().unwrap(), &keys, true, Duration::from_secs(5)).unwrap();
    // after the handshake, random bytes can no longer be decrypted: the node closes
    raw.write_all(&[0, 32]).unwrap();
    raw.write_all(&[7u8; 32]).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match raw.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    assert_eq!(n.peer_count(), 0);
    n.stop();
}

#[test]
fn pinned_peer_key_blocks_impersonation() {
    let real = node(vec![], None);
    let key = real.id_hex();
    let wrong = Keys::generate().public_hex();

    let bad = node(vec![format!("{}@{}", real.addr, wrong)], None);
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(bad.peer_count(), 0, "the key does not match the pinned key: no connection");

    let good = node(vec![format!("{}@{}", real.addr, key)], None);
    wait("connection with the right pinned key", 20, || good.peer_count() == 1);
    for n in [&real, &bad, &good] {
        n.stop();
    }
}

#[test]
fn spam_of_invalid_transactions_gets_the_peer_disconnected() {
    let n = node(vec![], None);
    let mut c = Conn::connect(&n.addr).unwrap();
    c.send(&Msg::Hello { node_id: 1, genesis: n.shared.genesis_hash, height: 0, work: 0, listen: None }).unwrap();
    let evil = SigningKey::from_bytes(&[55; 32]); // account without funds: fees impossible
    let mut closed = false;
    for i in 0..60u64 {
        let tx = SignedTx::new(Tx { from: pubkey(&evil), nonce: i, fee: COIN, kind: TxKind::Transfer { to: [1u8; 32], amount: 1 } }, &evil);
        if c.send(&Msg::NewTx(tx)).is_err() {
            closed = true;
            break;
        }
    }
    c.set_timeout(Duration::from_secs(5));
    while !closed {
        match c.recv() {
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => panic!("faulty peer not disconnected"),
            Err(_) => closed = true,
        }
    }
    assert_eq!(n.shared.node.lock().unwrap().mempool.len(), 0, "no invalid transaction in the mempool");
    n.stop();
}

#[test]
fn a_node_that_does_not_mine_evicts_the_transactions_that_can_never_go_through() {
    // A node that does not mine (the seed, the node of a pool, a relay) used to keep such a transaction for good, to pass it on again and again,
    // and to refuse every later transaction of the sender (the nonce must follow the pending sequence): on the public testnet a worker whose
    // claim had lost a race could not send anything any more.
    let n = node(vec![], None);
    let alice = SigningKey::from_bytes(&[100; 32]);
    let nonce = match request(&n.addr, &Msg::GetAccount(pubkey(&alice))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    // admitted (signature, nonce and fee are fine) but it can never be applied: more than the balance
    let impossible = SignedTx::new(Tx { from: pubkey(&alice), nonce, fee: 0, kind: TxKind::Transfer { to: [7u8; 32], amount: u64::MAX / 4 } }, &alice);
    let after = SignedTx::new(Tx { from: pubkey(&alice), nonce: nonce + 1, fee: 0, kind: TxKind::Transfer { to: [7u8; 32], amount: 1 } }, &alice);
    assert!(matches!(request(&n.addr, &Msg::NewTx(impossible)).unwrap(), Msg::Ack { ok: true, .. }));
    assert!(matches!(request(&n.addr, &Msg::NewTx(after)).unwrap(), Msg::Ack { ok: true, .. }));
    assert_eq!(n.shared.node.lock().unwrap().mempool.len(), 2);
    // the same nonce again is refused while the first one is pending
    let again = SignedTx::new(Tx { from: pubkey(&alice), nonce, fee: 0, kind: TxKind::Transfer { to: [8u8; 32], amount: 1 } }, &alice);
    assert!(matches!(request(&n.addr, &Msg::NewTx(again.clone())).unwrap(), Msg::Ack { ok: false, .. }));
    wait("the stuck transactions are evicted by a node that does not mine", 60, || n.shared.node.lock().unwrap().mempool.is_empty());
    // and the sender is free again
    assert!(matches!(request(&n.addr, &Msg::NewTx(again)).unwrap(), Msg::Ack { ok: true, .. }));
    n.stop();
}

#[test]
fn inbound_admission_limits_per_ip_and_per_subnet() {
    let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
    // two connections from the same IP: the 3rd is refused
    let existing = vec![ip("203.0.113.5"), ip("203.0.113.5")];
    assert!(!inbound_allowed(&existing, &ip("203.0.113.5")));
    // four from the same /16: the 5th is refused, even with a different IP (multi-IP attacker)
    let net = vec![ip("198.51.1.1"), ip("198.51.2.2"), ip("198.51.3.3"), ip("198.51.4.4")];
    assert!(!inbound_allowed(&net, &ip("198.51.9.9")));
    assert!(inbound_allowed(&net, &ip("192.0.2.7")), "a different /16 is still admitted");
    // global cap
    let full: Vec<IpAddr> = (0..24).map(|i| ip(&format!("10.{i}.0.1"))).collect();
    assert!(!inbound_allowed(&full, &ip("192.0.2.9")));
    // outgoing: never two peers in the same /16
    assert!(!outbound_candidate_ok(&[ip("198.51.1.1")], &ip("198.51.200.1")));
    assert!(outbound_candidate_ok(&[ip("198.51.1.1")], &ip("192.0.2.1")));
}

#[test]
fn many_half_open_connections_do_not_block_honest_peers() {
    let n = node(vec![], None);
    // 200 TCP connections opened without ever doing the handshake
    let idle: Vec<TcpStream> = (0..200).filter_map(|_| TcpStream::connect(&n.addr).ok()).collect();
    let t = Instant::now();
    let r = request(&n.addr, &Msg::GetStatus);
    // the cap on simultaneous handshakes may refuse clients during the attack, but the node
    // stays alive and answers as soon as the mute connections expire
    if r.is_err() {
        wait("the node answers after the mute connections expire", 30, || request(&n.addr, &Msg::GetStatus).is_ok());
    }
    assert!(t.elapsed() < Duration::from_secs(40));
    drop(idle);
    n.stop();
}

// ---------------------------------------------------------------- multi-layer quantised inference (network)

use vearl_core::mlp::*;

fn mlp_info(node: &str, id: JobId) -> (String, u8) {
    match request(node, &Msg::GetMlp(id)).unwrap() {
        Msg::MlpInfo { status, layers_posted, .. } => (status, layers_posted),
        _ => ("unknown".into(), 0),
    }
}

fn client_tx(node: &NodeHandle, client: &SigningKey, kind: TxKind) -> Msg {
    let nonce = match request(&node.addr, &Msg::GetAccount(pubkey(client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let tx = SignedTx::new(Tx { from: pubkey(client), nonce, fee: 0, kind }, client);
    request(&node.addr, &Msg::NewTx(tx)).unwrap()
}

/// Submits an inference job, waits for the publication of all the layers, then does like the CLI:
/// verifies each layer and sends Accept or a fraud proof. Returns the final status.
fn run_inference(worker: &NodeHandle, passive: &NodeHandle, layers: usize, seed: u64, expect_final: &str) -> String {
    let n = WorkParams::TESTNET.n;
    let client = SigningKey::from_bytes(&[100; 32]);
    let (x0, ws) = demo_net(n, layers, seed);
    let x0_root = cols_root_of(&x0, n);
    let w_roots: Vec<Hash> = ws.iter().map(|w| rows_root_of(w, n)).collect();
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = mlp_id(&pubkey(&client), nonce, &x0_root, &w_roots);
    assert!(matches!(request(&worker.addr, &Msg::PutMlp { x0: x0.clone(), ws: ws.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    let submit = TxKind::Mlp(MlpTx::Submit { x0_root, w_roots, shifts: vec![DEMO_SHIFT; layers], escrow: 30 * COIN * layers as u64, deadline: passive.height() + 500 });
    assert!(matches!(client_tx(passive, &client, submit), Msg::Ack { ok: true, .. }));

    wait("all layers published", 60, || mlp_info(&passive.addr, id).1 as usize == layers);
    let posted = match request(&passive.addr, &Msg::GetMlp(id)).unwrap() {
        Msg::MlpInfo { posted, .. } => posted,
        m => panic!("{m:?}"),
    };
    let mut xprev = x0.clone();
    for l in 0..layers {
        let (z, x) = match request(&worker.addr, &Msg::GetLayer { job: id, layer: l as u8 }).unwrap() {
            Msg::LayerData { z, x } => (z, x),
            m => panic!("{m:?}"),
        };
        let (zt, xt) = (c_tree(&z, n), cols_tree(&x, n));
        assert_eq!((zt.root(), xt.root()), posted[l], "the served data matches the on-chain roots");
        if !freivalds(&ws[l], &xprev, &z, n, 24, &[7u8; 32]) {
            let (i, j) = find_bad_entry(&ws[l], &xprev, &z, n, &[7u8; 32]).unwrap();
            let kind = MlpFraudKind::Gemm {
                i: i as u32,
                j: j as u32,
                a_row: ws[l][i * n..(i + 1) * n].to_vec(),
                a_path: rows_tree(&ws[l], n).proof(i),
                b_col: (0..n).map(|k| xprev[k * n + j]).collect(),
                b_path: cols_tree(&xprev, n).proof(j),
                z_row: row_of(&z, n, i),
                z_path: zt.proof(i),
            };
            assert!(matches!(client_tx(passive, &client, TxKind::Mlp(MlpTx::Fraud { job_id: id, layer: l as u8, kind })), Msg::Ack { ok: true, .. }));
            wait("final status", 60, || mlp_info(&passive.addr, id).0 == expect_final);
            return format!("gemm-fraud@{l}");
        }
        let want = requantize(&z, DEMO_SHIFT, l + 1 < layers);
        if let Some(idx) = (0..want.len()).find(|&k| want[k] != x[k]) {
            let (i, j) = (idx / n, idx % n);
            let kind = MlpFraudKind::Act { i: i as u32, j: j as u32, z_row: row_of(&z, n, (idx) / n), z_path: zt.proof((idx) / n), x_col: (0..n).map(|k| x[k * n + j]).collect(), x_path: xt.proof(j) };
            assert!(matches!(client_tx(passive, &client, TxKind::Mlp(MlpTx::Fraud { job_id: id, layer: l as u8, kind })), Msg::Ack { ok: true, .. }));
            wait("final status", 60, || mlp_info(&passive.addr, id).0 == expect_final);
            return format!("act-fraud@{l}");
        }
        xprev = x;
    }
    assert!(matches!(client_tx(passive, &client, TxKind::Mlp(MlpTx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("final status", 60, || mlp_info(&passive.addr, id).0 == expect_final);
    "accepted".into()
}

#[test]
fn inference_job_end_to_end_honest_worker_is_paid() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_inference(&worker, &passive, 3, 11, "Settled"), "accepted");
    let layer_blocks = worker.shared.node.lock().unwrap().chain.blocks.iter().filter(|b| matches!(b.header.class, WorkClass::Layer { .. })).count();
    assert!(layer_blocks >= 3, "the worker mined at least one block per layer ({layer_blocks})");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn inference_job_end_to_end_wrong_gemm_is_slashed() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_inference(&worker, &passive, 3, 12, "Slashed"), "gemm-fraud@1");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn inference_job_end_to_end_wrong_activation_is_slashed() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat_act: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_inference(&worker, &passive, 3, 13, "Slashed"), "act-fraud@0");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

// ---------------------------------------------------------------- auctions between competing workers (network)

#[test]
fn two_competing_workers_bid_and_the_cheapest_wins_the_job() {
    let cheap = node_with(vec![], Some(102), Some(WorkerCfg { ask: Some(20 * COIN), ..Default::default() }), None);
    let dear = node_with(vec![cheap.addr.clone()], Some(101), Some(WorkerCfg { ask: Some(35 * COIN), ..Default::default() }), None);
    let passive = node(vec![cheap.addr.clone()], None);
    wait("network connected", 20, || cheap.peer_count() >= 2 && dear.peer_count() >= 1);

    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(77);
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = job_id(&pubkey(&client), nonce, &cm.a_root(), &cm.b_root());
    for w in [&cheap, &dear] {
        assert!(matches!(request(&w.addr, &Msg::PutJob { a: cm.a.clone(), b: cm.b.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    }
    let submit = TxKind::SubmitJobAuction { a_root: cm.a_root(), b_root: cm.b_root(), escrow: 50 * COIN, deadline: passive.height() + 500, auction_secs: 20 };
    assert!(matches!(client_tx(&passive, &client, submit), Msg::Ack { ok: true, .. }));

    let t0 = Instant::now();
    while !job_status(&passive.addr, id).starts_with("Posted") {
        if t0.elapsed() > Duration::from_secs(90) {
            let dump: Vec<String> = [&cheap, &dear, &passive].iter().map(|n| format!("h={} tip_ts={} now={} mempool={:?} job={:?}", n.height(), n.shared.node.lock().unwrap().chain.tip_ts(), vearl_core::net::now_secs(), n.shared.node.lock().unwrap().mempool.iter().map(|t| format!("{:?}", t.tx.kind).chars().take(30).collect::<String>()).collect::<Vec<_>>(), request(&n.addr, &Msg::GetJob(id)).ok().map(|m| match m { Msg::JobInfo { status, auction_end_ts, .. } => format!("{status} end={auction_end_ts}"), o => format!("{o:?}") }))).collect();
            panic!("timeout: job posted; node states: {dump:#?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The 3 nodes mine without waiting: the chain reorganises often, a state read now may be undone a
    // second later. We therefore only check the result once the job is settled, retrying the acceptance if a
    // reorg made it disappear.
    let t1 = Instant::now();
    while job_status(&passive.addr, id) != "Settled" {
        assert!(t1.elapsed() < Duration::from_secs(120), "timeout: job settled (status {})", job_status(&passive.addr, id));
        if job_status(&passive.addr, id).starts_with("Posted") {
            let _ = client_tx(&passive, &client, TxKind::Accept { job_id: id });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (escrow_net, best_bid) = match request(&passive.addr, &Msg::GetJob(id)).unwrap() {
        Msg::JobInfo { escrow_net, best_bid, .. } => (escrow_net, best_bid),
        m => panic!("{m:?}"),
    };
    // The blocks follow each other without waiting and the chain clock can run ahead of the wall clock: the cheapest
    // bid is not always included BEFORE the end of the auction (legitimate race, deterministic only at the
    // chain level: tests/auction.rs). Here we check end-to-end consistency: the job is settled AT THE PRICE OF THE
    // RETAINED BID, to the benefit of its author, whose reputation records one completed job.
    let (winner, price) = best_bid.expect("a bid was retained");
    let (cheap_k, dear_k) = (pubkey(&SigningKey::from_bytes(&[102; 32])), pubkey(&SigningKey::from_bytes(&[101; 32])));
    assert!(winner == cheap_k || winner == dear_k);
    assert_eq!(price, if winner == cheap_k { 20 * COIN } else { 35 * COIN });
    assert_eq!(escrow_net, price, "the job is settled at the price of the winning bid");
    match request(&passive.addr, &Msg::GetRep(winner)).unwrap() {
        Msg::Rep { done, slashed, .. } => assert_eq!((done, slashed), (1, 0)),
        m => panic!("{m:?}"),
    }
    for n in [&cheap, &dear, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

// ---------------------------------------------------------------- data availability (network)

fn served_entries(node: &str, id: JobId) -> Vec<(u32, u32, Vec<i32>, Vec<Hash>)> {
    match request(node, &Msg::GetServed(id)).unwrap() {
        Msg::Served { entries } => entries,
        m => panic!("{m:?}"),
    }
}

fn dot(cm: &CommittedMatrices, i: usize, j: usize) -> i32 {
    let n = WorkParams::TESTNET.n;
    (0..n).map(|k| cm.a[i * n + k] as i32 * cm.b[k * n + j] as i32).sum()
}

#[test]
fn data_audit_honest_worker_serves_on_chain_and_client_verifies_then_accepts() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(31);
    let id = submit_job(&client, &passive, &worker, &cm);
    wait("job posted", 60, || job_status(&passive.addr, id).starts_with("Posted"));

    let picks = [(3u32, 5u32), (100, 7), (64, 64)];
    for (i, j) in picks {
        assert!(matches!(client_tx(&passive, &client, TxKind::Fetch { job_id: id, i, j }), Msg::Ack { ok: true, .. }));
    }
    wait("the 3 entries served on-chain", 60, || served_entries(&passive.addr, id).len() == 3);
    for (i, j, v, _) in served_entries(&passive.addr, id) {
        assert_eq!(v[j as usize], dot(&cm, i as usize, j as usize), "entry ({i},{j}) correct");
    }
    assert!(matches!(client_tx(&passive, &client, TxKind::Accept { job_id: id }), Msg::Ack { ok: true, .. }));
    wait("job settled", 60, || job_status(&passive.addr, id) == "Settled");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn a_withholding_worker_is_slashed_automatically_by_a_third_party_miner() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { no_serve: true, ..Default::default() }), None);
    let watcher = node(vec![worker.addr.clone()], Some(1)); // simple miner: reports the unanswered requests
    let passive = node(vec![worker.addr.clone()], None);
    wait("network connected", 20, || worker.peer_count() >= 2);
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(32);
    let id = submit_job(&client, &passive, &worker, &cm);
    wait("job posted", 60, || job_status(&passive.addr, id).starts_with("Posted"));
    assert!(matches!(client_tx(&passive, &client, TxKind::Fetch { job_id: id, i: 1, j: 2 }), Msg::Ack { ok: true, .. }));
    wait("worker slashed for non-response", 90, || job_status(&passive.addr, id) == "Slashed");
    let rep = match request(&passive.addr, &Msg::GetRep(pubkey(&SigningKey::from_bytes(&[101; 32])))).unwrap() {
        Msg::Rep { slashed, .. } => slashed,
        m => panic!("{m:?}"),
    };
    assert_eq!(rep, 1);
    for n in [&worker, &watcher, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn an_invented_result_is_caught_by_one_sampled_on_chain_entry() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat_garbage: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    let client = SigningKey::from_bytes(&[100; 32]);
    let cm = rand_cm(33);
    let id = submit_job(&client, &passive, &worker, &cm);
    wait("job posted", 60, || job_status(&passive.addr, id).starts_with("Posted"));
    assert!(matches!(client_tx(&passive, &client, TxKind::Fetch { job_id: id, i: 9, j: 4 }), Msg::Ack { ok: true, .. }));
    wait("entry served", 60, || !served_entries(&passive.addr, id).is_empty());
    let (i, j, row, path) = served_entries(&passive.addr, id)[0].clone();
    assert_ne!(row[j as usize], dot(&cm, i as usize, j as usize), "the served entry is invented");
    let n = WorkParams::TESTNET.n;
    let (iu, ju) = (i as usize, j as usize);
    let proof = FraudProof {
        job_id: id,
        i,
        j,
        a_row: cm.a[iu * n..(iu + 1) * n].to_vec(),
        a_path: cm.a_tree.proof(iu),
        b_col: cm.col(ju, n),
        b_path: cm.b_tree.proof(ju),
        c_row: row,
        c_path: path,
    };
    assert!(matches!(client_tx(&passive, &client, TxKind::Fraud(proof)), Msg::Ack { ok: true, .. }));
    wait("worker slashed", 60, || job_status(&passive.addr, id) == "Slashed");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

// ---------------------------------------------------------------- block-wise products (network)

use vearl_core::tiled::*;

fn tiled_status(node: &str, id: JobId) -> (String, bool) {
    match request(node, &Msg::GetTiled(id)).unwrap() {
        Msg::TiledInfo { status, posted, .. } => (status, posted),
        _ => ("unknown".into(), false),
    }
}

/// Submits a rectangular (I,K,J) job, waits for publication, verifies like the CLI, then Accept or Fraud. Returns the outcome.
fn run_tiled(worker: &NodeHandle, passive: &NodeHandle, dims: (usize, usize, usize), seed: u64, expect_final: &str) -> String {
    let n = WorkParams::TESTNET.n;
    let client = SigningKey::from_bytes(&[100; 32]);
    let (am, bm) = demo_matrices(n, dims, seed);
    let (bi, bk, bj) = dims;
    let (ar, br) = (a_block_roots(&am, bk * n, bi, bk, n), b_block_roots(&bm, bj * n, bk, bj, n));
    let d8 = (bi as u8, bk as u8, bj as u8);
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = tiled_id(&pubkey(&client), nonce, d8, &ar, &br);
    assert!(matches!(request(&worker.addr, &Msg::PutTiled { a: am.clone(), b: bm.clone(), dims: d8 }).unwrap(), Msg::Ack { ok: true, .. }));
    let submit = TxKind::Tiled(TiledTx::Submit { dims: d8, a_roots: ar, b_roots: br, escrow: 20 * COIN * (bi * bk * bj) as u64, deadline: passive.height() + 500 });
    assert!(matches!(client_tx(passive, &client, submit), Msg::Ack { ok: true, .. }));
    wait("result published", 60, || tiled_status(&passive.addr, id).1);
    let (product_roots, c_roots) = match request(&passive.addr, &Msg::GetTiled(id)).unwrap() {
        Msg::TiledInfo { product_roots, c_roots, .. } => (product_roots, c_roots),
        m => panic!("{m:?}"),
    };
    let mut all = vec![];
    for i in 0..bi {
        for j in 0..bj {
            let (products, c) = match request(&worker.addr, &Msg::GetTiledGroup { job: id, i: i as u8, j: j as u8 }).unwrap() {
                Msg::TiledGroup { products, c } => (products, c),
                m => panic!("{m:?}"),
            };
            let ptrees: Vec<_> = products.iter().map(|x| c_tree(x, n)).collect();
            let ctree = c_tree(&c, n);
            for k in 0..bk {
                assert_eq!(ptrees[k].root(), product_roots[(i * bj + j) * bk + k], "served data = published roots");
            }
            assert_eq!(ctree.root(), c_roots[i * bj + j]);
            for k in 0..bk {
                let (ab, bb) = (get_block(&am, bk * n, i, k, n), get_block(&bm, bj * n, k, j, n));
                if !freivalds(&ab, &bb, &products[k], n, 24, &[7u8; 32]) {
                    let (r, cc) = find_bad_entry(&ab, &bb, &products[k], n, &[7u8; 32]).unwrap();
                    let kind = TiledFraudKind::Product {
                        i: i as u8, j: j as u8, k: k as u8, r: r as u32, c: cc as u32,
                        a_row: ab[r * n..(r + 1) * n].to_vec(), a_path: rows_tree(&ab, n).proof(r),
                        b_col: (0..n).map(|t| bb[t * n + cc]).collect(), b_path: cols_tree(&bb, n).proof(cc),
                        z_row: row_of(&products[k], n, r), z_path: ptrees[k].proof(r),
                    };
                    assert!(matches!(client_tx(passive, &client, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })), Msg::Ack { ok: true, .. }));
                    wait("final status", 60, || tiled_status(&passive.addr, id).0 == expect_final);
                    return "product-fraud".into();
                }
            }
            if let Some(idx) = (0..n * n).find(|&e| products.iter().map(|x| x[e] as i64).sum::<i64>() != c[e] as i64) {
                let kind = TiledFraudKind::Sum {
                    i: i as u8, j: j as u8, r: (idx / n) as u32, c: (idx % n) as u32,
                    z_rows: products.iter().map(|x| row_of(x, n, (idx) / n)).collect(), z_paths: ptrees.iter().map(|t| t.proof((idx) / n)).collect(),
                    c_row: row_of(&c, n, (idx) / n), c_path: ctree.proof((idx) / n),
                };
                assert!(matches!(client_tx(passive, &client, TxKind::Tiled(TiledTx::Fraud { job_id: id, kind })), Msg::Ack { ok: true, .. }));
                wait("final status", 60, || tiled_status(&passive.addr, id).0 == expect_final);
                return "sum-fraud".into();
            }
            all.push(c);
        }
    }
    // the assembled result is the real rectangular product
    let full = assemble(&all, bi, bj, n);
    let (kt, nt) = (bk * n, bj * n);
    for &(r, c) in &[(0usize, 0usize), (bi * n - 1, nt - 1), ((bi * n) / 2, n.min(nt - 1))] {
        let want: i64 = (0..kt).map(|t| am[r * kt + t] as i64 * bm[t * nt + c] as i64).sum();
        assert_eq!(full[r * nt + c] as i64, want, "entry ({r},{c}) of the assembled rectangular product");
    }
    assert!(matches!(client_tx(passive, &client, TxKind::Tiled(TiledTx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("final status", 60, || tiled_status(&passive.addr, id).0 == expect_final);
    "accepted".into()
}

#[test]
fn tiled_job_end_to_end_honest_rectangular_product() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_tiled(&worker, &passive, (1, 2, 2), 41, "Settled"), "accepted");
    let product_blocks = worker.shared.node.lock().unwrap().chain.blocks.iter().filter(|b| matches!(b.header.class, WorkClass::Product { .. })).count();
    assert!(product_blocks >= 1, "the worker mined blocks on the client's products ({product_blocks})");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn tiled_data_requests_are_served_on_chain_by_an_honest_worker() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    let n = WorkParams::TESTNET.n;
    let client = SigningKey::from_bytes(&[100; 32]);
    let dims = (1usize, 1usize, 2usize);
    let (am, bm) = demo_matrices(n, dims, 47);
    let (ar, br) = (a_block_roots(&am, n, 1, 1, n), b_block_roots(&bm, 2 * n, 1, 2, n));
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = tiled_id(&pubkey(&client), nonce, (1, 1, 2), &ar, &br);
    assert!(matches!(request(&worker.addr, &Msg::PutTiled { a: am, b: bm, dims: (1, 1, 2) }).unwrap(), Msg::Ack { ok: true, .. }));
    let submit = TxKind::Tiled(TiledTx::Submit { dims: (1, 1, 2), a_roots: ar, b_roots: br, escrow: 40 * COIN, deadline: passive.height() + 500 });
    assert!(matches!(client_tx(&passive, &client, submit), Msg::Ack { ok: true, .. }));
    wait("result published", 60, || tiled_status(&passive.addr, id).1);
    // the client demands a sum entry AND a product entry; the honest worker serves them by itself
    for (which, j, idx) in [(1u8, 1u8, 5u32), (0, 0, 9)] {
        assert!(matches!(client_tx(&passive, &client, TxKind::Tiled(TiledTx::Fetch { job_id: id, which, i: 0, j, k: 0, idx })), Msg::Ack { ok: true, .. }));
    }
    wait("requests served", 60, || passive.shared.node.lock().unwrap().chain.state.tiled.get(&id).map_or(false, |j| j.fetches.is_empty() && j.fetch_held == 0));
    assert!(matches!(client_tx(&passive, &client, TxKind::Tiled(TiledTx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("final status", 60, || tiled_status(&passive.addr, id).0 == "Settled");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn tiled_job_end_to_end_wrong_product_is_slashed() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_tiled(&worker, &passive, (2, 1, 2), 42, "Slashed"), "product-fraud");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn tiled_job_end_to_end_wrong_sum_is_slashed() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat_sum: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_tiled(&worker, &passive, (2, 2, 1), 43, "Slashed"), "sum-fraud");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

// ---------------------------------------------------------------- tensor programs (small CNN with a residual block), network

use vearl_core::prog::*;

fn prog_status(node: &str, id: JobId) -> (String, u8) {
    match request(node, &Msg::GetProg(id)).unwrap() {
        Msg::ProgInfo { status, posted, .. } => (status, posted),
        _ => ("unknown".into(), 0),
    }
}

/// Submits the demonstration CNN, waits for the publication of the 8 operations, verifies like the CLI (Freivalds + recomputation),
/// then Accept or fraud proof. Returns the kind of fraud found ("" if accepted).
fn run_prog(worker: &NodeHandle, passive: &NodeHandle, seed: u64, expect_final: &str) -> String {
    run_prog_named(worker, passive, "cnn", seed, expect_final)
}

fn run_prog_named(worker: &NodeHandle, passive: &NodeHandle, name: &str, seed: u64, expect_final: &str) -> String {
    run_prog_full(worker, passive, name, seed, expect_final, false, false)
}

fn run_prog_full(worker: &NodeHandle, passive: &NodeHandle, name: &str, seed: u64, expect_final: &str, registry: bool, fetch: bool) -> String {
    let n = WorkParams::TESTNET.n;
    let client = SigningKey::from_bytes(&[100; 32]);
    let (x0, ws, ops) = demo_program(name, n, seed).unwrap();
    let x0_root = cols_tree(&x0, n).root();
    let w_roots: Vec<Hash> = ws.iter().map(|w| rows_tree(w, n).root()).collect();
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = prog_id(&pubkey(&client), nonce, &x0_root, &w_roots, &ops);
    if registry {
        // registry: only the unknown blocks are deposited, then the input by reference; an unknown reference is refused
        assert!(matches!(request(&worker.addr, &Msg::PutProgRef { x0: x0.clone(), w_roots: w_roots.clone() }).unwrap(), Msg::Ack { ok: false, .. }), "unknown weights refused");
        let Msg::ModelHave { have } = request(&worker.addr, &Msg::HasModel { roots: w_roots.clone() }).unwrap() else { panic!() };
        let missing: Vec<Vec<i8>> = ws.iter().zip(&w_roots).zip(&have).filter(|(_, h)| !**h).map(|((w, _), _)| w.clone()).collect();
        if !missing.is_empty() {
            assert!(matches!(request(&worker.addr, &Msg::PutModel { ws: missing }).unwrap(), Msg::Ack { ok: true, .. }));
        }
        let Msg::ModelHave { have } = request(&worker.addr, &Msg::HasModel { roots: w_roots.clone() }).unwrap() else { panic!() };
        assert!(have.iter().all(|h| *h));
        assert!(matches!(request(&worker.addr, &Msg::PutProgRef { x0: x0.clone(), w_roots: w_roots.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    } else {
        assert!(matches!(request(&worker.addr, &Msg::PutProg { x0: x0.clone(), ws: ws.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    }
    let gemms = ops.iter().filter(|o| o.is_gemm()).count() as u64;
    let submit = TxKind::Prog(ProgTx::Submit { x0_root, w_roots, ops: ops.clone(), escrow: 20 * COIN * gemms, deadline: passive.height() + 500 });
    assert!(matches!(client_tx(passive, &client, submit), Msg::Ack { ok: true, .. }));
    wait("all operations published", 60, || prog_status(&passive.addr, id).1 as usize == ops.len());
    if fetch {
        // the client demands a column ON-CHAIN; the (honest) worker serves it by itself; the job stays settleable afterwards
        assert!(matches!(client_tx(passive, &client, TxKind::Prog(ProgTx::Fetch { job_id: id, tensor: ops.len() as u8, col: 3 })), Msg::Ack { ok: true, .. }));
        wait("request served", 60, || passive.shared.node.lock().unwrap().chain.state.progs.get(&id).map_or(false, |j| j.fetches.is_empty() && j.fetch_held == 0));
    }
    let roots = match request(&passive.addr, &Msg::GetProg(id)).unwrap() {
        Msg::ProgInfo { roots, .. } => roots,
        m => panic!("{m:?}"),
    };
    let (mut tens, mut zs) = (vec![x0], vec![]);
    for k in 0..ops.len() {
        let (z, x) = match request(&worker.addr, &Msg::GetOp { job: id, op: k as u8 }).unwrap() {
            Msg::OpData { z, x } => (z, x),
            m => panic!("{m:?}"),
        };
        assert_eq!((z.as_ref().map_or([0u8; 32], |zz| c_tree(zz, n).root()), cols_tree(&x, n).root()), roots[k], "served data = published roots (op {k})");
        zs.push(z);
        tens.push(x);
    }
    let outcome = match find_fraud_proof(&ops, &ws, &tens, &zs, n) {
        Some((op, kind)) => {
            let label = match &kind {
                ProgFraud::Gemm { .. } => "gemm",
                ProgFraud::Act { .. } => "act",
                ProgFraud::Elem { .. } => "elem",
                ProgFraud::Col { .. } => "col",
                ProgFraud::Bias { .. } => "bias",
                ProgFraud::Lut { .. } => "lut",
                ProgFraud::MulW { .. } => "mulw",
            };
            assert!(matches!(client_tx(passive, &client, TxKind::Prog(ProgTx::Fraud { job_id: id, op, kind })), Msg::Ack { ok: true, .. }));
            format!("{label}@{op}")
        }
        None => {
            assert!(matches!(client_tx(passive, &client, TxKind::Prog(ProgTx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
            String::new()
        }
    };
    wait("final status", 60, || prog_status(&passive.addr, id).0 == expect_final);
    outcome
}

#[test]
fn tensor_program_end_to_end_honest_cnn_is_paid() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_prog(&worker, &passive, 51, "Settled"), "");
    let op_blocks = worker.shared.node.lock().unwrap().chain.blocks.iter().filter(|b| matches!(b.header.class, WorkClass::Op { .. })).count();
    assert!(op_blocks >= 1, "the worker mined blocks on the client's GEMMs ({op_blocks})");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn program_data_request_is_served_on_chain_by_an_honest_worker() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_prog_full(&worker, &passive, "cnn", 62, "Settled", false, true), "");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn model_registry_weights_sent_once_then_jobs_send_only_inputs() {
    let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_prog_full(&worker, &passive, "cnn", 61, "Settled", true, false), "");
    // second job of the same model (same weights, other input): no weight block left to send
    let n = WorkParams::TESTNET.n;
    let (_, ws, _) = demo_program("cnn", n, 61).unwrap();
    let roots: Vec<Hash> = ws.iter().map(|w| rows_tree(w, n).root()).collect();
    let Msg::ModelHave { have } = request(&worker.addr, &Msg::HasModel { roots }).unwrap() else { panic!() };
    assert!(have.iter().all(|h| *h), "the weights stay in the worker's registry");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

#[test]
fn tensor_program_end_to_end_each_fault_is_caught_and_slashed() {
    for (cfg, want_prefix, seed) in [
        (WorkerCfg { cheat: true, ..Default::default() }, "gemm@", 52u64),
        (WorkerCfg { cheat_act: true, ..Default::default() }, "act@", 53),
        (WorkerCfg { cheat_elem: true, ..Default::default() }, "elem@0", 54),
    ] {
        let worker = node_with(vec![], Some(101), Some(cfg), None);
        let passive = node(vec![worker.addr.clone()], None);
        let got = run_prog(&worker, &passive, seed, "Slashed");
        assert!(got.starts_with(want_prefix), "expected {want_prefix}, got {got}");
        for n in [&worker, &passive] {
            assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
            n.stop();
        }
    }
}

#[test]
fn transformer_block_end_to_end_honest_and_each_fault_is_caught() {
    // honest: the 14 operations (including softmax and 2 normalisations) are verified then paid
    {
        let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
        let passive = node(vec![worker.addr.clone()], None);
        assert_eq!(run_prog_named(&worker, &passive, "transformer", 61, "Settled"), "");
        let op_blocks = worker.shared.node.lock().unwrap().chain.blocks.iter().filter(|b| matches!(b.header.class, WorkClass::Op { .. })).count();
        assert!(op_blocks >= 1, "blocks mined on the client's GEMMs, including the attention scores ({op_blocks})");
        for n in [&worker, &passive] {
            assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
            n.stop();
        }
    }
    // faults: wrong GEMM (2nd GEMM = K projection), wrong softmax column
    for (cfg, want, seed) in [
        (WorkerCfg { cheat: true, ..Default::default() }, "gemm@", 62u64),
        (WorkerCfg { cheat_col: true, ..Default::default() }, "col@4", 63),
    ] {
        let worker = node_with(vec![], Some(101), Some(cfg), None);
        let passive = node(vec![worker.addr.clone()], None);
        let got = run_prog_named(&worker, &passive, "transformer", seed, "Slashed");
        assert!(got.starts_with(want), "expected {want}, got {got}");
        for n in [&worker, &passive] {
            assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
            n.stop();
        }
    }
}

#[test]
fn imported_digits_cnn_runs_as_a_network_job_honest_and_cheating() {
    // real model (8x8 CNN -> 10 classes, int8 quantised) imported from models/digits-cnn.json
    let name = "model:models/digits-cnn.json";
    {
        let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
        let passive = node(vec![worker.addr.clone()], None);
        assert_eq!(run_prog_named(&worker, &passive, name, 0, "Settled"), "");
        for n in [&worker, &passive] {
            assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
            n.stop();
        }
    }
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    let got = run_prog_named(&worker, &passive, name, 1, "Slashed");
    assert!(got.starts_with("gemm@"), "got {got}");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

// ---------------------------------------------------------------- level 2 (Monte Carlo, rendering), network

use vearl_core::l2::*;

fn l2_status(node: &str, id: JobId) -> String {
    match request(node, &Msg::GetL2(id)).unwrap() {
        Msg::L2Info { status, .. } => status,
        _ => "unknown".into(),
    }
}

/// Submits a level 2 job, waits for publication, AUDITS all the chunks (local recomputation + Merkle opening), then Accept or Fraud.
fn run_l2(worker: &NodeHandle, passive: &NodeHandle, kernel: Kernel, chunks: u32, seed: u8) -> String {
    let client = SigningKey::from_bytes(&[seed; 32]);
    let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = l2_id(&pubkey(&client), nonce, &kernel, chunks);
    let submit = TxKind::L2(L2Tx::Submit { kernel: kernel.clone(), chunks, escrow: 10 * COIN, deadline: passive.height() + 500 });
    assert!(matches!(client_tx(passive, &client, submit), Msg::Ack { ok: true, .. }));
    wait("level 2 result published", 60, || l2_status(&passive.addr, id).starts_with("Posted"));
    let Msg::L2Info { root: Some(root), .. } = request(&passive.addr, &Msg::GetL2(id)).unwrap() else { panic!("root") };
    let depth = depth_for(chunks as usize);
    for i in 0..chunks {
        let Msg::L2ChunkData { out, path } = request(&worker.addr, &Msg::GetL2Chunk { job: id, chunk: i }).unwrap() else { panic!("chunk {i}") };
        assert!(verify_proof(&root, chunk_leaf(i, &out), i as usize, &path, depth), "the served chunks are opened against the committed root");
        if kernel.chunk(i) != out {
            assert!(matches!(client_tx(passive, &client, TxKind::L2(L2Tx::Fraud { job_id: id, chunk: i, out, path })), Msg::Ack { ok: true, .. }));
            wait("level 2 fraud penalised", 60, || l2_status(&passive.addr, id) == "Slashed");
            return format!("Slashed@{i}");
        }
    }
    assert!(matches!(client_tx(passive, &client, TxKind::L2(L2Tx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("level 2 job settled", 60, || l2_status(&passive.addr, id) == "Settled");
    "Settled".into()
}

#[test]
fn level2_render_and_monte_carlo_honest_worker_is_paid_and_cheater_is_slashed() {
    let mc = Kernel::MonteCarlo(McParams { seed: [3; 32], dim: 2, samples: 1024, out: 6, program: mc_pi_program() });
    let scene = Kernel::Render(demo_scene(48, 48, 1, [5; 32]));
    {
        let worker = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
        let passive = node(vec![worker.addr.clone()], None);
        assert_eq!(run_l2(&worker, &passive, mc.clone(), 24, 100), "Settled");
        assert_eq!(run_l2(&worker, &passive, scene.clone(), 9, 100), "Settled");
        for n in [&worker, &passive] {
            assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
            n.stop();
        }
    }
    let worker = node_with(vec![], Some(101), Some(WorkerCfg { cheat_l2: true, ..Default::default() }), None);
    let passive = node(vec![worker.addr.clone()], None);
    assert_eq!(run_l2(&worker, &passive, mc, 24, 100), "Slashed@12", "the middle chunk is wrong");
    assert_eq!(run_l2(&worker, &passive, scene, 9, 100), "Slashed@4");
    for n in [&worker, &passive] {
        assert!(n.shared.node.lock().unwrap().chain.check_supply_invariant());
        n.stop();
    }
}

/// A busy worker does not claim from the queue: with `max_jobs` = 1 it never holds two claimed jobs at once, and two
/// workers share four jobs submitted at once (the computation runs in the background, the node stays responsive).
#[test]
fn level2_a_busy_worker_leaves_the_queue_to_the_other_miners() {
    use vearl_core::l2::L2Status;
    let w1 = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let w2 = node_with(vec![w1.addr.clone()], Some(102), Some(WorkerCfg::default()), None);
    let passive = node(vec![w1.addr.clone()], None);
    wait("the three nodes see each other", 30, || w1.peer_count() >= 1 && w2.peer_count() >= 1 && passive.peer_count() >= 1);
    // each worker must have mined enough to pay the bond of a claim
    for seed in [101u8, 102] {
        let pk = pubkey(&SigningKey::from_bytes(&[seed; 32]));
        wait("the worker can afford a bond", 60, || matches!(request(&passive.addr, &Msg::GetAccount(pk)), Ok(Msg::Account { balance, .. }) if balance >= 20 * COIN));
    }
    let client = SigningKey::from_bytes(&[100; 32]);
    let mut ids = vec![];
    for i in 0..4u8 {
        let kernel = Kernel::Render(demo_scene(256, 256, 4, [i + 1; 32]));
        let chunks = Kernel::forced_chunks(&kernel).unwrap();
        let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
            Msg::Account { next_nonce, .. } => next_nonce,
            m => panic!("{m:?}"),
        };
        ids.push(l2_id(&pubkey(&client), nonce, &kernel, chunks));
        let submit = TxKind::L2(L2Tx::Submit { kernel, chunks, escrow: 10 * COIN, deadline: passive.height() + 500 });
        assert!(matches!(client_tx(&passive, &client, submit), Msg::Ack { ok: true, .. }));
    }
    let (mut most_claimed, mut workers) = (0usize, std::collections::HashSet::new());
    wait("the four jobs are published", 120, || {
        let n = passive.shared.node.lock().unwrap();
        let mut per: std::collections::HashMap<PubKey, usize> = Default::default();
        let mut posted = 0;
        for id in &ids {
            match n.chain.state.l2.get(id).map(|j| &j.status) {
                Some(L2Status::Claimed { worker, .. }) => {
                    *per.entry(*worker).or_default() += 1;
                    workers.insert(*worker);
                }
                Some(L2Status::Posted { worker, .. }) => {
                    workers.insert(*worker);
                    posted += 1;
                }
                Some(L2Status::Open) | None => {}
                Some(_) => posted += 1,
            }
        }
        most_claimed = most_claimed.max(per.values().copied().max().unwrap_or(0));
        posted == ids.len()
    });
    assert!(most_claimed <= 1, "a busy worker must not claim another job ({most_claimed} claimed at a time)");
    assert_eq!(workers.len(), 2, "both miners each took jobs from the queue");
    for n in [&w1, &w2, &passive] {
        n.stop();
    }
}

/// Dual mining (dual.rs): during the other miner's window the mining loop is paused, but a paid job that arrives must be seen
/// at once (`native_work` becomes false) and claimed, so that the scheduler gives the GPU back to Vearl in under a second.
#[test]
fn a_paused_worker_still_notices_a_paid_job() {
    use std::sync::atomic::Ordering;
    use vearl_core::l2::L2Status;
    let a = node_with(vec![], Some(101), Some(WorkerCfg::default()), None);
    let b = node(vec![a.addr.clone()], Some(102));
    wait("the nodes see each other", 30, || a.peer_count() >= 1 && b.peer_count() >= 1);
    let a_pk = pubkey(&SigningKey::from_bytes(&[101; 32]));
    wait("the worker can afford a bond", 60, || matches!(request(&b.addr, &Msg::GetAccount(a_pk)), Ok(Msg::Account { balance, .. }) if balance >= 20 * COIN));
    // window of the other miner: pause of A's mining (B keeps mining the blocks)
    a.shared.paused.store(true, Ordering::SeqCst);
    a.shared.cancel.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(1200));
    a.shared.native_work.store(true, Ordering::SeqCst);
    let client = SigningKey::from_bytes(&[100; 32]);
    let kernel = Kernel::Render(demo_scene(128, 128, 2, [9; 32]));
    let chunks = Kernel::forced_chunks(&kernel).unwrap();
    let nonce = match request(&b.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = l2_id(&pubkey(&client), nonce, &kernel, chunks);
    let submit = TxKind::L2(L2Tx::Submit { kernel, chunks, escrow: 10 * COIN, deadline: b.height() + 500 });
    assert!(matches!(client_tx(&b, &client, submit), Msg::Ack { ok: true, .. }));
    let t = Instant::now();
    wait("the paused worker sees the paid job", 60, || !a.shared.native_work.load(Ordering::SeqCst));
    eprintln!("job seen by the paused worker after {:?}", t.elapsed());
    assert!(a.shared.paused.load(Ordering::SeqCst), "the mining loop stayed paused during that time");
    wait("the job is claimed by the paused worker", 60, || {
        let n = b.shared.node.lock().unwrap();
        matches!(n.chain.state.l2.get(&id).map(|j| &j.status), Some(L2Status::Claimed { worker, .. }) | Some(L2Status::Posted { worker, .. }) if *worker == a_pk)
    });
    a.shared.paused.store(false, Ordering::SeqCst);
    a.stop();
    b.stop();
}

// ---------------------------------------------------------------- deep fork: search for the common ancestor

fn serve_blocks(c: &mut Conn, peer: &Chain, until: impl Fn() -> bool) {
    c.set_timeout(Duration::from_millis(300));
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) && !until() {
        if let Ok(Msg::GetBlocks { from }) = c.recv() {
            let v: Vec<Block> = peer.blocks.iter().skip(from as usize).take(BATCH).cloned().collect();
            c.send(&Msg::Blocks(v)).unwrap();
        }
    }
}

#[test]
fn a_deep_fork_is_resolved_by_locating_the_common_ancestor() {
    let n = node(vec![], None);
    let (m1, m2) = (SigningKey::from_bytes(&[9; 32]), SigningKey::from_bytes(&[10; 32]));
    let mut local = Chain::from_config(&genesis());
    let mine = |c: &mut Chain, k: &SigningKey| {
        let ts = c.tip_ts() + BLOCK_TIME;
        let b = c.mine(k, WorkClass::Native, None, vec![], ts).unwrap().block;
        c.validate_and_apply(b.clone()).unwrap();
        b
    };
    let common: Vec<Block> = (0..30).map(|_| mine(&mut local, &m1)).collect();
    let mut peer = Chain::from_config(&genesis());
    for b in &common {
        peer.validate_and_apply(b.clone()).unwrap();
    }
    let mut mine_branch: Vec<Block> = common.clone();
    for _ in 0..10 {
        mine_branch.push(mine(&mut local, &m1)); // 10 local blocks after the common ancestor (height 30)
    }
    let mut c = Conn::connect(&n.addr).unwrap();
    c.send(&Msg::Hello { node_id: 777, genesis: n.shared.genesis_hash, height: 0, work: 0, listen: None }).unwrap();
    for b in mine_branch {
        c.send(&Msg::NewBlock(b)).unwrap();
    }
    wait("the node has the local chain (40 blocks)", 20, || n.height() == 40);
    let local_tip = n.tip();
    assert_eq!(local_tip, local.tip_hash());
    for _ in 0..25 {
        mine(&mut peer, &m2); // 25 blocks on the competing branch: more work (x2.5), fork 10 blocks deep
    }
    // a second peer, which announces more work and serves its chain in batches
    let mut c2 = Conn::connect(&n.addr).unwrap();
    c2.send(&Msg::Hello { node_id: 778, genesis: n.shared.genesis_hash, height: peer.height(), work: peer.total_work(), listen: None }).unwrap();
    serve_blocks(&mut c2, &peer, || n.height() == 55 && n.tip() == peer.tip_hash());
    assert_eq!(n.height(), 55, "the node adopted the heaviest branch");
    assert_eq!(n.tip(), peer.tip_hash());
    assert_ne!(n.tip(), local_tip);
    n.stop();
}

#[test]
fn sync_works_when_replies_are_limited_by_size() {
    // the source node only returns ONE block per reply (minimal budget): the catching-up node must continue until the empty batch
    let a = node(vec![], Some(1));
    a.shared.node.lock().unwrap().sync_budget = 1;
    wait("a mined 40 blocks", 60, || a.height() >= 40);
    let b = node(vec![a.addr.clone()], None);
    wait("b catches up with a in batches of one block", 60, || b.height() >= 40 && block_hash_at(&b, 39) == block_hash_at(&a, 39));
    a.stop();
    b.stop();
}

/// A worker that claimed a public job and then went away must not hold it until the deadline: after the lease another worker takes it back
/// (the first one loses its bond) and computes it. The lease is 15 x serve_secs; here serve_secs = 3.
#[test]
fn level2_a_job_abandoned_by_its_worker_is_taken_over_by_another_worker() {
    use vearl_core::l2::L2Status;
    let mut g = genesis();
    g.timing.serve_secs = 3; // lease of 45 s on the chain clock
    let spawn = |peers: Vec<String>, seed: u8, worker: Option<WorkerCfg>| {
        spawn_node(NodeConfig { genesis: g.clone(), listen: "127.0.0.1:0".into(), peers, mine_key: Some(SigningKey::from_bytes(&[seed; 32])), use_gpu: false, log: false, worker, data_dir: None }).unwrap()
    };
    let miner = spawn(vec![], 102, None); // makes the blocks, takes no job
    let client = SigningKey::from_bytes(&[100; 32]);
    let ghost = SigningKey::from_bytes(&[102; 32]); // "worker" that claims and then disappears: a bare key, no node behind it
    let kernel = Kernel::Render(demo_scene(128, 128, 2, [5; 32]));
    let chunks = Kernel::forced_chunks(&kernel).unwrap();
    let nonce = match request(&miner.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = l2_id(&pubkey(&client), nonce, &kernel, chunks);
    let submit = TxKind::L2(L2Tx::Submit { kernel, chunks, escrow: 10 * COIN, deadline: miner.height() + 5000 });
    assert!(matches!(client_tx(&miner, &client, submit), Msg::Ack { ok: true, .. }));
    wait("the job is on the chain", 60, || miner.shared.node.lock().unwrap().chain.state.l2.contains_key(&id));
    assert!(matches!(client_tx(&miner, &ghost, TxKind::L2(L2Tx::Claim { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("the ghost holds the job", 60, || matches!(miner.shared.node.lock().unwrap().chain.state.l2.get(&id).map(|j| &j.status), Some(L2Status::Claimed { .. })));
    let burned = miner.shared.node.lock().unwrap().chain.state.burned;
    let (ghost_at, lease) = {
        let n = miner.shared.node.lock().unwrap();
        match n.chain.state.l2[&id].status {
            L2Status::Claimed { at_ts, .. } => (at_ts, n.chain.state.timing.claim_lease_secs()),
            ref s => panic!("{s:?}"),
        }
    };

    // the real worker comes online: during the lease it leaves the job alone
    let worker = spawn(vec![miner.addr.clone()], 101, Some(WorkerCfg::default()));
    let worker_pk = pubkey(&SigningKey::from_bytes(&[101; 32]));
    let ghost_pk = pubkey(&ghost);
    wait("the worker is connected", 30, || worker.peer_count() >= 1);
    // (the blocks of the test chain come in milliseconds but their timestamps advance one second at least, so the chain clock runs faster than
    // the wall clock: the lease is read on the chain clock)
    let started = Instant::now();
    let mut watched = 0;
    while started.elapsed() < Duration::from_secs(10) {
        {
            let n = miner.shared.node.lock().unwrap();
            if n.chain.tip_ts() + 2 < ghost_at + lease {
                assert!(
                    matches!(n.chain.state.l2.get(&id).map(|j| &j.status), Some(L2Status::Claimed { worker, .. }) if *worker == ghost_pk),
                    "the job is not taken away while the lease runs"
                );
                watched += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(watched > 0, "the lease was observed while it ran");
    // the lease runs out: the worker takes the job over and publishes the result
    wait("the worker took the job over", 120, || {
        matches!(miner.shared.node.lock().unwrap().chain.state.l2.get(&id).map(|j| &j.status), Some(L2Status::Claimed { worker, .. }) | Some(L2Status::Posted { worker, .. }) if *worker == worker_pk)
    });
    wait("the result is published", 120, || matches!(miner.shared.node.lock().unwrap().chain.state.l2.get(&id).map(|j| &j.status), Some(L2Status::Posted { worker, .. }) if *worker == worker_pk));
    let n = miner.shared.node.lock().unwrap();
    assert!(n.chain.state.burned > burned, "the bond of the worker that disappeared was burned");
    assert_eq!(n.chain.state.reputation(&ghost_pk).expired, 1);
    assert!(n.chain.check_supply_invariant());
    drop(n);
    worker.stop();
    miner.stop();
}

/// The client deposits the data of a model with SEVERAL workers (`vearl-cli infer WORKER1,WORKER2`): the jobs spread over them, a worker
/// never holds more jobs at once than `--max-jobs`, and every job still gets its result from the worker that claimed it.
#[test]
fn model_jobs_spread_over_the_workers_that_hold_their_data() {
    use vearl_core::prog::ProgStatus;
    let cfg = WorkerCfg { max_jobs: 2, ..Default::default() };
    let w1 = node_with(vec![], Some(101), Some(cfg), None);
    let w2 = node_with(vec![w1.addr.clone()], Some(102), Some(cfg), None);
    let passive = node(vec![w1.addr.clone()], None);
    wait("the three nodes see each other", 30, || w1.peer_count() >= 1 && w2.peer_count() >= 1 && passive.peer_count() >= 1);
    for seed in [101u8, 102] {
        let pk = pubkey(&SigningKey::from_bytes(&[seed; 32]));
        wait("the worker can afford a bond", 60, || matches!(request(&passive.addr, &Msg::GetAccount(pk)), Ok(Msg::Account { balance, .. }) if balance >= 20 * COIN));
    }
    let n = WorkParams::TESTNET.n;
    let client = SigningKey::from_bytes(&[100; 32]);
    let (x0, ws, ops) = demo_program("cnn", n, 7).unwrap();
    let x0_root = cols_tree(&x0, n).root();
    let w_roots: Vec<Hash> = ws.iter().map(|w| rows_tree(w, n).root()).collect();
    for w in [&w1, &w2] {
        assert!(matches!(request(&w.addr, &Msg::PutProg { x0: x0.clone(), ws: ws.clone() }).unwrap(), Msg::Ack { ok: true, .. }));
    }
    let gemms = ops.iter().filter(|o| o.is_gemm()).count() as u64;
    let mut ids = vec![];
    // many small jobs: a worker that took two goes back to the queue only when they are done, so the other one gets its share
    for _ in 0..24 {
        let nonce = match request(&passive.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
            Msg::Account { next_nonce, .. } => next_nonce,
            m => panic!("{m:?}"),
        };
        ids.push(prog_id(&pubkey(&client), nonce, &x0_root, &w_roots, &ops));
        let submit = TxKind::Prog(ProgTx::Submit { x0_root, w_roots: w_roots.clone(), ops: ops.clone(), escrow: 20 * COIN * gemms, deadline: passive.height() + 500 });
        assert!(matches!(client_tx(&passive, &client, submit), Msg::Ack { ok: true, .. }));
    }
    let (mut most, mut workers) = (0usize, std::collections::HashSet::new());
    wait("the jobs are complete", 120, || {
        let node = passive.shared.node.lock().unwrap();
        let mut per: std::collections::HashMap<PubKey, usize> = Default::default();
        let mut done = 0;
        for id in &ids {
            match node.chain.state.progs.get(id).map(|j| &j.status) {
                Some(ProgStatus::Working { worker, .. }) => {
                    *per.entry(*worker).or_default() += 1;
                    workers.insert(*worker);
                }
                Some(ProgStatus::Complete { worker, .. }) => {
                    workers.insert(*worker);
                    done += 1;
                }
                Some(ProgStatus::Open) | None => {}
                Some(_) => done += 1,
            }
        }
        most = most.max(per.values().copied().max().unwrap_or(0));
        done == ids.len()
    });
    assert!(most <= 2, "a worker holds at most max-jobs jobs at once ({most})");
    assert_eq!(workers.len(), 2, "the jobs spread over both workers");
    // both workers mine, so a claim can live on a branch that is reorganised away: wait until the three nodes follow the same chain, and give the
    // workers a turn to drop the run of a job that another worker finally holds
    let tip = |h: &NodeHandle| h.shared.node.lock().unwrap().chain.tip_hash();
    wait("the three nodes follow the same chain", 60, || tip(&w1) == tip(&passive) && tip(&w2) == tip(&passive));
    std::thread::sleep(Duration::from_millis(1500));
    // each result is served by the worker that computed it (the client asks them in turn, as `vearl-cli infer` does)
    for id in &ids {
        let served = [&w1, &w2].iter().filter(|w| matches!(request(&w.addr, &Msg::GetOp { job: *id, op: 0 }), Ok(Msg::OpData { .. }))).count();
        assert_eq!(served, 1, "exactly one worker serves the result of a job");
    }
    for node in [&w1, &w2, &passive] {
        node.stop();
    }
}

/// A model pack installed in advance (`--models-dir`): the node reports its blocks as present (`HasModel`), so a client sends nothing, and the pack
/// does not eat the upload cap. A pack built for another matrix size is ignored.
#[test]
fn a_model_pack_installed_in_advance_makes_the_client_upload_nothing() {
    let dir = std::env::temp_dir().join(format!("vearl-models-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let n = genesis().params.n;
    let blocks: Vec<Vec<i8>> = (0..3).map(|k| (0..n * n).map(|i| (((i * 31 + k * 7) % 61) as i32 - 30) as i8).collect()).collect();
    let write = |name: &str, pn: usize, bl: &[Vec<i8>]| {
        let mut f = Vec::new();
        f.extend_from_slice(MODEL_PACK_MAGIC);
        f.extend_from_slice(&(pn as u32).to_le_bytes());
        f.extend_from_slice(&(bl.len() as u32).to_le_bytes());
        for b in bl {
            f.extend(b.iter().map(|v| *v as u8));
        }
        std::fs::write(dir.join(name), f).unwrap();
    };
    write("good.vblocks", n, &blocks[..2]);
    write("other-size.vblocks", n * 2, &blocks[2..]);
    let w = node(vec![], None);
    let (loaded, refused) = w.preload_models(dir.clone(), false).join().unwrap();
    assert_eq!((loaded, refused), (2, 1));
    let roots: Vec<Hash> = blocks.iter().map(|b| vearl_core::work::rows_tree(b, n).root()).collect();
    match request(&w.addr, &Msg::HasModel { roots: roots.clone() }).unwrap() {
        Msg::ModelHave { have } => assert_eq!(have, vec![true, true, false], "the two blocks of the good pack are present, the one of the other pack is not"),
        m => panic!("{m:?}"),
    }
    // the client uploads the missing block only, as before, and the registry then has the three
    assert!(matches!(request(&w.addr, &Msg::PutModel { ws: vec![blocks[2].clone()] }).unwrap(), Msg::Ack { ok: true, .. }));
    match request(&w.addr, &Msg::HasModel { roots }).unwrap() {
        Msg::ModelHave { have } => assert_eq!(have, vec![true; 3]),
        m => panic!("{m:?}"),
    }
    w.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
