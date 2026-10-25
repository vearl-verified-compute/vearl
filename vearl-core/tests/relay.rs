//! Relay (docs/21): a worker that nobody can dial (behind a home router) is audited through the seed it is connected to.
//! The "router" is simulated by never giving the client the worker's address: the client only knows the seed.
use ed25519_dalek::SigningKey;
use std::time::{Duration, Instant};
use vearl_core::chain::*;
use vearl_core::crypto::*;
use vearl_core::l2::*;
use vearl_core::net::*;
use vearl_core::state::*;
use vearl_core::types::*;

fn genesis() -> GenesisConfig {
    let mut g = devnet_genesis();
    g.target = u64::MAX / 256;
    g.retarget = Retarget::Fixed;
    g.timing.serve_secs = 6;
    g
}

fn node_with(peers: Vec<String>, seed: Option<u8>, worker: Option<WorkerCfg>) -> NodeHandle {
    spawn_node(NodeConfig { genesis: genesis(), listen: "127.0.0.1:0".into(), peers, mine_key: seed.map(|s| SigningKey::from_bytes(&[s; 32])), use_gpu: false, log: false, worker, data_dir: None }).unwrap()
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

fn client_tx(node: &NodeHandle, client: &SigningKey, kind: TxKind) -> Msg {
    let nonce = match request(&node.addr, &Msg::GetAccount(pubkey(client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    request(&node.addr, &Msg::NewTx(SignedTx::new(Tx { from: pubkey(client), nonce, fee: 0, kind }, client))).unwrap()
}

fn l2_status(node: &str, id: JobId) -> String {
    match request(node, &Msg::GetL2(id)).unwrap() {
        Msg::L2Info { status, .. } => status,
        _ => "unknown".into(),
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// seed (relay, mines) <- worker (dials the seed with the pinned key, never dialed by anybody)
fn setup(relay_on: bool) -> (NodeHandle, NodeHandle) {
    let seed = node_with(vec![], Some(1), None);
    seed.set_relay(relay_on);
    let worker = node_with(vec![format!("{}@{}", seed.addr, seed.id_hex())], Some(101), Some(WorkerCfg::default()));
    wait("worker connected to the seed", 30, || seed.peer_count() >= 1 && worker.peer_count() >= 1);
    (seed, worker)
}

fn submit_job(seed: &NodeHandle, chunks: u32) -> (JobId, Kernel) {
    let client = SigningKey::from_bytes(&[100; 32]);
    let kernel = Kernel::MonteCarlo(McParams { seed: [3; 32], dim: 2, samples: 1024, out: 6, program: mc_pi_program() });
    let nonce = match request(&seed.addr, &Msg::GetAccount(pubkey(&client))).unwrap() {
        Msg::Account { next_nonce, .. } => next_nonce,
        m => panic!("{m:?}"),
    };
    let id = l2_id(&pubkey(&client), nonce, &kernel, chunks);
    let submit = TxKind::L2(L2Tx::Submit { kernel: kernel.clone(), chunks, escrow: 10 * COIN, deadline: seed.height() + 500 });
    assert!(matches!(client_tx(seed, &client, submit), Msg::Ack { ok: true, .. }));
    (id, kernel)
}

#[test]
fn a_worker_nobody_can_dial_is_audited_through_the_seed() {
    let (seed, worker) = setup(true);
    wait("the seed knows a route to the worker", 30, || seed.relay_routes() == 1);
    let (id, kernel) = submit_job(&seed, 24);
    wait("result published", 60, || l2_status(&seed.addr, id).starts_with("Posted"));
    let Msg::L2Info { root: Some(root), chunks, .. } = request(&seed.addr, &Msg::GetL2(id)).unwrap() else { panic!("root") };
    let depth = depth_for(chunks as usize);

    // by the level 2 job: the seed itself finds who holds it
    let by_job = format!("relay://{}/l2:{}", seed.addr, hex32(&id));
    // by the account: the worker key of this test
    let by_acct = format!("relay://{}/acct:{}", seed.addr, hex32(&pubkey(&SigningKey::from_bytes(&[101; 32]))));
    for addr in [&by_job, &by_acct] {
        for i in 0..chunks {
            let Msg::L2ChunkData { out, path } = request(addr, &Msg::GetL2Chunk { job: id, chunk: i }).unwrap() else { panic!("chunk {i} through {addr}") };
            assert!(verify_proof(&root, chunk_leaf(i, &out), i as usize, &path, depth), "the relayed chunk opens against the on-chain root");
            assert_eq!(kernel.chunk(i), out, "and it is the right output");
        }
    }

    // a connection kept open for several requests (what `l2-finish` does)
    let mut c = Conn::connect(&by_job).unwrap();
    c.set_timeout(Duration::from_secs(10));
    for i in 0..3 {
        c.send(&Msg::GetL2Chunk { job: id, chunk: i }).unwrap();
        let reply = loop {
            match c.recv().unwrap() {
                Msg::Hello { .. } => continue, // every node greets a new connection first
                r => break r,
            }
        };
        assert!(matches!(reply, Msg::L2ChunkData { .. }), "{reply:?}");
    }
    // 8 clients at once
    std::thread::scope(|s| {
        for t in 0..8u32 {
            let a = by_job.clone();
            s.spawn(move || {
                for k in 0..chunks {
                    let r = request(&a, &Msg::GetL2Chunk { job: id, chunk: (k + t) % chunks });
                    assert!(matches!(r, Ok(Msg::L2ChunkData { .. })), "{r:?}");
                }
            });
        }
    });

    // what writes, or relays again, does not travel
    let put = Msg::PutJob { a: vec![0; 4], b: vec![0; 4] };
    // requests whose reply is a matrix do not travel either (they need a direct connection), except the ones of an AI job (see the last test)
    for big in [Msg::GetResult(id), Msg::GetTiledSum { job: id, i: 0, j: 0 }, Msg::GetLayer { job: id, layer: 0 }, Msg::PutModel { ws: vec![vec![0; 4]; 3] }] {
        match request(&by_job, &big).unwrap() {
            Msg::Ack { ok: false, info } => assert!(info.contains("not relayable"), "{info}"),
            r => panic!("{r:?}"),
        }
    }
    let nest = Msg::RelayRequest { to: RelayTo::L2Job(id), req: encode(&Msg::GetStatus).unwrap() };
    for m in [put, nest] {
        match request(&by_job, &m).unwrap() {
            Msg::Ack { ok: false, info } => assert!(info.contains("not relayable"), "{info}"),
            r => panic!("{r:?}"),
        }
    }
    // an unknown worker, a job nobody holds
    let ghost = format!("relay://{}/acct:{}", seed.addr, hex32(&[7; 32]));
    assert!(matches!(request(&ghost, &Msg::GetL2(id)).unwrap(), Msg::Ack { ok: false, info } if info.contains("no relay route")));
    let nojob = format!("relay://{}/l2:{}", seed.addr, hex32(&[9; 32]));
    assert!(matches!(request(&nojob, &Msg::GetL2(id)).unwrap(), Msg::Ack { ok: false, info } if info.contains("no worker")));

    // the audit then settles the job like a direct one
    let client = SigningKey::from_bytes(&[100; 32]);
    assert!(matches!(client_tx(&seed, &client, TxKind::L2(L2Tx::Accept { job_id: id })), Msg::Ack { ok: true, .. }));
    wait("settled", 60, || l2_status(&seed.addr, id) == "Settled");

    // the worker leaves: the route goes away at once and a request is refused, not left hanging
    worker.stop();
    drop(c);
    wait("route removed", 30, || seed.relay_routes() == 0);
    assert!(matches!(request(&by_acct, &Msg::GetL2(id)).unwrap(), Msg::Ack { ok: false, .. }));
    assert!(seed.shared.node.lock().unwrap().chain.check_supply_invariant());
    seed.stop();
}

#[test]
fn a_node_that_is_not_a_relay_refuses_and_keeps_no_route() {
    let (seed, worker) = setup(false);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(seed.relay_routes(), 0, "announcements are ignored unless --relay");
    let addr = format!("relay://{}/acct:{}", seed.addr, hex32(&pubkey(&SigningKey::from_bytes(&[101; 32]))));
    assert!(matches!(request(&addr, &Msg::GetStatus).unwrap(), Msg::Ack { ok: false, info } if info.contains("not a relay")));
    worker.stop();
    seed.stop();
}

#[test]
fn a_forged_announcement_does_not_create_or_steal_a_route() {
    let (seed, worker) = setup(true);
    wait("route", 30, || seed.relay_routes() == 1);
    let real = SigningKey::from_bytes(&[101; 32]);
    // an attacker connects as a peer (Hello) and announces the worker's account with the worker's own genuine signature:
    // that signature is bound to the WORKER's connection key, not to the attacker's, so it must be refused
    let mut c = Conn::connect(&seed.addr).unwrap();
    c.send(&Msg::Hello { node_id: 42, genesis: seed.shared.genesis_hash, height: 0, work: 0, listen: None }).unwrap();
    let sig = sign(&real, &relay_msg(&seed.shared.genesis_hash, &worker.shared.keys.public));
    c.send(&Msg::RelayAnnounce { account: pubkey(&real), sig }).unwrap();
    // and one with a random signature
    c.send(&Msg::RelayAnnounce { account: pubkey(&real), sig: vec![1; 64] }).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(seed.relay_routes(), 1, "still only the real route");
    // the real worker still answers
    let acct = format!("relay://{}/acct:{}", seed.addr, hex32(&pubkey(&real)));
    assert!(matches!(request(&acct, &Msg::GetStatus).unwrap(), Msg::Status { .. }), "the route of the real worker was not stolen");
    drop(c);
    worker.stop();
    seed.stop();
}

#[test]
fn relay_address_syntax() {
    let id = [0xabu8; 32];
    let a = format!("relay://seed.example.org:9000/l2:{}", hex32(&id));
    assert_eq!(parse_relay_addr(&a), Some(("seed.example.org:9000".to_string(), RelayTo::L2Job(id))));
    let b = format!("relay://127.0.0.1:9000/acct:{}", hex32(&id));
    assert_eq!(parse_relay_addr(&b), Some(("127.0.0.1:9000".to_string(), RelayTo::Account(id))));
    for bad in ["127.0.0.1:9000", "relay://host/l2:zz", "relay://host/xx:00", "relay://host", "relay://host/l2:abcd"] {
        assert_eq!(parse_relay_addr(bad), None, "{bad}");
    }
}

/// The requests of an AI job on a model that the miner holds in advance (docs/21 section 4 bis) travel through the relay: `HasModel`, the input of the job
/// (`PutProgRef`, 1 MiB) and the reads of the outputs; uploading weights, or an input of the wrong size, does not.
#[test]
fn the_requests_of_an_ai_job_travel_through_the_relay() {
    let n = genesis().params.n;
    let dir = std::env::temp_dir().join(format!("vearl-relay-models-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let blocks: Vec<Vec<i8>> = (0..3).map(|k| (0..n * n).map(|i| (((i * 31 + k * 7) % 61) as i32 - 30) as i8).collect()).collect();
    let mut f = Vec::new();
    f.extend_from_slice(MODEL_PACK_MAGIC);
    f.extend_from_slice(&(n as u32).to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    for b in &blocks[..2] {
        f.extend(b.iter().map(|v| *v as u8));
    }
    std::fs::write(dir.join("m.vblocks"), f).unwrap();

    let (seed, worker) = setup(true);
    assert_eq!(worker.preload_models(dir.clone(), false).join().unwrap(), (2, 0));
    wait("route", 30, || seed.relay_routes() == 1);
    let acct = format!("relay://{}/acct:{}", seed.addr, hex32(&pubkey(&SigningKey::from_bytes(&[101; 32]))));
    let roots: Vec<Hash> = blocks.iter().map(|b| vearl_core::work::rows_tree(b, n).root()).collect();

    // has the miner the model?
    match request(&acct, &Msg::HasModel { roots: roots.clone() }).unwrap() {
        Msg::ModelHave { have } => assert_eq!(have, vec![true, true, false]),
        m => panic!("{m:?}"),
    }
    // the input of a job (1 MiB through the seed) is accepted, like a direct put; an unknown block is refused by the WORKER (not by the relay)
    let x0 = vec![1i8; n * n];
    assert!(matches!(request(&acct, &Msg::PutProgRef { x0: x0.clone(), w_roots: roots[..2].to_vec() }).unwrap(), Msg::Ack { ok: true, .. }));
    match request(&acct, &Msg::PutProgRef { x0: x0.clone(), w_roots: roots.clone() }).unwrap() {
        Msg::Ack { ok: false, info } => assert!(info.contains("unknown model block"), "{info}"),
        m => panic!("{m:?}"),
    }
    // and it is in the worker's store: the same call made directly says the same
    assert!(matches!(request(&worker.addr, &Msg::PutProgRef { x0: x0.clone(), w_roots: roots[..2].to_vec() }).unwrap(), Msg::Ack { ok: true, .. }));
    // reads of the outputs reach the worker (nothing has run, so it answers "no such operation": an answer of the worker, not a refusal of the relay)
    for m in [Msg::GetOpsBox { job: [5; 32], ops: vec![0, 1] }, Msg::GetOpsBoxZ { job: [5; 32], ops: vec![0, 1] }, Msg::GetOp { job: [5; 32], op: 0 }] {
        match request(&acct, &m).unwrap() {
            Msg::Ack { ok: false, info } => assert!(!info.contains("not relayable"), "{info}"),
            m => panic!("{m:?}"),
        }
    }
    // what must not travel: the weights of a model (more than a couple of blocks), an input that is not 1 MiB-ish, a request that relays again
    match request(&acct, &Msg::PutModel { ws: blocks.clone() }).unwrap() {
        Msg::Ack { ok: false, info } => assert!(info.contains("not relayable"), "{info}"),
        m => panic!("{m:?}"),
    }
    // ... but one block that the pack does not hold (the mean vector of a text of another length) can be put, and is then there
    assert!(matches!(request(&acct, &Msg::PutModel { ws: vec![blocks[2].clone()] }).unwrap(), Msg::Ack { ok: true, .. }));
    match request(&acct, &Msg::HasModel { roots: roots.clone() }).unwrap() {
        Msg::ModelHave { have } => assert_eq!(have, vec![true; 3]),
        m => panic!("{m:?}"),
    }
    let too_big = Msg::PutProgRef { x0: vec![1i8; 3 << 20], w_roots: roots[..2].to_vec() };
    match request(&acct, &too_big).unwrap() {
        Msg::Ack { ok: false, info } => assert!(info.contains("not relayable"), "{info}"),
        m => panic!("{m:?}"),
    }
    // the bulk budget: two inputs in flight at once through one worker are fine, and the node keeps answering the small requests meanwhile
    std::thread::scope(|s| {
        for _ in 0..2 {
            let (a, x, r) = (acct.clone(), x0.clone(), roots[..2].to_vec());
            s.spawn(move || {
                let reply = request(&a, &Msg::PutProgRef { x0: x, w_roots: r }).unwrap();
                assert!(matches!(reply, Msg::Ack { ok: true, .. }) || matches!(&reply, Msg::Ack { info, .. } if info.contains("busy") || info.contains("store full")), "{reply:?}");
            });
        }
        assert!(matches!(request(&acct, &Msg::GetStatus).unwrap(), Msg::Status { .. }));
    });
    worker.stop();
    seed.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The compressed reply of operation outputs (`OpsBoxZ`): what the worker packs, the client unpacks, identically; a bomb or garbage is refused.
#[test]
fn compressed_operation_outputs_round_trip_and_a_bomb_is_refused() {
    let n = 64usize;
    // outputs the way a program has them: a box with repeated rows, mostly small values
    let x: Vec<i8> = (0..n * 8).map(|i| ((i % 8) as i8) - 3).collect();
    let z: Vec<i32> = (0..n * 8).map(|i| (i % 8) as i32 * 1000 - 3000).collect();
    let items = vec![BoxedOp { x_dims: (8, n as u32), x: x.clone(), z_dims: Some((8, n as u32)), z: z.clone() }, BoxedOp { x_dims: (0, 0), x: vec![], z_dims: None, z: vec![] }];
    let packed = pack_ops_z(&items).unwrap();
    assert!(packed.len() * 4 < (x.len() + 4 * z.len()), "repetitive boxes shrink a lot ({} bytes)", packed.len());
    let back = unpack_ops_z(&packed).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!((back[0].x.clone(), back[0].z.clone(), back[0].x_dims, back[0].z_dims), (x, z, (8, n as u32), Some((8, n as u32))));
    assert!(back[1].x.is_empty() && back[1].z_dims.is_none());
    // garbage, a truncated stream and a bomb (a huge run of zeros that inflates beyond the limit) are refused
    assert!(unpack_ops_z(&[1, 2, 3, 4, 5]).is_none());
    assert!(unpack_ops_z(&packed[..packed.len() / 2]).is_none());
    let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; OPS_BOX_Z_MAX_RAW + 1024], 9);
    assert!(bomb.len() < 200_000, "the bomb itself is small ({} bytes)", bomb.len());
    assert!(unpack_ops_z(&bomb).is_none(), "refused instead of inflated");
}

/// The relay node knows which announced workers can also be dialed directly (`/api/workers`), and a link test goes through the relay and measures the
/// miner's real link (bytes that do not compress).
#[test]
fn the_relay_lists_its_workers_and_a_link_test_goes_through_it() {
    let (seed, worker) = setup(true);
    wait("route", 30, || seed.relay_routes() == 1);
    wait("the seed has tried to dial the worker", 30, || relay_workers(&seed.shared).first().map_or(false, |w| w.direct.is_some()));
    let list = relay_workers(&seed.shared);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].account, pubkey(&SigningKey::from_bytes(&[101; 32])));
    assert_eq!(list[0].direct, Some(true), "a node listening on a reachable address is marked direct (here the loopback)");
    assert_eq!(list[0].dial.as_deref(), Some(worker.addr.as_str()));

    let acct = format!("relay://{}/acct:{}", seed.addr, hex32(&list[0].account));
    for addr in [&acct, &worker.addr] {
        match request(addr, &Msg::GetProbe { bytes: 3 << 20, nonce: 7 }).unwrap() {
            Msg::Probe(v) => {
                assert_eq!(v.len(), 3 << 20);
                assert_eq!(v, probe_bytes(3 << 20, 7), "the same stream from both ends");
                assert!(miniz_oxide::deflate::compress_to_vec(&v[..1 << 20], 6).len() > (1 << 20) * 9 / 10, "it does not compress: the test measures the link");
            }
            m => panic!("{m:?}"),
        }
    }
    // asked for more than the maximum: the maximum (8 MiB goes through a relay)
    match request(&acct, &Msg::GetProbe { bytes: u32::MAX, nonce: 1 }).unwrap() {
        Msg::Probe(v) => assert_eq!(v.len(), PROBE_MAX as usize),
        m => panic!("{m:?}"),
    }
    // the worker leaves: the entry goes with the route
    worker.stop();
    wait("route removed", 30, || relay_workers(&seed.shared).is_empty());
    seed.stop();
}
