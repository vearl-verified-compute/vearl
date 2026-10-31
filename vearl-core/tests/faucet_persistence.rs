//! Real CLI process restart regression: no state is shared between faucet instances.
use ed25519_dalek::SigningKey;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use vearl_core::{chain::GenesisConfig, crypto::pubkey, net::{spawn_node, NodeConfig},
    state::Timing, wallet::{address_of, derive_account, new_mnemonic, KdfParams, Keystore}, work::WorkParams};

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) { for p in &mut self.0 { let _ = p.kill(); let _ = p.wait(); } }
}
struct Dir(PathBuf);
impl Drop for Dir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn http(port: u16, address: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let body = address.map(|a| serde_json::json!({"address":a}).to_string()).unwrap_or_default();
    let (method, path) = if address.is_some() { ("POST", "/drip") } else { ("GET", "/health") };
    write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut out = String::new(); s.read_to_string(&mut out).unwrap();
    (out.split_whitespace().nth(1).unwrap().parse().unwrap(), out)
}

#[test]
fn cli_limits_survive_abrupt_process_restart() {
    let dir = Dir(std::env::temp_dir().join(format!("vearl-faucet-cli-{:016x}", rand::random::<u64>())));
    std::fs::create_dir(&dir.0).unwrap();
    let phrase = new_mnemonic();
    let ks = Keystore::create(&phrase, "disposable-test-password", KdfParams::LIGHT).unwrap();
    let wallet = dir.0.join("wallet.json"); ks.save(&wallet).unwrap();
    let node = spawn_node(NodeConfig {
        genesis: GenesisConfig { params: WorkParams::TESTNET, alloc: vec![(pubkey(&derive_account(&phrase, 0)), 100_000_000_000)],
            ts: 1_700_000_000, target: u64::MAX / 256, timing: Timing::default(), retarget: vearl_core::chain::Retarget::Fixed },
        listen: "127.0.0.1:0".into(), peers: vec![], mine_key: Some(SigningKey::from_bytes(&[2;32])),
        use_gpu: false, log: false, worker: None, data_dir: None,
    }).unwrap();
    let bind = TcpListener::bind("127.0.0.1:0").unwrap(); let port = bind.local_addr().unwrap().port(); drop(bind);
    let state = dir.0.join("limits.json");
    let start = |cap: &str| {
        Command::new(env!("CARGO_BIN_EXE_vearl-faucet"))
            .args(["--node", &node.addr, "--wallet"]).arg(&wallet)
            .args(["--listen", &format!("127.0.0.1:{port}"), "--amount", "10", "--max-per-day", cap, "--state-file"])
            .arg(&state).env("VEARL_WALLET_PASSWORD", "disposable-test-password")
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap()
    };
    let ready = |p: &mut Child| {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            assert!(p.try_wait().unwrap().is_none(), "faucet exited before listen");
            if TcpStream::connect(("127.0.0.1", port)).is_ok() { return; }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("faucet did not listen");
    };
    let mut processes = Children(vec![start("10")]); ready(&mut processes.0[0]);
    let a = address_of(&pubkey(&SigningKey::from_bytes(&[8;32])));
    let b = address_of(&pubkey(&SigningKey::from_bytes(&[9;32])));
    assert_eq!(http(port, Some(&a)).0, 200);
    processes.0[0].kill().unwrap(); processes.0[0].wait().unwrap();
    processes.0.push(start("10")); ready(&mut processes.0[1]);
    let response = http(port, Some(&b)); assert_eq!(response.0, 429, "{}", response.1);
    assert!(response.1.contains("daily faucet cap"));
    processes.0[1].kill().unwrap(); processes.0[1].wait().unwrap();
    processes.0.push(start("100")); ready(&mut processes.0[2]);
    let response = http(port, Some(&a)); assert_eq!(response.0, 429); assert!(response.1.contains("this address"));
    let response = http(port, Some(&b)); assert_eq!(response.0, 429); assert!(response.1.contains("this IP"));
    drop(processes);
    node.stop();
}
