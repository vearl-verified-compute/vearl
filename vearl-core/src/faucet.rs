//! Testnet faucet: hands out a small amount (without value) to an address, with limits per address, per IP and per day.
//! The faucet key is that of a dedicated wallet, funded by the genesis; it must never be that of a
//! personal wallet. Behind a reverse proxy, the IP seen is the proxy's: apply a limit there too.
use crate::crypto::*;
use crate::httpmini::{Request, Response};
use crate::net::{request, Msg};
use crate::types::*;
use crate::wallet::{address_of, fmt_amount, parse_address};
use ed25519_dalek::SigningKey;
use serde_json::json;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct FaucetConfig {
    pub node: String,
    pub amount: u64,
    pub cooldown: Duration,
    pub max_per_day: u64,
}

pub struct Faucet {
    cfg: FaucetConfig,
    sk: SigningKey,
    state: Mutex<FaucetState>,
    storage: Option<Storage>,
}

// Wall-clock seconds survive process restarts. A backward clock adjustment must not
// open a fresh daily budget or shorten a previously reserved cooldown.
#[derive(Clone, Default, Serialize, Deserialize)]
struct FaucetState {
    by_addr: HashMap<String, u64>,
    by_ip: HashMap<String, u64>,
    day: u64,
    sent_today: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedState {
    version: u32,
    faucet: String,
    limits: FaucetState,
}

struct Storage {
    path: PathBuf,
    // Lock a separate inode: the state file is atomically replaced on every save.
    _lock: File,
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

impl Storage {
    fn save(&self, state: &FaucetState, faucet: &str) -> Result<(), String> {
        let raw = serde_json::to_vec(&SavedState {
            version: 1, faucet: faucet.into(), limits: state.clone(),
        }).map_err(|e| e.to_string())?;
        let mut temp = self.path.as_os_str().to_os_string();
        temp.push(format!(".tmp-{:016x}", rand::random::<u64>()));
        let temp = PathBuf::from(temp);
        let result = (|| -> std::io::Result<()> {
            let mut file = private_file(&temp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &self.path)?;
            #[cfg(unix)]
            File::open(self.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&temp); }
        result.map_err(|e| format!("cannot persist faucet limits: {e}"))
    }
}

const PAGE: &str = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>\
<title>VEARL faucet</title><style>body{font:15px system-ui;max-width:560px;margin:40px auto;padding:0 16px}\
input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box}button{padding:10px 16px}</style>\
<h1>VEARL faucet (testnet)</h1><p>Test tokens with no value. One request per address and per hour.</p>\
<input id=a placeholder='vrl1...' autocomplete=off><button id=b>Receive</button><pre id=o></pre>\
<script>document.getElementById('b').onclick=async()=>{const r=await fetch('/drip',{method:'POST',body:JSON.stringify({address:document.getElementById('a').value.trim()})});\
document.getElementById('o').textContent=JSON.stringify(await r.json(),null,2)}</script>";

impl Faucet {
    /// Ephemeral limits for embedded/devnet use; the CLI uses `persistent`.
    pub fn new(cfg: FaucetConfig, sk: SigningKey) -> Faucet {
        Faucet { cfg, sk, state: Mutex::new(FaucetState::default()), storage: None }
    }

    /// Persist rate limits; missing state starts a new budget, unreadable/invalid state fails closed.
    /// The parent directory must already exist and be writable by the service user.
    pub fn persistent(cfg: FaucetConfig, sk: SigningKey, path: impl AsRef<Path>) -> Result<Faucet, String> {
        let path = path.as_ref().to_path_buf();
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock = match private_file(&lock_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new().read(true).write(true).open(&lock_path).map_err(|e| e.to_string())?,
            Err(e) => return Err(format!("cannot open faucet state lock: {e}")),
        };
        lock.try_lock().map_err(|e| format!("cannot lock faucet state (another faucet running?): {e}"))?;
        let address = address_of(&pubkey(&sk));
        let state = match fs::read(&path) {
            Ok(raw) => {
                let saved: SavedState = serde_json::from_slice(&raw).map_err(|e| format!("invalid faucet state: {e}"))?;
                if saved.version != 1 || saved.faucet != address {
                    return Err("faucet state version or wallet mismatch".into());
                }
                saved.limits
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FaucetState::default(),
            Err(e) => return Err(format!("cannot read faucet state: {e}")),
        };
        let storage = Storage { path, _lock: lock };
        storage.save(&state, &address)?;
        Ok(Faucet { cfg, sk, state: Mutex::new(state), storage: Some(storage) })
    }

    pub fn address(&self) -> String {
        address_of(&pubkey(&self.sk))
    }

    pub fn handle(&self, req: Request) -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => Response::html(PAGE),
            ("GET", "/health") => Response::json(200, &json!({ "ok": true, "faucet": self.address() })),
            ("POST", "/drip") => self.drip(&req),
            ("GET", _) | ("POST", _) => Response::error(404, "unknown route"),
            _ => Response::error(405, "method not allowed"),
        }
    }

    fn drip(&self, req: &Request) -> Response {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(t) => t.as_secs(),
            Err(_) => return Response::error(503, "system clock predates Unix epoch"),
        };
        self.drip_at(req, now, |msg| request(&self.cfg.node, msg))
    }

    fn drip_at(&self, req: &Request, now: u64, mut send: impl FnMut(&Msg) -> std::io::Result<Msg>) -> Response {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else { return Response::error(400, "JSON body expected: {\"address\":\"vrl1...\"}") };
        let Some(addr) = v.get("address").and_then(|a| a.as_str()) else { return Response::error(400, "field 'address' required") };
        let to = match parse_address(addr) {
            Ok(p) => p,
            Err(e) => return Response::error(400, &e),
        };
        if to == pubkey(&self.sk) {
            return Response::error(400, "the faucet does not send anything to itself");
        }
        let day = now / 86_400;
        // Critical section: checks the limits AND signs/sends under the same lock (sequential nonces, no race).
        let mut st = self.state.lock().unwrap();
        if day > st.day {
            st.day = day;
            st.sent_today = 0;
        }
        if self.cfg.amount > self.cfg.max_per_day.saturating_sub(st.sent_today) {
            return Response::error(429, "daily faucet cap reached");
        }
        for (label, last) in [("this address", st.by_addr.get(&address_of(&to)).copied()), ("this IP", st.by_ip.get(&req.peer).copied())] {
            if let Some(t) = last {
                let wait = t.saturating_add(self.cfg.cooldown.as_secs()).saturating_sub(now);
                if wait > 0 {
                    return Response::json(429, &json!({ "error": format!("{label} has already received tokens"), "retry_in_secs": wait }));
                }
            }
        }
        let from = pubkey(&self.sk);
        let (balance, next_nonce) = match send(&Msg::GetAccount(from)) {
            Ok(Msg::Account { balance, next_nonce, .. }) => (balance, next_nonce),
            _ => return Response::error(503, "node unreachable"),
        };
        if balance < self.cfg.amount {
            return Response::error(503, "faucet empty");
        }
        let tx = SignedTx::new(Tx { from, nonce: next_nonce, fee: 0, kind: TxKind::Transfer { to, amount: self.cfg.amount } }, &self.sk);
        let id = tx.id();
        // Reserve BEFORE broadcast. A crash, rejection or ambiguous reply must not
        // allow another payment against the same budget after a restart.
        // Expired cooldowns can be discarded; the daily budget is independent.
        st.by_addr.retain(|_, t| now.saturating_sub(*t) < self.cfg.cooldown.as_secs());
        st.by_ip.retain(|_, t| now.saturating_sub(*t) < self.cfg.cooldown.as_secs());
        st.by_addr.insert(address_of(&to), now);
        st.by_ip.insert(req.peer.clone(), now);
        st.sent_today = st.sent_today.saturating_add(self.cfg.amount);
        if let Some(storage) = &self.storage {
            if storage.save(&st, &self.address()).is_err() {
                // Keep the in-memory reservation too; no transaction is sent.
                return Response::error(503, "cannot persist faucet limits; no transfer sent");
            }
        }
        match send(&Msg::NewTx(tx)) {
            Ok(Msg::Ack { ok: true, .. }) => {}
            Ok(Msg::Ack { ok: false, info }) => return Response::error(503, &format!("transaction refused: {info}")),
            _ => return Response::error(503, "node unreachable"),
        }
        Response::json(200, &json!({ "ok": true, "amount": fmt_amount(self.cfg.amount), "to": address_of(&to), "tx": id.iter().map(|b| format!("{b:02x}")).collect::<String>() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("vearl-faucet-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn state(&self) -> PathBuf { self.0.join("limits.json") }
    }
    impl Drop for Dir { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn config(cap: u64) -> FaucetConfig {
        FaucetConfig { node: "unused".into(), amount: 10, cooldown: Duration::from_secs(3600), max_per_day: cap }
    }
    fn open(dir: &Dir, cap: u64) -> Faucet {
        Faucet::persistent(config(cap), SigningKey::from_bytes(&[101; 32]), dir.state()).unwrap()
    }
    fn req(seed: u8, ip: &str) -> Request {
        Request { method: "POST".into(), path: "/drip".into(), query: String::new(),
            body: json!({"address": address_of(&pubkey(&SigningKey::from_bytes(&[seed; 32])))}).to_string().into_bytes(), peer: ip.into() }
    }
    fn accepted(msg: &Msg) -> std::io::Result<Msg> {
        Ok(match msg {
            Msg::GetAccount(_) => Msg::Account { balance: u64::MAX, nonce: 0, next_nonce: 0 },
            Msg::NewTx(_) => Msg::Ack { ok: true, info: String::new() },
            _ => panic!("unexpected message"),
        })
    }
    const NOW: u64 = 50 * 86400 + 100;

    #[test]
    fn daily_cap_survives_restart() {
        let dir = Dir::new();
        let f = open(&dir, 10);
        assert_eq!(f.drip_at(&req(1, "a"), NOW, accepted).status, 200);
        drop(f);
        let f = open(&dir, 10);
        assert_eq!(f.drip_at(&req(2, "b"), NOW + 1, accepted).status, 429);
    }

    #[test]
    fn address_and_ip_cooldowns_survive_restart_and_expire() {
        let dir = Dir::new();
        let f = open(&dir, 100);
        assert_eq!(f.drip_at(&req(1, "a"), NOW, accepted).status, 200);
        drop(f);
        let f = open(&dir, 100);
        assert_eq!(f.drip_at(&req(1, "b"), NOW + 1, accepted).status, 429);
        assert_eq!(f.drip_at(&req(2, "a"), NOW + 1, accepted).status, 429);
        assert_eq!(f.drip_at(&req(1, "a"), NOW + 3600, accepted).status, 200);
    }

    #[test]
    fn state_is_reserved_before_broadcast_and_ambiguous_reply_stays_reserved() {
        let dir = Dir::new();
        let f = open(&dir, 10);
        let response = f.drip_at(&req(1, "a"), NOW, |msg| {
            if matches!(msg, Msg::NewTx(_)) {
                let saved: SavedState = serde_json::from_slice(&fs::read(dir.state()).unwrap()).unwrap();
                assert_eq!(saved.limits.sent_today, 10);
                return Err(std::io::Error::other("reply lost after send"));
            }
            accepted(msg)
        });
        assert_eq!(response.status, 503);
        drop(f);
        assert_eq!(open(&dir, 10).drip_at(&req(2, "b"), NOW + 1, accepted).status, 429);
    }

    #[test]
    fn rejected_send_is_conservatively_reserved() {
        let dir = Dir::new();
        let f = open(&dir, 10);
        assert_eq!(f.drip_at(&req(1, "a"), NOW, |msg| {
            if matches!(msg, Msg::NewTx(_)) { Ok(Msg::Ack { ok: false, info: "refused".into() }) } else { accepted(msg) }
        }).status, 503);
        drop(f);
        assert_eq!(open(&dir, 10).drip_at(&req(2, "b"), NOW + 1, accepted).status, 429);
    }

    #[test]
    fn persistence_failure_never_broadcasts() {
        let dir = Dir::new();
        let f = open(&dir, 100);
        fs::remove_file(dir.state()).unwrap();
        fs::create_dir(dir.state()).unwrap(); // Atomic rename cannot replace a directory.
        let response = f.drip_at(&req(1, "a"), NOW, |msg| {
            assert!(!matches!(msg, Msg::NewTx(_)), "must not broadcast without durable reservation");
            accepted(msg)
        });
        assert_eq!(response.status, 503);
    }

    #[test]
    fn corrupt_mismatched_and_locked_state_fail_closed() {
        let dir = Dir::new();
        let f = open(&dir, 100);
        assert!(Faucet::persistent(config(100), SigningKey::from_bytes(&[101; 32]), dir.state()).is_err());
        drop(f);
        assert!(Faucet::persistent(config(100), SigningKey::from_bytes(&[102; 32]), dir.state()).is_err());
        fs::write(dir.state(), b"{}").unwrap();
        assert!(Faucet::persistent(config(100), SigningKey::from_bytes(&[101; 32]), dir.state()).is_err());
        fs::write(dir.state(), b"not json").unwrap();
        assert!(Faucet::persistent(config(100), SigningKey::from_bytes(&[101; 32]), dir.state()).is_err());
    }

    #[test]
    fn utc_rollover_opens_budget_but_clock_rollback_does_not() {
        let dir = Dir::new();
        let f = open(&dir, 10);
        assert_eq!(f.drip_at(&req(1, "a"), NOW, accepted).status, 200);
        drop(f);
        let f = open(&dir, 10);
        assert_eq!(f.drip_at(&req(2, "b"), NOW - 86400, accepted).status, 429);
        assert_eq!(f.drip_at(&req(2, "b"), NOW + 86400, accepted).status, 200);
    }

    #[test]
    fn concurrent_requests_cannot_overspend_cap() {
        let dir = Dir::new();
        let f = Arc::new(open(&dir, 20));
        let sends = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (1..9).map(|i| {
            let f = f.clone(); let sends = sends.clone();
            std::thread::spawn(move || f.drip_at(&req(i, &i.to_string()), NOW, |msg| {
                if matches!(msg, Msg::NewTx(_)) { sends.fetch_add(1, Ordering::SeqCst); }
                accepted(msg)
            }).status)
        }).collect();
        let statuses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(statuses.iter().filter(|s| **s == 200).count(), 2);
        assert_eq!(sends.load(Ordering::SeqCst), 2);
        drop(f);
        assert_eq!(open(&dir, 20).drip_at(&req(10, "new"), NOW + 1, accepted).status, 429);
    }
}
