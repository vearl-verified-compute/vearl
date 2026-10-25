//! Dual mining: a GPU shared between Vearl and an external Quantus (QTC) miner.
//!
//! When the node has no paid work to do (no job it can compute), the GPU time is split by a fixed duty cycle: for `share_pct` percent of
//! every cycle an external miner owns the GPU and the Vearl miner is paused; for the rest of the cycle the external miner is frozen and
//! the Vearl miner owns the GPU. The two never compute at the same moment, so the split is exact and no work is lost to contention.
//! As soon as the node has a job to compute, Vearl takes the whole GPU (the external miner stays frozen).
//!
//! **Development fee (disclosed).** In the Quantus mode the operator mines to their OWN address, and `qtc_fee_pct()` percent of the
//! Quantus mining time is spent mining to the Vearl development address (`dev_qtc_address()`). The fee address is a constant of the program,
//! it has no option; the percentage and the address are printed at every start and written in `docs/15`. This is a convention of the
//! official build, not a protocol rule: the source is open and anyone can build a version without the fee.
//!
//! What this is not: Vearl never reads, verifies or pays anything for the Quantus work. The Quantus rewards come from the pool.
use crate::net::Shared;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Address that receives the development fee (Quantus, mainnet). Not a string of the program: see `feeguard.rs`.
pub fn dev_qtc_address() -> String {
    crate::feeguard::dev_address()
}
/// Share of the Quantus mining time given to the development address, in percent. Not a constant of the source: it is generated when the program
/// is built and hidden in the executable together with the address (`feeguard.rs`, `build.rs`).
pub fn qtc_fee_pct() -> u32 {
    crate::feeguard::fee_pct()
}
/// Default pool (quanpool.com, QUIC) and the SHA-256 pin of its certificate, as published on the pool's "Start mining" page.
pub const QTC_POOL_ADDR: &str = "37.187.143.115:9834";
pub const QTC_POOL_CERT: &str = "87dc37af6096a3ddc860b94368ca087775f3ad3e0c4e9bcff3b07ea08d8abef6";
/// Current phase of dual mining (0: scheduler inactive, 1: Quantus, 2: fee miner, 3: Vearl window, 4: paid job) and cumulative
/// time spent in each phase (ms): used for the node's status lines.
pub static DUAL_PHASE: AtomicU8 = AtomicU8::new(0);
pub static DUAL_MS: [AtomicU64; 5] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Cumulative time during which the GPU worked for Vearl (Vearl windows + paid jobs), in ms.
pub fn vearl_active_ms() -> u64 {
    DUAL_MS[3].load(Ordering::Relaxed) + DUAL_MS[4].load(Ordering::Relaxed)
}

/// Readable summary of the GPU time split since the start (None if the scheduler did not run).
pub fn dual_summary() -> Option<String> {
    let ms: Vec<u64> = DUAL_MS.iter().map(|m| m.load(Ordering::Relaxed)).collect();
    let total: u64 = ms[1..].iter().sum();
    if total == 0 {
        return None;
    }
    let pct = |i: usize| ms[i] as f64 * 100.0 / total as f64;
    let now = match DUAL_PHASE.load(Ordering::Relaxed) {
        1 => "Quantus",
        2 => "Quantus (development fee)",
        3 => "Vearl",
        4 => "PAID JOB (Vearl)",
        _ => "-",
    };
    Some(format!("GPU now: {now} | share of the time since start: Quantus {:.0} % + dev fee {:.0} %, Vearl {:.0} %, paid jobs {:.0} %", pct(1), pct(2), pct(3), pct(4)))
}

/// Sleeps `ms` milliseconds (interruptible) and counts them in phase `phase`.
fn spend(sh: &Shared, phase: u8, ms: u64) {
    DUAL_PHASE.store(phase, Ordering::Relaxed);
    let t = Instant::now();
    sleep_ms_or_stop(sh, ms);
    DUAL_MS[phase as usize].fetch_add(t.elapsed().as_millis() as u64, Ordering::Relaxed);
}

/// Shortest slice given to the fee miner, in seconds (the fee is paid in slices of about this length).
const MIN_FEE_SLICE: f64 = 8.0;

#[derive(Clone, Debug)]
pub struct FeeCfg {
    /// Command line of the miner that mines to the development address.
    pub cmd: Vec<String>,
    /// Share of the external mining time it gets, in percent.
    pub pct: u32,
}

#[derive(Clone, Debug)]
pub struct DualCfg {
    /// Command line of the external miner (program and arguments).
    pub cmd: Vec<String>,
    /// Development-fee miner, if any.
    pub fee: Option<FeeCfg>,
    /// Share of the GPU time given to the external miner while the node has no paid work, in percent (0..=100).
    pub share_pct: u32,
    /// Length of one duty cycle, in seconds.
    pub cycle_s: u64,
    /// Path of the official Quantus miner: when set, its hash is checked against the pin of this build before EVERY start.
    pub quantus_bin: Option<String>,
    /// Signed beacons for the fee audit (feeguard.rs); None for stand-in miners (tests).
    pub beacon: Option<BeaconCfg>,
}

#[derive(Clone)]
pub struct BeaconCfg {
    pub key: ed25519_dalek::SigningKey,
    pub quantus: String,
    /// seed specs `host:port@noise_key`
    pub seeds: Vec<String>,
}

impl std::fmt::Debug for BeaconCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BeaconCfg {{ quantus: {}, seeds: {} }}", self.quantus, self.seeds.len()) // never prints the key
    }
}

/// Splits a command line into words; single and double quotes group words, there is no other escaping.
pub fn parse_cmd(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut any) = (Vec::new(), String::new(), None::<char>, false);
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                quote = Some(ch);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Lengths in seconds of the external window and of the Vearl window of one cycle. Each non-empty share keeps at least one second.
pub fn windows(cycle_s: u64, pct: u32) -> (u64, u64) {
    let pct = pct.min(100) as u64;
    let cycle = cycle_s.max(2);
    if pct == 0 {
        return (0, cycle);
    }
    if pct == 100 {
        return (cycle, 0);
    }
    let p = (cycle * pct / 100).clamp(1, cycle - 1);
    (p, cycle - p)
}

/// A Quantus payout address: `qz` followed by letters and digits (the pool refuses anything else).
pub fn valid_qtc_address(a: &str) -> bool {
    (40..=60).contains(&a.len()) && a.starts_with("qz") && a.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Commands of the two Quantus miners: the one that mines to the operator's address and the fee miner (development address).
/// `miner` is the path of the official `quantus-miner` binary, `id` is a short hexadecimal identifier of the Vearl miner (worker name).
pub fn qtc_commands(miner: &str, user_addr: &str, id: &str, pool: &str, cert: &str, extra: &[String]) -> (Vec<String>, Vec<String>) {
    let build = |addr: &str, worker: String, metrics: &str| -> Vec<String> {
        let mut c: Vec<String> = vec![miner.into(), "serve".into(), "--node-addr".into(), pool.into(), "--auth-token".into(), format!("{addr}.{worker}"), "--tls-cert-sha256".into(), cert.into()];
        c.extend(extra.iter().cloned());
        c.push("--metrics-port".into());
        c.push(metrics.into());
        c
    };
    (build(user_addr, format!("vrl-{id}"), "9900"), build(&dev_qtc_address(), format!("vrl-fee-{id}"), "9901"))
}

/// Decides, second by second, whether the fee miner owns the GPU: the fee miner gets exactly `pct` percent of the external time,
/// in slices of at least `MIN_FEE_SLICE` seconds so that the pool sees a steady stream of shares.
pub struct FeeMeter {
    credit: f64,
    debt: f64,
    active: bool,
}

impl FeeMeter {
    pub fn new(pct: u32) -> Self {
        FeeMeter { credit: pct.min(100) as f64 / 100.0, debt: 0.0, active: false }
    }

    /// Call once per second of external mining time; true if the fee miner must run during that second.
    pub fn tick(&mut self) -> bool {
        self.debt += self.credit;
        if !self.active && self.debt >= MIN_FEE_SLICE {
            self.active = true;
        }
        let run = self.active;
        if run {
            self.debt -= 1.0;
            if self.debt < 1.0 {
                self.active = false;
            }
        }
        run
    }
}

/// An external miner: started on demand, frozen outside its windows, restarted if it exits.
struct ExtProc {
    name: &'static str,
    cmd: Vec<String>,
    child: Option<Child>,
    frozen: bool,
    /// official binary whose hash must match the pin before every start
    verify: Option<String>,
}

impl ExtProc {
    fn new(name: &'static str, cmd: Vec<String>) -> Self {
        ExtProc { name, cmd, child: None, frozen: false, verify: None }
    }

    fn alive(&mut self) -> bool {
        match self.child.as_mut().map(|c| c.try_wait()) {
            Some(Ok(None)) => true,
            Some(_) => {
                eprintln!("[dual] the {} miner exited, it will be restarted at its next window", self.name);
                self.child = None;
                self.frozen = false;
                false
            }
            None => false,
        }
    }

    fn start(&mut self) {
        if crate::feeguard::violation() {
            return;
        }
        if self.name == "fee" && self.verify.is_some() && !crate::feeguard::fee_cmd_ok(&self.cmd) {
            // the fee miner would not mine to the development address: nothing of this program may use the Quantus miner then
            eprintln!("[dual] the fee miner is NOT started: its command does not mine to the development address of this program (altered settings)");
            crate::feeguard::set_violation();
            return;
        }
        if let Some(bin) = &self.verify {
            if let Err(e) = crate::feeguard::verify_quantus_binary(std::path::Path::new(bin)) {
                eprintln!("[dual] the {} miner is NOT started: {e}", self.name);
                return;
            }
            if !crate::feeguard::fee_constants_ok() {
                eprintln!("[dual] the {} miner is NOT started: the fee constants of this program were altered", self.name);
                return;
            }
        }
        let logname = format!("{}-miner.log", self.name);
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&logname);
        let (out, err) = match log {
            Ok(f) => match f.try_clone() {
                Ok(g) => (Stdio::from(f), Stdio::from(g)),
                Err(_) => (Stdio::null(), Stdio::null()),
            },
            Err(_) => (Stdio::null(), Stdio::null()),
        };
        match Command::new(&self.cmd[0]).args(&self.cmd[1..]).stdin(Stdio::null()).stdout(out).stderr(err).spawn() {
            Ok(c) => {
                eprintln!("[dual] {} miner started (pid {}), its output goes to {logname}", self.name, c.id());
                #[cfg(unix)]
                watchdog(c.id());
                self.child = Some(c);
                self.frozen = false;
            }
            Err(e) => eprintln!("[dual] cannot start the {} miner `{}`: {e}", self.name, self.cmd[0]),
        }
    }

    /// Lets the miner run (starts it if needed).
    fn resume(&mut self) {
        if !self.alive() {
            self.start();
            return;
        }
        if self.frozen {
            #[cfg(unix)]
            if let Some(c) = &self.child {
                signal(c.id(), "-CONT");
            }
            #[cfg(windows)]
            if let Some(c) = &self.child {
                use std::os::windows::io::AsRawHandle;
                unsafe { winproc::NtResumeProcess(c.as_raw_handle() as *mut _) };
            }
            self.frozen = false;
        }
    }

    /// Freezes the miner: SIGSTOP on Unix, NtSuspendProcess on Windows (the process and its VRAM stay, so it resumes instantly).
    fn freeze(&mut self) {
        if !self.alive() || self.frozen {
            return;
        }
        #[cfg(unix)]
        if let Some(c) = &self.child {
            signal(c.id(), "-STOP");
        }
        #[cfg(windows)]
        if let Some(c) = &self.child {
            use std::os::windows::io::AsRawHandle;
            unsafe { winproc::NtSuspendProcess(c.as_raw_handle() as *mut _) };
        }
        self.frozen = true;
    }

    fn shutdown(&mut self) {
        if let Some(mut c) = self.child.take() {
            #[cfg(unix)]
            signal(c.id(), "-CONT");
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                unsafe { winproc::NtResumeProcess(c.as_raw_handle() as *mut _) };
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Windows: NtSuspendProcess / NtResumeProcess (ntdll) freeze and wake all the threads of the process like SIGSTOP / SIGCONT: the external miner
/// keeps its CUDA context and its memory, resuming is immediate (no restart at every window).
#[cfg(windows)]
mod winproc {
    use std::ffi::c_void;
    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtSuspendProcess(h: *mut c_void) -> i32;
        pub fn NtResumeProcess(h: *mut c_void) -> i32;
    }
}

#[cfg(unix)]
fn signal(pid: u32, sig: &str) {
    let _ = Command::new("kill").arg(sig).arg(pid.to_string()).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// If the node dies while the miner is frozen, nobody would ever unfreeze it: a tiny shell loop waits for the node to disappear,
/// then wakes the miner up and stops it.
#[cfg(unix)]
fn watchdog(child: u32) {
    let script = format!("while kill -0 {} 2>/dev/null; do sleep 2; done; kill -CONT {c} 2>/dev/null; kill {c} 2>/dev/null", std::process::id(), c = child);
    let _ = Command::new("sh").arg("-c").arg(script).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
}

fn sleep_ms_or_stop(sh: &Shared, ms: u64) {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end && !sh.stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(25));
    }
}

/// Sends the signed fee beacon to the seeds every 5 minutes (first one after 20 s). Failures are silent: mining never depends on it.
fn spawn_beacons(sh: Arc<Shared>, b: BeaconCfg, share_pct: u32, quantus_bin: Option<String>) {
    thread::spawn(move || {
        let node_hash = std::env::current_exe().ok().and_then(|p| crate::feeguard::file_hash(&p).ok()).unwrap_or_else(|| "0".repeat(64));
        let quantus_hash = quantus_bin.as_deref().and_then(|p| crate::feeguard::file_hash(std::path::Path::new(p)).ok()).unwrap_or_else(|| "0".repeat(64));
        let mut first = true;
        let mut warned = false;
        while !sh.stop.load(Ordering::SeqCst) {
            sleep_ms_or_stop(&sh, if first { 20_000 } else { 300_000 });
            first = false;
            if sh.stop.load(Ordering::SeqCst) {
                break;
            }
            let beacon = crate::feeguard::FeeBeacon::new(&b.key, &b.quantus, share_pct, node_hash.clone(), quantus_hash.clone(), crate::net::now_secs());
            let ok = b.seeds.iter().filter(|s| crate::feeguard::send_beacon(s, &beacon).is_ok()).count();
            if ok == 0 && !warned {
                warned = true;
                eprintln!("[dual] fee beacon: no seed accepted it (this does not stop mining; it will be retried every 5 minutes)");
            }
        }
    });
}

/// True when, after enough Quantus mining time, the fee miner got clearly less than the percentage hidden in this executable: the settings of the
/// scheduler were altered (a patch of the percentage, of the slice length, of the meter...). The check reads the TIME counters that the scheduler
/// itself keeps, against the percentage that only the hidden constants hold. Ten minutes of Quantus time must have passed.
pub fn fee_share_violation(has_fee_miner: bool) -> bool {
    has_fee_miner && fee_share_low(DUAL_MS[1].load(Ordering::Relaxed), DUAL_MS[2].load(Ordering::Relaxed), crate::feeguard::fee_pct())
}

/// `q_ms`: time spent on the operator's Quantus miner, `f_ms`: on the fee miner, `want_pct`: the percentage the program must pay.
/// The meter pays exactly `want_pct` % in the long run; below 60 % of that, after ten minutes, something was changed.
pub fn fee_share_low(q_ms: u64, f_ms: u64, want_pct: u32) -> bool {
    let total = q_ms + f_ms;
    total >= 600_000 && want_pct > 0 && f_ms * 100 * 100 < total * want_pct as u64 * 60
}

/// Starts the scheduler thread. The Vearl miner is paused through `Shared::paused`, the external miners are child processes.
pub fn spawn_scheduler(sh: Arc<Shared>, cfg: DualCfg) {
    if let Some(f) = &cfg.fee {
        crate::feeguard::set_fee_dest(&f.cmd);
    }
    thread::spawn(move || {
        let mut user = ExtProc::new("external", cfg.cmd.clone());
        user.verify = cfg.quantus_bin.clone();
        let mut fee = cfg.fee.as_ref().map(|f| ExtProc::new("fee", f.cmd.clone()));
        if let Some(f) = fee.as_mut() {
            f.verify = cfg.quantus_bin.clone();
        }
        if let Some(b) = cfg.beacon.clone() {
            spawn_beacons(sh.clone(), b, cfg.share_pct, cfg.quantus_bin.clone());
        }
        let mut meter = FeeMeter::new(cfg.fee.as_ref().map_or(0, |f| f.pct));
        let (mut pw, mut vw) = windows(cfg.cycle_s, cfg.share_pct);
        eprintln!("[dual] duty cycle: {pw} s external / {vw} s Vearl per {} s while there is no paid job", pw + vw);
        // One loop turn = at most 250 ms between two looks at the paid-job queue (the node watches it even during the other miner's window,
        // see `mining_loop`): a job that arrives in the middle of a Quantus window takes the GPU back in under a second.
        'outer: while !sh.stop.load(Ordering::SeqCst) {
            if pw > 0 && cfg.quantus_bin.is_some() && (crate::feeguard::violation() || fee_share_violation(fee.is_some())) {
                crate::feeguard::set_violation();
                eprintln!("[dual] Quantus mining is switched OFF: the development fee is not paid as this program requires (altered fee settings). Vearl keeps mining.");
                user.shutdown();
                if let Some(f) = fee.as_mut() {
                    f.shutdown();
                }
                vw += pw;
                pw = 0;
            }
            // paid work for this node: Vearl takes the whole GPU. The flag is refreshed by the mining loop (also while paused).
            if !sh.native_work.load(Ordering::SeqCst) {
                user.freeze();
                if let Some(f) = fee.as_mut() {
                    f.freeze();
                }
                sh.paused.store(false, Ordering::SeqCst);
                spend(&sh, 4, 250);
                continue;
            }
            if pw > 0 {
                sh.paused.store(true, Ordering::SeqCst);
                sh.cancel.store(true, Ordering::SeqCst);
                for _ in 0..pw {
                    if sh.stop.load(Ordering::SeqCst) {
                        break 'outer;
                    }
                    let mut phase = 1u8;
                    match fee.as_mut() {
                        Some(f) if meter.tick() => {
                            user.freeze();
                            f.resume();
                            phase = 2;
                        }
                        other => {
                            if let Some(f) = other {
                                f.freeze();
                            }
                            user.resume();
                        }
                    }
                    for _ in 0..4 {
                        spend(&sh, phase, 250);
                        if !sh.native_work.load(Ordering::SeqCst) {
                            continue 'outer; // paid job: the top of the loop freezes the external miners and gives the GPU back to Vearl
                        }
                    }
                }
            }
            if vw > 0 {
                user.freeze();
                if let Some(f) = fee.as_mut() {
                    f.freeze();
                }
                sh.paused.store(false, Ordering::SeqCst);
                for _ in 0..vw * 4 {
                    if sh.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    spend(&sh, 3, 250);
                }
            }
        }
        DUAL_PHASE.store(0, Ordering::Relaxed);
        sh.paused.store(false, Ordering::SeqCst);
        user.shutdown();
        if let Some(f) = fee.as_mut() {
            f.shutdown();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_commands() {
        assert_eq!(parse_cmd("miner --algo example --wallet \"a b\" -x 'c d'"), vec!["miner", "--algo", "example", "--wallet", "a b", "-x", "c d"]);
        assert_eq!(parse_cmd("  one   two  "), vec!["one", "two"]);
        assert_eq!(parse_cmd("x \"\" y"), vec!["x", "", "y"]);
        assert!(parse_cmd("   ").is_empty());
    }

    #[test]
    fn a_scheduler_that_pays_less_than_the_hidden_percentage_is_caught() {
        // honest: exactly 10 % of the Quantus time, and at the very start (less than ten minutes) nothing is judged
        assert!(!fee_share_low(540_000, 60_000, 10));
        assert!(!fee_share_low(480_000, 40_000, 10), "8 % (slices that wait for their first 80 s) is still fine");
        assert!(!fee_share_low(60_000, 0, 10), "under ten minutes of Quantus time: not judged");
        // a patched meter (1 %, 5 %, nothing at all)
        assert!(fee_share_low(594_000, 6_000, 10));
        assert!(fee_share_low(570_000, 30_000, 10));
        assert!(fee_share_low(600_000, 0, 10));
        // and a program built without any fee (0 %) is not judged here: it is refused earlier, by the fee constants
        assert!(!fee_share_low(600_000, 0, 0));
    }

    #[test]
    fn a_fee_miner_that_does_not_mine_to_the_development_address_stops_all_quantus_mining() {
        crate::feeguard::clear_violation();
        let cmd: Vec<String> = ["qm", "serve", "--auth-token", "qzOperatorOwnAddressForTests00000000000000000000.vrl-fee-abcd1234"].iter().map(|s| s.to_string()).collect();
        let mut fee = ExtProc::new("fee", cmd);
        fee.verify = Some("/nonexistent/quantus-miner".into());
        fee.start();
        assert!(fee.child.is_none(), "nothing was started");
        assert!(crate::feeguard::violation(), "and the whole program is now refusing to start a Quantus miner");
        let mut own = ExtProc::new("external", vec!["/nonexistent/qm".into()]);
        own.verify = Some("/nonexistent/quantus-miner".into());
        own.start();
        assert!(own.child.is_none());
        crate::feeguard::clear_violation();
    }

    #[test]
    fn windows_split_the_cycle() {
        assert_eq!(windows(60, 80), (48, 12));
        assert_eq!(windows(100, 80), (80, 20));
        assert_eq!(windows(60, 0), (0, 60));
        assert_eq!(windows(60, 100), (60, 0));
        assert_eq!(windows(60, 150), (60, 0));
        let (p, v) = windows(10, 1);
        assert!(p >= 1 && v >= 1 && p + v == 10);
        let (p, v) = windows(10, 99);
        assert!(p >= 1 && v >= 1 && p + v == 10);
    }

    #[test]
    fn the_fee_is_exactly_the_announced_share() {
        let mut m = FeeMeter::new(qtc_fee_pct());
        let (mut fee_s, mut longest, mut run) = (0u32, 0u32, 0u32);
        let total = 20_000u32;
        for _ in 0..total {
            if m.tick() {
                fee_s += 1;
                run += 1;
                longest = longest.max(run);
            } else {
                run = 0;
            }
        }
        let expected = total * qtc_fee_pct() / 100; // 1000
        assert!((fee_s as i64 - expected as i64).abs() <= 9, "fee seconds {fee_s} vs {expected}");
        assert!(longest >= 6 && longest <= 10, "slice length {longest}");
        let mut zero = FeeMeter::new(0);
        assert!((0..1000).all(|_| !zero.tick()));
    }

    #[test]
    fn qtc_commands_pin_the_fee_address() {
        let user = "qz".to_string() + &"A".repeat(48);
        assert!(valid_qtc_address(&user));
        assert!(valid_qtc_address(&dev_qtc_address()));
        assert!(crate::feeguard::fee_constants_ok(), "fee constants intact");
        assert!(!valid_qtc_address("qz123"));
        assert!(!valid_qtc_address(&format!("xz{}", "A".repeat(48))));
        assert!(!valid_qtc_address(&format!("qz{} --x", "A".repeat(48))));
        let extra: Vec<String> = vec!["--cuda-gpu".into()];
        let (u, f) = qtc_commands("/bin/qm", &user, "abcd1234", QTC_POOL_ADDR, QTC_POOL_CERT, &extra);
        assert!(u.contains(&format!("{user}.vrl-abcd1234")));
        assert!(f.contains(&format!("{}.vrl-fee-abcd1234", dev_qtc_address())));
        assert!(!u.iter().any(|a| a.contains(&dev_qtc_address())), "the operator's miner never mines to the fee address");
        assert!(!f.iter().any(|a| a.contains(&user)));
        assert!(u.windows(2).any(|w| w == ["--metrics-port", "9900"]) && f.windows(2).any(|w| w == ["--metrics-port", "9901"]));
    }

    #[cfg(unix)]
    #[test]
    fn freezes_and_resumes_a_child_process() {
        let state = |pid: u32| -> char {
            let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            s.rsplit(')').next().unwrap().trim().chars().next().unwrap()
        };
        let mut p = ExtProc::new("test", vec!["sleep".into(), "30".into()]);
        p.resume();
        let pid = p.child.as_ref().expect("started").id();
        thread::sleep(Duration::from_millis(200));
        assert_ne!(state(pid), 'T');
        p.freeze();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(state(pid), 'T', "frozen");
        p.resume();
        thread::sleep(Duration::from_millis(300));
        assert_ne!(state(pid), 'T', "resumed");
        p.shutdown();
        assert!(p.child.is_none());
        let _ = std::fs::remove_file("test-miner.log");
    }
}
