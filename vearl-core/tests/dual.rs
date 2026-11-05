//! Dual mining scheduler (dual.rs): window of the other miner, immediate return to Vearl when a paid job arrives.
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use vearl_core::chain::*;
use vearl_core::dual::*;
use vearl_core::net::*;

// These tests share external-miner.log in the process working directory.
// Hold the lock through scheduler shutdown and log cleanup.
static EXTERNAL_LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn node() -> NodeHandle {
    let mut g = devnet_genesis();
    g.retarget = Retarget::Fixed;
    spawn_node(NodeConfig { genesis: g, listen: "127.0.0.1:0".into(), peers: vec![], mine_key: None, use_gpu: false, log: false, worker: None, data_dir: None }).unwrap()
}

fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) -> Duration {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return t.elapsed();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timeout: {what}");
}

#[cfg(unix)]
fn sleeper() -> Vec<String> {
    vec!["sleep".into(), "120".into()]
}
#[cfg(windows)]
fn sleeper() -> Vec<String> {
    vec!["ping".into(), "-n".into(), "120".into(), "127.0.0.1".into()]
}

#[test]
fn a_paid_job_takes_the_gpu_back_from_the_external_miner_within_a_second() {
    let _log_guard = EXTERNAL_LOG_LOCK.lock().unwrap();
    let nd = node();
    let sh = nd.shared.clone();
    // 10 s cycle: 8 s for the external miner, 2 s for Vearl
    spawn_scheduler(sh.clone(), DualCfg { cmd: sleeper(), fee: None, share_pct: 80, cycle_s: 10, quantus_bin: None, beacon: None });
    wait("external miner window (Vearl mining is paused)", 5, || sh.paused.load(Ordering::SeqCst));
    // a paid job arrives in the middle of the external window: the node signals it through `native_work`
    std::thread::sleep(Duration::from_millis(1500));
    assert!(sh.paused.load(Ordering::SeqCst), "still in the external window");
    sh.native_work.store(false, Ordering::SeqCst);
    let back = wait("Vearl takes the GPU back", 5, || !sh.paused.load(Ordering::SeqCst));
    assert!(back < Duration::from_millis(1000), "back to Vearl in {back:?}");
    // as long as the job lasts, the external miner does not take over again, even after several cycles
    std::thread::sleep(Duration::from_secs(3));
    assert!(!sh.paused.load(Ordering::SeqCst));
    // job finished: the cycle resumes
    sh.native_work.store(true, Ordering::SeqCst);
    wait("the cycle resumes", 5, || sh.paused.load(Ordering::SeqCst));
    nd.stop();
    std::thread::sleep(Duration::from_millis(600));
    let _ = std::fs::remove_file("external-miner.log");
}

#[test]
fn without_a_share_for_the_external_miner_vearl_always_owns_the_gpu() {
    let _log_guard = EXTERNAL_LOG_LOCK.lock().unwrap();
    let nd = node();
    let sh = nd.shared.clone();
    spawn_scheduler(sh.clone(), DualCfg { cmd: sleeper(), fee: None, share_pct: 0, cycle_s: 10, quantus_bin: None, beacon: None });
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!sh.paused.load(Ordering::SeqCst));
    nd.stop();
    std::thread::sleep(Duration::from_millis(600));
    let _ = std::fs::remove_file("external-miner.log");
}

/// The Quantus miner is PINNED: a binary that is not the release's (script that ignores the fee address, modified build)
/// is never started. Proof: the scheduler opens `external-miner.log` just before starting a miner; with an unpinned binary
/// it never opens it.
#[test]
fn a_quantus_miner_that_is_not_the_pinned_one_is_never_started() {
    let _log_guard = EXTERNAL_LOG_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("vearl-pinned-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fake = dir.join("quantus-miner");
    std::fs::write(&fake, b"not the official miner").unwrap();
    let log = std::path::Path::new("external-miner.log");
    let _ = std::fs::remove_file(log);
    let nd = node();
    spawn_scheduler(nd.shared.clone(), DualCfg { cmd: sleeper(), fee: None, share_pct: 80, cycle_s: 10, quantus_bin: Some(fake.display().to_string()), beacon: None });
    std::thread::sleep(Duration::from_secs(4));
    assert!(!log.exists(), "the unpinned miner must not run");
    nd.stop();
    std::thread::sleep(Duration::from_millis(600));
    // control: without the pin check the same command does start
    let nd = node();
    spawn_scheduler(nd.shared.clone(), DualCfg { cmd: sleeper(), fee: None, share_pct: 80, cycle_s: 10, quantus_bin: None, beacon: None });
    wait("the control command starts", 8, || log.exists());
    nd.stop();
    std::thread::sleep(Duration::from_millis(600));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(log);
}
