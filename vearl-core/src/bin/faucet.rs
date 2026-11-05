//! vearl-faucet --node HOST:PORT --wallet FAUCET.json [--listen 127.0.0.1:8081] [--amount 10] [--cooldown-secs 3600]
//!              [--max-per-day 10000] [--state-file PATH]
//! Wallet password: VEARL_WALLET_PASSWORD, or --password-file, or masked prompt. DEDICATED wallet.
use vearl_core::faucet::{Faucet, FaucetConfig};
use vearl_core::httpmini::serve;
use vearl_core::wallet::*;
use std::sync::Arc;
use std::time::Duration;

fn die(m: &str) -> ! {
    eprintln!("error: {m}");
    std::process::exit(1)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn password(args: &[String]) -> String {
    read_password("Faucet wallet password: ", arg(args, "--password-file").as_deref()).unwrap_or_else(|e| die(&e))
}

const HELP: &str = r#"vearl-faucet: a small service that gives test tokens to anyone who asks (testnet only).

  vearl-faucet --node HOST:PORT --wallet FAUCET.json [--listen 127.0.0.1:8081] [--amount 10] [--cooldown-secs 3600] [--max-per-day 10000] [--state-file PATH]

Use a DEDICATED wallet. Its password is asked in the terminal, or given in VEARL_WALLET_PASSWORD or with --password-file FILE.
Rate limits are persisted to --state-file (default: WALLET.faucet-state.json).
Keep this file across restarts; its parent directory must exist and be writable.
Reservations are saved before broadcast: failed/uncertain sends can consume quota.
Details: docs/06."#;

fn main() {
    vearl_core::launcher::help_or_continue(HELP);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let node = arg(&args, "--node").unwrap_or_else(|| die("--node required"));
    let wallet = arg(&args, "--wallet").unwrap_or_else(|| die("--wallet required"));
    let listen = arg(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8081".into());
    let amount = parse_amount(&arg(&args, "--amount").unwrap_or_else(|| "10".into())).unwrap_or_else(|e| die(&e));
    let cooldown: u64 = arg(&args, "--cooldown-secs").map_or(3600, |v| v.parse().unwrap_or_else(|_| die("invalid cooldown")));
    let max_day = parse_amount(&arg(&args, "--max-per-day").unwrap_or_else(|| "10000".into())).unwrap_or_else(|e| die(&e));
    let ks = Keystore::load(std::path::Path::new(&wallet)).unwrap_or_else(|e| die(&e));
    let m = ks.unlock(&password(&args)).unwrap_or_else(|e| die(&e));
    let state_file = arg(&args, "--state-file").unwrap_or_else(|| format!("{wallet}.faucet-state.json"));
    let faucet = Arc::new(Faucet::persistent(FaucetConfig { node, amount, cooldown: Duration::from_secs(cooldown), max_per_day: max_day }, derive_account(&m, 0), &state_file).unwrap_or_else(|e| die(&e)));
    let f2 = faucet.clone();
    let bound = serve(&listen, move |req| f2.handle(req)).unwrap_or_else(|e| die(&format!("cannot listen: {e}")));
    eprintln!("[faucet] {} hands out {} VRL per request; listening on http://{bound}/", faucet.address(), fmt_amount(amount));
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
