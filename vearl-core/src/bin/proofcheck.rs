//! proofcheck GENESIS.json CHAIN.bin [--limit N]
//!
//! Replays a block file the way a node does at start (the tile proofs of buried blocks leave memory, see `PROOF_KEEP`), prints the memory used, then checks
//! that EVERY block rebuilt by `Chain::full_block` is, byte for byte, the frame stored in the file. Reads the files only; starts no network.
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use vearl_core::chain::*;
use vearl_core::genesis::parse_genesis;
use vearl_core::state::EPOCH_LEN;
use vearl_core::types::Block;

/// Linux: resident and peak memory of this process.
fn memory() -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let get = |k: &str| s.lines().find(|l| l.starts_with(k)).map(|l| l.split_whitespace().skip(1).take(2).collect::<Vec<_>>().join(" ")).unwrap_or_else(|| "?".into());
    format!("resident {} / peak {}", get("VmRSS:"), get("VmHWM:"))
}

fn frames(path: &str, limit: usize) -> impl Iterator<Item = Vec<u8>> {
    let mut f = File::open(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    (0..limit).map_while(move |_| {
        let mut l = [0u8; 4];
        f.read_exact(&mut l).ok()?;
        let mut buf = vec![0u8; u32::from_le_bytes(l) as usize];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: proofcheck GENESIS.json CHAIN.bin [--limit N]");
        std::process::exit(2);
    }
    let limit = args.iter().position(|a| a == "--limit").and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let (name, cfg) = parse_genesis(&std::fs::read_to_string(&args[1]).expect("genesis file")).expect("invalid genesis");
    let mut chain = Chain::from_config(&cfg);
    eprintln!("network '{name}'; replaying {} (PROOF_KEEP {PROOF_KEEP}, NATIVE_KEEP {NATIVE_KEEP}); {}", args[2], memory());
    let t0 = std::time::Instant::now();
    for buf in frames(&args[2], limit) {
        let b: Block = bincode::deserialize(&buf).expect("block frame");
        if let Err(e) = chain.validate_and_apply(b) {
            eprintln!("block {} refused: {e}", chain.height());
            std::process::exit(1);
        }
        if chain.height() % 10_000 == 0 {
            eprintln!("  {} blocks, {:.0} s; {} snapshots; {}", chain.height(), t0.elapsed().as_secs_f64(), chain.snapshot_count(), memory());
        }
    }
    let height = chain.height() as usize;
    let evicted = chain.blocks.iter().filter(|b| b.proof.is_evicted()).count();
    println!(
        "replayed {height} blocks in {:.0} s; proofs dropped from memory: {evicted}; epochs of matrices kept: {}; state snapshots kept: {}; {}",
        t0.elapsed().as_secs_f64(),
        chain.native_cached(),
        chain.snapshot_count(),
        memory()
    );

    // every block, as a peer that syncs would receive it, must be the stored frame
    let (mut checked, mut cache) = (0usize, HashMap::new());
    for (i, buf) in frames(&args[2], height).enumerate() {
        let b = &chain.blocks[i];
        if cache.len() > 2 && b.proof.is_evicted() && !cache.contains_key(&(b.header.height / EPOCH_LEN)) {
            cache.clear(); // sequential walk: the epochs behind us are not needed again
        }
        let full = chain.full_block(b, &mut cache);
        let rebuilt = bincode::serialize(&*full).expect("serialize");
        if rebuilt != buf {
            println!("MISMATCH at block {i} (class {:?}, proof dropped: {})", b.header.class, b.proof.is_evicted());
            std::process::exit(1);
        }
        checked += 1;
    }
    println!("OK: {checked} blocks rebuilt byte for byte; {}", memory());
}
