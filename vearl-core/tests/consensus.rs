//! Hardened consensus rules: cap on transactions per block, state snapshots + atomic reorganisation, MESS slowdown.
use ed25519_dalek::SigningKey;
use vearl_core::chain::*;
use vearl_core::crypto::*;
use vearl_core::state::*;
use vearl_core::types::*;
use vearl_core::work::*;

const P: WorkParams = WorkParams::TESTNET;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn new_chain() -> Chain {
    let alloc: Vec<(PubKey, u64)> = (1..4u8).map(|s| (pubkey(&key(s)), 1_000_000 * COIN)).collect();
    Chain::genesis(P, &alloc, 1_000, u64::MAX / 64)
}

fn mine_one(chain: &mut Chain, sk: &SigningKey, txs: Vec<SignedTx>) -> Block {
    let t = chain.tip_ts() + BLOCK_TIME;
    let out = chain.mine(sk, WorkClass::Native, None, txs, t).unwrap();
    chain.validate_and_apply(out.block.clone()).unwrap();
    out.block
}

fn transfer(sk: &SigningKey, nonce: u64, to: u8) -> SignedTx {
    SignedTx::new(Tx { from: pubkey(sk), nonce, fee: 0, kind: TxKind::Transfer { to: pubkey(&key(to)), amount: 1 } }, sk)
}

fn same_state(a: &Chain, b: &Chain) -> bool {
    a.state.accounts == b.state.accounts && a.state.minted == b.state.minted && a.state.burned == b.state.burned && a.target == b.target
}

#[test]
fn mess_factor_is_monotone_and_bounded() {
    assert_eq!(mess_factor_milli(0), 1000);
    assert_eq!(mess_factor_milli(MESS_T_MAX), 1000 * MESS_MAX_FACTOR);
    assert_eq!(mess_factor_milli(10 * MESS_T_MAX), 1000 * MESS_MAX_FACTOR, "capped");
    let mut prev = 0;
    for t in (0..=MESS_T_MAX).step_by(30) {
        let f = mess_factor_milli(t);
        assert!(f >= prev, "monotone");
        prev = f;
    }
    // ECIP-1100 parameters: a few minutes of fork are barely slowed (liveness), hours are strongly slowed
    assert!(mess_factor_milli(180) < 1010, "3 min: less than 1 % extra work required");
    assert!(mess_factor_milli(600) < 1060);
    assert!(mess_factor_milli(4 * 3600) > 15_000, "4 h: more than 15 times the work");
}

#[test]
fn reorg_rule_without_mess_is_plain_work_comparison() {
    assert!(reorg_accepted(100, 101, 100_000, false));
    assert!(!reorg_accepted(100, 100, 0, false));
    assert!(!reorg_accepted(100, 101, MESS_T_MAX, true), "a one-block gap is not enough after a long lead");
    assert!(reorg_accepted(100, 3300, MESS_T_MAX, true));
}

#[test]
fn block_with_too_many_transactions_is_rejected() {
    let (a, b) = (key(1), key(2));
    let mut chain = new_chain();
    let mut fresh = new_chain();
    let ok: Vec<SignedTx> = (0..MAX_BLOCK_TXS as u64).map(|i| transfer(&a, i, 3)).collect();
    let too_many: Vec<SignedTx> = (0..MAX_BLOCK_TXS as u64 + 1).map(|i| transfer(&a, i, 3)).collect();
    let t = chain.tip_ts() + BLOCK_TIME;
    let out = chain.mine(&b, WorkClass::Native, None, too_many, t).unwrap();
    let err = fresh.validate_and_apply(out.block).unwrap_err();
    assert!(err.contains("too many transactions"), "{err}");
    let out = chain.mine(&b, WorkClass::Native, None, ok, t).unwrap();
    fresh.validate_and_apply(out.block).expect("exactly MAX_BLOCK_TXS transactions: accepted");
}

#[test]
fn rewind_restores_exactly_the_state_of_a_shorter_chain() {
    let (a, b) = (key(1), key(2));
    let mut chain = new_chain();
    let mut blocks = vec![];
    for i in 0..45u64 {
        let txs = if i % 3 == 0 { vec![transfer(&a, i / 3, 3)] } else { vec![] };
        blocks.push(mine_one(&mut chain, &b, txs));
    }
    // reference chain up to 21 blocks (not a multiple of SNAP_EVERY: the snapshot is at 16, 5 blocks replayed)
    let mut shorter = new_chain();
    for blk in &blocks[..21] {
        shorter.validate_and_apply(blk.clone()).unwrap();
    }
    let removed = chain.rewind_to(21).unwrap();
    assert_eq!(removed.len(), 24);
    assert_eq!(chain.height(), 21);
    assert_eq!(chain.tip_hash(), shorter.tip_hash());
    assert!(same_state(&chain, &shorter));
    assert!(chain.check_supply_invariant());
    // the removed blocks can be replayed
    for blk in removed {
        chain.validate_and_apply(blk).unwrap();
    }
    assert_eq!(chain.height(), 45);
    assert_eq!(chain.tip_hash(), blocks[44].header.hash());
}

/// Two chains from the same prefix of `common` blocks: the local one has `local` more blocks, the competing one `cand`.
fn fork(common: usize, local: usize, cand: usize) -> (Chain, Vec<Block>, Chain) {
    let (b, c) = (key(2), key(3));
    let mut mine_chain = new_chain();
    let mut prefix = vec![];
    for _ in 0..common {
        prefix.push(mine_one(&mut mine_chain, &b, vec![]));
    }
    let mut other = new_chain();
    for blk in &prefix {
        other.validate_and_apply(blk.clone()).unwrap();
    }
    for _ in 0..local {
        mine_one(&mut mine_chain, &b, vec![]);
    }
    let mut cand_blocks = vec![];
    for _ in 0..cand {
        cand_blocks.push(mine_one(&mut other, &c, vec![]));
    }
    (mine_chain, cand_blocks, other)
}

#[test]
fn heavier_fork_replaces_the_local_chain_atomically() {
    let (mut local, cand, other) = fork(10, 12, 20);
    let old_tip = local.tip_hash();
    let old = local.try_reorg(10, cand, 10_000_000, false).expect("more work: the reorganisation is accepted");
    assert_eq!(old.len(), 12);
    assert_eq!(local.height(), 30);
    assert_eq!(local.tip_hash(), other.tip_hash());
    assert_ne!(local.tip_hash(), old_tip);
    assert!(same_state(&local, &other));
    assert!(local.check_supply_invariant());
}

#[test]
fn lighter_fork_is_refused_and_chain_unchanged() {
    let (mut local, cand, _) = fork(10, 20, 12);
    let (tip, height) = (local.tip_hash(), local.height());
    let before = local.state.accounts.clone();
    let err = local.try_reorg(10, cand, 10_000_000, false).unwrap_err();
    assert!(err.contains("out-work"), "{err}");
    assert_eq!((local.tip_hash(), local.height()), (tip, height));
    assert_eq!(local.state.accounts, before);
}

#[test]
fn mess_refuses_a_slightly_heavier_fork_that_plain_work_would_accept() {
    // 200 blocks ahead (6,000 s) against 220: more work (x1.1) but MESS requires ~x5.3 after 6,000 s
    let (mut local, cand, other) = fork(10, 200, 220);
    let (tip, height) = (local.tip_hash(), local.height());
    let err = local.try_reorg(10, cand.clone(), 10_000_000, true).unwrap_err();
    assert!(err.contains("out-work"), "{err}");
    assert_eq!((local.tip_hash(), local.height()), (tip, height), "local chain intact");
    // without slowdown, the same chain is accepted
    local.try_reorg(10, cand, 10_000_000, false).expect("without MESS");
    assert_eq!(local.tip_hash(), other.tip_hash());
}

#[test]
fn invalid_candidate_block_restores_the_local_chain() {
    let (mut local, mut cand, _) = fork(10, 12, 30);
    let (tip, height) = (local.tip_hash(), local.height());
    let (accounts, minted) = (local.state.accounts.clone(), local.state.minted);
    cand[15].header.jackpot = [0xEE; 32]; // falsified work in the middle of the branch
    let err = local.try_reorg(10, cand, 10_000_000, false).unwrap_err();
    assert!(err.starts_with("invalid candidate block"), "{err}");
    assert_eq!((local.tip_hash(), local.height()), (tip, height));
    assert_eq!((local.state.accounts.clone(), local.state.minted), (accounts, minted));
    assert!(local.check_supply_invariant());
}

#[test]
fn fork_from_genesis_and_deep_reorg_beyond_snapshots() {
    // 100 local blocks (snapshots 0,16,..,96), candidate of 120 blocks from genesis
    let (mut local, cand, other) = fork(0, 100, 120);
    local.try_reorg(0, cand, 10_000_000, false).expect("reorganisation from genesis");
    assert_eq!(local.tip_hash(), other.tip_hash());
    assert!(same_state(&local, &other));
}

// ---------------------------------------------------------------- header v2: account root

#[test]
fn header_carries_work_roots_and_accounts_root_matching_the_post_block_state() {
    let (a, b, miner) = (key(1), key(2), key(3));
    let mut chain = new_chain();
    let tx = transfer(&a, 0, 3);
    let t = chain.tip_ts() + BLOCK_TIME;
    let out = chain.mine(&miner, WorkClass::Native, None, vec![tx], t).unwrap();
    let hd = out.block.header.clone();
    chain.validate_and_apply(out.block).unwrap();
    assert_eq!(hd.accounts_root, chain.state.accounts_root(), "the header root is that of the state AFTER the block");
    let (idx, count, path) = chain.state.accounts_proof(&pubkey(&b)).expect("live beneficiary account");
    assert!(verify_account_proof(&hd.accounts_root, &pubkey(&b), chain.state.balance(&pubkey(&b)), chain.state.nonce(&pubkey(&b)), idx, count, &path));
    // a wrong balance does not pass
    assert!(!verify_account_proof(&hd.accounts_root, &pubkey(&b), chain.state.balance(&pubkey(&b)) + 1, chain.state.nonce(&pubkey(&b)), idx, count, &path));
}

#[test]
fn tampering_the_accounts_root_is_rejected() {
    let (a, miner) = (key(1), key(3));
    let mut chain = new_chain();
    let mut fresh = new_chain();
    let t = chain.tip_ts() + BLOCK_TIME;
    let mut out = chain.mine(&miner, WorkClass::Native, None, vec![transfer(&a, 0, 2)], t).unwrap();
    out.block.header.accounts_root[0] ^= 1;
    let err = fresh.validate_and_apply(out.block).unwrap_err();
    assert!(err.contains("accounts_root"), "{err}");
}

// ---------------------------------------------------------------- ASERT (aserti3-2d): default difficulty rule

fn asert_chain() -> Chain {
    let alloc: Vec<(PubKey, u64)> = (1..4u8).map(|s| (pubkey(&key(s)), 1_000_000 * COIN)).collect();
    let mut c = Chain::genesis(P, &alloc, 1_000, u64::MAX / 64);
    c.retarget = Retarget::Asert;
    c
}

fn mine_dt(chain: &mut Chain, dt: u64) {
    let t = chain.tip_ts() + dt;
    let out = chain.mine(&key(2), WorkClass::Native, None, vec![], t).unwrap();
    chain.validate_and_apply(out.block).unwrap();
}

#[test]
fn asert_is_the_default_and_keeps_the_target_on_schedule() {
    assert_eq!(Retarget::default(), Retarget::Asert);
    let mut c = asert_chain();
    let t0 = c.target;
    for _ in 0..40 {
        mine_dt(&mut c, BLOCK_TIME);
    }
    assert_eq!(c.target, t0, "blocks exactly on time: target unchanged");
}

#[test]
fn asert_anchors_on_the_first_block_instead_of_the_genesis_timestamp() {
    let (mut on_time, mut delayed) = (asert_chain(), asert_chain());
    let initial_target = on_time.target;
    mine_dt(&mut on_time, BLOCK_TIME);
    mine_dt(&mut delayed, 4 * ASERT_HALFLIFE);
    assert_eq!(on_time.target, initial_target);
    assert_eq!(delayed.target, initial_target, "a late first block keeps the initial target");
    for dt in [1, BLOCK_TIME, 2 * BLOCK_TIME] {
        mine_dt(&mut on_time, dt);
        mine_dt(&mut delayed, dt);
        assert_eq!(on_time.target, delayed.target, "the same post-anchor schedule gives the same target");
    }
}

#[test]
fn asert_halves_or_doubles_the_target_after_one_halflife_of_drift() {
    // blocks that are too fast (1 s): ahead of schedule, the target drops (harder)
    let mut fast = asert_chain();
    let t0 = fast.target;
    for _ in 0..40 {
        mine_dt(&mut fast, 1);
    }
    assert!(fast.target < t0);
    // exact advance of one half-life on the ideal schedule: target divided by 2 (up to the rounding of the polynomial)
    let a = asert_core(1 << 40, 0, (ASERT_HALFLIFE / BLOCK_TIME) - 1, BLOCK_TIME, ASERT_HALFLIFE);
    assert_eq!(a, 1 << 39);
    // delay of one half-life: target doubled; huge delay: cap; huge advance: floor
    assert_eq!(asert_core(1 << 40, (ASERT_HALFLIFE + BLOCK_TIME) as i128, 0, BLOCK_TIME, ASERT_HALFLIFE), 1 << 41);
    assert_eq!(asert_core(1 << 40, 10_000_000_000, 0, BLOCK_TIME, ASERT_HALFLIFE), u64::MAX);
    assert_eq!(asert_core(1 << 40, 0, 10_000_000, BLOCK_TIME, ASERT_HALFLIFE), 1 << 16);
}

#[test]
fn asert_chain_survives_a_rewind_and_reorg_with_the_same_targets() {
    let mut c = asert_chain();
    for i in 0..30u64 {
        mine_dt(&mut c, 5 + (i * 7) % 50);
    }
    let (tip, target) = (c.tip_hash(), c.target);
    let removed = c.rewind_to(12).unwrap();
    for b in removed {
        c.validate_and_apply(b).unwrap();
    }
    assert_eq!((c.tip_hash(), c.target), (tip, target), "the target only depends on the blocks");
}

#[test]
fn block_whose_transactions_exceed_the_byte_limit_is_rejected() {
    // the rule applies to BYTES: 256 post-quantum transactions (7.9 KiB) make ~2 MiB and pass the 4 MiB limit; bulky proofs
    // (here inflated to 1.2 MiB) exceed it at 4 transactions. The refusal happens BEFORE any signature or content check.
    let a = key(1);
    let mut chain = new_chain();
    let big = |nonce: u64| {
        let f = FraudProof { job_id: [0; 32], i: 0, j: 0, a_row: vec![], a_path: vec![], b_col: vec![], b_path: vec![], c_row: vec![0; 300_000], c_path: vec![] };
        SignedTx::new(Tx { from: pubkey(&a), nonce, fee: 0, kind: TxKind::Fraud(f) }, &a)
    };
    let txs: Vec<SignedTx> = (0..4).map(big).collect();
    assert!(txs_bytes(&txs) > MAX_BLOCK_TX_BYTES && txs_bytes(&txs[..3]) < MAX_BLOCK_TX_BYTES);
    let t = chain.tip_ts() + BLOCK_TIME;
    let out = chain.mine(&key(2), WorkClass::Native, None, txs, t).unwrap();
    let mut fresh = new_chain();
    let err = fresh.validate_and_apply(out.block).unwrap_err();
    assert!(err.contains("too large"), "{err}");
    // 256 post-quantum transactions stay under the byte limit
    let pq = vearl_core::pq::PqKey::from_seed(&[5; 32]);
    let one = SignedTx::new_pq(Tx { from: pq.pubkey(), nonce: 0, fee: 0, kind: TxKind::Transfer { to: pubkey(&a), amount: 1 } }, &pq);
    assert!(txs_bytes(&vec![one; MAX_BLOCK_TXS]) < MAX_BLOCK_TX_BYTES);
}
