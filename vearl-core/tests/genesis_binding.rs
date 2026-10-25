//! A block is bound to the genesis STATE: a block mined on a chain whose genesis lacks one allocation is refused by a chain whose genesis has it
//! (the header commits to `accounts_root`, the root of all the accounts after the block). This is what makes a genesis file that has not been
//! published unpredictable: nobody can prepare blocks for it, although the work (matrices, sigma, target) does not depend on the genesis file.
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

fn chain_with(extra: &[(PubKey, u64)]) -> Chain {
    let mut alloc: Vec<(PubKey, u64)> = vec![(pubkey(&key(1)), 1_000_000 * COIN)];
    alloc.extend_from_slice(extra);
    // the same parameters, start time and target in both: only the allocations differ
    Chain::genesis(P, &alloc, 1_000, u64::MAX / 64)
}

fn mine(chain: &mut Chain, miner: &SigningKey) -> Block {
    let t = chain.tip_ts() + BLOCK_TIME;
    chain.mine(miner, WorkClass::Native, None, vec![], t).unwrap().block
}

#[test]
fn a_block_prepared_without_the_secret_allocation_is_refused() {
    let secret = (pubkey(&key(200)), 1u64); // one unit to an address nobody else knows
    let mut public = chain_with(&[]);
    let mut real = chain_with(&[secret]);
    let attacker = key(9);
    // the work and the target are the same on both chains: the attacker can mine a block perfectly well on the genesis it knows...
    let block = mine(&mut public, &attacker);
    let mut control = chain_with(&[]);
    control.validate_and_apply(block.clone()).expect("the block is valid on the genesis it was mined for");
    // ...but the real chain, whose accounts include the unknown allocation, refuses it
    let err = real.validate_and_apply(block).expect_err("must be refused");
    assert!(err.contains("accounts_root"), "{err}");
    assert_eq!(real.height(), 0);
}

#[test]
fn the_same_genesis_accepts_the_same_block() {
    let secret = (pubkey(&key(200)), 1u64);
    let mut a = chain_with(&[secret]);
    let mut b = chain_with(&[secret]);
    let block = mine(&mut a, &key(9));
    b.validate_and_apply(block).expect("same genesis: accepted");
}
