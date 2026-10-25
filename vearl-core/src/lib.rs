//! VEARL testnet core.
//!
//! Status: UNAUDITED PROTOTYPE. No security property here is proven;
//! see docs/02-design-vearl-v1.md for what is [LIT] (literature), [HYP] (hypothesis) or [RESEARCH NEEDED].
pub mod launcher;
pub mod updatesig;
pub mod chain;
pub mod crypto;
pub mod pq;
pub mod mlp;
pub mod state;
pub mod types;
pub mod work;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod net;
pub mod index;
pub mod dual;
pub mod feeguard;
pub mod netfuzz;
pub mod secure;
pub mod attack;
pub mod wallet;
pub mod regmail;
pub mod api;
pub mod faucet;
pub mod genesis;
pub mod httpmini;
pub mod tiled;
pub mod prog;
pub mod model;
pub mod l2;
pub mod render2;
pub mod render3;
pub mod pool;
pub mod poolpoints;
pub mod poolminer;
