# 16 - Mining pool protocol (`vpool/1` and `vpool/2`)

Status: reference implementation (`vearl-core/src/pool.rs`, `src/poolminer.rs`, `src/poolpoints.rs`, binaries `vearl-pool`, `vearl-poolminer` and
`vearl-pool-audit`), tested on a CPU devnet (`tests/pool.rs`, `tests/pool_points.rs`). `vpool/2` is `vpool/1` plus the signed receipts and the
signed hourly ledger of section 13 (fraud protection of the testnet points); a pool speaks both. **Unaudited prototype, testnet only, tokens have no value.** This document is the specification: a third party can write a
compatible miner or pool from it.

## 1. Why a pool, and what it changes

A Vearl block is found by one `sigma` evaluation (one noised GEMM) whose tile jackpot is below the network target. A small GPU may need hours per
block. A pool lets many miners search together and share the rewards in proportion to their work.

The protocol uses one property of the consensus rules: **a block header carries the reward recipient (`miner`) as a plain public key, and the block
carries no signature of that key.** `sigma = H("vearl/sigma/v1", prev, miner, class, extra_nonce, tx_root, timestamp)` only needs the *public* key.
So:

- the pool is the `miner` of every block it finds; the pool's key receives the whole reward on-chain;
- workers never need the pool's private key, and the pool never needs a worker's key;
- a worker proves its work with **shares**: tile jackpots below an easier *share target*; a share that also meets the network target is a block.

Pools mine the **Native Work** (class 0). Paid jobs (level 1 / level 2) stay reserved to solo workers (`node --worker`): the block rules require
the job's worker to be the miner, which a pool cannot delegate. A pool operator can still run a worker next to the pool, and since rc22 a pool MINER can
too: `vearl-miner` in pool mode with a wallet starts `node --worker --no-native` next to `vearl-poolminer` (docs/15), so that the machine mines for the
pool and takes paid jobs on its own account.

## 2. Roles

| Role | Program | Holds |
|---|---|---|
| Pool server | `vearl-pool` (a full node without its own mining loop + the pool server) | the pool key (hot wallet), the ledger, the signed points documents |
| Worker | `vearl-poolminer` (CPU or CUDA) | a payout address only, and the receipts it is sent |
| Auditor | `vearl-pool-audit` + `tools/fetch_pool_bundle.py` | nothing: anybody can run it |
| Explorer / dashboards | any HTTP client | nothing |

## 3. Transport

TCP, UTF-8 JSON, **one message per line** (`\n`). Maximum line: 4096 bytes (the server closes longer lines). No TLS in the protocol: for a public pool
put a TLS terminator in front (stunnel or nginx `stream`) and let workers connect through it. 64-bit integers (targets, `extra_nonce`) are sent as
**16 lowercase hexadecimal digits** (JSON numbers do not hold a `u64` in every language); hashes and keys are 64 hex digits; heights, tile indexes and
counts are ordinary JSON numbers.

Requests: `{"id":N,"method":"...","params":{...}}`. Responses: `{"id":N,"result":{...}}` or `{"id":N,"error":{"code":C,"message":"..."}}`.
Notifications (server to worker, no `id`): `job`, `set_target`, `receipt` (`vpool/2`, section 13.2).

### 3.1 `login` (first request, once)

```json
{"id":1,"method":"login","params":{"proto":"vpool/1","address":"vrl1...","worker":"rig1","agent":"vearl-poolminer/0.1","sigma_rate":150.0}}
```

- `proto` is `vpool/2` (receipts, points) or `vpool/1` (same shares and payouts, no receipts, no points). `address` is the payout address (Bech32m `vrl1...`; the pool's own address is refused).
- `worker`: 1-32 characters among letters, digits, `.`, `_`, `-`. Several workers may share one address (their shares add up).
- `sigma_rate` (optional): estimated `sigma` evaluations per second; only used to choose the first share target.

Result: `{"proto","slot","share_target","pool_address","fee_bps","min_payout","payout_interval","confirmations","pplns_n","nonce_bits":40,"share_secs"}`.
The server then sends the current `job` immediately.

### 3.2 `job` notification

```json
{"method":"job","params":{
  "job_id":"a1b2c3d4e5f6","clean":true,"height":1234,"prev":"<hash>","miner":"<pool public key>","class":"native",
  "timestamp":1760000000,"tx_root":"<hash>","epoch":12,"target":"<u64 hex>","share_target":"<u64 hex>",
  "slot":17,"nonce_start":"<u64 hex>","nonce_end":"<u64 hex>",
  "params":{"n":1024,"tile":16,"rank":63,"fold_k":64}}}
```

- The worker computes, for `extra_nonce` in `[nonce_start, nonce_end)`:
  `sigma = H("vearl/sigma/v1", prev, miner, bincode(WorkClass::Native), extra_nonce (8 bytes LE), tx_root, timestamp (8 bytes LE))`
  (`H` = BLAKE3 `derive_key` with that context; `bincode(Native)` = four zero bytes), then the noised GEMM of the native matrices of `epoch`
  (`native_matrices(epoch, params)`, see docs/07) which yields one **jackpot per tile**. Tile `(ti, tj)` is index `ti * tiles + tj`, `tiles = n / tile`.
- Every tile whose jackpot is below `share_target` (compare the first 8 bytes of the jackpot, big-endian, as a `u64`) is a share.
- `clean = true`: new parent block, abandon the previous work. `clean = false`: same parent, new transactions or timestamp; switching is advised
  but older jobs of the same parent remain valid (the pool keeps the last 8).
- **Slots.** `extra_nonce = slot << 40 | counter`, so two workers never search the same space. A share with an `extra_nonce` outside the worker's
  slot is rejected. A slot is released when the connection closes.
- The worker needs no chain state: only these fields and the (deterministic) native matrices.

### 3.3 `submit`

```json
{"id":7,"method":"submit","params":{"job_id":"a1b2c3d4e5f6","extra_nonce":"<u64 hex>","ti":3,"tj":12}}
```

Result `{"accepted":true,"block":false,"weight":"..."}`; `block: true` means this share was also a block and the pool submitted it to the network.

| Code | Meaning | Counts toward ban |
|---|---|---|
| 20 | stale or unknown job (a job of the previous parent is still accepted for `stale_grace_secs`, default 4 s) | no |
| 21 | duplicate share (`job`, `extra_nonce`, `ti`, `tj`) | 2 |
| 22 | jackpot not below the share target | 5 |
| 23 | `extra_nonce` outside the worker's slot, or tile out of range | 5 |
| 24 | (reserved) unknown job | |
| 25 | not logged in | |
| 26 | rate limit (50 shares/s sustained, burst 100); not a strike, but more than 5000 violations in a minute closes the connection | no |
| 30 | malformed request / unknown method / bad login | |
| 31 | banned | |
| 32 | too many connections | |

25 strikes within 60 s ban the IP for 10 minutes (loopback is exempt from bans).

### 3.4 `set_target` notification (vardiff)

`{"method":"set_target","params":{"share_target":"<u64 hex>"}}`. Applies to the shares found from now on; the pool also accepts the previous target for
30 s to cover shares in flight.

### 3.5 `hint` (optional, measured rate)

`{"id":N,"method":"hint","params":{"sigma_rate":8000.0}}` tells the pool the worker's measured rate in `sigma` evaluations per second. The pool jumps
at once to the share target that matches (and sends `set_target`) instead of converging by steps of 4: a fast GPU that starts with the default
small-CPU target would otherwise flood the pool for ~15 s. At most 3 hints per session (error 26 beyond); a lying hint only hurts the liar (an easy
target is rate limited, a hard one only lowers its own share rate). The reference worker sends one after 4 s of mining, and never sends more than ~40 shares/s (burst 80) whatever the target.

### 3.6 `ping` and `stats`

`ping` returns `{"pong":<unix time>}`. A worker must send *something* at least every 10 minutes (the reference worker pings every 30 s when idle) or
the connection is closed. `stats` returns `{"accepted","rejected","share_target","balance","paid"}` for the session's address.

## 4. How the pool verifies a share

The pool **recomputes** the jackpot of tile `(ti, tj)` from its own copy of the matrices (`work::tile_jackpot`: `O(tile * n * rank)`, no full GEMM) and
compares it with the share target. A worker can therefore not claim a share it did not compute, and it does not have to be trusted with the
matrices. A forged `extra_nonce`, tile or job only costs the pool one tile computation and earns the sender strikes.

A share that is below the network `target` becomes a block: the pool builds `Header{version 2, height, prev, timestamp, miner = pool key, class Native,
extra_nonce, ti, tj, jackpot, tx_root, target, a_root, b_root, accounts_root}`, the tile proof (`work::build_proof`) and the job's transactions, and
submits it with the normal block validation (`net::submit_block`). `accounts_root` is computed when the job is created (job transactions applied to a copy
of the state, then the block reward). The block is relayed like any other.

## 5. Share target and vardiff

A share of target `T` represents `2^64 / T` tile attempts; its **weight** is `2^96 / T` (fixed point), so weights add up to work whatever
the target of each worker was. The target of every worker is adjusted to about one share every `share_secs` (default 15 s):

- first adjustment after 10 s without a share, otherwise every `retarget_secs` (default 30 s), or earlier after 30 shares;
- factor bounded to 4 per step, no change inside the 0.8-1.25 band;
- never harder than the network target (a block must also be a share). The credit follows the same rule: a share is credited at the hardest target
  it meets but never harder than the network target of ITS job (the network target eases from block to block, and the pool still holds the session
  target of the previous job for 30 s);
- the initial target comes from `sigma_rate` (or a small default) and converges in a few steps.

## 6. Accounting: PPLNS

- Window = the last shares whose total weight reaches `pplns_n` (default 2.0) times the weight of one share at the network target. The window
  spans block boundaries (classic PPLNS), which removes the incentive to hop between pools.
- When the pool finds a block, the **net reward** (`emission + fees of the block's transactions`, minus the pool fee `fee_bps`, default 1 %) is split
  across the window in proportion to weight. The split is frozen at that moment and is exact (the remainder of the integer division goes to the largest
  holder; nothing is created or lost).
- The block is `pending` until it is `confirmations` blocks deep (default 30, i.e. 300 s of blocks of 10 s; it was 10 with 30-s blocks) and still on the best chain; then each credit is added to the miners'
  balances. A block displaced by a reorganisation becomes `orphaned` and credits nothing; it is removed from the points documents that are not
  published yet, and a document lists, when it is closed, only the blocks that are still on the main chain (or too recent to be decided).
- The finder gets no bonus: the reward is by work only.
- **Solo port** (`--solo-listen ADDR [--solo-fee 1.0]`, off by default; 3366 on the official pool). It is the same protocol and the same verification on a second
  port: a worker that connects there mines SOLO through the pool, without running a node of its own. Its shares are checked, recorded in the points ledger and
  counted for the points exactly like any other (the work is the same), but they stay OUT of the PPLNS window, so they neither dilute nor profit from the miners
  of the main port. A block found by a solo worker pays the WHOLE net reward (emission + fees, minus `--solo-fee`, default 1 % of the gross reward) to its
  address, nothing to anyone else; a block found on the main port is split by the window as above and a solo address never receives a part of it. The login
  reply carries `"mode": "solo"` or `"pplns"` and the fee of that port; `/api/stats` has `solo: {enabled, fee_bps, workers}` and `/api/miner/ADDR` tells the
  mode of each worker. Confirmation, payouts, the signed ledger and the audit are the same for both ports. A solo miner finds a block rarely (a lottery, as
  alone with a node of its own): the main port is the better choice for a small or medium rig.

## 7. Payouts

Every `payout_interval` seconds (default 600) each miner whose balance is at least `min_payout` (default 1 VRL) receives one `Transfer` signed by the
pool key (fee 0), at most `max_payouts_per_round` (50) per round. The balance is debited when the transaction is created and tracked as *in flight*:

- included (the pool's nonce moved past it) and then final after `confirmations` more blocks, when it moves to the payment history;
- lost from the mempool: re-submitted every maintenance tick (2 s);
- undone by a reorganisation: detected (nonce back below) and re-submitted.

The pool never pays more than its on-chain balance minus what is already in flight. `GET /api/stats` exposes `money.solvent` (pool wallet balance covers
what is owed plus the pending blocks) and the pool prints a warning when it does not.

## 8. Persistence

`<data-dir>/pool/pool-state.bin` (bincode, atomic write via a temporary file, previous copy kept as `.bak`) holds the share window, balances, blocks, payments
and in-flight transfers; saved every 30 s when changed and at shutdown. At start it is **refused** if it belongs to another genesis or another pool key
(it is never overwritten in that case). The node's chain lives in `<data-dir>/node`. Without `--data-dir` nothing is persisted (tests only).

## 9. HTTP statistics (read-only, `--http ADDR`)

`/` (small dashboard), `/health`, `/api/stats`, `/api/blocks`, `/api/payments`, `/api/miner/<vrl1...>` (balance, pending, in flight, paid, share of the
window, workers with estimated rate in sigma/s, last payments). Bind it to localhost and publish it through a reverse proxy.

## 10. Running it

Pool operator (dedicated wallet; testnet example):

```
vearl-wallet new pool.json
vearl-pool --wallet pool.json --password-file pool.pw --genesis genesis.json --peer SEED:9000@KEY --listen 0.0.0.0:9000 \
           --pool-listen 127.0.0.1:3333 --http 127.0.0.1:8650 --data-dir /var/lib/vearl-pool --fee 1 --min-payout 1 --confirmations 30
```

Add `--solo-listen 0.0.0.0:3366` (and `--solo-fee 1`) to open the solo port beside the main one. Expose `--pool-listen` through a TLS proxy for the public (see section 3). Fund nothing: the pool key only receives rewards and sends payouts.

Worker:

```
vearl-poolminer --pool pool.example.org:3333 --address vrl1yourpayoutaddress --worker rig1 --gpu       # CUDA build
vearl-poolminer --pool pool.example.org:3333 --address vrl1yourpayoutaddress --threads 8               # CPU
```

The ordinary way for a miner to use a pool is the launcher of the release, which offers both ways of mining (the wizard asks at the first start):

```
vearl-miner pool                  # pool mode: the pool named in network.json ("pool", pool.vearl.org:3333 for the testnet); remembered
vearl-miner solo                  # solo mode: the node mines alone (needs a wallet file); remembered
vearl-miner --mode pool --pool pool.example.org:3333 --address vrl1yourpayoutaddress --worker-name rig1    # one run, no settings file (HiveOS, scripts)
```

In pool mode the launcher starts `vearl-poolminer` (GPU when one is usable, otherwise CPU) and no node: only the payout address is needed, no wallet
password. Its status line is shown and appended to `miner.log`, the signed receipts go to `pool-receipts.jsonl`. With a wallet it also starts a
worker-only node for the paid compute jobs (docs/15); the Quantus add-on belongs to solo mode. The worker name defaults to the computer name (the wizard asks, because the pool shows it).

The worker reconnects by itself (1 s doubled up to 30 s). It prints its rate, accepted/rejected shares and blocks every 10 s.

## 11. Security notes and limits (read before running a public pool)

- **Hot key.** Rewards land on the pool key and payouts are signed with it: use a dedicated wallet, keep the minimum there, run the pool as an
  unprivileged user. Anyone who gets the key steals the balance.
- **Block withholding.** A worker can submit shares but silently drop a share that would be a block (the pool then loses its reward share). This is inherent
  to pools with untrusted workers; the reference pool has no detection. Mitigations are operational (known miners, monitoring `rejected` vs expected
  blocks per work).
- **No TLS, no authentication.** The payout address is the only identity: anyone can mine for any address (that is harmless: they only give work). Do not
  put secrets in the protocol; terminate TLS in front for public use.
- **Denial of service.** Per-line size, idle and login timeouts, per-IP and total connection caps, token bucket on submissions, strikes and temporary
  bans bound the cost of hostile clients; behind a proxy all clients share the proxy's IP, so apply the per-IP limits in the proxy instead.
- **Single point of failure.** One pool process, one node. If the pool crashes, workers wait and reconnect; the state file keeps the books. No failover.
- **Timestamps.** A job's timestamp is fixed when created (refreshed every `refresh_secs`, 30 s). Blocks found on an older job of the same parent carry
  that older (still valid) timestamp.
- **Only Native Work.** Pool shares do not carry useful jobs; the useful-work market is for solo workers.
- Rounding: balances and payouts are integers (atoms, `1 VRL = 10^8`). The pool fee absorbs rounding remainders of the block split only through the exact
  split rule above (they stay with the largest holder).

## 12. What the tests check (`tests/pool.rs`, `pool::tests`)

- `tile_jackpot` equals the jackpot of the full GEMM and the one `verify_tile_proof` recomputes.
- Two real CPU workers on a real node: blocks found by the pool are accepted by the chain; every block's brute reward is `emission + fees` of the real
  block; the split of each block sums exactly to its reward; funds are conserved (`confirmed rewards = owed + in flight + paid + pool fee`); the pool's
  on-chain balance equals mined rewards minus transfers included; both miners receive real on-chain payments; statistics agree.
- Points ledger (`tests/pool_points.rs`): an honest pool with two miners passes the audit; each way of cheating is caught (edited document, document signed by
  another key, fake miners, hidden and made-up blocks, a miner credited less than its receipt, a share counted twice, shares credited at a harder target,
  a rewritten history, an unpublished epoch); the work-versus-blocks test; the Python downloader and the audit program end to end on a live pool.
- The solo port (`tests/pool.rs`): the two ports announce their mode and fee; a pool miner and a solo miner on a real node, each finds blocks; a solo block
  pays everything but the solo fee to its finder, a pool block pays the window and nothing to the solo address; the solo shares are not in the window but are in
  the points ledger.
- Hostile client: submit before login, bad protocol, bad address, bad worker name, double login, duplicate share, foreign slot, unknown job, out-of-range tile,
  share above the target, oversized line, repeated garbage, per-IP cap; none of them credits anything.
- Vardiff moves the target; state survives a restart (chain and pool), a foreign key or genesis is refused; PPLNS window arithmetic, bounded window,
  one-time confirmation, orphans credit nothing.

Not tested yet: a deep reorganisation that orphans a pending block on a live pool, a pool with thousands of workers, the CUDA worker against the pool for
a long run, TLS in front.

## 13. Points ledger and fraud protection (`vpool/2`)

The testnet rewards (docs/19) are computed from the chain, and the chain only shows the pool's key as the `miner` of a block. To give the
points of a pool's blocks to the miners that earned them, the pool publishes a **signed ledger of its work**, and everything it publishes can be
checked by anybody. Nothing here changes the consensus, the payouts of section 7 or the protocol of the shares; a `vpool/1` miner keeps working
exactly as before (and earns no points: it has no receipts to prove what it did).

### 13.1 What the pool publishes

The time is cut into **epochs** of one hour (`epoch = unix time / 3600`, configurable for tests). Five minutes after an epoch ends (the grace
for its last shares and blocks, `points_grace_secs`) the pool signs and stores one document per epoch and serves it on the statistics HTTP
server (`--http`, publish it through a reverse proxy):

| URL | content |
|---|---|
| `/api/points/index` | list of the published epochs: hash of the document, Merkle root of the shares, counts |
| `/api/points/epoch/N` | the signed document of epoch N (below) |
| `/api/points/share/N/I` | share number I of epoch N with its Merkle path |
| `/api/points/shares/N?from=F&limit=L` | the complete list of the shares of epoch N (hex records), 20,000 at most per answer |

The document (`vpool-points/1`) holds: the pool address and key, the genesis hash, the window (`start`, `end`), `prev` (SHA-256 of the previous
document, so history cannot be rewritten quietly), the blocks the pool found during the epoch (height, hash, header timestamp), the jobs the shares belong to
(parent, height, timestamp, transaction root, network target), the miners (address, work, shares, and the same figures for `vpool/2` sessions
only), the totals and the **Merkle root of the list of all shares** (one leaf per share: job, `extra_nonce`, tile, credited target, address,
protocol version; `vearl/merkle` hashing). It is signed with the pool key: `Ed25519(pool key, "vearl/pool-points/v1\0" + canonical JSON)`,
canonical JSON = keys sorted, no spaces, integers and strings only (so that Python, Rust and anybody else obtain the same bytes). Weights are
the `share_weight` of section 5, as decimal strings.

### 13.2 Receipts

Every `receipt_secs` (60) the pool sends each `vpool/2` session a notification

```json
{"method":"receipt","params":{"address":"vrl1...","epoch":N,"genesis":"...","pool":"vrl1...","shares":123,"ts":1760000000,"weight":"...","sig":"..."}}
```

signed with the pool key: the pool's promise that, in epoch N, the address has **at least** this `vpool/2` work. A final receipt is sent when the
epoch is closed. The reference miner checks the signature against the pool key of its jobs and appends every valid receipt to
`pool-receipts.jsonl` (`--receipts FILE`). If the signed ledger later credits less than a receipt, the pool has contradicted its own signature, and
the two signed documents are enough to prove it to anybody.

### 13.3 The audit

`vearl-pool-audit` (with `tools/fetch_pool_bundle.py`, which downloads the documents first and only then draws at random the shares to examine,
so the pool has already committed to the list when it learns which shares will be asked for) checks, with no trust in the operator:

| check | what it catches | result |
|---|---|---|
| signature, pool, genesis, arithmetic of each document | a document edited after signing, forged, or of another pool or network; totals that do not add up | unusable (suspect) / fraud |
| the blocks listed against the chain (same height, hash and timestamp), listed once | a block listed twice or in an epoch it cannot belong to; a block far above the top of the chain (more than 1000 heights): `phantom_block` | fraud |
| a listed block that is not on the chain | an **orphan**: another block won the height. It earns nothing (the points are computed from the blocks of the chain) and is not a finding (`orphaned_block`, informational). More than a third of at least 8 listed blocks off the chain: a fork, or blocks never found (`many_orphans`) | ok / suspect |
| every block of the pool on the chain is listed in some ledger once the deadline (24 h) has passed | a block hidden from the ledger; an unpublished epoch | fraud |
| Merkle path of the drawn shares to the signed root; with the complete list: the root, the weight of every miner, no share counted twice | a list changed after signing; weights that are not the sum of the shares | fraud |
| recomputation of the drawn shares (the jackpot of the tile, `work::tile_jackpot`) against the target they are credited at | shares nobody computed (made-up miners); a share credited at a harder target than it reached. (A target harder than the network target of the job is not a finding as long as the jackpot reaches it.) | fraud |
| receipts held by the miners against the signed ledger | a miner credited less than the pool signed; a receipt for an epoch that was never published | fraud |
| `prev` chain of the documents | a document replaced after the next one committed to it; missing documents | suspect |
| claimed work against the blocks found (Poisson test per day, `p < 1e-9`) | work invented without the blocks that would come with it; blocks without the work that explains them | suspect |
| share parents against the chain hashes | many shares on parents that are not on the chain | suspect |

The report (`audit.json`, exit status 0/1/2) gives a status for every epoch: `ok`, `suspect` or `fraud`. `tools/testnet_rewards.py --pools`
(docs/19 section 3 bis) counts only the `ok` epochs, holds the `suspect` ones until a person has looked, and gives nothing for a `fraud` epoch.

### 13.4 Operator duties

- Serve `/api/points/*` publicly (the other statistics can stay private), keep `<data-dir>/pool/points/` (documents and share lists; about 60
  bytes per share) and never delete an epoch that has been published.
- Register the pool with the team (docs/19) before the testnet starts counting; an unregistered pool's blocks are not shared with its miners.
- Do not edit or re-sign a document after publishing it: the next document commits to its hash.
- Keep the pool key safe. Whoever holds it can sign documents and receipts.
- Put a reverse proxy with a request rate limit in front of `--http` (`/api/points/share/N/I` builds a Merkle tree the first time an epoch is asked
  for); the pool caps one hour at `max_epoch_shares` shares (3 million) and refuses more with error 26, so that its memory and the document stay bounded.

### 13.5 What this does not prove (read before trusting a pool)

- **Attribution is the pool's word, backed by receipts.** A share is a proof of work, not a proof of who computed it: the pool could give your
  shares to another address. The defence is your receipt: a miner that keeps `pool-receipts.jsonl` and runs the audit will catch a pool that
  credits it less than it signed. A pool whose miners never check their receipts is still trusted. (A signature per share by the miner would close
  this; it costs a wallet unlock per mining session and is not done in this version.)
- **An operator can mine under several addresses.** That is real work, like any miner with several machines; the audit cannot (and need not)
  tell. Fake work without real computation is what the recomputation catches.
- **The audit treats the pool as an adversary.** Everything it downloads is checked before it is used as a file name or a number (plain integers only),
  answers are size-limited, redirects are not followed (a pool cannot make the auditing machine read its own private API), the number of epochs
  read per run is bounded, a document that appears long after its epoch ended is held (`late_document`), the epoch length is fixed by the program
  (3600 s, a pool cannot choose its own windows), jobs must lie inside their epoch and on the chain (`job_outside_epoch`, `job_from_the_future`),
  the matrices rebuilt for the recomputation are bounded (`audit_budget`), a weight can only be a plain non-negative integer (so a signed document
  can share the points of the pool's blocks but never create more), and if the audit program itself fails on a pool's data, that pool's hours are
  held (`audit_failed`) instead of keeping an older, favourable report in force.
- **Sampling is probabilistic.** With 16 shares drawn per epoch, a ledger in which 20 % of the shares are fake is caught with probability
  `1 - 0.8^16` = 97 % per epoch, and over several epochs it is certain. `--full` downloads every share and verifies the weights exactly; the
  recomputation itself can be run on all shares (`--verify-max`).
- **Block withholding.** A miner that submits shares but never submits a block lowers the number of blocks: the work-versus-blocks test then
  flags the pool as `suspect`, and a person decides. The same happens to an unlucky pool less than once in a billion days.
- **Chains with very fast blocks** (a test network) find many block solutions per height, most of them stale, and the Poisson test does not apply.
- **Hour boundaries.** A block is listed in the epoch in which the pool found it, like the shares; its header timestamp is that of the job it was found
  with, so it can precede that epoch by a few minutes (the audit accepts 10 minutes either way). The points of a scoring day are shared by the work of
  that day, so the difference does not matter.

### 13.6 Points shown to the miner

A miner types its wallet address on the pool and the pool tells it how many testnet points it has earned through the pool, with the rule of the rewards
program (docs/19 section 3 bis): the points that the pool's blocks earned in a scoring day (1 per block, 1.5 with paid work, x1.25 in the first three
days), times the share of the `vpool/2` work that the address did that day.

- `GET /api/points/miner/<vrl1...>` returns `provisional` (computed by the pool from its own signed ledger, including the current hour), `per_day`,
  `counted_work`, `pool_points_total` and `official`. `GET /api/miner/<address>` carries the same object under `points`, the pool page shows both
  figures, and the `stats` request of the protocol returns the provisional figure, which `vearl-poolminer` prints every 10 s.
- `provisional` is the pool's own computation. It is not the figure that counts: the official one is the row of the published leaderboard
  (`leaderboard.json` of `tools/testnet_rewards.py`), which also applies the audit (a held or fraudulent hour counts for nothing), the registration and the
  eligibility rules. Start the pool with `--leaderboard FILE` (the file you refresh from <https://vearl.org/rewards/leaderboard.json>, for example with a
  cron job) and `official` shows rank, points, eligibility and the reasons if the address is not yet eligible. Without the file `official` is `null`.
- The pool needs the start of the testnet to cut the days: `--testnet-start 2026-10-23T16:00:00Z` (the default of the public testnet). Blocks and hours
  before it are not counted.
- A miner that speaks `vpool/1`, or an address that never mined in this pool, has 0 points here: there are no receipts to back its work.
- The two figures are written independently (Rust in the pool, Python in the rewards tool) and the tests check that they agree.

### Auditing growing histories without exhausting the matrix budget

`tools/audit_pools.py` recomputes shares in batches of 16 hourly epochs by default
(`--batch-epochs N`). Each process still reads **all** signed epoch documents,
first-seen times, receipts and the same frozen chain snapshot: document chaining,
hidden blocks, work-versus-blocks checks and receipt contradictions are not split
into isolated windows. Only share/proof files are partitioned. A batch that reaches
`audit_budget` is retried in halves; a single epoch that still exceeds the budget
remains held. Neither an exhausted budget nor a process failure is waived.

Install `audit_batches.py` alongside `audit_pools.py` and rebuild/install
`vearl-pool-audit` from the same revision. The merger requires the audit binary's
`unknown_parent_shares` counter to recheck that statistical threshold across all
batches; an older binary fails closed. The CLI also accepts `--matrix-builds N`
for a smaller per-process budget (1 through 400, never above the default).

The final report is replaced atomically only after complete share coverage. Fraud
findings survive merging, including when another batch fails. Existing project
waivers and documented statistical relaxations run afterward as before. Initial
re-auditing of a long history can take substantially longer than an exhausted
single pass; this is bounded recomputation per process, not incremental reuse of
previous audits. Test runtime/resource use on the operator's host before changing
the production schedule. Do not restore credit by enabling unaudited counting or
removing resource guards.
