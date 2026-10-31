# 06 — Testnet: commissioning and operation

**This is an unaudited TESTNET with no value whatsoever.** Tokens have no price, the chain can be reset at any time, and nothing here must be used to protect real funds (`docs/02` §4, `docs/03` §4).

## 1. What is provided

| component | binary | role |
|---|---|---|
| node | `node` | consensus, encrypted P2P network (Noise), CPU/GPU mining, worker, HTTP API + explorer |
| wallet | `vearl-wallet` | 24-word phrase, encrypted keystore (Argon2id + ChaCha20-Poly1305), `vrl1…` addresses, `send`, `balance` |
| genesis | `vearl-genesis` | JSON genesis file (work parameters, allocations, durations, retargeting) |
| faucet | `vearl-faucet` | hands out a small amount, limits per address / IP / day |
| tools | `vearl-cli` | compute market (jobs, auctions, audits, inference) — devnet seeds |
| deployment | `deploy/` | hardened systemd units, nginx config (TLS + rate limits), install script |

## 2. Quick start (one machine, loopback)

```bash
cd vearl-core && cargo build --release && B=target/release
export VEARL_WALLET_PASSWORD='a strong password'               # or --password-file
$B/vearl-wallet new --file faucet.json                          # WRITE DOWN the 24-word phrase
$B/vearl-genesis --network my-testnet --faucet $($B/vearl-wallet address --file faucet.json) > genesis.json
$B/node --genesis genesis.json --listen 0.0.0.0:9000 --mine-seed 1 --api 127.0.0.1:8545 --data-dir ./data &
$B/vearl-faucet --node 127.0.0.1:9000 --wallet faucet.json --listen 127.0.0.1:8081 &
# explorer: http://127.0.0.1:8545/   faucet: http://127.0.0.1:8081/
```
To mine with **your** wallet: `--miner-wallet miner.json` (password through `VEARL_WALLET_PASSWORD`, `VEARL_WALLET_PASSWORD_FILE` or hidden prompt). `--mine-seed N` derives the key from a **public seed**: it is **refused** with a file genesis (unless `--insecure-devnet-keys`) and only serves the built-in devnet and the tests.

## 3. Deployment on a server

1. `sudo ./deploy/install.sh` (system user `vearl`, binaries in `/opt/vearl`, systemd units).
2. Create the faucet wallet **on a trusted machine**, then copy only `faucet-wallet.json` into `/etc/vearl/`; the password goes into `/etc/vearl/faucet-password` (`chmod 600`), given to the service through `LoadCredential` (neither a command-line argument nor an environment variable).
3. Generate the genesis (`vearl-genesis`) and **distribute it as is to all nodes**: the genesis hash covers all its fields, two different files = two networks that refuse to talk to each other.
4. `systemctl enable --now vearl-node vearl-faucet`.
5. Firewall: open **9000/tcp** (P2P) and **443/tcp** (nginx); do NOT open 8545 or 8081 (they stay on loopback behind nginx).
6. `deploy/nginx/vearl.conf` provides TLS, 20 req/s on the API and 1 request/min on the faucet.

## 3 bis. The genesis of the public testnet

`deploy/genesis/make-genesis.sh` builds it with `vearl-genesis --preset public`. What it fixes, and why:

- **Work parameters**: `n = 1024`, tile 16, rank 63, `fold_k = 64`. The default `devnet` preset (`n = 128`) is a toy size for tests; the models and jobs of the testnet are sized for 1024.
- **Start time (`LAUNCH_UTC`)**: the instant the network starts. The difficulty rule (ASERT) is anchored on the genesis timestamp, so a file dated too early would make the first blocks almost free, and one dated later makes nodes wait: a node started before the timestamp simply sleeps until a minute before it. Default: 2026-10-23 16:00 UTC (18:00 in Paris). If the launch slips, build a new file: a new timestamp is a new genesis hash and every node must use the same one.
- **Initial target (`HASHRATE`)**: set so that a network of that many tile attempts per second finds a block every 10 s (`target = 2^64 / (hashrate × 10)`; the published genesis of the 23 October testnet was calibrated for 30 s before the block time became 10 s, so its first blocks may be slower than 10 s until ASERT, which anchors on the first block, has corrected the schedule). One RTX 5060 Ti measured about 49 million attempts per second at `n = 1024`; the default 100 million assumes two or three cards at the start. ASERT corrects the rest, with a half-life of 15 minutes.
- **Allocations**: one dedicated faucet wallet (1,000,000 VRL, i.e. 100 days at the faucet's 10,000 VRL daily cap) and optional extra allocations. No other premine. The tool refuses any address derived from a public devnet seed.
- **Faucet wallet**: created **offline** (`vearl-wallet new --file faucet.json`), the 24 words on paper. Only its address is needed to build the genesis.

Checklist:

1. Build the file (`FAUCET_ADDRESS=vrl1… bash deploy/genesis/make-genesis.sh`), read the summary twice (faucet address, start time, `n = 1024`) and keep the **genesis hash** it prints.
2. Check it again from the file alone: `vearl-genesis --check genesis.json` (same hash, `valid: yes`).
3. Copy `genesis.json` unchanged to every node, publish it with its SHA-256 (for example `https://vearl.org/genesis.json`) and announce the genesis hash. A node refuses peers with another hash and prints its own at start-up.
4. Start the seed nodes before the launch; they wait for the start time. Commit the final file as `deploy/genesis/genesis-<network>.json`.
5. Tested (2026-10-06, development server): a public-preset genesis calibrated at 49 M/s, one GPU miner and one CPU-only follower on loopback; the follower stayed at the miner's height.

## 3 ter. Launch checklist (public testnet, 2026-10-23 16:00 UTC)

Everything below is scripted; what only the operator can do is marked **[you]**.

1. **[you]** Create the faucet wallet offline (`vearl-wallet new --file faucet-wallet.json`, 24 words on paper), give the address `vrl1…`.
2. `FAUCET_ADDRESS=vrl1… HASHRATE=<attempts/s of the miners present at the start> bash deploy/genesis/make-genesis.sh`, then read `summary.txt` twice and keep the genesis hash. If the launch time slips, rebuild: a new timestamp is a new network.
3. Binaries: Linux static CPU builds (cross-compiled from Windows, see below) and the Windows multi-architecture GPU build, packaged with `python deploy/release/make_release.py --version testnet-1 --linux DIR --windows DIR --genesis genesis.json`; it writes the two archives and `SHA256SUMS.txt`. **All nodes must run the same release.**
   - Linux static build from any machine with Rust: `rustup target add x86_64-unknown-linux-musl`, copy the crate, set `blake3 = { version = "1", features = ["pure"] }` in the copy's `Cargo.toml` (no C compiler needed), and build with `linker = "rust-lld"` and `rustflags = ["-C", "link-self-contained=yes"]` for that target (`cargo build --release --target x86_64-unknown-linux-musl --bin node --bin vearl-cli --bin vearl-wallet --bin vearl-genesis --bin vearl-faucet`).
   - Windows GPU build: `deploy/windows/build-gpu-windows.bat` with `VEARL_CUDA_ARCH=all`.
4. Seed node (the site server has no GPU and does not need one): `deploy/install.sh --bin DIR` (no cargo on the server; `--prefix NAME --ports P2P,API,FAUCET` installs a second copy beside a running one, which is how the rehearsal below was done), then copy `genesis.json`, `faucet-wallet.json` **[you]** and the faucet password file **[you]**, `systemctl enable --now vearl-node vearl-faucet`. Open 9000/tcp.
   - **Seed node as installed (2026-10-08):** on the SITE server `SERVER_IP` (Ubuntu 24.04, same machine as vearl.org; `vearl.org` already resolves to it, `seed.vearl.org` needs an A record at your DNS provider: `seed A SERVER_IP`). Service `vearl-node` (user `vearl`, data `/var/lib/vearl`, config `/etc/vearl`, API 127.0.0.1:8545, P2P 0.0.0.0:9000), health timer `vearl-watch.timer`, and the fee auditor timer `vearl-feeaudit.timer` (docs/17, node started with `--collect-fee-beacons`). Genesis hash `a5771be7...b744` (replaced on 2026-10-23, the first one was `46c57f50...fb17`), network public key `2edc285bed24fde1a5e41b6e2dedb52777a1b4aeacb0815802de9d6c83e52f35`; the releases list `seed.vearl.org:9000@KEY`, `vearl.org:9000@KEY` and `SERVER_IP:9000@KEY`. **Back up `/var/lib/vearl/node.key`** somewhere safe and offline: if it is lost the key changes and every release has to be redone. The faucet is NOT installed yet (it needs the faucet wallet file and password, which only the owner has).
5. Website. **Published on 2026-10-07 in pre-launch mode** with `bash deploy/deploy-site.sh --nginx --with-explorer --with-compute`: `https://vearl.org/explorer/` shows SAMPLE DATA (from 2026-10-07, at the owner's request, to show what it will look like): `/api/` reads the demo network (node on 127.0.0.1:18545, `nginx-vearl-api-sample.conf`) and a banner that cannot be closed says so on every screen, with the countdown to the launch. The banner stays for as long as the node's genesis is the demo one (`<meta name="vearl-demo-genesis">`), so demo numbers can never pass for the testnet. **At the launch run `deploy-site.sh --nginx --api-live`**, which points `/api/` to the real node on 127.0.0.1:8545 (without the `<meta>` and with the launch meta only, the page shows an empty pre-launch screen with a countdown instead), and `https://vearl.org/compute/` shows the complete job form but cannot create a job (`/gw/` answers with fixed files from `deploy/gateway/prelaunch/`, `POST /gw/jobs` gets a 503). At the launch: start the seed node, then `deploy-site.sh --with-faucet` once the faucet runs; the job page stays closed until a job gateway runs against the PUBLIC network (see below), then `deploy-site.sh --nginx --gw-live`. `deploy/private-explorer/deploy.sh` republishes the site with the explorer and the job page, so it does not remove them.
   - **Before opening job creation on the public network:** the gateway (`deploy/gateway/vearl-gateway.py`) was written for the demo chain (n = 128: digit images and 128-wide matrix blocks, `seed:100` service key). On the public preset (n = 1024) the digits and matrix kinds need models and block sizes for n = 1024, the service key must be a funded `wallet:FILE`, and a GPU worker network must exist; the render kinds and the text and photo kinds (which already run on an n = 1024 chain) do not depend on n. The faucet page `/faucet/` posts to `/drip` The faucet takes the visitor's address from `X-Real-IP` when the connection comes from the loopback (nginx sets it), so its per-IP limit is per visitor and not shared by everybody.
6. Publish `genesis.json`, its SHA-256 and the release archives (for example under `https://vearl.org/`), announce the genesis hash and the seed's public key (`--peer HOST:9000@KEY`).
7. At the start time at least one miner must be running (the first block is expected a few seconds after the start at the calibrated hash rate; ASERT then adjusts with a half-life of 15 minutes).
8. Rehearsal (done 2026-10-07 with a throw-away wallet and a 20 M/s calibration, seed on the site server over the Internet, miner on a GPU PC): see §3 quater. To rerun it: `make-genesis.sh` with another `NETWORK`, `LAUNCH_UTC` a few minutes ahead and a throw-away `FAUCET_ADDRESS`, then `install.sh --bin DIR --prefix vrehearsal --ports 9100,8645,8181`.
9. `deploy-site.sh --nginx` replaces the nginx site file: it keeps the include of the unlisted preview pages (`/etc/nginx/vearl-private/*.conf`), so the private preview survives.

## 3 quater. Rehearsal report

**Rehearsal of 2026-10-07** (network `vearl-rehearsal`, built by the real `make-genesis.sh` with a throw-away faucet wallet, `n = 1024`, 20 M attempts/s calibration, 100,000 VRL faucet, start 16:51 UTC):

- Seed on the site server (Linux static CPU build, installed with `deploy/install.sh --bin DIR --prefix vrehearsal --ports 9100,8645,8181`, 5.7 MB of memory); miner on a Windows PC with an RTX 4070 SUPER **over the Internet** (port 9100 open, no tunnel), peered with `--peer HOST:9100@KEY`. The packaged Windows `node.exe` (multi-architecture CUDA build: sm_80, 86, 89, 90, 100, 120) synced 36 blocks from the seed in under 25 s on a fresh data directory.
- 39 blocks in 14 minutes: 16 s on average at the start (the real hash rate was above the calibration) and rising towards the 30 s target as ASERT corrected. The seed followed the miner block for block (`mempool 0`, same height at every sample), and kept up with the pure-Rust BLAKE3 build.
- Restart of the seed in the middle of the run: it reloaded its chain (height 26), kept its network key and the miner reconnected by itself.
- Faucet (`vearl-faucet` under systemd with the password through `LoadCredential`, behind the local proxy): paid an address, refused a second request for the same address, refused a second address from the same visitor, refused garbage. **Bug found and fixed:** behind nginx every visitor had the proxy's address, so the per-IP cooldown was global (one drip per hour for everybody); the HTTP server now takes `X-Real-IP` from a loopback connection (test `the_http_server_takes_the_client_address_from_the_local_proxy`), and a spoofed `X-Real-IP` sent by a visitor is overwritten by nginx (checked through the private page).
- Not covered: more than one miner on different machines, a seed under load, a launch with several GPU models, mining on Linux with a GPU (no Linux CUDA machine available).

## 3 quinquies. Launch day: faucet and job creation (prepared 2026-10-15)

**Faucet.** `deploy/faucet/install-faucet.sh` (run it from your PC; it needs only the faucet wallet file and its password, typed hidden): it checks that the wallet is the genesis faucet and that the password opens it, copies the *encrypted* wallet and the password (through ssh's standard input, root-only on the server) and installs `vearl-faucet.service` (25 VRL per request, one per address and per visitor each hour, 5,000 VRL a day). `--check` only verifies the wallet and the password on the PC. The page `/faucet/` is published with `deploy-site.sh ... --with-faucet`. Rehearsed on a local public-preset network (payment, refusal of a second request).

Faucet limits survive restarts: the CLI stores them in `--state-file` (default `WALLET.faucet-state.json` next to the encrypted wallet). The systemd service uses `/var/lib/vearl-faucet/limits.json`, created under its private `StateDirectory`. Back up and retain this state and its `.lock` file location; do not delete/replace them or run multiple faucets for the same wallet with different state paths. Existing installations start recording limits on upgrade; earlier payouts cannot be reconstructed from the old in-memory counters. Invalid, unreadable or wallet-mismatched state prevents startup. The state contains recipient addresses/IPs and is written with mode 0600 on Unix; protect backups too. Quota is reserved and synced before broadcasting, so a failed or uncertain send may consume quota even if no payment confirms. The cap counts these reservations, not only confirmed transfers; restarting cannot refund them. The UTC daily counter advances only when the clock moves to a later day. Restoring an older state backup can reopen budget, so reconcile it before reopening the faucet. This state uses Rust's standard file locking API (Rust 1.89 or newer).


**Job creation for everybody (`/compute/`).** The gateway has a public mode (`vearl-gateway.py --public`). What changed compared with the demo chain, and why:
- *Who audits whom.* On the public network any miner may take a job, and the audit needs the outputs of the miner that computed them. The gateway asks `vearl-cli l2-who` which node it can reach really serves the job's chunks (each answer is opened against the published Merkle root): the project's worker (`--worker 127.0.0.1:19110`, the reverse tunnel of `deploy/pc-worker/public-worker-tunnel.bat`) and the reachable peers of the seed (`--peers-file`).
- *Limit, measured.* A miner behind a home router cannot be reached. On a local rehearsal with a second, unknown worker, about half of the jobs were taken by it; the gateway then sends the job again (up to 2 times, `--retries`; the escrow is the service account's test tokens) and all 6 jobs of the last run ended "done". The RELAY (docs/21, release rc14) removes the limit: a miner behind a router keeps its connection to the seed, and the seed (started with `--relay`) carries the audit's requests to it; the gateway tries it first. It needs the rc14 node on the seed and `--relay` in `/etc/vearl/node.env`; until then the behaviour above applies.
- *Kinds.* Studio render, Vearl Orb, 3D scene and Monte Carlo (they do not depend on the work size n). The exact kinds written for n = 128 (digits, matmul) and the ML kinds (text, photos: they run on a separate chain) are off in public mode.
- *Money.* A service wallet (`install-public-gateway.sh` creates it on the server with a random password, root-only) pays the escrow of every free job: 2 VRL, 10 % burned, the rest to the miner. Fund it after the first blocks: `vearl-wallet send --file faucet.json --node seed.vearl.org:9000 --to <service address> --amount 100000` (do it before the faucet serves anybody: both use the faucet wallet's nonce).

Sequence at 16:00 UTC (23 October): (1) your miner is running and the tunnel window is open; (2) first blocks appear (`curl 127.0.0.1:8545/api/status` on the server: height > 0); (3) fund the service wallet; (4) `systemctl enable --now vearl-gateway`; (5) `bash deploy/deploy-site.sh --nginx --api-live --gw-live --with-explorer --with-compute --with-leaderboard --with-participate --with-faucet` (explorer on the real chain, `/compute/` open, `/faucet/` published); (6) create one job from the page yourself and one drip from the faucet page. Before: `install-faucet.sh` and `install-public-gateway.sh` (nothing public changes). If something goes wrong with jobs: `systemctl stop vearl-gateway` and `deploy-site.sh --nginx` without `--gw-live` puts the page back in its closed state.

## 3 sexies. The launch switch: everything goes on line by itself (prepared 2026-10-18)

At the launch time (23 October 2026, 16:00:00 UTC) nobody has to do anything on the seed server. `vearl-launch.timer` runs `/opt/vearl/launch/vearl-launch.sh` every minute (and once exactly at the launch time); the script does nothing before that time and nothing once everything is on line. Its stages, each idempotent, each verified before it counts and each undone when its verification fails:

1. **api** (at the launch time): the explorer's `/api/` is pointed at the real node (nginx snippet `vearl-api.conf`: sample network -> `127.0.0.1:8545`), then `https://vearl.org/api/status` must answer the testnet genesis. The explorer page needs no change: its sample banner disappears by itself as soon as the node's genesis is not the demo one.
2. **fund** (once the chain has 3 blocks): the faucet wallet, which is on this server, pays 100,000 VRL to the service wallet of the job gateway (one transfer, never sent twice while it is awaited).
3. **gateway** (once the service wallet is funded): `vearl-gateway` is started and `/gw/` is pointed at it (snippet `vearl-gw.conf`: pre-launch -> live), then `https://vearl.org/gw/info` must be the live gateway: `/compute/` creates jobs.
4. **faucet**: the faucet page `/faucet/` is published (the page was prepared with the fingerprints of the files that are on the server).
5. **demo off**: the demo nodes of the sample explorer are stopped and disabled, and give their memory back to the real node.

It never switches to a network whose genesis hash is not the testnet's. A stage that fails three times is retried every five minutes only. One hour before the launch a full read-only check is e-mailed to contact@vearl.org (good or bad), and each stage that succeeds, or keeps failing, sends one short e-mail there too.

- `vearl-launch.sh --check` (read-only, any day): the node, nginx, the files and wallets, the balance of the faucet wallet, the services, the clock, `--relay`, the published pages. `vearl-launch.sh --status`: which stages are done. Logs: `journalctl -u vearl-launch`.
- Install or update: `bash deploy/launch/install-launch.sh` (nothing public changes until the launch time). Logic test of the script: `bash deploy/launch/test-launch.sh` (the real script, with a made-up world: before the launch, the chain starting, failures and their undoing, a restart in the middle).
- After the launch `deploy-site.sh` keeps the testnet on line: when the server has `/var/lib/vearl-launch/live`, `--api-live`, `--gw-live` and `--with-faucet` are implied (`--sample` goes back to the pre-launch variants).
- What the script cannot do: mine the first blocks. At least one miner must be running at the launch time (the first block follows within seconds at the calibrated hash rate), and the job service finds its workers among the miners that run a node in solo mode (the seed is started with `--relay`, so a miner behind a router is reached); the project's own GPU worker (`deploy/pc-worker/public-worker-tunnel.bat`) is an extra, not a requirement.
- Rehearsed on 2026-10-18 on the real server, without changing anything public: the API stage for a few seconds (then undone), the gateway process (started, probed, stopped), the transfer command up to the balance check; the rest of the sequence by the logic test.

## 3 septies. A crowd at the launch: what the servers hold (measured 2026-10-18)

Servers: the seed and website server (6 vCPU, 3.9 GB, nginx + node + mail) and the pool server (4 vCPU, 15.7 GB, nginx + pool). The pages are light: the home page is 443 KiB on a first visit (two JPEG pictures are most of it), the explorer, job page and pool page about 120 KiB, and every stylesheet, script and font is cached for a year (fingerprinted URLs), so a refresh costs the HTML and a few API reads.

- **Pages.** 3000 visitors opening the home page in the same second, each with a NEW TLS connection: 3000 answers out of 3000, no error, the seed server at 16 % of its CPU at the peak (about 400 new TLS connections per second from a single load generator; the generator, not the server, was the limit). The pool page: 3000 of 3000 as well. nginx now takes 8192 connections per worker (it was 768) and 65,535 open files.
- **API.** The node's HTTP server takes 64 connections at a time and only 16 long polls: measured straight on it, 200 visitors waiting for a block gave 16 answers and 184 refusals (429). So (1) the explorer no longer long-polls: it asks `/api/status` every 4 to 6 seconds, with a random part, and refreshes when the height moved; (2) nginx has a **micro-cache** in front of the node (`vearl-locations.conf`, zone `vearl_micro`): everybody that asks for the same URL within one second shares ONE request to the node (`proxy_cache_lock`), and the last answer is served if the node is busy (`proxy_cache_use_stale`); the cache is emptied by the launch switch whenever it flips a snippet. Measured with the same location (without the per-address limit): 3000 visitors x the 6 calls of the explorer's overview = 18,000 requests in 4.9 s, 0 errors, 98.7 % served from the cache; 200 visitors on `/api/wait` through the cache: 200 answers, one request to the node.
- **Job gateway.** The `GET` answers of `/gw/` (info, recent jobs, a job's status) are cached for 2 seconds in the same way (none depends on the visitor); creating a job (`POST`) is never cached and keeps its quotas.
- **Pool.** The same micro-cache (2 s) in front of the pool's statistics (`deploy/nginx/nginx-vearl-pool.conf`), and `--max-conns 5000` for the miners' port (it was 2000; one thread and two descriptors per connection, 65,535 allowed).
- **What was not tested.** The real bandwidth of the two servers (the hosting plans' limit is not known here: a burst of 3000 first visits of the home page is about 1.3 GB), a crowd on the live job gateway (nothing runs behind it before the launch), and several thousand miners connected at the same time to the pool.

## 4. Joining an existing network
```bash
node --genesis genesis.json --peer seed.example.org:9000@<PUBLIC_KEY_HEX> --listen 0.0.0.0:9000 --data-dir ./data
```
The bootstrap node's public key is displayed at start-up (`[node] network public key …`); the private key is in `node.key`, in its data directory; pinning it (`@key`) prevents impersonation of that peer. Nodes remember their peers (`peers.txt`) and retry them at restart.
To **mine**: `--miner-wallet FILE` (rewards go to the wallet's address); to be a compute **worker**: add `--worker --ask <price>` (the address must hold funds for the bond). Under systemd, create a *drop-in* (`systemctl edit vearl-node`) with `LoadCredential=miner-password:/etc/vearl/miner-password` and `Environment=VEARL_EXTRA_ARGS="--miner-wallet /etc/vearl/miner-wallet.json --password-file %d/miner-password"`.

## 4 bis. Using the network from Python (SDK)

`vearl-core/tools/vearl_client.py` speaks the real protocol (Noise XX + bincode) without depending on the Rust code (prerequisites: `pip install noiseprotocol blake3 numpy cryptography`):

```python
from vearl_client import Client
c = Client("127.0.0.1:9300", seed=4)                  # or Client(addr, secret=<32 bytes>)
job = c.submit_matmul(worker="127.0.0.1:9300", a=A, b=B, escrow_vrl=5)   # A, B: int8 in [-64, 64], n x n
c.wait_status(job, "Posted")
C = c.result_and_settle(job, worker="127.0.0.1:9300", a=A, b=B)          # Freivalds (error <= 2^-24), then Accept; otherwise Fraud
```
`python3 tools/client_demo.py` demonstrates it against an honest worker (paid) and a cheating worker (fraud detected, proof published, bond seized). A node's `Ack ok` means "accepted into the mempool": `wait_status` waits for inclusion.

## 4 ter. Running a GPU worker (inference, embeddings, linear algebra)

- **Start-up**: `node --worker --gpu --data-dir DIR --miner-wallet … --ask <price>`; `--gpu` enables mining on tensor cores **and** useful computation on the GPU (exact product and Merkle roots, `docs/12`). Without a GPU, everything works on the CPU (slower).
- **Memory**: an inference job keeps its tensors (`n²` bytes per operation, plus `4 n²` per Gemm); a tiled product `I×K×J` keeps `I·K·J` products of 4 MiB (2 GiB at 8×8×8 blocks of 1024). The worker keeps at most **32 program data sets** and **8 tiled-product data sets** alive (sets for which no job is alive any more are evicted); plan for ≥ 16 GiB of RAM for n = 1024.
- **Disk**: `putdata.bin` (client deposits: weights, inputs, matrices) is capped at **512 MiB**; beyond that new deposits are no longer persisted (the worker keeps them in memory but would lose them at a restart: do not exceed it on a worker that hosts long jobs).
- **Model registry**: weights deposited once (`PutModel`) are reused by all the jobs that reference them (`vearl-cli infer`); they are persisted with the rest.
- **Availability**: the worker **automatically serves** its clients' on-chain data requests (`Fetch`); do not shut it down during the challenge window (otherwise the bond is seized through `SlashUnserved`). `--no-serve` is a TEST flag (a worker that withholds): never in production.
- **Mempool policy**: 64 pending transactions per sender, 5,000 in total; a worker publishes one transaction per job (`PostBatch`) plus one claim.
- **Client tools**: `vearl-cli infer` (inference / embedding batches; `WORKER1,WORKER2,...` deposits the data with several workers so that they share the jobs), `vearl-cli tiled-run` (large products), `tools/embed_client.py`, `tools/la_client.py`; model conversion: `tools/quantize.py`, `tools/quantize_cnn.py`, `tools/import_onnx.py` (`docs/12`).
- **Checking an installation**: `python3 tools/audit_all.py --quick` (17 independent checks, `docs/09`).

## 4 quater. The explorer website

`site/explorer/` (with `site/assets/explorer.css` and `explorer.js`) is a single-page explorer in the style of the website: overview with a ribbon of the latest blocks coloured by the work they carried, charts (block time, network rate, transactions per block, share of miners, share of blocks that carried paid work), block, transaction, address and job pages (with the job life cycle), miners and richest accounts, mempool, and a network page with the genesis hash, supply check and the list of API routes. It is static: it reads the node's JSON API in the visitor's browser, builds every element with `textContent` (no `innerHTML`) and loads nothing from a third party, so it runs under the site's strict CSP. The search box resolves a height, a block hash, a transaction, a job id or an address (`/api/search`). It follows the chain live through the long poll `/api/wait`.

The routes it needs beyond the original ones are `/api/jobs`, `/api/miners`, `/api/accounts`, `/api/chart`, `/api/search`, the level-2 case of `/api/job/{id}` and extra fields of `/api/status` (tests: `explorer_routes_jobs_miners_accounts_chart_and_search` in `tests/p8.rs`).

Publishing: `bash deploy/deploy-site.sh --with-explorer` copies the page (without the flag it is not published). `deploy/nginx-vearl-locations.conf` proxies `/api/` to the node on `127.0.0.1:8545` (GET only, 20 requests per second per address, long-poll friendly): start the node with `--api 127.0.0.1:8545`. Until a node answers there, the explorer shows "No node reachable". To try it locally, serve `site/` with any static server that proxies `/api` to a node (the page asks for `/api` on its own origin; the `vearl-api` meta tag of `site/explorer/index.html` changes that prefix).

## 4 quinquies. Vearl Compute: the free "create a job" website

`site/compute/` (with `site/assets/compute.css` and `compute.js`, same design and the same CSP rules as the explorer) lets a visitor create a level-2 job without a wallet: pick Vearl Orb (Render2), the classic 3D scene (Render) or a Monte Carlo estimate of pi, set the size or the number of points and a seed, press a button, follow the job (submitted, taken by a miner, result posted, audited, accepted) and download the audited result. "My jobs" lists the jobs of this browser (kept in `localStorage`, no account); "How it works" states what is and is not guaranteed.

A web page cannot speak the node's encrypted peer protocol nor sign a transaction, so `deploy/gateway/vearl-gateway.py` (Python 3 standard library, no new Rust code) does it: it validates the request against fixed bounds (sizes, samples, chunks, seed), submits the job from its own service account with `vearl-cli l2-submit`, waits until a worker node posts a result (`l2-status`), then runs `vearl-cli l2-finish` (recomputes 4 random chunks, opens them against the Merkle root, accepts or proves fraud, assembles the output), converts the image to PNG and keeps it. It is free for the visitor because the service account pays the escrow in testnet tokens (2 VRL per job by default, of which 10 % is burned by the protocol, so 1,000 VRL fund about 5,000 jobs). Limits per visitor (6 an hour, 2 at a time) and in total (12 in progress); the visitor key is a salted hash kept in memory. It listens on `127.0.0.1:18600`; nginx exposes it as `/gw/` (`deploy/nginx-vearl-locations.conf`, GET and POST, 5 requests per second per address).

```
python3 vearl-gateway.py --cli /opt/vearl/vearl-cli --node HOST:PORT --worker HOST:PORT --key wallet:FILE --data /var/lib/vearl-gateway
```

`--key seed:N` is a PUBLIC devnet key (demo chain only); on a real network use `wallet:FILE` with a funded wallet (the password comes from `VEARL_WALLET_PASSWORD_FILE`, read by `vearl-cli`), and repeat `--key` to spread jobs over several service accounts. `--worker` is the worker node (`node --worker`) from which the audit reads chunks: it is a single address for now, so jobs are audited against one worker. A job nobody takes within 15 minutes is reported as failed (the escrow returns when the job expires).

Tested end to end against the demo chain on the site server (a temporary gateway process, then stopped): a Monte Carlo job and a 64 x 64 render were submitted through the gateway, taken by the demo worker, audited and accepted (about 3 to 6 minutes each, dominated by the 30 s blocks and the throttled demo worker).

Publishing: `bash deploy/deploy-site.sh --with-compute` copies the page, and only makes sense with the gateway running behind `/gw/`.

**Exact jobs (digits, matrix products) and the two language / vision jobs.** Besides the level-2 kernels the site offers `digits` (`vearl-cli infer` on `models/digits-cnn.json`, the 12 sample pairs shipped with the model) and `matmul` (`vearl-cli tiled-run`, 128 to 512 wide, the service recomputes 6 entries itself): the client checks every operation exactly (Merkle proof and Freivalds, 24 rounds). `gpt` (TinyStories-33M, 2 verified jobs per word) and `vit` (DeiT-Tiny, 2 chained jobs per photo) need a chain with n = 1024 and the quantized model files, which are too heavy and too GPU-bound for the web server: they run in `deploy/ml/vearl-ml.py` next to the GPU worker (Python clients of `vearl-core/tools`, numpy, PIL, `transformers` for the tokenizer and the label list) and the gateway forwards those two kinds to it (`--ml http://127.0.0.1:18602`, reached through an ssh reverse tunnel `-R 18602:127.0.0.1:18602`). The browser shrinks a photo to a 224 x 224 JPEG before sending it; the service reads it once and deletes it. One ML job runs at a time.

**Text embeddings (`embed`, Qwen3-Embedding-0.6B).** A third ML kind: one to four sentences (140 characters each) go together through the ten chained jobs of the 0.6-billion-parameter model (2,195 operations, `tools/qwen3_client.py`), and the visitor gets the table of cosine similarities. It needs the model file of the release (`qwen3-embedding-0.6b-int8.json.xz`, 300 MB), a chain whose nodes run **rc17 or later** (four more program operations) and a worker that accepts 528 weight blocks (registry cap 1,024): `python vearl-ml.py ... --embed qwen3-embedding-0.6b-int8.json.xz` (it can be combined with `--gpt` / `--vit`). On a CPU worker a text takes about 50 s (3 texts: 173 s measured), so the whole job lasts a few minutes. The kind is in the catalogue and in the pre-launch `info.json` (`deploy/gateway/prelaunch/info.json`): while the public site is in pre-launch mode nothing can be created (`/gw/` answers 503), whatever the kind.

Producing the model files (once, on a CUDA machine; Windows works): `pip install transformers datasets`, then `python tools/qat_gpt.py gpt-qat.json --train 30000 --epochs 2` (text: 91.9 % same next word as the float model on 25,183 positions, 4/4 bit-exact checks; 100,000 stories as in the published run take about 35 minutes alone on an RTX 4070 SUPER, much longer if the GPU is shared with a miner) and `python tools/qat_vit.py vit-qat.json --data coco --epochs 5 --lr 5e-5` (photos: 70.6 % top-1 against 78.2 % for the float model; needs `~/data/imagenette2-320` and the 5,000 COCO `val2017` photos). The chain: `vearl-genesis --preset public --retarget Fixed --target-divisor 100000000 --launch <UTC> --faucet <vrl1 of seed:4>` gives blocks of about 2 to 4 seconds on one GPU, which is what makes a word take about 22 s instead of 80 s (this is a private demo chain; the real testnet keeps ASERT at 30 s). Start a node with `--genesis genesis.json --mine-seed 1 --insecure-devnet-keys --worker --gpu`, fund `seed:1` (the worker bond) from `seed:4`, then `python vearl-ml.py --tools tools --cli vearl-cli --node 127.0.0.1:19120 --worker 127.0.0.1:19120 --key seed:4 --gpt gpt-qat.json --vit vit-qat.json`.

## 4 sexies. Running a mining pool

`vearl-pool` is a full node plus the pool server (protocol `vpool/1`, full specification and security notes in `docs/16-pool-protocol.md`). Workers run `vearl-poolminer` with a payout address only.

```
vearl-wallet new --file pool.json            # DEDICATED wallet: it receives the block rewards and signs the payouts
vearl-pool --wallet pool.json --password-file pool.pw --genesis genesis.json --peer SEED:9000@KEY --listen 0.0.0.0:9000            --pool-listen 127.0.0.1:3333 --http 127.0.0.1:8650 --data-dir /var/lib/vearl-pool --fee 1 --min-payout 1 --confirmations 30
```

- Put a TLS proxy (nginx `stream` or stunnel) in front of `--pool-listen` for the public, and a reverse proxy in front of `--http` (read-only statistics: `/api/stats`, `/api/blocks`, `/api/payments`, `/api/miner/<address>`). Behind a proxy all workers share its IP: raise `--max-per-ip` or apply the limits in the proxy.
- Back up `<data-dir>/pool/pool-state.bin` with the wallet: it holds the balances owed to the miners. The pool refuses to start with a state file from another genesis or another key.
- Watch `money.solvent` in `/api/stats` and the 30 s log line (`owed to miners`); `pending` blocks become `confirmed` after `--confirmations` blocks, `orphaned` ones credit nothing.
- Limits: unaudited, one process (no failover), native work only, no protection against block withholding by a worker (see the document).

## 5. Backups and incidents
- To back up: `node.key` (the node's network identity), `faucet-wallet.json` + **the 24-word phrase, offline**. The chain (`chain.bin`) resynchronises from peers.
- Worker: data deposited by clients is persisted in `putdata.bin` (data directory) and reloaded at start-up; back it up with `node.key` if the worker hosts long jobs. `VEARL_DEBUG_MEMPOOL=1` logs the mempool transactions that do not go through and the evictions.
- Corrupted chain: the node replays and re-validates `chain.bin` at start-up and **truncates** at the first error; as a last resort delete the data directory.
- Testnet reset: new genesis (new `--network`, new timestamp), new distribution; announce the date in advance.
- Minimal monitoring: `GET /api/status` (height, peers, mempool, total work); alert if the height stops increasing or if `peers` = 0 (the node also logs "no outbound peer for 30 s").
- `deploy/monitor/vearl-watch.py` does exactly that every minute (systemd timer installed by `install.sh`, enabled with `systemctl enable --now vearl-watch.timer`): it alerts once in the journal and, if `/etc/vearl/alert-webhook` holds a Discord webhook URL, in that channel, when the node does not answer, has no peer, has been stuck on one height for 5 minutes or reports a false supply invariant, and says when it recovers.

## 6. Security: what is covered and what is not
| covered | not covered |
|---|---|
| keys never sent to the node (transactions signed on the wallet side); encrypted keystore, refusal to overwrite; checksummed addresses | compromised workstation (keylogger, memory capture); weak password |
| encrypted and authenticated P2P, key pinning, admission limits per IP and per /16 | motivated Sybil/eclipse attack (`docs/02`); network anonymity (IPs visible) |
| API: read-only + submission of signed transactions, security headers, strict CSP, bounded inputs | no TLS or per-client limiting **inside** the built-in server: nginx is mandatory for public exposure |
| faucet: limits per address, per IP and per day (behind the local nginx the visitor's address comes from `X-Real-IP`, set by nginx and trusted only on a loopback connection) | a visitor with many addresses or many IPs can drain the daily cap (25 VRL per request, 5,000 per day by default): the cap is the real protection |
| systemd: dedicated user, read-only file system, secrets through `LoadCredential` | no external audit; consensus, work and market are prototypes (`docs/02`, `docs/03`) |

## 7. Known limits of this stage
- `vearl-cli` now accepts `wallet:FILE` and `vrl1…` addresses; `seed:N` seeds remain available for the devnet but must serve nothing else.
- The per-address history is a bounded backward walk over the blocks (no index): enough for a testnet, not for a large chain. The "long wait" (`/api/wait`) replaces polling; there is no WebSocket.
- Worker and miner keys are those of account 0 of a wallet; no multi-account, no hardware signing.
- No external audit: wallet, API and faucet are prototypes.

## 8. Preparing a new GPU server (Ubuntu 24.04, NVIDIA)
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev python3-pip tmux git   nvidia-cuda-toolkit nvidia-headless-580-server nvidia-utils-580-server linux-headers-$(uname -r)
sudo modprobe nvidia && nvidia-smi                  # otherwise reboot; the module is built by DKMS for the current kernel
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal && . ~/.cargo/env
cd vearl-core && cargo test --release --features gpu   # ~170 tests, including GPU = CPU bit-for-bit equality
```
By default the build targets Ampere, Ada and Hopper (sm_80, 86, 89, 90) and, with CUDA 12.8 or newer, Blackwell (sm_100, sm_120: RTX 50 series), plus the PTX of the newest one. For another selection: `VEARL_CUDA_ARCH=<compute capability without the dot, comma separated> cargo build --features gpu` (for example `VEARL_CUDA_ARCH=120` for a single RTX 5060 Ti).
