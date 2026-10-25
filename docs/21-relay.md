# 21 - Relay: auditing a miner that nobody can dial

## 1. The problem

To accept a paid job, the client audits the worker: it asks the worker for the outputs of a few chunks, recomputes them and opens each
one against the Merkle root the worker published on the chain. For that the client must **open a connection to the worker**. A miner at
home sits behind a router that refuses incoming connections, so its job cannot be audited. On the public gateway about half of the jobs
went to such a miner; they were sent again to another one, and the unreachable miner computed for nothing (docs/06 section 3 quinquies).

## 2. The idea

A miner already keeps **one outgoing connection to the seed** (the seed is pinned in `network.json`). The relay uses that connection in
the other direction:

```
client / gateway                 seed (node --relay)                 worker (behind a router)
      |  RelayRequest{job, GetL2Chunk} |                                    |
      |------------------------------->|  RelayForward{id, GetL2Chunk}      |
      |                                |----------------------------------->|  answers like a direct client
      |                                |  RelayReply{id, L2ChunkData}       |
      |  RelayResponse{L2ChunkData}    |<-----------------------------------|
      |<-------------------------------|                                    |
```

The seed is **only a pipe**. The client still opens every chunk against the on-chain root and recomputes it, exactly as with a direct
connection, so a seed that lies, drops or alters a reply can make an audit fail but can never make a wrong result pass.

## 3. Messages (appended at the end of `Msg`, no consensus change)

| message | direction | content |
|---|---|---|
| `RelayAnnounce { account, sig }` | worker -> seed | `sig` = Ed25519 signature, by the worker's account key, of `BLAKE3("vearl/relay/v1", genesis, Noise key of this connection)` |
| `RelayRequest { to, req }` | client -> seed | `to` = `Account(pubkey)` or `L2Job(job id)` (the seed looks the worker up on the chain); `req` = an encoded request |
| `RelayForward { id, req }` | seed -> worker | the same request, on the worker's own connection |
| `RelayReply { id, resp }` | worker -> seed | the encoded reply |
| `RelayResponse { resp }` | seed -> client | the encoded reply |

Nothing in blocks, transactions, headers or the genesis changes: the genesis hash stays `a5771be7...` (vearl-testnet-1), a node of an older release keeps
working on the chain. Only the audit path gains a new route.

## 4. Rules and limits

- **Only small read requests travel** (`relay_allowed` in `net.rs`): `GetL2`, `GetL2Chunk`, `GetJob`, `GetMlp`, `GetProg`, `GetTiled`,
  `GetServed`, `GetRep`, `GetStatus`. Anything that writes (`Put*`, `NewTx`), relays again, or answers with a matrix (`GetOp`, `GetOpsBox`,
  `GetResult`, `GetLayer`, the tiled getters) is refused, by the seed and again by the worker. A reply larger than 2 MiB is not handed over.
- **A route cannot be stolen or forged.** The signature covers the Noise key of the connection: it is useless on any other connection, and
  nobody else can sign for the account. A bad announcement costs the peer 20 penalty points (ban at 100). One account per connection.
- **Opt-in on the seed.** A node ignores announcements and refuses requests unless started with `--relay`. On the server:
  `VEARL_EXTRA_ARGS=--collect-fee-beacons --relay` in `/etc/vearl/node.env`, then `systemctl restart vearl-node vearl-faucet vearl-gateway`.
- **Bounded.** Requests of at most 64 KiB; 1,024 routes; 128 requests in flight overall and 64 per worker; a pending request dies after 60 s;
  a worker answers at most 64 relayed requests at a time (the others get "worker busy"). Relayed messages have their own rate bucket
  (1,000 per second, burst 2,000) so that an audit of thousands of chunks does not hit the 100 per second limit of ordinary messages.
- **Only pinned seeds get the announcement.** A worker announces itself only to the peers it dialed with a pinned key (`HOST:PORT@KEY`, the
  seeds of `network.json`): an older node would not understand the message and would drop the connection.
- **Cost.** Every relayed byte goes through the seed. A chunk is small, but a very large render (tens of thousands of chunks) makes the seed
  carry the whole image once. Direct connections stay preferred: the gateway tries the relay first only because it answers at once when
  there is no route.
- **When the worker disconnects**, its routes disappear and the clients waiting on it get "worker disconnected" immediately.

## 4 bis. AI jobs through the relay (rc25)

The AI jobs of the testnet (`vearl-cli infer`, the clients of ResNet-20, MiniLM, BGE-base, gpt, vit, Qwen3) talk to the worker, not only the chain:
the client asks which model blocks the worker holds, puts the input of the job, and, once the worker has published its operations, fetches them
to verify every one before paying. For a miner at home this needs the relay too, so a few more requests travel, all of them **bulk** (`relay_is_bulk`):

| request | what | limit |
|---|---|---|
| `HasModel` | which weight blocks the worker already holds (a miner installs the packs in advance, `node --models-dir`) | small |
| `PutProgRef` | the input of one job (n x n int8, 1 MiB) and the roots of its weights | request up to 1.1 MiB |
| `PutModel` | **at most 2 blocks** that a pack does not hold (for MiniLM and BGE the mean vector of a text depends on its length) | request up to 2.1 MiB |
| `GetOpsBox`, `GetOp` | the outputs of operations, as bounding boxes | reply up to 9 MiB |

What still does not travel: the weights of a model (more than 2 blocks in a `PutModel`), `PutProg`/`PutProgMore`, `NewTx`, every other matrix.
A relay node lets at most **16 bulk requests** through at the same time and **4 per worker** (`relay busy` otherwise; `vearl-cli` waits and asks again, and
verifies 2 jobs and fetches 2 groups of operations at a time when the worker is behind a relay instead of 4 and 4). The worker applies the same rules
and keeps the input it received like one put directly.

**Compatibility.** No consensus change, no genesis change. A worker of an older release answers `request not relayable` to these requests, so a client
that asks it through a relay simply does not get the model it wants and takes another worker; only workers of rc25 or later can be given an AI job
through a relay. The seed must run rc25 as well.

**What it costs (measured on a local network, resnet / minilm / bge files regenerated on 2026-10-24; every output identical to the independent engine).**
The client verifies every operation, so it fetches every operation: that is the bandwidth of the worker as much as of the seed.

| model | one job | to the worker | back from the worker |
|---|---|---|---|
| ResNet-20 (one photo) | 76 operations | 1 MiB | **3.6 MB** |
| MiniLM-L6 (one text) | 195 operations | 1-2 MiB | **about 180 MB** |
| BGE-base (one text) | 3 chained jobs, 492 operations | 1-2 MiB x 3 | **about 800 MB** |

A miner at home with 30 Mbit/s of upload needs about a minute per MiniLM text and about four minutes per BGE text only to send the operations. This is
not a relay limit (a direct connection carries the same bytes); it comes from verifying everything. See the options in the roadmap of the project.

## 5. Using it

- Address syntax everywhere a worker address is accepted by `vearl-cli` (`l2-who`, `l2-finish`, ...):
  `relay://SEED:9000/l2:<job id hex>` (the seed finds the worker of that level 2 job) or `relay://SEED:9000/acct:<account hex>`.
- The public gateway (`--public`) adds `relay://<--node>/l2:<chain id>` as the first candidate of `l2-who`. If the node is not a relay, or
  the worker is not connected, the answer is a refusal and `l2-who` goes on with the direct candidates (the project's worker and the
  reachable peers of the seed).
- Miners need no setting: a worker (`vearl-miner`, `node --worker`) announces itself on its own once it is connected to the pinned seed.

## 5 bis. Rollout order (important)

1. **Upgrade the seed first** (`node` of rc14 in `/opt/vearl/bin`, then `--relay` in `/etc/vearl/node.env`, restart `vearl-node` and the units that
   require it). An old seed does not understand `RelayAnnounce` and drops the connection, so an rc14 miner that dials an old seed would
   reconnect over and over without syncing.
2. Then publish rc14 to the miners. Older miners (rc13 and before) keep working with the new seed: it only sends relay messages to workers
   that announced themselves. Their jobs simply stay unreachable behind a router, as before.
3. Check on the seed: `journalctl -u vearl-node | grep "\[relay\]"` shows each worker that announced itself ("reachable through peer N").

## 6. What it does not do

- It serves the **audit reads** (level 2 jobs). The gateway's other lanes, and clients that write to a worker (`Put*`: deposit of matrices
  or weights), still need a direct connection to the worker.
- A seed that is down, or that does not run `--relay`, means no relay: the system falls back to the previous behaviour (direct candidates,
  then the job is sent again).
- The seed sees the audited chunks in clear text between the Noise hops (each hop is encrypted, the relay is not end-to-end). The chunks are
  public job outputs, so nothing secret passes, but a hostile seed could withhold them. The seed is the project's own server.
- Several relay nodes are not coordinated: a worker connected to two relay seeds is announced to both.

## 7. Tests

`tests/relay.rs`: a worker that only dials out is audited through the seed by job and by account (every chunk opens against the root and
matches the kernel); a connection kept open for several requests; eight clients at once; refusals (write request, nested relay, unknown
worker, job without worker, node that is not a relay); a forged and a replayed announcement create no route and steal none; the route
disappears when the worker leaves; the address syntax.
