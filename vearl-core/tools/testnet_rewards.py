#!/usr/bin/env python3
"""Testnet rewards: scores the contributors of the public testnet from the blocks of the chain (rules: docs/19-testnet-rewards.md).

    python3 tools/testnet_rewards.py --node HOST:PORT --start 2026-10-23T16:00:00Z --out rewards-out [--dump-blocks]
    python3 tools/testnet_rewards.py --blocks-file rewards-out/blocks.json --start 2026-10-23T16:00:00Z --out rewards-check

--node reads every block through the public API of a node (/api/blocks) and, with --dump-blocks, saves them in OUT/blocks.json together
with their SHA-256: anybody can publish or download such a file and re-run the computation with --blocks-file to get exactly the same
result. Nothing else than the blocks is used, so the score of a miner cannot be inflated off-chain.

Score: 1 point per valid block mined to the address, 1.5 for a block that carried paid work (a job of a client), multiplied by 1.25 during
the first three days. The 1.5 is not paid for a job the miner submitted itself (client = miner), for more than 20 blocks of one job, nor twice for
the same operation, layer or product of a job (a job that nobody else wants cannot be farmed). The blocks of a registered mining pool (--pools) are shared between the pool's miners in proportion to their verified work
(tools/pool_points.py). Eligibility: at least 3 distinct active days (24-hour windows since the start), a minimum share of all the points,
a registered address if a registration list is given, and not on the exclusion list. The reward pool is shared between the eligible
addresses in proportion to their points. All parameters are printed in the output and can be changed with the options below.
Python 3 standard library only.
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import pool_points  # noqa: E402  (needs `cryptography` only when --pools is used)
except ImportError:  # an older installation that does not ship the pool tools
    pool_points = None

# Statuses of deploy/feeaudit/feeaudit.py that break the rule of the optional Quantus add-on (the development fee, docs/17 and docs/19).
FEE_NONCOMPLIANT = {"no_fee", "low", "wrong_fee_pct", "wrong_fee_dest", "low_declared_split", "unofficial_build"}

DEFAULTS = {
    "epoch_days": 1,          # length of a scoring period, for the leaderboard (the mainnet is expected soon after the start: days, not weeks)
    "early_days": 3,          # the first days get a multiplier (the network is most fragile at the start)
    "early_mult": 1.25,
    "useful_mult": 1.5,       # a block that carried paid work counts more than a block of native work
    "grace_minutes": 0,       # blocks in the first minutes after the start do not count (0: all count). A lever for the team if the launch is found to be gamed (blocks mined in advance)
    "useful_cap_per_job": 20,  # at most this many blocks of one job (class "job") get the paid-work multiplier; the others count 1.0
    "min_active_days": 3,     # distinct 24-hour windows with at least one block
    "min_share": 0.00005,     # of all the points (0.005 %): no dust
    "pool_pct": 0.7,          # informational: percentage of the maximum mainnet supply set aside for THIS testnet, the first of five (docs/19 section 1: 0.7 / 1.05 / 1.4 / 1.75 / 2.1 %)
}


def parse_time(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp())


def fetch_blocks(node, timeout=30):
    """All the blocks of the chain, oldest first: {height, timestamp, miner, work}."""
    def get(path):
        for attempt in range(4):
            try:
                with urllib.request.urlopen(f"http://{node}{path}", timeout=timeout) as r:
                    return json.load(r)
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
    first = get("/api/blocks?limit=1")
    tip = first.get("tip", 0)
    out, start = [], tip - 1
    while start >= 0:
        page = get(f"/api/blocks?from={start}&limit=100").get("blocks", [])
        if not page:
            break
        for b in page:
            w = b["work"]
            blk = {"height": b["height"], "timestamp": b["timestamp"], "miner": b["miner"], "work": w["type"]}
            if b.get("target") is not None:
                blk["target"] = int(b["target"])
            if w.get("job"):
                blk["job"] = w["job"]
                unit = w.get("op", w.get("layer", w.get("block")))
                if unit is not None:
                    blk["unit"] = json.dumps(unit)
            out.append(blk)
        start = min(b["height"] for b in page) - 1
    out.sort(key=lambda b: b["height"])
    # who submitted each job that a block carried: a miner that is its own client is not paid the multiplier (see score)
    clients = {}
    for b in out:
        j = b.get("job")
        if not j:
            continue
        if j not in clients:
            try:
                clients[j] = get(f"/api/job/{j}").get("client")
            except Exception:
                clients[j] = None  # unknown: the per-job limits still apply
        if clients[j]:
            b["client"] = clients[j]
    return out


def data_hash(blocks):
    canon = json.dumps(blocks, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def score(blocks, start_ts, p, registered=None, excluded=(), pools=None, unaudited="hold", fee_status=None):
    """The leaderboard from a list of blocks. `registered`: set of addresses (None = no registration needed).

    `fee_status`: {vearl address: status} from the fee audit (compliance.json): an address that uses the Quantus add-on without paying the development
    fee is not eligible. `pools`: registered mining pools (pool_points.load_pools). The blocks of a pool are not credited to the pool's address: their points are
    shared between its miners according to the pool's signed hourly documents and the audit of those documents (docs/16 section 13)."""
    epoch_secs = p["epoch_days"] * 86400
    miners = {}
    last_ts = start_ts
    epochs = {}
    pools = pools or {}
    pots = {a: {} for a in pools}
    pool_blocks = {a: 0 for a in pools}
    job_blocks, seen_units = {}, set()
    for b in blocks:
        ts = b["timestamp"]
        if ts < start_ts + p["grace_minutes"] * 60:
            continue
        last_ts = max(last_ts, ts)
        ep = (ts - start_ts) // epoch_secs
        useful = b["work"] != "native"
        if useful:
            # paid work that nobody else asked for is not paid work: a miner that is its own client, an endless job mined again and again, the same
            # operation / layer / product mined twice. Such a block is a valid block, it counts 1.0
            job = b.get("job")
            if b.get("client") and b["client"] == b["miner"]:
                useful = False
            elif job and b["work"] == "job":
                job_blocks[job] = job_blocks.get(job, 0) + 1
                useful = job_blocks[job] <= p["useful_cap_per_job"]
            elif job:
                key = (job, b.get("unit"))
                useful = key not in seen_units
                seen_units.add(key)
        pts = (p["useful_mult"] if useful else 1.0) * (p["early_mult"] if ts - start_ts < p["early_days"] * 86400 else 1.0)
        if b["miner"] in pools:
            pots[b["miner"]][ep] = pots[b["miner"]].get(ep, 0.0) + pts
            pool_blocks[b["miner"]] += 1
            epochs[ep] = epochs.get(ep, 0) + 1
            continue
        m = miners.setdefault(b["miner"], {"address": b["miner"], "blocks": 0, "useful_blocks": 0, "points": 0.0, "days": set(), "per_epoch": {}})
        m["blocks"] += 1
        m["useful_blocks"] += 1 if useful else 0
        m["points"] += pts
        m["days"].add((ts - start_ts) // 86400)
        m["per_epoch"][ep] = m["per_epoch"].get(ep, 0.0) + pts
        epochs[ep] = epochs.get(ep, 0) + 1
    pool_report = []
    for a, pool in pools.items():
        if pool_points is None:
            raise SystemExit("pool_points.py is missing: install it next to testnet_rewards.py to use --pools")
        shares, rep_ = pool_points.allocate(pool, pots[a], start_ts, epoch_secs, unaudited)
        for addr, r in shares.items():
            m = miners.setdefault(addr, {"address": addr, "blocks": 0, "useful_blocks": 0, "points": 0.0, "days": set(), "per_epoch": {}})
            m["points"] += r["points"]
            m["pool_points"] = m.get("pool_points", 0.0) + r["points"]
            m.setdefault("pools", []).append(a)
            m["days"] |= r["days"]
            for ep, v in r["periods"].items():
                m["per_epoch"][ep] = m["per_epoch"].get(ep, 0.0) + v
        pool_report.append({"address": a, "name": pool["name"], "blocks": pool_blocks[a], "audit_verdict": pool["verdict"], "problems": pool["problems"],
                            **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in rep_.items()}})
    total = sum(m["points"] for m in miners.values())
    rows = []
    for m in miners.values():
        share = m["points"] / total if total else 0.0
        reasons = []
        if m["address"] in excluded:
            reasons.append("excluded by the team (see docs/19)")
        if fee_status and fee_status.get(m["address"]) in FEE_NONCOMPLIANT:
            reasons.append(f"uses the Quantus add-on without paying the development fee (audit status: {fee_status[m['address']]}, see docs/17)")
        if registered is not None and m["address"] not in registered:
            reasons.append("address not registered")
        if len(m["days"]) < p["min_active_days"]:
            reasons.append(f"fewer than {p['min_active_days']} active days ({len(m['days'])})")
        if share < p["min_share"]:
            reasons.append(f"share below {p['min_share'] * 100:.3f} %")
        rows.append({"address": m["address"], "blocks": m["blocks"], "useful_blocks": m["useful_blocks"], "pool_points": round(m.get("pool_points", 0.0), 4),
                     "pools": m.get("pools", []), "points": round(m["points"], 4),
                     "share": share, "active_days": len(m["days"]), "eligible": not reasons, "reasons": reasons,
                     "points_per_epoch": {str(k): round(v, 4) for k, v in sorted(m["per_epoch"].items())}})
    rows.sort(key=lambda r: (-r["points"], r["address"]))
    elig_total = sum(r["points"] for r in rows if r["eligible"])
    for i, r in enumerate(rows, 1):
        r["rank"] = i
        r["pool_share"] = (r["points"] / elig_total) if r["eligible"] and elig_total else 0.0
    return {
        "totals": {"blocks": sum(r["blocks"] for r in rows), "pool_blocks": sum(pool_blocks.values()),
                   "chain_blocks": sum(r["blocks"] for r in rows) + sum(pool_blocks.values()), "miners": len(rows), "eligible": sum(1 for r in rows if r["eligible"]),
                   "points": round(total, 4), "eligible_points": round(elig_total, 4), "last_block_time": last_ts},
        "epochs": [{"index": k, "blocks": v} for k, v in sorted(epochs.items())],
        "pools": pool_report,
        "miners": rows,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--node", help="HOST:PORT of a node API")
    src.add_argument("--blocks-file", help="blocks.json written earlier by --dump-blocks")
    ap.add_argument("--start", required=True, help="start of the testnet, ISO UTC (e.g. 2026-10-23T16:00:00Z)")
    ap.add_argument("--end", help="ignore the blocks after this ISO UTC time (final snapshot)")
    ap.add_argument("--out", required=True, help="output folder")
    ap.add_argument("--dump-blocks", action="store_true", help="save the blocks used in OUT/blocks.json (for reproduction)")
    ap.add_argument("--registered", help="JSON file made by verify_registration.py: only these addresses can be eligible")
    ap.add_argument("--exclude", help="text file, one address per line (disqualified, with a public reason in docs/19)")
    ap.add_argument("--fee-compliance", help="compliance.json of deploy/feeaudit/feeaudit.py: addresses that use the Quantus add-on without the development fee are not eligible")
    ap.add_argument("--pools", help="pools.json: the registered mining pools, their signed documents and audit reports (tools/pool_points.py)")
    ap.add_argument("--pool-unaudited", choices=["hold", "count"], default="hold", help="what to do with the hours of a pool that has no audit report yet (default: hold them)")
    ap.add_argument("--pool-tokens", type=float, help="size of the reward pool in tokens: adds a token amount to every eligible row")
    for k, v in DEFAULTS.items():
        ap.add_argument("--" + k.replace("_", "-"), type=type(v), default=v)
    a = ap.parse_args()
    p = {k: getattr(a, k) for k in DEFAULTS}
    start_ts = parse_time(a.start)
    if a.node:
        blocks = fetch_blocks(a.node)
    else:
        blocks = json.load(open(a.blocks_file))["blocks"]
    if a.end:
        end_ts = parse_time(a.end)
        blocks = [b for b in blocks if b["timestamp"] <= end_ts]
    registered = None
    if a.registered:
        registered = set(json.load(open(a.registered))["addresses"])
    excluded = set()
    if a.exclude:
        excluded = {l.strip() for l in open(a.exclude) if l.strip() and not l.startswith("#")}
    if a.pools and pool_points is None:
        raise SystemExit("--pools needs pool_points.py next to this script")
    pools = pool_points.load_pools(a.pools) if a.pools else None
    fee_status = None
    if a.fee_compliance:
        with open(a.fee_compliance, encoding="utf-8") as f:
            fee_status = json.load(f).get("miners", {})
    result = score(blocks, start_ts, p, registered, excluded, pools, a.pool_unaudited, fee_status)
    if a.pool_tokens:
        for r in result["miners"]:
            r["tokens"] = round(r["pool_share"] * a.pool_tokens, 8)
    result = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "start": a.start, "params": p,
              "data_hash": data_hash([b for b in blocks if b["timestamp"] >= start_ts]),
              **({"pool_data_hash": pool_points.pools_hash(pools)} if pools else {}), **result}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "leaderboard.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1)
    with open(os.path.join(a.out, "leaderboard.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["rank", "address", "blocks", "useful_blocks", "points", "share", "active_days", "eligible", "pool_share", "reasons"])
        for r in result["miners"]:
            w.writerow([r["rank"], r["address"], r["blocks"], r["useful_blocks"], r["points"], f"{r['share']:.6f}", r["active_days"], r["eligible"], f"{r['pool_share']:.6f}", "; ".join(r["reasons"])])
    if a.dump_blocks:
        with open(os.path.join(a.out, "blocks.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"data_hash": result["data_hash"], "blocks": blocks}, f, separators=(",", ":"))
    t = result["totals"]
    print(f"{t['blocks']} blocks, {t['miners']} miners, {t['eligible']} eligible; data hash {result['data_hash'][:16]}...; written to {a.out}")


if __name__ == "__main__":
    sys.exit(main())
