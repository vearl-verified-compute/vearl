#!/usr/bin/env python3
"""Audits the registered mining pools of the testnet rewards program (docs/16 section 13, docs/19 section 3 bis).

    python3 tools/audit_pools.py --spec pools.json --genesis genesis.json --blocks blocks.json --audit-bin /opt/vearl/bin/vearl-pool-audit

pools.json: {"pools": [{"address": "vrl1...", "name": "...", "url": "https://pool.example.org", "dir": "pool-example", "audit": "pool-example-audit.json"}]}
(paths relative to the file). For each pool with a `url` it downloads the signed documents and draws random shares (`fetch_pool_bundle.py`), runs
`vearl-pool-audit` against the chain blocks (`blocks.json` of the rewards run) and writes the report to `audit`; `testnet_rewards.py --pools`
reads the documents from `dir` and the report. A pool that cannot be reached keeps its previous documents and report. Exit status 0 even when a
pool is found fraudulent (that is a result, not an error). Standard library only.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
from audit_batches import run_batched

SEVERITY = {"ok": 0, "info": 0, "suspect": 1, "fraud": 2}
# the work-versus-blocks test (a Poisson test) assumes that the difficulty of the blocks is about the same all day long. When the chain's target moves by
# more than this factor during the day (the first minutes of a network whose initial difficulty was far from its real hashrate), the share of the work
# that finds a block that is already stale is no longer negligible, and "work claimed too high" is what an honest pool shows.
TARGET_RAMP = 4.0
# The same test also counts, as the work of a pool, the shares of jobs that were already stale when the share arrived (a pool credits a share for a few
# seconds after the parent block changed) and the blocks that lost the race at their height: with 10-second blocks the work claimed is then a bit more than
# the blocks that end up on the chain. Measured on 2026-10-24 on the two largest pools of the testnet (two different pool programs, 48 % of the
# blocks each): the ledgers claim 1.23-1.24 times the blocks found, while the small pools show 1.0. Up to this fraction of the claimed work may be lost.
STALE_ALLOWANCE = 0.30
# p below which the Poisson test calls a pool suspect (the audit program's own default, `AuditCfg::p_suspect`)
P_SUSPECT = 1e-9


def _poisson_cdf(k, mu):
    """P(X <= k) for X ~ Poisson(mu), by summing the terms in log space (mu up to a few thousand)."""
    import math
    if mu <= 0:
        return 1.0
    top = max(k, 0)
    logs = [-mu + i * math.log(mu) - math.lgamma(i + 1) for i in range(max(0, top - 4000), top + 1)]
    m = max(logs)
    return min(1.0, math.exp(m) * sum(math.exp(x - m) for x in logs))


def _recompute(rep_):
    """The status of every epoch and the verdict, from the findings (after some of them were turned into information)."""
    findings = rep_["findings"]
    epochs = {e: "ok" for e in rep_.get("epochs", {})}
    for fnd in findings:
        sev = fnd.get("severity", "ok")
        targets_ = list(epochs) if fnd.get("epoch") is None else [str(fnd["epoch"])]
        for e in targets_:
            if SEVERITY.get(sev, 2) > SEVERITY.get(epochs.get(e, "ok"), 0):
                epochs[e] = sev
    rep_["epochs"] = epochs
    worst = max((SEVERITY.get(x.get("severity", "ok"), 2) for x in findings), default=0)
    rep_["verdict"] = {0: "ok", 1: "suspect", 2: "fraud"}[worst] if worst < 3 else "fraud"


def relax_stale_loss(report_path, allowance=STALE_ALLOWANCE, p_suspect=P_SUSPECT):
    """Turns a `work_vs_blocks` finding of the kind "claimed work too high" into information when the blocks found are still plausible if up to
    `allowance` of the claimed work was lost to stale jobs and lost races (see STALE_ALLOWANCE): the Poisson test is run again with the expected
    number of blocks lowered by that fraction. A pool that claims much more than that stays suspect, and so does every other finding (also the
    opposite one, "the ledger hides work"). Returns the days relaxed."""
    import re
    try:
        with open(report_path, encoding="utf-8") as f:
            rep_ = json.load(f)
    except (OSError, ValueError):
        return []
    relaxed = []
    for fnd in rep_.get("findings", []):
        if fnd.get("code") != "work_vs_blocks" or fnd.get("severity") != "suspect" or "claimed work too high" not in fnd.get("detail", ""):
            continue
        m = re.match(r"day (\d+): the ledger claims work worth ([0-9.]+) blocks but the pool found (\d+) ", fnd.get("detail", ""))
        if not m:
            continue
        day, mu, k = int(m.group(1)), float(m.group(2)), int(m.group(3))
        if _poisson_cdf(k, mu * (1.0 - allowance)) >= p_suspect:
            fnd["detail"] += f" [tolerated: {100 * allowance:.0f} % of the claimed work may have been lost to stale jobs and lost races; the blocks found are what the other {100 * (1 - allowance):.0f} % predicts; the other checks stand]"
            fnd["severity"] = "ok"
            fnd["code"] = "work_vs_blocks_stale_loss"
            relaxed.append(day)
    if relaxed:
        _recompute(rep_)
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep_, f, indent=1)
    return relaxed


def relax_target_ramp(report_path, blocks_path, ratio=TARGET_RAMP):
    """Turns a `work_vs_blocks` finding of the kind "claimed work too high" into information when the target of the CHAIN (read from the blocks of the
    rewards run, never from the pool's own document) changed by more than `ratio` during that day. Every other finding stays as the audit program wrote it.
    The verdict and the status of every epoch are recomputed from the findings. Returns the list of the days relaxed. Fails closed: no target in the blocks
    (an older blocks.json), no relaxation."""
    try:
        with open(report_path, encoding="utf-8") as f:
            rep_ = json.load(f)
        with open(blocks_path, encoding="utf-8") as f:
            blocks = json.load(f)["blocks"]
    except (OSError, ValueError, KeyError):
        return []
    targets = {}
    for b in blocks:
        t = b.get("target")
        if t is None:
            return []
        try:
            targets.setdefault(int(b["timestamp"]) // 86400, []).append(int(t))
        except (TypeError, ValueError):
            return []
    relaxed = []
    for fnd in rep_.get("findings", []):
        if fnd.get("code") != "work_vs_blocks" or fnd.get("severity") != "suspect" or "claimed work too high" not in fnd.get("detail", ""):
            continue
        m = re.match(r"day (\d+):", fnd.get("detail", ""))
        ts = targets.get(int(m.group(1))) if m else None
        if not ts or len(ts) < 2 or min(ts) <= 0:
            continue
        spread = max(ts) / min(ts)
        if spread > ratio:
            fnd["detail"] += f" [not applicable: the target of the chain moved by x{spread:.0f} during that day, the blocks found at that pace were lost as stale; the other checks stand]"
            fnd["severity"] = "ok"
            fnd["code"] = "work_vs_blocks_target_ramp"
            relaxed.append(int(m.group(1)))
    if relaxed:
        findings = rep_["findings"]
        epochs = {e: "ok" for e in rep_.get("epochs", {})}
        for fnd in findings:
            sev = fnd.get("severity", "ok")
            targets_ = list(epochs) if fnd.get("epoch") is None else [str(fnd["epoch"])]
            for e in targets_:
                if SEVERITY.get(sev, 2) > SEVERITY.get(epochs.get(e, "ok"), 0):
                    epochs[e] = sev
        rep_["epochs"] = epochs
        worst = max((SEVERITY.get(x.get("severity", "ok"), 2) for x in findings), default=0)
        rep_["verdict"] = {0: "ok", 1: "suspect", 2: "fraud"}[worst] if worst < 3 else "fraud"
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep_, f, indent=1)
    return relaxed


DEFAULT_WAIVERS = "/etc/vearl/rewards-waivers.json"


def apply_waivers(report_path, waivers_path, pool_address):
    """Turns SUSPECT findings that the project decided to accept into information, and recomputes the verdict and the status of every hour.

    waivers_path: {"waivers": [{"pool": "vrl1...", "code": "late_document", "epoch": 498013, "reason": "...", "date": "2026-10-26"}, ...]}
    A waiver names the pool, the code of the finding and the hour (epoch): nothing broader. A `fraud` finding can never be waived, and a file that cannot
    be read or understood waives nothing (the audit stays as it was written). The finding keeps its text, with the reason and the date added, and its
    code becomes `waived_<code>`, so that the public report shows what was accepted and why. Returns the list of (code, epoch) that were waived."""
    try:
        with open(waivers_path, encoding="utf-8") as f:
            wl = json.load(f)["waivers"]
        with open(report_path, encoding="utf-8") as f:
            rep_ = json.load(f)
        mine = {(w["code"], int(w["epoch"])): w for w in wl if isinstance(w, dict) and w.get("pool") == pool_address and w.get("reason")}
    except (OSError, ValueError, KeyError, TypeError):
        return []
    done = []
    for fnd in rep_.get("findings", []):
        if fnd.get("severity") != "suspect" or fnd.get("epoch") is None:
            continue
        w = mine.get((fnd.get("code"), int(fnd["epoch"])))
        if not w:
            continue
        fnd["detail"] = f"{fnd.get('detail', '')} [waived by the project{(' on ' + w['date']) if w.get('date') else ''}: {w['reason']}]"
        fnd["code"] = "waived_" + fnd["code"]
        fnd["severity"] = "ok"
        done.append((fnd["code"][len("waived_"):], int(fnd["epoch"])))
    if done:
        _recompute(rep_)
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep_, f, indent=1)
    return done


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--genesis", required=True)
    ap.add_argument("--blocks", required=True)
    ap.add_argument("--audit-bin", required=True)
    ap.add_argument("--samples", default="16")
    ap.add_argument("--full", action="store_true", help="also download and verify the complete share lists")
    ap.add_argument("--last", default="0", help="only the last N epochs of each pool")
    ap.add_argument("--max-epochs", default="400", help="most epochs read from a pool in one run")
    ap.add_argument("--audit-arg", action="append", default=[], help="extra argument for vearl-pool-audit (repeat), e.g. --audit-arg=--verify-max --audit-arg=500")
    ap.add_argument("--receipts-dir", help="folder of pool-receipts*.jsonl files kept by miners (more evidence for the audit)")
    ap.add_argument("--waivers", default=DEFAULT_WAIVERS, help="optional file of findings that the project accepts (hour by hour, never a fraud), see apply_waivers")
    ap.add_argument("--batch-epochs", type=int, default=16, help="share epochs recomputed per process; budget-exhausted batches are split again")
    a = ap.parse_args()
    if a.batch_epochs < 1:
        ap.error("--batch-epochs must be positive")
    base = os.path.dirname(os.path.abspath(a.spec))
    here = os.path.dirname(os.path.abspath(__file__))
    with open(a.spec, encoding="utf-8") as f:
        pools = json.load(f)["pools"]
    for p in pools:
        if not p.get("url"):
            continue
        bundle = os.path.join(base, p["dir"])
        report = os.path.join(base, p.get("audit") or p["dir"] + "-audit.json")
        fetch = [sys.executable, os.path.join(here, "fetch_pool_bundle.py"), "--pool", p["url"], "--out", bundle, "--samples", a.samples, "--last", a.last if a.last != "0" else a.max_epochs]
        if a.full:
            fetch.append("--full")
        r = subprocess.run(fetch, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"{p.get('name', p['address'])}: cannot read the pool ({r.stderr.strip().splitlines()[-1] if r.stderr.strip() else 'error'}); documents and report left as they are")
            continue
        cmd = [a.audit_bin, "--bundle", bundle, "--genesis", a.genesis, "--pool", p["address"], "--blocks", a.blocks, "--out", report] + a.audit_arg
        if a.receipts_dir:
            for rf in sorted(glob.glob(os.path.join(a.receipts_dir, "*.jsonl"))):
                cmd += ["--receipts", rf]
        merged = run_batched(cmd, bundle, report, p["address"], a.batch_epochs)
        print(f"{p.get('name', p['address'])}: {merged['verdict']}")
        days = relax_target_ramp(report, a.blocks)
        if days:
            print(f"{p.get('name', p['address'])}: work-versus-blocks test not applicable on day(s) {days} (the chain's target moved by more than x{TARGET_RAMP:.0f}); verdict recomputed")
        waived = apply_waivers(report, a.waivers, p["address"])
        if waived:
            print(f"{p.get('name', p['address'])}: {len(waived)} finding(s) accepted by the project (waivers): {waived}; verdict recomputed")
        days = relax_stale_loss(report)
        if days:
            print(f"{p.get('name', p['address'])}: work-versus-blocks test on day(s) {days}: the claimed work is plausible once {100 * STALE_ALLOWANCE:.0f} % of it is allowed to be lost to stale jobs; verdict recomputed")


if __name__ == "__main__":
    sys.exit(main())
