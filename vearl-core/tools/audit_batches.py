"""Bound share recomputation per process without splitting whole-history audit checks."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def _recompute(report):
    severity = {"ok": 0, "info": 0, "suspect": 1, "fraud": 2}
    epochs = {e: "ok" for e in report["epochs"]}
    worst = 0
    for finding in report["findings"]:
        level = severity[finding["severity"]]
        worst = max(worst, level)
        targets = list(epochs) if finding["epoch"] is None else [str(finding["epoch"])]
        for epoch in targets:
            if level > severity[epochs.get(epoch, "ok")]:
                epochs[epoch] = {0: "ok", 1: "suspect", 2: "fraud"}[level]
    report["epochs"] = epochs
    report["verdict"] = {0: "ok", 1: "suspect", 2: "fraud"}[worst]


def run_batched(cmd, bundle, report_path, pool, batch_size=16, runner=None):
    """Snapshot once; keep all documents/receipts/chain in every invocation.

    Only share/proof files are partitioned. Split a budget-exhausted batch again,
    down to one epoch. Never waive an exhausted single epoch or a failed process.
    Requires the audit binary's unknown_parent_shares counter for exact aggregation.
    """
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    runner = runner or subprocess.run
    report_path = Path(report_path)
    evidence = []
    try:
        with tempfile.TemporaryDirectory(prefix="vearl-audit-") as tmp:
            root = Path(tmp)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            common, samples = [], {}
            for source in sorted(Path(bundle).iterdir()):
                match = re.fullmatch(r"(epoch|shares|proofs)-(\d+)\.json", source.name)
                if not match and source.name != "seen.json":
                    continue
                target = snapshot / source.name
                shutil.copyfile(source, target)
                if match and match[1] != "epoch":
                    samples.setdefault(int(match[2]), []).append(target)
                else:
                    common.append(target)
            # Freeze chain, genesis and receipts too; no mixed snapshots between batches.
            base_cmd = list(cmd)
            for index, value in enumerate(base_cmd[:-1]):
                if value in ("--blocks", "--genesis", "--receipts"):
                    frozen = root / ("input-" + str(index))
                    shutil.copyfile(base_cmd[index + 1], frozen)
                    base_cmd[index + 1] = str(frozen)
            if "--now" not in base_cmd:
                base_cmd += ["--now", str(int(time.time()))]
            reports, covered = [], []
            serial = 0

            def run(epochs):
                nonlocal serial
                serial += 1
                work = root / str(serial)
                work.mkdir()
                for source in common + [f for e in epochs for f in samples[e]]:
                    os.link(source, work / source.name)
                output = root / (str(serial) + ".json")
                args = list(base_cmd)
                args[args.index("--bundle") + 1] = str(work)
                args[args.index("--out") + 1] = str(output)
                result = runner(args, capture_output=True, text=True)
                if result.returncode not in (0, 1, 2):
                    raise ValueError("audit process failed: " + result.stderr[-300:])
                report = json.loads(output.read_text(encoding="utf-8"))
                if report["proto"] != "vpool-audit/1" or report["pool"] != pool:
                    raise ValueError("audit report identity mismatch")
                if {"ok": 0, "suspect": 1, "fraud": 2}[report["verdict"]] != result.returncode:
                    raise ValueError("audit exit status does not match verdict")
                evidence.append(report)
                if any(f["code"] == "audit_budget" for f in report["findings"]) and len(epochs) > 1:
                    mid = len(epochs) // 2
                    run(epochs[:mid])
                    run(epochs[mid:])
                    return
                for key in ("shares_recomputed", "unknown_parent_shares"):
                    if type(report["stats"].get(key)) is not int or report["stats"][key] < 0:
                        raise ValueError("audit binary missing batch counters; update vearl-pool-audit")
                reports.append(report)
                covered.extend(epochs)

            epochs = sorted(samples)
            for offset in range(0, len(epochs), batch_size):
                run(epochs[offset:offset + batch_size])
            if not epochs:
                run([])
            if sorted(covered) != epochs:
                raise ValueError("incomplete or overlapping share coverage")
            merged = reports[0]
            findings = {}
            for report in reports:
                if set(report["epochs"]) != set(merged["epochs"]):
                    raise ValueError("batch epoch coverage mismatch")
                for finding in report["findings"]:
                    # Missing samples in a different batch are deliberate; genuine gaps remain.
                    if finding["code"] == "not_sampled" and finding["epoch"] in samples:
                        continue
                    # Re-evaluate this statistical check over all disjoint share subsets.
                    if finding["code"] == "unknown_parent":
                        continue
                    findings[json.dumps(finding, sort_keys=True)] = finding
            verified = sum(r["stats"]["shares_recomputed"] for r in reports)
            unknown = sum(r["stats"]["unknown_parent_shares"] for r in reports)
            if verified >= 10 and unknown * 4 > verified:
                findings["unknown_parent"] = {"epoch": None, "severity": "suspect", "code": "unknown_parent",
                    "detail": f"{unknown} of {verified} checked shares were found on a parent block that is not on the chain"}
            merged["findings"] = list(findings.values())
            merged["stats"].update(shares_recomputed=verified, unknown_parent_shares=unknown,
                share_batches=len(reports), share_epochs_checked=len(epochs))
            _recompute(merged)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Failure must not erase fraud already established by a completed invocation.
        fraud = [f for r in evidence for f in r.get("findings", []) if f.get("severity") == "fraud"]
        merged = {"proto": "vpool-audit/1", "pool": pool, "verdict": "suspect", "epochs": {}, "stats": {},
            "findings": [{"epoch": None, "severity": "suspect", "code": "audit_failed", "detail": str(error)}] + fraud}
        _recompute(merged)
    temporary = report_path.with_name(report_path.name + ".tmp")
    temporary.write_text(json.dumps(merged, indent=1), encoding="utf-8")
    os.replace(temporary, report_path)
    return merged
