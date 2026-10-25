#!/usr/bin/env python3
"""Checks of audit_pools.relax_target_ramp: python3 tools/test_audit_relax.py"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_pools as ap  # noqa: E402

DAY = 20749


def write(d, name, obj):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return p


def report(findings, epochs=("497991", "497992")):
    verdict = max((x["severity"] for x in findings), key=lambda s: {"ok": 0, "suspect": 1, "fraud": 2}[s], default="ok")
    sev = {e: "ok" for e in epochs}
    for x in findings:
        for e in (epochs if x["epoch"] is None else [str(x["epoch"])]):
            if {"ok": 0, "suspect": 1, "fraud": 2}[x["severity"]] > {"ok": 0, "suspect": 1, "fraud": 2}[sev[e]]:
                sev[e] = x["severity"]
    return {"proto": "vpool-audit/1", "pool": "vrl1x", "verdict": verdict, "epochs": sev, "stats": {}, "findings": findings}


HIGH = {"epoch": None, "severity": "suspect", "code": "work_vs_blocks", "detail": f"day {DAY}: the ledger claims work worth 1738.5 blocks but the pool found 54 (p = 0.00e0): claimed work too high"}
HIDES = {"epoch": None, "severity": "suspect", "code": "work_vs_blocks", "detail": f"day {DAY}: the pool found 900 blocks for work worth 100.0 (p = 1.0e-30): the ledger hides work"}


def blocks_file(d, targets):
    return write(d, "blocks.json", {"blocks": [{"height": i, "timestamp": DAY * 86400 + i, "miner": "m", "work": "native", **({"target": t} if t is not None else {})} for i, t in enumerate(targets)]})


class Relax(unittest.TestCase):
    def run_it(self, findings, targets, **kw):
        with tempfile.TemporaryDirectory() as d:
            rp = write(d, "r.json", report(findings))
            bp = blocks_file(d, targets)
            days = ap.relax_target_ramp(rp, bp, **kw)
            return days, json.load(open(rp))

    def test_a_target_that_moved_a_hundred_fold_relaxes_the_test(self):
        days, r = self.run_it([HIGH], [6_000_000_000, 3_000_000_000, 300_000_000, 60_000_000])
        self.assertEqual(days, [DAY])
        self.assertEqual(r["verdict"], "ok")
        self.assertEqual(set(r["epochs"].values()), {"ok"})
        self.assertEqual(r["findings"][0]["code"], "work_vs_blocks_target_ramp")
        self.assertIn("x100", r["findings"][0]["detail"])

    def test_a_steady_target_keeps_the_finding(self):
        days, r = self.run_it([HIGH], [100, 110, 90, 105])
        self.assertEqual(days, [])
        self.assertEqual(r["verdict"], "suspect")
        self.assertEqual(r["findings"][0]["code"], "work_vs_blocks")

    def test_hidden_work_is_never_relaxed(self):
        days, r = self.run_it([HIDES], [6_000_000_000, 60_000_000])
        self.assertEqual(days, [])
        self.assertEqual(r["verdict"], "suspect")

    def test_blocks_without_a_target_relax_nothing(self):
        days, r = self.run_it([HIGH], [6_000_000_000, None])
        self.assertEqual(days, [])
        self.assertEqual(r["verdict"], "suspect")

    def test_other_findings_stand(self):
        fraud = {"epoch": 497992, "severity": "fraud", "code": "receipt_contradiction", "detail": "x"}
        days, r = self.run_it([HIGH, fraud], [6_000_000_000, 60_000_000])
        self.assertEqual(days, [DAY])
        self.assertEqual(r["verdict"], "fraud")
        self.assertEqual(r["epochs"], {"497991": "ok", "497992": "fraud"})
        other = {"epoch": None, "severity": "suspect", "code": "unknown_parent", "detail": "y"}
        days, r = self.run_it([HIGH, other], [6_000_000_000, 60_000_000])
        self.assertEqual(r["verdict"], "suspect")
        self.assertEqual(set(r["epochs"].values()), {"suspect"})

    def test_a_missing_or_broken_file_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(ap.relax_target_ramp(os.path.join(d, "none.json"), os.path.join(d, "none2.json")), [])


if __name__ == "__main__":
    unittest.main()
