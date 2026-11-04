#!/usr/bin/env python3
"""Checks of audit_pools.apply_waivers (findings that the project accepts, hour by hour): python3 tools/test_audit_waivers.py"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_pools as ap  # noqa: E402

POOL = "vrl1pool"
OTHER = "vrl1other"


def report(findings, epochs=("100", "101", "102")):
    return {"proto": "vpool-audit/1", "pool": POOL, "verdict": "suspect", "epochs": {e: "ok" for e in epochs}, "stats": {}, "findings": findings}


def f(code, epoch, sev="suspect"):
    return {"epoch": epoch, "severity": sev, "code": code, "detail": f"{code} at {epoch}"}


class Waivers(unittest.TestCase):
    def run_case(self, rep, waivers):
        with tempfile.TemporaryDirectory() as d:
            rp, wp = os.path.join(d, "r.json"), os.path.join(d, "w.json")
            json.dump(rep, open(rp, "w"))
            if waivers is not None:
                open(wp, "w").write(waivers if isinstance(waivers, str) else json.dumps(waivers))
            done = ap.apply_waivers(rp, wp, POOL)
            return done, json.load(open(rp))

    def test_an_accepted_finding_becomes_information_and_the_hour_is_ok_again(self):
        rep = report([f("late_document", 100), f("hidden_block", 101), f("block_pending", 102, "ok")])
        ws = {"waivers": [{"pool": POOL, "code": "late_document", "epoch": 100, "reason": "documents first seen after the pool was added", "date": "2026-10-26"}]}
        done, out = self.run_case(rep, ws)
        self.assertEqual(done, [("late_document", 100)])
        self.assertEqual(out["epochs"]["100"], "ok")
        self.assertEqual(out["epochs"]["101"], "suspect", "another finding stays")
        self.assertEqual(out["verdict"], "suspect")
        w = out["findings"][0]
        self.assertEqual((w["code"], w["severity"]), ("waived_late_document", "ok"))
        self.assertIn("waived by the project on 2026-10-26: documents first seen after the pool was added", w["detail"])

    def test_when_every_finding_is_accepted_the_pool_is_ok(self):
        rep = report([f("late_document", 100), f("hidden_block", 101)])
        ws = {"waivers": [{"pool": POOL, "code": "late_document", "epoch": 100, "reason": "r1"}, {"pool": POOL, "code": "hidden_block", "epoch": 101, "reason": "r2"}]}
        done, out = self.run_case(rep, ws)
        self.assertEqual(len(done), 2)
        self.assertEqual(out["verdict"], "ok")
        self.assertEqual(set(out["epochs"].values()), {"ok"})

    def test_a_fraud_can_never_be_waived(self):
        rep = report([f("forged_share", 100, "fraud")])
        rep["verdict"], rep["epochs"]["100"] = "fraud", "fraud"          # as the audit program writes it
        ws = {"waivers": [{"pool": POOL, "code": "forged_share", "epoch": 100, "reason": "x"}]}
        done, out = self.run_case(rep, ws)
        self.assertEqual(done, [])
        self.assertEqual(out["verdict"], "fraud")
        self.assertEqual(out["epochs"]["100"], "fraud")

    def test_a_waiver_is_for_one_pool_one_code_one_hour(self):
        rep = report([f("late_document", 100), f("late_document", 101)])
        ws = {"waivers": [{"pool": OTHER, "code": "late_document", "epoch": 100, "reason": "x"},       # another pool
                          {"pool": POOL, "code": "hidden_block", "epoch": 100, "reason": "x"},          # another code
                          {"pool": POOL, "code": "late_document", "epoch": 999, "reason": "x"}]}        # another hour
        done, out = self.run_case(rep, ws)
        self.assertEqual(done, [])
        self.assertEqual(out["verdict"], "suspect")

    def test_a_waiver_without_a_reason_is_ignored(self):
        rep = report([f("late_document", 100)])
        done, out = self.run_case(rep, {"waivers": [{"pool": POOL, "code": "late_document", "epoch": 100}]})
        self.assertEqual(done, [])
        self.assertEqual(out["verdict"], "suspect")

    def test_a_missing_or_broken_file_waives_nothing(self):
        rep = report([f("late_document", 100)])
        for bad in (None, "not json", "{}", '{"waivers": 5}', '{"waivers": [{"pool": "vrl1pool", "code": "late_document", "epoch": "abc", "reason": "x"}]}'):
            done, out = self.run_case(rep, bad)
            self.assertEqual(done, [], bad)
            self.assertEqual(out["verdict"], "suspect", bad)

    def test_running_it_twice_changes_nothing_more(self):
        rep = report([f("late_document", 100)])
        ws = {"waivers": [{"pool": POOL, "code": "late_document", "epoch": 100, "reason": "r"}]}
        with tempfile.TemporaryDirectory() as d:
            rp, wp = os.path.join(d, "r.json"), os.path.join(d, "w.json")
            json.dump(rep, open(rp, "w"))
            json.dump(ws, open(wp, "w"))
            self.assertEqual(len(ap.apply_waivers(rp, wp, POOL)), 1)
            first = open(rp).read()
            self.assertEqual(ap.apply_waivers(rp, wp, POOL), [], "the finding is information now")
            self.assertEqual(open(rp).read(), first)


if __name__ == "__main__":
    unittest.main()
