"""Batch orchestration regressions: no network, wallet, or expensive matrices."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from audit_batches import run_batched


class Batches(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        for e in range(4):
            for kind in ("epoch", "proofs"):
                (self.bundle / f"{kind}-{e}.json").write_text("{}")
        (self.bundle / "seen.json").write_text("{}")
        self.out = self.root / "report.json"
        self.cmd = ["fake-audit", "--bundle", str(self.bundle), "--out", str(self.out)]
        self.calls = []
        self.fail = None
        self.budget = 2
        self.fraud = False
        self.global_fault = False
        self.unknown = 0

    def runner(self, args, **kwargs):
        b = Path(args[args.index("--bundle") + 1])
        epochs = sorted(int(f.stem.split("-")[1]) for f in b.glob("proofs-*.json"))
        self.calls.append(epochs)
        # Every batch must still check the complete signed-document history.
        self.assertEqual(len(list(b.glob("epoch-*.json"))), 4)
        self.assertTrue((b / "seen.json").exists())
        if self.fail is not None and self.fail in epochs:
            return subprocess.CompletedProcess(args, 3, "", "crash")
        findings = [{"epoch": e, "severity": "ok", "code": "not_sampled", "detail": "absent"} for e in range(4) if e not in epochs]
        if len(epochs) > self.budget:
            findings.append({"epoch": None, "severity": "suspect", "code": "audit_budget", "detail": "budget"})
        if self.fraud and 1 in epochs:
            findings.append({"epoch": 1, "severity": "fraud", "code": "share_invalid", "detail": "bad share"})
        if self.global_fault:
            findings.append({"epoch": None, "severity": "fraud", "code": "hidden_block", "detail": "whole-history failure"})
        verdict = "fraud" if any(f["severity"] == "fraud" for f in findings) else "suspect" if len(epochs) > self.budget else "ok"
        r = {"proto": "vpool-audit/1", "pool": "pool", "epochs": {str(e): "ok" for e in range(4)}, "verdict": verdict,
             "findings": findings, "stats": {"documents": 4, "shares_recomputed": 3 * len(epochs), "unknown_parent_shares": self.unknown * len(epochs)}}
        Path(args[args.index("--out") + 1]).write_text(json.dumps(r))
        return subprocess.CompletedProcess(args, {"ok": 0, "suspect": 1, "fraud": 2}[verdict], "", "")

    def run_audit(self, size=4):
        return run_batched(self.cmd, self.bundle, self.out, "pool", size, self.runner)

    def test_budget_exhaustion_is_split_without_losing_coverage(self):
        r = self.run_audit()
        self.assertEqual(self.calls, [[0, 1, 2, 3], [0, 1], [2, 3]])
        self.assertEqual(r["verdict"], "ok")
        self.assertEqual(r["stats"]["shares_recomputed"], 12)
        self.assertEqual(r["stats"]["share_epochs_checked"], 4)
        self.assertEqual(set(r["epochs"].values()), {"ok"})
        self.assertEqual(r["findings"], [])

    def test_fraud_and_whole_history_checks_survive_merge(self):
        self.fraud = self.global_fault = True
        r = self.run_audit()
        self.assertEqual(r["verdict"], "fraud")
        self.assertEqual({f["code"] for f in r["findings"]}, {"share_invalid", "hidden_block"})
        self.assertEqual(set(r["epochs"].values()), {"fraud"})

    def test_single_epoch_budget_is_never_waived(self):
        self.budget = 0
        r = self.run_audit()
        self.assertEqual(r["verdict"], "suspect")
        self.assertIn("audit_budget", [f["code"] for f in r["findings"]])
        self.assertEqual(set(r["epochs"].values()), {"suspect"})

    def test_crash_replaces_previous_favourable_report(self):
        self.out.write_text('{"verdict":"ok"}')
        self.fail = 3
        r = self.run_audit(2)
        self.assertEqual(r["verdict"], "suspect")
        self.assertEqual(r["findings"][0]["code"], "audit_failed")
        self.assertEqual(json.loads(self.out.read_text()), r)

    def test_later_crash_never_erases_proven_fraud(self):
        self.fraud = True
        self.fail = 3
        r = self.run_audit(2)
        self.assertEqual(r["verdict"], "fraud")
        self.assertIn("share_invalid", [f["code"] for f in r["findings"]])
        self.assertIn("audit_failed", [f["code"] for f in r["findings"]])

    def test_unknown_parent_threshold_is_rechecked_across_small_batches(self):
        self.unknown = 1
        r = self.run_audit(1)
        self.assertEqual(r["stats"]["shares_recomputed"], 12)
        self.assertEqual(r["verdict"], "suspect")
        self.assertIn("unknown_parent", [f["code"] for f in r["findings"]])

    def test_frozen_inputs_survive_changes_to_original(self):
        chain = self.root / "blocks.json"
        chain.write_text("old chain")
        self.cmd += ["--blocks", str(chain)]
        original = self.runner
        def mutate(args, **kwargs):
            chain.write_text("new chain")
            self.assertEqual(Path(args[args.index("--blocks") + 1]).read_text(), "old chain")
            return original(args, **kwargs)
        r = run_batched(self.cmd, self.bundle, self.out, "pool", 2, mutate)
        self.assertEqual(r["verdict"], "ok")

    def test_missing_batch_counters_fail_closed(self):
        original = self.runner
        def old_binary(args, **kwargs):
            result = original(args, **kwargs)
            path = Path(args[args.index("--out") + 1])
            r = json.loads(path.read_text())
            del r["stats"]["unknown_parent_shares"]
            path.write_text(json.dumps(r))
            return result
        r = run_batched(self.cmd, self.bundle, self.out, "pool", 2, old_binary)
        self.assertEqual(r["verdict"], "suspect")
        self.assertIn("update vearl-pool-audit", r["findings"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
