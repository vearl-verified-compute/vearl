"""Regression tests without launching the standalone soak's node processes.

Load its function definitions and final verdict expression through the AST:
importing soak itself starts a full devnet. SOAK_TEST_SOURCE permits running
the same regression cases against an unmodified historical script.
"""
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import time
import unittest
from unittest.mock import Mock


SOURCE = Path(os.environ.get("SOAK_TEST_SOURCE", Path(__file__).with_name("soak.py")))
TREE = ast.parse(SOURCE.read_text())


def functions():
    namespace = dict(re=re, subprocess=subprocess, time=time, print=lambda *args: None)
    definitions = [n for n in TREE.body if isinstance(n, ast.FunctionDef)]
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace


def verdict(**values):
    assignments = [n for n in TREE.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id in ("outcomes_ok", "ok") for t in n.targets)]
    exec(compile(ast.Module(body=assignments, type_ignores=[]), str(SOURCE), "exec"), values)
    return values["ok"]


class GenesisStreams(unittest.TestCase):
    def test_json_stdout_is_separate_from_summary(self):
        env = functions()
        env.update(B="unused", subprocess=Mock())
        env["subprocess"].run.return_value = subprocess.CompletedProcess([], 0, '{"network":"soak"}', 'GENESIS HASH: summary\n')
        self.assertEqual(json.loads(env["run"]("vearl-genesis", stdout_only=True)), {"network": "soak"})
        self.assertTrue(env["subprocess"].run.call_args.kwargs["check"])

    def test_other_commands_keep_diagnostics(self):
        env = functions()
        env.update(B="unused", subprocess=Mock())
        env["subprocess"].run.return_value = subprocess.CompletedProcess([], 0, 'output\n', 'diagnostic\n')
        self.assertIn('diagnostic', env["run"]("vearl-cli"))


class FinishResult(unittest.TestCase):
    def test_nonterminal_finish_is_retried(self):
        env = functions()
        env.update(statusline=lambda j: 'status: "Complete"', addrof=lambda worker: worker,
                   CL="seed:4", HUB="A", stats={"finished": 0},
                   run=Mock(side_effect=['final job status: Complete', 'final job status: Slashed']))
        job = dict(kind="mlp", worker="C", seed=1, id="job", done=False)
        env["try_finish"](job)
        self.assertFalse(job["done"])
        self.assertEqual(env["stats"]["finished"], 0)
        env["try_finish"](job)
        self.assertTrue(job["done"])
        self.assertEqual(env["stats"]["finished"], 1)


class Drain(unittest.TestCase):
    def setup_world(self, initial="Working", remembered_done=False):
        env = functions()
        self.now = 0
        self.state = initial
        def sleep(seconds):
            self.now += seconds
        env.update(time=Mock(monotonic=lambda: self.now, sleep=sleep),
                   jobs=[dict(done=remembered_done)], NODES={"A": {}, "B": {}},
                   stats={"errors": 0}, status=lambda node: (1, 'same-tip', 1),
                   statusline=lambda job: f'status: "{self.state}"')
        return env

    def test_convergence_does_not_end_drain_before_late_result(self):
        env = self.setup_world()
        def finish(job):
            self.state = "Complete" if self.state == "Working" else "Settled"
        env["try_finish"] = Mock(side_effect=finish)
        converged, _ = env["drain_jobs"](timeout=10)
        self.assertTrue(converged)
        self.assertEqual(self.state, "Settled")
        self.assertEqual(env["try_finish"].call_count, 2)

    def test_reorganised_done_job_is_processed_again(self):
        env = self.setup_world(initial="Complete", remembered_done=True)
        env["try_finish"] = Mock(side_effect=lambda job: setattr(self, "state", "Slashed"))
        self.assertTrue(env["drain_jobs"](10)[0])
        env["try_finish"].assert_called_once()

    def test_unfinished_job_hits_drain_timeout(self):
        env = self.setup_world()
        env["try_finish"] = Mock()
        self.assertFalse(env["drain_jobs"](timeout=5)[0])
        self.assertGreaterEqual(self.now, 5)

    def test_missing_node_is_not_convergence(self):
        env = self.setup_world(initial="Settled")
        env["status"] = lambda node: None if node == "B" else (1, 'same-tip', 1)
        env["try_finish"] = Mock()
        self.assertFalse(env["drain_jobs"](timeout=5)[0])


class Verdict(unittest.TestCase):
    def valid(self):
        return dict(conv=True, inv={"supply_invariant": True}, crashed=[], stats={"errors": 0},
                    summary={("mlp", "honest", "Settled"): 1, ("mlp", "cheater", "Slashed"): 1})

    def test_expected_outcomes_pass(self):
        self.assertTrue(verdict(**self.valid()))

    def test_missing_or_false_supply_invariant_fails(self):
        for inv in (None, {}, {"supply_invariant": False}):
            with self.subTest(inv=inv):
                values = self.valid()
                values["inv"] = inv
                self.assertFalse(verdict(**values))

    def test_wrong_pending_or_empty_outcomes_fail(self):
        for summary in ({}, {("mlp", "cheater", "Complete"): 1},
                        {("job", "cheater", "Settled"): 1}, {("job", "honest", "Expired"): 1}):
            with self.subTest(summary=summary):
                values = self.valid()
                values["summary"] = summary
                self.assertFalse(verdict(**values))

    def test_tool_errors_crashes_and_divergence_fail(self):
        for field, value in (("stats", {"errors": 1}), ("crashed", ["B"]), ("conv", False)):
            with self.subTest(field=field):
                values = self.valid()
                values[field] = value
                self.assertFalse(verdict(**values))


if __name__ == "__main__":
    unittest.main()
