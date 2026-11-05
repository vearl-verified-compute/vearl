"""Exercise the real frozen-vector replay without retaining its entire history."""
from contextlib import redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import weakref

try:
    import prog_ref as P
except ModuleNotFoundError as error:
    if error.name not in {"numpy", "blake3", "cryptography"}:
        raise
    P = None

# Allow the same memory regression to be run safely against a historical file.
if P is not None and os.environ.get("PROG_REF_TEST_SOURCE"):
    spec = importlib.util.spec_from_file_location("historical_prog_ref", os.environ["PROG_REF_TEST_SOURCE"])
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

VECTOR = Path(__file__).resolve().parents[1] / "tests/vectors/prog-v1.json"


@unittest.skipIf(P is None, "requires numpy, blake3 and cryptography")
class ReferenceSnapshots(unittest.TestCase):
    def setUp(self):
        # Qwen's exporter changes the shared operation engine width at import.
        # Use the frozen vectors' width here and restore it for other tools.
        width = patch.object(P.R, "N", P.N)
        width.start()
        self.addCleanup(width.stop)

    def test_full_replay_retains_bounded_states_and_runs_negative_cases(self):
        vectors = json.loads(VECTOR.read_text())
        live_states = weakref.WeakSet()
        peak = 0
        applied = []
        deepcopy = copy.deepcopy
        apply = P.ProgChain.apply

        def tracked_copy(value, memo=None):
            nonlocal peak
            result = deepcopy(value, memo)
            if isinstance(result, P.ProgChain):
                live_states.add(result)
                peak = max(peak, len(live_states))
                # Seven replay snapshots plus working states for the negative
                # cases. Abort early on the old implementation, before OOM.
                self.assertLessEqual(len(live_states), 16, "retaining full state for every block")
            return result

        def tracked_apply(state, block):
            applied.append(block.get("hash"))
            return apply(state, block)

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "prog.json"
            path.write_text(json.dumps(vectors))
            output = io.StringIO()
            with patch.object(P.copy, "deepcopy", tracked_copy), patch.object(P.ProgChain, "apply", tracked_apply), redirect_stdout(output):
                self.assertTrue(P.main(str(path)))
            self.assertEqual(applied[:len(vectors["blocks"])], [b["hash"] for b in vectors["blocks"]])
            for kind in ("Gemm", "Act", "Elem", "Col"):
                self.assertIn(f"valid {kind} fraud (replayed by another challenger): accepted", output.getvalue())
            self.assertIn("money supply invariant", output.getvalue())
            self.assertTrue((Path(folder) / "prog.ext.json").is_file())
        self.assertGreater(peak, 0)

    def test_snapshot_plan_matches_all_negative_case_inputs(self):
        vectors = json.loads(VECTOR.read_text())
        ids = [j["id"] for j in vectors["final"]["jobs"]]
        matches = {}
        for index, block in enumerate(vectors["blocks"]):
            for tx in block["txs"]:
                for kind, data in tx["kind"].get("Prog", {}).items():
                    job = bytes(data.get("job_id", [])).hex()
                    matches.setdefault((kind, job), []).append(index)
                    if kind == "Fraud":
                        matches.setdefault(("FraudKind", next(iter(data["kind"]))), []).append(index)
        first_submit = min(i for (kind, _), indices in matches.items() if kind == "Submit" for i in indices)
        expected = {first_submit - 1, matches[("PostOp", ids[0])][-1], matches[("Claim", ids[2])][-1]}
        expected.update(matches[("FraudKind", kind)][0] - 1 for kind in ("Gemm", "Act", "Elem", "Col"))
        self.assertEqual(P.snapshot_indices(vectors), expected)
        self.assertLessEqual(len(expected), 7)
        self.assertTrue(all(0 <= index < len(vectors["blocks"]) for index in expected))

    def test_unsaved_block_still_has_its_hash_checked(self):
        vectors = json.loads(VECTOR.read_text())
        needed = P.snapshot_indices(vectors)
        index = next(i for i in range(len(vectors["blocks"])) if i not in needed)
        vectors["blocks"][index]["hash"] = "00" * 32
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "altered.json"
            path.write_text(json.dumps(vectors))
            with redirect_stdout(io.StringIO()), self.assertRaisesRegex(AssertionError, "header hash"):
                P.main(str(path))


if __name__ == "__main__":
    unittest.main()
