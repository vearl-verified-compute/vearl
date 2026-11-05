"""Monitor CLI regressions; all API replies are local mocks, webhooks are absent."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("vearl_watch", Path(__file__).with_name("vearl-watch.py"))
watch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watch)


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "watch.json"
        self.now = 1_800_000_000

    def invoke(self, status=None, *, now=None, error=None, state=None):
        if status is None:
            status = {"height": 20, "peers": 2, "supply_invariant": True}
        args = ["vearl-watch.py", "--state", str(state or self.state), "--webhook-file",
                str(Path(self.temp.name) / "absent-webhook"), "--stall-secs", "300"]
        output = io.StringIO()
        with patch.object(sys, "argv", args), patch.object(watch.time, "time", return_value=self.now if now is None else now), \
                patch.object(watch, "fetch", return_value=status, side_effect=error), contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as result:
                watch.main()
        return result.exception.code, output.getvalue()

    def saved(self):
        return json.loads(self.state.read_text())

    def test_healthy_status_is_silent_and_saved(self):
        self.assertEqual(self.invoke(), (0, ""))
        self.assertEqual(self.saved()["height"], 20)
        self.assertEqual(self.saved()["height_since"], self.now)

    def test_peer_loss_does_not_repeat_when_height_changes(self):
        first = {"height": 20, "peers": 0, "supply_invariant": True}
        code, text = self.invoke(first)
        self.assertEqual(code, 1)
        self.assertIn("ALERT: no peer", text)
        self.assertEqual(self.invoke(first), (1, ""))
        self.assertEqual(self.invoke(dict(first, height=21)), (1, ""))
        self.assertEqual(self.saved()["height"], 21)

    def test_stall_does_not_repeat_as_elapsed_minutes_change(self):
        self.invoke()
        code, text = self.invoke(now=self.now + 301)
        self.assertEqual(code, 1)
        self.assertIn("height stuck at 20", text)
        self.assertEqual(self.invoke(now=self.now + 361), (1, ""))
        self.assertEqual(self.invoke(now=self.now + 421), (1, ""))

    def test_recovery_emits_once_and_clears_the_fault(self):
        self.invoke({"height": 20, "peers": 0, "supply_invariant": True})
        code, text = self.invoke()
        self.assertEqual(code, 0)
        self.assertIn("recovered", text)
        self.assertEqual(self.invoke(), (0, ""))
        self.assertIsNone(self.saved()["alert"])

    def test_invariant_failure_takes_priority_over_peer_loss_and_stall(self):
        self.invoke()
        code, text = self.invoke({"height": 20, "peers": 0, "supply_invariant": False}, now=self.now + 400)
        self.assertEqual(code, 1)
        self.assertIn("SUPPLY INVARIANT IS FALSE", text)

    def test_missing_or_nonboolean_invariant_is_not_healthy(self):
        for value in (None, 0, 1, "true", []):
            with self.subTest(value=value):
                code, text = self.invoke({"height": 20, "peers": 2, "supply_invariant": value})
                self.assertEqual(code, 1)
        self.state.unlink(missing_ok=True)
        code, text = self.invoke({"height": 20, "peers": 2})
        self.assertEqual(code, 1)
        self.assertIn("invariant", text.lower())

    def test_invalid_height_or_peers_is_not_healthy(self):
        for field in ("height", "peers"):
            for value in (None, True, -1, "20", 1.5):
                with self.subTest(field=field, value=value):
                    status = {"height": 20, "peers": 2, "supply_invariant": True}
                    status[field] = value
                    self.assertEqual(self.invoke(status)[0], 1)

    def test_nonobject_api_response_alerts(self):
        self.assertEqual(self.invoke([20, 2, True])[0], 1)

    def test_transport_errors_do_not_repeat_when_details_change(self):
        code, text = self.invoke(error=OSError("connection refused"))
        self.assertEqual(code, 1)
        self.assertIn("ALERT", text)
        self.assertEqual(self.invoke(error=OSError("timed out")), (1, ""))

    def test_transport_recovery_emits_once(self):
        self.invoke(error=OSError("connection refused"))
        code, text = self.invoke()
        self.assertEqual(code, 0)
        self.assertIn("recovered", text)
        self.assertEqual(self.invoke(), (0, ""))

    def test_a_different_fault_emits_a_new_alert(self):
        self.invoke({"height": 20, "peers": 0, "supply_invariant": True})
        code, text = self.invoke({"height": 20, "peers": 2, "supply_invariant": False})
        self.assertEqual(code, 1)
        self.assertIn("INVARIANT", text)

    def test_legacy_fault_state_recovers(self):
        self.state.write_text(json.dumps({"height": 20, "height_since": self.now, "alert": "no peer (height 20)"}))
        code, text = self.invoke()
        self.assertEqual(code, 0)
        self.assertIn("recovered", text)
        self.assertEqual(self.invoke(), (0, ""))

    def test_legacy_ongoing_fault_migrates_and_then_deduplicates(self):
        self.state.write_text(json.dumps({"height": 20, "height_since": self.now, "alert": "no peer (height 20)"}))
        status = {"height": 20, "peers": 0, "supply_invariant": True}
        self.assertEqual(self.invoke(status)[0], 1)
        self.assertEqual(self.invoke(dict(status, height=21)), (1, ""))
        self.assertEqual(self.saved()["alert_key"], "no_peer")

    def test_unparseable_or_nonobject_saved_state_is_reinitialized(self):
        for text in ("not json", "[]", "null"):
            with self.subTest(text=text):
                self.state.write_text(text)
                self.assertEqual(self.invoke(), (0, ""))
                self.assertEqual(self.saved()["height"], 20)

    def test_state_write_failure_is_an_error_even_when_node_is_healthy(self):
        directory = Path(self.temp.name) / "directory"
        directory.mkdir()
        code, text = self.invoke(state=directory)
        self.assertEqual(code, 2)
        self.assertIn("cannot save state", text)


if __name__ == "__main__":
    unittest.main()
