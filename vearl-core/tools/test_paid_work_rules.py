#!/usr/bin/env python3
"""Checks of the paid-work rules of testnet_rewards.py (self-dealt and endless jobs): python3 tools/test_paid_work_rules.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import testnet_rewards as tr  # noqa: E402

START = 1_800_000_000
P = dict(tr.DEFAULTS)
P["early_days"] = 0          # no early multiplier: the numbers below are plain points
P["min_active_days"] = 1
P["min_share"] = 0.0


def blk(h, miner, work="native", job=None, client=None, unit=None):
    b = {"height": h, "timestamp": START + h * 10, "miner": miner, "work": work}
    if job:
        b["job"] = job
    if client:
        b["client"] = client
    if unit is not None:
        b["unit"] = unit
    return b


def points(blocks, who):
    r = tr.score(blocks, START, P)
    return next(m["points"] for m in r["miners"] if m["address"] == who)


class Rules(unittest.TestCase):
    def test_native_and_honest_paid_work(self):
        self.assertEqual(points([blk(1, "m"), blk(2, "m")], "m"), 2.0)
        self.assertEqual(points([blk(1, "m", "job", "j1", client="c")], "m"), 1.5)

    def test_a_miner_that_is_its_own_client_gets_no_bonus(self):
        farm = [blk(h, "m", "job", "j1", client="m") for h in range(1, 201)]
        self.assertEqual(points(farm, "m"), 200.0)

    def test_an_endless_job_is_paid_the_bonus_only_up_to_the_cap(self):
        farm = [blk(h, "m", "job", "j1", client="c") for h in range(1, 201)]
        cap = P["useful_cap_per_job"]
        self.assertEqual(points(farm, "m"), cap * 1.5 + (200 - cap) * 1.0)
        # a second job has its own allowance
        two = farm + [blk(300 + h, "m", "job", "j2", client="c") for h in range(1, 6)]
        self.assertEqual(points(two, "m"), cap * 1.5 + (200 - cap) + 5 * 1.5)

    def test_the_same_operation_is_paid_once(self):
        ops = [blk(1, "m", "program_op", "j1", client="c", unit="3"), blk(2, "m", "program_op", "j1", client="c", unit="3"), blk(3, "m", "program_op", "j1", client="c", unit="4")]
        self.assertEqual(points(ops, "m"), 1.5 + 1.0 + 1.5)

    def test_old_data_without_job_or_client_keeps_the_old_rule(self):
        self.assertEqual(points([blk(1, "m", "job")], "m"), 1.5)

    def test_the_early_multiplier_still_applies(self):
        p = dict(P, early_days=3)
        r = tr.score([blk(1, "m", "job", "j1", client="c")], START, p)
        self.assertAlmostEqual(r["miners"][0]["points"], 1.5 * 1.25)

    def test_the_grace_period_leaves_the_first_minutes_out(self):
        p = dict(P, grace_minutes=5)
        blocks = [blk(h, "m") for h in range(0, 60)]          # one block every 10 s: 10 minutes
        r = tr.score(blocks, START, p)
        self.assertEqual(r["miners"][0]["points"], 30.0)      # the blocks of the last 5 minutes only
        self.assertEqual(tr.score(blocks, START, P)["miners"][0]["points"], 60.0)


class Fetch(unittest.TestCase):
    def test_the_client_of_a_job_is_read_from_the_node(self):
        import json
        import threading
        import urllib.parse
        from http.server import BaseHTTPRequestHandler, HTTPServer
        chain = [{"height": 0, "timestamp": START, "miner": "m", "work": {"type": "native"}},
                 {"height": 1, "timestamp": START + 10, "miner": "m", "work": {"type": "job", "job": "ab" * 32}},
                 {"height": 2, "timestamp": START + 20, "miner": "m", "work": {"type": "program_op", "job": "cd" * 32, "op": 7}}]

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                if u.path.startswith("/api/job/"):
                    body = json.dumps({"client": "m" if "ab" in u.path else "other"}).encode()
                else:
                    q = urllib.parse.parse_qs(u.query)
                    start = min(int(q.get("from", ["2"])[0]), 2)
                    body = json.dumps({"tip": 3, "blocks": [chain[h] for h in range(start, -1, -1)]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            got = tr.fetch_blocks(f"127.0.0.1:{srv.server_port}")
        finally:
            srv.shutdown()
        self.assertEqual(got[1]["client"], "m")
        self.assertEqual((got[2]["client"], got[2]["unit"]), ("other", "7"))
        self.assertNotIn("client", got[0])
        r = tr.score(got, START, P)
        self.assertEqual(r["miners"][0]["points"], 1.0 + 1.0 + 1.5)   # native, self-dealt job (no bonus), honest operation


if __name__ == "__main__":
    unittest.main(verbosity=2)
