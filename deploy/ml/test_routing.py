"""Tests of the choice of the miner for an AI job (routing.py): python -m unittest test_routing"""
import unittest

import routing as R


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def fake_run(speeds, present):
    """A stand-in for vearl-cli: `probe` answers the speed of the worker in the address, `has-model` its blocks."""
    def run(args, timeout=60):
        addr = args[2]
        key = addr.split("acct:")[-1] if "acct:" in addr else addr
        if args[0] == "probe":
            mb = speeds.get(key)
            return "PROBE failed: Err" if mb is None else f"PROBE bytes=4194304 secs=1.0 mbit={mb}"
        if args[0] == "has-model":
            n, tot = present.get(key, (0, 10))
            return f"HASMODEL present={n} total={tot}"
        raise AssertionError(args)
    return run


def router(workers, speeds, present, models=None):
    clk = Clock()
    r = R.Router("seed:9000", "http://x", "vearl-cli", models=models or {"minilm": "m", "bge": "b", "resnet": "r", "gpt": "g", "vit": "v"}, run=fake_run(speeds, present), now=clk)
    for w in workers:
        r.workers[w.account] = w
    r.clk = clk
    return r


class RoutingTests(unittest.TestCase):
    def test_what_a_kind_needs_follows_what_it_sends(self):
        self.assertAlmostEqual(R.needed_mbit("minilm"), 4 * 8 / 30 * 1.5)       # 1.6 Mbit/s: any home line
        self.assertGreater(R.needed_mbit("vit"), 10)
        self.assertGreater(R.needed_mbit("embed"), 400)                         # Qwen3: a data-centre link
        self.assertGreater(R.needed_mbit("bge", 4), R.needed_mbit("bge", 1))

    def test_a_home_miner_gets_the_light_kinds_and_not_qwen3(self):
        home = R.Worker("aa", direct=False)
        r = router([home], {"aa": 30.0}, {"aa": (10, 10)})
        for kind, expect in (("resnet", True), ("minilm", True), ("gpt", True), ("bge", True), ("vit", True), ("embed", False)):
            got = r.choose(kind)
            self.assertEqual(got is not None, expect, kind)
        self.assertTrue(r.choose("minilm")[1].startswith("relay://seed:9000/acct:aa"))

    def test_the_heavy_kind_wants_a_miner_that_can_be_dialed_and_a_fast_link(self):
        home = R.Worker("aa", direct=False)
        dc_slow = R.Worker("bb", direct=True, dial="203.0.113.5:9000")
        dc = R.Worker("cc", direct=True, dial="203.0.113.6:9000")
        r = router([home, dc_slow, dc], {"aa": 900.0, "203.0.113.5:9000": 100.0, "203.0.113.6:9000": 800.0}, {"aa": (10, 10), "203.0.113.5:9000": (10, 10), "203.0.113.6:9000": (10, 10)}, models={"embed": ""})
        w, addr = r.choose("embed")
        self.assertEqual(w.account, "cc", "the relay-only miner is skipped however fast it is; the slow data-centre miner does not qualify")
        self.assertEqual(addr, "203.0.113.6:9000", "dialed directly, not through the seed")

    def test_the_miner_must_hold_the_model(self):
        a, b = R.Worker("aa", direct=False), R.Worker("bb", direct=False)
        r = router([a, b], {"aa": 50.0, "bb": 20.0}, {"aa": (3, 10), "bb": (10, 10)})
        self.assertEqual(r.choose("bge")[0].account, "bb", "aa is faster but lacks the model")
        # one block that depends on the text (minilm, bge) may be missing: the client sends it
        c = R.Worker("cc", direct=False)
        r2 = router([c], {"cc": 20.0}, {"cc": (9, 10)})
        self.assertIsNotNone(r2.choose("minilm"))
        r3 = router([R.Worker("cc", direct=False)], {"cc": 20.0}, {"cc": (7, 10)})
        self.assertIsNone(r3.choose("minilm"))

    def test_the_fastest_qualifying_miner_wins_and_a_failed_one_rests(self):
        a, b = R.Worker("aa", direct=False), R.Worker("bb", direct=False)
        r = router([a, b], {"aa": 40.0, "bb": 90.0}, {"aa": (10, 10), "bb": (10, 10)})
        w, _ = r.choose("vit")
        self.assertEqual(w.account, "bb")
        r.failed(w)
        w2, _ = r.choose("vit")
        self.assertEqual(w2.account, "aa", "bb rests after a failure")
        r.clk.t += 1000
        w3, _ = r.choose("vit")
        self.assertEqual(w3.account, "bb", "and comes back later (measured again)")

    def test_a_probe_that_fails_means_no_job(self):
        a = R.Worker("aa", direct=False)
        r = router([a], {}, {})
        self.assertIsNone(r.choose("resnet"))
        self.assertEqual(a.mbit, 0.0)

    def test_dead_miners_do_not_use_up_the_budget_of_every_round(self):
        # 31 miners that fail the probe sit in front of the good one: with a budget of 8 per call, the good one must still be reached after a few calls
        dead = [R.Worker("d%02d" % i, direct=False) for i in range(31)]
        good = R.Worker("zz", direct=False)
        r = router(dead + [good], {"zz": 20.0}, {"zz": (10, 10)})
        for _ in range(6):
            r.choose("minilm")
        self.assertIs(r.pick("minilm"), good)
        before = [w.mbit_at for w in dead]
        r.choose("minilm")
        self.assertEqual(before, [w.mbit_at for w in dead], "a miner measured too slow is not probed again before its measure expires")

    def test_old_measures_are_not_trusted(self):
        a = R.Worker("aa", direct=False)
        r = router([a], {"aa": 50.0}, {"aa": (10, 10)})
        self.assertIsNotNone(r.choose("minilm"))
        r.clk.t += R.PROBE_TTL + 1
        self.assertIsNone(r.pick("minilm"), "stale: pick alone refuses, choose measures again")
        self.assertIsNotNone(r.choose("minilm"))


if __name__ == "__main__":
    unittest.main()
