"""Which miner gets an AI job (docs/21 section 4 bis).

The client verifies every operation of a job, so the miner has to SEND the outputs of all of them. Measured on a local network with the compressed
reply (rc25), what a miner sends for one unit of each kind of job:

    resnet   0.9 MB per photo         minilm   4 MB per text         gpt     9 MB per word
    bge     24 MB per text            vit     33 MB per photo        embed   1,050 MB per series of texts (Qwen3-Embedding, ten chained jobs)

A miner at home with 30 Mbit/s of upload sends 3.7 MB/s: fine for the first four, slow for the next two, hopeless for the last one. So a job goes
only to a miner that
  - holds the model (packs installed in advance: `vearl-cli has-model`),
  - has a measured link fast enough to send the operations in `TARGET_SECS` (`vearl-cli probe`: a download that does not compress), with a margin,
  - and, for the very heavy kinds, can be dialed directly: those bytes are not worth carrying through the seed.

The module is pure policy plus a thin shell over `vearl-cli` and the node's `/api/workers`; `Router.pick` has no side effects and is what the tests check.
"""
import json
import subprocess
import threading
import time
import urllib.request

# megabytes that a miner sends for one unit of work, measured (docs/21 4 bis); the unit is what a visitor asks for (a photo, a text, a word, a series)
TRAFFIC_MB = {"resnet": 1.0, "minilm": 4.0, "gpt": 9.0, "bge": 24.0, "vit": 33.0, "embed": 1050.0}
TARGET_SECS = 30.0       # the operations of a job should reach the client in about this time
MARGIN = 1.5             # the probe is a short test: ask for more than the strict minimum
DIRECT_ONLY_MB = 100.0   # above this, only miners that can be dialed directly (the seed does not carry it)
PROBE_MB = 4
PROBE_TTL = 600.0        # a link measure is kept ten minutes
HAS_MODEL_TTL = 300.0


def needed_mbit(kind, units=1):
    """Link speed in Mbit/s that a miner must have to send the outputs of `units` of `kind` in TARGET_SECS (with the margin)."""
    return TRAFFIC_MB[kind] * max(1, units) * 8.0 / TARGET_SECS * MARGIN


class Worker:
    def __init__(self, account, direct=None, dial=None):
        self.account = account          # hex of the 32-byte public key
        self.direct = direct            # True / False / None (not tested)
        self.dial = dial                # "IP:PORT" where it listens, when known
        self.mbit = None                # last measured link speed (Mbit/s), None = not measured
        self.mbit_at = 0.0
        self.has = {}                   # model name -> (present, total, at)
        self.failures = 0
        self.cool_until = 0.0

    def addr(self, relay):
        """How to reach it: directly when it can be dialed, otherwise through the relay of the seed."""
        if self.direct and self.dial:
            return self.dial
        return f"relay://{relay}/acct:{self.account}"

    def via_relay(self):
        return not (self.direct and self.dial)


class Router:
    def __init__(self, relay, node_api, cli, models=None, run=None, now=time.time):
        self.relay = relay              # "HOST:PORT" of the relay node (the seed)
        self.node_api = node_api        # "http://127.0.0.1:8545"
        self.cli = cli
        self.models = models or {}      # kind -> path of the model file (for has-model)
        self.workers = {}
        self.lock = threading.Lock()
        self.run = run or self._run
        self.now = now

    # -- shell over the tools ------------------------------------------------------------------------------------------------------------------
    def _run(self, args, timeout=60):
        r = subprocess.run([self.cli] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout

    def refresh(self):
        """The workers announced to the relay node (answered in full only to a request from the machine itself)."""
        with urllib.request.urlopen(self.node_api.rstrip("/") + "/api/workers", timeout=10) as r:
            d = json.load(r)
        with self.lock:
            seen = set()
            for w in d.get("workers", []):
                seen.add(w["account"])
                x = self.workers.setdefault(w["account"], Worker(w["account"]))
                x.direct, x.dial = w.get("direct"), w.get("dial")
            for a in list(self.workers):
                if a not in seen:
                    del self.workers[a]
        return len(self.workers)

    def measure(self, w):
        """Link speed of one worker, from a download that does not compress, over the path a job would use."""
        out = self.run(["probe", self.relay, w.addr(self.relay), str(PROBE_MB)])
        for tok in out.split():
            if tok.startswith("mbit="):
                w.mbit, w.mbit_at = float(tok[5:]), self.now()
                return w.mbit
        w.mbit, w.mbit_at = 0.0, self.now()
        return 0.0

    def holds(self, w, kind):
        """True when the worker holds (nearly) all the weight blocks of the model of `kind`."""
        c = w.has.get(kind)
        if c and self.now() - c[2] < HAS_MODEL_TTL:
            return c[0] >= c[1] > 0
        path = self.models.get(kind)
        if not path:
            # no model file to compare with here (the Qwen3 model is shipped compressed): try it, a failed job puts the worker aside (`failed`)
            w.has[kind] = (1, 1, self.now())
            return True
        out = self.run(["has-model", self.relay, w.addr(self.relay), path])
        present = total = 0
        for tok in out.split():
            if tok.startswith("present="):
                present = int(tok[8:])
            elif tok.startswith("total="):
                total = int(tok[6:])
        # a model that depends on the text keeps a block or two out of its pack (the mean vector): the client sends those, a few MiB
        w.has[kind] = (present + (2 if kind in ("minilm", "bge", "embed") else 0), total, self.now())
        return w.has[kind][0] >= w.has[kind][1] > 0

    # -- policy ---------------------------------------------------------------------------------------------------------------------------------
    def pick(self, kind, units=1, workers=None):
        """The worker for `units` of `kind`: the fastest that qualifies (None if nobody does). Uses what is known (measures that are still fresh);
        `candidates` tells which workers still need a measure."""
        need = needed_mbit(kind, units)
        heavy = TRAFFIC_MB[kind] * max(1, units) > DIRECT_ONLY_MB
        t = self.now()
        best = None
        for w in (workers if workers is not None else list(self.workers.values())):
            if t < w.cool_until or w.mbit is None or t - w.mbit_at > PROBE_TTL:
                continue
            if heavy and w.via_relay():
                continue
            if w.mbit < need:
                continue
            c = w.has.get(kind)
            if not c or t - c[2] > HAS_MODEL_TTL or not (c[0] >= c[1] > 0):
                continue
            if best is None or w.mbit > best.mbit:
                best = w
        return best

    def candidates(self, kind, units=1):
        """Workers that could still qualify and whose link or models are not known (fresh enough): measure these first."""
        t = self.now()
        heavy = TRAFFIC_MB[kind] * max(1, units) > DIRECT_ONLY_MB
        out = []
        for w in list(self.workers.values()):
            if t < w.cool_until or (heavy and w.via_relay()):
                continue
            if w.mbit is None or t - w.mbit_at > PROBE_TTL:
                out.append(w)
            else:
                c = w.has.get(kind)
                if not c or t - c[2] > HAS_MODEL_TTL:
                    out.append(w)
        return out

    def choose(self, kind, units=1, budget=8):
        """Measures what is missing (at most `budget` workers), then picks. Returns (worker, address) or None."""
        for w in self.candidates(kind, units)[:budget]:
            if w.mbit is None or self.now() - w.mbit_at > PROBE_TTL:
                self.measure(w)
            if w.mbit and w.mbit >= needed_mbit(kind, units):
                self.holds(w, kind)
        w = self.pick(kind, units)
        return (w, w.addr(self.relay)) if w else None

    def failed(self, w, secs=120.0):
        """A job failed on this worker: leave it alone for a while (longer each time)."""
        w.failures += 1
        w.cool_until = self.now() + secs * w.failures
        w.mbit = None
        w.has.clear()

    def succeeded(self, w):
        """A job finished on this worker."""
        w.failures = 0
