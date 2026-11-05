#!/usr/bin/env python3
"""ENDURANCE test of a mini-network of REAL processes (4 nodes): miners, an honest worker, a CHEATING worker,
a relay; a client that randomly submits transfers and jobs of all kinds (product, block-wise, inference,
tensor program, auction); and CHAOS: abrupt stop (SIGKILL) then restart of random nodes.
Verdict: (1) the 4 nodes converge to the same tip, (2) the money supply invariant holds on node A,
(3) no process crashed by itself, (4) the cheaters were penalised, the honest ones paid.

    python3 tools/soak.py [DURATION_SECONDS=300] [SEED=1]      # after cargo build --release --bins; pip install cryptography
"""
import json, os, random, re, signal, subprocess, sys, tempfile, time, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
import chain_ref as C

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 300
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
B = os.environ.get("B", "target/release")
D = tempfile.mkdtemp(prefix="vearl-soak-")

# ---------------- Bech32m addresses (encoding) ----------------
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def polymod(v):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    c = 1
    for x in v:
        b = c >> 25
        c = (c & 0x1FFFFFF) << 5 ^ x
        for i in range(5):
            c ^= gen[i] if (b >> i) & 1 else 0
    return c


def bech32m(hrp, data):
    acc = bits = 0
    five = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = polymod(exp + five + [0] * 6) ^ 0x2BC830A3
    return hrp + "1" + "".join(CH[d] for d in five + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def addr(seed):
    return bech32m("vrl", bytes.fromhex(C.pub_hex(seed)))


def run(*args, check=False, timeout=60, stdout_only=False):
    r = subprocess.run([f"{B}/{args[0]}"] + list(args[1:]), capture_output=True, text=True, timeout=timeout, check=check or stdout_only)
    return r.stdout.strip() if stdout_only else (r.stdout + r.stderr).strip()


# ---------------- genesis ----------------
alloc = []
for s in range(1, 7):
    alloc += ["--alloc", f"{addr(s)}=200000"]
g = run("vearl-genesis", "--network", "soak", "--faucet", addr(7), "--retarget", "Fixed", "--target-divisor", "256", *alloc, stdout_only=True)
gj = json.loads(g)
gj["timing"] = {"challenge_secs": int(os.environ.get("SOAK_WINDOW", 120)), "serve_secs": 15}
gpath = f"{D}/genesis.json"
json.dump(gj, open(gpath, "w"), indent=1)

# ---------------- nodes ----------------
NODES = {
    "A": dict(port=9401, seed=1, api=8801, extra=[], peers=[]),
    "B": dict(port=9402, seed=2, extra=["--worker", "--ask", "2"], peers=["A"]),        # honest worker
    "C": dict(port=9403, seed=3, extra=["--worker", "--cheat"], peers=["A"]),            # CHEATING worker
    "D": dict(port=9404, seed=None, extra=[], peers=["A", "B"]),                          # relay (does not mine)
}
procs, logs = {}, {}


def start(name):
    n = NODES[name]
    env = dict(os.environ, VEARL_DEBUG_MEMPOOL="1")
    cmd = [f"{B}/node", "--genesis", gpath, "--listen", f"127.0.0.1:{n['port']}", "--data-dir", f"{D}/{name}"]
    if n["seed"]:
        cmd += ["--mine-seed", str(n["seed"]), "--insecure-devnet-keys"]
    if n.get("api"):
        cmd += ["--api", f"127.0.0.1:{n['api']}"]
    for p in n["peers"]:
        cmd += ["--peer", f"127.0.0.1:{NODES[p]['port']}"]
    cmd += n["extra"]
    logs[name] = open(f"{D}/{name}.log", "ab")
    procs[name] = subprocess.Popen(cmd, stdout=logs[name], stderr=subprocess.STDOUT, env=env)


def addrof(name):
    return f"127.0.0.1:{NODES[name]['port']}"


def status(name):
    o = run("vearl-cli", "status", addrof(name))
    m = re.search(r"height: (\d+), tip: \[([\d, ]+)\], work: (\d+)", o)
    return (int(m.group(1)), tuple(int(x) for x in m.group(2).split(", ")), int(m.group(3))) if m else None


def api_status(name):
    port = NODES[name].get("api")
    if not port:
        return None
    try:
        return json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=5))
    except Exception:
        return None


for nm in NODES:
    start(nm)
    time.sleep(0.5)
time.sleep(5)
print(f"[soak] folder {D}; nodes started: {', '.join(NODES)}; duration {DUR} s")

# ---------------- client actions ----------------
CL, HUB = "seed:4", addrof("A")
jobs = []          # dicts: kind, id, worker, cheat, args, state
stats = {"transfer": 0, "kill": 0, "submitted": 0, "finished": 0, "errors": 0}


def jid(out):
    m = re.search(r"job_id = ([0-9a-f]{64})", out)
    return m.group(1) if m else None


def submit():
    worker = rng.choice(["B", "C"])
    cheat = worker == "C"
    wa = addrof(worker)
    kind = rng.choice(["job", "job", "auction", "tiled", "mlp", "prog"])
    seed = rng.randint(1, 10**6)
    if kind == "job":
        out = run("vearl-cli", "job-submit", HUB, wa, CL, "5", str(seed))
    elif kind == "auction":
        out = run("vearl-cli", "job-submit", HUB, wa, CL, "5", str(seed), "20")
    elif kind == "tiled":
        out = run("vearl-cli", "tiled-submit", HUB, wa, CL, "3", "1", "2", "1", str(seed))
    elif kind == "mlp":
        out = run("vearl-cli", "mlp-submit", HUB, wa, CL, "5", "2", str(seed))
    else:
        out = run("vearl-cli", "prog-submit", HUB, wa, CL, "5", str(seed), "cnn")
    i = jid(out)
    if i:
        jobs.append(dict(kind=kind, id=i, worker=worker, cheat=cheat, seed=seed, t=time.time(), done=False))
        stats["submitted"] += 1
    else:
        stats["errors"] += 1


def statusline(j):
    cmd = {"job": "job-status", "auction": "job-status", "tiled": "tiled-status", "mlp": "mlp-status", "prog": "prog-status"}[j["kind"]]
    return run("vearl-cli", cmd, HUB, j["id"])


def try_finish(j):
    o = statusline(j)
    ready = ("Posted" in o) if j["kind"] in ("job", "auction", "tiled") else ("Complete" in o)
    if not ready:
        return
    wa, s = addrof(j["worker"]), str(j["seed"])
    if j["kind"] in ("job", "auction"):
        out = run("vearl-cli", "job-finish", HUB, wa, CL, j["id"], s)
    elif j["kind"] == "tiled":
        out = run("vearl-cli", "tiled-finish", HUB, wa, CL, j["id"], "1", "2", "1", s)
    elif j["kind"] == "mlp":
        out = run("vearl-cli", "mlp-finish", HUB, wa, CL, j["id"], "2", s)
    else:
        out = run("vearl-cli", "prog-finish", HUB, wa, CL, j["id"], s, "cnn")
    final = re.search(r"final job status: (Settled|Slashed|Expired)\b", out)
    j["done"] = final is not None
    j["finish"] = out[-200:].replace(chr(10), " | ")
    if j["done"]:
        stats["finished"] += 1


def drain_jobs(timeout=240):
    """Keep verifying late or reorganised results even after the tips converge."""
    deadline = time.monotonic() + timeout
    next_report = 0
    conv, sts = False, {}
    while time.monotonic() < deadline:
        for j in jobs:
            if time.monotonic() >= deadline:
                return False, sts
            # A previously settled result can be reorganised away. Read the
            # canonical state rather than trusting the remembered done flag.
            m = re.search(r'status: "([A-Za-z]+)', statusline(j))
            j["done"] = bool(m and m.group(1) in ("Settled", "Slashed", "Expired"))
            if not j["done"]:
                try:
                    try_finish(j)
                except subprocess.TimeoutExpired:
                    stats["errors"] += 1
        states = []
        for j in jobs:
            m = re.search(r'status: "([A-Za-z]+)', statusline(j))
            states.append(m.group(1) if m else "unknown")
        sts = {n: status(n) for n in NODES}
        conv = all(sts.values()) and len({s[1] for s in sts.values()}) == 1
        pending = sum(s not in ("Settled", "Slashed", "Expired") for s in states)
        if time.monotonic() >= next_report:
            print(f"[soak] drain: {pending} nonterminal jobs; converged={conv}")
            next_report = time.monotonic() + 15
        if conv and not pending:
            return True, sts
        time.sleep(2)
    return False, sts


t0 = time.time()
next_chaos = t0 + 60
next_report = t0 + 30
while time.time() - t0 < DUR:
    a = rng.random()
    try:
        if a < 0.25:
            to = rng.choice([5, 6, 7])
            run("vearl-cli", "transfer", HUB, CL, f"seed:{to}", str(rng.randint(1, 20)))
            stats["transfer"] += 1
        elif a < 0.6 and len([j for j in jobs if not j["done"]]) < 8:
            submit()
        for j in [j for j in jobs if not j["done"] and time.time() - j["t"] > 3]:
            try_finish(j)
    except subprocess.TimeoutExpired:
        stats["errors"] += 1
    if time.time() > next_chaos:
        victim = rng.choice(["B", "C", "D", "A"] if rng.random() < 0.2 else ["B", "C", "D"])
        procs[victim].send_signal(signal.SIGKILL)
        procs[victim].wait()
        stats["kill"] += 1
        print(f"[soak] t={int(time.time()-t0)}s: node {victim} killed (SIGKILL)")
        time.sleep(3)
        start(victim)
        next_chaos = time.time() + rng.randint(int(os.environ.get("SOAK_CHAOS_MIN", 40)), int(os.environ.get("SOAK_CHAOS_MAX", 90)))
    if time.time() > next_report:
        st = {n: (status(n) or (None,))[0] for n in NODES}
        mp = {n: (re.search(r"mempool: (\d+)", run("vearl-cli", "status", addrof(n))) or [0, "?"])[1] for n in NODES}
        states = {}
        for j in jobs:
            m = re.search(r'status: "([A-Za-z]+)', statusline(j))
            k = (j["kind"][0] + ("!" if j["cheat"] else "+"), m.group(1) if m else "?")
            states[k] = states.get(k, 0) + 1
        print(f"[soak] t={int(time.time()-t0)}s heights {st} mempool {mp}; jobs {states}; {stats}")
        next_report = time.time() + 30
    time.sleep(rng.uniform(1.0, 3.0))

# ---------------- end: stop of the chaos, convergence, checks ----------------
print("[soak] end of activity; waiting for convergence...")
for nm, p in procs.items():
    if p.poll() is not None:
        print(f"[soak] WARNING: node {nm} stopped by itself (code {p.returncode})")
        stats["errors"] += 1
        start(nm)
# Convergence alone does not finish jobs. Keep verifying late results until
# every submitted job has a terminal status, with a bounded drain deadline.
with open(f"{D}/jobs.json", "w") as f:
    json.dump(jobs, f, indent=2)
conv, sts = drain_jobs()
with open(f"{D}/jobs.json", "w") as f:
    json.dump(jobs, f, indent=2)
print("[soak] tips:", {n: (s[0] if s else None) for n, s in sts.items()}, "-> CONVERGENCE" if conv else "-> NO CONVERGENCE")
inv = api_status("A")
print("[soak] API of node A: money supply invariant ==", inv and inv.get("supply_invariant"), "; supply:", inv and inv.get("supply"))
summary = {}
for j in jobs:
    o = statusline(j)
    st = re.search(r'status: "([A-Za-z]+)', o)
    key = (j["kind"], "cheater" if j["cheat"] else "honest", st.group(1) if st else "?")
    summary[key] = summary.get(key, 0) + 1
    if j["cheat"] and key[2] == "Settled":
        # a CHEATER PAID: either the client did not verify in time (window closed), or the cheating did not alter this job
        print(f"[soak] ANOMALY cheater paid: {j['kind']} {j['id'][:8]}; client verification: {j.get('finish', 'NEVER VERIFIED')!r}")
print("[soak] jobs (type, worker, final status):")
for k, v in sorted(summary.items()):
    print("   ", k, v)
crashed = [n for n, p in procs.items() if p.poll() is not None]
for p in procs.values():
    try:
        p.send_signal(signal.SIGTERM)
    except Exception:
        pass
outcomes_ok = bool(summary) and all(
    status == ("Slashed" if worker == "cheater" else "Settled")
    for (_, worker, status) in summary
)
ok = conv and inv is not None and inv.get("supply_invariant") is True and not crashed and stats["errors"] == 0 and outcomes_ok
cheat_slashed = sum(v for (k, w, s), v in summary.items() if w == "cheater" and s == "Slashed")
honest_paid = sum(v for (k, w, s), v in summary.items() if w == "honest" and s == "Settled")
print(f"[soak] cheaters penalised: {cheat_slashed}; honest paid: {honest_paid}; tool errors: {stats['errors']}; kills: {stats['kill']}")
print("[soak] VERDICT :", "OK" if ok else "FAIL", f"(logs in {D})")
sys.exit(0 if ok else 1)
