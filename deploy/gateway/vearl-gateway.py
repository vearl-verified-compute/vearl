#!/usr/bin/env python3
"""Vearl job gateway: the free "create a compute job" service behind https://vearl.org/compute/.

A web page cannot speak the node's encrypted peer protocol nor sign a transaction, so this small service does it for the visitor:
  1. it checks the request against fixed limits (kinds, sizes, a few jobs per visitor per hour),
  2. it submits a level-2 job from its OWN service account (the visitor pays nothing: on the testnet the escrow is test tokens),
  3. a miner running a worker node (`node --worker`) takes the job and posts a result,
  4. the gateway audits the result by sampling (`vearl-cli l2-finish`: it recomputes random chunks and opens them against the
     published Merkle root), accepts or proves fraud, assembles the output and keeps it for the visitor.
Two families of jobs: level-2 jobs (renders, Monte Carlo; audited by sampling) and exact ones that `vearl-cli` drives from end to end
(handwritten digits by a CNN, tiled matrix products: every operation is checked by the client before anything is paid).
It only drives the `vearl-cli` binary that ships with the node: no consensus code is duplicated here, and every request becomes the
same transactions a person would send by hand. Python 3 standard library only. Listens on loopback: nginx is the public face.

    python3 vearl-gateway.py --cli /opt/vearl/vearl-cli --node 127.0.0.1:19101 --worker 127.0.0.1:19102 --key seed:100 --data /var/lib/vearl-gateway

--key is `seed:N` (PUBLIC devnet key, demo chain only) or `wallet:FILE` (a funded wallet; the password is read by vearl-cli from
VEARL_WALLET_PASSWORD_FILE). Repeat --key for several service accounts: jobs are spread over them.

PUBLIC network (--public): any miner may take a job, and the audit needs the outputs of the miner that did. The gateway therefore asks
`vearl-cli l2-who` which of the nodes it can reach (every --worker, and the addresses listed in --peers-file) really serves the job's chunks,
opened against the published root, and audits that one. A miner that cannot be reached (behind a home router) cannot be audited: the job
then ends as "failed" with a plain explanation (the miner is still paid by the chain, the visitor just has no picture to see). The exact
kinds of the demo chain (digits, matmul: written for n = 128) are not offered.
"""
import argparse
import array
import base64
import collections
import json
import os
import random
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- what can be asked
# Every bound is below the protocol's own limits (docs/10-level-2.md): a visitor cannot make the network do more than this.
SIDES = [64, 96, 128, 160, 192, 256]
KINDS = {
    "pi": {
        "title": "Estimate π",
        "short": "Monte Carlo",
        "summary": "Throws random points in a square and counts how many fall inside the quarter circle. The share, times four, is π.",
        "params": {"samples": {"min": 64, "max": 4096, "default": 1024, "step": 64}, "chunks": {"min": 8, "max": 256, "default": 32, "step": 8}},
        "output": "number",
    },
}
R3_SCENES = {"watch": "Wristwatch", "cocktail": "Cocktail", "mini": "Glass and metal", "orb": "Vearl Orb", "gallery": "Gallery"}
R3_STUDIO = ["watch", "cocktail", "mini"]   # the scenes of the Studio render card; the Orb and the 3D scene have their own cards
R3_FIXED = {"render2": "orb", "render": "gallery"}
R3_WIDTHS = [256, 384, 512, 768]
R3_SHAPES = {"square": "Square", "wide": "Wide 16:9"}
R3_QUALITY = [128, 256, 512, 1024]  # samples per pixel; one pass of a tile = 32 samples per pixel
R3_SPP = 32
R3_MAX_SAMPLES = 180_000_000  # pixels x samples: about 1.5 to 3 minutes of GPU on the project's card


def r3_height(width, shape):
    return width if shape == "square" else (width * 9 // 16) // 16 * 16


KINDS["render3"] = {
    "title": "Studio render",
    "short": "Path tracer · global illumination",
    "summary": "A physically based path tracer: every ray bounces up to 14 times, so glass, liquid, metal, soft light and depth of field look like a photograph. Hundreds of samples per pixel make it smooth and sharp, and take the GPU from tens of seconds to a few minutes.",
    "params": {"scene": {"choices": R3_STUDIO, "labels": R3_SCENES, "default": "watch"}, "size": {"choices": R3_WIDTHS, "default": 512}, "shape": {"choices": list(R3_SHAPES), "labels": R3_SHAPES, "default": "square"},
               "quality": {"choices": R3_QUALITY, "default": 256}, "max_samples": R3_MAX_SAMPLES},
    "output": "image",
}
for _k, _title, _short, _sum in (
        ("render2", "Vearl Orb", "Liquid metal · neon · GPU path tracer", "A sphere of liquid metal swirling in blue and pink, circled by two neon rings, with glass pearls and gold balls on a mirror floor of dark tiles, and out-of-focus lights behind. Path traced on the GPU."),
        ("render", "3D scene", "Still life · GPU path tracer", "A still life on polished stone tiles: veined marble, waxed walnut, brass, a cracked ceramic vase and a swirl-glass bowl, in soft studio light. Path traced on the GPU.")):
    KINDS[_k] = {"title": _title, "short": _short, "summary": _sum,
                 "params": {"size": {"choices": R3_WIDTHS, "default": 512}, "shape": {"choices": list(R3_SHAPES), "labels": R3_SHAPES, "default": "wide"},
                            "quality": {"choices": R3_QUALITY, "default": 256}, "max_samples": R3_MAX_SAMPLES}, "output": "image"}
KINDS["digits"] = {
    "title": "Handwritten digits",
    "short": "CNN · exact verification",
    "summary": "A small convolutional network reads two handwritten digits. Every operation of the network is checked by exact arithmetic before the miner is paid.",
    "params": {"sample": {"min": 0, "max": 11, "default": 0}},
    "output": "digits",
    "family": "exact",
}
KINDS["matmul"] = {
    "title": "Matrix multiplication",
    "short": "Tiled int8 GEMM",
    "summary": "Multiply two random int8 matrices. The product is cut into 128 × 128 blocks that miners compute; every block is checked exactly, then the result is compared with an independent computation.",
    "params": {"blocks": {"choices": [1, 2, 3, 4], "default": 2}},
    "output": "matrix",
    "family": "exact",
}
for _k in ("pi", "render", "render2", "render3"):
    KINDS[_k]["family"] = "level2"
STAGES = ["queued", "submitting", "open", "claimed", "posted", "verifying", "done"]
FINAL = ("done", "rejected", "failed")
BLOCK = 128  # side of one matrix block on the demo chain (n = 128)

# What Vearl can compute, with the figures published on the website. Only the entries with `available` can be created here: the others
# need quantized model files that are not installed on this demo network (they were produced and measured on a GPU server).
CATALOG = [
    {"id": "gpt", "title": "Text generation", "model": "TinyStories-33M language model, 4 layers, 50,257-word vocabulary", "size": "307 ops · 2 jobs per word",
     "measure": "Writes stories word by word: 8 stories in parallel, ≈ 18 s per word, 92.9% same next word as the original model", "available": False},
    {"id": "vit", "title": "Photo recognition", "model": "DeiT-Tiny vision transformer, 224 × 224 photos, 1,000 ImageNet classes", "size": "386 ops · 2 chained jobs",
     "measure": "≈ 1.7 s per photo, 70.6% top-1 on photos never seen in training (original model: 78.2%)", "available": False},
    {"id": "embed", "title": "Text embeddings", "model": "Qwen3-Embedding-0.6B, 28 layers, 0.6 billion parameters, 1,024 dimensions", "size": "2,195 ops · 10 chained jobs",
     "measure": "Verified operation by operation, outputs bit-identical to an independent engine; cosine 0.77 with the floating-point model, topic search 85% (original 90%)", "available": False},
    {"id": "bge", "title": "Semantic search embeddings", "model": "BGE-base, 12 layers, 110 million parameters", "size": "492 ops · 3 chained jobs",
     "measure": "≈ 3.3 s per text, 96.7% of the original model's score on STS-B (0.836 vs 0.864)", "available": False},
    {"id": "minilm", "title": "Fast sentence embeddings", "model": "all-MiniLM-L6-v2, 6 layers, 12 attention heads", "size": "195 ops · 61 GEMMs",
     "measure": "≈ 1.0 s per text, cosine similarity 0.92 with the original model", "available": False},
    {"id": "resnet", "title": "Small-image classification", "model": "ResNet-20 on CIFAR-10", "size": "76 ops · 22 GEMMs",
     "measure": "88.6% top-1 accuracy, 32 images in 41 s", "available": False},
    {"id": "matmul", "title": "Matrix multiplication", "model": "Tiled int8 GEMM", "size": "8192 × 8192 × 8192 on the public network",
     "measure": "1.1 trillion operations, verified end to end in about 11 s", "available": True,
     "note": "Here: up to 512 × 512 on the demo network (128-wide blocks)."},
    {"id": "digits", "title": "Handwritten digits", "model": "MLP and CNN on MNIST", "size": "10,000 test images",
     "measure": "98.1% top-1 accuracy in int8", "available": True,
     "note": "Here: a small CNN on 8 × 8 digit images (the demo network's block size is 128)."},
    {"id": "bulk", "title": "Bulk embeddings", "model": "Distilled text encoder", "size": "20,480 texts",
     "measure": "Outputs bit-identical to an independent reference engine", "available": False},
]
CATALOG_NOTE = "Needs model files that are not installed on this demo network."
CATALOG_NOTE_PUBLIC = "Not offered on this page yet: the job service starts with the studio renders and Monte Carlo jobs."


def tiles(w, h):
    return (w // 16) * (h // 16)


def validate(body):
    """Returns (clean params, cli args after the escrow) or raises ValueError with a message for the visitor."""
    kind = body.get("kind")
    if kind not in KINDS:
        raise ValueError("Unknown job type.")

    def num(name, lo, hi, default=None):
        v = body.get(name, default)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != int(v):
            raise ValueError(f"'{name}' must be a whole number.")
        v = int(v)
        if v < lo or v > hi:
            raise ValueError(f"'{name}' must be between {lo} and {hi}.")
        return v

    seed = num("seed", 0, 2**53, secrets.randbelow(2**31))
    if kind == "digits":
        return {"kind": kind, "sample": num("sample", 0, 11)}, [], 1
    if kind == "matmul":
        b = num("blocks", 1, 4)
        return {"kind": kind, "blocks": b, "size": BLOCK * b, "seed": seed}, [], b * b * b
    if kind == "pi":
        s, c = num("samples", 64, 4096), num("chunks", 8, 256)
        return {"kind": kind, "samples": s, "chunks": c, "seed": seed}, ["mc", str(s), str(c), str(seed)], c
    if kind in ("render3", "render2", "render"):
        scene = R3_FIXED.get(kind) or body.get("scene", "watch")
        if scene not in (R3_STUDIO if kind == "render3" else R3_SCENES):
            raise ValueError("Pick one of the offered scenes.")
        shape = body.get("shape", "square")
        if shape not in R3_SHAPES:
            raise ValueError("Pick one of the offered image shapes.")
        side, q = num("size", 64, 4096, 512), num("quality", 1, 8192, 256)
        if side not in R3_WIDTHS or q not in R3_QUALITY:
            raise ValueError("Pick one of the offered image sizes and qualities.")
        h = r3_height(side, shape)
        if side * h * q > R3_MAX_SAMPLES:
            raise ValueError("This image is too large for this quality: pick a smaller size or fewer samples.")
        passes = q // R3_SPP
        chunks = tiles(side, h) * passes
        return {"kind": kind, "scene": scene, "size": side, "height": h, "shape": shape, "quality": q, "seed": seed}, ["render3", scene, str(side), str(h), str(R3_SPP), str(passes), str(seed)], chunks
    side, spp = num("size", 64, 256), num("spp", 1, 4)
    if side not in SIDES:
        raise ValueError("Pick one of the offered image sizes.")
    return {"kind": kind, "size": side, "spp": spp, "seed": seed}, [kind, str(side), str(side), str(spp), str(seed)], tiles(side, side)


# ---------------------------------------------------------------- png
def ppm_to_png(ppm_path, png_path):
    data = open(ppm_path, "rb").read()
    head = data.split(b"\n", 3)
    if len(head) < 4 or head[0] != b"P6":
        raise ValueError("not a P6 image")
    w, h = (int(x) for x in head[1].split())
    pix = head[3]
    if len(pix) != w * h * 3:
        raise ValueError("truncated image")
    raw = b"".join(b"\x00" + pix[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    tmp = png_path + ".tmp"
    open(tmp, "wb").write(png)
    os.replace(tmp, png_path)
    return w, h


# ---------------------------------------------------------------- service
class Gateway:
    def __init__(self, a):
        self.a = a
        self.lock = threading.Lock()
        self.jobs = {}
        self.order = []
        self.hits = collections.defaultdict(collections.deque)  # visitor key -> submission times (memory only, never written)
        self.active_by = collections.Counter()
        self.lane_locks = {k: threading.Lock() for k in a.key}
        self.lane_load = collections.Counter()
        os.makedirs(os.path.join(a.data, "out"), exist_ok=True)
        self._ml = (0.0, {})
        self.digits = None if a.public else self.load_digits()
        self.state_path = os.path.join(a.data, "jobs.json")
        self.load()

    def load_digits(self):
        """The 12 samples (2 handwritten digits each) shipped with models/digits-cnn.json, or None when the model is not installed."""
        path = os.path.join(self.a.models, "digits-cnn.json")
        try:
            m = json.load(open(path))
            samples = []
            for sm in m["samples"]:
                a = base64.b64decode(sm["x0"])
                # the 2 images of a sample are interleaved in the first row of the 128 x 128 input: image b = a[b], a[b + 2], ...
                ims = [[min(16, a[2 * i + b] // 4) for i in range(64)] for b in range(2)]
                samples.append({"images": ims, "labels": sm["labels"]})
            return {"path": path, "samples": samples}
        except (OSError, ValueError, KeyError):
            return None

    def candidates(self):
        """Addresses the audit may ask for a job's chunks: the --worker nodes first, then the reachable peers of --peers-file."""
        seen, out = set(), []
        for w in list(self.a.workers) + self.peers_from_file():
            if w not in seen:
                seen.add(w)
                out.append(w)
        return out

    def peers_from_file(self):
        """The seed node's peers.txt (one HOST:PORT per line). Loopback and wildcard addresses are the node's own bookkeeping, not miners."""
        if not self.a.peers_file:
            return []
        try:
            lines = [l.strip() for l in open(self.a.peers_file)]
        except OSError:
            return []
        good = []
        for l in lines:
            m = re.fullmatch(r"([A-Za-z0-9.\-]+):(\d{2,5})", l)
            if m and not m.group(1).startswith(("127.", "0.0.0.0", "localhost")):
                good.append(l)
        return good[:64]

    def find_worker(self, node, chain_id):
        """The node that serves this posted job's chunks (public mode: asked among the candidates; demo chain: the one --worker)."""
        cands = self.candidates()
        if not self.a.public and len(cands) == 1:
            return cands[0]
        if self.a.public and re.fullmatch(r"[0-9a-f]{64}", chain_id or ""):
            # a miner behind a home router keeps one connection to the seed (docs/21): the seed started with --relay hands the audit's
            # requests to it. Tried FIRST: a node without --relay (or a worker that is not connected) answers at once with a refusal
            # and l2-who goes on with the direct candidates.
            cands = ["relay://%s/l2:%s" % (node, chain_id)] + cands
        for attempt in range(3):
            rc, out = self.cli(["l2-who", node, chain_id] + cands, 150)
            m = re.search(r"worker = (\S+)", out)
            if m and m.group(1) != "none":
                return m.group(1)
            time.sleep(6)
        return None

    # -- persistence
    def load(self):
        try:
            saved = json.load(open(self.state_path))
        except (OSError, ValueError):
            saved = {"jobs": []}
        for j in saved["jobs"]:
            self.jobs[j["ref"]] = j
            self.order.append(j["ref"])
        for j in list(self.jobs.values()):
            if j["status"] in FINAL:
                continue
            if j.get("lane") not in self.lane_locks:
                j["lane"] = self.a.key[0]
            self.active_by[j.get("owner", "")] += 1
            self.lane_load[j["lane"]] += 1
            if j.get("chain_id"):
                self.spawn(j, resume=True)
            else:
                self.finish(j, "failed", "The service restarted before the job reached the chain. Nothing was spent: submit it again.")

    def save(self):
        with self.lock:
            keep = [self.jobs[r] for r in self.order[-500:]]
            for r in self.order[:-500]:
                self.jobs.pop(r, None)
            self.order = self.order[-500:]
            tmp = self.state_path + ".tmp"
            json.dump({"jobs": keep}, open(tmp, "w"))
            os.replace(tmp, self.state_path)

    # -- cli
    def cli(self, args, timeout, env=None):
        e = dict(os.environ)
        e.update(env or {})
        try:
            p = subprocess.run([self.a.cli] + args, capture_output=True, text=True, timeout=timeout, env=e)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except OSError as ex:
            return 127, str(ex)

    PROGRESS = [
        (r"worker registry", "The model weights were sent to the miner."),
        (r"job_id = ", "The job is on the chain."),
        (r"batch (\d+) verified", "A batch came back and was checked exactly."),
        (r"sums C_ij verified", "Every block sum was checked (Merkle proof and 24 Freivalds rounds)."),
        (r"Accept: Ack \{ ok: true", "The result was accepted: the miner is paid."),
        (r"INFER: ", "All batches were accepted."),
        (r"TILED: ", "The product was assembled."),
    ]

    def cli_stream(self, j, args, timeout, env=None):
        """Runs vearl-cli, turns its lines into short English progress notes on the job, returns (returncode, whole output)."""
        e = dict(os.environ)
        e.update(env or {})
        lines = []
        try:
            p = subprocess.Popen([self.a.cli] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=e)
        except OSError as ex:
            return 127, str(ex)
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        try:
            for line in p.stdout:
                lines.append(line)
                for pat, msg in self.PROGRESS:
                    if re.search(pat, line):
                        with self.lock:
                            notes = j.setdefault("progress", [])
                            if not notes or notes[-1] != msg:
                                notes.append(msg)
                        break
            p.wait()
        finally:
            timer.cancel()
        self.save()
        return p.returncode, "".join(lines)

    # -- job life
    def set(self, j, status=None, **kw):
        with self.lock:
            if status:
                j["status"] = status
                j.setdefault("times", {})[status] = int(time.time())
            j.update(kw)
        self.save()

    def finish(self, j, status, message, **kw):
        self.set(j, status, message=message, **kw)
        with self.lock:
            self.active_by[j.get("owner", "")] -= 1
            if j.get("lane"):
                self.lane_load[j["lane"]] -= 1

    def spawn(self, j, resume=False):
        threading.Thread(target=self.run, args=(j, resume), daemon=True).start()

    def run_exact(self, j, resume=False):
        """digits / matmul: one vearl-cli command does everything (submit, wait for the miner, verify exactly, accept)."""
        a, p = self.a, j["params"]
        key = j["lane"] if j.get("lane") in self.lane_locks else self.a.key[0]
        try:
            if resume:
                return self.finish(j, "failed", "The service restarted while this job was running. Submit it again.")
            outdir = os.path.join(a.data, "out")
            env = {"VEARL_WAIT_SECS": str(a.wait_finish)}
            with self.lane_locks[key]:
                self.set(j, "running")
                if j["kind"] == "digits":
                    if not self.digits:
                        return self.finish(j, "failed", "The digit model is not installed on this service.")
                    out = os.path.join(outdir, j["ref"] + ".i8")
                    s0 = str(p["sample"])
                    rc, text = self.cli_stream(j, ["infer", a.node, a.worker, key, "1", self.digits["path"], s0, s0, out], a.wait_exact, env)
                    ok = re.search(r"INFER: (\d+) batch\(es\) accepted, (\d+) refused", text)
                    if not ok or int(ok.group(1)) < 1 or int(ok.group(2)) != 0 or not os.path.exists(out):
                        return self.finish(j, "failed", "The job was not accepted" + (": a batch was refused." if ok and int(ok.group(2)) else "."))
                    raw = open(out, "rb").read()
                    os.remove(out)
                    if len(raw) != 20:
                        return self.finish(j, "failed", "The classifier returned an unexpected output.")
                    sm = self.digits["samples"][p["sample"]]
                    items = []
                    for b in range(2):
                        logits = [v - 256 if v > 127 else v for v in raw[b * 10:(b + 1) * 10]]
                        items.append({"pixels": sm["images"][b], "label": sm["labels"][b], "predicted": max(range(10), key=lambda c: (logits[c], -c)), "logits": logits})
                    res = {"type": "digits", "items": items}
                    t = re.search(r"samples in ([\d.]+) s", text)
                    if t:
                        res["seconds"] = float(t.group(1))
                else:
                    b, seed = p["blocks"], p["seed"]
                    side = BLOCK * b
                    rnd = random.Random(seed)
                    A = [rnd.randint(-64, 64) for _ in range(side * side)]
                    B = [rnd.randint(-64, 64) for _ in range(side * side)]
                    fa, fb, fc = (os.path.join(outdir, j["ref"] + x) for x in (".a", ".b", ".c"))
                    open(fa, "wb").write(bytes(v & 255 for v in A))
                    open(fb, "wb").write(bytes(v & 255 for v in B))
                    try:
                        rc, text = self.cli_stream(j, ["tiled-run", a.node, a.worker, key, "1", fa, fb, str(b), str(b), str(b), fc], a.wait_exact, env)
                        if not os.path.exists(fc) or "-> Accept: Ack { ok: true" not in text:
                            return self.finish(j, "failed", "The product was not accepted.")
                        C = array.array("i")
                        C.frombytes(open(fc, "rb").read())
                        if len(C) != side * side:
                            return self.finish(j, "failed", "The product has an unexpected size.")
                    finally:
                        for f in (fa, fb, fc):
                            try:
                                os.remove(f)
                            except OSError:
                                pass
            # independent check outside the lock: the service recomputes 6 entries of the product itself, with plain Python integers
            if j["kind"] == "matmul":
                chk = random.Random(seed ^ 0x5EED)
                spots = [(chk.randrange(side), chk.randrange(side)) for _ in range(6)]
                good = sum(1 for (r, c) in spots if sum(A[r * side + k] * B[k * side + c] for k in range(side)) == C[r * side + c])
                t = re.search(r"total ([\d.]+) s", text)
                w = re.search(r"worker computation \(submission -> roots published\) ([\d.]+) s", text)
                res = {"type": "matrix", "side": side, "blocks": b, "products": b * b * b, "ops": 2 * side ** 3, "checked": len(spots), "matching": good,
                       "corner": [[C[r * side + c] for c in range(min(6, side))] for r in range(min(6, side))], "seconds": float(t.group(1)) if t else None,
                       "miner_seconds": float(w.group(1)) if w else None}
                if good != len(spots):
                    return self.finish(j, "failed", "The independent spot check disagrees with the product: not shown.")
            self.finish(j, "done", "Verified and accepted.", result=res)
        except Exception as ex:
            print("job", j.get("ref"), "error", repr(ex), file=sys.stderr)
            self.finish(j, "failed", "Internal error while following the job.")

    def run(self, j, resume=False):
        if KINDS[j["kind"]].get("family") == "exact":
            return self.run_exact(j, resume)
        a = self.a
        try:
            node, key = a.node, j["lane"] if j.get("lane") else self.a.key[0]
            if not resume:
                with self.lane_locks[key]:
                    self.set(j, "submitting")
                    rc, out = self.cli(["l2-submit", node, key, str(a.escrow)] + j["cli"], 120)
                m = re.search(r"job_id = ([0-9a-f]{64})", out)
                if rc != 0 or not m or "ok: true" not in out:
                    why = re.search(r'info: "([^"]*)"', out)
                    if rc == 0 and why and why.group(1):
                        msg = "The chain refused the job: " + why.group(1)
                    elif rc == 0:
                        msg = "The chain refused the job."
                    else:
                        msg = "The job could not be sent to the chain."
                    return self.finish(j, "failed", msg)
                self.set(j, "open", chain_id=m.group(1))
            # wait for a miner: open -> claimed -> posted
            t0 = time.time()
            while True:
                rc, out = self.cli(["l2-status", node, j["chain_id"]], 30)
                m = re.search(r"L2 (\w+)", out)
                st = m.group(1).lower() if m else ""
                if st in ("open", "claimed", "posted") and j["status"] in STAGES and STAGES.index(st) > STAGES.index(j["status"]):
                    self.set(j, st)
                if st == "posted":
                    break
                if st in ("settled", "slashed", "expired"):
                    return self.finish(j, "failed", "The job ended on the chain as '%s' before the gateway could read it." % st)
                # a big image is thousands of tiles to compute: the allowance grows with the job
                if time.time() - t0 > a.wait_miner + (j.get("chunks") or 0) // 8:
                    if st == "claimed":
                        return self.finish(j, "failed", "A miner took this job but did not post its result in time. Nothing is lost: try again later.")
                    return self.finish(j, "failed", "No miner took this job in time. The escrow comes back to the service account when the job expires: you lose nothing. Try again later.")
                time.sleep(4)
            # audit by sampling, accept, assemble
            self.set(j, "verifying")
            ppm = os.path.join(a.data, "out", j["ref"] + ".ppm")
            worker = self.find_worker(node, j["chain_id"])
            if not worker and j.get("attempts", 0) < a.retries:
                # an unreachable miner took the job: the chain has paid it, the visitor has nothing to see. Submit the same job again
                # (the escrow is the service account's, test tokens): another miner, perhaps a reachable one, will take it
                with self.lock:
                    j["attempts"] = j.get("attempts", 0) + 1
                    j.setdefault("progress", []).append("A miner took the job but cannot be reached to check it: the job was sent again.")
                self.set(j, "queued", chain_id=None)
                return self.run(j, resume=False)
            if not worker:
                return self.finish(j, "failed", "A miner took this job and posted its result, but it cannot be reached to check it (most likely it runs behind a home "
                                   "router). The miner is still paid by the chain; you lose nothing. Try again: another miner may take the next job.")
            with self.lane_locks[key]:
                fin = a.wait_finish + (j.get("chunks") or 0) // 30  # a big image is thousands of chunks to fetch
                rc, out = self.cli(["l2-finish", node, worker, key, j["chain_id"], str(a.audit), ppm], fin + 60, {"VEARL_WAIT_SECS": str(fin)})
            audit = None
            m = re.search(r"(\d+) chunk\(s\) out of (\d+) recomputed", out)
            if m:
                audit = {"checked": int(m.group(1)), "of": int(m.group(2))}
            if "WRONG" in out:
                return self.finish(j, "rejected", "The miner's result failed the audit: a recomputed chunk did not match. A fraud proof was sent and the miner loses its bond.", audit=audit)
            # the audit of a big job (or of a miner that answers slowly) can outlast the challenge window: the chain then settles the job by itself and the
            # miner is paid, so our own Accept is refused. The audit found nothing wrong (every chunk drawn was recomputed and opened against the root,
            # no fraud proof): the job is a success, not a failure
            settled_by_chain = "final job status: Settled" in out and "all correct" in out and "WRONG" not in out
            if "Accept: Ack { ok: true" not in out and not settled_by_chain:
                tail = out.strip().splitlines()[-1] if out.strip() else "no answer"
                return self.finish(j, "failed", "The result could not be accepted: " + tail[:200], audit=audit)
            res = {}
            m = re.search(r"E = ([\d.]+) \+- ([\d.]+) \((\d+) samples\).*pi ~ ([\d.]+)", out)
            if m:
                res = {"type": "number", "pi": float(m.group(4)), "mean": float(m.group(1)), "stderr": float(m.group(2)) * 4, "samples": int(m.group(3))}
            elif os.path.exists(ppm):
                png = os.path.join(a.data, "out", j["ref"] + ".png")
                w, h = ppm_to_png(ppm, png)
                os.remove(ppm)
                res = {"type": "image", "width": w, "height": h}
            else:
                return self.finish(j, "failed", "The result was accepted but the output could not be assembled.", audit=audit)
            final = re.search(r"final job status: (\w+)", out)
            self.finish(j, "done", "Verified and accepted.", audit=audit, result=res, chain_final=final.group(1) if final else None)
        except Exception as ex:  # never lose a job to a bug in one request
            print("job", j.get("ref"), "error", repr(ex), file=sys.stderr)
            self.finish(j, "failed", "Internal error while following the job.")

    # -- requests
    # -- the ML service (text generation, photo recognition) runs next to the GPU worker and is reached through a tunnel
    def ml_http(self, method, path, body=None, timeout=15):
        req = urllib.request.Request(self.a.ml + path, data=None if body is None else json.dumps(body).encode(), method=method, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    def ml_kinds(self):
        """Job kinds the ML service offers right now ({} when it is not configured or not reachable); cached for 15 s."""
        if not self.a.ml:
            return {}
        now = time.time()
        if now - self._ml[0] < 15:
            return self._ml[1]
        try:
            kinds = self.ml_http("GET", "/ml/info", timeout=3)["kinds"]
        except Exception:
            kinds = {}
        self._ml = (now, kinds)
        return kinds

    def run_remote(self, j, body):
        try:
            try:
                v = self.ml_http("POST", "/ml/jobs", body, timeout=30)
            except urllib.error.HTTPError as e:
                try:
                    msg = json.loads(e.read()).get("error", "The ML service refused the job.")
                except ValueError:
                    msg = "The ML service refused the job."
                return self.finish(j, "failed", msg)
            except Exception:
                return self.finish(j, "failed", "The ML worker is offline right now. Try again later.")
            self.set(j, None, params=v.get("params") or j["params"], rref=v["ref"])
            t0, misses, last = time.time(), 0, None
            while True:
                try:
                    v = self.ml_http("GET", "/ml/jobs/" + j["rref"])
                    misses = 0
                except Exception:
                    misses += 1
                    if misses > 20:
                        return self.finish(j, "failed", "The ML worker stopped answering.")
                    time.sleep(3)
                    continue
                st = v.get("status")
                with self.lock:
                    j["progress"] = v.get("progress") or []
                    j["result"] = v.get("result")
                if st == "running" and j["status"] != "running":
                    self.set(j, "running")
                if st == "done":
                    return self.finish(j, "done", v.get("message") or "Verified.", result=v.get("result"), progress=v.get("progress"))
                if st == "failed":
                    return self.finish(j, "failed", v.get("message") or "The job failed.")
                if time.time() - t0 > self.a.wait_ml:
                    return self.finish(j, "failed", "The job took too long and was given up.")
                if (st, len(j["progress"])) != last:
                    last = (st, len(j["progress"]))
                    self.save()
                time.sleep(2)
        except Exception as ex:
            print("job", j.get("ref"), "error", repr(ex), file=sys.stderr)
            self.finish(j, "failed", "Internal error while following the job.")

    def create(self, body, visitor):
        if self.a.public and body.get("kind") in ("digits", "matmul"):
            raise ValueError("This kind of job is not offered on the public network yet.")
        remote = body.get("kind") in self.ml_kinds()
        params, cli, chunks = ({"kind": body["kind"]}, [], 1) if remote else validate(body)
        now = time.time()
        with self.lock:
            q = self.hits[visitor]
            while q and now - q[0] > 3600:
                q.popleft()
            if len(q) >= self.a.per_hour:
                raise PermissionError(f"Free limit reached: {self.a.per_hour} jobs per hour. Try again in {int((3600 - (now - q[0])) / 60) + 1} min.")
            if self.active_by[visitor] >= self.a.per_visitor_active:
                raise PermissionError(f"You already have {self.a.per_visitor_active} jobs in progress. Wait for one to finish.")
            if sum(self.active_by.values()) >= self.a.max_active:
                raise PermissionError("The network is busy right now (too many jobs in progress). Try again in a few minutes.")
            lane = None if remote else min(self.a.key, key=lambda k: self.lane_load[k])
            ref = secrets.token_hex(6)
            j = {"ref": ref, "status": "queued", "kind": params["kind"], "params": params, "chunks": chunks, "cli": cli, "lane": lane, "owner": visitor,
                 "created": int(now), "times": {"queued": int(now)}, "chain_id": None, "message": None, "result": None, "audit": None, "remote": remote}
            self.jobs[ref] = j
            self.order.append(ref)
            q.append(now)
            self.active_by[visitor] += 1
            if lane:
                self.lane_load[lane] += 1
        self.save()
        if remote:
            threading.Thread(target=self.run_remote, args=(j, body), daemon=True).start()
        else:
            self.spawn(j)
        return self.view(j)

    def view(self, j):
        return {k: j.get(k) for k in ("ref", "status", "kind", "params", "chunks", "created", "times", "chain_id", "message", "result", "audit", "progress")}

    def info(self):
        with self.lock:
            active = sum(self.active_by.values())
            done = sum(1 for j in self.jobs.values() if j["status"] == "done")
        kinds = {k: v for k, v in KINDS.items() if k not in ("digits", "matmul") or (not self.a.public and (k != "digits" or self.digits))}
        mlk = self.ml_kinds()
        kinds.update(mlk)
        catalog = []
        for c in CATALOG:
            ok = (c["available"] and (c["id"] != "digits" or bool(self.digits)) and not (self.a.public and c["id"] in ("digits", "matmul"))) or c["id"] in mlk
            d = dict(c, available=ok, reason=None if ok else (CATALOG_NOTE_PUBLIC if self.a.public else CATALOG_NOTE))
            if c["id"] in mlk:
                d["note"] = "Here: runs on the project's GPU worker, one job at a time."
            catalog.append(d)
        return {"free": True, "kinds": kinds, "catalog": catalog, "stages": STAGES, "limits": {"per_hour": self.a.per_hour, "per_visitor_active": self.a.per_visitor_active, "max_active": self.a.max_active},
                "audit_chunks": self.a.audit, "escrow": self.a.escrow, "active": active, "done_total": done, "lanes": len(self.a.key)}

    def recent(self):
        with self.lock:
            refs = list(self.order[-12:])[::-1]
            return {"jobs": [{k: self.jobs[r].get(k) for k in ("ref", "status", "kind", "params", "chunks", "created", "chain_id")} for r in refs]}


def make_handler(gw):
    class H(BaseHTTPRequestHandler):
        server_version = "vearl-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, code, obj=None, raw=None, ctype="application/json"):
            body = raw if raw is not None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def visitor(self):
            # nginx sets X-Real-IP; the key is a salted hash so that no address is kept anywhere
            ip = self.headers.get("X-Real-IP") or self.client_address[0]
            import hashlib
            return hashlib.sha256((gw.a.salt + ip).encode()).hexdigest()[:16]

        def do_GET(self):
            p = self.path.split("?")[0].rstrip("/")
            if p == "/gw/info":
                return self.send(200, gw.info())
            if p == "/gw/recent":
                return self.send(200, gw.recent())
            if p == "/gw/samples/digits":
                if not gw.digits:
                    return self.send(404, {"error": "The digit model is not installed."})
                return self.send(200, {"samples": [{"index": i, "images": sm["images"]} for i, sm in enumerate(gw.digits["samples"])]})
            m = re.fullmatch(r"/gw/jobs/([0-9a-f]{12})(/image\.png)?", p)
            if m:
                j = gw.jobs.get(m.group(1))
                if not j:
                    return self.send(404, {"error": "Unknown job."})
                if m.group(2):
                    f = os.path.join(gw.a.data, "out", j["ref"] + ".png")
                    if not os.path.exists(f):
                        return self.send(404, {"error": "No image for this job."})
                    return self.send(200, raw=open(f, "rb").read(), ctype="image/png")
                return self.send(200, gw.view(j))
            self.send(404, {"error": "Not found."})

        def do_POST(self):
            if self.path.split("?")[0].rstrip("/") != "/gw/jobs":
                return self.send(404, {"error": "Not found."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > 200_000:
                    raise ValueError("Request body must be small JSON.")
                body = json.loads(self.rfile.read(n))
                if not isinstance(body, dict):
                    raise ValueError("Request body must be a JSON object.")
                if n > 2048 and body.get("kind") not in gw.ml_kinds():
                    raise ValueError("Request body must be small JSON.")
                return self.send(201, gw.create(body, self.visitor()))
            except PermissionError as e:
                return self.send(429, {"error": str(e)})
            except (ValueError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})

    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cli", required=True)
    ap.add_argument("--node", required=True, help="a node HOST:PORT (peer port) the service account talks to")
    ap.add_argument("--worker", action="append", required=True, help="a worker node HOST:PORT that serves chunks for the audit (repeat for several; with one and no --public it is THE worker)")
    ap.add_argument("--public", action="store_true", help="the PUBLIC network: any miner may take a job; the worker is looked for among --worker and --peers-file; the exact kinds (n = 128) are off")
    ap.add_argument("--retries", type=int, default=None, help="how many times a job is sent again when the miner that took it cannot be reached for the audit (default 2 with --public, else 0)")
    ap.add_argument("--peers-file", dest="peers_file", default=None, help="the seed node's peers.txt: its reachable addresses are asked too when looking for the worker of a job")
    ap.add_argument("--key", action="append", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--listen", default="127.0.0.1:18600")
    ap.add_argument("--escrow", type=float, default=2.0, help="VRL locked per job (>= 1)")
    ap.add_argument("--audit", type=int, default=4, help="chunks the gateway recomputes per job")
    ap.add_argument("--per-hour", dest="per_hour", type=int, default=6)
    ap.add_argument("--per-visitor-active", dest="per_visitor_active", type=int, default=2)
    ap.add_argument("--max-active", dest="max_active", type=int, default=12)
    ap.add_argument("--wait-miner", dest="wait_miner", type=int, default=900, help="seconds to wait for a miner to post a result")
    ap.add_argument("--wait-finish", dest="wait_finish", type=int, default=150)
    ap.add_argument("--wait-exact", dest="wait_exact", type=int, default=900, help="seconds allowed to one digits / matrix job")
    ap.add_argument("--ml", default=None, help="URL of the ML service (vearl-ml.py) that runs text generation and photo recognition, e.g. http://127.0.0.1:18602")
    ap.add_argument("--wait-ml", dest="wait_ml", type=int, default=1500, help="seconds allowed to one ML job")
    ap.add_argument("--models", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"), help="folder with digits-cnn.json")
    a = ap.parse_args()
    a.retries = (2 if a.public else 0) if a.retries is None else a.retries
    a.workers, a.worker = a.worker, a.worker[0]       # every --worker, and the first one (the exact kinds of the demo chain use that one)
    os.makedirs(a.data, exist_ok=True)
    sp = os.path.join(a.data, "salt")
    if not os.path.exists(sp):
        open(sp, "w").write(secrets.token_hex(16))
    a.salt = open(sp).read().strip()
    if a.escrow < 1:
        sys.exit("--escrow must be at least 1 VRL")
    host, port = a.listen.rsplit(":", 1)
    gw = Gateway(a)
    srv = ThreadingHTTPServer((host, int(port)), make_handler(gw))
    print(f"vearl-gateway on {a.listen} (node {a.node}, worker(s) {', '.join(a.workers)}{', PUBLIC network' if a.public else ''}, {len(a.key)} account(s))", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
