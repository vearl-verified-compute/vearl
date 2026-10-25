#!/usr/bin/env python3
"""Vearl ML service: verified text generation (TinyStories-33M), verified photo recognition (DeiT-Tiny) and verified text embeddings
(Qwen3-Embedding-0.6B) for the compute website.

It runs on the machine that has the GPU worker, the two quantized model files and the Python clients of vearl-core/tools (numpy and the
`transformers` tokenizer / label list are needed). The job gateway on the web server forwards the two ML kinds to it through an ssh tunnel;
it never talks to a browser directly. One job at a time (the service account's transactions need sequential nonces).

  - a story: the prompt is cut in tokens, then for each new word TWO verified jobs run on the chain (the body of the network, then the
    head that scores the 50,257 words); the client picks the word with the highest integer score and repeats;
  - a photo: two chained verified jobs (layers 0-5, then layers 6-11 and the classifier); the photo is deleted as soon as it is read.
  - embeddings: up to 4 short texts go together through the TEN chained verified jobs of Qwen3-Embedding-0.6B (tools/qwen3_client.py); the
    visitor gets the table of cosine similarities between his texts. The workers of this chain must run rc17 or later and hold the model.
  - minilm / bge: the same table with all-MiniLM-L6-v2 (195 operations per text) or BGE-base (three chained jobs per text).

With `--auto-workers` the jobs go to the PUBLIC miners instead of one worker (rc25): the service reads the miners announced to the relay node
(`--node-api`), measures their link and checks which models they hold (routing.py), and gives each job to the fastest miner that can send its
operations in time; a job that fails puts that miner aside. Run it on the machine of the seed: it needs no GPU then.

    python vearl-ml.py --tools vearl-core/tools --cli vearl-cli --node 127.0.0.1:19120 --worker 127.0.0.1:19120 --key seed:4 \\
        --gpt /path/gpt-qat.json --vit /path/vit-qat.json --embed /path/qwen3-embedding-0.6b-int8.json.xz --listen 127.0.0.1:18602
"""
import argparse
import base64
import binascii
import collections
import io
import json
import os
import queue
import re
import secrets
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import routing  # noqa: E402

MAX_BODY = 200_000
MAX_PHOTO = 150_000
MAX_TEXTS = 4
MAX_TEXT_LEN = 140
EXAMPLE_TEXTS = ["The striker scored twice in the final.", "Her goals won the championship for the team.", "The new processor is faster and uses less power."]
KINDS = {
    "gpt": {
        "title": "Text generation",
        "short": "TinyStories-33M · every word verified",
        "summary": "A small language model writes a children's story word by word. Each word costs two verified jobs: the network body, then the head that scores all 50,257 words.",
        "params": {"prompt": {"max_length": 200, "default": "Once upon a time, there was a little cat"}, "words": {"min": 1, "max": 30, "default": 12}},
        "output": "text",
        "family": "ml",
    },
    "vit": {
        "title": "Photo recognition",
        "short": "DeiT-Tiny · 1,000 ImageNet classes",
        "summary": "A vision transformer looks at your photo and names what it sees. Two chained jobs, every operation verified; your photo is deleted right after.",
        "params": {"image": {"max_bytes": MAX_PHOTO}},
        "output": "photo",
        "family": "ml",
    },
    "minilm": {
        "title": "Fast sentence embeddings",
        "short": "all-MiniLM-L6-v2 · 6 layers",
        "summary": "A small language model turns each of your sentences into 384 numbers; sentences that mean the same get close numbers. 195 operations per sentence, every one verified before the miner is paid.",
        "params": {"texts": {"min_items": 1, "max_items": MAX_TEXTS, "max_length": MAX_TEXT_LEN, "default": EXAMPLE_TEXTS}},
        "output": "embedding",
        "family": "ml",
    },
    "bge": {
        "title": "Semantic search embeddings",
        "short": "BGE-base · 110 million parameters",
        "summary": "A 12-layer model turns each of your sentences into 768 numbers, the kind used for semantic search. Three chained jobs per sentence, every operation verified before the miner is paid.",
        "params": {"texts": {"min_items": 1, "max_items": MAX_TEXTS, "max_length": MAX_TEXT_LEN, "default": EXAMPLE_TEXTS}},
        "output": "embedding",
        "family": "ml",
    },
    "embed": {
        "title": "Text embeddings",
        "short": "Qwen3-Embedding-0.6B · 0.6 billion parameters",
        "summary": "A language model of 0.6 billion parameters turns each of your sentences into 1,024 numbers; sentences that mean the same get close numbers. Ten chained jobs per series, every operation verified; you get the table of similarities.",
        "params": {"texts": {"min_items": 1, "max_items": MAX_TEXTS, "max_length": MAX_TEXT_LEN, "default": EXAMPLE_TEXTS}},
        "output": "embedding",
        "family": "ml",
    },
}


# VRL of escrow that a job commits per unit of work (about one VRL per GEMM of 1024^3, `--escrow`): a photo, a text, a word of a story, a series of texts.
# Estimates (resnet measured: 22 VRL per photo); the daily budget counts with them.
COST_VRL = {"resnet": 22, "minilm": 61, "bge": 305, "gpt": 52, "vit": 80, "embed": 700}
PRIVACY = (" The job is computed by a miner of the network, who can see what you send: do not send anything private.")


class Service:
    def __init__(self, a):
        self.a = a
        sys.path.insert(0, os.path.abspath(a.tools))
        import numpy as np  # noqa: F401
        self.np = np
        self.jobs = {}
        self.order = []
        self.lock = threading.Lock()
        self.q = queue.Queue()
        self.gpt = self.vit = self.embed = self.minilm = self.bge = self.resnet = None
        self.spent = {}                    # day (UTC) -> estimated VRL committed that day, for --daily-budget
        self.router = None
        if a.auto_workers:
            models = {"minilm": a.minilm, "bge": a.bge, "gpt": a.gpt, "vit": a.vit, "resnet": a.resnet}
            self.router = routing.Router(a.relay, a.node_api, a.cli, models={k: v for k, v in models.items() if v})
            threading.Thread(target=self.watch_workers, daemon=True).start()
        t0 = time.time()
        if a.gpt:
            import gpt_client
            self.gpt = gpt_client.GptClient(a.gpt, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"text model loaded ({time.time() - t0:.0f} s)", flush=True)
        if a.vit:
            import vit_client
            self.vit = vit_client.VitClient(a.vit, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"photo model loaded ({time.time() - t0:.0f} s)", flush=True)
        if a.embed:
            import qwen3_client
            self.embed = qwen3_client.Qwen3EmbedClient(a.embed, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"embedding model loaded ({time.time() - t0:.0f} s)", flush=True)
        if a.minilm:
            import minilm_client
            self.minilm = minilm_client.MiniLMEmbedClient(a.minilm, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"MiniLM loaded ({time.time() - t0:.0f} s)", flush=True)
        if a.resnet:
            import resnet_client
            self.resnet = resnet_client.ResnetClient(a.resnet, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"ResNet loaded ({time.time() - t0:.0f} s)", flush=True)
        if a.bge:
            import bert_client
            self.bge = bert_client.BertEmbedClient(a.bge, a.node, a.worker, key=a.key, escrow_per_gemm=a.escrow, cli=a.cli)
            print(f"BGE loaded ({time.time() - t0:.0f} s)", flush=True)
        threading.Thread(target=self.loop, daemon=True).start()

    def kinds(self):
        have = {"gpt": self.gpt, "vit": self.vit, "embed": self.embed, "minilm": self.minilm, "bge": self.bge, "resnet": self.resnet}
        out = {k: v for k, v in KINDS.items() if have.get(k)}
        if self.router:
            # public miners: offered only while a miner that holds the model and has a fast enough link is online, and with the notice
            out = {k: dict(v, summary=v["summary"] + PRIVACY) for k, v in out.items() if self.router.pick(k) is not None}
        return out

    def budget_ok(self, kind, units=1):
        """The daily budget (`--daily-budget` VRL, estimated) must not be exceeded; reserves the cost when it is not."""
        if not self.a.daily_budget:
            return True
        day = time.strftime("%Y-%m-%d", time.gmtime())
        cost = COST_VRL.get(kind, 100) * max(1, units)
        with self.lock:
            self.spent = {day: self.spent.get(day, 0)}
            if self.spent[day] + cost > self.a.daily_budget:
                return False
            self.spent[day] += cost
        return True

    # -- miners (routing.py)
    def watch_workers(self):
        while True:
            try:
                self.router.refresh()
                for k in list(self.router.models) + ["embed"]:
                    self.router.choose(k)          # measures what is missing or old, so that the list of kinds above is fresh
            except Exception as ex:  # the node API may be restarting
                print("workers list:", repr(ex), file=sys.stderr, flush=True)
            time.sleep(30)

    def route(self, j, client, kind, units=1):
        """The miner for this piece of work (None = the single configured worker). Sets `client.worker`; raises when nobody qualifies."""
        if not self.router:
            return None
        got = self.router.choose(kind, units)
        if not got:
            raise RuntimeError("No miner can take this job right now: it needs a miner that holds the model and has a fast enough link.")
        w, addr = got
        client.worker = addr
        self.note(j, "A miner was chosen (%s, %.0f Mbit/s measured)." % ("through the relay" if w.via_relay() else "direct connection", w.mbit))
        return w

    # -- requests
    def create(self, body):
        kind = body.get("kind")
        if kind not in self.kinds():
            raise ValueError("Unknown or unavailable job type.")
        if self.q.qsize() >= self.a.max_queue:
            raise PermissionError("The ML service is busy. Try again in a few minutes.")
        j = {"ref": secrets.token_hex(6), "kind": kind, "status": "queued", "created": int(time.time()), "times": {"queued": int(time.time())},
             "progress": [], "result": None, "message": None}
        if kind == "gpt":
            prompt = body.get("prompt", "")
            if not isinstance(prompt, str) or not 1 <= len(prompt.strip()) <= 200:
                raise ValueError("The prompt must be between 1 and 200 characters.")
            prompt = re.sub(r"\s+", " ", "".join(ch if 32 <= ord(ch) < 127 or ch in "\n\t" else " " for ch in prompt)).strip()
            words = body.get("words", 12)
            if isinstance(words, bool) or not isinstance(words, int) or not 1 <= words <= 30:
                raise ValueError("'words' must be a whole number between 1 and 30.")
            j["params"] = {"kind": kind, "prompt": prompt, "words": words}
            j["_in"] = (prompt, words)
        elif kind in ("embed", "minilm", "bge"):
            texts = body.get("texts")
            if not isinstance(texts, list) or not 1 <= len(texts) <= MAX_TEXTS or not all(isinstance(t, str) for t in texts):
                raise ValueError("Send between 1 and %d texts." % MAX_TEXTS)
            clean = []
            for t in texts:
                t = re.sub(r"\s+", " ", "".join(ch if ch.isprintable() else " " for ch in t)).strip()
                if not 1 <= len(t) <= MAX_TEXT_LEN:
                    raise ValueError("Each text must be between 1 and %d characters." % MAX_TEXT_LEN)
                clean.append(t)
            j["params"] = {"kind": kind, "texts": clean}
            j["_in"] = clean
        else:
            raw = body.get("image", "")
            m = re.fullmatch(r"data:image/(jpeg|png);base64,([A-Za-z0-9+/=\s]+)", raw if isinstance(raw, str) else "")
            if not m:
                raise ValueError("Send the photo as a JPEG or PNG data URL.")
            try:
                data = base64.b64decode(m.group(2), validate=False)
            except binascii.Error:
                raise ValueError("The photo could not be decoded.")
            if len(data) > MAX_PHOTO:
                raise ValueError("The photo is too large (150 KB at most after the browser shrinks it).")
            j["params"] = {"kind": kind}
            j["_in"] = data
        units = len(j["_in"]) if kind in ("minilm", "bge") else (j["_in"][1] if kind == "gpt" else 1)     # only a request that passed the checks above costs budget
        if not self.budget_ok(kind, units):
            raise PermissionError("The job service reached its budget for today. Try again tomorrow.")
        with self.lock:
            self.jobs[j["ref"]] = j
            self.order.append(j["ref"])
            for r in self.order[:-200]:
                self.jobs.pop(r, None)
            self.order = self.order[-200:]
        self.q.put(j["ref"])
        return self.view(j)

    def view(self, j):
        return {k: j.get(k) for k in ("ref", "kind", "status", "created", "times", "params", "progress", "result", "message")}

    def set(self, j, status=None, **kw):
        with self.lock:
            if status:
                j["status"] = status
                j["times"][status] = int(time.time())
            j.update(kw)

    def note(self, j, text):
        with self.lock:
            if not j["progress"] or j["progress"][-1] != text:
                j["progress"].append(text)

    # -- work
    def loop(self):
        while True:
            ref = self.q.get()
            j = self.jobs.get(ref)
            if not j:
                continue
            try:
                self.set(j, "running")
                {"gpt": self.run_gpt, "vit": self.run_vit, "resnet": self.run_resnet, "embed": self.run_embed, "minilm": self.run_texts, "bge": self.run_texts}[j["kind"]](j)
            except Exception as ex:  # a failed job must never stop the service
                print("job", ref, "failed:", repr(ex), file=sys.stderr, flush=True)
                self.set(j, "failed", message="The job did not complete: " + (str(ex).splitlines()[0][:160] if str(ex) else "internal error"))
            finally:
                j.pop("_in", None)

    def run_gpt(self, j):
        c, np = self.gpt, self.np
        prompt, words = j["_in"]
        seq = c.tk(prompt)["input_ids"][: c.L - 1]
        start = len(seq)
        t0 = time.time()
        self.note(j, "The prompt was cut in %d tokens." % start)
        for k in range(words):
            w = self.route(j, c, "gpt")
            try:
                row = c.step([seq])[0]                                 # two verified jobs: body, then head
            except Exception:
                if w:
                    self.router.failed(w)
                raise
            if w:
                self.router.succeeded(w)
            nxt = int(np.argmax(row))                                  # greedy: highest integer score, lowest id on a tie
            seq = seq + [nxt]
            text = c.tk.decode([t for t in seq if t != c.eos])
            self.set(j, result={"type": "text", "prompt": prompt, "text": text, "words": k + 1, "wanted": words, "seconds": round(time.time() - t0, 1)})
            self.note(j, "Word %d chosen from 50,257 scores; both jobs verified." % (k + 1))
            if nxt == c.eos or len(seq) >= c.L:
                break
        self.set(j, "done", message="Every word was verified before the miner was paid.")

    def run_embed(self, j):
        c, np = self.embed, self.np
        texts = j["_in"]
        t0 = time.time()
        self.note(j, "%d text%s cut in tokens; ten chained jobs will run, all texts together." % (len(texts), "s" if len(texts) > 1 else ""))
        w = self.route(j, c, "embed")
        try:
            E = c.embed(texts, progress=lambda k, n: self.note(j, "Chained job %d of %d verified operation by operation." % (k, n)))
        except Exception:
            if w:
                self.router.failed(w)
            raise
        if w:
            self.router.succeeded(w)
        S = E @ E.T
        res = {"type": "embedding", "texts": texts, "dim": int(E.shape[1]), "similarity": [[round(float(v), 3) for v in row] for row in S],
               "head": [[round(float(v), 4) for v in row[:8]] for row in E], "seconds": round(time.time() - t0, 1)}
        self.set(j, "done", result=res, message="Every operation of the ten jobs was verified before the miner was paid.")

    def run_texts(self, j):
        """MiniLM and BGE: the table of cosine similarities between the texts of the visitor."""
        kind = j["kind"]
        c, np = (self.minilm if kind == "minilm" else self.bge), self.np
        texts = j["_in"]
        t0 = time.time()
        self.note(j, "%d text%s cut in tokens; every operation will be verified before the miner is paid." % (len(texts), "s" if len(texts) > 1 else ""))
        w = self.route(j, c, kind, len(texts))
        try:
            E = c.embed(texts).astype("float64")
        except Exception:
            if w:
                self.router.failed(w)
            raise
        if w:
            self.router.succeeded(w)
        E = E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-12)
        S = E @ E.T
        res = {"type": "embedding", "texts": texts, "dim": int(E.shape[1]), "similarity": [[round(float(v), 3) for v in row] for row in S],
               "head": [[round(float(v), 4) for v in row[:8]] for row in E], "seconds": round(time.time() - t0, 1)}
        self.set(j, "done", result=res, message="Every operation was verified before the miner was paid.")

    def run_resnet(self, j):
        c, np = self.resnet, self.np
        from PIL import Image
        t0 = time.time()
        im = Image.open(io.BytesIO(j["_in"]))
        im.load()
        j["_in"] = None                                                # the upload is dropped from memory
        arr = c.prepare(im)
        self.note(j, "The photo was prepared (32 × 32).")
        w = self.route(j, c, "resnet")
        try:
            logits = c.classify_arrays([arr])[0]
        except Exception:
            if w:
                self.router.failed(w)
            raise
        if w:
            self.router.succeeded(w)
        top = c.top(logits, 3)
        res = {"type": "photo", "top": [{"index": i, "name": name, "prob": round(prob, 4), "score": score} for i, name, prob, score in top],
               "seconds": round(time.time() - t0, 1)}
        self.note(j, "All 76 operations were verified.")
        self.set(j, "done", result=res, message="Verified. The photo was deleted.")

    def run_vit(self, j):
        c, np = self.vit, self.np
        from PIL import Image
        t0 = time.time()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "photo.jpg")
            im = Image.open(io.BytesIO(j["_in"]))
            im.load()
            im = im.convert("RGB")
            if max(im.size) > 1024:
                im.thumbnail((1024, 1024))
            im.save(path, "JPEG", quality=92)
            j["_in"] = None                                            # the upload is dropped from memory too; the file goes with the temp dir
            self.note(j, "The photo was prepared (224 × 224).")
            w = self.route(j, c, "vit")
            try:
                top = c.classify([path])[0]
            except Exception:
                if w:
                    self.router.failed(w)
                raise
            if w:
                self.router.succeeded(w)
        idx, name, logits = top
        s = float(c.plan.get("s_logit", 1.0))
        z = logits.astype("float64") * s
        z -= z.max()
        p = np.exp(z)
        p /= p.sum()
        best = np.argsort(-logits, kind="stable")[:5]
        res = {"type": "photo", "top": [{"index": int(i), "name": str(c.labels[int(i)]).split(",")[0], "prob": round(float(p[i]), 4), "score": int(logits[i])} for i in best],
               "seconds": round(time.time() - t0, 1)}
        self.note(j, "Both jobs were verified operation by operation.")
        self.set(j, "done", result=res, message="Verified. The photo was deleted.")


def make_handler(svc):
    class H(BaseHTTPRequestHandler):
        server_version = "vearl-ml"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = self.path.split("?")[0].rstrip("/")
            if p == "/ml/info":
                return self.send(200, {"kinds": svc.kinds(), "queued": svc.q.qsize()})
            m = re.fullmatch(r"/ml/jobs/([0-9a-f]{12})", p)
            if m and m.group(1) in svc.jobs:
                return self.send(200, svc.view(svc.jobs[m.group(1)]))
            self.send(404, {"error": "Not found."})

        def do_POST(self):
            if self.path.split("?")[0].rstrip("/") != "/ml/jobs":
                return self.send(404, {"error": "Not found."})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > MAX_BODY:
                    raise ValueError("Request body too large or empty.")
                body = json.loads(self.rfile.read(n))
                if not isinstance(body, dict):
                    raise ValueError("Request body must be a JSON object.")
                return self.send(201, svc.create(body))
            except PermissionError as e:
                return self.send(429, {"error": str(e)})
            except (ValueError, json.JSONDecodeError) as e:
                return self.send(400, {"error": str(e)})

    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tools", required=True, help="vearl-core/tools (gpt_client.py, vit_client.py, vearl_ref.py)")
    ap.add_argument("--cli", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--worker", default="", help="the single GPU worker (not needed with --auto-workers)")
    ap.add_argument("--auto-workers", dest="auto_workers", action="store_true", help="give each job to a public miner (routing.py)")
    ap.add_argument("--relay", default="127.0.0.1:9000", help="HOST:PORT of the relay node (the seed), for miners that cannot be dialed")
    ap.add_argument("--node-api", dest="node_api", default="http://127.0.0.1:8545", help="HTTP API of the relay node (/api/workers)")
    ap.add_argument("--key", default="seed:4")
    ap.add_argument("--gpt", help="quantized text model (qat_gpt.py output)")
    ap.add_argument("--vit", help="quantized photo model (qat_vit.py output)")
    ap.add_argument("--embed", help="Qwen3-Embedding-0.6B model file (tools/quantize_qwen3.py output, optionally .xz)")
    ap.add_argument("--resnet", help="quantized ResNet-20 (tools/qat_graph.py resnet output)")
    ap.add_argument("--daily-budget", dest="daily_budget", type=float, default=0.0, help="most VRL (estimated escrow) the service commits per UTC day; 0 = no limit")
    ap.add_argument("--minilm", help="quantized MiniLM (tools/qat_minilm.py output)")
    ap.add_argument("--bge", help="quantized BGE-base (tools/qat_bert.py output)")
    ap.add_argument("--escrow", type=float, default=1.0, help="VRL per operation product (>= 1)")
    ap.add_argument("--max-queue", dest="max_queue", type=int, default=6)
    ap.add_argument("--listen", default="127.0.0.1:18602")
    a = ap.parse_args()
    if not (a.gpt or a.vit or a.embed or a.minilm or a.bge or a.resnet):
        sys.exit("give at least one of --gpt / --vit / --embed / --minilm / --bge / --resnet")
    if not (a.worker or a.auto_workers):
        sys.exit("give --worker, or --auto-workers")
    host, port = a.listen.rsplit(":", 1)
    svc = Service(a)
    srv = ThreadingHTTPServer((host, int(port)), make_handler(svc))
    print(f"vearl-ml on {a.listen}: {', '.join(svc.kinds())}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
