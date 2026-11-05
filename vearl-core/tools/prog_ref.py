#!/usr/bin/env python3
"""INDEPENDENT validator of verifiable tensor programs (CNN, transformer: convolutions, pooling, residuals, GemmAT,
integer softmax and LayerNorm): job state machine, `Op` work blocks, and the FOUR fraud proofs (Gemm, Act, Elem, Col).
Written from docs/07-work-specification.md section 12. Re-validates a chain produced by `vearl-prog-vectors`.

    ../target/release/vearl-prog-vectors > prog.json
    python3 prog_ref.py prog.json        # pip install blake3 numpy cryptography
"""
import base64, copy, json, struct, sys
import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import spec_ref as S
import chain_ref as C
import vearl_ref as R
import market_ref as M

N = 128
MAX_OPS, MAX_WEIGHTS, MAX_SHIFT = 240, 64, 24
MAX_SOFTMAX_SCALE = 4
MAX_RMS_SHIFT = 4


class Invalid(Exception):
    pass


u8 = lambda x: struct.pack("<B", x)
u16 = lambda x: struct.pack("<H", x)
u32 = lambda x: struct.pack("<I", x)
u64 = lambda x: struct.pack("<Q", x)
hb = lambda lst: bytes(lst)                       # list of integers 0..255 -> bytes (32-byte hash)
i8b = lambda lst: bytes(v & 0xFF for v in lst)    # list of i8 -> bytes


def vec(items, enc):
    return u64(len(items)) + b"".join(enc(x) for x in items)


# ---------------- bincode encoding (from the JSON serde form of the reference node) ----------------
def enc_op(op):
    ((k, p),) = op.items()
    b = lambda name: u8(p[name])
    if k == "Gemm":
        return u32(0) + b("w") + b("x") + b("shift") + u8(int(p["relu"]))
    if k == "Add":
        return u32(1) + b("a") + b("b") + u8(int(p["relu"]))
    if k == "Map":
        m = p["map"]
        if m == "Transpose":
            return u32(2) + b("x") + u32(0)
        ((mk, mp),) = m.items()
        if mk == "Shift":
            return u32(2) + b("x") + u32(4) + u16(mp["dr"]) + u16(mp["dc"])
        if mk in ("HeadSpread", "HeadGather"):
            return u32(2) + b("x") + u32(5 if mk == "HeadSpread" else 6) + u16(mp["dh"]) + u16(mp["heads"]) + u16(mp["l"])
        if mk == "Conv":
            return u32(2) + b("x") + u32(3) + u16(mp["c_in"]) + u16(mp["h"]) + u16(mp["w"]) + u16(mp["batch"]) + u8(mp["kh"]) + u8(mp["kw"]) + u8(mp["pad"]) + u8(mp["stride"])
        if mk == "Im2col":
            return u32(2) + b("x") + u32(1) + u16(mp["c_in"]) + u16(mp["h"]) + u16(mp["w"]) + u16(mp["batch"]) + u8(mp["kh"]) + u8(mp["kw"]) + u8(mp["pad"])
        return u32(2) + b("x") + u32(2) + u16(mp["c"]) + u16(mp["h"]) + u16(mp["w"]) + u16(mp["batch"])
    if k == "Pool":
        ((pk, mp),) = p["pool"].items()
        return u32(3) + b("x") + u32(0 if pk == "Avg" else 1) + u16(mp["c"]) + u16(mp["h"]) + u16(mp["w"]) + u16(mp["batch"]) + u8(mp["k"])
    if k == "GemmAT":
        return u32(4) + b("a") + b("x") + b("shift") + u8(int(p["relu"]))
    if k == "Softmax":
        return u32(5) + b("x") + u16(p["len"])
    if k == "LayerNorm":
        return u32(6) + b("x") + u16(p["len"])
    if k == "Bias":
        return u32(7) + b("x") + b("w") + u16(p["row"]) + u8(int(p["relu"]))
    if k == "Lut":
        return u32(8) + b("x") + b("w") + u16(p["row"])
    if k == "Mul":
        return u32(9) + b("x") + b("w") + u16(p["row"]) + b("shift")
    if k == "SoftmaxLo":
        return u32(10) + b("x") + u16(p["len"])
    if k == "CausalSoftmax":
        return u32(11) + b("x") + u16(p["len"]) + u16(p["l"]) + u8(int(p["fine"]))
    if k == "CausalSoftmaxS":
        return u32(15) + b("x") + u16(p["len"]) + u16(p["l"]) + u8(int(p["fine"])) + b("scale")
    if k == "RmsNorm":
        return u32(12) + b("x") + u16(p["len"]) + u16(p["group"]) + b("shift")
    if k == "MulT":
        return u32(13) + b("a") + b("b") + b("shift")
    if k == "MulW":
        return u32(14) + b("x") + b("w") + b("shift")
    raise ValueError(op)


def enc_fraud(f):
    ((k, p),) = f.items()
    path = lambda name: vec(p[name], lambda h: hb(h))
    if k == "Gemm":
        return (u32(0) + u32(p["i"]) + u32(p["j"]) + vec(p["w_row"], lambda v: i8b([v])) + path("w_path") + vec(p["x_col"], lambda v: i8b([v])) + path("x_path")
                + vec(p["z_row"], lambda v: struct.pack("<i", v)) + path("z_path"))
    if k == "Act":
        return u32(1) + u32(p["i"]) + u32(p["j"]) + vec(p["z_row"], lambda v: struct.pack("<i", v)) + path("z_path") + vec(p["out_col"], lambda v: i8b([v])) + path("out_path")
    if k == "Elem":
        ins = vec(p["ins"], lambda o: u8(o["tensor"]) + u32(o["col"]) + vec(o["vals"], lambda v: i8b([v])) + vec(o["path"], lambda h: hb(h)))
        return u32(2) + u32(p["i"]) + u32(p["j"]) + ins + vec(p["out_col"], lambda v: i8b([v])) + path("out_path")
    if k == "Col":
        return u32(3) + u32(p["j"]) + vec(p["in_col"], lambda v: i8b([v])) + path("in_path") + vec(p["out_col"], lambda v: i8b([v])) + path("out_path")
    if k == "Bias":
        return (u32(4) + u32(p["j"]) + vec(p["in_col"], lambda v: i8b([v])) + path("in_path") + vec(p["b_row"], lambda v: i8b([v])) + path("b_path")
                + vec(p["out_col"], lambda v: i8b([v])) + path("out_path"))
    if k == "Lut":
        return (u32(5) + u32(p["j"]) + vec(p["in_col"], lambda v: i8b([v])) + path("in_path") + vec(p["t_row"], lambda v: i8b([v])) + path("t_path")
                + vec(p["out_col"], lambda v: i8b([v])) + path("out_path"))
    if k == "MulW":
        return (u32(6) + u32(p["i"]) + u32(p["j"]) + vec(p["in_col"], lambda v: i8b([v])) + path("in_path") + vec(p["w_row"], lambda v: i8b([v])) + path("w_path")
                + vec(p["out_col"], lambda v: i8b([v])) + path("out_path"))
    raise ValueError(k)


def enc_kind(kind):
    ((k, p),) = kind.items()
    if k == "Transfer":
        return u32(0) + hb(p["to"]) + u64(p["amount"])
    assert k == "Prog"
    ((pk_, q),) = p.items()
    j = lambda: hb(q["job_id"])
    if pk_ == "Submit":
        return (u32(14) + u32(0) + hb(q["x0_root"]) + vec(q["w_roots"], lambda h: hb(h)) + vec(q["ops"], enc_op) + u64(q["escrow"]) + u64(q["deadline"]))
    if pk_ == "Claim":
        return u32(14) + u32(1) + j()
    if pk_ == "PostOp":
        return u32(14) + u32(2) + j() + u8(q["op"]) + hb(q["z_root"]) + hb(q["x_root"])
    if pk_ == "Accept":
        return u32(14) + u32(3) + j()
    if pk_ == "Fraud":
        return u32(14) + u32(4) + j() + u8(q["op"]) + enc_fraud(q["kind"])
    if pk_ == "Settle":
        return u32(14) + u32(5) + j()
    if pk_ == "PostBatch":
        return u32(14) + u32(6) + j() + u8(q["op"]) + vec(q["posts"], lambda zx: hb(zx[0]) + hb(zx[1]))
    if pk_ == "Fetch":
        return u32(14) + u32(7) + j() + u8(q["tensor"]) + u32(q["col"])
    if pk_ == "Serve":
        return u32(14) + u32(8) + j() + u8(q["tensor"]) + u32(q["col"]) + vec(q["vals"], lambda v: i8b([v])) + vec(q["path"], lambda h: hb(h))
    if pk_ == "SlashUnserved":
        return u32(14) + u32(9) + j()
    raise ValueError(pk_)


def tx_bytes(t):
    return bytes.fromhex(t["from"]) + u64(t["nonce"]) + u64(t["fee"]) + enc_kind(t["kind"])


def tx_id(t):
    sig = bytes.fromhex(t["sig"])
    return S.H("vearl/tx/v1", tx_bytes(t) + u64(len(sig)) + sig)


def prog_id(client_hex, nonce, x0_root, w_roots, ops):
    return S.H("vearl/prog/v1", bytes.fromhex(client_hex), u64(nonce), x0_root, vec(ops, enc_op), *w_roots)


def conv_out_dims(h, w, kh, kw, pad, stride):
    if stride == 0 or h + 2 * pad < kh or w + 2 * pad < kw:
        return None
    return ((h + 2 * pad - kh) // stride + 1, (w + 2 * pad - kw) // stride + 1)


# ---------------- program validation (docs/07 section 12) ----------------
def validate_ops(ops, n_weights, n=N):
    if not ops or len(ops) > MAX_OPS or n_weights > MAX_WEIGHTS:
        raise Invalid("program size")
    for k, op in enumerate(ops):
        ((kind, p),) = op.items()
        ok_t = lambda t: t <= k
        if kind == "Gemm":
            ok = p["w"] < n_weights and ok_t(p["x"]) and p["shift"] <= MAX_SHIFT
        elif kind == "GemmAT":
            ok = ok_t(p["a"]) and ok_t(p["x"]) and p["shift"] <= MAX_SHIFT
        elif kind in ("Softmax", "SoftmaxLo", "LayerNorm"):
            ok = ok_t(p["x"]) and p["x"] >= 1 and p["len"] >= 1 and p["len"] <= n
        elif kind == "CausalSoftmax":
            ok = ok_t(p["x"]) and p["x"] >= 1 and p["len"] >= 1 and p["len"] <= n and p["l"] >= 1 and p["l"] <= n
        elif kind == "CausalSoftmaxS":
            ok = ok_t(p["x"]) and p["x"] >= 1 and p["len"] >= 1 and p["len"] <= n and p["l"] >= 1 and p["l"] <= n and p["scale"] <= MAX_SOFTMAX_SCALE
        elif kind == "RmsNorm":
            ok = ok_t(p["x"]) and p["x"] >= 1 and p["len"] >= 1 and p["len"] <= n and p["group"] >= 1 and p["group"] <= p["len"] and p["len"] % p["group"] == 0 and p["shift"] <= MAX_RMS_SHIFT
        elif kind == "MulT":
            ok = ok_t(p["a"]) and ok_t(p["b"]) and p["shift"] <= MAX_SHIFT
        elif kind == "MulW":
            ok = ok_t(p["x"]) and p["w"] < n_weights and p["shift"] <= MAX_SHIFT
        elif kind == "Add":
            ok = ok_t(p["a"]) and ok_t(p["b"])
        elif kind in ("Bias", "Lut"):
            ok = ok_t(p["x"]) and p["w"] < n_weights and p["row"] < n
        elif kind == "Mul":
            ok = ok_t(p["x"]) and p["w"] < n_weights and p["row"] < n and p["shift"] <= MAX_SHIFT
        elif kind == "Map":
            m = p["map"]
            ok = ok_t(p["x"])
            if m != "Transpose":
                ((mk, mp),) = m.items()
                if mk == "Flatten":
                    c, h, w, b = mp["c"], mp["h"], mp["w"], mp["batch"]
                    ok = ok and min(c, h, w, b) > 0 and c * h * w <= n and h * w * b <= n and c <= n
                elif mk == "Shift":
                    ok = ok and mp["dr"] < n and mp["dc"] < n
                elif mk in ("HeadSpread", "HeadGather"):
                    ok = ok and mp["dh"] > 0 and mp["heads"] > 0 and mp["l"] > 0 and mp["heads"] * mp["dh"] <= n and mp["heads"] * mp["l"] <= n
                elif mk == "Conv":
                    ci, h, w, b, kh, kw, pad, st = (mp[x] for x in ("c_in", "h", "w", "batch", "kh", "kw", "pad", "stride"))
                    dims = conv_out_dims(h, w, kh, kw, pad, st)
                    ok = ok and dims is not None and min(ci, h, w, b, kh, kw) > 0 and ci * kh * kw <= n and h * w * b <= n and dims[0] * dims[1] * b <= n and ci <= n and pad < kh + kw and st >= 1
                else:
                    ci, h, w, b, kh, kw, pad = (mp[x] for x in ("c_in", "h", "w", "batch", "kh", "kw", "pad"))
                    ok = ok and min(ci, h, w, b, kh, kw) > 0 and ci * kh * kw <= n and h * w * b <= n and ci <= n and pad < kh + kw
        elif kind == "Pool":
            ((_, mp),) = p["pool"].items()
            ok = ok_t(p["x"]) and mp["k"] >= 1 and mp["h"] % mp["k"] == 0 and mp["w"] % mp["k"] == 0 and mp["c"] <= n and mp["h"] * mp["w"] * mp["batch"] <= n
        else:
            ok = False
        if not ok:
            raise Invalid("invalid operation")


# ---------------- element-wise operations, SCALAR version (for the fraud proofs) ----------------
def op_inputs(op, i, j, n=N):
    """Source cells (tensor, row, column) of the output (i, j) of an Add / Map / Pool operation; empty list => output 0."""
    ((kind, p),) = op.items()
    if kind in ("Add", "MulT"):
        return [(p["a"], i, j), (p["b"], i, j)]
    if kind == "Map":
        m = p["map"]
        if m == "Transpose":
            return [(p["x"], j, i)]
        ((mk, mp),) = m.items()
        if mk == "Flatten":
            c, h, w, b = mp["c"], mp["h"], mp["w"], mp["batch"]
            if i >= c * h * w or j >= b or i >= n or j >= n:
                return []
            ch, rem = divmod(i, h * w)
            py, px = divmod(rem, w)
            return [(p["x"], ch, (py * w + px) * b + j)]
        if mk == "Shift":
            si, sj = i + mp["dr"], j + mp["dc"]
            if i >= n or j >= n or si >= n or sj >= n:
                return []
            return [(p["x"], si, sj)]
        if mk == "HeadSpread":                          # out[i][h*l + j] = in[i][j], h = i // dh
            dh, H, l = mp["dh"], mp["heads"], mp["l"]
            if i >= H * dh or i >= n or j >= n:
                return []
            h = i // dh
            if not (h * l <= j < h * l + l):
                return []
            return [(p["x"], i, j - h * l)]
        if mk == "HeadGather":                          # out[i][j] = in[i][(i // dh)*l + j]
            dh, H, l = mp["dh"], mp["heads"], mp["l"]
            if i >= H * dh or j >= l or i >= n or j >= n:
                return []
            sj = (i // dh) * l + j
            return [] if sj >= n else [(p["x"], i, sj)]
        if mk == "Conv":
            ci, h, w, b, kh, kw, pad, st = (mp[x] for x in ("c_in", "h", "w", "batch", "kh", "kw", "pad", "stride"))
            dims = conv_out_dims(h, w, kh, kw, pad, st)
            if dims is None:
                return []
            oh, ow = dims
            if i >= ci * kh * kw or j >= oh * ow * b or i >= n or j >= n:
                return []
            c, rem = divmod(i, kh * kw)
            dy, dx = divmod(rem, kw)
            pos, bb = divmod(j, b)
            oy, ox = divmod(pos, ow)
            sy, sx = oy * st + dy - pad, ox * st + dx - pad
            if sy < 0 or sx < 0 or sy >= h or sx >= w:
                return []
            return [(p["x"], c, (sy * w + sx) * b + bb)]
        ci, h, w, b, kh, kw, pad = (mp[x] for x in ("c_in", "h", "w", "batch", "kh", "kw", "pad"))
        if i >= ci * kh * kw or j >= h * w * b or i >= n or j >= n:
            return []
        c, rem = divmod(i, kh * kw)
        dy, dx = divmod(rem, kw)
        pos, bb = divmod(j, b)
        py, px = divmod(pos, w)
        sy, sx = py + dy - pad, px + dx - pad
        if sy < 0 or sx < 0 or sy >= h or sx >= w:
            return []
        return [(p["x"], c, (sy * w + sx) * b + bb)]
    if kind == "Pool":
        ((_, mp),) = p["pool"].items()
        c, h, w, b, k = (mp[x] for x in ("c", "h", "w", "batch", "k"))
        oh, ow = h // k, w // k
        if i >= c or j >= oh * ow * b or i >= n or j >= n:
            return []
        pos, bb = divmod(j, b)
        y, xx = divmod(pos, ow)
        return [(p["x"], i, ((y * k + dy) * w + xx * k + dx) * b + bb) for dy in range(k) for dx in range(k)]
    raise ValueError(kind)


def op_eval(op, vals):
    ((kind, p),) = op.items()
    if kind == "Add":
        return int(np.clip(vals[0] + vals[1], 0 if p["relu"] else -64, 64))
    if kind == "MulT":
        return int(np.clip((vals[0] * vals[1]) >> p["shift"], -64, 64))
    if kind == "Map":
        return vals[0] if vals else 0
    if kind == "Pool":
        ((_, mp),) = p["pool"].items()
        if not vals:
            return 0
        k2 = mp["k"] * mp["k"]
        if next(iter(p["pool"])) == "Max":
            return max(vals)
        return (sum(vals) + k2 // 2) // k2
    raise ValueError(kind)


def col_op(op, col, j):
    """Output column j of a per-column operation (causal softmax: the query q = j mod l only sees the keys 0..q)."""
    ((kind, p),) = op.items()
    a = np.array(col, dtype=np.int64).reshape(-1, 1)
    if kind == "CausalSoftmax":
        eff = min(p["len"], j % p["l"] + 1)
        f = R._softmax_lo if p["fine"] else R._softmax
        return [int(v) for v in f(a, eff).reshape(-1)]
    if kind == "CausalSoftmaxS":
        eff = min(p["len"], j % p["l"] + 1)
        f = R._softmax_lo if p["fine"] else R._softmax
        return [int(v) for v in f(a, eff, p["scale"]).reshape(-1)]
    if kind == "RmsNorm":
        return [int(v) for v in R._rmsnorm(a, p["len"], p["group"], p["shift"]).reshape(-1)]
    f = {"Softmax": R._softmax, "SoftmaxLo": R._softmax_lo, "LayerNorm": R._layernorm}[kind]
    return [int(v) for v in f(a, p["len"]).reshape(-1)]


def act(z, shift, relu):
    return int(np.clip(z >> shift, 0 if relu else -64, 64))


def depth_for(count):
    d = 0
    while (1 << d) < count:
        d += 1
    return d


def vp(root, leaf, idx, path, depth):
    return M.verify_path(root, leaf, idx, [hb(x) for x in path], depth)


class ProgChain:
    def __init__(self, V):
        g = V["genesis"]
        self.g, self.c, self.p, self.timing = g, g["constants"], g["params"], g["timing"]
        self.bal = {a["key"]: a["amount"] for a in g["alloc"]}
        self.genesis_supply = sum(self.bal.values())
        self.nonce, self.rep, self.progs = {}, {}, {}
        self.minted = self.burned = 0
        self.headers, self.native = [], {}
        self.native_roots = {}
        self.bind = True   # attach the test data to the published roots (disabled by the differential fuzz)
        self.tip_ts, self.tip_hash, self.target = g["timestamp"], b"\x00" * 32, g["target"]
        # data of the programs, attached to their COMMITMENTS: (root of X0, roots of the weights)
        self.data = {}
        for d in V["prog_data"]:
            dec = lambda s: np.frombuffer(base64.b64decode(s), dtype=np.int8).astype(np.int64).reshape(N, N)
            x0, ws, tens = dec(d["x0"]), [dec(w) for w in d["ws"]], [dec(t) for t in d["tensors"]]
            x0r = self.croot(x0)
            wrs = tuple(self.rroot(w) for w in ws)
            zs = [None if z is None else np.frombuffer(base64.b64decode(z), dtype="<i4").astype(np.int64).reshape(N, N) for z in d["zs"]]
            self.data[(x0r, wrs)] = dict(x0=x0, ws=ws, tens=tens, zs=zs)

    @staticmethod
    def rroot(m):
        return S.merkle_root([S.leaf_hash(i, S.i8bytes(m[i])) for i in range(N)])

    @staticmethod
    def croot(m):
        return S.merkle_root([S.leaf_hash(j, S.i8bytes(m[:, j])) for j in range(N)])

    @staticmethod
    def zroot(z):
        return S.c_root(z)

    def credit(self, k, x):
        self.bal[k] = self.bal.get(k, 0) + x

    def debit(self, k, x):
        if self.bal.get(k, 0) < x:
            raise Invalid("insufficient balance")
        self.bal[k] -= x

    def challenge_open(self, height, ts, at, at_ts):
        return not (height > at + self.c["challenge_window"] and ts >= at_ts + self.timing["challenge_secs"])

    def repd(self, k):
        return self.rep.setdefault(k, {"done": 0, "slashed": 0, "expired": 0})

    # roots of tensors and of GEMMs
    def tensor_root(self, j, t):
        if t == 0:
            return j["x0_root"]
        return j["posted"][t - 1][1] if t - 1 < len(j["posted"]) else None

    def gemm_roots(self, j, k):
        if k >= len(j["ops"]):
            return None
        ((kind, p),) = j["ops"][k].items()
        if kind == "Gemm":
            x = self.tensor_root(j, p["x"])
            return (j["w_roots"][p["w"]], x) if x else None
        if kind == "GemmAT":
            a, x = self.tensor_root(j, p["a"]), self.tensor_root(j, p["x"])
            return (a, x) if a and x else None
        return None

    def held(self):
        h = 0
        for j in self.progs.values():
            if j["status"] == "Open":
                h += j["escrow_net"]
            elif j["status"] in ("Working", "Complete"):
                h += j["escrow_net"] + j["bond"] + j["fetch_held"]
        return h

    # ---------------- transactions ----------------
    def apply_tx(self, t, height, ts, miner):
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(t["from"])).verify(bytes.fromhex(t["sig"]), tx_bytes(t))
        except (InvalidSignature, ValueError):
            raise Invalid("signature")
        if self.nonce.get(t["from"], 0) != t["nonce"]:
            raise Invalid("nonce")
        self.nonce[t["from"]] = t["nonce"] + 1
        self.debit(t["from"], t["fee"])
        self.credit(miner, t["fee"])
        me, c = t["from"], self.c
        ((k, p),) = t["kind"].items()
        if k == "Transfer":
            self.debit(me, p["amount"])
            self.credit(hb(p["to"]).hex(), p["amount"])
            return
        ((pk_, q),) = p.items()
        if pk_ == "Submit":
            ops, wr = q["ops"], [hb(w) for w in q["w_roots"]]
            validate_ops(ops, len(wr))
            gemms = sum(1 for o in ops if next(iter(o)) in ("Gemm", "GemmAT"))
            if gemms == 0:
                raise Invalid("a program must contain at least one Gemm")
            if q["escrow"] < c["min_escrow"] * gemms:
                raise Invalid("escrow below the per-Gemm floor")
            if q["deadline"] <= height:
                raise Invalid("deadline passed")
            jid = prog_id(me, t["nonce"], hb(q["x0_root"]), wr, ops).hex()
            if jid in self.progs:
                raise Invalid("duplicate job")
            self.debit(me, q["escrow"])
            burn = M.bps(q["escrow"], c["burn_bps"])
            self.burned += burn
            self.progs[jid] = dict(client=me, x0_root=hb(q["x0_root"]), w_roots=wr, ops=ops, escrow_net=q["escrow"] - burn, deadline=q["deadline"], status="Open",
                                   rebate_left=burn, posted=[], fetches=[], fetch_held=0)
            return
        j = self.progs.get(hb(q["job_id"]).hex())
        if j is None:
            raise Invalid("unknown job")
        if pk_ == "Claim":
            if j["status"] != "Open" or height > j["deadline"]:
                raise Invalid("job not claimable")
            bond = M.bps(j["escrow_net"], c["bond_bps"])
            self.debit(me, bond)
            j["status"], j["worker"], j["bond"] = "Working", me, bond
        elif pk_ == "PostOp":
            if j["status"] != "Working":
                raise Invalid("the job is not in progress")
            if j["worker"] != me or height > j["deadline"]:
                raise Invalid("cannot publish (post)")
            if q["op"] != len(j["posted"]) or len(j["posted"]) >= len(j["ops"]):
                raise Invalid("operations are published in order")
            if next(iter(j["ops"][q["op"]])) not in ("Gemm", "GemmAT") and hb(q["z_root"]) != b"\x00" * 32:
                raise Invalid("z_root only makes sense for a Gemm")
            # attaching the test data to the published commitments: x_root = root of the columns of T_(op+1), z_root = root of Z
            if self.bind:  # (the differential fuzz publishes arbitrary roots: no data exists for them)
                d = self.data[(j["x0_root"], tuple(j["w_roots"]))]
                if self.croot(d["tens"][q["op"] + 1]) != hb(q["x_root"]):
                    raise Invalid("the supplied tensor does not match x_root")
                zk = d["zs"][q["op"]]
                if (zk is None) != (next(iter(j["ops"][q["op"]])) not in ("Gemm", "GemmAT")):
                    raise Invalid("supplied Z inconsistent with the operation type")
                if zk is not None and self.zroot(zk) != hb(q["z_root"]):
                    raise Invalid("the supplied Z does not match z_root")
            j["posted"].append((hb(q["z_root"]), hb(q["x_root"])))
            if len(j["posted"]) == len(j["ops"]):
                j["status"], j["at"], j["at_ts"] = "Complete", height, ts
        elif pk_ == "PostBatch":
            if j["status"] != "Working":
                raise Invalid("the job is not in progress")
            if j["worker"] != me or height > j["deadline"]:
                raise Invalid("cannot publish (post)")
            posts = q["posts"]
            if not posts or q["op"] != len(j["posted"]) or len(j["posted"]) + len(posts) > len(j["ops"]):
                raise Invalid("operations are published in order")
            newp = []
            for i, (z, x) in enumerate(posts):
                if next(iter(j["ops"][q["op"] + i])) not in ("Gemm", "GemmAT") and hb(z) != b"\x00" * 32:
                    raise Invalid("z_root only makes sense for a Gemm")
                if self.bind:
                    d = self.data[(j["x0_root"], tuple(j["w_roots"]))]
                    k = q["op"] + i
                    if self.croot(d["tens"][k + 1]) != hb(x):
                        raise Invalid("the supplied tensor does not match x_root")
                    zk = d["zs"][k]
                    if (zk is None) != (next(iter(j["ops"][k])) not in ("Gemm", "GemmAT")):
                        raise Invalid("supplied Z inconsistent with the operation type")
                    if zk is not None and self.zroot(zk) != hb(z):
                        raise Invalid("the supplied Z does not match z_root")
                newp.append((hb(z), hb(x)))
            j["posted"].extend(newp)
            if len(j["posted"]) == len(j["ops"]):
                j["status"], j["at"], j["at_ts"] = "Complete", height, ts
        elif pk_ == "Accept":
            if not (j["status"] == "Complete" and j["client"] == me):
                raise Invalid("cannot accept (accept)")
            self.credit(j["worker"], j["escrow_net"] + j["bond"])
            self.repd(j["worker"])["done"] += 1
            held, j["fetch_held"], j["fetches"], j["status"] = j["fetch_held"], 0, [], "Settled"
            self.credit(j["client"], held)
        elif pk_ == "Fetch":
            if j["status"] != "Complete":
                raise Invalid("no result published")
            if j["client"] != me:
                raise Invalid("only the client can request (client)")
            if not (1 <= q["tensor"] <= len(j["ops"])) or q["col"] >= self.p["n"]:
                raise Invalid("index out of bounds")
            if not self.challenge_open(height, ts, j["at"], j["at_ts"]):
                raise Invalid("window closed")
            if len(j["fetches"]) >= c["max_pending_fetches"] or any((f[0], f[1]) == (q["tensor"], q["col"]) for f in j["fetches"]):
                raise Invalid("duplicate request or too many")
            self.debit(me, c["fetch_fee"])
            j["fetch_held"] += c["fetch_fee"]
            j["fetches"].append((q["tensor"], q["col"], ts + self.timing["serve_secs"]))
        elif pk_ == "Serve":
            if j["status"] != "Complete":
                raise Invalid("no result published")
            if j["worker"] != me:
                raise Invalid("only the worker can serve")
            pos = next((x for x, f in enumerate(j["fetches"]) if (f[0], f[1]) == (q["tensor"], q["col"])), None)
            if pos is None:
                raise Invalid("no pending request")
            n = self.p["n"]
            if len(q["vals"]) != n or any(abs(v) > 64 for v in q["vals"]):
                raise Invalid("malformed served column")
            root = self.tensor_root(j, q["tensor"])
            if root is None or not vp(root, S.leaf_hash(q["col"], i8b(q["vals"])), q["col"], q["path"], depth_for(n)):
                raise Invalid("invalid Merkle proof (Merkle)")
            del j["fetches"][pos]
            j["fetch_held"] -= c["fetch_fee"]
            j["at_ts"] = max(max(ts + c["fetch_extend_secs"] - self.timing["challenge_secs"], 0), j["at_ts"])
            j["at"] = max(max(height + 2 - c["challenge_window"], 0), j["at"])
            self.credit(me, c["fetch_fee"])
        elif pk_ == "SlashUnserved":
            if j["status"] != "Complete":
                raise Invalid("no result published")
            if not any(ts > f[2] for f in j["fetches"]):
                raise Invalid("no expired request (no expired)")
            reward = j["bond"] // 2
            self.credit(me, reward)
            self.burned += j["bond"] - reward
            self.credit(j["client"], j["escrow_net"] + j["fetch_held"])
            self.repd(j["worker"])["slashed"] += 1
            j["fetch_held"], j["fetches"], j["status"] = 0, [], "Slashed"
        elif pk_ == "Fraud":
            if j["status"] == "Working":
                pass
            elif j["status"] == "Complete":
                if not self.challenge_open(height, ts, j["at"], j["at_ts"]):
                    raise Invalid("dispute window closed")
            else:
                raise Invalid("no result to contest")
            self.verify_fraud(j, q["op"], q["kind"])
            reward = j["bond"] // 2
            self.credit(me, reward)
            self.burned += j["bond"] - reward
            self.credit(j["client"], j["escrow_net"] + j["fetch_held"])
            self.repd(j["worker"])["slashed"] += 1
            j["fetch_held"], j["fetches"], j["status"] = 0, [], "Slashed"
        elif pk_ == "Settle":
            if j["status"] == "Complete" and j["fetches"]:
                raise Invalid("pending requests")
            if j["status"] == "Complete" and not self.challenge_open(height, ts, j["at"], j["at_ts"]):
                self.credit(j["worker"], j["escrow_net"] + j["bond"])
                self.repd(j["worker"])["done"] += 1
                j["status"] = "Settled"
            elif j["status"] == "Open" and height > j["deadline"]:
                self.credit(j["client"], j["escrow_net"])
                j["status"] = "Expired"
            elif j["status"] == "Working" and height > j["deadline"]:
                self.repd(j["worker"])["expired"] += 1
                self.burned += j["bond"]
                self.credit(j["client"], j["escrow_net"])
                j["status"] = "Expired"
            else:
                raise Invalid("settlement impossible for now (cannot settle)")

    # ---------------- fraud proofs ----------------
    def verify_fraud(self, j, op_idx, f):
        n, d, cd = N, depth_for(N), depth_for(N)
        zrow_ok = lambda r, row, path: len(row) == n and vp(j["posted"][op_idx][0], S.leaf_hash(r, S.i32bytes(row)), r, path, cd)
        if op_idx >= len(j["posted"]):
            raise Invalid("operation not published")
        op = j["ops"][op_idx]
        ((okind, op_p),) = op.items()
        out_root = j["posted"][op_idx][1]
        ((kind, p),) = f.items()
        if kind == "Gemm" and okind in ("Gemm", "GemmAT"):
            i, jj = p["i"], p["j"]
            if i >= n or jj >= n or len(p["w_row"]) != n or len(p["x_col"]) != n:
                raise Invalid("malformed proof")
            if any(abs(v) > 64 for v in p["w_row"] + p["x_col"]):
                raise Invalid("values out of bounds")
            roots = self.gemm_roots(j, op_idx)
            if roots is None:
                raise Invalid("inputs unavailable")
            if not vp(roots[0], S.leaf_hash(i, i8b(p["w_row"])), i, p["w_path"], d):
                raise Invalid("invalid opening of W")
            if not vp(roots[1], S.leaf_hash(jj, i8b(p["x_col"])), jj, p["x_path"], d):
                raise Invalid("invalid opening of the input")
            if not zrow_ok(i, p["z_row"], p["z_path"]):
                raise Invalid("invalid opening of Z")
            if sum(a * b for a, b in zip(p["w_row"], p["x_col"])) == p["z_row"][jj]:
                raise Invalid("correct entry: not a fraud")
        elif kind == "Act" and okind in ("Gemm", "GemmAT"):
            i, jj = p["i"], p["j"]
            if i >= n or jj >= n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            if not zrow_ok(i, p["z_row"], p["z_path"]):
                raise Invalid("invalid opening of Z")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            if p["out_col"][i] == act(p["z_row"][jj], op_p["shift"], op_p["relu"]):
                raise Invalid("correct activation: not a fraud")
        elif kind == "Elem" and okind in ("Add", "MulT", "Map", "Pool"):
            i, jj = p["i"], p["j"]
            if i >= n or jj >= n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            req = op_inputs(op, i, jj)
            if len(p["ins"]) != len(req):
                raise Invalid("wrong number of source openings")
            vals = []
            for o, (t, si, sj) in zip(p["ins"], req):
                if o["tensor"] != t or o["col"] != sj or len(o["vals"]) != n:
                    raise Invalid("source opening inconsistent with the operation")
                root = self.tensor_root(j, t)
                if root is None:
                    raise Invalid("source tensor unavailable")
                if not vp(root, S.leaf_hash(sj, i8b(o["vals"])), sj, o["path"], d):
                    raise Invalid("invalid source opening")
                vals.append(o["vals"][si])
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            if p["out_col"][i] == op_eval(op, vals):
                raise Invalid("correct entry: not a fraud")
        elif kind == "Col" and okind in ("Softmax", "SoftmaxLo", "LayerNorm", "CausalSoftmax", "CausalSoftmaxS", "RmsNorm"):
            jj = p["j"]
            if jj >= n or len(p["in_col"]) != n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            in_root = self.tensor_root(j, op_p["x"])
            if in_root is None:
                raise Invalid("input tensor unavailable")
            if not vp(in_root, S.leaf_hash(jj, i8b(p["in_col"])), jj, p["in_path"], d):
                raise Invalid("invalid opening of the input")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            if col_op(op, p["in_col"], jj) == p["out_col"]:
                raise Invalid("correct column: not a fraud")
        elif kind == "MulW" and okind == "MulW":
            i, jj = p["i"], p["j"]
            if i >= n or jj >= n or len(p["in_col"]) != n or len(p["w_row"]) != n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            if any(abs(v) > 64 for v in p["w_row"] + p["in_col"]):
                raise Invalid("values out of bounds")
            in_root = self.tensor_root(j, op_p["x"])
            if in_root is None:
                raise Invalid("input tensor unavailable")
            if not vp(in_root, S.leaf_hash(jj, i8b(p["in_col"])), jj, p["in_path"], d):
                raise Invalid("invalid opening of the input")
            if not vp(j["w_roots"][op_p["w"]], S.leaf_hash(i, i8b(p["w_row"])), i, p["w_path"], d):
                raise Invalid("invalid opening of the weight row")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            if p["out_col"][i] == int(np.clip((p["in_col"][i] * p["w_row"][jj]) >> op_p["shift"], -64, 64)):
                raise Invalid("correct entry: not a fraud")
        elif kind == "Lut" and okind == "Lut":
            jj = p["j"]
            if jj >= n or len(p["in_col"]) != n or len(p["t_row"]) != n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            if any(abs(v) > 64 for v in p["t_row"] + p["in_col"]):
                raise Invalid("values out of bounds")
            in_root = self.tensor_root(j, op_p["x"])
            if in_root is None:
                raise Invalid("input tensor unavailable")
            if not vp(in_root, S.leaf_hash(jj, i8b(p["in_col"])), jj, p["in_path"], d):
                raise Invalid("invalid opening of the input")
            if not vp(j["w_roots"][op_p["w"]], S.leaf_hash(op_p["row"], i8b(p["t_row"])), op_p["row"], p["t_path"], d):
                raise Invalid("invalid opening of the table")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            want = [p["t_row"][min(max(v, -64), 63) + 64] for v in p["in_col"]]
            if want == list(p["out_col"]):
                raise Invalid("correct column: not a fraud")
        elif kind == "Bias" and okind == "Mul":           # same proof shape as Bias; arbitrary gamma row (8 bits)
            jj = p["j"]
            if jj >= n or len(p["in_col"]) != n or len(p["b_row"]) != n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            in_root = self.tensor_root(j, op_p["x"])
            if in_root is None:
                raise Invalid("input tensor unavailable")
            if not vp(in_root, S.leaf_hash(jj, i8b(p["in_col"])), jj, p["in_path"], d):
                raise Invalid("invalid opening of the input")
            if not vp(j["w_roots"][op_p["w"]], S.leaf_hash(op_p["row"], i8b(p["b_row"])), op_p["row"], p["b_path"], d):
                raise Invalid("invalid opening of the scale")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            want = [int(np.clip((a * g) >> op_p["shift"], -64, 64)) for a, g in zip(p["in_col"], p["b_row"])]
            if want == list(p["out_col"]):
                raise Invalid("correct column: not a fraud")
        elif kind == "Bias" and okind == "Bias":
            jj = p["j"]
            if jj >= n or len(p["in_col"]) != n or len(p["b_row"]) != n or len(p["out_col"]) != n:
                raise Invalid("malformed proof")
            if any(abs(v) > 64 for v in p["b_row"]):
                raise Invalid("values out of bounds")
            in_root = self.tensor_root(j, op_p["x"])
            if in_root is None:
                raise Invalid("input tensor unavailable")
            if not vp(in_root, S.leaf_hash(jj, i8b(p["in_col"])), jj, p["in_path"], d):
                raise Invalid("invalid opening of the input")
            if not vp(j["w_roots"][op_p["w"]], S.leaf_hash(op_p["row"], i8b(p["b_row"])), op_p["row"], p["b_path"], d):
                raise Invalid("invalid opening of the bias")
            if not vp(out_root, S.leaf_hash(jj, i8b(p["out_col"])), jj, p["out_path"], d):
                raise Invalid("invalid opening of the output")
            want = [int(np.clip(a + b, 0 if op_p["relu"] else -64, 64)) for a, b in zip(p["in_col"], p["b_row"])]
            if want == list(p["out_col"]):
                raise Invalid("correct column: not a fraud")
        else:
            raise Invalid("the proof kind does not match the operation")

    # ---------------- blocks ----------------
    def matrices(self, epoch):
        if epoch not in self.native:
            self.native[epoch] = S.native_matrices(epoch, N)
        return self.native[epoch]

    def op_matrices(self, j, k):
        """(A, B) of GEMM `k` of the program, rebuilt from the tensors PUBLISHED by the worker and attached to the on-chain roots."""
        d = self.data[(j["x0_root"], tuple(j["w_roots"]))]
        ((kind, p),) = j["ops"][k].items()
        if kind == "Gemm":
            a, b = d["ws"][p["w"]], d["tens"][p["x"]]
            ra, rb = self.rroot(a), self.croot(b)
        else:
            ta = d["tens"][p["a"]]
            a, b = ta.T.copy(), d["tens"][p["x"]]
            ra, rb = self.rroot(a), self.croot(b)
        want = self.gemm_roots(j, k)
        if (ra, rb) != want:
            raise Invalid("the data does not match the committed roots")
        return a, b

    def apply(self, b):
        hd, p, c = b["header"], self.p, self.c
        if hd["version"] != 2:
            raise Invalid("version")
        if hd["height"] != len(self.headers):
            raise Invalid("height")
        if bytes.fromhex(hd["prev"]) != self.tip_hash:
            raise Invalid("prev")
        if hd["timestamp"] <= self.tip_ts:
            raise Invalid("timestamp not increasing")
        if hd["target"] != self.target:
            raise Invalid("target")
        jackpot = bytes.fromhex(hd["jackpot"])
        if not S.meets_target(jackpot, hd["target"]):
            raise Invalid("jackpot above the target")
        ids = [tx_id(t) for t in b["txs"]]
        if len(b["txs"]) > 256:                                   # MAX_BLOCK_TXS (consensus rule)
            raise Invalid("too many transactions")
        if sum(len(tx_bytes(t)) + 8 + len(bytes.fromhex(t["sig"])) for t in b["txs"]) > 4 << 20:   # MAX_BLOCK_TX_BYTES (bincode(SignedTx))
            raise Invalid("block transactions too heavy")
        root = C.merkle_tx_root(ids)
        if bytes.fromhex(hd["tx_root"]) != root:
            raise Invalid("tx_root")
        cls = hd["class"]
        if cls["type"] == "Native":
            a, bm = self.matrices(hd["height"] // c["epoch_len"])
            ct = ("Native",)
        else:
            j = self.progs.get(cls["job"])
            if j is None:
                raise Invalid("unknown job")
            if not (j["status"] in ("Working", "Complete") and j["worker"] == hd["miner"]):
                raise Invalid("the miner is not the active worker of this program (miner)")
            if self.gemm_roots(j, cls["op"]) is None:
                raise Invalid("the operation is not an unlocked Gemm")
            a, bm = self.op_matrices(j, cls["op"])
            ct = ("Op", bytes.fromhex(cls["job"]), cls["op"])
        if (bytes.fromhex(hd["a_root"]), bytes.fromhex(hd["b_root"])) != self.work_roots(cls, hd["height"]):
            raise Invalid("work roots")
        sg = S.sigma_of(bytes.fromhex(hd["prev"]), bytes.fromhex(hd["miner"]), ct, hd["extra_nonce"], root, hd["timestamp"])
        T = p["n"] // p["tile"]
        if not (hd["ti"] < T and hd["tj"] < T):
            raise Invalid("tile out of bounds")
        jp, _, _ = S.work(a, bm, sg, p["n"], p["tile"], p["rank"], p["fold_k"])
        if jp[hd["ti"] * T + hd["tj"]] != jackpot:
            raise Invalid("jackpot different from the recomputation")
        snap = copy.deepcopy((self.bal, self.nonce, self.rep, self.progs, self.burned))
        try:
            for t in b["txs"]:
                self.apply_tx(t, hd["height"], hd["timestamp"], hd["miner"])
            reward = C.base_reward(c, hd["height"])
            bonus = 0
            if cls["type"] == "Op" and cls["job"] in self.progs:
                jb = self.progs[cls["job"]]
                bonus = min(reward // 2, jb["rebate_left"])
                jb["rebate_left"] -= bonus
            self.credit(hd["miner"], reward + bonus)
            if bytes.fromhex(hd["accounts_root"]) != S.accounts_root(self.bal, self.nonce):
                raise Invalid("accounts_root")
        except Invalid:
            self.bal, self.nonce, self.rep, self.progs, self.burned = snap
            raise
        self.minted += reward + bonus
        self.headers.append(hd)
        self.tip_ts = hd["timestamp"]
        self.tip_hash = S.H("vearl/header/v1", header_bytes(hd))

    def work_roots(self, cls, height):
        """Roots (A, B) of the work of a block (v2 header)."""
        if cls["type"] == "Native":
            ep = height // self.c["epoch_len"]
            if ep not in self.native_roots:
                a, bm = self.matrices(ep)
                self.native_roots[ep] = (S.rows_root(a), S.cols_root(bm))
            return self.native_roots[ep]
        return self.gemm_roots(self.progs[cls["job"]], cls["op"])

    def post_root(self, miner, cls, txs, height, ts):
        """Account root after applying the block (reference miner); null root if the transactions are invalid."""
        snap = copy.deepcopy((self.bal, self.nonce, self.rep, self.progs, self.burned))
        try:
            for t in txs:
                self.apply_tx(t, height, ts, miner)
            reward = C.base_reward(self.c, height)
            bonus = 0
            if cls["type"] == "Op" and cls["job"] in self.progs:
                bonus = min(reward // 2, self.progs[cls["job"]]["rebate_left"])
            self.credit(miner, reward + bonus)
            return S.accounts_root(self.bal, self.nonce)
        except Invalid:
            return b"\x00" * 32
        finally:
            self.bal, self.nonce, self.rep, self.progs, self.burned = snap

    def invariant(self):
        return sum(self.bal.values()) + self.held() + self.burned == self.genesis_supply + self.minted


def class_tuple(c):
    return ("Native",) if c["type"] == "Native" else ("Op", bytes.fromhex(c["job"]), c["op"])


def header_bytes(hd):
    return S.header_bytes(hd["version"], hd["height"], bytes.fromhex(hd["prev"]), hd["timestamp"], bytes.fromhex(hd["miner"]), class_tuple(hd["class"]),
                          hd["extra_nonce"], hd["ti"], hd["tj"], bytes.fromhex(hd["jackpot"]), bytes.fromhex(hd["tx_root"]), hd["target"],
                          bytes.fromhex(hd["a_root"]), bytes.fromhex(hd["b_root"]), bytes.fromhex(hd["accounts_root"]))


def _signed(st, seed, kind):
    who = C.pub_hex(seed)
    t = {"from": who, "nonce": st.nonce.get(who, 0), "fee": 0, "kind": kind}
    t["sig"] = C.priv(seed).sign(tx_bytes(t)).hex()
    t["id"] = tx_id(t).hex()
    return t


def _mine(st, miner, cls, txs, ts):
    height = len(st.headers)
    if cls[0] == "Native":
        a, bm = st.matrices(height // st.c["epoch_len"])
    else:
        a, bm = st.op_matrices(st.progs[cls[1].hex()], cls[2])
    root = C.merkle_tx_root([tx_id(t) for t in txs])
    T = st.p["n"] // st.p["tile"]
    for en in range(1 << 20):
        sg = S.sigma_of(st.tip_hash, bytes.fromhex(miner), cls, en, root, ts)
        jp, _, _ = S.work(a, bm, sg, st.p["n"], st.p["tile"], st.p["rank"], st.p["fold_k"])
        for idx, jk in enumerate(jp):
            if S.meets_target(jk, st.target):
                cj = {"type": "Native"} if cls[0] == "Native" else {"type": "Op", "job": cls[1].hex(), "op": cls[2]}
                ra, rb = st.work_roots(cj, height)
                hd = {"version": 2, "height": height, "prev": st.tip_hash.hex(), "timestamp": ts, "miner": miner, "class": cj, "extra_nonce": en,
                      "ti": idx // T, "tj": idx % T, "jackpot": jk.hex(), "tx_root": root.hex(), "target": st.target,
                      "a_root": ra.hex(), "b_root": rb.hex(), "accounts_root": st.post_root(miner, cj, txs, height, ts).hex()}
                return {"header": hd, "txs": txs}
    raise RuntimeError("no solution")


def build_extension(V, path):
    """The Python validator AUTHOR of a program: it defines a small network (2 GEMM + softmax + LayerNorm), COMPUTES it with its
    independent engine, submits it, mines the work blocks of its GEMMs, publishes the operations (once honestly, once
    with a wrong LayerNorm column for which it builds the fraud proof itself): the file is replayed by the RUST validator."""
    m = ProgChain(V)
    for b in V["blocks"]:
        m.apply(b)
    ext, prog_data = list(V["blocks"]), list(V["prog_data"])
    rng = np.random.default_rng(77)
    ts = m.tip_ts
    client, worker, chall = C.pub_hex(1), C.pub_hex(2), C.pub_hex(3)
    hl = lambda h: list(h) if isinstance(h, (bytes, bytearray)) else list(bytes.fromhex(h))
    P = lambda **kw: {"Prog": kw}

    def push(miner, cls, txs, dt=20):
        nonlocal ts
        ts += dt
        blk = _mine(m, miner, cls, txs, ts)
        m.apply(blk)
        ext.append(blk)

    def pr(leaves, idx):
        return [list(h) for h in S.merkle_proof(leaves, idx)]

    ops = [{"Gemm": {"w": 0, "x": 0, "shift": 6, "relu": True}}, {"Softmax": {"x": 1, "len": 16}}, {"Gemm": {"w": 1, "x": 2, "shift": 5, "relu": False}}, {"LayerNorm": {"x": 3, "len": 32}}]
    bops = [{"Gemm": {"w": 0, "x": 0, "shift": 6, "relu": False}}, {"Bias": {"x": 1, "w": 2, "row": 0, "relu": False}}, {"Lut": {"x": 2, "w": 2, "row": 2}},
            {"Gemm": {"w": 1, "x": 3, "shift": 6, "relu": False}}, {"Bias": {"x": 4, "w": 2, "row": 1, "relu": False}}]

    def author(ops, x0, ws, variant, tamper, fraud_op, fraud, batch=False):
        tens, zs = R.run_program(x0, ws, ops)
        tens = [np.asarray(t, dtype=np.int64) for t in tens]
        zs = [None if z is None else np.asarray(z, dtype=np.int64) for z in zs]
        if variant == "wrong":
            tens[tamper[0]] = tens[tamper[0]].copy()
            tens[tamper[0]][tamper[1]] += 1
        x0r, wrs = ProgChain.croot(x0), tuple(ProgChain.rroot(w) for w in ws)
        enc = lambda x: base64.b64encode(S.i8bytes(x)).decode()
        prog_data.append({"x0": enc(x0), "ws": [enc(w) for w in ws], "tensors": [enc(t) for t in tens],
                          "zs": [None if z is None else base64.b64encode(z.astype("<i4").tobytes()).decode() for z in zs]})
        m.data[(x0r, wrs)] = dict(x0=x0, ws=ws, tens=tens, zs=zs)
        jid = prog_id(client, m.nonce.get(client, 0), x0r, list(wrs), ops).hex()
        push(C.pub_hex(4), ("Native",), [_signed(m, 1, P(Submit=dict(x0_root=hl(x0r), w_roots=[hl(w) for w in wrs], ops=ops, escrow=60 * 10**8, deadline=len(m.headers) + 500)))])
        push(C.pub_hex(4), ("Native",), [_signed(m, 2, P(Claim=dict(job_id=hl(jid))))])
        if batch:
            # all the operations in ONE transaction (PostBatch), then the useful blocks of the Gemms during `Complete`
            posts = [[hl(ProgChain.zroot(zs[k]) if zs[k] is not None else b"\x00" * 32), hl(ProgChain.croot(tens[k + 1]))] for k in range(len(ops))]
            push(C.pub_hex(4), ("Native",), [_signed(m, 2, P(PostBatch=dict(job_id=hl(jid), op=0, posts=[[z, x] for z, x in posts])))])
            for k, op in enumerate(ops):
                if next(iter(op)) == "Gemm":
                    push(worker, ("Op", bytes.fromhex(jid), k), [])
        else:
            for k, op in enumerate(ops):
                if next(iter(op)) == "Gemm":
                    push(worker, ("Op", bytes.fromhex(jid), k), [])
                z_root = ProgChain.zroot(zs[k]) if zs[k] is not None else b"\x00" * 32
                push(C.pub_hex(4), ("Native",), [_signed(m, 2, P(PostOp=dict(job_id=hl(jid), op=k, z_root=hl(z_root), x_root=hl(ProgChain.croot(tens[k + 1])))))])
        if variant == "fetch":
            # the client demands column 2 of the last tensor; the worker serves it; acceptance (the client's fees are returned)
            last = len(ops)
            tl = [S.leaf_hash(x, S.i8bytes(tens[last][:, x])) for x in range(N)]
            push(C.pub_hex(4), ("Native",), [_signed(m, 1, P(Fetch=dict(job_id=hl(jid), tensor=last, col=2)))])
            push(C.pub_hex(4), ("Native",), [_signed(m, 2, P(Serve=dict(job_id=hl(jid), tensor=last, col=2, vals=[int(v) for v in tens[last][:, 2]], path=pr(tl, 2))))])
            push(C.pub_hex(4), ("Native",), [_signed(m, 1, P(Accept=dict(job_id=hl(jid))))])
            assert m.progs[jid]["status"] == "Settled" and m.progs[jid]["fetch_held"] == 0
        elif variant == "unserved":
            push(C.pub_hex(4), ("Native",), [_signed(m, 1, P(Fetch=dict(job_id=hl(jid), tensor=1, col=4)))])
            push(C.pub_hex(4), ("Native",), [], dt=45)
            push(C.pub_hex(4), ("Native",), [_signed(m, 3, P(SlashUnserved=dict(job_id=hl(jid))))])
            assert m.progs[jid]["status"] == "Slashed"
        elif variant == "honest":
            push(C.pub_hex(4), ("Native",), [_signed(m, 1, P(Accept=dict(job_id=hl(jid))))])
            assert m.progs[jid]["status"] == "Settled"
        else:
            push(C.pub_hex(4), ("Native",), [_signed(m, 3, P(Fraud=dict(job_id=hl(jid), op=fraud_op, kind=fraud(tens, ws))))])
            assert m.progs[jid]["status"] == "Slashed"

    def col_fraud(tens, ws):
        # column fraud proof (softmax / normalisation) built here: opening of column 0 as input (T_3) and as output (T_4)
        tin, tout = tens[3], tens[4]
        in_l = [S.leaf_hash(x, S.i8bytes(tin[:, x])) for x in range(N)]
        out_l = [S.leaf_hash(x, S.i8bytes(tout[:, x])) for x in range(N)]
        return {"Col": dict(j=0, in_col=[int(v) for v in tin[:, 0]], in_path=pr(in_l, 0), out_col=[int(v) for v in tout[:, 0]], out_path=pr(out_l, 0))}

    def bias_fraud(tens, ws):
        # BIAS fraud proof (operation 4, output T_5, column 7): input column (T_4), bias row 1 of weight 2, output column
        tin, tout, bt = tens[4], tens[5], ws[2]
        in_l = [S.leaf_hash(x, S.i8bytes(tin[:, x])) for x in range(N)]
        out_l = [S.leaf_hash(x, S.i8bytes(tout[:, x])) for x in range(N)]
        b_l = [S.leaf_hash(x, S.i8bytes(bt[x])) for x in range(N)]
        return {"Bias": dict(j=7, in_col=[int(v) for v in tin[:, 7]], in_path=pr(in_l, 7), b_row=[int(v) for v in bt[1]], b_path=pr(b_l, 1),
                             out_col=[int(v) for v in tout[:, 7]], out_path=pr(out_l, 7))}

    for variant in ("honest", "wrong"):
        x0 = np.zeros((N, N), dtype=np.int64)
        x0[:24, :32] = rng.integers(0, 33, (24, 32))
        ws = []
        for _ in range(2):
            w = np.zeros((N, N), dtype=np.int64)
            w[:16 if not ws else 32, :24 if not ws else 16] = rng.integers(-6, 7, (16 if not ws else 32, 24 if not ws else 16))
            ws.append(w)
        author(ops, x0, ws, variant, (4, (0, 0)), 3, col_fraud)     # column 0 of the LayerNorm output is wrong
    def lut_fraud(tens, ws):
        # TABLE fraud proof (operation 2, output T_3, column 5): input column (T_2), row 2 of weight 2 (the table), output column
        tin, tout, bt = tens[2], tens[3], ws[2]
        in_l = [S.leaf_hash(x, S.i8bytes(tin[:, x])) for x in range(N)]
        out_l = [S.leaf_hash(x, S.i8bytes(tout[:, x])) for x in range(N)]
        b_l = [S.leaf_hash(x, S.i8bytes(bt[x])) for x in range(N)]
        return {"Lut": dict(j=5, in_col=[int(v) for v in tin[:, 5]], in_path=pr(in_l, 5), t_row=[int(v) for v in bt[2]], t_path=pr(b_l, 2),
                            out_col=[int(v) for v in tout[:, 5]], out_path=pr(out_l, 5))}

    for variant in ("honest", "wrong", "table", "batch", "fetch", "unserved"):
        # 16 -> 24 -> 10 MLP WITH BIASES AND AN ACTIVATION TABLE (quantised tanh) (op Bias: bias vector = row of a weight block), defined and computed by Python
        x0 = np.zeros((N, N), dtype=np.int64)
        x0[:16, :32] = rng.integers(0, 65, (16, 32))
        w0, w1, bt = (np.zeros((N, N), dtype=np.int64) for _ in range(3))
        w0[:24, :16] = rng.integers(-6, 7, (24, 16))
        w1[:10, :24] = rng.integers(-6, 7, (10, 24))
        bt[0, :24] = rng.integers(-20, 21, 24)
        bt[1, :10] = rng.integers(-20, 21, 10)
        bt[2, :128] = np.round(64 * np.tanh((np.arange(128) - 64) / 32.0)).astype(np.int64)
        if variant in ("fetch", "unserved"):
            author(bops, x0, [w0, w1, bt], variant, None, None, None)
        elif variant == "batch":
            author(bops, x0, [w0, w1, bt], "wrong", (5, (2, 7)), 4, bias_fraud, batch=True)   # everything published in one batch, then Bias fraud proof (Complete job)
        elif variant == "table":
            author(bops, x0, [w0, w1, bt], "wrong", (3, (4, 5)), 2, lut_fraud)     # cell (4, 5) of the table output is wrong
        else:
            author(bops, x0, [w0, w1, bt], variant, (5, (2, 7)), 4, bias_fraud)     # cell (2, 7) of the last Bias output is wrong
    assert m.invariant()
    out = path.replace(".json", "") + ".ext.json"
    json.dump({"genesis": V["genesis"], "prog_data": prog_data, "blocks": ext, "final": V["final"]}, open(out, "w"))
    print("extension mined in Python (%d blocks: one honest program paid, one wrong program proven) written to %s -> Rust validator: vearl-prog-vectors verify %s" % (len(ext) - len(V["blocks"]), out, out))



def snapshot_indices(vectors):
    """States needed by the negative cases; retain no other tensor history."""
    def block_has(b, name, jid=None, fraud=None):
        for t in b["txs"]:
            p = t["kind"].get("Prog", {})
            if name not in p:
                continue
            if jid is not None and hb(p[name]["job_id"]).hex() != jid:
                continue
            if fraud is not None and fraud not in p[name]["kind"]:
                continue
            return True
        return False
    jobs = vectors["final"]["jobs"]
    blocks = vectors["blocks"]
    needed = {next(k for k, b in enumerate(blocks) if block_has(b, "Submit")) - 1}
    needed.add(max(k for k, b in enumerate(blocks) if block_has(b, "PostOp", jobs[0]["id"])))
    needed.add(max(k for k, b in enumerate(blocks) if block_has(b, "Claim", jobs[2]["id"])))
    for fraud in ("Gemm", "Act", "Elem", "Col"):
        needed.add(next(k for k, b in enumerate(blocks) if block_has(b, "Fraud", fraud=fraud)) - 1)
    return needed


def main(path):
    V = json.load(open(path))
    bad = 0

    def chk(name, got, want):
        nonlocal bad
        ok = got == want
        bad += not ok
        print(("ok   " if ok else "FAIL"), name, "" if ok else f"\n   got {got}\n   expected {want}")

    m = ProgChain(V)
    needed = snapshot_indices(V)
    snaps, kinds = {}, {}
    for block_index, b in enumerate(V["blocks"]):
        for t in b["txs"]:
            if tx_bytes(t).hex() != t["tx_bincode"] or tx_id(t).hex() != t["id"]:
                bad += 1
                print("FAIL transaction encoding")
            ((k, p),) = t["kind"].items()
            name = k if k == "Transfer" else "Prog." + next(iter(p)) + ("(" + next(iter(next(iter(p.values()))["kind"])) + ")" if next(iter(p)) == "Fraud" else "")
            kinds[name] = kinds.get(name, 0) + 1
        m.apply(b)
        assert S.H("vearl/header/v1", header_bytes(b["header"])).hex() == b["hash"], "header hash"
        if block_index in needed:
            snaps[block_index] = copy.deepcopy(m)
    chk("%d valid blocks; transactions: %s" % (len(V["blocks"]), dict(sorted(kinds.items()))), len(m.headers), V["final"]["height"])
    F = V["final"]
    chk("emission", m.minted, F["minted"])
    chk("burned", m.burned, F["burned"])
    for a in F["accounts"]:
        chk("account " + a["key"][:8], (m.bal.get(a["key"], 0), m.nonce.get(a["key"], 0)), (a["balance"], a["nonce"]))
    for jb in F["jobs"]:
        j = m.progs[jb["id"]]
        chk("program " + jb["id"][:8] + " " + jb["status"], (j["status"], j["rebate_left"], j["escrow_net"], len(j["posted"])), (jb["status"], jb["rebate_left"], jb["escrow_net"], jb["posted"]))
    for r in F["reputation"]:
        chk("reputation " + r["key"][:8], m.rep.get(r["key"], {"done": 0, "slashed": 0, "expired": 0}), {"done": r["done"], "slashed": r["slashed"], "expired": r["expired"]})
    chk("money supply invariant", m.invariant(), True)

    # ---- cross-check with the independent operation engine: the published tensors of HONEST programs = run_program ----
    for jb, (key, d) in zip(F["jobs"][:2], list(m.data.items())[:2]):
        j = m.progs[jb["id"]]
        ref, _ = R.run_program(d["x0"], d["ws"], j["ops"])
        chk("honest program " + jb["id"][:8] + ": published tensors == independent engine", all(np.array_equal(a, b) for a, b in zip(ref, d["tens"])), True)

    # ---------------- negative tests: each alteration is refused, for the right reason ----------------
    def signed(st, seed, kind):
        who = C.pub_hex(seed)
        t = {"from": who, "nonce": st.nonce.get(who, 0), "fee": 0, "kind": kind}
        t["sig"] = C.priv(seed).sign(tx_bytes(t)).hex()
        t["id"] = tx_id(t).hex()
        return t

    def mine(st, miner, cls, txs, ts):
        height = len(st.headers)
        if cls[0] == "Native":
            a, bm = st.matrices(height // st.c["epoch_len"])
        else:
            a, bm = st.op_matrices(st.progs[cls[1].hex()], cls[2])
        root = C.merkle_tx_root([tx_id(t) for t in txs])
        T = st.p["n"] // st.p["tile"]
        for en in range(1 << 20):
            sg = S.sigma_of(st.tip_hash, bytes.fromhex(miner), cls, en, root, ts)
            jp, _, _ = S.work(a, bm, sg, st.p["n"], st.p["tile"], st.p["rank"], st.p["fold_k"])
            for idx, jk in enumerate(jp):
                if S.meets_target(jk, st.target):
                    cj = {"type": "Native"} if cls[0] == "Native" else {"type": "Op", "job": cls[1].hex(), "op": cls[2]}
                    ra, rb = st.work_roots(cj, height)
                    hd = {"version": 2, "height": height, "prev": st.tip_hash.hex(), "timestamp": ts, "miner": miner, "class": cj, "extra_nonce": en,
                          "ti": idx // T, "tj": idx % T, "jackpot": jk.hex(), "tx_root": root.hex(), "target": st.target,
                          "a_root": ra.hex(), "b_root": rb.hex(), "accounts_root": st.post_root(miner, cj, txs, height, ts).hex()}
                    return {"header": hd, "txs": txs}
        raise RuntimeError("no solution")

    def attempt(name, st, txs, why, miner=None, cls=("Native",), dt=20):
        nonlocal bad
        blk = mine(st, miner or C.pub_hex(4), cls, txs, st.tip_ts + dt)
        try:
            copy.deepcopy(st).apply(blk)
            got = "ACCEPTED"
        except Invalid as e:
            got = str(e)
        ok = why in got
        bad += not ok
        print(("ok   " if ok else "FAIL"), "refusal:", name, "->", got)

    def find_tx(pred):
        for k, b in enumerate(V["blocks"]):
            for t in b["txs"]:
                if pred(t["kind"]):
                    return k, t
        raise KeyError

    def prog_kind(name):
        return lambda kd: "Prog" in kd and name in kd["Prog"]

    ids = [jb["id"] for jb in F["jobs"]]
    hl = lambda h: list(bytes.fromhex(h))   # hex hash -> list of integers (JSON serde form)
    P = lambda **kw: {"Prog": kw}
    ks, _ = find_tx(lambda kd: "Prog" in kd and "Submit" in kd["Prog"])

    def last_block_of(jid, kind):
        return max(k for k, b in enumerate(V["blocks"]) if any(prog_kind(kind)(t["kind"]) and hb(t["kind"]["Prog"][kind]["job_id"]).hex() == jid for t in b["txs"]))

    st_c = copy.deepcopy(snaps[last_block_of(ids[0], "PostOp")])   # program 0: Complete, window open
    assert st_c.progs[ids[0]]["status"] == "Complete"

    def gemm_proof(st, jid, k, i, jj):
        """Gemm fraud proof with VALID openings on the entry (i, jj), with the PUBLISHED value of Z."""
        j = st.progs[jid]
        d = st.data[(j["x0_root"], tuple(j["w_roots"]))]
        ((kind, p_),) = j["ops"][k].items()
        a = d["ws"][p_["w"]] if kind == "Gemm" else d["tens"][p_["a"]].T
        b = d["tens"][p_["x"]]
        z = d["zs"][k]
        rl = [S.leaf_hash(x, S.i8bytes(a[x])) for x in range(N)]
        cl = [S.leaf_hash(x, S.i8bytes(b[:, x])) for x in range(N)]
        zl = S.row_leaves(z)
        pr = lambda leaves, idx: [list(h) for h in S.merkle_proof(leaves, idx)]
        return {"Gemm": dict(i=i, j=jj, w_row=[int(v) for v in a[i]], w_path=pr(rl, i), x_col=[int(v) for v in b[:, jj]], x_path=pr(cl, jj),
                             z_row=[int(v) for v in z[i]], z_path=pr(zl, i))}

    attempt("fraud on a CORRECT entry (honest GEMM)", st_c, [signed(st_c, 3, P(Fraud=dict(job_id=hl(ids[0]), op=1, kind=gemm_proof(st_c, ids[0], 1, 3, 5))))], "not a fraud")
    bad_open = gemm_proof(st_c, ids[0], 1, 3, 5)
    bad_open["Gemm"]["w_row"][0] = bad_open["Gemm"]["w_row"][0] + 1 if bad_open["Gemm"]["w_row"][0] < 64 else 0
    attempt("fraud with a falsified row of W", st_c, [signed(st_c, 3, P(Fraud=dict(job_id=hl(ids[0]), op=1, kind=bad_open)))], "opening of W")
    act_on_add = {"Act": dict(i=0, j=0, z_row=[0] * N, z_path=[hl("00" * 32)] * 7, out_col=[0] * N, out_path=[hl("00" * 32)] * 7)}
    attempt("proof kind unsuitable for the operation (Act on Add)", st_c, [signed(st_c, 3, P(Fraud=dict(job_id=hl(ids[0]), op=6, kind=act_on_add)))], "does not match")
    attempt("acceptance by a third party", st_c, [signed(st_c, 3, P(Accept=dict(job_id=hl(ids[0]))))], "accept")
    attempt("settlement before the end of the window", st_c, [signed(st_c, 4, P(Settle=dict(job_id=hl(ids[0]))))], "cannot settle")
    attempt("useful block mined by a non-worker (Op)", st_c, [], "miner", miner=C.pub_hex(3), cls=("Op", bytes.fromhex(ids[0]), 1))
    # ---- program in progress: publication order, non-worker, double claim
    st_w = copy.deepcopy(snaps[last_block_of(ids[2], "Claim")])
    post = lambda op: P(PostOp=dict(job_id=hl(ids[2]), op=op, z_root=hl("00" * 32), x_root=hl("00" * 32)))
    attempt("out-of-order publication (operation 3 before 0)", st_w, [signed(st_w, 2, post(3))], "order")
    attempt("publication by a non-worker", st_w, [signed(st_w, 3, post(0))], "cannot publish")
    attempt("double claim", st_w, [signed(st_w, 3, P(Claim=dict(job_id=hl(ids[2]))))], "claimable")
    attempt("acceptance of an incomplete program", st_w, [signed(st_w, 1, P(Accept=dict(job_id=hl(ids[2]))))], "accept")
    # ---- submission
    st_s = copy.deepcopy(snaps[ks - 1])
    sub = next(t for t in V["blocks"][ks]["txs"] if prog_kind("Submit")(t["kind"]))["kind"]["Prog"]["Submit"]
    mk = lambda **kw: signed(st_s, 1, P(Submit=dict(sub, **kw)))
    attempt("escrow below the floor (per Gemm)", st_s, [mk(escrow=10**8)], "floor")
    attempt("deadline in the past", st_s, [mk(deadline=1)], "deadline")
    attempt("program without Gemm", st_s, [mk(ops=[{"Softmax": {"x": 1, "len": 4}}])], "invalid")
    attempt("program with a forward reference (Gemm reads a tensor not yet computed)", st_s, [mk(ops=[{"Gemm": {"w": 0, "x": 3, "shift": 4, "relu": True}}])], "invalid")
    attempt("shift out of bounds", st_s, [mk(ops=[{"Gemm": {"w": 0, "x": 0, "shift": 25, "relu": True}}])], "invalid")
    attempt("pooling that does not divide the size", st_s, [mk(ops=[{"Gemm": {"w": 0, "x": 0, "shift": 3, "relu": True}}, {"Pool": {"x": 1, "pool": {"Avg": {"c": 8, "h": 7, "w": 8, "batch": 2, "k": 2}}}}])], "invalid")
    attempt("valid submission: accepted", st_s, [signed(st_s, 1, P(Submit=dict(sub)))], "ACCEPTED")
    # ---- the 4 valid frauds of the vector set, replayed by another challenger: accepted
    for name in ("Gemm", "Act", "Elem", "Col"):
        kfr, tf = find_tx(lambda kd, name=name: "Prog" in kd and "Fraud" in kd["Prog"] and name in kd["Prog"]["Fraud"]["kind"])
        st_f = copy.deepcopy(snaps[kfr - 1])
        attempt(f"valid {name} fraud (replayed by another challenger): accepted", st_f, [signed(st_f, 1, tf["kind"])], "ACCEPTED")
    print("")

    build_extension(V, path)
    print("\nRESULT:", "TENSOR PROGRAMS VALIDATED BY THE INDEPENDENT IMPLEMENTATION" if bad == 0 else f"{bad} FAILURE(S)")
    return bad == 0


if __name__ == "__main__":
    sys.exit(0 if main(sys.argv[1]) else 1)
