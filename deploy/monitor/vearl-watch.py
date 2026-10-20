#!/usr/bin/env python3
"""Minimal health check of a Vearl node, meant to run every minute from a systemd timer (deploy/monitor/).

    vearl-watch.py [--api http://127.0.0.1:8545] [--state /var/lib/vearl/watch.json] [--stall-secs 300] [--webhook-file /etc/vearl/alert-webhook]

It reads GET /api/status and raises an alert when
  - the node does not answer,
  - it has no peer,
  - the height has not increased for --stall-secs (the chain is stuck, or this node is cut off from it),
  - the supply invariant is false, missing or invalid.
An alert is written to stderr (so to the journal) and, if the webhook file exists (one line: a Discord webhook URL), posted there once;
a message "recovered" follows when everything is fine again. State is kept in a small JSON file so that the same alert is not sent every minute.
Alerts are deduplicated by fault kind. Upgrading an old state file may emit one
fresh alert for an ongoing fault before subsequent checks become silent.
Python 3 standard library only. Exit code 0 = healthy, 1 = alert, 2 = cannot save state.
"""
import argparse
import json
import os
import sys
import time
import urllib.request


def fetch(api, path):
    with urllib.request.urlopen(api + path, timeout=8) as r:
        return json.loads(r.read())


def notify(webhook_file, text):
    print(text, file=sys.stderr, flush=True)
    try:
        url = open(webhook_file).read().strip()
    except OSError:
        return
    if not url.startswith("https://"):
        return
    body = json.dumps({"content": text[:1800]}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "vearl-watch"})
    try:
        urllib.request.urlopen(req, timeout=8).read()
    except Exception as e:  # an unreachable webhook must not hide the alert in the journal
        print("webhook failed:", e, file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8545")
    ap.add_argument("--state", default="/var/lib/vearl/watch.json")
    ap.add_argument("--stall-secs", type=int, default=300)
    ap.add_argument("--webhook-file", default="/etc/vearl/alert-webhook")
    ap.add_argument("--name", default="vearl seed")
    a = ap.parse_args()
    now = int(time.time())
    try:
        with open(a.state) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    if not isinstance(st, dict):
        st = {}
    problem = None
    problem_key = None
    try:
        s = fetch(a.api, "/api/status")
        h, peers = s.get("height"), s.get("peers")
        if type(h) is not int or h < 0 or type(peers) is not int or peers < 0:
            raise ValueError("missing or invalid height/peers")
        if h != st.get("height"):
            st["height"], st["height_since"] = h, now
        if s.get("supply_invariant") is False:
            problem_key, problem = "supply_invariant", "SUPPLY INVARIANT IS FALSE"
        elif s.get("supply_invariant") is not True:
            problem_key, problem = "invariant_unavailable", "supply invariant is missing or invalid"
        elif peers == 0:
            problem_key, problem = "no_peer", f"no peer (height {h})"
        elif now - st.get("height_since", now) > a.stall_secs:
            problem_key = "stalled"
            problem = f"height stuck at {h} for {(now - st['height_since']) // 60} min"
    except Exception as e:
        problem_key, problem = "unreachable", f"node does not answer ({e})"
    # Human-readable details may change while the same fault persists. Deduplicate
    # on a stable fault key rather than height, elapsed minutes or exception text.
    was = st.get("alert_key") or ("legacy" if st.get("alert") else None)
    if problem_key and problem_key != was:
        notify(a.webhook_file, f"[{a.name}] ALERT: {problem}")
    elif not problem_key and was:
        notify(a.webhook_file, f"[{a.name}] recovered (height {st.get('height')})")
    st["alert_key"], st["alert"] = problem_key, problem
    tmp = a.state + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, a.state)
    except OSError as e:
        print("cannot save state:", e, file=sys.stderr)
        sys.exit(2)
    sys.exit(1 if problem else 0)


if __name__ == "__main__":
    main()
