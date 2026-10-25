#!/bin/bash
# vearl-launch.sh: puts the Vearl testnet on line BY ITSELF at the launch time (docs/06 section 3 sexies).
#
# Run every minute by vearl-launch.timer (as root, on the seed server). It does nothing before the launch time and nothing once everything is on line.
# Stages, each idempotent, each checked before it counts, each undone if its check fails:
#   1. api      at the launch time: the explorer's /api/ reads the real node (nginx snippet vearl-api.conf: sample -> live)
#   2. fund     once the chain has MIN_HEIGHT blocks: the faucet wallet (on this server) pays the service wallet of the job gateway
#   3. gateway  once the service wallet is funded: starts vearl-gateway and opens /gw/ (snippet vearl-gw.conf: prelaunch -> live), so /compute/ creates jobs
#   4. faucet   publishes the faucet page (/faucet/); the faucet service already runs behind /drip
# It never switches to a network whose genesis hash is not GENESIS_HASH. Status: `vearl-launch.sh --status`; read-only checks any day: `--check`.
# Logs go to the journal (journalctl -u vearl-launch); a short e-mail goes to NOTIFY_TO when a stage succeeds or keeps failing.
set -u

: "${LAUNCH_TS:=1792771200}"                    # 2026-10-23 16:00:00 UTC
: "${GENESIS_HASH:=a5771be72054adbfca6654cef5d4dbbcfb350655c3e901bfa2f5e626ada4b744}"
: "${NODE_API:=127.0.0.1:8545}"                 # the node's read-only HTTP API
: "${NODE_P2P:=127.0.0.1:9000}"                 # the node's peer port (wallet requests, loopback is never limited)
: "${MIN_HEIGHT:=3}"                            # blocks needed before the wallet, the gateway and the faucet are started
: "${FUND_AMOUNT:=100000}"                      # VRL sent to the service wallet (2 VRL of escrow per free job)
: "${FUND_MIN:=1000}"                           # the service wallet counts as funded from this balance
: "${STATE_DIR:=/var/lib/vearl-launch}"
: "${LIB:=/opt/vearl/launch}"                   # the files this script installs (nginx snippets, faucet page)
: "${SNIP:=/etc/nginx/snippets}"
: "${SITE:=/var/www/vearl}"
: "${CACHE_DIR:=/var/cache/nginx/vearl}"           # the nginx micro-cache of the API and the gateway
: "${WALLET:=/opt/vearl/bin/vearl-wallet}"
: "${FAUCET_WALLET:=/etc/vearl/faucet-wallet.json}"
: "${FAUCET_PW:=/etc/vearl/faucet-password}"
: "${SERVICE_WALLET:=/etc/vearl-gateway/service-wallet.json}"
: "${GW_LOCAL:=127.0.0.1:18610}"
: "${SITE_HOST:=vearl.org}"
: "${NOTIFY_TO=contact@vearl.org}"              # empty = no e-mail (no colon: an empty value is kept, not replaced by the default)
: "${RETRY_AFTER:=300}"                         # seconds between two tries of a stage that failed 3 times
: "${PRELAUNCH_CHECKS:=1}"                      # 1 = e-mail a full check an hour before the launch

log() { echo "[vearl-launch] $*"; }
now() { date -u +%s; }
has() { [ -f "$STATE_DIR/$1" ]; }
mark() { now > "$STATE_DIR/$1"; }
age() { local f="$STATE_DIR/$1"; [ -f "$f" ] && echo $(( $(now) - $(cat "$f") )) || echo 999999999; }

# ---------------------------------------------------------------- the world: every effect goes through one of these functions (the test replaces them)
api_status() { curl -fsS -m 5 "http://$NODE_API/api/status"; }
jget() { "${PY:-python3}" -c 'import sys,json; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1" 2>/dev/null; }
site_get() { curl -ksS -m 10 --resolve "$SITE_HOST:443:127.0.0.1" "https://$SITE_HOST$1"; }
cache_purge() { rm -rf "${CACHE_DIR:?}"/* 2>/dev/null || true; }   # the micro-cache must never keep an answer of the previous snippet (sample network, pre-launch gateway)
nginx_set() {   # $1 snippet name, $2 new content: install it, test nginx, reload; undo if anything fails
  local dst="$SNIP/$1"
  cp -a "$dst" "$STATE_DIR/$1.bak" 2>/dev/null || true
  install -m 644 "$2" "$dst" || return 1
  if ! nginx -t >/dev/null 2>&1 || ! systemctl reload nginx; then nginx_restore "$1"; return 1; fi
  cache_purge
}
nginx_restore() { [ -f "$STATE_DIR/$1.bak" ] && cp -a "$STATE_DIR/$1.bak" "$SNIP/$1" && nginx -t >/dev/null 2>&1 && systemctl reload nginx && cache_purge; }
svc_active() { systemctl is-active --quiet "$1"; }
svc_start() { systemctl enable --now "$1" >/dev/null 2>&1; }
gw_info() { curl -fsS -m 5 "http://$GW_LOCAL/gw/info"; }
wallet_address() { jget address < "$1"; }      # the address is in the wallet file itself (no password, no binary)
wallet_balance() { "$WALLET" balance --address "$1" --node "$NODE_P2P" 2>/dev/null | awk '{print $1}'; }
wallet_send() { "$WALLET" send --file "$FAUCET_WALLET" --password-file "$FAUCET_PW" --node "$NODE_P2P" --to "$1" --amount "$FUND_AMOUNT" 2>&1; }
install_page() { install -d -m 755 "$SITE/faucet" && install -m 644 "$LIB/faucet/index.html" "$SITE/faucet/index.html"; }
notify() {      # $1 subject, $2 body; at most once per subject and per 30 minutes
  [ -n "$NOTIFY_TO" ] || return 0
  local key; key="mail_$(echo "$1" | tr -c 'a-zA-Z0-9' '_' | cut -c1-60)"
  [ "$(age "$key")" -ge 1800 ] || return 0
  command -v sendmail >/dev/null 2>&1 || return 0
  printf 'From: Vearl launch <contact@vearl.org>\nTo: %s\nSubject: [vearl-launch] %s\n\n%s\n' "$NOTIFY_TO" "$1" "$2" | sendmail -t -f contact@vearl.org 2>/dev/null && mark "$key"
}
ge() { awk -v a="${1:-0}" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }

# a stage that failed 3 times is retried only every RETRY_AFTER seconds (no nginx reload every minute)
may_try() { local n; n=$(cat "$STATE_DIR/fails_$1" 2>/dev/null || echo 0); [ "$n" -lt 3 ] || [ "$(age "tried_$1")" -ge "$RETRY_AFTER" ]; }
failed() { local n; n=$(cat "$STATE_DIR/fails_$1" 2>/dev/null || echo 0); echo $((n + 1)) > "$STATE_DIR/fails_$1"; mark "tried_$1"; log "stage $1 FAILED: $2"; [ $((n + 1)) -ge 3 ] && notify "stage $1 keeps failing" "$2"; return 1; }
succeeded() { rm -f "$STATE_DIR/fails_$1"; mark "$1.done"; log "stage $1 done"; notify "$1 is on line" "$2"; }

# ---------------------------------------------------------------- stages
stage_api() {
  has api.done && return 0
  may_try api || return 1
  [ -f "$LIB/nginx-vearl-api-live.conf" ] || { failed api "missing $LIB/nginx-vearl-api-live.conf"; return 1; }
  nginx_set vearl-api.conf "$LIB/nginx-vearl-api-live.conf" || { failed api "nginx refused the live snippet (undone)"; return 1; }
  sleep 1
  local h; h=$(site_get /api/status | jget genesis_hash)
  if [ "$h" != "$GENESIS_HASH" ]; then nginx_restore vearl-api.conf; failed api "https /api/status answers genesis '$h' instead of the testnet (undone)"; return 1; fi
  succeeded api "The explorer (https://$SITE_HOST/explorer/) now reads the real testnet node."
}

stage_fund() {
  has fund.done && return 0
  may_try fund || return 1
  local addr bal
  addr=$(wallet_address "$SERVICE_WALLET"); [ -n "$addr" ] || { failed fund "cannot read the address of the service wallet"; return 1; }
  bal=$(wallet_balance "$addr")
  if ge "$bal" "$FUND_MIN"; then succeeded fund "The service wallet of the job gateway holds $bal VRL."; return 0; fi
  # a transfer sent less than 15 minutes ago is waited for, never sent twice
  if has fund.sent && [ "$(age fund.sent)" -lt 900 ]; then log "fund: transfer sent $(age fund.sent) s ago, waiting for it to be included"; return 1; fi
  local out; out=$(wallet_send "$addr")
  if echo "$out" | grep -q "accepted by the node"; then mark fund.sent; log "fund: $FUND_AMOUNT VRL sent to $addr"; return 1; fi
  failed fund "the transfer was refused: $(echo "$out" | tail -n 1)"
}

stage_gateway() {
  has gateway.done && return 0
  has fund.done || return 1
  may_try gateway || return 1
  [ -f "$LIB/nginx-vearl-gw-live.conf" ] || { failed gateway "missing $LIB/nginx-vearl-gw-live.conf"; return 1; }
  svc_active vearl-gateway || svc_start vearl-gateway
  local i ok=0
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do gw_info 2>/dev/null | grep -q '"kinds"' && { ok=1; break; }; sleep 5; done
  [ "$ok" = 1 ] || { failed gateway "the gateway does not answer on $GW_LOCAL"; return 1; }
  nginx_set vearl-gw.conf "$LIB/nginx-vearl-gw-live.conf" || { failed gateway "nginx refused the live snippet (undone)"; return 1; }
  sleep 1
  local info; info=$(site_get /gw/info)
  if ! echo "$info" | grep -q '"kinds"' || echo "$info" | grep -q '"prelaunch":true'; then nginx_restore vearl-gw.conf; failed gateway "https /gw/info is not the live gateway (undone)"; return 1; fi
  succeeded gateway "Job creation is open: https://$SITE_HOST/compute/"
}

stage_faucet() {
  has faucet.done && return 0
  has fund.done || return 1      # the service wallet is paid first: the faucet wallet's transactions must not cross
  may_try faucet || return 1
  [ -f "$LIB/faucet/index.html" ] || { failed faucet "missing $LIB/faucet/index.html"; return 1; }
  svc_active vearl-faucet || svc_start vearl-faucet
  svc_active vearl-faucet || { failed faucet "the faucet service is not running"; return 1; }
  install_page || { failed faucet "cannot publish the faucet page"; return 1; }
  site_get /faucet/ | grep -q 'faucet.js' || { failed faucet "https /faucet/ does not answer"; return 1; }
  succeeded faucet "The faucet page is published: https://$SITE_HOST/faucet/"
}

# the demo network of the sample explorer is of no use once the real one is on line: its nodes give their memory back to the real node
stage_demo_off() {
  has demo_off.done && return 0
  local u; for u in vearl-demo-a vearl-demo-b vearl-demo-c vearl-gateway-demo; do systemctl disable --now "$u" >/dev/null 2>&1 || true; done
  mark demo_off.done; log "demo nodes stopped"
}

all_done() { has api.done && has fund.done && has gateway.done && has faucet.done; }

main() {
  mkdir -p "$STATE_DIR" 2>/dev/null || { echo "cannot create $STATE_DIR" >&2; return 1; }
  exec 9> "$STATE_DIR/lock"; flock -n 9 || return 0
  has live && return 0
  if [ "$(now)" -lt "$LAUNCH_TS" ]; then
    # before the launch: one full check an hour before (the result is e-mailed, good or bad), then every 6 hours only if something is wrong
    if [ "$PRELAUNCH_CHECKS" = 1 ]; then
      if [ "$(now)" -ge $((LAUNCH_TS - 3600)) ] && ! has preflight_final; then
        mark preflight_final; local out; out=$(check 2>&1); notify "check one hour before the launch" "$out"
      elif [ "$(age preflight)" -ge 21600 ]; then
        mark preflight; local out; out=$(check 2>&1) || notify "pre-launch check found a problem" "$out"
      fi
    fi
    return 0
  fi
  local st gen height
  st=$(api_status) || { log "the node does not answer on $NODE_API"; return 1; }
  gen=$(echo "$st" | jget genesis_hash); height=$(echo "$st" | jget height)
  if [ "$gen" != "$GENESIS_HASH" ]; then log "REFUSED: the node runs genesis '$gen', not the testnet's"; notify "wrong genesis" "The node on $NODE_API runs genesis $gen instead of $GENESIS_HASH. Nothing was switched."; return 3; fi
  has launched || { mark launched; log "launch time reached (height $height)"; }
  stage_api
  [ "${height:-0}" -ge "$MIN_HEIGHT" ] 2>/dev/null || { log "waiting for the chain: height ${height:-?} of $MIN_HEIGHT"; return 0; }
  stage_fund
  stage_gateway
  stage_faucet
  if all_done; then mark live; log "EVERYTHING IS ON LINE"; stage_demo_off; notify "everything is on line" "Explorer, job creation and faucet are on line. Chain height: $height. The demo nodes of the sample explorer are stopped."; fi
  return 0
}

status() {
  echo "launch time: $(date -u -d @"$LAUNCH_TS" '+%F %T') UTC (now $(date -u '+%F %T'))"
  local s; for s in launched api.done fund.sent fund.done gateway.done faucet.done live demo_off.done; do
    if has "$s"; then echo "  [x] $s  ($(date -u -d @"$(cat "$STATE_DIR/$s")" '+%F %T') UTC)"; else echo "  [ ] $s"; fi
  done
  ls "$STATE_DIR" 2>/dev/null | grep '^fails_' | while read -r f; do echo "  failures $f: $(cat "$STATE_DIR/$f")"; done
}

# read-only checks of everything the launch needs (any day): prints OK / WARN / FAIL lines, exit 1 on a FAIL
check() {
  local bad=0
  ok() { echo "OK    $*"; }; warn() { echo "WARN  $*"; }; fail() { echo "FAIL  $*"; bad=1; }
  local st gen height
  if st=$(api_status); then
    gen=$(echo "$st" | jget genesis_hash); height=$(echo "$st" | jget height)
    [ "$gen" = "$GENESIS_HASH" ] && ok "node on the testnet genesis (height $height, $(echo "$st" | jget peers) peers)" || fail "node genesis is '$gen'"
  else fail "node does not answer on $NODE_API"; fi
  nginx -t >/dev/null 2>&1 && ok "nginx configuration valid" || fail "nginx -t fails"
  local f
  for f in "$LIB/nginx-vearl-api-live.conf" "$LIB/nginx-vearl-gw-live.conf" "$LIB/faucet/index.html" "$SNIP/vearl-api.conf" "$SNIP/vearl-gw.conf" "$FAUCET_WALLET" "$FAUCET_PW" "$SERVICE_WALLET" "$WALLET"; do
    [ -f "$f" ] && ok "file $f" || fail "missing $f"
  done
  grep -q 'proxy_pass http://127.0.0.1:8545' "$LIB/nginx-vearl-api-live.conf" 2>/dev/null && ok "live API snippet points to the real node" || fail "live API snippet is wrong"
  grep -q '127.0.0.1:18610' "$LIB/nginx-vearl-gw-live.conf" 2>/dev/null && ok "live gateway snippet points to the gateway" || fail "live gateway snippet is wrong"
  local faddr saddr fb sb
  faddr=$(wallet_address "$FAUCET_WALLET"); saddr=$(wallet_address "$SERVICE_WALLET")
  [ -n "$faddr" ] && ok "faucet wallet $faddr" || fail "cannot read the faucet wallet"
  [ -n "$saddr" ] && ok "service wallet $saddr" || fail "cannot read the service wallet"
  fb=$(wallet_balance "$faddr"); sb=$(wallet_balance "$saddr")
  ge "$fb" $((FUND_AMOUNT + 1000)) && ok "faucet wallet holds $fb VRL (needs $FUND_AMOUNT + the faucet's own payouts)" || fail "faucet wallet holds only '$fb' VRL"
  [ -n "$sb" ] && ok "service wallet balance: $sb VRL" || warn "cannot read the service wallet balance"
  svc_active vearl-faucet && ok "vearl-faucet running" || fail "vearl-faucet not running"
  svc_active vearl-node && ok "vearl-node running" || fail "vearl-node not running"
  systemctl cat vearl-gateway >/dev/null 2>&1 && ok "vearl-gateway unit installed" || fail "vearl-gateway unit missing"
  systemctl is-active --quiet vearl-gateway-peers.timer && ok "gateway peers timer active" || warn "gateway peers timer not active"
  systemctl is-active --quiet vearl-launch.timer && ok "vearl-launch.timer active" || warn "vearl-launch.timer not active"
  [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && ok "clock synchronised" || warn "clock not reported as synchronised"
  grep -q -- '--relay' /etc/vearl/node.env 2>/dev/null && ok "seed node runs with --relay (miners behind a router can serve jobs)" || warn "no --relay on the seed node"
  local sg; sg=$(site_get /api/status | jget genesis_hash)
  [ -n "$sg" ] && ok "https /api/ answers (genesis ${sg:0:8}...)" || fail "https /api/ does not answer (the explorer shows 'No node reachable')"
  [ -f "$SITE/compute/index.html" ] && ok "compute page published" || fail "compute page not published"
  [ -f "$SITE/explorer/index.html" ] && ok "explorer page published" || fail "explorer page not published"
  [ "$bad" = 0 ] && echo "ALL GOOD" || echo "PROBLEMS FOUND"
  return "$bad"
}

[ -n "${VEARL_LAUNCH_SOURCE_ONLY:-}" ] && return 0 2>/dev/null
case "${1:-}" in
  --status) status ;;
  --check) check ;;
  "") main ;;
  *) echo "usage: vearl-launch.sh [--status | --check]" >&2; exit 2 ;;
esac
