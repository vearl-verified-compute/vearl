#!/bin/bash
# Refreshes the public leaderboard of the testnet contributors program (docs/19) from the local node. Runs every hour (vearl-rewards.timer).
# Writes /var/www/vearl-rewards/{leaderboard.json,leaderboard.csv,blocks.json}, served by nginx at https://vearl.org/rewards/.
# Optional files: the registered addresses (/var/lib/vearl-register/rewards-registered.json, made by tools/process_registration_mail.py,
# or a hand-made /etc/vearl/rewards-registered.json from tools/verify_registration.py) and /etc/vearl/rewards-excluded.txt.
set -euo pipefail
START=${VEARL_TESTNET_START:-2026-10-23T16:00:00Z}
NODE=127.0.0.1:8545
OUT=/var/www/vearl-rewards
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# The node must be up to date. A node that is behind (restarting, syncing, stuck) makes honest pools look like liars to the audit (2026-10-29: three pools
# marked "fraud" because the node had been stuck for a day), so nothing is published from it: the leaderboard stays as it was until the node has caught up.
AGE=$(curl -fsS -m 10 "http://$NODE/api/status" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(0, d["node_time"] - d["tip_timestamp"]))' 2>/dev/null || echo 999999)
MAX_AGE=${VEARL_REWARDS_MAX_TIP_AGE:-600}
if [ "$AGE" -gt "$MAX_AGE" ]; then
  echo "the last block of the node is $AGE s old (limit $MAX_AGE s): the leaderboard and the pool audit are left as they were" >&2
  exit 0
fi
# ONE fresh copy of the chain for the pool audit and for the leaderboard. The audit used to read the copy of the PREVIOUS run, up to an hour old, so the hour
# that had just ended looked as if the pool had built jobs above the chain.
python3 /opt/vearl/tools/testnet_rewards.py --node "$NODE" --start "$START" --out "$TMP" --dump-blocks-only
ARGS=(--blocks-file "$TMP/blocks.json" --start "$START" --out "$TMP")
# the team can leave the first minutes of the testnet out of the score (docs/19): echo 30 > /etc/vearl/rewards-grace-minutes (absent: all blocks count)
[ -s /etc/vearl/rewards-grace-minutes ] && ARGS+=(--grace-minutes "$(tr -dc 0-9 < /etc/vearl/rewards-grace-minutes)")
# registered addresses: the list made by the registration processor (docs/19, vearl-register.timer), or a hand-made file
if [ -s /var/lib/vearl-register/rewards-registered.json ]; then
  ARGS+=(--registered /var/lib/vearl-register/rewards-registered.json)
elif [ -s /etc/vearl/rewards-registered.json ]; then
  ARGS+=(--registered /etc/vearl/rewards-registered.json)
fi
[ -s /etc/vearl/rewards-excluded.txt ] && ARGS+=(--exclude /etc/vearl/rewards-excluded.txt)
# addresses that use the Quantus add-on without paying the development fee are not eligible (deploy/feeaudit, docs/17); the counts are public
[ -s /var/lib/vearl/feeaudit/compliance.json ] && ARGS+=(--fee-compliance /var/lib/vearl/feeaudit/compliance.json)
# registered mining pools (docs/19 section 3 bis): /etc/vearl/rewards-pools.json lists them; their signed ledgers are audited first, with the fresh blocks,
# and the audit reports are read by the leaderboard
if [ -s /etc/vearl/rewards-pools.json ]; then
  if [ -x /opt/vearl/bin/vearl-pool-audit ]; then
    python3 /opt/vearl/tools/audit_pools.py --spec /etc/vearl/rewards-pools.json --genesis /etc/vearl/genesis.json --blocks "$TMP/blocks.json" \
      --audit-bin /opt/vearl/bin/vearl-pool-audit --last 72 || echo "pool audit failed (the previous reports stay in force)" >&2
  fi
  ARGS+=(--pools /etc/vearl/rewards-pools.json)
fi
python3 /opt/vearl/tools/testnet_rewards.py "${ARGS[@]}"
[ -s /var/lib/vearl/feeaudit/fee-stats.json ] && install -m 0644 /var/lib/vearl/feeaudit/fee-stats.json "$OUT/fee-stats.json.new" && mv "$OUT/fee-stats.json.new" "$OUT/fee-stats.json"
for f in leaderboard.json leaderboard.csv blocks.json; do
  install -m 0644 "$TMP/$f" "$OUT/$f.new"
  mv "$OUT/$f.new" "$OUT/$f"
done
