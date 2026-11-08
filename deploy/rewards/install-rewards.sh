#!/bin/bash
# Installs the leaderboard refresh on the web server (docs/19): the script, a systemd service and an hourly timer.
#   bash deploy/rewards/install-rewards.sh
# Needs the nginx location /rewards/ (bash deploy/deploy-site.sh --nginx --with-leaderboard publishes it with the page).
set -euo pipefail
cd "$(dirname "$0")/../.."
KEY="-i ${VEARL_SSH_KEY:-$HOME/.ssh/id_ed25519} -o IdentitiesOnly=yes"   # override with VEARL_SSH_KEY
HOST=${VEARL_SSH_HOST:?set VEARL_SSH_HOST, for example root@your-server}   # the web/seed server (override with VEARL_SSH_HOST)
scp -q $KEY vearl-core/tools/testnet_rewards.py vearl-core/tools/pool_points.py vearl-core/tools/audit_pools.py vearl-core/tools/audit_batches.py vearl-core/tools/fetch_pool_bundle.py vearl-core/tools/verify_registration.py deploy/rewards/vearl-rewards.sh deploy/rewards/vearl-rewards.service deploy/rewards/vearl-rewards.timer $HOST:/root/
ssh $KEY $HOST 'set -e
install -d -m 0755 /opt/vearl/tools
install -m 0755 /root/testnet_rewards.py /opt/vearl/tools/testnet_rewards.py
for f in pool_points audit_batches audit_pools fetch_pool_bundle verify_registration; do install -m 0755 /root/$f.py /opt/vearl/tools/$f.py; done
install -m 0755 /root/vearl-rewards.sh /opt/vearl/bin/vearl-rewards.sh
install -d -o vearl -g vearl -m 0755 /var/www/vearl-rewards
install -m 0644 /root/vearl-rewards.service /etc/systemd/system/vearl-rewards.service
install -m 0644 /root/vearl-rewards.timer /etc/systemd/system/vearl-rewards.timer
rm -f /root/testnet_rewards.py /root/pool_points.py /root/audit_pools.py /root/audit_batches.py /root/fetch_pool_bundle.py /root/verify_registration.py /root/vearl-rewards.sh /root/vearl-rewards.service /root/vearl-rewards.timer
systemctl daemon-reload
systemctl enable --now vearl-rewards.timer
systemctl start vearl-rewards.service || true
sleep 3
systemctl is-active vearl-rewards.timer
ls -la /var/www/vearl-rewards'
