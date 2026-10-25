#!/bin/bash
# Publish the website to the VPS: public files only (site/tools stays local), then optionally the nginx config.
# CSS/JS/font-stylesheet URLs get a content fingerprint (?v=hash) so browsers can cache them for a year and still see every update.
#   bash deploy/deploy-site.sh [--nginx] [--with-explorer] [--with-faucet] [--with-compute] [--with-leaderboard] [--with-participate] [--with-team]
#   --with-faucet also publishes the faucet page (/faucet/). It needs the faucet service behind /drip (deploy/systemd/vearl-faucet.service) and --nginx once.
#   --with-participate also publishes the page that explains how to take part in the testnet (/participate/).
#   --with-team also publishes the team page (/team/): one card per member, the details open from the photo.
#   --with-leaderboard also publishes the testnet contributors leaderboard (/leaderboard/, docs/19). Its data is written by deploy/rewards/ (install-rewards.sh) into
#   /var/www/vearl-rewards, served at /rewards/ (needs --nginx once).
#   --nginx installs the config; the explorer's /api/ reads the demo network until you pass --api-live (at the launch, once the real node answers on 127.0.0.1:8545)
#   After the launch (the server has /var/lib/vearl-launch/live) --api-live, --gw-live and --with-faucet are implied; --sample goes back to the pre-launch variants.
#   --with-explorer also publishes the testnet explorer (/explorer/); without it the page is not copied, so nothing links to a node that is not online yet.
#   --with-compute also publishes the job-creation site (/compute/). Before the testnet starts /gw/ answers with fixed files (deploy/gateway/prelaunch/): the page is
#   complete but no job can be created. With --nginx --gw-live /gw/ is the real job gateway (deploy/gateway/) instead: use it only once the gateway runs on the public network.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY="-i ${VEARL_SSH_KEY:-$HOME/.ssh/id_ed25519} -o IdentitiesOnly=yes"   # override with VEARL_SSH_KEY
HOST=${VEARL_SSH_HOST:?set VEARL_SSH_HOST, for example root@your-server}   # the web/seed server (override with VEARL_SSH_HOST)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
ARGS=" $* "
# once the launch switch has put the testnet on line (/var/lib/vearl-launch/live on the server), a redeploy keeps it on line: the live explorer API and job gateway,
# and the faucet page (rsync --delete would remove it). --sample forces the pre-launch variants again.
if [[ "$ARGS" != *" --sample "* ]] && [ "$(ssh $KEY $HOST 'test -f /var/lib/vearl-launch/live && echo 1 || echo 0' 2>/dev/null || echo 0)" = 1 ]; then
  echo "the testnet is on line: keeping the live API, the live gateway and the faucet page"
  ARGS="$ARGS --api-live --gw-live --with-faucet "
fi
( cd site && cp -r index.html 404.html credits.html whitepaper.html robots.txt sitemap.xml favicon.svg favicon-32.png apple-touch-icon.png og-image.png mark.svg assets fonts "$OUT"/ )
if [[ "$ARGS" == *" --with-explorer "* ]]; then cp -r site/explorer "$OUT"/; fi
if [[ "$ARGS" == *" --with-compute "* ]]; then cp -r site/compute "$OUT"/; mkdir -p "$OUT/gw-static"; cp deploy/gateway/prelaunch/info.json deploy/gateway/prelaunch/digits.json "$OUT/gw-static/"; fi
if [[ "$ARGS" == *" --with-faucet "* ]]; then cp -r site/faucet "$OUT"/; fi
if [[ "$ARGS" == *" --with-leaderboard "* ]]; then cp -r site/leaderboard "$OUT"/; fi
if [[ "$ARGS" == *" --with-participate "* ]]; then cp -r site/participate "$OUT"/; fi
if [[ "$ARGS" == *" --with-team "* ]]; then cp -r site/team "$OUT"/; fi
PAGES="$OUT/index.html $OUT/404.html $OUT/credits.html $OUT/whitepaper.html"
[ -f "$OUT/explorer/index.html" ] && PAGES="$PAGES $OUT/explorer/index.html"
[ -f "$OUT/compute/index.html" ] && PAGES="$PAGES $OUT/compute/index.html"
[ -f "$OUT/faucet/index.html" ] && PAGES="$PAGES $OUT/faucet/index.html"
[ -f "$OUT/leaderboard/index.html" ] && PAGES="$PAGES $OUT/leaderboard/index.html"
[ -f "$OUT/participate/index.html" ] && PAGES="$PAGES $OUT/participate/index.html"
[ -f "$OUT/team/index.html" ] && PAGES="$PAGES $OUT/team/index.html"
for f in assets/site.css assets/site.js assets/photos.js assets/whitepaper.css assets/whitepaper.js assets/explorer.css assets/explorer.js assets/compute.css assets/compute.js assets/faucet.js assets/leaderboard.js assets/nav.js assets/participate.css assets/team.css assets/team.js fonts/fonts.css; do
  h=$(md5sum "site/$f" | cut -c1-10)
  sed -i "s#/$f\"#/$f?v=$h\"#g" $PAGES
done
grep -o '/assets/site\.[a-z]*?v=[0-9a-f]*\|/fonts/fonts\.css?v=[0-9a-f]*' "$OUT/index.html"
tar czf - -C "$OUT" . \
  | ssh $KEY $HOST 'rm -rf ~/vearl-www && mkdir -p ~/vearl-www && tar xzf - -C ~/vearl-www && sudo mkdir -p /var/www/vearl && sudo rsync -a --delete ~/vearl-www/ /var/www/vearl/ && sudo chown -R root:root /var/www/vearl && sudo find /var/www/vearl -type d -exec chmod 755 {} + && sudo find /var/www/vearl -type f -exec chmod 644 {} + && echo site-ok'
if [[ "$ARGS" == *" --nginx "* ]]; then
  GW=prelaunch; [[ "$ARGS" == *" --gw-live "* ]] && GW=live
  API=sample; [[ "$ARGS" == *" --api-live "* ]] && API=live
  scp -q $KEY deploy/nginx-vearl.conf deploy/nginx-vearl-headers.conf deploy/nginx-vearl-locations.conf deploy/nginx-vearl-gw-$GW.conf deploy/nginx-vearl-api-$API.conf $HOST:~/
  ssh $KEY $HOST 'sudo install -m 644 ~/nginx-vearl-headers.conf /etc/nginx/snippets/vearl-headers.conf && sudo install -m 644 ~/nginx-vearl-locations.conf /etc/nginx/snippets/vearl-locations.conf && sudo install -m 644 ~/nginx-vearl-gw-'"$GW"'.conf /etc/nginx/snippets/vearl-gw.conf && sudo install -m 644 ~/nginx-vearl-api-'"$API"'.conf /etc/nginx/snippets/vearl-api.conf && sudo install -m 644 ~/nginx-vearl.conf /etc/nginx/sites-available/vearl && sudo ln -sfn /etc/nginx/sites-available/vearl /etc/nginx/sites-enabled/vearl && sudo rm -f /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx && echo nginx-ok'
fi
