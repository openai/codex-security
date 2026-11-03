#!/usr/bin/env bash
set -euo pipefail

# The hosted image's unrelated PHP service times out during needrestart.
sudo tee /etc/needrestart/conf.d/action-ci.conf > /dev/null <<'EOF'
$nrconf{override_rc}{qr(^php8\.3-fpm\.service$)} = 0;
EOF
sudo apt-get update
sudo apt-get install --yes bubblewrap apparmor-profiles
sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
