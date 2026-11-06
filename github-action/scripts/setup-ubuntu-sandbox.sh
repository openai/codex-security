#!/usr/bin/env bash
set -euo pipefail

# The hosted image's unrelated PHP service times out during needrestart.
sudo tee /etc/needrestart/conf.d/action-ci.conf > /dev/null <<'EOF'
$nrconf{override_rc}{qr(^php8\.3-fpm\.service$)} = 0;
EOF
sudo apt-get update
sudo apt-get install --yes bubblewrap apparmor-profiles
bwrap_profile=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
# Ubuntu 26.04 installs this profile under /etc/apparmor.d.
if [[ ! -f "$bwrap_profile" ]]; then
  bwrap_profile=/etc/apparmor.d/bwrap-userns-restrict
fi
sudo apparmor_parser -r "$bwrap_profile"
