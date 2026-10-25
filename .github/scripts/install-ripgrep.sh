#!/usr/bin/env bash
set -euo pipefail

# Hosted Ubuntu images already have package lists. Refresh them if the install fails.
if ! sudo apt-get install --yes ripgrep; then
  sudo apt-get update
  sudo apt-get install --yes ripgrep
fi
