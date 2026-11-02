#!/usr/bin/env bash

set -euo pipefail

image=${1:?Usage: verify-container-sandbox.sh IMAGE}
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
apparmor_options=()

if docker info --format '{{json .SecurityOptions}}' | grep -Fq '"name=apparmor"'; then
  sudo install -m 0644 "$repository_root/docker/codex-security.apparmor" \
    /etc/apparmor.d/codex-security-container
  sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
  sudo grep -Fxq 'codex-security-container (enforce)' \
    /sys/kernel/security/apparmor/profiles
  apparmor_options=(--security-opt apparmor=codex-security-container)
  if [[ -n ${GITHUB_ENV:-} ]]; then
    printf '%s\n' 'COMPOSE_FILE=compose.yaml:compose.apparmor.yaml' >> "$GITHUB_ENV"
  fi
fi

docker run --rm -i \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt "seccomp=$repository_root/docker/codex-security-seccomp.json" \
  "${apparmor_options[@]}" \
  --entrypoint /bin/sh "$image" -es <<'SH'
unshare --user --map-root-user --net python3 - <<'PYTHON'
import ctypes
import errno
import os
import socket
from unittest import TestCase

socket.socket(socket.AF_INET).close()
try:
    socket.socket(socket.AF_INET6).close()
except OSError as exc:
    if exc.errno != errno.EAFNOSUPPORT:
        raise
# A fresh user and network namespace grants CAP_NET_RAW only in this isolated namespace.
socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
with TestCase().assertRaises(PermissionError):
    socket.socket(socket.AF_INET, 10 | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC, 0)  # SOCK_PACKET
with TestCase().assertRaises(PermissionError):
    socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
for endpoint in socket.socketpair():
    endpoint.close()
socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE).close()

with TestCase().assertRaises(PermissionError):
    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_USERSOCK)
with TestCase().assertRaises(PermissionError):
    socket.socketpair(socket.AF_TIPC, socket.SOCK_SEQPACKET)

libc = ctypes.CDLL(None, use_errno=True)
assert libc.ptrace(0, 0, None, None) == -1 and ctypes.get_errno() == errno.EPERM  # PTRACE_TRACEME
for call in (libc.process_vm_readv, libc.process_vm_writev):
    assert call(os.getpid(), None, 0, None, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM
PYTHON
cd "$(dirname "$(readlink -f /usr/local/bin/codex-security)")"
exec npm exec --offline -- codex sandbox /usr/bin/true
SH
