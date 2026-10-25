#!/usr/bin/env bash
# Count failed SSH logins by source IP.
# Usage: ./failed_ssh_by_ip.sh /var/log/auth.log
set -euo pipefail

LOG="${1:-/var/log/auth.log}"
[[ -r "$LOG" ]] || { echo "Cannot read $LOG" >&2; exit 1; }

echo "Count  Source IP"
grep "Failed password" "$LOG" \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
  | sort | uniq -c | sort -rn
