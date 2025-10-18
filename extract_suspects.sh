#!/usr/bin/env bash
# extract_suspects.sh
# Ajuste LOG_GLOB se os seus arquivos tiverem outro nome
LOG_GLOB="/var/log/fortigate-*.log"
OUT="/opt/auto-block/logs/suspects_raw.txt"
TMP="/tmp/suspects.tmp"

# Regex to extract srcip and full line timestamp (works with Forti syslog)
# We'll output: TIMESTAMP|SRCIP|FULL_LINE
: > "$TMP"
for f in $LOG_GLOB; do
  [ -f "$f" ] || continue
  # grep for lines with action="dropped" (case sensitive) and containing srcip=
  grep 'action="dropped"' "$f" | while read -r line; do
    # try to extract srcip and timestamp (first fields in syslog)
    # Example syslog prefix: Oct 14 19:38:32 192.168.0.107  time=15:38:32 ...
    ts=$(echo "$line" | awk '{print $1" "$2" "$3}')
    # extract srcip=... (IPv4)
    srcip=$(echo "$line" | sed -n 's/.*srcip=\([0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}\).*/\1/p')
    if [ -n "$srcip" ]; then
      # output timestamp|ip|raw
      printf '%s|%s|%s\n' "$ts" "$srcip" "$line" >> "$TMP"
    fi
  done
done

# dedupe by ip and keep latest occurrence (sort by ip then timestamp)
# we'll keep unique IPs, newest first
awk -F'|' '{print $2 "|" $1 "|" $3}' "$TMP" | \
  # sort by ip then timestamp reverse (naive), then keep first occurrence per ip
  sort -t'|' -k1,1 -k2,2r | awk -F'|' '!seen[$1]++ {print $2 "|" $1 "|" $3}' > "$OUT"

# OUT format: TIMESTAMP|IP|FULL_LINE
