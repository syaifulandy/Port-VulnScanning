#!/usr/bin/env bash
set -euo pipefail

# nmapscan.sh
# Validate the result of masscan using nmap with script and service scan
# Usage:
#   ./nmapscan.sh <input-file>
# Example:
#   ./nmapscan.sh tesscan
#   -> writes output to output_nmap_servicescript_tesscan
#
# Notes:
# - Bash 4+ (associative arrays)
# - nmap must be in PATH
# - Output uses ';' as separator and collapses Host script results into one long field.

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <input-file>" >&2
  exit 2
fi

INPUT="$1"

[[ -f "$INPUT" ]] || { echo "File not found: $INPUT" >&2; exit 3; }

# derive output filename: output_nmap_servicescript_<basename-without-extension>
basefile="$(basename -- "$INPUT")"
name="${basefile%.*}"
OUTFILE="output_nmap_servicescript_${name}"

declare -A ip_ports

# === 1. Read input and group ports per IP (dedupe) ===
while IFS= read -r raw || [[ -n "${raw:-}" ]]; do
  line="${raw%%#*}"
  line="$(printf "%s" "$line" | tr -d '\r' | xargs 2>/dev/null || true)"
  [[ -z "$line" ]] && continue
  [[ "$line" != *:* ]] && continue
  ip="${line%%:*}"
  port="${line#*:}"
  [[ -z "$ip" || -z "$port" ]] && continue
  cur="${ip_ports[$ip]:-}"
  if [[ -z "$cur" ]]; then
    ip_ports[$ip]="$port"
  else
    IFS=',' read -r -a arr <<< "$cur"
    dup=0
    for p in "${arr[@]}"; do
      [[ "$p" == "$port" ]] && { dup=1; break; }
    done
    [[ $dup -eq 0 ]] && ip_ports[$ip]="$cur,$port"
  fi
done < "$INPUT"

# === 2. Sort IPs numerically ===
mapfile -t ips_sorted < <(
  for ip in "${!ip_ports[@]}"; do
    IFS=. read -r a b c d <<< "$ip"
    printf "%03d.%03d.%03d.%03d %s\n" "$a" "$b" "$c" "$d" "$ip"
  done | sort | awk '{print $2}'
)

# === 3. Reset output file ===
: > "$OUTFILE"

# === 4. Main scan+parse function ===
scan_and_parse() {
  local ip="$1" ports_csv="$2"
  echo ">> Scanning $ip ports $ports_csv" >&2

  local nmap_out
  nmap_out="$(nmap -Pn -n "$ip" -p "$ports_csv" --version-intensity 0 -sCV --host-timeout 60 -oN - 2>/dev/null || true)"

  # parse ports (only open) -> IP;PORT;SERVICE;VERSION_OR_-
  printf "%s\n" "$nmap_out" | awk -v IP="$ip" -v SEP=";" '
    /^[0-9]+\/[a-z]+[ \t]+/ {
      portproto=$1; state=$2; service=$3;
      version="";
      if (NF>=4) {
        for (i=4;i<=NF;i++){ if(i>4)version=version" "; version=version $i }
      }
      if (state=="open") {
        split(portproto,a,"/"); port=a[1];
        if (length(version)==0) version="-";
        gsub(/^[ \t]+|[ \t]+$/,"",version);
        print IP SEP port SEP service SEP version;
      }
    }
  ' >> "$OUTFILE"

  # collapse Host script results into single line (preserve leading '|' or '|_')
  local script_line
  script_line="$(
    printf "%s\n" "$nmap_out" | awk '
      BEGIN { in_block=0; have=0; out="Host script results:" }
      /^Host script results:/ { in_block=1; next }
      {
        if (in_block) {
          if ($0 ~ /^[[:space:]]*\|/) {
            line=$0
            sub(/^[[:space:]]*/, "", line)
            sub(/\r$/, "", line)
            if (have==0) { out=out " " line; have=1 }
            else         { out=out " " line }
            next
          } else {
            in_block=0
          }
        }
      }
      END { if (have==1) print out }
    '
  )"

  if [[ -n "$script_line" ]]; then
    printf "%s;script;%s\n" "$ip" "$script_line" >> "$OUTFILE"
  fi
}

# === 5. Run for each IP ===
for ip in "${ips_sorted[@]}"; do
  IFS=',' read -r -a parr <<< "${ip_ports[$ip]}"
  mapfile -t sorted_ports < <(printf "%s\n" "${parr[@]}" | sort -n | awk '!x[$0]++')
  ports_final="$(IFS=,; echo "${sorted_ports[*]}")"
  scan_and_parse "$ip" "$ports_final"
done

echo "✅ Done. Results saved to $OUTFILE" >&2
