#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-all_unique_udp.txt}"
SNMP_COMMUNITY="${SNMP_COMMUNITY:-public}"
CONCURRENCY="${CONCURRENCY:-80}"
NMAP_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT:-45s}"
NMAP_SCRIPT_TIMEOUT="${NMAP_SCRIPT_TIMEOUT:-20s}"
LOG_DIR="${LOG_DIR:-scan_logs}"
OUT_SNMP="${OUT_SNMP:-snmp_public_results.txt}"
OUT_NTP="${OUT_NTP:-ntp_vuln_results.txt}"

mkdir -p "$LOG_DIR"
: > "$OUT_SNMP"
: > "$OUT_NTP"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[-] butuh $1"; exit 1; }; }
need awk; need grep; need nmap; need onesixtyone

# Validasi baris "ip:port", kumpulkan target 161 & 123
awk -F: 'NF==2 && $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && $2 ~ /^[0-9]+$/ {print}' "$INPUT_FILE" \
  | tee "$LOG_DIR/valid_all.txt" >/dev/null

grep -E ':(\s*)161$' "$LOG_DIR/valid_all.txt" | cut -d: -f1 | sort -u > "$LOG_DIR/targets_snmp.txt" || true
grep -E ':(\s*)123$' "$LOG_DIR/valid_all.txt" | cut -d: -f1 | sort -u > "$LOG_DIR/targets_ntp.txt"  || true

SNMP_COUNT=$(wc -l < "$LOG_DIR/targets_snmp.txt" 2>/dev/null || echo 0)
NTP_COUNT=$(wc -l < "$LOG_DIR/targets_ntp.txt" 2>/dev/null || echo 0)

echo "[*] Target SNMP (161/udp): $SNMP_COUNT"
echo "[*] Target NTP  (123/udp): $NTP_COUNT"

snmp_task() {
  ip="$1"
  # Jalankan onesixtyone dan bersihkan noise "Scanning X hosts, Y communities"
  raw=$(onesixtyone -c <(echo "$SNMP_COMMUNITY") "$ip" 2>&1 | sed -E '/^Scanning [0-9]+ hosts, [0-9]+ communities$/d')
  # Jika ada vendor/descr di output berarti community valid (read)
  if echo "$raw" | grep -qE '\[public\]|public\]|\bSNMP\b|sysDescr|HP|Cisco|MikroTik|Ubiquiti|Linux|Windows'; then
    # ringkas 1 baris
    oneline=$(echo "$raw" | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;SNMP_PUBLIC_OK;$oneline" >> "$OUT_SNMP"
  else
    # tetap simpan error ringkas agar bisa di-audit
    oneline=$(echo "$raw" | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;NO_ACCESS;$oneline" >> "$OUT_SNMP"
  fi
}

ntp_task() {
  ip="$1"
  # Hanya script vuln/ekspos: ntp-monlist & ntp-readvar
  output=$(nmap -Pn -sU -p 123 \
      --script=ntp-monlist \
      --max-retries 2 \
      --host-timeout "$NMAP_HOST_TIMEOUT" \
      --script-timeout "$NMAP_SCRIPT_TIMEOUT" \
      "$ip" 2>&1 || true)

  echo "$output" > "$LOG_DIR/ntp_${ip}.log"

  # Klasifikasi hasil
  if echo "$output" | grep -qiE '\| *ntp-monlist:.*(addr|items|received)'; then
    # Ada daftar monlist nyata
    summary=$(echo "$output" | awk '/ntp-monlist:/{flag=1} /Service Info:|Nmap done:/{if(flag){exit}} flag' | tr '\n' ' ')
    echo "$ip;VULN_MONLIST;$summary" >> "$OUT_NTP"
  elif echo "$output" | grep -qiE 'monlist request|ntp-monlist: (disabled|denied|rejected|no reply)'; then
    reason=$(echo "$output" | grep -iE 'ntp-monlist: .*' | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;MONLIST_BLOCKED;$reason" >> "$OUT_NTP"
  else
    # Tidak terlihat vuln / atau host tidak merespon
    short=$(echo "$output" | awk '/Nmap scan report for|123\/udp|ntp-/{print}' | tr '\n' ' ')
    [ -n "$short" ] || short="no-evidence"
    echo "$ip;NO_VULN;$short" >> "$OUT_NTP"
  fi
}

export -f snmp_task ntp_task
export SNMP_COMMUNITY OUT_SNMP OUT_NTP LOG_DIR NMAP_HOST_TIMEOUT NMAP_SCRIPT_TIMEOUT

run_parallel() {
  local file="$1" func="$2" label="$3"
  local count; count=$(wc -l < "$file" 2>/dev/null || echo 0)
  [ "$count" -gt 0 ] || { echo "[-] Tidak ada target $label"; return 0; }

  if command -v parallel >/dev/null 2>&1; then
    echo "[*] $label: GNU parallel -j $CONCURRENCY"
    parallel -a "$file" -j "$CONCURRENCY" --halt soon,fail=1 "$func" {}
  else
    echo "[*] $label: xargs -P $CONCURRENCY (fallback)"
    xargs -a "$file" -P "$CONCURRENCY" -I{} bash -c "$func \"{}\""
  fi
}

run_parallel "$LOG_DIR/targets_snmp.txt" snmp_task "SNMP"
run_parallel "$LOG_DIR/targets_ntp.txt"  ntp_task  "NTP"

echo "[✓] Selesai."
echo "    SNMP: $OUT_SNMP"
echo "    NTP : $OUT_NTP"
echo "    Logs: $LOG_DIR/"
