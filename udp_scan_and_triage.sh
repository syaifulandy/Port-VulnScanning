#!/usr/bin/env bash
set -euo pipefail

# =========================
# Konfigurasi
# =========================
CIDR_DIR="${CIDR_DIR:-cidr}"                 # folder berisi *.txt, tiap baris = CIDR/IP/per-host
OUTPUT_DIR="${OUTPUT_DIR:-output_udp}"       # hasil utama
LOG_DIR="$OUTPUT_DIR/scan_logs"              # log tahap 2
UDP_PORTS="${UDP_PORTS:-53,123,161,162}"     # daftar port UDP target (comma)
ZIP_NAME="${ZIP_NAME:-${OUTPUT_DIR}.zip}"

# Param nmap (scan tahap 1)
NMAP_MAX_RETRIES="${NMAP_MAX_RETRIES:-1}"
NMAP_HOST_TIMEOUT_SCAN="${NMAP_HOST_TIMEOUT_SCAN:-60s}"

# Param triage (tahap 2)
SNMP_COMMUNITY="${SNMP_COMMUNITY:-public}"
CONCURRENCY="${CONCURRENCY:-80}"
NMAP_HOST_TIMEOUT="${NMAP_HOST_TIMEOUT:-45s}"
NMAP_SCRIPT_TIMEOUT="${NMAP_SCRIPT_TIMEOUT:-20s}"

# Output file ringkasan
ALL_UNIQUE_UDP="$OUTPUT_DIR/all_unique_udp.txt"
OUT_SNMP="$OUTPUT_DIR/snmp_public_results.txt"
OUT_NTP="$OUTPUT_DIR/ntp_vuln_results.txt"

# =========================
# Helpers
# =========================
need() { command -v "$1" >/dev/null 2>&1 || { echo "[-] butuh $1"; exit 1; }; }

# prefer sudo bila perlu raw socket dan bukan root
nmap_cmd() {
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    sudo nmap "$@"
  else
    nmap "$@"
  fi
}

# =========================
# Validasi
# =========================
need awk; need grep; need nmap
mkdir -p "$OUTPUT_DIR" "$LOG_DIR"
: > "$ALL_UNIQUE_UDP"

# Ambil file CIDR
CIDR_FILES=()
while IFS= read -r -d '' f; do CIDR_FILES+=("$f"); done < <(find "$CIDR_DIR" -maxdepth 1 -type f -name "*.txt" -print0 | sort -z)
[ ${#CIDR_FILES[@]} -gt 0 ] || { echo "❌ Tidak ada file *.txt di $CIDR_DIR"; exit 1; }

# Hitung total lines (entry) di semua file untuk estimasi kerja
TOTAL_CIDR=${#CIDR_FILES[@]}
TOTAL_LINES=0
for f in "${CIDR_FILES[@]}"; do
  # hitung baris non-empty
  cnt=$(grep -cve '^\s*$' "$f" || echo 0)
  TOTAL_LINES=$((TOTAL_LINES + cnt))
done

echo "✅ UDP Ports: $UDP_PORTS"
echo "📁 CIDR files: $TOTAL_CIDR"
echo "🧾 Total lines (entries) across files: $TOTAL_LINES"
echo

# =========================
# TAHAP 1 — UDP Scan (nmap) with per-file progress
# =========================
idx=0
for CIDR_FILE in "${CIDR_FILES[@]}"; do
  idx=$((idx+1))
  LINES_IN_FILE=$(grep -cve '^\s*$' "$CIDR_FILE" || echo 0)

  if [ "$LINES_IN_FILE" -eq 0 ]; then
    echo "⚠️  [$idx/$TOTAL_CIDR] $(basename "$CIDR_FILE") kosong, dilewati."
    continue
  fi

  name=$(basename "$CIDR_FILE" .txt)
  start_time=$(date +%s)
  echo "🚀 [$idx/$TOTAL_CIDR] Memproses $CIDR_FILE (lines: $LINES_IN_FILE)..."

  udp_tmp=$(mktemp)
  gnmap_tmp=$(mktemp)

  # Scan UDP: gunakan -Pn supaya nmap tidak ICMP/ping terlebih dahulu (sering ter-block)
  nmap_cmd -sU -Pn -p "$UDP_PORTS" \
    -iL "$CIDR_FILE" \
    --max-retries "$NMAP_MAX_RETRIES" \
    --host-timeout "$NMAP_HOST_TIMEOUT_SCAN" \
    -oG - > "$gnmap_tmp" || true

  # Parse output gaya "ip:port" hanya yang open/udp
  awk '
  /^Host:/ {
    ip = $2
    ports = ""
    for (i=1; i<=NF; i++) if ($i ~ /^Ports:/) { ps=i+1; break }
    for (j=ps; j<=NF; j++) ports = ports $j " "
    n = split(ports, plist, ",")
    for (k=1; k<=n; k++) {
      gsub(/^ +| +$/, "", plist[k])
      split(plist[k], pinfo, "/")
      if (pinfo[2] == "open" && pinfo[3] == "udp") print ip ":" pinfo[1]
    }
  }' "$gnmap_tmp" >> "$udp_tmp"

  sort -u "$udp_tmp" -o "$udp_tmp"
  rm -f "$gnmap_tmp"

  end_time=$(date +%s)
  duration_sec=$((end_time - start_time))
  duration_min=$(( (duration_sec + 59) / 60 ))

  start_fmt=$(date -d "@$start_time" +"%Y%m%dT%H%M")
  end_fmt=$(date -d "@$end_time" +"%Y%m%dT%H%M")
  name_with_time="${name}_start_${start_fmt}_end_${end_fmt}_${duration_min}min"

  udp_final="$OUTPUT_DIR/udp_${name_with_time}.txt"
  mv "$udp_tmp" "$udp_final"
  cat "$udp_final" >> "$ALL_UNIQUE_UDP"

  echo "✅ [$idx/$TOTAL_CIDR] Selesai: $udp_final (durasi: ${duration_min}m)"
  echo
done

sort -u "$ALL_UNIQUE_UDP" -o "$ALL_UNIQUE_UDP"

# =========================
# TAHAP 2 — TRIAGE SNMP & NTP
# =========================
echo
echo "🔎 Tahap 2: Triage SNMP (161/udp) & NTP (123/udp)"

: > "$OUT_SNMP"
: > "$OUT_NTP"

# Pastikan tools untuk triage
need onesixtyone

# Filter & siapkan target
awk -F: 'NF==2 && $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && $2 ~ /^[0-9]+$/ {print}' "$ALL_UNIQUE_UDP" \
  | tee "$LOG_DIR/valid_all.txt" >/dev/null

grep -E ':(\s*)161$' "$LOG_DIR/valid_all.txt" | cut -d: -f1 | sort -u > "$LOG_DIR/targets_snmp.txt" || true
grep -E ':(\s*)123$' "$LOG_DIR/valid_all.txt" | cut -d: -f1 | sort -u > "$LOG_DIR/targets_ntp.txt"  || true

SNMP_COUNT=$(wc -l < "$LOG_DIR/targets_snmp.txt" 2>/dev/null || echo 0)
NTP_COUNT=$(wc -l < "$LOG_DIR/targets_ntp.txt" 2>/dev/null || echo 0)

echo "[*] Target SNMP (161/udp): $SNMP_COUNT"
echo "[*] Target NTP  (123/udp): $NTP_COUNT"

snmp_task() {
  ip="$1"
  raw=$(onesixtyone -c <(echo "$SNMP_COMMUNITY") "$ip" 2>&1 | sed -E '/^Scanning [0-9]+ hosts, [0-9]+ communities$/d')
  if echo "$raw" | grep -qE '\[public\]|public\]|\bSNMP\b|sysDescr|HP|Cisco|MikroTik|Ubiquiti|Linux|Windows'; then
    oneline=$(echo "$raw" | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;SNMP_PUBLIC_OK;$oneline" >> "$OUT_SNMP"
  else
    oneline=$(echo "$raw" | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;NO_ACCESS;$oneline" >> "$OUT_SNMP"
  fi
}

ntp_task() {
  ip="$1"
  output=$(nmap_cmd -Pn -sU -p 123 \
      --script=ntp-monlist \
      --max-retries 2 \
      --host-timeout "$NMAP_HOST_TIMEOUT" \
      --script-timeout "$NMAP_SCRIPT_TIMEOUT" \
      "$ip" 2>&1 || true)

  echo "$output" > "$LOG_DIR/ntp_${ip}.log"

  if echo "$output" | grep -qiE '\| *ntp-monlist:.*(addr|items|received)'; then
    summary=$(echo "$output" | awk '/ntp-monlist:/{flag=1} /Service Info:|Nmap done:/{if(flag){exit}} flag' | tr '\n' ' ')
    echo "$ip;VULN_MONLIST;$summary" >> "$OUT_NTP"
  elif echo "$output" | grep -qiE 'monlist request|ntp-monlist: (disabled|denied|rejected|no reply)'; then
    reason=$(echo "$output" | grep -iE 'ntp-monlist: .*' | tr '\n' ' ' | sed -E 's/\s+/ /g')
    echo "$ip;MONLIST_BLOCKED;$reason" >> "$OUT_NTP"
  else
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

# =========================
# Arsip dan ringkasan
# =========================
( cd "$OUTPUT_DIR" && zip -q -r "../$ZIP_NAME" . )
echo
echo "🎉 Selesai."
echo "📄 UDP gabungan   : $ALL_UNIQUE_UDP"
echo "📝 SNMP results   : $OUT_SNMP"
echo "📝 NTP results    : $OUT_NTP"
echo "🗜️  ZIP            : $ZIP_NAME"
echo "🗂️  Logs           : $LOG_DIR/"
