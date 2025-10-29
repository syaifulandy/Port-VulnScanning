#!/usr/bin/env bash
set -euo pipefail

## ------------ Config (ubah jika perlu) ------------
DOMAINS_FILE="targets.txt"
PORTS_FILE="ports.txt"
OUT_DIR="masscan_out"
RATE=1000               # paket per detik, sesuaikan
MASSCAN_BIN=$(command -v masscan || true)
DIG_BIN=$(command -v dig || true)
HOST_BIN=$(command -v host || true)
# ---------------------------------------------------

if [[ -z "$MASSCAN_BIN" ]]; then
  echo "masscan tidak ditemukan di PATH. Install masscan dulu."
  exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "File domain tidak ditemukan: $DOMAINS_FILE"
  exit 1
fi
if [[ ! -f "$PORTS_FILE" ]]; then
  echo "File ports tidak ditemukan: $PORTS_FILE"
  exit 1
fi

mkdir -p "$OUT_DIR"
IPS_V4="$OUT_DIR/ips_v4.txt"
IPS_V6="$OUT_DIR/ips_v6.txt"
MAP="$OUT_DIR/domain_ip_map.tsv"
OUT_V4="$OUT_DIR/masscan_v4.json"
OUT_V6="$OUT_DIR/masscan_v6.json"

: > "$IPS_V4"
: > "$IPS_V6"
: > "$MAP"

echo "Resolving domains from $DOMAINS_FILE ..."
while IFS= read -r line || [[ -n "$line" ]]; do
  # remove comments and trim
  d="${line%%#*}"
  d="$(echo -n "$d" | xargs)" || true
  [[ -z "$d" ]] && continue

  # try dig then host
  if [[ -n "$DIG_BIN" ]]; then
    # get A records
    mapfile -t A_ARR < <(dig +short A "$d" | sed '/^$/d')
    # get AAAA records
    mapfile -t AAAA_ARR < <(dig +short AAAA "$d" | sed '/^$/d')
  elif [[ -n "$HOST_BIN" ]]; then
    mapfile -t A_ARR < <(host -t A "$d" 2>/dev/null | awk '/has address/ {print $4}')
    mapfile -t AAAA_ARR < <(host -t AAAA "$d" 2>/dev/null | awk '/has IPv6 address/ {print $5}')
  else
    echo "Tidak ada resolver (dig/host) tersedia — cannot resolve $d"
    continue
  fi

  # write mappings
  for ip in "${A_ARR[@]:-}"; do
    # basic IPv4 validation
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      echo "$ip" >> "$IPS_V4"
      echo -e "$d\t$ip" >> "$MAP"
    fi
  done
  for ip in "${AAAA_ARR[@]:-}"; do
    # basic IPv6 presence (very permissive)
    if [[ "$ip" == *:* ]]; then
      echo "$ip" >> "$IPS_V6"
      echo -e "$d\t$ip" >> "$MAP"
    fi
  done
done < "$DOMAINS_FILE"

# dedup & clean
if [[ -f "$IPS_V4" ]]; then
  sort -u "$IPS_V4" -o "$IPS_V4" || true
fi
if [[ -f "$IPS_V6" ]]; then
  sort -u "$IPS_V6" -o "$IPS_V6" || true
fi

# build ports string (comma separated)
PORTS=$(paste -sd, "$PORTS_FILE" | sed 's/[[:space:]]//g' | sed 's/,$//')
if [[ -z "$PORTS" ]]; then
  echo "Ports kosong setelah membaca $PORTS_FILE"
  exit 1
fi

# run masscan for IPv4
if [[ -s "$IPS_V4" ]]; then
  echo "Menjalankan masscan (IPv4) pada $(wc -l < "$IPS_V4") IP, ports: $PORTS"
  echo "Output: $OUT_V4"
  "$MASSCAN_BIN" -iL "$IPS_V4" -p "$PORTS" --rate "$RATE" -oJ "$OUT_V4" || true
else
  echo "Tidak ada IP IPv4 untuk di-scan."
fi

# run masscan for IPv6 (gunakan -6)
if [[ -s "$IPS_V6" ]]; then
  echo "Menjalankan masscan (IPv6) pada $(wc -l < "$IPS_V6") IP, ports: $PORTS"
  echo "Output: $OUT_V6"
  "$MASSCAN_BIN" -6 -iL "$IPS_V6" -p "$PORTS" --rate "$RATE" -oJ "$OUT_V6" || true
else
  echo "Tidak ada IP IPv6 untuk di-scan."
fi

echo "Selesai. Files di: $OUT_DIR/"
echo "- IP list IPv4: $IPS_V4"
echo "- IP list IPv6: $IPS_V6"
echo "- Mapping domain->IP: $MAP"
echo "- masscan v4 json: $OUT_V4"
echo "- masscan v6 json: $OUT_V6"
echo
echo "Catatan:"
echo "- Jika target memakai CDN (Cloudflare, Akamai, ELB, dll.), IP yang di-resolve biasanya bukan IP server Anda — pastikan Anda punya izin."
echo "- Untuk menggabungkan hasil JSON, gunakan 'jq -s add masscan_v4.json masscan_v6.json > masscan_all.json' jika jq tersedia."
echo "- Sesuaikan RATE jika perlu; jangan set terlalu tinggi tanpa izin."
