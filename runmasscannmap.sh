#!/bin/bash
set -e

PORT_FILE="./ports.txt"
UDP_PORTS="53,123,161,162"
CIDR_DIR="cidr"
OUTPUT_DIR="output"
RATE=10000

mkdir -p "$OUTPUT_DIR"
ALL_UNIQUE_TCP="$OUTPUT_DIR/all_unique_tcp.txt"
ALL_UNIQUE_UDP="$OUTPUT_DIR/all_unique_udp.txt"
> "$ALL_UNIQUE_TCP"
> "$ALL_UNIQUE_UDP"

# Ambil file CIDR dari folder
CIDR_FILES=("$CIDR_DIR"/*.txt)

# Validasi input
[[ ! -f "$PORT_FILE" ]] && echo "❌ File $PORT_FILE tidak ditemukan!" && exit 1
for file in "${CIDR_FILES[@]}"; do
  [[ ! -f "$file" ]] && echo "❌ File $file tidak ditemukan!" && exit 1
done

# Ambil port TCP valid
PORT_LIST=$(tr ', ' '\n' < "$PORT_FILE" | grep -E '^[0-9]+$' | sort -nu | paste -sd "," -)
[[ -z "$PORT_LIST" ]] && echo "❌ $PORT_FILE kosong atau tidak valid!" && exit 1

echo "✅ TCP Ports: $PORT_LIST"
echo "✅ UDP Ports: $UDP_PORTS"

for CIDR_FILE in "${CIDR_FILES[@]}"; do
  [[ ! -s "$CIDR_FILE" ]] && echo "⚠️  $CIDR_FILE kosong, dilewati!" && continue

  name=$(basename "$CIDR_FILE" .txt)

  start_time=$(date +%s)
  echo "🚀 Memproses $CIDR_FILE..."

  tcp_out_file=$(mktemp)
  udp_out_file=$(mktemp)

  # TCP Scan
  while read -r cidr; do
    [[ -z "$cidr" ]] && continue
    echo "▶️ [TCP] Scanning $cidr"
    masscan -p"$PORT_LIST" --rate "$RATE" --wait 0 -oL - "$cidr" \
      | grep '^open' | awk '{print $4 ":" $3}' >> "$tcp_out_file"
  done < "$CIDR_FILE"

  sort -u "$tcp_out_file" -o "$tcp_out_file"

  # UDP Scan
  echo "▶️ [UDP] Nmap scan $CIDR_FILE..."
  sudo nmap -sU -p "$UDP_PORTS" -iL "$CIDR_FILE" -oG - > temp_nmap.gnmap

  awk '
  /^Host:/ {
    ip = $2
    ports = ""
    for (i=1; i<=NF; i++) {
      if ($i ~ /^Ports:/) {
        ports_start = i+1
        break
      }
    }
    for (j=ports_start; j<=NF; j++) {
      ports = ports $j " "
    }
    n = split(ports, plist, ",")
    for (k=1; k<=n; k++) {
      gsub(/^ +| +$/, "", plist[k])
      split(plist[k], pinfo, "/")
      if (pinfo[2] == "open" && pinfo[3] == "udp") {
        print ip ":" pinfo[1]
      }
    }
  }' temp_nmap.gnmap >> "$udp_out_file"

  sort -u "$udp_out_file" -o "$udp_out_file"
  rm -f temp_nmap.gnmap

  end_time=$(date +%s)
  duration_sec=$((end_time - start_time))
  duration_min=$(( (duration_sec + 59) / 60 ))

  start_fmt=$(date -d "@$start_time" +"%Y%m%dT%H%M")
  end_fmt=$(date -d "@$end_time" +"%Y%m%dT%H%M")
  name_with_time="${name}_start_${start_fmt}_end_${end_fmt}_${duration_min}min"

  tcp_final="$OUTPUT_DIR/tcp_${name_with_time}.txt"
  udp_final="$OUTPUT_DIR/udp_${name_with_time}.txt"

  mv "$tcp_out_file" "$tcp_final"
  mv "$udp_out_file" "$udp_final"

  cat "$tcp_final" >> "$ALL_UNIQUE_TCP"
  cat "$udp_final" >> "$ALL_UNIQUE_UDP"
done

sort -u "$ALL_UNIQUE_TCP" -o "$ALL_UNIQUE_TCP"
sort -u "$ALL_UNIQUE_UDP" -o "$ALL_UNIQUE_UDP"

zip_name="${OUTPUT_DIR}.zip"

# Buat ZIP hasil output
zip -r "$zip_name" "$OUTPUT_DIR"

echo "✅ Scanning selesai!"
echo "📄 TCP hasil gabungan: $ALL_UNIQUE_TCP"
echo "📄 UDP hasil gabungan: $ALL_UNIQUE_UDP"
echo "🗜️ Arsip ZIP dibuat: $zip_name"

