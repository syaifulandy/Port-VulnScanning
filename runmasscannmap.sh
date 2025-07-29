#!/bin/bash
set -e
#Masscan: scanning TCP ports from ports.txt
#NMAP: scanning UDP ports

PORT_FILE="ports.txt"
UDP_PORTS="53,123,161,162"
OUTPUT_DIR="output"
RATE=10000

CIDR_FOLDER="cidr"
CIDR_FILES=( "$CIDR_FOLDER"/*.txt )

# Validasi input
[[ ! -f "$PORT_FILE" ]] && echo "❌ File $PORT_FILE tidak ditemukan!" && exit 1
for file in "${CIDR_FILES[@]}"; do
  [[ ! -f "$file" ]] && echo "❌ File $file tidak ditemukan!" && exit 1
done

mkdir -p "$OUTPUT_DIR"
ALL_UNIQUE_TCP="$OUTPUT_DIR/all_unique_tcp.txt"
ALL_UNIQUE_UDP="$OUTPUT_DIR/all_unique_udp.txt"
> "$ALL_UNIQUE_TCP"
> "$ALL_UNIQUE_UDP"

# Ambil port TCP valid
PORT_LIST=$(tr ', ' '\n' < "$PORT_FILE" | grep -E '^[0-9]+$' | sort -nu | paste -sd "," -)
[[ -z "$PORT_LIST" ]] && echo "❌ $PORT_FILE kosong atau tidak valid!" && exit 1

echo "✅ TCP Ports: $PORT_LIST"
echo "✅ UDP Ports: $UDP_PORTS"

for CIDR_FILE in "${CIDR_FILES[@]}"; do
  [[ ! -s "$CIDR_FILE" ]] && echo "⚠️  $CIDR_FILE kosong, dilewati!" && continue

  name=$(basename "$CIDR_FILE" .txt)
  tcp_out_file="$OUTPUT_DIR/output_tcp_$name.txt"
  udp_out_file="$OUTPUT_DIR/output_udp_$name.txt"
  > "$tcp_out_file"
  > "$udp_out_file"

  echo "🚀 Memproses $CIDR_FILE..."
  while read -r cidr; do
    [[ -z "$cidr" ]] && continue
    echo "▶️ [TCP] Scanning $cidr"
    masscan -p"$PORT_LIST" --rate "$RATE" --wait 0 -oL - "$cidr" \
      | grep '^open' | awk '{print $4 ":" $3}' >> "$tcp_out_file"
  done < "$CIDR_FILE"

  sort -u "$tcp_out_file" -o "$tcp_out_file"
  cat "$tcp_out_file" >> "$ALL_UNIQUE_TCP"

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
  }
  ' temp_nmap.gnmap >> "$udp_out_file"



  sort -u "$udp_out_file" -o "$udp_out_file"
  cat "$udp_out_file" >> "$ALL_UNIQUE_UDP"
done

sort -u "$ALL_UNIQUE_TCP" -o "$ALL_UNIQUE_TCP"
sort -u "$ALL_UNIQUE_UDP" -o "$ALL_UNIQUE_UDP"
rm -f temp_nmap.gnmap

echo "✅ Scanning selesai!"
echo "📄 TCP hasil gabungan: $ALL_UNIQUE_TCP"
echo "📄 UDP hasil gabungan: $ALL_UNIQUE_UDP"

# Jalankan konversi hasil ke CSV
echo "🛠️ Konversi hasil ke CSV..."
./convertmasscantocsv.sh "$ALL_UNIQUE_TCP"
./convertnmapscantocsvperip.sh "$ALL_UNIQUE_UDP"
echo "✅ Konversi selesai!"
