#!/bin/bash

CIDR_FILE="cidrs.txt"
PORT_FILE="ports.txt"
OUTPUT_DIR="output"
ALL_OUTPUT="$OUTPUT_DIR/all_raw.txt"
ALL_UNIQUE="$OUTPUT_DIR/all_unique.txt"
RATE=10000

# Validasi file input
if [ ! -f "$CIDR_FILE" ]; then
  echo "❌ File $CIDR_FILE tidak ditemukan!"
  exit 1
fi

if [ ! -f "$PORT_FILE" ]; then
  echo "❌ File $PORT_FILE tidak ditemukan!"
  exit 1
fi

# Siapkan folder dan file
mkdir -p "$OUTPUT_DIR"
> "$ALL_OUTPUT"

# Ambil dan bersihkan daftar port
PORT_LIST=$(tr ',' '\n' < "$PORT_FILE" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -nu | paste -sd "," -)

if [ -z "$PORT_LIST" ]; then
  echo "❌ ports.txt kosong atau tidak valid!"
  exit 1
fi

echo "✅ Port yang akan discan: $PORT_LIST"

# Scan tiap CIDR
while read -r cidr; do
  [[ -z "$cidr" ]] && continue

  safe_name=$(echo "$cidr" | tr '/' '_' | tr -d ' ')
  out_file="$OUTPUT_DIR/$safe_name.txt"

  echo "▶️ Scanning $cidr → $out_file"
  masscan -p"$PORT_LIST" --rate "$RATE" --wait 0 -oL "$out_file" "$cidr"
  grep '^open' "$out_file" | awk '{print $4 ":" $3}' >> "$ALL_OUTPUT"
  

done < "$CIDR_FILE"

# Gabungan hasil unik
sort -u "$ALL_OUTPUT" > "$ALL_UNIQUE"

echo "✅ Scan selesai!"
echo "📄 Gabungan hasil unik: $ALL_UNIQUE"
